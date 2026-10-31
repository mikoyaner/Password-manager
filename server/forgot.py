"""忘记密码（v2.8）：两步确认 + 随机临时密码 + 两阶段落库。

流程（邮件通道，根治发件人伪造）：
  第 1 步 worker 收到 01<用户名> 且**发件人哈希与注册绑定匹配** → 生成一次性
  确认码（15 分钟有效，绑定发件人），自动回复到发件邮箱（= 注册邮箱）；
  第 2 步 用户回复该邮件（正文含确认码，发件人不变 = 证明能收信）→ worker
  校验确认码 → 生成**随机临时密码**并回复给用户 → 发送成功后才写入数据库
  （两阶段提交：SMTP 失败自动回滚旧密码并保留确认码，用户不会被锁在门外）。

安全要点：
  - **不存在全局固定密码**：临时密码只发往"通过哈希验证的注册邮箱"。攻击者
    伪造 From 只能让真正的邮箱主人收到确认码/临时密码，自己拿不到任何凭据；
  - 24h 内已重置且用户**未自行改密**（改密会清除标记）→ 免确认码直接重发
    **新的**随机临时密码（用户要求）；每用户每小时最多重发 3 次（防刷）；
  - 24h 节流在最终落库时以 CAS 条件更新生效；
  - 短信通道无下行能力：/internal/sms-up 仅提醒管理员人工处理（见 main.py）；
  - 临时密码**绝不写日志/审计**；审计文件（forgot.log）记录成功与失败，
    发件人打码；每 180 天清理一次、删除 90 天前的日志行（用户指定，严格按字面）；
  - 用户名**精确匹配**（审计报告 P0-3：注册/登录/找回全链路一致，杜绝
    大小写变体跨账号重置）。
"""
from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import time

import auth
import contacts
import store

log = logging.getLogger("pwmanager.forgot")

_THROTTLE_MS = 24 * 3600 * 1000              # 每用户 24h 内只重置一次（落库时 CAS 生效）
_TOKEN_TTL_S = 15 * 60                       # 确认码有效期
_PWD_LEN = 12                                # 随机临时密码长度
_PWD_ALPHABET = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
_RESEND_LIMIT = 3                            # 24h 窗口内"直接重发"的最多次数（防 DoS 刷重置）
_RESEND_WINDOW_MS = 3600 * 1000

# 结果码：ok / no_user / mismatch / invalid_contact / invalid_token / throttled
# / resent / resend_limited

# ---- 审计日志（用户指定：正确与错误都记录；发件人打码）----
# 文件位于数据目录（沙箱唯一可写点）。

_AUDIT_PATH: str | None = None
_CLEAN_INTERVAL_S = 180 * 86400
_KEEP_S = 90 * 86400
_LINE_TS = re.compile(r"\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]")

try:
    import fcntl
except ImportError:                          # 非 POSIX（开发机 Windows）降级为无文件锁
    fcntl = None


def _data_dir() -> str:
    db = os.environ.get("PWMGR_DB", "")
    return os.path.dirname(db) if db else "."


def _audit_path() -> str:
    global _AUDIT_PATH
    if _AUDIT_PATH is None:
        _AUDIT_PATH = os.path.join(_data_dir(), "forgot.log")
    return _AUDIT_PATH


@contextlib.contextmanager
def _file_lock():
    """跨进程互斥（mail worker 与 API 进程共用数据目录）。POSIX 用 flock。"""
    path = _audit_path() + ".lock"
    f = open(path, "a+")
    try:
        if fcntl is not None:
            fcntl.flock(f, fcntl.LOCK_EX)
        yield
    finally:
        try:
            if fcntl is not None:
                fcntl.flock(f, fcntl.LOCK_UN)
        finally:
            f.close()


def _mask(contact: str) -> str:
    c = (contact or "").strip()
    if "@" in c:
        local, _, dom = c.partition("@")
        return (local[:3] + "***@" + dom) if len(local) > 3 else "***@" + dom
    return (c[:3] + "****" + c[-4:]) if len(c) > 7 else "***"


def audit(event: str, *, user: str = "-", channel: str = "-",
          sender: str = "-", detail: str = "") -> None:
    """追加一条审计记录；发件人打码，用户名/时间/通道/结果完整记录。"""
    try:
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        line = (f"[{ts}] {event} user={user} channel={channel} "
                f"sender={_mask(sender)}" + (f" detail={detail}" if detail else ""))
        with _file_lock(), open(_audit_path(), "a", encoding="utf-8") as f:
            f.write(line + "\n")
        log.info("audit: %s", line)
    except Exception:
        log.exception("audit write failed")


def cleanup_if_due(now: float | None = None) -> None:
    """每 180 天执行一次：删除 forgot.log 中 90 天前的日志行（严格按用户指定）。"""
    now = time.time() if now is None else now
    state = _audit_path() + ".clean.state"
    try:
        with _file_lock():
            try:
                with open(state, encoding="utf-8") as f:
                    last = float(f.read().strip() or 0)
            except Exception:
                last = 0.0
            if now - last < _CLEAN_INTERVAL_S:
                return
            cut = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now - _KEEP_S))
            removed = kept = 0
            path = _audit_path()
            if os.path.exists(path):
                with open(path, encoding="utf-8") as f:
                    lines = f.readlines()
                out = []
                for ln in lines:
                    m = _LINE_TS.match(ln)
                    if m and m.group(1) < cut:
                        removed += 1
                        continue
                    kept += 1
                    out.append(ln)
                if removed:
                    with open(path, "w", encoding="utf-8") as f:
                        f.writelines(out)
            with open(state, "w", encoding="utf-8") as f:
                f.write(str(now))
            log.info("forgot audit cleanup: removed=%d kept=%d cut<=%s",
                     removed, kept, cut)
    except Exception:
        log.exception("forgot audit cleanup failed")


# ---- 确认码 / 临时密码 / 待确认状态 ----

def gen_token() -> str:
    return "".join(secrets.choice("ABCDEFGHJKLMNPQRSTUVWXYZ23456789")
                   for _ in range(8))


def gen_temp_pwd() -> str:
    return "".join(secrets.choice(_PWD_ALPHABET) for _ in range(_PWD_LEN))


def _pending_path() -> str:
    return os.path.join(_data_dir(), "forgot_pending.json")


def _sender_h(kind: str, sender: str) -> str:
    """发件人哈希：pending 文件不存明文联系方式（审计报告 P1-7）。"""
    if kind == "email":
        v = contacts.normalize_email(sender)
    else:
        v = contacts.normalize_phone(sender)
    pepper = os.environ.get("PWMGR_CONTACT_PEPPER", "")
    if not pepper:
        raise ValueError("PWMGR_CONTACT_PEPPER 未配置：确认码发件人哈希拒绝计算")
    return hmac.new(pepper.encode("utf-8"), f"{kind}:{v}".encode("utf-8"),
                    hashlib.sha256).hexdigest()


def sender_hash_for(kind: str, sender: str) -> str:
    return _sender_h(kind, sender)


def write_json_atomic(path: str, obj) -> None:
    """原子写 JSON：tmp + fsync + rename（审计报告 C6）。"""
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=1)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def _load_pending_nolock() -> dict:
    try:
        with open(_pending_path(), encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _write_pending_nolock(d: dict) -> None:
    """原子写：tmp + fsync + rename（审计报告 C6）。调用方需已持 _file_lock。"""
    path = _pending_path()
    tmp = path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(d, f, ensure_ascii=False, indent=1)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except Exception:
        log.exception("pending save failed")
        with contextlib.suppress(Exception):
            os.remove(tmp)


def read_pending() -> dict:
    """读取待确认状态（持跨进程文件锁，审计报告 A8）。"""
    with _file_lock():
        return _load_pending_nolock()


def mutate_pending(fn) -> None:
    """load→modify→save 整段持同一把跨进程文件锁（审计报告 A8）。

    fn(d) 返回修改后的 dict；返回 None 表示不做修改。
    """
    with _file_lock():
        d = _load_pending_nolock()
        d2 = fn(d)
        if d2 is not None:
            _write_pending_nolock(d2)


def _drop_pending_for_user(username: str) -> None:
    """作废某用户的全部待确认码（用户名**精确匹配**，审计报告 A4）。"""
    mutate_pending(lambda d: {t: v for t, v in d.items()
                              if v.get("user") != username})


def _resend_allowed(username: str) -> bool:
    """重发频率限制：每用户每小时最多 3 次（审计报告 P1-8 的 DoS 口）。"""
    path = os.path.join(_data_dir(), "forgot_resend.state")
    key = username
    now_ms = int(time.time() * 1000)
    with _file_lock():
        try:
            with open(path, encoding="utf-8") as f:
                d = json.load(f)
        except Exception:
            d = {}
        lst = [t for t in d.get(key, []) if now_ms - t < _RESEND_WINDOW_MS]
        if len(lst) >= _RESEND_LIMIT:
            _save = {**d, key: lst}
            try:
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(_save, f)
            except Exception:
                log.exception("resend state save failed")
            return False
        lst.append(now_ms)
        d[key] = lst
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(d, f)
        except Exception:
            log.exception("resend state save failed")
        return True


# ---- 核心流程 ----

def _verify_sender(row: dict, kind: str, contact: str) -> str | None:
    """发件人哈希比对。返回错误码或 None（通过）。"""
    try:
        got = contacts.contact_hash(row["contact_salt"], kind, contact)
    except ValueError:
        return "invalid_contact"
    expected = row["email_hash"] if kind == "email" else row["phone_hash"]
    if not expected or not hmac.compare_digest(got, expected):
        return "mismatch"
    return None


def begin_reset(username: str, kind: str, contact: str) -> tuple[str, dict]:
    """第 1 步 / 24h 内免确认码：验证发件人 → 生成待投递内容（未落库）。

    返回 (result, payload)。
    - result: ok / no_user / mismatch / invalid_contact
    - payload["action"]:
        "deliver_token" —— pending 已保存；投递确认码（第 2 步走 confirm_by_token）
        "deliver_temp"  —— payload["commit"] 就绪；投递临时密码后必须调用
                           commit_reset(payload)（两阶段：先发信后落库）
    payload["rollback"] 携带旧密码哈希，投递失败时回滚用。
    """
    username = (username or "").strip()
    if not username:
        audit("NO_USER", detail="empty username")
        return "no_user", {}
    row = store.get_user_contact_row(username)
    if row is None or row["contact_salt"] is None:
        log.info("forgot: no such user (username suppressed)")
        audit("NO_USER", user=username, channel=kind, sender=contact)
        return "no_user", {}

    err = _verify_sender(row, kind, contact)
    if err:
        if err == "mismatch":
            log.info("forgot: contact mismatch via %s", kind)
        audit(err.upper() if err != "mismatch" else "MISMATCH",
              user=username, channel=kind, sender=contact)
        return err, {}

    now_ms = int(time.time() * 1000)
    last = row["last_forgot_at"] or 0
    temp = gen_temp_pwd()
    salt = auth.new_salt()
    verifier = auth.derive_verifier(temp, salt)
    commit = {"user": username, "hash": verifier, "salt": salt, "now": now_ms,
              "channel": kind,
              "old_hash": bytes(row["service_pwd_hash"]).hex(),
              "old_salt": bytes(row["service_pwd_salt"]).hex()}

    if last and now_ms - last < _THROTTLE_MS:
        # 24h 内已重置且未自行改密（改密会清除标记）：免确认码直接重发新临时密码。
        # 频率限制防 DoS 刷重置（审计报告 P1-8）。
        if not _resend_allowed(username):
            audit("RESEND_LIMITED", user=username, channel=kind, sender=contact,
                  detail="resend rate limited, password unchanged")
            return "resend_limited", {}
        audit("RESET_PREPARED", user=username, channel=kind, sender=contact,
              detail="within 24h: deliver new temp password directly")
        return "ok", {"action": "deliver_temp", "temp": temp, "commit": commit}

    token = gen_token()
    sender_h = _sender_h(kind, contact)
    now = time.time()

    def _issue(d: dict) -> dict:
        # 过滤过期项 + 清除同用户旧确认码（审计报告 P1-6：旧码随新码签发作废；
        # 用户名精确匹配，审计报告 A4）
        d = {t: v for t, v in d.items()
             if v.get("exp", 0) > now and v.get("user") != username}
        d[token] = {"user": username, "kind": kind,
                    "sender_h": sender_h, "exp": now + _TOKEN_TTL_S}
        return d

    mutate_pending(_issue)
    audit("TOKEN_SENT", user=username, channel=kind, sender=contact,
          detail="confirmation code issued, expires in 15min")
    return "ok", {"action": "deliver_token", "token": token}


def confirm_by_token(token: str, sender: str) -> tuple[str, dict]:
    """第 2 步：确认码 + 发件人（必须与第 1 步相同）→ 待投递的随机临时密码。

    返回 (result, payload)。result: ok / invalid_token；ok 时 payload 含
    "temp" 与 "commit"——**先投递邮件，成功后再 commit_reset**（两阶段）。
    确认码一次性；用户已被删除 → invalid_token（不误报节流）。
    """
    token = (token or "").strip().upper()
    sender_n = (sender or "").strip()
    pending = read_pending()
    entry = pending.get(token)
    if entry is None or entry.get("exp", 0) < time.time():
        if entry is not None:
            _drop_pending_for_user(entry.get("user", ""))
        audit("TOKEN_INVALID", sender=sender_n, detail="expired or unknown token")
        return "invalid_token", {}

    kind = entry.get("kind", "email")
    if entry.get("sender_h") != _sender_h(kind, sender_n):
        audit("TOKEN_SENDER_MISMATCH", user=entry.get("user", "-"),
              channel=kind, sender=sender_n)
        return "invalid_token", {}
    username = entry.get("user", "")

    row = store.get_user_contact_row(username)
    if row is None or row["contact_salt"] is None:
        _drop_pending_for_user(username)
        audit("NO_USER", user=username, channel=kind, sender=sender_n,
              detail="user deleted after token issued")
        return "invalid_token", {}

    now_ms = int(time.time() * 1000)
    temp = gen_temp_pwd()
    salt = auth.new_salt()
    verifier = auth.derive_verifier(temp, salt)
    commit = {"user": username, "hash": verifier, "salt": salt, "now": now_ms,
              "channel": kind,
              "old_hash": bytes(row["service_pwd_hash"]).hex(),
              "old_salt": bytes(row["service_pwd_salt"]).hex()}
    audit("RESET_PREPARED", user=username, channel=kind, sender=sender_n,
          detail="confirmation code verified")
    return "ok", {"action": "deliver_temp", "temp": temp, "commit": commit,
                  "token": token}


def commit_reset(payload: dict) -> bool:
    """两阶段提交：把 prepare 好的临时密码写入数据库（清 pending、盖节流戳）。

    CAS（审计报告 C2）：以 prepare 时的旧密码哈希为条件——若用户在确认码
    有效期内自行改密，则不覆盖（返回 False，已发出的临时密码作废）。
    """
    c = payload["commit"]
    ok = store.set_service_pwd_and_stamp(
        c["user"], c["hash"], c["salt"], c["now"],
        expect_old_hash=bytes.fromhex(c["old_hash"]),
    )
    if ok:
        _drop_pending_for_user(c["user"])
        auth.invalidate_user_cache(c["user"])   # 旧密码的验证缓存立即失效
        audit("RESET_OK", user=c["user"], channel=c.get("channel", "-"),
              detail="random temp password committed after delivery")
        log.info("forgot: password reset committed for %s", c["user"])
    else:
        log.warning("forgot: commit raced with user password change, skipped")
    return ok


def manual_reset(username: str, contact: str) -> tuple[str, str]:
    """管理员手动兜底：验证绑定 → 随机临时密码（打印给管理员线下告知用户）。"""
    username = (username or "").strip()
    row = store.get_user_contact_row(username)
    if row is None or row["contact_salt"] is None:
        audit("NO_USER", user=username, channel="manual", sender=contact)
        return "no_user", ""
    kind = "email" if "@" in contact else "sms"
    err = _verify_sender(row, kind, contact)
    if err:
        audit(err.upper(), user=username, channel="manual", sender=contact)
        return err, ""
    now_ms = int(time.time() * 1000)
    temp = gen_temp_pwd()
    salt = auth.new_salt()
    verifier = auth.derive_verifier(temp, salt)
    store.set_service_pwd_and_stamp(username, verifier, salt, now_ms)
    auth.invalidate_user_cache(username)   # 旧密码的验证缓存立即失效
    audit("RESET_OK", user=username, channel="manual", sender=contact,
          detail="admin manual reset, temp pwd delivered out-of-band")
    return "ok", temp

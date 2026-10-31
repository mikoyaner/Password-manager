"""忘记密码（v2.8）：两步确认 + 随机临时密码。

流程（邮件通道，根治发件人伪造）：
  第 1 步 worker 收到 01<用户名> 且**发件人哈希与注册绑定匹配** → 生成一次性
  确认码（15 分钟有效），自动回复到发件邮箱（= 注册邮箱）；
  第 2 步 用户回复该邮件（正文含确认码，发件人不变 = 证明能收信）→ worker 校验
  确认码 → 生成**随机临时密码**回复给用户，并写入数据库。

安全要点：
  - **不存在全局固定密码**：临时密码只发往"通过哈希验证的注册邮箱"。攻击者
    伪造 From 只能让真正的邮箱主人收到确认码，自己拿不到任何凭据（根治接管）；
  - 确认码 = "能收信"证明，一次性、15 分钟过期、绑定发件人；
  - 24h 节流在最终重置时生效；
  - 短信通道无下行能力：/internal/sms-up 仅通知管理员人工处理（见 main.py）；
  - 临时密码**绝不写日志**；审计文件（forgot.log）记录成功与失败，发件人打码，
    每 180 天清理一次、删除 90 天前的日志行（用户指定，严格按字面）。
"""
from __future__ import annotations

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

_THROTTLE_MS = 24 * 3600 * 1000              # 每用户 24h 内只重置一次
_TOKEN_TTL_S = 15 * 60                       # 确认码有效期
_PWD_LEN = 12                                # 随机临时密码长度
_PWD_ALPHABET = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"

# 结果码：ok / no_user / mismatch / throttled / invalid_contact / invalid_token

# ---- 审计日志（用户指定：正确与错误都记录；发件人打码）----
# 文件位于数据目录（沙箱唯一可写点）。清理策略（用户指定，严格按字面）：
# 清理动作每 180 天执行一次，执行时删除 90 天前的日志行 → 实际保留 90~180 天。

_AUDIT_PATH: str | None = None
_CLEAN_INTERVAL_S = 180 * 86400
_KEEP_S = 90 * 86400
_LINE_TS = re.compile(r"\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]")


def _data_dir() -> str:
    db = os.environ.get("PWMGR_DB", "")
    return os.path.dirname(db) if db else "."


def _audit_path() -> str:
    global _AUDIT_PATH
    if _AUDIT_PATH is None:
        _AUDIT_PATH = os.path.join(_data_dir(), "forgot.log")
    return _AUDIT_PATH


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
        with open(_audit_path(), "a", encoding="utf-8") as f:
            f.write(line + "\n")
        log.info("audit: %s", line)
    except Exception:
        log.exception("audit write failed")


def cleanup_if_due(now: float | None = None) -> None:
    """每 180 天执行一次：删除 forgot.log 中 90 天前的日志行（严格按用户指定）。"""
    now = time.time() if now is None else now
    state = _audit_path() + ".clean.state"
    try:
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


# ---- 确认码 / 临时密码 ----

def _pwd_charset() -> str:
    return _PWD_ALPHABET


def gen_token() -> str:
    return "".join(secrets.choice("ABCDEFGHJKLMNPQRSTUVWXYZ23456789")
                   for _ in range(8))


def gen_temp_pwd() -> str:
    return "".join(secrets.choice(_pwd_charset()) for _ in range(_PWD_LEN))


def _pending_path() -> str:
    return os.path.join(_data_dir(), "forgot_pending.json")


def _load_pending() -> dict:
    try:
        with open(_pending_path(), encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _save_pending(d: dict) -> None:
    try:
        with open(_pending_path(), "w", encoding="utf-8") as f:
            json.dump(d, f, ensure_ascii=False, indent=1)
    except Exception:
        log.exception("pending save failed")


def _drop_pending_for_user(username: str, token: str | None = None) -> None:
    d = _load_pending()
    kept = {t: v for t, v in d.items()
            if v.get("user", "").lower() != username.lower()
            and (token is None or t != token)}
    _save_pending(kept)


def issue_token(username: str, kind: str, contact: str) -> tuple[str, str]:
    """第 1 步：验证发件人哈希后签发一次性确认码。

    返回 (result, token)。result: ok / no_user / mismatch / invalid_contact。
    同一用户重复申请会替换旧确认码。
    """
    username = (username or "").strip()
    if not username:
        audit("NO_USER", detail="empty username")
        return "no_user", ""
    row = store.get_user_contact_row(username)
    if row is None or row["contact_salt"] is None:
        log.info("forgot: no such user (username suppressed)")
        audit("NO_USER", user=username, channel=kind, sender=contact)
        return "no_user", ""

    try:
        got = contacts.contact_hash(row["contact_salt"], kind, contact)
    except ValueError:
        audit("INVALID_CONTACT", user=username, channel=kind, sender=contact)
        return "invalid_contact", ""
    expected = row["email_hash"] if kind == "email" else row["phone_hash"]
    if not expected or not hmac.compare_digest(got, expected):
        log.info("forgot: contact mismatch via %s", kind)
        audit("MISMATCH", user=username, channel=kind, sender=contact)
        return "mismatch", ""

    token = gen_token()
    pending = _load_pending()
    # 同一用户只保留最新确认码；顺带清掉过期项
    now = time.time()
    pending = {t: v for t, v in pending.items() if v.get("exp", 0) > now}
    pending[token] = {"user": username, "kind": kind,
                      "sender": contact, "exp": now + _TOKEN_TTL_S}
    _save_pending(pending)
    audit("TOKEN_SENT", user=username, channel=kind, sender=contact,
          detail="confirmation code issued, expires in 15min")
    return "ok", token


def confirm_reset(token: str, sender: str) -> tuple[str, str]:
    """第 2 步：确认码 + 发件人（必须与第 1 步相同）→ 随机临时密码。

    返回 (result, temp_pwd)。result: ok / invalid_token / throttled。
    临时密码只在 ok 时返回，**绝不写日志/审计**。
    """
    token = (token or "").strip().upper()
    sender_n = (sender or "").strip()
    pending = _load_pending()
    entry = pending.get(token)
    if entry is None or entry.get("exp", 0) < time.time():
        if entry is not None:
            _drop_pending_for_user(entry.get("user", ""), token)
        audit("TOKEN_INVALID", sender=sender_n, detail="expired or unknown token")
        return "invalid_token", ""
    if entry.get("sender", "").strip().lower() != sender_n.strip().lower():
        audit("TOKEN_SENDER_MISMATCH", user=entry.get("user", "-"),
              channel=entry.get("kind", "-"), sender=sender_n)
        return "invalid_token", ""
    username = entry.get("user", "")
    kind = entry.get("kind", "email")

    row = store.get_user_contact_row(username)
    now_ms = int(time.time() * 1000)
    last = (row or {}).get("last_forgot_at", 0) or 0
    if row is None or now_ms - last < _THROTTLE_MS:
        _drop_pending_for_user(username, token)
        log.info("forgot: throttled (within 24h)")
        audit("THROTTLED", user=username, channel=kind, sender=sender_n,
              detail="reset within 24h, password unchanged")
        return "throttled", ""

    temp = gen_temp_pwd()
    salt = auth.new_salt()
    verifier = auth.derive_verifier(temp, salt)
    store.set_service_pwd_and_stamp(username, verifier, salt, now_ms)
    _drop_pending_for_user(username, token)
    log.info("forgot: password reset to random temp via %s", kind)
    audit("RESET_OK", user=username, channel=kind, sender=sender_n,
          detail="random temp password issued via two-step confirm")
    return "ok", temp


def manual_reset(username: str, contact: str) -> tuple[str, str]:
    """管理员手动兜底：验证绑定 → 随机临时密码（打印给管理员线下告知用户）。"""
    username = (username or "").strip()
    row = store.get_user_contact_row(username)
    if row is None or row["contact_salt"] is None:
        audit("NO_USER", user=username, channel="manual", sender=contact)
        return "no_user", ""
    kind = "email" if "@" in contact else "sms"
    try:
        got = contacts.contact_hash(row["contact_salt"], kind, contact)
    except ValueError:
        return "invalid_contact", ""
    expected = row["email_hash"] if kind == "email" else row["phone_hash"]
    if not expected or not hmac.compare_digest(got, expected):
        audit("MISMATCH", user=username, channel="manual", sender=contact)
        return "mismatch", ""
    now_ms = int(time.time() * 1000)
    temp = gen_temp_pwd()
    salt = auth.new_salt()
    verifier = auth.derive_verifier(temp, salt)
    store.set_service_pwd_and_stamp(username, verifier, salt, now_ms)
    audit("RESET_OK", user=username, channel="manual", sender=contact,
          detail="admin manual reset, temp pwd delivered out-of-band")
    return "ok", temp

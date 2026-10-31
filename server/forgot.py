"""忘记密码重置核心逻辑（v2.7）。

邮件（mail_worker）、短信（/internal/sms-up webhook）、管理员手动
（manage.py forgot_reset）三条入口共用 attempt_reset：
  1) 归一化发件人联系方式，与该用户注册时存的哈希比对；
  2) 通过 24h 节流后把用户密码重置为初始密码 86868686。

安全语义：验证失败一律静默（不回复、不区分"用户不存在/联系方式不符"），
让外部无法探测账号存在性；全部尝试写审计日志（不记录明文联系方式）。
"""
from __future__ import annotations

import hmac
import logging
import os
import re
import time

import auth
import contacts
import store

log = logging.getLogger("pwmanager.forgot")

INIT_PWD = "86868686"                       # 重置后的初始密码（用户要求）
_THROTTLE_MS = 24 * 3600 * 1000             # 每用户 24h 内只重置一次

# 结果码：ok / no_user / mismatch / throttled / invalid_contact

# ---- 审计日志（用户指定：正确与错误都记录；发件人打码）----
# 文件位于数据目录（沙箱唯一可写点）。清理策略（用户指定，严格按字面）：
# 清理动作每 180 天执行一次，执行时删除 90 天前的日志行 → 实际保留 90~180 天。

_AUDIT_PATH: str | None = None
_CLEAN_INTERVAL_S = 180 * 86400
_KEEP_S = 90 * 86400
_LINE_TS = re.compile(r"\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]")


def _audit_path() -> str:
    global _AUDIT_PATH
    if _AUDIT_PATH is None:
        db = os.environ.get("PWMGR_DB", "")
        _AUDIT_PATH = (os.path.join(os.path.dirname(db), "forgot.log")
                       if db else "forgot.log")
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


def attempt_reset(username: str, kind: str, contact: str) -> str:
    """kind: "email" | "sms"。联系方式的归一化/哈希见 contacts.py。"""
    username = (username or "").strip()
    if not username:
        audit("NO_USER", detail="empty username")
        return "no_user"
    row = store.get_user_contact_row(username)
    if row is None or row["contact_salt"] is None:
        log.info("forgot: no such user (username suppressed)")
        audit("NO_USER", user=username, channel=kind, sender=contact)
        return "no_user"

    try:
        got = contacts.contact_hash(row["contact_salt"], kind, contact)
    except ValueError:
        audit("INVALID_CONTACT", user=username, channel=kind, sender=contact)
        return "invalid_contact"
    expected = row["email_hash"] if kind == "email" else row["phone_hash"]
    if not expected or not hmac.compare_digest(got, expected):
        log.info("forgot: contact mismatch via %s", kind)
        audit("MISMATCH", user=username, channel=kind, sender=contact)
        return "mismatch"

    now = int(time.time() * 1000)
    last = row["last_forgot_at"] or 0
    if now - last < _THROTTLE_MS:
        log.info("forgot: throttled (within 24h)")
        audit("THROTTLED", user=username, channel=kind, sender=contact,
              detail="reset within 24h, password unchanged")
        return "throttled"

    salt = auth.new_salt()
    verifier = auth.derive_verifier(INIT_PWD, salt)
    store.set_service_pwd_and_stamp(username, verifier, salt, now)
    log.info("forgot: password reset to initial via %s", kind)
    audit("RESET_OK", user=username, channel=kind, sender=contact)
    return "ok"

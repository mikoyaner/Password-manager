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
import time

import auth
import contacts
import store

log = logging.getLogger("pwmanager.forgot")

INIT_PWD = "86868686"                       # 重置后的初始密码（用户要求）
_THROTTLE_MS = 24 * 3600 * 1000             # 每用户 24h 内只重置一次

# 结果码：ok / no_user / mismatch / throttled / invalid_contact


def attempt_reset(username: str, kind: str, contact: str) -> str:
    """kind: "email" | "sms"。联系方式的归一化/哈希见 contacts.py。"""
    username = (username or "").strip()
    if not username:
        return "no_user"
    row = store.get_user_contact_row(username)
    if row is None or row["contact_salt"] is None:
        log.info("forgot: no such user (username suppressed)")
        return "no_user"

    try:
        got = contacts.contact_hash(row["contact_salt"], kind, contact)
    except ValueError:
        return "invalid_contact"
    expected = row["email_hash"] if kind == "email" else row["phone_hash"]
    if not expected or not hmac.compare_digest(got, expected):
        log.info("forgot: contact mismatch via %s", kind)
        return "mismatch"

    now = int(time.time() * 1000)
    last = row["last_forgot_at"] or 0
    if now - last < _THROTTLE_MS:
        log.info("forgot: throttled (within 24h)")
        return "throttled"

    salt = auth.new_salt()
    verifier = auth.derive_verifier(INIT_PWD, salt)
    store.set_service_pwd_and_stamp(username, verifier, salt, now)
    log.info("forgot: password reset to initial via %s", kind)
    return "ok"

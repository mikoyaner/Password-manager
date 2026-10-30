"""找回密码邮件轮询 worker（v2.7 一期：邮箱找回全自动）。

由 pwmanager-mail.timer 每 60s 触发一次（单次执行后退出）：
  IMAP 取管理员邮箱未读邮件 → 主题/正文找 01<用户名> → 归一化发件人邮箱 →
  与注册哈希比对 → 重置为 86868686 → SMTP 回复原邮件 → 无论结果一律标记已读。

配置全部来自环境变量（systemd EnvironmentFile=admin.env 注入）：
  PWMGR_IMAP_HOST / PWMGR_IMAP_USER / PWMGR_IMAP_PASS
  PWMGR_SMTP_HOST / PWMGR_SMTP_PORT / PWMGR_SMTP_USER / PWMGR_SMTP_PASS
  PWMGR_ADMIN_EMAIL（回复时的发件人 = 接收找回邮件的同一邮箱）
IMAP/SMTP 未配置时打印提示并以 0 退出（先上线代码、后补配置）。

安全：验证失败的邮件静默忽略（不回复，不泄露账号存在性），但标记已读。
"""
from __future__ import annotations

import imaplib
import logging
import os
import re
import smtplib
import sys
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import parseaddr

import forgot

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(name)s %(levelname)s %(message)s")
log = logging.getLogger("pwmanager.mail")

# 邮件里的找回码：01<用户名>（负向断言防止匹配更长串的前缀）
_CODE_RE = re.compile(r"01([a-zA-Z0-9._-]{3,20})(?![a-zA-Z0-9._-])")

RESET_REPLY = (
    "你的用户密码已重置为初始密码：86868686\n\n"
    "请使用该密码登录，并立即在客户端『修改用户密码』中设置新密码。\n"
    "（本邮件由系统自动发送）"
)


def _extract_code(text: str) -> str | None:
    m = _CODE_RE.search(text or "")
    return m.group(1) if m else None


def _message_text(msg) -> str:
    """主题 + 所有 text/plain 部件拼接（找回码可能写在主题或正文）。"""
    parts = [str(msg.get("Subject", ""))]
    if msg.is_multipart():
        for p in msg.walk():
            if p.get_content_type() == "text/plain":
                try:
                    parts.append(p.get_content())
                except Exception:
                    parts.append(p.get_payload(decode=True).decode("utf-8", "replace"))
    elif msg.get_content_type() == "text/plain":
        try:
            parts.append(msg.get_content())
        except Exception:
            parts.append(msg.get_payload(decode=True).decode("utf-8", "replace"))
    return "\n".join(parts)


def _smtp_send_reply(to_addr: str) -> None:
    admin = os.environ["PWMGR_ADMIN_EMAIL"]
    host = os.environ["PWMGR_SMTP_HOST"]
    port = int(os.environ.get("PWMGR_SMTP_PORT", "465"))
    user = os.environ["PWMGR_SMTP_USER"]
    pwd = os.environ["PWMGR_SMTP_PASS"]

    mail = EmailMessage()
    mail["From"] = admin
    mail["To"] = to_addr
    mail["Subject"] = "密码重置完成"
    mail.set_content(RESET_REPLY)

    if port == 465:
        server = smtplib.SMTP_SSL(host, port, timeout=30)
    else:
        server = smtplib.SMTP(host, port, timeout=30)
        server.starttls()
    try:
        server.login(user, pwd)
        server.send_message(mail)
    finally:
        server.quit()
    log.info("replied to requester")


def _process_message(raw: bytes) -> None:
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    sender = parseaddr(str(msg.get("From", "")))[1]
    code = _extract_code(_message_text(msg))
    if not code or not sender:
        log.info("mail without code/sender: marked read, ignored")
        return
    result = forgot.attempt_reset(code, "email", sender)
    if result == "ok":
        try:
            _smtp_send_reply(sender)
        except Exception:
            log.exception("reset ok but reply failed (user can still log in)")
    elif result == "throttled":
        # 24h 内已重置过：回复提示而不是静默，避免用户以为没处理
        try:
            _smtp_send_reply(sender)
        except Exception:
            log.exception("throttle reply failed")
        log.info("throttled reset request")


def main() -> int:
    imap_host = os.environ.get("PWMGR_IMAP_HOST", "")
    imap_user = os.environ.get("PWMGR_IMAP_USER", "")
    imap_pass = os.environ.get("PWMGR_IMAP_PASS", "")
    if not (imap_host and imap_user and imap_pass):
        log.info("IMAP 未配置（admin.env），本次跳过")
        return 0

    imap = imaplib.IMAP4_SSL(imap_host)
    try:
        imap.login(imap_user, imap_pass)
        imap.select("INBOX")
        typ, data = imap.search(None, "UNSEEN")
        if typ != "OK":
            log.warning("IMAP search failed: %s", typ)
            return 1
        ids = data[0].split()
        log.info("unseen mails: %d", len(ids))
        for num in ids:
            typ, parts = imap.fetch(num, "(RFC822)")
            if typ != "OK" or not parts or parts[0] is None:
                continue
            raw = parts[0][1]
            try:
                _process_message(raw)
            except Exception:
                log.exception("failed to process one mail")
            # 无论成功/失败/无码，都标记已读，避免同一封邮件反复处理
            imap.store(num, "+FLAGS", "\\Seen")
        return 0
    finally:
        try:
            imap.logout()
        except Exception:
            pass


if __name__ == "__main__":
    sys.exit(main())

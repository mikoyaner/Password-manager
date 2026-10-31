"""找回密码邮件轮询 worker（v2.8：两步确认 + 随机临时密码）。

由 pwmanager-mail.timer 每 60s 触发一次（单次执行后退出）：
  IMAP 取管理员邮箱未读邮件（BODY.PEEK，不打乱未读状态）→
  - 含 01<用户名> 且发件人哈希匹配 → 自动回复**确认码**（15 分钟有效）→ 标已读；
  - 含待确认的**确认码**（发件人相同）→ 生成随机临时密码回复用户 → 重置 → 标已读；
  - 验证失败（码存在但发件人不匹配）→ 丢弃 + 标已读；
  - 其他无关邮件：**保持未读、不改动**（Message-ID 记入状态文件防重复扫描）。

配置全部来自环境变量（systemd EnvironmentFile=mail.env 注入）：
  PWMGR_IMAP_HOST / PWMGR_IMAP_USER / PWMGR_IMAP_PASS
  PWMGR_SMTP_HOST / PWMGR_SMTP_PORT / PWMGR_SMTP_USER / PWMGR_SMTP_PASS
未配置时打印提示并以 0 退出（先上线代码、后补配置）。

安全：临时密码只回复给"通过哈希验证的发件邮箱"，伪造 From 的邮件即使被处理，
确认码/临时密码也只会发往真正的邮箱主人；验证失败静默丢弃；临时密码绝不写日志。
每轮最多处理 10 封（Argon2 放大防护，见审计报告 P1-8）。
"""
from __future__ import annotations

import hashlib
import html as _html
import imaplib
import json
import logging
import os
import re
import smtplib
import sys
import time
from datetime import datetime, timezone
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import parseaddr, parsedate_to_datetime

import forgot

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(name)s %(levelname)s %(message)s")
log = logging.getLogger("pwmanager.mail")

# 邮件里的找回码：01<用户名>（允许 01 与用户名之间有空格；大小写不敏感——
# 查库时用 COLLATE NOCASE；负向断言防止匹配更长串的前缀）
_CODE_RE = re.compile(r"01\s*([a-zA-Z0-9._-]{3,20})(?![a-zA-Z0-9._-])", re.IGNORECASE)

# 用户指定：邮件接收时间与服务器时间相差不得超过 60 分钟，超时旧邮件直接丢弃
_FRESH_SECONDS = 60 * 60
_HTML_TAG = re.compile(r"<[^>]+>")
_MAX_PROCESSED_PER_RUN = 10   # 每轮最多处理的找回邮件数（Argon2 放大防护）
_SCAN_STATE_MAX = 500         # 无关邮件 Message-ID 去重状态上限


def _scan_state_path() -> str:
    return forgot._audit_path() + ".scan.json"


def _load_scan_state() -> set:
    try:
        with open(_scan_state_path(), encoding="utf-8") as f:
            return set(json.load(f).get("seen_ids", []))
    except Exception:
        return set()


def _save_scan_state(ids: set) -> None:
    try:
        keep = list(ids)[-_SCAN_STATE_MAX:]
        with open(_scan_state_path(), "w", encoding="utf-8") as f:
            json.dump({"seen_ids": keep}, f)
    except Exception:
        log.exception("scan state save failed")


def _mail_id(msg, raw: bytes) -> str:
    mid = str(msg.get("Message-ID", "")).strip()
    if mid:
        return mid
    return "sha1:" + hashlib.sha1(raw).hexdigest()


def _part_text(p) -> str:
    try:
        return p.get_content()
    except Exception:
        try:
            return p.get_payload(decode=True).decode("utf-8", "replace")
        except Exception:
            return ""


def _message_text(msg) -> str:
    """主题 + 正文文本。

    网页版邮箱（189/126 等）默认只发 HTML：没有纯文本部分时剥掉 HTML 标签
    参与匹配，否则正文里的验证码会读不到。
    """
    parts = [str(msg.get("Subject", ""))]
    plains, htmls = [], []
    if msg.is_multipart():
        for p in msg.walk():
            ct = p.get_content_type()
            if ct == "text/plain":
                plains.append(_part_text(p))
            elif ct == "text/html":
                htmls.append(_part_text(p))
    else:
        ct = msg.get_content_type()
        if ct == "text/plain":
            plains.append(_part_text(msg))
        elif ct == "text/html":
            htmls.append(_part_text(msg))
    parts += plains if plains else htmls
    text = "\n".join(parts)
    if htmls and not plains:
        text = _html.unescape(_HTML_TAG.sub(" ", text))
    return text


def _extract_code(text: str) -> str | None:
    m = _CODE_RE.search(text or "")
    return m.group(1) if m else None


def _find_pending_token(text: str, sender: str) -> str | None:
    """正文/主题里是否包含该发件人名下的待确认码。"""
    pending = forgot._load_pending()
    for token, entry in pending.items():
        if entry.get("sender", "").strip().lower() != sender.strip().lower():
            continue
        if entry.get("exp", 0) < time.time():
            continue
        if token.lower() in (text or "").lower():
            return token
    return None


def _is_fresh(msg) -> bool:
    """用户指定：邮件接收时间与服务器时间相差不大于 60 分钟，否则丢弃。"""
    d = msg.get("Date")
    if not d:
        return False
    try:
        dt = parsedate_to_datetime(str(d))
    except Exception:
        return False
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return abs((datetime.now(timezone.utc) - dt).total_seconds()) <= _FRESH_SECONDS


def _smtp_send(to_addr: str, subject: str, body: str) -> None:
    admin = os.environ["PWMGR_ADMIN_EMAIL"]
    host = os.environ["PWMGR_SMTP_HOST"]
    port = int(os.environ.get("PWMGR_SMTP_PORT", "465"))
    user = os.environ["PWMGR_SMTP_USER"]
    pwd = os.environ["PWMGR_SMTP_PASS"]

    mail = EmailMessage()
    mail["From"] = admin
    mail["To"] = to_addr
    mail["Subject"] = subject
    mail.set_content(body)

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


def _process_message(msg, raw: bytes) -> str:
    """处理一封未读邮件，返回 'code' / 'token' / 'skip'。

    'code'   = 带找回码的邮件（应答后标已读）
    'token'  = 带确认码的邮件（应答后标已读）
    'skip'   = 无关邮件（保持未读，仅记录扫描状态）
    """
    sender = parseaddr(str(msg.get("From", "")))[1]
    text = _message_text(msg)

    if not _is_fresh(msg):
        log.info("mail older than %ds: discarded", _FRESH_SECONDS)
        forgot.audit("FRESH_SKIP", user="-", channel="email", sender=sender,
                     detail="mail older than 60min, discarded")
        return "skip"

    if sender:
        token = _find_pending_token(text, sender)
        if token:
            result, temp = forgot.confirm_reset(token, sender)
            if result == "ok":
                _smtp_send(sender, "您的临时密码",
                           "你的用户密码已重置为随机临时密码：\n\n"
                           f"{temp}\n\n"
                           "请立即用它登录，并马上在客户端『修改用户密码』中"
                           "设置你自己的新密码。\n（本邮件由系统自动发送）")
                log.info("two-step reset completed")
                return "token"
            if result == "throttled":
                _smtp_send(sender, "密码重置请求已收到",
                           "该账号 24 小时内已处理过重置。如果当时的新密码不是你设置的，"
                           "请检查重置邮件；若你已自行修改过密码，请直接用新密码登录。")
                log.info("two-step reset throttled")
                return "token"
            log.info("token confirm failed: %s", result)
            return "skip"

    code = _extract_code(text)
    if not code or not sender:
        log.info("mail without code/token: left unread")
        return "skip"

    result, token = forgot.issue_token(code, "email", sender)
    if result == "ok":
        _smtp_send(sender, "密码重置确认码",
                   f"确认码：{token}\n\n"
                   f"有效期 15 分钟。请**回复本邮件**（或用同一邮箱再发一封），"
                   f"正文中包含该确认码，系统确认后会把随机临时密码发送到本邮箱。\n"
                   "（本邮件由系统自动发送）")
        log.info("confirmation code issued")
        return "code"
    if result == "mismatch":
        # 验证码存在但发件人与注册绑定不符：按用户规格丢弃 + 标已读
        log.info("code with mismatched sender: discarded")
        forgot.audit("MISMATCH_DISCARD", user=code, channel="email", sender=sender)
        return "code"
    if result == "no_user":
        log.info("code for unknown user: discarded")
        forgot.audit("NO_USER", user=code, channel="email", sender=sender)
        return "code"
    log.info("issue failed: %s", result)
    return "skip"


def main() -> int:
    imap_host = os.environ.get("PWMGR_IMAP_HOST", "")
    imap_user = os.environ.get("PWMGR_IMAP_USER", "")
    imap_pass = os.environ.get("PWMGR_IMAP_PASS", "")
    # 审计日志清理（用户指定：每 180 天执行一次，删除 90 天前的日志行）
    forgot.cleanup_if_due()
    if not (imap_host and imap_user and imap_pass):
        log.info("IMAP 未配置（mail.env），本次跳过")
        return 0

    seen_ids = _load_scan_state()
    imap = imaplib.IMAP4_SSL(imap_host)
    try:
        imap.login(imap_user, imap_pass)
        # 网易（163/126）IMAP 的防滥用要求：登录后必须先发 ID 命令标识客户端，
        # 否则后续 SELECT 会被拒绝。其他服务商不支持 ID 时静默忽略。
        try:
            imaplib.Commands["ID"] = ("AUTH", "SELECTED")
            imap._simple_command("ID", '("name" "PwdMgr" "version" "1.0")')
        except Exception:
            pass
        typ, _ = imap.select("INBOX")
        if typ != "OK":
            raise RuntimeError(f"IMAP select INBOX failed: {typ}")
        typ, data = imap.search(None, "UNSEEN")
        if typ != "OK":
            log.warning("IMAP search failed: %s", typ)
            return 1
        ids = data[0].split()
        log.info("unseen mails: %d", len(ids))

        processed = 0
        for num in ids:
            # BODY.PEEK：不打乱未读状态；无关邮件保持原样（用户指定）
            typ, parts = imap.fetch(num, "(BODY.PEEK[])")
            if typ != "OK" or not parts or parts[0] is None:
                log.warning("IMAP fetch failed for num=%s: typ=%s parts=%s",
                            num, typ, len(parts) if parts else 0)
                continue
            raw = parts[0][1]
            msg = BytesParser(policy=policy.default).parsebytes(raw)
            try:
                kind = _process_message(msg, raw)
            except Exception:
                log.exception("failed to process one mail")
                kind = "skip"
            mid = _mail_id(msg, raw)
            if kind in ("code", "token"):
                # 用户指定：只有找回相关的邮件才标已读
                imap.store(num, "+FLAGS", "\\Seen")
                seen_ids.add(mid)
                processed += 1
                if processed >= _MAX_PROCESSED_PER_RUN:
                    log.info("per-run processing cap reached (%d)", processed)
                    break
            else:
                seen_ids.add(mid)   # 无关邮件不标已读，仅去重防重复扫描
        _save_scan_state(seen_ids)
        return 0
    finally:
        try:
            imap.logout()
        except Exception:
            pass


if __name__ == "__main__":
    sys.exit(main())

"""找回密码邮件轮询 worker（v2.8：两步确认 + 随机临时密码 + 两阶段投递）。

由 pwmanager-mail.timer 每 60s 触发一次（单次执行后退出）：
  IMAP 取管理员邮箱未读邮件（BODY.PEEK，不打乱未读状态）→
  - 含 01<用户名> 且发件人哈希匹配 →
      24h 内已重置且未改密：直接回复**新的随机临时密码**（免确认码，用户要求）；
      否则回复**确认码**（15 分钟有效）→ 标已读；
  - 含待确认的**确认码**（发件人相同）→ 回复**随机临时密码** → 落库 → 标已读；
  - 验证失败（码存在但发件人不匹配/用户不存在）→ 丢弃 + 标已读；
  - 其他无关邮件：**保持未读、不改动**（Message-ID 记入状态文件防重复扫描）。

投递安全（审计报告 P0-2）：临时密码邮件**发送成功后才写数据库**；
SMTP 失败自动回滚（CAS 保留用户可能已自行设置的新密码）、确认码保留、
邮件保持未读下轮自动重试；同一封连续失败 3 轮后放弃并审计 DELIVER_GIVEUP。

配置全部来自环境变量（systemd EnvironmentFile=mail.env 注入）：
  PWMGR_IMAP_HOST / PWMGR_IMAP_USER / PWMGR_IMAP_PASS
  PWMGR_SMTP_HOST / PWMGR_SMTP_PORT / PWMGR_SMTP_USER / PWMGR_SMTP_PASS
未配置 SMTP 时整轮跳过处理并明确告警（找回无法投递，处理无意义）；
PWMGR_CONTACT_PEPPER 缺失时同样拒绝处理（确认码发件人哈希无法安全计算）。

安全：临时密码只回复给"通过哈希验证的发件邮箱"，伪造 From 的邮件即使被处理，
确认码/临时密码也只会发往真正的邮箱主人；验证失败静默丢弃；临时密码绝不写日志。
每轮最多处理 10 封（Argon2 放大防护，审计报告 P1-8）。
"""
from __future__ import annotations

import hashlib
import html as _html
import imaplib
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

# 邮件里的找回码：01<用户名>（允许 01 与用户名之间有空格；用户名**精确匹配**——
# 注册/找回全链路大小写敏感，见审计报告 P0-3；负向断言防止匹配更长串的前缀）
_CODE_RE = re.compile(r"01\s*([a-zA-Z0-9._-]{3,20})(?![a-zA-Z0-9._-])")

# 用户指定：邮件接收时间与服务器时间相差不得超过 60 分钟，超时旧邮件直接丢弃
_FRESH_SECONDS = 60 * 60
_HTML_TAG = re.compile(r"<[^>]+>")
_MAX_PROCESSED_PER_RUN = 10   # 每轮最多处理的找回邮件数（Argon2 放大防护，P1-8）
_SCAN_STATE_MAX = 500         # 状态文件上限（seen_ids + 重试计数）
_RETRY_GIVEUP_ROUNDS = 3      # 同一封邮件连续投递失败 3 轮后放弃（A1）


def _state_path() -> str:
    return forgot._audit_path() + ".scan.json"


def _load_state() -> tuple[set, dict]:
    try:
        with open(_state_path(), encoding="utf-8") as f:
            d = json.load(f)
        return set(d.get("seen_ids", [])), dict(d.get("retries", {}))
    except Exception:
        return set(), {}


def _save_state(seen_ids: set, retries: dict) -> None:
    forgot.write_json_atomic(_state_path(), {
        "seen_ids": sorted(seen_ids)[-_SCAN_STATE_MAX:],
        "retries": {k: v for k, v in list(retries.items())[-_SCAN_STATE_MAX:]},
    })


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
    pending = forgot.read_pending()
    for token, entry in pending.items():
        if entry.get("sender_h") != forgot.sender_hash_for(
                entry.get("kind", "email"), sender):
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
    """发送邮件。发件人优先 PWMGR_ADMIN_EMAIL，缺失回退 SMTP_USER（P0-1）。"""
    admin = os.environ.get("PWMGR_ADMIN_EMAIL") or os.environ["PWMGR_SMTP_USER"]
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


def _smtp_send_retry(to_addr: str, subject: str, body: str, attempts: int = 2) -> bool:
    """发送（带一次重试）。全部失败返回 False——调用方据此转入待重试。"""
    for i in range(attempts):
        try:
            _smtp_send(to_addr, subject, body)
            return True
        except Exception:
            log.exception("smtp send failed (attempt %d/%d)", i + 1, attempts)
    return False


def _process_message(msg, raw: bytes) -> tuple[str, str]:
    """处理一封未读邮件，返回 (类别, 发件人)。

    'handled'    = 终态（投递成功 / 按规格丢弃）→ 标已读
    'retry'      = 投递暂时失败 → 保持未读、不进去重状态，下一轮重试
    'unrelated'  = 无关邮件 → 保持未读，仅记入去重状态
    """
    sender = parseaddr(str(msg.get("From", "")))[1]
    text = _message_text(msg)

    if not _is_fresh(msg):
        log.info("mail older than %ds: discarded", _FRESH_SECONDS)
        forgot.audit("FRESH_SKIP", user="-", channel="email", sender=sender,
                     detail="mail older than 60min, discarded")
        return "handled", sender

    if sender:
        token = _find_pending_token(text, sender)
        if token:
            result, payload = forgot.confirm_by_token(token, sender)
            if result == "ok":
                sent = _smtp_send_retry(
                    sender, "您的临时密码",
                    f"临时密码：{payload['temp']}\n\n"
                    "请立即用它登录，并马上在客户端『修改用户密码』中"
                    "设置你自己的新密码。\n（本邮件由系统自动发送）")
                if sent:
                    forgot.commit_reset(payload)
                    forgot.audit("RESET_DELIVERED", user=payload["user"],
                                 channel="email", sender=sender,
                                 detail="temp password emailed and committed")
                    log.info("two-step reset completed")
                    return "handled", sender
                log.warning("temp delivery failed: token retained, will retry")
                forgot.audit("DELIVER_FAILED", user=payload["user"],
                             channel="email", sender=sender,
                             detail="temp mail delivery failed, token retained, will retry")
                return "retry", sender
            # invalid_token：确认码过期/未知/发件人不符——终态，标已读
            log.info("token confirm failed: %s", result)
            return "handled", sender

    code = _extract_code(text)
    if not code or not sender:
        log.info("mail without code/token: left unread")
        return "unrelated", sender

    result, payload = forgot.begin_reset(code, "email", sender)
    if result == "ok":
        action = payload["action"]
        if action == "deliver_token":
            sent = _smtp_send_retry(
                sender, "密码重置确认码",
                f"验证码：{payload['token']}\n\n"
                f"有效期 15 分钟。\n\n"
                "操作步骤：**复制上面的验证码，新建一封空白邮件**（收件人填写本邮箱地址），"
                "把验证码粘贴到正文后发送。系统确认后会把随机临时密码发送到本邮箱。\n"
                "注意：请勿直接回复本邮件。")
            if sent:
                log.info("confirmation code issued")
                forgot.audit("TOKEN_DELIVERED", user=code, channel="email",
                             sender=sender, detail="confirmation code emailed")
                return "handled", sender
            log.warning("token mail delivery failed: mail left unread for retry")
            forgot.audit("DELIVER_FAILED", user=code, channel="email",
                         sender=sender,
                         detail="confirmation mail delivery failed, will retry")
            return "retry", sender
        if action == "deliver_temp":
            sent = _smtp_send_retry(
                sender, "您的临时密码",
                f"临时密码：{payload['temp']}\n\n"
                "请立即用它登录，并马上在客户端『修改用户密码』中"
                "设置你自己的新密码。如非本人操作，请立即检查邮箱安全。\n"
                "（本邮件由系统自动发送）")
            if sent:
                forgot.commit_reset(payload)
                forgot.audit("RESET_DELIVERED", user=code, channel="email",
                             sender=sender,
                             detail="temp password emailed and committed (24h resend)")
                log.info("24h direct temp delivered and committed")
            else:
                log.warning("temp delivery failed: mail left unread for retry")
                forgot.audit("DELIVER_FAILED", user=code, channel="email",
                             sender=sender,
                             detail="temp mail delivery failed, will retry")
                return "retry", sender
            return "handled", sender
        # resend_limited：不投递、不改密（P1-8 防护）
        log.info("resend rate limited: discarded")
        forgot.audit("RESEND_LIMITED", user=code, channel="email", sender=sender)
        return "handled", sender
    # mismatch / no_user / invalid_contact：按用户规格丢弃 + 标已读
    log.info("reset request rejected: %s", result)
    return "handled", sender


def main() -> int:
    imap_host = os.environ.get("PWMGR_IMAP_HOST", "")
    imap_user = os.environ.get("PWMGR_IMAP_USER", "")
    imap_pass = os.environ.get("PWMGR_IMAP_PASS", "")
    smtp_ready = all(os.environ.get(k) for k in
                     ("PWMGR_SMTP_HOST", "PWMGR_SMTP_USER", "PWMGR_SMTP_PASS"))
    # 审计日志清理（用户指定：每 180 天执行一次，删除 90 天前的日志行）
    forgot.cleanup_if_due()
    if not (imap_host and imap_user and imap_pass):
        log.info("IMAP 未配置（mail.env），本次跳过")
        return 0
    if not smtp_ready:
        # 审计报告 P0-2：无法投递临时密码时绝不执行重置，避免把用户锁在门外
        log.warning("SMTP 未配置（mail.env 缺 PWMGR_SMTP_*）："
                    "找回邮件无法投递，本轮跳过处理")
        return 0
    if not os.environ.get("PWMGR_CONTACT_PEPPER"):
        # 审计报告 A5：确认码发件人哈希需要 pepper，缺失时拒绝该功能而不是降级
        log.warning("PWMGR_CONTACT_PEPPER 未配置（api.env）："
                    "确认码发件人哈希无法安全计算，本轮跳过处理")
        return 0

    seen_ids, retries = _load_state()
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
            mid = _mail_id(msg, raw)
            if mid in seen_ids:
                continue   # 已扫描过（终态或放弃）：跳过，仍保持未读
            try:
                kind, sender = _process_message(msg, raw)
            except Exception:
                log.exception("failed to process one mail")
                kind, sender = "retry", ""
            if kind == "retry":
                n = retries.get(mid, 0) + 1
                retries[mid] = n
                if n >= _RETRY_GIVEUP_ROUNDS:
                    # 连续 3 轮投递失败：放弃（保持未读、进入去重状态，不再重试）
                    imap.store(num, "+FLAGS", "\\Seen")
                    seen_ids.add(mid)
                    retries.pop(mid, None)
                    forgot.audit("DELIVER_GIVEUP", channel="email", sender=sender,
                                 detail=f"delivery failed {n} consecutive rounds, giving up")
                _save_state(seen_ids, retries)
                continue
            if kind == "handled":
                imap.store(num, "+FLAGS", "\\Seen")
                seen_ids.add(mid)
                retries.pop(mid, None)
                processed += 1
                if processed >= _MAX_PROCESSED_PER_RUN:
                    log.info("per-run processing cap reached (%d)", processed)
                    break
            else:   # unrelated：保持未读，仅记入去重状态
                seen_ids.add(mid)
                retries.pop(mid, None)
            _save_state(seen_ids, retries)
        return 0
    finally:
        try:
            imap.logout()
        except Exception:
            pass


if __name__ == "__main__":
    sys.exit(main())

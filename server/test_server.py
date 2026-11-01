"""同步服务器 v2.3 端到端测试。

用 FastAPI TestClient 在进程内跑通：health/注册/鉴权/多版本 FIFO/属主隔离/
改用户密码/注销/限流。使用临时数据库，不污染生产库。

运行: python test_server.py
"""
import base64
import json
import os
import tempfile

# 用临时数据库，必须在 import store 前设置
_tmp = tempfile.mkdtemp()
os.environ["PWMGR_DB"] = os.path.join(_tmp, "test.db")
os.environ["PWMGR_REG_PER_HOUR"] = "1000"  # 测试环境放开注册限流
os.environ["PWMGR_CONTACT_PEPPER"] = "test-pepper"  # 找回哈希测试用

from fastapi.testclient import TestClient  # noqa: E402

import auth  # noqa: E402
import main  # noqa: E402
import store  # noqa: E402


def _auth(user: str, pwd: str) -> dict:
    raw = f"{user}:{pwd}".encode("utf-8")
    return {"Authorization": "Basic " + base64.b64encode(raw).decode("ascii")}


def _reg(c, user, pwd, **kw) -> object:
    body = {"username": user, "service_pwd": pwd,
            "email": f"{user}@example.com", "phone": ""}
    body.update(kw)
    return c.post("/register", json=body)


def _vault(seed: int) -> str:
    return base64.b64encode(b"\x00" * 49 + f"cipher-{seed}".encode()).decode()


def run():
    store.init_db()
    c = TestClient(main.app)

    # 1. health 不再暴露账号数
    r = c.get("/health")
    assert r.status_code == 200 and r.json() == {"status": "ok"}, r.text

    # 1b. 超大请求体（分块发送，没有 Content-Length）也必须是 413
    def _big_chunks():
        chunk = b"x" * (1024 * 1024)
        for _ in range(13):
            yield chunk

    r = c.post("/register", content=_big_chunks(),
               headers={"Content-Type": "application/json"})
    assert r.status_code == 413, (r.status_code, r.text[:200])

    # 2. 注册：仅建账号，云端零库
    r = _reg(c, "alice", "password123")
    assert r.status_code == 200 and r.json()["first_vid"] is None, r.text
    assert c.get("/vaults", headers=_auth("alice", "password123")).json() == {"vaults": []}
    # 重复用户名 / 非法用户名 / 无联系方式
    assert _reg(c, "alice", "password123").status_code == 409
    assert _reg(c, "1", "password123").status_code == 400
    assert _reg(c, "bob", "password123", email="", phone="").status_code == 400
    assert _reg(c, "bob", "password123", email="bad", phone="").status_code == 400

    # 3. 密文非法时不得留下半个账号
    assert _reg(c, "carol", "password123", pwd_time=1, ciphertext="!!!").status_code == 400
    assert _reg(c, "carol", "password123").status_code == 200, "carol 被半注册"

    # 3b. 并发重名：绕过 user_exists 预检后由唯一约束兜底，必须是 409 而不是 500
    real_exists = store.user_exists
    store.user_exists = lambda u: False
    try:
        r = _reg(c, "alice", "password123")
        assert r.status_code == 409, (r.status_code, r.text)
    finally:
        store.user_exists = real_exists
    # 首版库写入失败时整体回滚：直接用重复用户名调事务函数
    import sqlite3 as _sqlite3
    try:
        store.create_user_and_vault(
            username="alice", service_pwd_hash=b"\x00" * 32,
            service_pwd_salt=b"\x00" * 16, contact_salt=b"\x00" * 16,
            email_hash=b"\x00" * 32, phone_hash=None,
            pwd_time=1, label="x", ciphertext=b"c", ciphertext_sha256="0" * 64)
        raise AssertionError("重复用户名应抛 IntegrityError")
    except _sqlite3.IntegrityError:
        pass
    assert len(c.get("/vaults", headers=_auth("alice", "password123")).json()["vaults"]) == 0

    # 4. 鉴权
    assert c.get("/vaults").status_code == 401
    assert c.get("/vaults", headers=_auth("alice", "wrong-password")).status_code == 401
    assert c.get("/vaults", headers=_auth("nobody", "password123")).status_code == 401

    # 5. 注册时携带首版库
    r = _reg(c, "dave", "password123", pwd_time=1000, label="初始", ciphertext=_vault(0))
    assert r.status_code == 200 and isinstance(r.json()["first_vid"], int), r.text
    dave_vid = r.json()["first_vid"]
    assert len(c.get("/vaults", headers=_auth("dave", "password123")).json()["vaults"]) == 1

    # 6. 多版本：每次 PUT 新增一份，最多保留 5 份
    a = _auth("dave", "password123")
    for i in range(1, 7):
        r = c.put("/vault", headers=a, json={"pwd_time": 1000 + i,
                                             "label": f"v{i}",
                                             "ciphertext": _vault(i)})
        assert r.status_code == 200, r.text
    vs = c.get("/vaults", headers=a).json()["vaults"]
    assert len(vs) == 5, vs
    assert vs[0]["label"] == "v6" and vs[-1]["label"] == "v2", vs

    # 7. 属主隔离：bob 拿不到 dave 的 vid
    bob = _auth("carol", "password123")
    assert c.get(f"/vault/{dave_vid}", headers=bob).status_code == 404
    assert c.get("/vaults", headers=bob).json() == {"vaults": []}

    # 8. 改用户密码（当前密码由 Basic 证明）
    assert c.post("/change_service_pwd", headers=_auth("dave", "password123"),
                  json={"new_pwd": "newpassword1"}).status_code == 200
    assert c.get("/vaults", headers=_auth("dave", "password123")).status_code == 401
    assert c.get("/vaults", headers=_auth("dave", "newpassword1")).status_code == 200

    # 9. 注销：必须 confirm，级联删库
    assert c.request("DELETE", "/account", headers=_auth("dave", "newpassword1"),
                     json={"confirm": False}).status_code == 400
    assert c.request("DELETE", "/account", headers=_auth("dave", "newpassword1"),
                     json={"confirm": True}).status_code == 200
    assert c.get("/vaults", headers=_auth("dave", "newpassword1")).status_code == 401

    # 10. X-Forwarded-For 不再能绕过限流
    auth._attempts.clear()
    for i in range(5):
        r = c.get("/vaults", headers={**_auth("alice", "wrong-password"),
                                      "X-Forwarded-For": f"10.9.9.{i}"})
        assert r.status_code == 401, (i, r.text)
    r = c.get("/vaults", headers={**_auth("alice", "wrong-password"),
                                  "X-Forwarded-For": "10.9.9.99"})
    assert r.status_code == 429, r.text

    # 11. 忘记密码 v2.8：联系方式哈希存储 + 两步确认 + 随机临时密码
    auth._attempts.clear()
    auth._pwd_cache.clear()
    import re as _re  # noqa: E402
    import forgot as forgot_mod  # noqa: E402
    import sqlite3 as _s  # noqa: E402

    r = _reg(c, "erin", "password123", email="Erin@Example.COM ")
    assert r.status_code == 200, r.text
    conn = _s.connect(os.environ["PWMGR_DB"])
    conn.row_factory = _s.Row
    row = conn.execute("SELECT email, contact_salt, email_hash, email_uniq FROM users "
                       "WHERE username='erin'").fetchone()
    assert row["email"] == "", "明文邮箱必须清空"
    assert row["contact_salt"] and row["email_hash"] and row["email_uniq"],         "哈希列与查重列必须写入"
    conn.close()

    # 错误发件人：签发被拒（不产生待确认项），原密码仍有效
    assert forgot_mod.begin_reset("erin", "email", "attacker@evil.com")[0] == "mismatch"
    assert c.get("/vaults", headers=_auth("erin", "password123")).status_code == 200
    # 正确发件人（大小写/空格归一化）→ 签发 8 位确认码
    res, payload = forgot_mod.begin_reset("erin", "email", " erin@example.com ")
    assert res == "ok" and payload["action"] == "deliver_token", (res, payload)
    token = payload["token"]
    assert _re.fullmatch(r"[A-HJ-NP-Z2-9]{8}", token), token
    # 错误确认者（发件人与签发时不一致）→ invalid_token
    assert forgot_mod.confirm_by_token(token, "attacker@evil.com")[0] == "invalid_token"
    # 正确确认（大小写归一）→ 两阶段：prepare 随机临时密码（12 位，绝不是 86868686）
    res2, payload2 = forgot_mod.confirm_by_token(token, "Erin@Example.COM")
    assert res2 == "ok" and payload2["action"] == "deliver_temp", (res2, payload2)
    temp = payload2["temp"]
    assert len(temp) == 12 and temp != "86868686", temp
    # commit（CAS：以 prepare 时的旧哈希为条件）→ 旧密码失效、临时密码可登录
    assert forgot_mod.commit_reset(payload2), "commit 应成功"
    assert c.get("/vaults", headers=_auth("erin", "password123")).status_code == 401
    assert c.get("/vaults", headers=_auth("erin", temp)).status_code == 200
    # 确认码一次性（用过即作废）
    assert forgot_mod.confirm_by_token(token, "erin@example.com")[0] == "invalid_token"

    # 24h 内重复申请（未改密）→ 免确认码直接重发新的随机临时密码（用户要求）
    res3, p3 = forgot_mod.begin_reset("erin", "email", "erin@example.com")
    assert res3 == "ok" and p3["action"] == "deliver_temp", (res3, p3)
    temp2 = p3["temp"]
    assert forgot_mod.commit_reset(p3)
    assert c.get("/vaults", headers=_auth("erin", temp)).status_code == 401
    assert c.get("/vaults", headers=_auth("erin", temp2)).status_code == 200

    # 重发限流：每用户每小时 3 次（第 4 次起拒绝，审计报告 P1-8）
    last_temp = temp2
    limited = 0
    for i in range(4):
        rl, pl = forgot_mod.begin_reset("erin", "email", "erin@example.com")
        if rl == "ok" and pl["action"] == "deliver_temp":
            assert forgot_mod.commit_reset(pl)
            last_temp = pl["temp"]
        elif rl == "resend_limited":
            limited += 1
            forgot_mod.audit("RESEND_LIMITED", user="erin", channel="email",
                             sender="erin@example.com")
    assert limited >= 1, "第 4 次申请应触发重发限流"
    assert c.get("/vaults", headers=_auth("erin", last_temp)).status_code == 200

    # 用户自行改密（用最新临时密码）→ 清除重置标记 → 恢复正常两步确认
    assert c.post("/change_service_pwd", headers=_auth("erin", last_temp),
                  json={"new_pwd": "ChangedPwd-9"}).status_code == 200
    assert c.get("/vaults", headers=_auth("erin", last_temp)).status_code == 401
    res5, p5 = forgot_mod.begin_reset("erin", "email", "erin@example.com")
    assert res5 == "ok" and p5["action"] == "deliver_token", (res5, p5)
    res6, p6 = forgot_mod.confirm_by_token(p5["token"], "erin@example.com")
    assert res6 == "ok"
    assert forgot_mod.commit_reset(p6)
    temp3 = p6["temp"]
    assert c.get("/vaults", headers=_auth("erin", temp3)).status_code == 200

    # 管理员手动兜底：mismatch 拒绝 / 正确发件人 → 随机临时密码
    assert forgot_mod.manual_reset("erin", "attacker@evil.com")[0] == "mismatch"
    res7, temp7 = forgot_mod.manual_reset("erin", "erin@example.com")
    assert res7 == "ok" and len(temp7) == 12
    assert c.get("/vaults", headers=_auth("erin", temp7)).status_code == 200

    # /contact：未配置时返回空串
    assert c.get("/contact").json() == {"admin_email": "", "sms_hint": ""}

    # 14. 短信通道（审计报告 P0-1/P1-7）：仅头 token、恒定响应、通知管理员人工处理
    os.environ["PWMGR_SMS_HOOK_TOKEN"] = "hook-token-1"
    r = _reg(c, "frank", "password123", phone="+86 138-0013-8000")
    assert r.status_code == 200, r.text
    r = c.post("/internal/sms-up", json={"mobile": "13800138000", "text": "01frankd"},
               headers={"X-Hook-Token": "bad"})
    assert r.status_code == 403, r.text
    r = c.post("/internal/sms-up", json={"mobile": "13800138000", "text": "01frankd"})
    assert r.status_code == 403, "URL 参数不再接受 token"
    r = c.post("/internal/sms-up", json={"mobile": "13800138000", "text": "01frankd"},
               headers={"X-Hook-Token": "hook-token-1"})
    assert r.json() == {"ok": True}, r.text   # 恒定响应：不泄露匹配结果

    # 12. 联系方式唯一性：A 绑定的邮箱/手机，B 不能再绑（归一化后比对）
    r = _reg(c, "gina", "password123", email="ERIN@example.com")
    assert r.status_code == 409 and r.json()["detail"]["error"] == "register_conflict", r.text
    r = _reg(c, "gina", "password123", phone="138 0013 8000")
    assert r.status_code == 409 and r.json()["detail"]["error"] == "register_conflict", r.text
    assert c.get("/vaults", headers=_auth("gina", "password123")).status_code == 401

    # 13. 审计日志：文件生成、结果齐全、发件人打码、180 天清理（删 90 天前行）
    import time as _time  # noqa: E402
    audit_path = os.path.join(os.path.dirname(os.environ["PWMGR_DB"]), "forgot.log")
    assert os.path.exists(audit_path), "审计日志文件必须生成"
    text = open(audit_path, encoding="utf-8").read()
    assert "TOKEN_SENT user=erin" in text, "第 1 步签发必须记录"
    assert text.count("RESET_OK user=erin") >= 5, "正确重置必须记录"
    assert "MISMATCH user=erin" in text, "错误尝试必须记录"
    assert "RESEND_LIMITED user=erin" in text, "重发限流必须记录"
    assert "eri***@example.com" in text, "发件人必须打码"
    assert "erin@example.com" not in text, "明文邮箱不得出现在日志"
    for t7 in (temp, temp2, temp3, temp7):
        assert t7 not in text, "临时密码绝不入日志"
    # 旧邮件（Date 超 60 分钟）→ FRESH_SKIP 丢弃
    import json as _json  # noqa: E402
    import mail_worker as mw  # noqa: E402
    from email.parser import BytesParser as _BP  # noqa: E402
    from email import policy as _policy  # noqa: E402
    from email.message import EmailMessage as _EM  # noqa: E402
    old_mail = _EM()
    old_mail["From"] = "erin@example.com"
    old_mail["Subject"] = "01erin"
    old_mail["Date"] = "Mon, 01 Jan 2024 00:00:00 +0000"
    old_mail.set_content("01erin")
    msg2 = _BP(policy=_policy.default).parsebytes(old_mail.as_bytes())
    mw._process_message(msg2, old_mail.as_bytes())
    text = open(audit_path, encoding="utf-8").read()
    assert "FRESH_SKIP" in text, "超时旧邮件必须被丢弃并记录"
    # 清理：写一条 2020 年的日志 + 把清理状态归零 → 应删除旧行并记录清理时间
    with open(audit_path, "a", encoding="utf-8") as f:
        f.write("[2020-01-01 00:00:00] RESET_OK user=ancient\n")
    forgot_mod.cleanup_if_due(_time.time())
    text = open(audit_path, encoding="utf-8").read()
    assert "user=ancient" not in text, "90 天前的日志必须被清理"
    assert "RESET_OK user=erin" in text, "90 天内的日志必须保留"
    assert os.path.exists(audit_path + ".clean.state"), "清理状态文件必须存在"

    # 15. 注册限流（审计报告 P1-8：成功注册也计数）
    os.environ["PWMGR_REG_PER_HOUR"] = "1"
    r = _reg(c, "henry", "password123")
    assert r.status_code == 429, r.text
    os.environ["PWMGR_REG_PER_HOUR"] = "1000"

    # 16. mail_worker.main() 状态机（审计报告 D2/N1/N3/S2 验收：假 IMAP + 假 SMTP）
    import mail_worker as mw  # noqa: E402
    import imaplib as _imaplib  # noqa: E402
    import smtplib as _smtplib  # noqa: E402
    from email.message import EmailMessage as _EM2  # noqa: E402
    from email.utils import formatdate as _fmtdate  # noqa: E402

    class _FakeIMAP:
        """假 IMAP：实现 worker 用到的最小接口，UNSEEN 按 seen 编号集合计算。"""

        def __init__(self, mails):
            self.mails = list(mails)
            self.seen = set()          # 1-based 编号
            self.stored = []           # (编号, flags) —— 验证 \Seen 标记时机

        def login(self, u, p): pass

        def _simple_command(self, *a): pass

        def _untagged_response(self, typ, dat, name): return "OK", [b"ID ok"]

        def select(self, box): return "OK", [str(len(self.mails)).encode()]

        def search(self, charset, *crit):
            assert crit[0] == "UNSEEN"
            ids = [str(i + 1).encode() for i in range(len(self.mails))
                   if (i + 1) not in self.seen]
            return "OK", [b" ".join(ids)]

        def fetch(self, num, spec):
            i = int(num) - 1
            raw = self.mails[i]
            return "OK", [(num + b" (BODY.PEEK[] {%d}" % len(raw), raw), b")"]

        def store(self, num, cmd, flags):
            self.stored.append((int(num), flags))
            self.seen.add(int(num))

        def logout(self): pass

    class _FakeSMTP:
        sent = []
        fail = False

        def __init__(self, *a, **k): pass

        def login(self, u, p): pass

        def send_message(self, m):
            if _FakeSMTP.fail:
                raise RuntimeError("smtp down")
            _FakeSMTP.sent.append(m)

        def quit(self): pass

    real_imap = _imaplib.IMAP4_SSL
    real_smtp = _smtplib.SMTP_SSL
    mail_box = []                  # 假收件箱（原始字节列表，用例自行投递）
    os.environ.update(
        PWMGR_IMAP_HOST="imap.test", PWMGR_IMAP_USER="admin@test",
        PWMGR_IMAP_PASS="x", PWMGR_SMTP_HOST="smtp.test",
        PWMGR_SMTP_PORT="465", PWMGR_SMTP_USER="admin@test",
        PWMGR_SMTP_PASS="x", PWMGR_ADMIN_EMAIL="admin@test")
    fake_imaps = []

    def _mk_imap(host):
        inst = _FakeIMAP(mail_box)
        fake_imaps.append(inst)
        return inst

    _imaplib.IMAP4_SSL = _mk_imap
    _smtplib.SMTP_SSL = lambda *a, **k: _FakeSMTP()

    def _fresh_mail(frm, code):
        m = _EM2()
        m["From"] = frm
        m["To"] = "admin@test"
        m["Subject"] = "01" + code
        m["Date"] = _fmtdate(localtime=True)
        m.set_content(code)
        return m.as_bytes()

    def _run_main():
        assert mw.main() == 0

    def _audit_text():
        return open(audit_path, encoding="utf-8").read()

    def _state():
        try:
            return json.load(open(mw._state_path(), encoding="utf-8"))
        except FileNotFoundError:
            return {"seen_ids": {}, "retries": {}}   # 首轮无状态文件是正常态

    # 前面用例耗尽了 erin 的重发配额：清空重发计数，保证 T1-T3 走"投递失败→重试"
    _resend_state = os.path.join(os.path.dirname(os.environ["PWMGR_DB"]),
                                 "forgot_resend.state")
    if os.path.exists(_resend_state):
        os.remove(_resend_state)

    # T1：投递失败 → 待重试（保持未读、不入 seen_ids、计数累积）
    _FakeSMTP.fail = True
    mail_box.append(_fresh_mail("erin@example.com", "erin"))
    mw.main()
    fi = fake_imaps[-1]
    st = _state()
    assert len(st["retries"]) == 1 and list(st["retries"].values()) == [1], st
    assert 1 not in fi.seen and 1 not in fi.stored, "待重试邮件必须保持未读"
    assert "DELIVER_FAILED" in _audit_text(), "投递失败必须入审计"

    # T2：再失败一轮 → 计数累积到 2
    mw.main()
    st = _state()
    assert list(st["retries"].values()) == [2], st

    # T3：连续失败至 25 轮上限 → DELIVER_GIVEUP（保持未读、进入去重状态、管理员告警）
    for _ in range(23):
        mw.main()
    st = _state()
    assert st["retries"] == {}, "放弃后重试计数必须清除"
    assert "DELIVER_GIVEUP" in _audit_text(), "25 轮失败后必须放弃并审计"
    assert 1 not in fake_imaps[-1].seen, "放弃的邮件保持未读"

    # 放弃后再跑一轮：去重状态生效，不再重复处理（无新告警）
    n_giveup = _audit_text().count("DELIVER_GIVEUP")
    mw.main()
    assert _audit_text().count("DELIVER_GIVEUP") == n_giveup, "放弃后不得重复处理"

    # T4：两步全链路（新用户 mailuser，无 24h 重置历史 → 走确认码路径）
    _FakeSMTP.fail = False
    _FakeSMTP.sent.clear()
    r = c.post("/register", json={"username": "mailuser",
                                  "service_pwd": "password123",
                                  "email": "mailuser@example.com"})
    assert r.status_code == 200, r.text
    mail_box.append(_fresh_mail("mailuser@example.com", "mailuser"))
    mw.main()   # 第 1 步：确认码投递
    assert len(_FakeSMTP.sent) == 1 and "确认码" in _FakeSMTP.sent[0].get("Subject", ""),         "第 1 步必须发出确认码邮件"
    token = _re.search(r"验证码：([A-HJ-NP-Z2-9]{8})", _FakeSMTP.sent[0].get_content()).group(1)
    # 用户回复：新邮件正文带确认码（同一发件人）
    reply = _EM2()
    reply["From"] = "mailuser@example.com"
    reply["To"] = "admin@test"
    reply["Subject"] = "Re: 密码重置确认码"
    reply["Date"] = _fmtdate(localtime=True)
    reply.set_content(token)
    mail_box.append(reply.as_bytes())
    mw.main()   # 第 2 步：临时密码投递 + 落库
    assert len(_FakeSMTP.sent) == 2 and "临时密码" in _FakeSMTP.sent[1].get("Subject", ""),         "第 2 步必须发出临时密码邮件"
    temp_pwd = _re.search(r"临时密码：([A-Za-z0-9]{12})", _FakeSMTP.sent[1].get_content()).group(1)
    r = c.get("/vaults", headers=_auth("mailuser", temp_pwd))
    assert r.status_code == 200, "临时密码必须可登录"
    assert "RESET_DELIVERED" in _audit_text(), "全链路成功必须审计"

    _imaplib.IMAP4_SSL = real_imap
    _smtplib.SMTP_SSL = real_smtp

    # 17. 查重列语义统一（审计 Q1/N1）：pepper 为空 → uniq 写 NULL（与迁移一致），
    #     不再写"空密钥 HMAC"；S5 的 email_uniq IS NULL 判据因此能抓到这些行。
    import sqlite3 as _s3

    def _uniq_of(user):
        with _s3.connect(os.environ["PWMGR_DB"]) as _conn:
            row = _conn.execute(
                "SELECT email_uniq FROM users WHERE username = ?", (user,)
            ).fetchone()
        return row[0] if row else None

    _pepper_saved = os.environ.pop("PWMGR_CONTACT_PEPPER")   # 场景 A：无 pepper 注册
    r = _reg(c, "nopepper1", "password123")
    assert r.status_code == 200, r.text
    assert _uniq_of("nopepper1") is None, "pepper 为空时注册 uniq 必须是 NULL"

    r = _reg(c, "nopepper2", "password123", email="same@example.com")
    assert r.status_code == 200, r.text
    assert _uniq_of("nopepper2") is None
    os.environ["PWMGR_CONTACT_PEPPER"] = "test-pepper"       # 场景 B：pepper 就绪

    r = _reg(c, "withpepper1", "password123", email="same@example.com")
    assert r.status_code == 200, r.text
    u1 = _uniq_of("withpepper1")
    assert u1 is not None and u1 != "", "pepper 就绪后注册 uniq 必须是真实 HMAC"

    r = _reg(c, "withpepper2", "password123", email="same@example.com")
    assert r.status_code == 409, "同 pepper 同邮箱必须 409"

    # 场景 D：set_contact 在 pepper 为空时也写 NULL
    import manage as _mg
    os.environ.pop("PWMGR_CONTACT_PEPPER")
    _mg._set_contact("withpepper1", "rebind@example.com")
    assert _uniq_of("withpepper1") is None, "pepper 为空时 set_contact 必须写 NULL"
    os.environ["PWMGR_CONTACT_PEPPER"] = "test-pepper"
    _mg._set_contact("withpepper1", "rebind2@example.com")
    assert _uniq_of("withpepper1") is not None, "pepper 就绪后 set_contact 必须写真实 HMAC"

    print("server v2.8 e2e: all ok")



if __name__ == "__main__":
    run()

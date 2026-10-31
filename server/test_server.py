"""同步服务器 v2.3 端到端测试。

用 FastAPI TestClient 在进程内跑通：health/注册/鉴权/多版本 FIFO/属主隔离/
改用户密码/注销/限流。使用临时数据库，不污染生产库。

运行: python test_server.py
"""
import base64
import os
import tempfile

# 用临时数据库，必须在 import store 前设置
_tmp = tempfile.mkdtemp()
os.environ["PWMGR_DB"] = os.path.join(_tmp, "test.db")
os.environ["PWMGR_REG_PER_HOUR"] = "1000"  # 测试环境放开注册限流

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
    assert forgot_mod.issue_token("erin", "email", "attacker@evil.com")[0] == "mismatch"
    assert c.get("/vaults", headers=_auth("erin", "password123")).status_code == 200
    # 正确发件人（大小写/空格归一化）→ 签发 8 位确认码
    res, token = forgot_mod.issue_token("erin", "email", " erin@example.com ")
    assert res == "ok", res
    assert _re.fullmatch(r"[A-HJ-NP-Z2-9]{8}", token), token
    # 错误确认者（发件人与签发时不一致）→ invalid_token
    assert forgot_mod.confirm_reset(token, "attacker@evil.com")[0] == "invalid_token"
    # 正确确认（大小写归一）→ 随机临时密码（12 位，绝不再是 86868686）
    res2, temp = forgot_mod.confirm_reset(token, "Erin@Example.COM")
    assert res2 == "ok" and len(temp) == 12 and temp != "86868686", (res2, temp)
    # 旧密码失效、临时密码可登录
    assert c.get("/vaults", headers=_auth("erin", "password123")).status_code == 401
    assert c.get("/vaults", headers=_auth("erin", temp)).status_code == 200
    # 确认码一次性（用过即作废）
    assert forgot_mod.confirm_reset(token, "erin@example.com")[0] == "invalid_token"
    # 24h 节流（在最终重置时生效）
    _, t2 = forgot_mod.issue_token("erin", "email", "erin@example.com")
    assert forgot_mod.confirm_reset(t2, "erin@example.com")[0] == "throttled"

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
    assert r.status_code == 409 and r.json()["detail"]["error"] == "contact_taken", r.text
    r = _reg(c, "gina", "password123", phone="138 0013 8000")
    assert r.status_code == 409 and r.json()["detail"]["error"] == "contact_taken", r.text
    assert c.get("/vaults", headers=_auth("gina", "password123")).status_code == 401

    # 13. 审计日志：文件生成、结果齐全、发件人打码、180 天清理（删 90 天前行）
    import time as _time  # noqa: E402
    audit_path = os.path.join(os.path.dirname(os.environ["PWMGR_DB"]), "forgot.log")
    assert os.path.exists(audit_path), "审计日志文件必须生成"
    text = open(audit_path, encoding="utf-8").read()
    assert "TOKEN_SENT user=erin" in text, "第 1 步签发必须记录"
    assert "RESET_OK user=erin" in text, "正确重置必须记录"
    assert "MISMATCH user=erin" in text, "错误尝试必须记录"
    assert "THROTTLED user=erin" in text, "节流必须记录"
    assert "eri***@example.com" in text, "发件人必须打码"
    assert "erin@example.com" not in text, "明文邮箱不得出现在日志"
    assert temp not in text, "临时密码绝不入日志"
    # 旧邮件（Date 超 60 分钟）→ FRESH_SKIP 丢弃
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

    print("server v2.8 e2e: all ok")



if __name__ == "__main__":
    run()

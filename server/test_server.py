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
            service_pwd_salt=b"\x00" * 16, email="x@y.z", phone="",
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

    print("server v2.3 e2e: all ok")


if __name__ == "__main__":
    run()

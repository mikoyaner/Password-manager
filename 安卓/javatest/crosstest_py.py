import sys, os, json, time, uuid
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "window"))
from crypto import encrypt_vault, decrypt_vault  # noqa

PW = "Vault-Passw0rd-123"

def make_vault():
    rid = str(uuid.uuid4())
    rid2 = str(uuid.uuid4())
    return {
        "username": "demo@示例",
        "pwd_time": int(time.time() * 1000),
        "modified_at": int(time.time() * 1000),
        "label": "跨端对拍库",
        "records": {
            rid: {
                "type": "login", "title": "GitHub", "url": "https://github.com",
                "username": "a@x.com", "password": "pw-中文-!@#", "apikey": None,
                "note": "备注含逗号,和\"引号\"", "updated_at": int(time.time()*1000),
                "deleted": False,
            },
            rid2: {
                "type": "apikey", "title": "OpenAI", "url": None, "username": None,
                "password": None, "apikey": "sk-proj-密钥", "note": "",
                "updated_at": int(time.time()*1000), "deleted": False,
            },
        },
    }

if __name__ == "__main__":
    mode = sys.argv[1]
    if mode == "gen":
        blob = encrypt_vault(json.dumps(make_vault(), ensure_ascii=False).encode("utf-8"), PW)
        with open(sys.argv[2], "wb") as f:
            f.write(blob)
        print("PY_GEN_OK bytes=%d magic=%s" % (len(blob), blob[:6].decode()))
    elif mode == "verify":
        with open(sys.argv[2], "rb") as f:
            blob = f.read()
        plain = decrypt_vault(blob, PW)
        data = json.loads(plain.decode("utf-8"))
        titles = [r["title"] for r in data["records"].values() if not r.get("deleted")]
        print("PY_VERIFY_OK fmt_ver=%d records=%d titles=%s" % (blob[6], len(titles), titles))

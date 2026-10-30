"""服务器管理脚本（v2.1）。

用法：
  python manage.py list_users
  python manage.py delete_user <username>
  python manage.py reset_password <username> <new_service_pwd>
  python manage.py health
"""
import sys

import auth
import store


def _list_users():
    store.init_db()
    import sqlite3
    conn = sqlite3.connect(store._DB_PATH)
    conn.row_factory = sqlite3.Row
    users = conn.execute(
        "SELECT username, email, phone, created_at, last_login_at "
        "FROM users ORDER BY created_at DESC"
    ).fetchall()
    if not users:
        print("(no users)")
        return
    for u in users:
        vs = conn.execute(
            "SELECT vid, pwd_time, label, upload_time, length(ciphertext) AS cipher_len "
            "FROM vaults WHERE username = ? ORDER BY upload_time DESC",
            (u["username"],),
        ).fetchall()
        print(f"{u['username']:<20} email={u['email']} phone={u['phone']} cloud_vaults={len(vs)}")
        for v in vs:
            print(f"    vid={v['vid']} pwd_time={v['pwd_time']} label={v['label']!r} "
                  f"upload_time={v['upload_time']} cipher_len={v['cipher_len']}")



def _delete_user(username: str):
    store.init_db()
    store.delete_account(username)
    print(f"deleted: {username}")


def _reset_password(username: str, new_pwd: str):
    if len(new_pwd) < 8:
        print("new password must be at least 8 characters", file=sys.stderr)
        sys.exit(1)
    store.init_db()
    if not store.user_exists(username):
        print(f"user not found: {username}", file=sys.stderr)
        sys.exit(1)
    salt = auth.new_salt()
    verifier = auth.derive_verifier(new_pwd, salt)
    store.update_service_pwd(username, verifier, salt)
    print(f"reset ok for: {username}")


def _health():
    store.init_db()
    print(f"ok, users={store.user_count()}")


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    cmd = sys.argv[1]
    if cmd == "list_users":
        _list_users()
    elif cmd == "delete_user" and len(sys.argv) >= 3:
        _delete_user(sys.argv[2])
    elif cmd == "reset_password" and len(sys.argv) >= 4:
        _reset_password(sys.argv[2], sys.argv[3])
    elif cmd == "health":
        _health()
    else:
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()

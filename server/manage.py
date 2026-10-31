"""服务器管理脚本（v2.7）。

用法：
  python manage.py list_users
  python manage.py delete_user <username>
  python manage.py reset_password <username> <new_service_pwd>
  python manage.py forgot_reset <username> <发件人邮箱或手机号>
  python manage.py set_contact <username> <新邮箱或手机号>
  python manage.py health
"""
import sys

import auth
import forgot
import store


def _list_users():
    store.init_db()
    import sqlite3
    conn = sqlite3.connect(store._DB_PATH)
    conn.row_factory = sqlite3.Row
    users = conn.execute(
        "SELECT username, email, phone, created_at, last_login_at, "
        "(email_hash IS NOT NULL) AS has_email, (phone_hash IS NOT NULL) AS has_phone "
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
        print(f"{u['username']:<20} 找回邮箱={'已绑定' if u['has_email'] else '未绑定'} "
              f"找回手机={'已绑定' if u['has_phone'] else '未绑定'} cloud_vaults={len(vs)}")
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


def _forgot_reset(username: str, contact: str):
    """忘记密码手动兜底：contact 为用户发来的邮件里的发件人邮箱/短信发件人手机号。"""
    store.init_db()
    kind = "email" if "@" in contact else "sms"
    result = forgot.attempt_reset(username, kind, contact)
    if result == "ok":
        print(f"已重置：{username} 的用户密码现为初始密码 86868686，请提醒用户立即修改")
    elif result == "no_user":
        print(f"未找到用户 {username}", file=sys.stderr); sys.exit(1)
    elif result == "mismatch":
        print("发件人联系方式与注册信息不匹配，未重置", file=sys.stderr); sys.exit(1)
    elif result == "throttled":
        print("该账号 24 小时内已重置过（无需重复操作）")
    else:
        print(f"失败: {result}", file=sys.stderr); sys.exit(1)


def _set_contact(username: str, contact: str):
    """管理员重绑找回联系方式（contact 含 @ 视为邮箱，否则视为手机号）。"""
    import os as _os
    store.init_db()
    kind = "email" if "@" in contact else "sms"
    pepper = _os.environ.get("PWMGR_CONTACT_PEPPER", "")
    try:
        store.set_contact_hash(username, kind, contact, pepper)
        print(f"已重绑 {username} 的找回{('邮箱' if kind == 'email' else '手机号')}")
    except ValueError as e:
        print(f"失败: {e}", file=sys.stderr); sys.exit(1)


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
    elif cmd == "forgot_reset" and len(sys.argv) >= 4:
        _forgot_reset(sys.argv[2], sys.argv[3])
    elif cmd == "set_contact" and len(sys.argv) >= 4:
        _set_contact(sys.argv[2], sys.argv[3])
    elif cmd == "health":
        _health()
    else:
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()

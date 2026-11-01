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



def _delete_user(username: str, *, confirm: bool = False):
    """注销服务器账号。审计新2：级联删除该账号名下所有云端库（含最多 5 份
    历史版本），不可恢复（本地库不受影响）——必须显式 --confirm 才执行，
    与 /account DELETE 接口的 confirm:true 同一语义。"""
    if not confirm:
        print(f"危险操作：注销 {username} 将级联删除该账号所有云端密码库"
              "（含最多 5 份历史版本），不可恢复（本地库不受影响）。",
              file=sys.stderr)
        print("确认执行请加 --confirm：manage.py delete_user "
              f"{username} --confirm", file=sys.stderr)
        sys.exit(1)
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
    # 审计报告 A7：管理员改密后作废该用户全部待确认码
    forgot._drop_pending_for_user(username)
    print(f"reset ok for: {username}")


def _forgot_reset(username: str, contact: str):
    """忘记密码手动兜底：contact 为用户发来的邮件里的发件人邮箱/短信发件人手机号。

    安全（审计报告 P0-1）：不再使用固定密码 86868686，改为**随机临时密码**，
    只在本次输出中出现一次，请线下告知用户；用户登录后应立即修改。
    """
    store.init_db()
    result, temp = forgot.manual_reset(username, contact)
    if result == "ok":
        print(f"已重置：{username} 的临时密码为 {temp}\n"
              f"（仅此一次输出，请线下告知用户；用户登录后应立即修改密码）")
    elif result == "no_user":
        print(f"未找到用户 {username}", file=sys.stderr); sys.exit(1)
    elif result == "mismatch":
        print("发件人联系方式与注册信息不匹配，未重置", file=sys.stderr); sys.exit(1)
    elif result == "invalid_contact":
        print("联系方式无效", file=sys.stderr); sys.exit(1)


def _set_contact(username: str, contact: str):
    """管理员重绑找回联系方式（contact 含 @ 视为邮箱，否则视为手机号）。"""
    import os as _os
    import sqlite3 as _s
    store.init_db()
    pepper = _os.environ.get("PWMGR_CONTACT_PEPPER", "")
    kind = "email" if "@" in contact else "sms"
    try:
        store.set_contact_hash(username, kind, contact, pepper)
        print(f"已重绑 {username} 的找回{('邮箱' if kind == 'email' else '手机号')}")
    except _s.IntegrityError:
        # 审计 R6+新2：pepper 空窗期可能存在"同邮箱双账号"，重绑目标邮箱被
        # 另一账号占用时管理员需要明确的下一步与代价说明，而不是撞墙提示
        print("该联系方式已被其他账号绑定（一个联系方式只绑一个账号）。",
              file=sys.stderr)
        print("下一步：先确认保留哪个账号——manage.py list_users 核对；注销"
              "另一个请用 manage.py delete_user <用户名> --confirm（注意："
              "注销会级联删除该账号所有云端库含 5 份历史，让对应用户先在"
              "桌面端导出 CSV 备份或改用 reset_password 保留账号），"
              "再回到本命令重绑。", file=sys.stderr)
        sys.exit(1)
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
        _delete_user(sys.argv[2],
                     confirm=(len(sys.argv) >= 4 and sys.argv[3] == "--confirm"))
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

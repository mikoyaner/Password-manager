#!/usr/bin/env python3
"""远程执行服务器运维命令（不需要登录服务器）。

用法（在 server/ 目录）：
  python manage_remote.py list_users
  python manage_remote.py delete_user <username>
  python manage_remote.py reset_password <username> <new_password>
  python manage_remote.py health

认证与主机指纹沿用 server/.env + server/deploy_key；新部署走
   sudo -n -u pwmanager /opt/pwmanager/bin/manage-as-service.sh <args>
旧 nohup 部署回退为在 REMOTE_DIR 下用 .venv/bin/python manage.py。
"""
import shlex
import sys

from _deploy_secrets import HOST, USER, REMOTE_DIR, validate
from _ssh import connect

WRAPPER = "/opt/pwmanager/bin/manage-as-service.sh"


def main() -> None:
    args = sys.argv[1:]
    if not args:
        print(__doc__.strip())
        sys.exit(2)
    validate()
    quoted = " ".join(shlex.quote(a) for a in args)
    remote = (
        f"if [ -x {WRAPPER} ]; then sudo -n -u pwmanager {WRAPPER} {quoted}; "
        f"else cd {shlex.quote(REMOTE_DIR)} && .venv/bin/python manage.py {quoted}; fi"
    )
    ssh = connect(HOST, USER)
    _, out, err = ssh.exec_command(remote)
    stdout = out.read().decode()
    stderr = err.read().decode()
    rc = out.channel.recv_exit_status()
    ssh.close()
    sys.stdout.write(stdout)
    sys.stderr.write(stderr)
    sys.exit(rc)


if __name__ == "__main__":
    main()

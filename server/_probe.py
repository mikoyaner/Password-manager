"""临时只读探针：sudoers 是否已收紧、邮件服务状态与最近错误。用完即删。"""
from _ssh import connect
from _deploy_secrets import HOST, USER


def main() -> None:
    ssh = connect(HOST, USER)
    cmds = [
        "sudo -n -l",
        "systemctl is-active pwmanager.service pwmanager-mail.timer",
        "stat -c '%U:%G %a %n' /opt/pwmanager/api.env /opt/pwmanager/mail.env 2>&1",
        "journalctl -u pwmanager-mail.service -n 30 --no-pager 2>&1 | grep -E 'Traceback|KeyError|ERROR|WARNING' | tail -8",
    ]
    for cmd in cmds:
        _, out, err = ssh.exec_command(cmd)
        o = out.read().decode().strip()
        e = err.read().decode().strip()
        print(f"$ {cmd}\n{o or '(no stdout)'}")
        if e:
            print(f"[stderr] {e}")
        print("-" * 60)
    ssh.close()


if __name__ == "__main__":
    main()

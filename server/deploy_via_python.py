#!/usr/bin/env python3
"""首次 / 大版本部署（v2.6：双账号 + systemd 沙箱）。

流程：
1) 连接服务器（密钥优先，密码过渡回退；主机指纹校验见 _ssh.py）
2) 上传服务端代码 + requirements.txt + pwmanager.service + server_setup.sh
3) pwdeploy / pwmanager 账号已建：
   - 当前 SSH 账号是 root → 直接执行 server_setup.sh
   - 否则打印手动执行指引（需要 root/sudo 的一次性操作）
   账号未建 → 打印建号指引退出；`--legacy` 可走旧版 remote_install.sh（不推荐）
"""
import os
import shlex
import sys

from _deploy_secrets import HOST, USER, REMOTE_DIR, OLD_DIR, validate
from _ssh import connect

SERVER_FILES = ["main.py", "store.py", "auth.py", "contacts.py", "forgot.py",
                "mail_worker.py", "manage.py"]
EXTRA_FILES = ["requirements.txt", "pwmanager.service",
               "pwmanager-mail.service", "pwmanager-mail.timer", "server_setup.sh"]
LOCAL_DIR = os.path.dirname(os.path.abspath(__file__))


def run(ssh, cmd, timeout=120, show=True):
    stdin, stdout, stderr = ssh.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode().strip()
    err = stderr.read().decode().strip()
    if show and out:
        print(out)
    if err:
        print("[stderr]", err)
    return out


def main():
    validate()
    legacy = "--legacy" in sys.argv
    print(f"=== 部署到 {USER}@{HOST}:{REMOTE_DIR} ===")
    ssh = connect(HOST, USER)
    print(">>> 连接成功")

    # 首次安装若用普通账号，/opt 通常不可写；提前给出两条可行路径，而不是在 sftp 里报错
    mk = run(ssh, f"mkdir -p {shlex.quote(REMOTE_DIR)} && test -w {shlex.quote(REMOTE_DIR)} "
                  "&& echo ok || echo fail", show=False)
    if mk != "ok":
        print(f"!!! 无法写入 {REMOTE_DIR}（账号 {USER} 权限不足）。首次安装请改用下面任一方式：")
        print("    A) 用有 root/sudo 的 SSH 账号：.env 设 PWMGR_SSH_USER=<root或sudo账号>、")
        print("       PWMGR_REMOTE_DIR=/opt/pwmanager/server，可选 PWMGR_OLD_DIR=<旧部署目录>，重跑本脚本；")
        print("    B) 先用旧账号把代码上传到旧目录：.env 设 PWMGR_REMOTE_DIR=<旧部署目录>，")
        print("       重跑本脚本上传；再以 root/sudo 执行 server_setup.sh <旧部署目录> 迁移到 /opt。")
        ssh.close(); sys.exit(1)

    sftp = ssh.open_sftp()
    for f in SERVER_FILES + EXTRA_FILES:
        lp = os.path.join(LOCAL_DIR, f)
        if not os.path.exists(lp):
            print(f"跳过缺失文件: {f}")
            continue
        print(f">>> 上传 {f}")
        sftp.put(lp, f"{REMOTE_DIR}/{f}")
    sftp.chmod(f"{REMOTE_DIR}/server_setup.sh", 0o755)
    sftp.close()

    if legacy:
        print(">>> [--legacy] 执行旧版 remote_install.sh（nohup + 用户目录部署）...")
        run(ssh, f"cd {REMOTE_DIR} && PUBLIC_IP={HOST} bash remote_install.sh", timeout=600)
        fp = run(ssh, f"openssl x509 -in {REMOTE_DIR}/certs/server.crt -noout -fingerprint "
                      "-sha256 | sed 's/.*=//' | tr -d ':' | tr 'A-F' 'a-f'", show=False)
        print(f">>> 证书 SHA-256 指纹: {fp}")
        print(f">>> 服务器地址: https://{HOST}:8443")
        run(ssh, "curl -sk https://localhost:8443/health")
        ssh.close()
        print("=== 部署完成（旧版路径）===")
        return

    has_accounts = run(
        ssh, "id pwdeploy >/dev/null 2>&1 && id pwmanager >/dev/null 2>&1 && echo yes || echo no",
        show=False)
    if has_accounts != "yes":
        print("!!! 尚未创建专用账号 pwdeploy / pwmanager。")
        print("    请按 server/DEPLOY.md『第一步』在服务器上以 root 建号（用户名固定），")
        print("    然后重新运行本脚本；或 `python deploy_via_python.py --legacy` 走旧版路径（不推荐）。")
        ssh.close(); sys.exit(1)

    am_root = run(ssh, '[ "$(id -u)" = 0 ] && echo root || echo no', show=False)
    setup_script = shlex.quote(f"{REMOTE_DIR}/server_setup.sh")
    setup_arg = f" {shlex.quote(OLD_DIR)}" if OLD_DIR else ""
    if am_root == "root":
        print(">>> 当前 SSH 账号是 root，直接执行 server_setup.sh ...")
        if OLD_DIR:
            print(f">>> 旧部署目录: {OLD_DIR}")
        else:
            print(">>> 未设置 PWMGR_OLD_DIR，由 server_setup.sh 自动探测旧目录")
        stdin, stdout, stderr = ssh.exec_command(
            f"bash {setup_script}{setup_arg}", timeout=900)
        for line in iter(stdout.readline, ""):
            print(line.rstrip())
        rc = stdout.channel.recv_exit_status()
        err = stderr.read().decode()
        if err:
            print(err)
        if rc != 0:
            print(f"!!! server_setup.sh 失败（退出码 {rc}）")
            ssh.close(); sys.exit(1)
        print("=== 部署完成（systemd 沙箱路径）===")
    else:
        print(">>> 当前 SSH 账号无 root 权限，setup 需要你手动执行一次（唯一需要 root 的步骤）：")
        print("      以有 sudo 权限的账号登录服务器，执行：")
        print(f"      sudo bash {setup_script}{setup_arg}")
        if not OLD_DIR:
            print("      （未设置 PWMGR_OLD_DIR；如旧部署不在 /home/*/AiWork/psd_manager，请补上旧目录参数）")
        print("    完成后把 .env 的 PWMGR_REMOTE_DIR 改为 /opt/pwmanager/server，再运行 python _sync_code.py。")

    ssh.close()


if __name__ == "__main__":
    main()

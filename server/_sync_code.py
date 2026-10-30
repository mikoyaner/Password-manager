#!/usr/bin/env python3
"""最小化同步：上传代码 → 远端语法自检 → 重启（自动适配 nohup / systemd 两种形态）。

服务形态自动探测：
- 服务器上存在 pwmanager.service（systemd 沙箱部署，见 server_setup.sh）
  → `sudo -n systemctl restart pwmanager.service`
- 否则维持旧形态：pkill + nohup uvicorn（自签证书直连 8443）
"""
import os
import sys
import time

from _deploy_secrets import HOST, USER, REMOTE_DIR, validate
from _ssh import connect

CERT_DIR = f"{REMOTE_DIR}/certs"

# 需要与远端保持一致的代码文件
UPLOAD = ["main.py", "store.py", "auth.py", "manage.py"]
LOCAL_DIR = os.path.dirname(os.path.abspath(__file__))


def run(ssh, cmd, timeout=60, show=True):
    stdin, stdout, stderr = ssh.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode().strip()
    err = stderr.read().decode().strip()
    if show and out:
        print(out)
    if err:
        print("[stderr]", err)
    return out


def service_mode(ssh) -> str:
    mode = run(ssh, "systemctl cat pwmanager.service >/dev/null 2>&1 && echo systemd || echo nohup",
               show=False)
    return mode if mode in ("systemd", "nohup") else "nohup"


def remote_python(ssh) -> str:
    """远端解释器：优先各部署形态的 venv，其次系统 python3。"""
    return run(
        ssh,
        f"if [ -x {REMOTE_DIR}/.venv/bin/python ]; then echo {REMOTE_DIR}/.venv/bin/python; "
        f"elif [ -x {REMOTE_DIR}/../venv/bin/python ]; then echo {REMOTE_DIR}/../venv/bin/python; "
        f"else echo python3; fi",
        show=False,
    ).strip() or "python3"


def main():
    validate()
    print(f"=== 同步代码到 {USER}@{HOST}:{REMOTE_DIR} ===")
    ssh = connect(HOST, USER)
    print(">>> 连接成功")

    mode = service_mode(ssh)
    print(f">>> 服务形态: {mode}")

    # 备份远端当前文件（可回滚）
    ts = time.strftime("%Y%m%d_%H%M%S")
    for f in UPLOAD:
        run(ssh, f"cp {REMOTE_DIR}/{f} {REMOTE_DIR}/{f}.bak_{ts} 2>/dev/null || true", show=False)
    print(f">>> 已备份远端原文件为 *.bak_{ts}")

    sftp = ssh.open_sftp()
    for f in UPLOAD:
        lp = os.path.join(LOCAL_DIR, f)
        print(f">>> 上传 {f} ({os.path.getsize(lp)} 字节)")
        sftp.put(lp, f"{REMOTE_DIR}/{f}")
    sftp.close()

    # 语法自检（远端对应形态的 python）
    py = remote_python(ssh)
    chk = run(ssh, f"cd {REMOTE_DIR} && {py} -c \"import py_compile;"
                   f"[py_compile.compile(x,doraise=True) for x in {UPLOAD!r}];print('py ok')\"")
    if "py ok" not in chk:
        print("!!! 远端语法检查失败，中止（未重启）")
        ssh.close(); sys.exit(1)

    if mode == "systemd":
        print(">>> systemctl 重启 pwmanager.service ...")
        out = run(ssh, "sudo -n systemctl restart pwmanager.service && echo restarted",
                  timeout=30, show=False)
        if "restarted" not in out:
            print("!!! 重启失败（检查服务器 /etc/sudoers.d/pwmanager 白名单是否已安装）")
            ssh.close(); sys.exit(1)
        time.sleep(2)
        print(">>> 服务日志尾部:")
        # pwdeploy 在 systemd-journal 组（重登录后生效）；sudoers 只放行无附加参数的
        # `systemctl status pwmanager.service`，故附加 flags 的写法会被拒绝
        run(ssh, "journalctl -u pwmanager.service -n 15 --no-pager 2>/dev/null "
                 "|| sudo -n systemctl status pwmanager.service | head -n 15 || true")
    else:
        print(">>> 停止旧 uvicorn...")
        run(ssh, "pkill -f 'uvicorn main:app' || true", show=False)
        time.sleep(1)
        print(">>> 启动服务（复用现有证书）...")
        start = (
            f"cd {REMOTE_DIR} && ( nohup .venv/bin/uvicorn main:app --host 0.0.0.0 --port 8443 "
            f"--workers 1 --ssl-keyfile {CERT_DIR}/server.key --ssl-certfile {CERT_DIR}/server.crt "
            f"> server.log 2>&1 </dev/null & ) ; echo started"
        )
        run(ssh, start, timeout=15, show=False)
        time.sleep(3)
        print(">>> 启动日志尾部:")
        run(ssh, f"tail -n 15 {REMOTE_DIR}/server.log")

    print(">>> 健康检查:")
    run(ssh, "curl -sk https://localhost:8443/health")

    fp = run(ssh, f"openssl x509 -in {CERT_DIR}/server.crt -noout -fingerprint -sha256 "
                  "| sed 's/.*=//' | tr -d ':' | tr 'A-F' 'a-f'")
    print(f">>> 证书 SHA-256 指纹: {fp}")

    ssh.close()
    print("=== 完成 ===")


if __name__ == "__main__":
    main()

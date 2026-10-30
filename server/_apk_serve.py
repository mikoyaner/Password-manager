#!/usr/bin/env python3
"""临时：把 app-debug.apk 挂到现有 8443 服务上供手机下载，用完 revert 还原。

用法:
  python _apk_serve.py serve   # 追加下载路由 + 上传 APK + 重启
  python _apk_serve.py revert  # 还原 main.py + 删除 APK + 重启

只在远端 main.py 末尾追加一段带标记的路由（本地 main.py 不动），
备份为 main.py.pre_apk；revert 时从备份还原并清理。
"""
import os
import secrets
import sys
import time

import paramiko

from _deploy_secrets import validate
from _sync_code import HOST, USER, PASSWORD, REMOTE_DIR, CERT_DIR

LOCAL_APK = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "安卓",
                 "app", "build", "outputs", "apk", "debug", "app-debug.apk"))
REMOTE_APK = f"{REMOTE_DIR}/app.apk"

# 一次性下载令牌：不带/带错的请求一律 404，避免临时路由公开暴露安装包
APK_TOKEN = os.environ.get("APK_TOKEN") or secrets.token_urlsafe(18)

MARKER = "# ===== 临时：APK 下载（_apk_serve 注入，revert 移除）====="
ROUTE = f'''

{MARKER}
import os as _os
import hmac as _hmac
from fastapi.responses import FileResponse as _FileResponse

_APK_TOKEN = {APK_TOKEN!r}


@app.get("/app.apk")
def _download_apk(t: str = ""):
    if not _hmac.compare_digest(t, _APK_TOKEN):
        raise HTTPException(status_code=404, detail={{"error": "not_found"}})
    p = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "app.apk")
    if not _os.path.exists(p):
        raise HTTPException(status_code=404, detail={{"error": "no_apk"}})
    return _FileResponse(
        p,
        media_type="application/vnd.android.package-archive",
        filename="pwdmgr.apk",
    )
'''


def run(ssh, cmd, timeout=90, show=True):
    stdin, stdout, stderr = ssh.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode().strip()
    err = stderr.read().decode().strip()
    if show and out:
        print(out)
    if err:
        print("[stderr]", err)
    return out


def restart(ssh):
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
    print(">>> 健康检查:")
    run(ssh, "curl -sk https://localhost:8443/health")


def serve():
    validate()
    if not os.path.exists(LOCAL_APK):
        print(f"!!! 本地 APK 不存在: {LOCAL_APK}")
        sys.exit(1)
    print(f"=== 挂载 APK 下载 ({os.path.getsize(LOCAL_APK)} 字节) ===")
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(HOST, username=USER, password=PASSWORD, timeout=30)
    print(">>> 连接成功")

    # 备份远端 main.py（仅一次，避免重复 revert 目标被覆盖）
    run(ssh, f"test -f {REMOTE_DIR}/main.py.pre_apk || cp {REMOTE_DIR}/main.py {REMOTE_DIR}/main.py.pre_apk",
        show=False)
    print(">>> 已确保备份 main.py.pre_apk")

    # 追加路由（若尚未注入）
    cur = run(ssh, f"cat {REMOTE_DIR}/main.py", show=False)
    if MARKER in cur:
        print("!!! 远端已存在旧版注入路由（令牌未知），请先执行 revert 再 serve")
        ssh.close()
        sys.exit(1)
    else:
        # 用 base64 传输避免 shell 转义问题
        import base64 as _b64
        payload = _b64.b64encode(ROUTE.encode("utf-8")).decode("ascii")
        run(ssh, f"printf '%s' '{payload}' | base64 -d >> {REMOTE_DIR}/main.py", show=False)
        print(">>> 已追加 /app.apk 路由（需令牌）")

    # 上传 APK
    sftp = ssh.open_sftp()
    print(">>> 上传 app.apk ...")
    sftp.put(LOCAL_APK, REMOTE_APK)
    sftp.close()

    # 语法自检
    chk = run(ssh, f"cd {REMOTE_DIR} && .venv/bin/python -c \"import py_compile;py_compile.compile('main.py',doraise=True);print('py ok')\"")
    if "py ok" not in chk:
        print("!!! 语法检查失败，还原 main.py 并中止")
        run(ssh, f"cp {REMOTE_DIR}/main.py.pre_apk {REMOTE_DIR}/main.py", show=False)
        ssh.close()
        sys.exit(1)

    restart(ssh)
    print(">>> 验证 /app.apk（不带令牌应 404）:")
    run(ssh, "curl -sk -o /dev/null -w 'HTTP=%{http_code}\\n' https://localhost:8443/app.apk")
    print(">>> 验证 /app.apk（带令牌应 200）:")
    run(ssh, f"curl -sk -o /dev/null -w 'HTTP=%{{http_code}} size=%{{size_download}}\\n' "
             f"'https://localhost:8443/app.apk?t={APK_TOKEN}'")
    ssh.close()
    print("=== 完成：手机浏览器打开 "
          f"https://{HOST}:8443/app.apk?t={APK_TOKEN} 下载（忽略自签证书警告）===")
    print("=== 用完记得执行 revert，令牌仅本次有效 ===")


def revert():
    validate()
    print("=== 还原：移除 APK 路由与文件 ===")
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(HOST, username=USER, password=PASSWORD, timeout=30)
    print(">>> 连接成功")
    run(ssh, f"test -f {REMOTE_DIR}/main.py.pre_apk && cp {REMOTE_DIR}/main.py.pre_apk {REMOTE_DIR}/main.py && rm -f {REMOTE_DIR}/main.py.pre_apk && echo restored || echo no_backup",
        show=True)
    run(ssh, f"rm -f {REMOTE_APK} && echo apk_removed", show=True)
    chk = run(ssh, f"cd {REMOTE_DIR} && .venv/bin/python -c \"import py_compile;py_compile.compile('main.py',doraise=True);print('py ok')\"")
    if "py ok" not in chk:
        print("!!! 还原后语法检查失败，请手动检查 main.py")
        ssh.close()
        sys.exit(1)
    restart(ssh)
    print(">>> 验证 /app.apk 应 404:")
    run(ssh, "curl -sk -o /dev/null -w 'HTTP=%{http_code}\\n' https://localhost:8443/app.apk")
    ssh.close()
    print("=== 已还原 ===")


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else ""
    if mode == "serve":
        serve()
    elif mode == "revert":
        revert()
    else:
        print("用法: python _apk_serve.py [serve|revert]")
        sys.exit(2)

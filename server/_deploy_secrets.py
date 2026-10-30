"""本机部署凭据加载器（可安全提交）。

真实值放在同目录的 `.env`（已被 .gitignore 排除）；同名环境变量优先，
方便 CI 或临时覆盖。模板见 `.env.example`。
"""
from __future__ import annotations

import os
from pathlib import Path

_ENV_FILE = Path(__file__).with_name(".env")


def _read_env_file() -> dict[str, str]:
    vals: dict[str, str] = {}
    if not _ENV_FILE.exists():
        return vals
    for raw in _ENV_FILE.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, val = line.split("=", 1)
        vals[key.strip()] = val.strip().strip('"').strip("'")
    return vals


_FILE = _read_env_file()


def _get(key: str, default: str = "") -> str:
    return os.environ.get(key, "").strip() or _FILE.get(key, "") or default


HOST = _get("PWMGR_SSH_HOST")
USER = _get("PWMGR_SSH_USER")
PASSWORD = _get("PWMGR_SSH_PASSWORD")  # 过渡期认证；切换密钥后可从 .env 删除
KEY_PATH = _get("PWMGR_SSH_KEY")  # 部署私钥路径（相对 server/ 目录或绝对路径）
HOST_FINGERPRINT = _get("PWMGR_SSH_HOST_FINGERPRINT")  # 服务器主机公钥 SHA256（强校验）
REMOTE_DIR = _get("PWMGR_REMOTE_DIR")
# 首次迁移用：旧 nohup 部署目录（不填则 server_setup.sh 自动探测 /home/*/AiWork/psd_manager）
OLD_DIR = _get("PWMGR_OLD_DIR")


def validate() -> None:
    """凭据缺失时给出可执行的提示，而不是在 paramiko 里报难懂的错误。"""
    missing = [k for k, v in (
        ("PWMGR_SSH_HOST", HOST),
        ("PWMGR_SSH_USER", USER),
        ("PWMGR_REMOTE_DIR", REMOTE_DIR),
    ) if not v]
    if not KEY_PATH and not PASSWORD:
        missing.append("PWMGR_SSH_KEY 或 PWMGR_SSH_PASSWORD（认证方式二选一）")
    if missing:
        raise SystemExit(
            "缺少部署凭据：" + ", ".join(missing)
            + "。请复制 server/.env.example 为 server/.env 并填写"
              "（server/.env 已被 .gitignore 排除）。"
        )

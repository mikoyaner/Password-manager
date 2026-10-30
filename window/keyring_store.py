"""服务密码（用户密码）本地存储：走系统凭据库（keyring / Windows Credential Manager）。

规范 §9：不落盘明文；配置只记录"是否记住"。
"""
from __future__ import annotations

from typing import Optional

SERVICE = "PwdMgr"

try:
    import keyring
    _KEYRING_OK = True
except Exception:
    keyring = None
    _KEYRING_OK = False


def available() -> bool:
    return _KEYRING_OK


def save_service_pwd(username: str, pwd: str) -> bool:
    if not _KEYRING_OK:
        return False
    try:
        keyring.set_password(SERVICE, username, pwd)
        return True
    except Exception:
        return False


def load_service_pwd(username: str) -> Optional[str]:
    if not _KEYRING_OK:
        return None
    try:
        return keyring.get_password(SERVICE, username)
    except Exception:
        return None


def delete_service_pwd(username: str) -> None:
    if not _KEYRING_OK:
        return
    try:
        keyring.delete_password(SERVICE, username)
    except Exception:
        pass

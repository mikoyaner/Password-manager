"""SSH 连接共享模块（v2.6：密钥优先 / 密码过渡回退 / 主机指纹校验）。

- 认证：配置了 PWMGR_SSH_KEY 用私钥（可同时配 PWMGR_SSH_PASSWORD 作私钥
  passphrase 或回退密码）；只有密码时用密码（过渡期）。
- 主机指纹：配置了 PWMGR_SSH_HOST_FINGERPRINT（"SHA256:xxx" 或裸 base64）则强校验，
  不符在发送任何凭据前拒绝连接；未配置则接受但打印实际指纹，提醒写入 .env。
  替换旧的 AutoAddPolicy（盲目信任任何服务器）。
"""
from __future__ import annotations

import base64
import hashlib
import os

import paramiko

from _deploy_secrets import HOST_FINGERPRINT, KEY_PATH, PASSWORD

_HERE = os.path.dirname(os.path.abspath(__file__))


class FingerprintMismatch(paramiko.SSHException):
    """服务器主机公钥与 .env 配置的指纹不符，疑似中间人。"""


def _b64_fp(key: paramiko.PKey) -> str:
    dig = hashlib.sha256(key.asbytes()).digest()
    return base64.b64encode(dig).decode("ascii").rstrip("=")


def _normalize(expected: str) -> str:
    e = expected.strip()
    if e.lower().startswith("sha256:"):
        e = e[len("sha256:"):]
    return e.rstrip("=")


class _HostKeyPolicy(paramiko.MissingHostKeyPolicy):
    """host key 协商阶段即校验（先于用户认证，凭据不会发给假服务器）。"""

    def __init__(self, expected: str):
        self._expected = _normalize(expected)

    def missing_host_key(self, client, hostname, key: paramiko.PKey):
        actual = _b64_fp(key)
        if not self._expected:
            print(
                "[ssh] 未配置 PWMGR_SSH_HOST_FINGERPRINT，本次未强校验主机指纹。\n"
                f"[ssh] 服务器指纹: SHA256:{actual}\n"
                "[ssh] 确认无误后请写入 server/.env，下次起强校验。")
            return
        if actual != self._expected:
            raise FingerprintMismatch(
                f"服务器主机指纹不符：期望 SHA256:{self._expected}，"
                f"实际 SHA256:{actual}。已在发送任何凭据前拒绝连接。"
                "若服务器确实更换了主机密钥，更新 server/.env 的 PWMGR_SSH_HOST_FINGERPRINT。")


def connect(host: str, user: str, timeout: int = 30) -> paramiko.SSHClient:
    """建 SSH 连接。paramiko 默认不加载系统 known_hosts，指纹只对 .env 校验。"""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(_HostKeyPolicy(_normalize(HOST_FINGERPRINT)))
    kwargs: dict = dict(hostname=host, username=user, timeout=timeout,
                        look_for_keys=False, allow_agent=False)
    if KEY_PATH:
        kf = KEY_PATH if os.path.isabs(KEY_PATH) else os.path.join(_HERE, KEY_PATH)
        if not os.path.exists(kf):
            raise SystemExit(f"SSH 私钥不存在: {kf}（检查 server/.env 的 PWMGR_SSH_KEY）")
        kwargs["key_filename"] = kf
        if PASSWORD:
            kwargs["password"] = PASSWORD  # 私钥 passphrase，或密钥未装好时的回退
    elif PASSWORD:
        kwargs["password"] = PASSWORD
    else:
        raise SystemExit(
            "无法认证：.env 里既没有可用的 PWMGR_SSH_KEY，也没有 PWMGR_SSH_PASSWORD。")
    client.connect(**kwargs)
    return client

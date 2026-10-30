"""同步客户端 v2.1（规范 §7 / §8）。

- HTTPS + 证书 SHA-256 指纹 pinning（发送任何数据前校验）
- HTTP Basic 认证（用户密码）
- 端点：/health /register /vault GET/PUT /change_service_pwd /account DELETE
"""
from __future__ import annotations

import base64
import hashlib
import http.client
import json
import ssl
import time
from urllib.parse import urlsplit


class SyncError(Exception):
    """同步失败（网络/服务器错误）。"""


class AuthError(SyncError):
    """用户名/用户密码错误 (401)。"""


class PinError(SyncError):
    """服务器证书指纹不匹配，疑似中间人攻击。"""


class UsernameTakenError(SyncError):
    """409 用户名已被占用。"""


class NotFoundError(SyncError):
    """404 无云端库。"""


def _ssl_context(cert_fingerprint: str | None):
    ctx = ssl.create_default_context()
    if cert_fingerprint:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _normalize_fp(fp: str) -> str:
    return fp.replace(":", "").strip().lower()


def _verify_pin(conn, cert_fingerprint: str) -> None:
    der = conn.sock.getpeercert(binary_form=True)
    if not der:
        raise PinError("无法获取服务器证书，已拒绝连接")
    actual = _normalize_fp(hashlib.sha256(der).hexdigest())
    if actual != _normalize_fp(cert_fingerprint):
        raise PinError("服务器证书指纹不匹配，可能存在中间人攻击，已拒绝连接")


def _basic_header(username: str, password: str) -> str:
    raw = f"{username}:{password}".encode("utf-8")
    return "Basic " + base64.b64encode(raw).decode("ascii")


def _request(url: str, *, method="GET", basic: tuple[str, str] | None = None,
             body: dict | None = None, cert_fingerprint: str | None = None,
             timeout: int = 30) -> tuple[int, dict]:
    data = json.dumps(body).encode("utf-8") if body is not None else None
    parts = urlsplit(url)
    if not parts.hostname:
        raise SyncError("尚未配置服务器地址：请先在『设置 → 服务器设置』填写 https://host:port")
    if parts.scheme != "https":
        # Basic 认证会把用户密码带上，明文 HTTP 一律拒绝
        raise SyncError("出于安全考虑，服务器地址必须是 https://host:port")
    host = parts.hostname
    port = parts.port or 443
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query

    headers = {"Content-Type": "application/json"}
    if basic:
        headers["Authorization"] = _basic_header(*basic)

    conn = None
    try:
        ctx = _ssl_context(cert_fingerprint)
        conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
        conn.connect()
        if cert_fingerprint:
            _verify_pin(conn, cert_fingerprint)
        conn.request(method, path, body=data, headers=headers)
        resp = conn.getresponse()
        raw = resp.read().decode("utf-8", "replace")
        try:
            return resp.status, json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            return resp.status, {"detail": raw}
    except PinError:
        raise
    except (ssl.SSLError, OSError, http.client.HTTPException) as e:
        raise SyncError(f"无法连接服务器: {e}") from e
    finally:
        if conn is not None:
            conn.close()


def _extract_err(body: dict) -> str:
    d = body.get("detail") if isinstance(body, dict) else None
    if isinstance(d, dict):
        return str(d.get("error", "unknown"))
    if isinstance(d, str):
        return d
    return "unknown"


class SyncClient:
    def __init__(self, server_url: str, username: str, service_pwd: str,
                 cert_fingerprint: str | None = None):
        self.base = server_url.rstrip("/")
        self.username = username
        self.pwd = service_pwd
        self.fp = cert_fingerprint

    def _url(self, path: str) -> str:
        return self.base + path

    def _basic(self) -> tuple[str, str]:
        return (self.username, self.pwd)

    # ---- 无认证 ----

    def health(self) -> dict:
        status, body = _request(self._url("/health"), cert_fingerprint=self.fp)
        if status != 200:
            raise SyncError(f"health 失败: {status} {body}")
        return body

    def contact(self) -> dict:
        """GET /contact：找回密码联系方式（无认证）。返回 {admin_email, sms_hint}。"""
        status, body = _request(self._url("/contact"), cert_fingerprint=self.fp)
        if status != 200:
            raise SyncError(f"GET /contact 失败 ({status}): {_extract_err(body)}")
        return body

    def register(self, *, service_pwd: str, email: str, phone: str,
                 pwd_time: int | None = None, label: str | None = None,
                 ciphertext_b64: str | None = None) -> dict:
        """POST /register：注册账号。

        - 不带 ciphertext_b64：仅创建账号，云端零库（推荐：先注册，再登录推送）。
        - 带 ciphertext_b64：注册同时上传首版库（pwd_time 必填）。
        返回 {created_at, first_vid}
        """
        body = {
            "username": self.username,
            "service_pwd": service_pwd,
            "email": email,
            "phone": phone,
        }
        if ciphertext_b64 is not None:
            body["pwd_time"] = pwd_time
            body["label"] = label
            body["ciphertext"] = ciphertext_b64
        status, resp = _request(self._url("/register"), method="POST",
                                body=body, cert_fingerprint=self.fp)
        if status == 409:
            raise UsernameTakenError("用户名已被占用")
        if status != 200:
            raise SyncError(f"注册失败 ({status}): {_extract_err(resp)}")
        return resp

    # ---- 需要 Basic ----

    def list_vaults(self) -> list[dict]:
        """GET /vaults：本账号名下最多 5 份历史库的元数据（新→旧，不含密文、不含属主）。

        每项 {vid, pwd_time, label, ciphertext_sha256, upload_time}。
        """
        status, body = _request(self._url("/vaults"), method="GET",
                                basic=self._basic(), cert_fingerprint=self.fp)
        if status == 401:
            raise AuthError("用户名或用户密码错误")
        if status != 200:
            raise SyncError(f"GET /vaults 失败 ({status}): {_extract_err(body)}")
        return body.get("vaults", [])

    def get_vault(self, vid: int) -> dict:
        """GET /vault/{vid}：下载本账号名下指定一份库。只能取到自己的。"""
        status, body = _request(self._url(f"/vault/{vid}"), method="GET",
                                basic=self._basic(), cert_fingerprint=self.fp)
        if status == 401:
            raise AuthError("用户名或用户密码错误")
        if status == 404:
            raise NotFoundError("云端无该份密码库（或不属于本账号）")
        if status != 200:
            raise SyncError(f"GET /vault 失败 ({status}): {_extract_err(body)}")
        return body

    def put_vault(self, *, pwd_time: int, label: str | None,
                  ciphertext_b64: str) -> dict:
        """PUT /vault：每次上传都新增一份（服务器保留最新 5 份）。

        返回 {vid, upload_time, ciphertext_sha256, kept}。
        """
        body = {
            "pwd_time": pwd_time,
            "label": label,
            "ciphertext": ciphertext_b64,
        }
        status, resp = _request(self._url("/vault"), method="PUT",
                                body=body, basic=self._basic(),
                                cert_fingerprint=self.fp)
        if status == 401:
            raise AuthError("用户名或用户密码错误")
        if status != 200:
            raise SyncError(f"PUT /vault 失败 ({status}): {resp}")
        return resp

    def change_service_pwd(self, new_pwd: str) -> dict:
        """改用户密码（服务密码）。当前密码由 Basic 认证证明。"""
        body = {"new_pwd": new_pwd}
        status, resp = _request(self._url("/change_service_pwd"), method="POST",
                                body=body, basic=self._basic(),
                                cert_fingerprint=self.fp)
        if status == 401:
            raise AuthError("旧用户密码错误")
        if status != 200:
            raise SyncError(f"改用户密码失败 ({status}): {resp}")
        self.pwd = new_pwd
        return resp

    def delete_account(self) -> dict:
        status, resp = _request(self._url("/account"), method="DELETE",
                                body={"confirm": True}, basic=self._basic(),
                                cert_fingerprint=self.fp)
        if status == 401:
            raise AuthError("用户名或用户密码错误")
        if status != 200:
            raise SyncError(f"注销账户失败 ({status}): {resp}")
        return resp


def now_ms() -> int:
    return int(time.time() * 1000)

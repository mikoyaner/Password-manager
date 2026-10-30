"""密码管理器同步服务器 v2.3 (FastAPI)。

规范 §7 端点全部实现。仅存密文与用户元数据，永不存明文密码/主密码。
云端库多版本：每用户每次上传新增一行，保留最新 5 份（FIFO），只能拉自己名下的。
"""
import base64
import binascii
import hashlib
import hmac
import os
import re
import sqlite3

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

import auth
import contacts
import forgot
import store

app = FastAPI(title="PwdMgr Sync Server", version="2.3")

_MAX_CIPHER_BYTES = 8 * 1024 * 1024  # 8 MiB，规范 §7
# base64 膨胀 4/3 再留 JSON 余量
_MAX_REQUEST_BYTES = 12 * 1024 * 1024


class _BodyLimitMiddleware:
    """按实际收到的字节数限流：chunked 请求没有 Content-Length，也必须拦住。"""

    def __init__(self, app, max_bytes: int):
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = {k.lower(): v for k, v in scope.get("headers", [])}
        cl = headers.get(b"content-length")
        if cl is not None:
            try:
                too_large = int(cl) > self.max_bytes
            except ValueError:
                await JSONResponse({"detail": {"error": "bad_content_length"}},
                                   status_code=400)(scope, receive, send)
                return
            if too_large:
                await JSONResponse({"detail": {"error": "request_too_large"}},
                                   status_code=413)(scope, receive, send)
                return

        total = 0

        async def limited_receive():
            nonlocal total
            msg = await receive()
            if msg["type"] == "http.request":
                total += len(msg.get("body", b""))
                if total > self.max_bytes:
                    raise HTTPException(413, {"error": "request_too_large"})
            return msg

        await self.app(scope, limited_receive, send)


app.add_middleware(_BodyLimitMiddleware, max_bytes=_MAX_REQUEST_BYTES)

# 用户名规则（规范 §5.1）
_USERNAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{1,18}[a-zA-Z0-9]$")

# 宽松邮箱/手机号（v2.1 只占位，不做真实验证）
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_PHONE_RE = re.compile(r"^[0-9+\-() ]{6,20}$")


@app.on_event("startup")
def _startup() -> None:
    store.init_db()


# ===== 请求模型 =====

class RegisterReq(BaseModel):
    username: str
    service_pwd: str = Field(min_length=8, max_length=256)
    email: str = ""
    phone: str = ""
    pwd_time: int | None = None
    label: str | None = None
    ciphertext: str | None = None


class PutVaultReq(BaseModel):
    pwd_time: int
    label: str | None = None
    ciphertext: str


class ChangeServicePwdReq(BaseModel):
    # 当前密码由 HTTP Basic 证明（basic_auth 已校验），不再重复接收 old_pwd
    new_pwd: str = Field(min_length=8, max_length=256)


class DeleteAccountReq(BaseModel):
    confirm: bool


# ===== 工具 =====

def _decode_cipher(b64: str) -> bytes:
    try:
        raw = base64.b64decode(b64, validate=True)
    except (binascii.Error, ValueError):
        raise HTTPException(status_code=400, detail={"error": "bad_base64"})
    if not raw:
        raise HTTPException(status_code=400, detail={"error": "empty_ciphertext"})
    if len(raw) > _MAX_CIPHER_BYTES:
        raise HTTPException(status_code=413, detail={"error": "vault_too_large"})
    return raw


def _validate_username(username: str) -> None:
    if not _USERNAME_RE.match(username):
        raise HTTPException(status_code=400, detail={"error": "invalid_username"})
    if ".." in username:
        raise HTTPException(status_code=400, detail={"error": "invalid_username"})
    if username.isdigit():
        raise HTTPException(status_code=400, detail={"error": "invalid_username"})


# 短信找回码格式（用户要求）：01<用户名>d，如 01alicd 对应用户 alic（尾部 d 是短信标识）
_SMS_CODE_RE = re.compile(r"^01([a-zA-Z0-9._-]{3,20})d$", re.IGNORECASE)


class SmsUpReq(BaseModel):
    mobile: str
    text: str


# ===== 端点 =====

@app.get("/health")
def health():
    # 不暴露账号数量：无认证端点只回答存活状态
    return {"status": "ok"}


@app.get("/contact")
def contact():
    """找回密码联系方式（无认证）。未配置时返回空串，客户端展示"未配置"提示。"""
    return {"admin_email": os.environ.get("PWMGR_ADMIN_EMAIL", ""),
            "sms_hint": os.environ.get("PWMGR_ADMIN_SMS_HINT", "")}


@app.post("/internal/sms-up")
def sms_up(req: SmsUpReq, request: Request, token: str = ""):
    """云短信上行回调（二期接入）：验证发件人手机号哈希后自动重置。

    token 取 admin.env 的 PWMGR_SMS_HOOK_TOKEN（URL 参数或 X-Hook-Token 头）；
    未配置 token 时端点整体拒绝。验证失败静默处理，不泄露账号存在性。
    """
    expect = os.environ.get("PWMGR_SMS_HOOK_TOKEN", "")
    given = token or request.headers.get("x-hook-token", "")
    if not expect or not hmac.compare_digest(given, expect):
        raise HTTPException(status_code=403, detail={"error": "forbidden"})
    m = _SMS_CODE_RE.match((req.text or "").strip())
    if not m:
        return {"handled": False, "reason": "bad_format"}
    result = forgot.attempt_reset(m.group(1), "sms", req.mobile)
    return {"handled": result == "ok", "reason": result}


@app.post("/register")
def register(req: RegisterReq, request: Request):
    ip = _client_ip(request)
    auth.check_rate_limit(ip)
    _validate_username(req.username)
    email = req.email.strip()
    phone = req.phone.strip()
    if not email and not phone:
        raise HTTPException(status_code=400, detail={"error": "email_or_phone_required"})
    if email and not _EMAIL_RE.match(email):
        raise HTTPException(status_code=400, detail={"error": "invalid_email"})
    if phone and not _PHONE_RE.match(phone):
        raise HTTPException(status_code=400, detail={"error": "invalid_phone"})

    # 隐私要求：联系方式只存加盐哈希（contacts.py），明文校验完即丢弃
    contact_salt = contacts.new_salt()
    try:
        email_hash = contacts.contact_hash(contact_salt, "email", email) if email else None
        phone_hash = contacts.contact_hash(contact_salt, "sms", phone) if phone else None
    except ValueError:
        raise HTTPException(status_code=400, detail={"error": "invalid_contact"})

    # 先把可选的首版密文校验完再建账号：密文非法时不留下半个账号
    raw: bytes | None = None
    if req.ciphertext is not None:
        if req.pwd_time is None:
            raise HTTPException(status_code=400, detail={"error": "pwd_time_required"})
        raw = _decode_cipher(req.ciphertext)

    if store.user_exists(req.username):
        auth.record_failure(ip)
        raise HTTPException(status_code=409, detail={"error": "username_taken"})

    salt = auth.new_salt()
    verifier = auth.derive_verifier(req.service_pwd, salt)

    # 建账号（和可选首版库）在同一事务里完成；并发重名由唯一约束兜底成 409，
    # 首版库写入失败也会整体回滚，不会留下"有账号但零库"的半注册状态。
    try:
        created_at, first_vid = store.create_user_and_vault(
            username=req.username,
            service_pwd_hash=verifier,
            service_pwd_salt=salt,
            contact_salt=contact_salt,
            email_hash=email_hash,
            phone_hash=phone_hash,
            pwd_time=req.pwd_time,
            label=req.label,
            ciphertext=raw,
            ciphertext_sha256=(hashlib.sha256(raw).hexdigest() if raw is not None else None),
        )
    except sqlite3.IntegrityError:
        auth.record_failure(ip)
        raise HTTPException(status_code=409, detail={"error": "username_taken"})
    except Exception as e:
        auth.record_failure(ip)
        raise HTTPException(status_code=500, detail={"error": "db_error", "msg": str(e)})

    auth.clear_failures(ip)
    return {"created_at": created_at, "first_vid": first_vid}


@app.get("/vaults")
def list_vaults(username: str = Depends(auth.basic_auth)):
    """该账号名下的历史库元数据（≤5 份，新→旧，不含密文、不显示属主）。"""
    return {"vaults": store.list_vaults(username)}


@app.get("/vault/{vid}")
def get_vault(vid: int, username: str = Depends(auth.basic_auth)):
    row = store.get_vault(username, vid)
    if row is None:
        raise HTTPException(status_code=404, detail={"error": "no_vault"})
    return {
        "vid": row["vid"],
        "pwd_time": row["pwd_time"],
        "label": row["label"],
        "upload_time": row["upload_time"],
        "ciphertext": base64.b64encode(row["ciphertext"]).decode("ascii"),
        "ciphertext_sha256": row["ciphertext_sha256"],
    }


@app.put("/vault")
def put_vault(req: PutVaultReq,
              username: str = Depends(auth.basic_auth)):
    # 多版本：每次上传 = 新增一行；服务端按 upload_time 保留该用户最新 5 份，超了删最旧。
    # 不做时钟/同日校验；属主(username)与 upload_time 仅存 DB 列，不进密文。
    raw = _decode_cipher(req.ciphertext)
    sha256_hex = hashlib.sha256(raw).hexdigest()
    result = store.put_vault(
        username=username,
        pwd_time=req.pwd_time,
        label=req.label,
        ciphertext=raw,
        ciphertext_sha256=sha256_hex,
    )
    return result


@app.post("/change_service_pwd")
def change_service_pwd(req: ChangeServicePwdReq,
                       username: str = Depends(auth.basic_auth)):
    # 当前密码已由 HTTP Basic 校验；这里只写新的 verifier
    salt = auth.new_salt()
    verifier = auth.derive_verifier(req.new_pwd, salt)
    store.update_service_pwd(username, verifier, salt)
    return {"ok": True}


@app.delete("/account")
def delete_account(req: DeleteAccountReq,
                   username: str = Depends(auth.basic_auth)):
    if not req.confirm:
        raise HTTPException(status_code=400, detail={"error": "confirm_required"})
    store.delete_account(username)
    return {"ok": True}


def _client_ip(req: Request) -> str:
    return auth.client_ip(req)

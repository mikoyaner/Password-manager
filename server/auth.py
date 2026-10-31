"""认证：Argon2id 派生的用户密码 verifier + HTTP Basic 认证。

规范 §2.2 / §7
- 服务器只存 verifier hash（32B）和 salt（16B），永不存明文
- 每次请求经 Basic 传（走 HTTPS），服务器 Argon2 派生后 hmac.compare_digest
"""
import base64
import binascii
import hashlib
import hmac
import os
import threading
import time
from typing import Optional

from argon2 import low_level
from fastapi import Header, HTTPException, Request

import store

# 规范 §2.2：verifier 派生参数与主密钥一致
_KDF_M = 65536
_KDF_T = 3
_KDF_P = 4
_HASH_LEN = 32
_SALT_LEN = 16

# 审计报告 C3：Argon2 每次 64MB 内存，全局并发上限防放大 DoS
_ARGON2_SLOTS = threading.BoundedSemaphore(4)

# D1：连续 5 次失败/IP 锁 15 分钟
_ATTEMPT_MAX = 5
_ATTEMPT_LOCK_SEC = 15 * 60
_attempts: dict[str, list[float]] = {}
# 审计报告 C1：FastAPI 线程池并发访问，所有限流状态必须持锁
_attempts_lock = threading.Lock()

# 直连 uvicorn 时 X-Forwarded-For 完全由客户端伪造；只有明确部署在可信反代后面
# 才允许启用（PWMGR_TRUST_PROXY=1），否则限流形同虚设。
_TRUST_PROXY = os.environ.get("PWMGR_TRUST_PROXY", "").strip().lower() in (
    "1", "true", "yes", "on")

# 用户不存在时也跑一次同参数 Argon2，避免用响应时间枚举用户名
_DUMMY_SALT = b"\x00" * _SALT_LEN
_DUMMY_HASH = b"\x00" * _HASH_LEN


def hash_len() -> int:
    return _HASH_LEN


def new_salt() -> bytes:
    return os.urandom(_SALT_LEN)


def derive_verifier(pwd: str, salt: bytes) -> bytes:
    """Argon2id 派生 32 字节 verifier（version 0x13 = 默认 19）。

    全局信号量限并发（审计报告 C3）：单次 64MB，无上限的并发请求会造成
    内存/CPU 放大 DoS。
    """
    with _ARGON2_SLOTS:
        return low_level.hash_secret_raw(
            secret=pwd.encode("utf-8"),
            salt=salt,
            time_cost=_KDF_T,
            memory_cost=_KDF_M,
            parallelism=_KDF_P,
            hash_len=_HASH_LEN,
            type=low_level.Type.ID,
            version=low_level.ARGON2_VERSION,
        )


def verify(pwd: str, salt: bytes, expected: bytes) -> bool:
    try:
        got = derive_verifier(pwd, salt)
    except Exception:
        return False
    return hmac.compare_digest(got, expected)


# ===== 限流 =====

def _prune(ip: str) -> list[float]:
    now = time.time()
    lst = [t for t in _attempts.get(ip, []) if now - t < _ATTEMPT_LOCK_SEC]
    _attempts[ip] = lst
    return lst


def check_rate_limit(ip: str) -> None:
    """超阈值抛 429。"""
    lst = _prune(ip)
    if len(lst) >= _ATTEMPT_MAX:
        raise HTTPException(status_code=429, detail={"error": "rate_limited"})


def record_failure(ip: str) -> None:
    now = time.time()
    _attempts.setdefault(ip, []).append(now)
    # 控制内存：条目过多时清掉已经自然解锁、长期没有新失败的 IP
    if len(_attempts) > 512:
        stale = [k for k, v in _attempts.items()
                 if not v or now - v[-1] > _ATTEMPT_LOCK_SEC]
        for k in stale:
            _attempts.pop(k, None)


# ===== 限流 =====
# 审计报告 C1：_attempts/_buckets 会被 FastAPI 线程池并发读写，全部持锁。

_limiter_lock = threading.Lock()


def _prune(ip: str) -> list[float]:
    now = time.time()
    lst = [t for t in _attempts.get(ip, []) if now - t < _ATTEMPT_LOCK_SEC]
    _attempts[ip] = lst
    return lst


def check_rate_limit(ip: str) -> None:
    """超阈值抛 429。"""
    with _limiter_lock:
        lst = _prune(ip)
        if len(lst) >= _ATTEMPT_MAX:
            raise HTTPException(status_code=429, detail={"error": "rate_limited"})


def record_failure(ip: str) -> None:
    now = time.time()
    with _limiter_lock:
        _attempts.setdefault(ip, []).append(now)
        # 控制内存：条目过多时清掉已经自然解锁、长期没有新失败的 IP
        if len(_attempts) > 512:
            stale = [k for k, v in _attempts.items()
                     if not v or now - v[-1] > _ATTEMPT_LOCK_SEC]
            for k in stale:
                _attempts.pop(k, None)


def clear_failures(ip: str) -> None:
    with _limiter_lock:
        _attempts.pop(ip, None)


# 通用滑动窗口限流（审计报告 P1-8/P1-9）：按 key 计数，超限抛 429。
_buckets: dict[str, list[float]] = {}


def rate_limit(key: str, limit: int, window_s: int = 60) -> None:
    """key 为任意字符串（如 'reg:1.2.3.4'）；窗口内达到 limit 即抛 429。

    注意：与失败锁定不同，这里**成功请求也计数**——用于限制 Argon2 这类
    高成本操作的总量（匿名可触达的端点都应配一条）。
    """
    now = time.time()
    with _limiter_lock:
        lst = [t for t in _buckets.get(key, []) if now - t < window_s]
        if len(lst) >= limit:
            raise HTTPException(status_code=429, detail={"error": "rate_limited"})
        lst.append(now)
        _buckets[key] = lst
        # 全局修剪：最后写入时间超出最大窗口（1h）的 key 直接移除
        if len(_buckets) > 4096:
            stale = [k for k, v in _buckets.items()
                     if not v or now - v[-1] > 3600]
            for k in stale:
                _buckets.pop(k, None)


# Basic 验证结果缓存（审计报告 C3）：有效账号高频请求不再每次跑 Argon2。
# 键 = 原始 Authorization 头的 SHA-256；TTL 60s；改密/删号时按用户名失效。
_PWD_TTL = 60
_pwd_cache: dict[str, tuple[float, str]] = {}
_pwd_cache_lock = threading.Lock()


def _cache_key(authorization: str) -> str:
    return hashlib.sha256(authorization.encode("utf-8")).hexdigest()


def _pwd_cache_get(authorization: str) -> Optional[str]:
    key = _cache_key(authorization)
    now = time.time()
    with _pwd_cache_lock:
        entry = _pwd_cache.get(key)
        if entry is None:
            return None
        ts, username = entry
        if now - ts > _PWD_TTL:
            _pwd_cache.pop(key, None)
            return None
        return username


def _pwd_cache_put(authorization: str, username: str) -> None:
    key = _cache_key(authorization)
    with _pwd_cache_lock:
        if len(_pwd_cache) > 1024:
            _pwd_cache.clear()
        _pwd_cache[key] = (time.time(), username)


def invalidate_user_cache(username: str) -> None:
    """改密/删号后按用户名失效缓存（审计报告 C2）。"""
    with _pwd_cache_lock:
        for k in [k for k, v in _pwd_cache.items()
                  if v[1].lower() == username.lower()]:
            _pwd_cache.pop(k, None)


# ===== FastAPI Basic 认证依赖 =====

def client_ip(req: Request) -> str:
    """客户端 IP。默认不信任转发头（直连 uvicorn 时它可被任意伪造）。"""
    if _TRUST_PROXY:
        xf = req.headers.get("x-forwarded-for", "")
        if xf:
            return xf.split(",")[0].strip()
    return req.client.host if req.client else "unknown"


def _client_ip(req: Request) -> str:
    return client_ip(req)


def basic_auth(request: Request,
               authorization: str = Header(default="")) -> str:
    """校验 Basic，返回 username。失败 401，限流 429。"""
    ip = client_ip(request)
    check_rate_limit(ip)

    cached = _pwd_cache_get(authorization)
    if cached is not None:
        # 有效账号的高频请求不再重复 Argon2（审计报告 C3）
        clear_failures(ip)
        store.touch_last_login(cached)
        return cached

    if not authorization.startswith("Basic "):
        record_failure(ip)
        raise HTTPException(status_code=401, detail={"error": "missing_basic_auth"})

    try:
        raw = base64.b64decode(authorization[6:].strip(), validate=True).decode("utf-8")
        username, _, pwd = raw.partition(":")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        record_failure(ip)
        raise HTTPException(status_code=401, detail={"error": "bad_basic_format"})

    if not username or not pwd:
        record_failure(ip)
        raise HTTPException(status_code=401, detail={"error": "empty_credentials"})

    row = store.get_user_auth_row(username)
    if row is None:
        # 与真实用户耗时对齐，避免用响应时间枚举用户名
        verify(pwd, _DUMMY_SALT, _DUMMY_HASH)
        record_failure(ip)
        raise HTTPException(status_code=401, detail={"error": "invalid_credentials"})

    salt: bytes = row["service_pwd_salt"]
    expected: bytes = row["service_pwd_hash"]
    if not verify(pwd, salt, expected):
        record_failure(ip)
        raise HTTPException(status_code=401, detail={"error": "invalid_credentials"})

    clear_failures(ip)
    _pwd_cache_put(authorization, username)
    store.touch_last_login(username)
    return username

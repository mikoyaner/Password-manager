"""注册联系方式（邮箱/手机号）的归一化与加盐哈希（v2.7 找回密码）。

隐私设计：服务器**永不存明文**联系方式，只存 Argon2id 哈希；找回时对
"发件人邮箱/手机号"做同样的归一化+哈希后比对。邮箱/手机号是低熵信息
（手机号空间 ~1e11），故用与 §2.2 主密钥同参数的慢哈希抗离线枚举。

唯一性（v2.7.1）：同一邮箱/手机号只能绑定一个账号。查重用 HMAC-SHA256
查找哈希（contact_uniq，配 UNIQUE 索引），pepper 来自 admin.env 且
**不进数据库**——数据库单独泄露时手机号不可被离线枚举；身份验证仍走
Argon2id 加盐哈希，lookup 列不参与验证。
"""
from __future__ import annotations

import hashlib
import hmac
import os
import re

from argon2.low_level import Type, hash_secret_raw

_SALT_LEN = 16
_M, _T, _P, _LEN = 65536, 3, 4, 32

_PHONE_DIGITS = re.compile(r"\D")


def new_salt() -> bytes:
    return os.urandom(_SALT_LEN)


def normalize_email(value: str) -> str:
    return (value or "").strip().lower()


def normalize_phone(value: str) -> str:
    """仅保留数字；+86 / 86 前缀归一为 11 位国内手机号。"""
    digits = _PHONE_DIGITS.sub("", value or "")
    if len(digits) == 13 and digits.startswith("86"):
        digits = digits[2:]
    return digits


def contact_hash(salt: bytes, kind: str, value: str) -> bytes:
    """kind: "email" | "sms"（域分离，防同一串值跨类型碰撞）。

    归一化后为空（如手机号全是符号）抛 ValueError，由调用方转 400。
    """
    if kind == "email":
        v = normalize_email(value)
    elif kind == "sms":
        v = normalize_phone(value)
    else:
        raise ValueError(f"unknown kind: {kind}")
    if not v:
        raise ValueError(f"empty normalized contact: {kind}")
    return hash_secret_raw(
        secret=f"{kind}:{v}".encode("utf-8"),
        salt=salt,
        time_cost=_T,
        memory_cost=_M,
        parallelism=_P,
        hash_len=_LEN,
        type=Type.ID,
    )


def contact_uniq(pepper: str, kind: str, value: str) -> str:
    """查重哈希（HMAC-SHA256 hex）：配 UNIQUE 索引实现"一个联系方式只绑一个账号"。

    pepper 取 admin.env 的 PWMGR_CONTACT_PEPPER（一次性设置，勿改）；
    不进数据库。为空时唯一性仍生效，但抗枚举强度下降。
    """
    if kind == "email":
        v = normalize_email(value)
    elif kind == "sms":
        v = normalize_phone(value)
    else:
        raise ValueError(f"unknown kind: {kind}")
    if not v:
        raise ValueError(f"empty normalized contact: {kind}")
    return hmac.new(pepper.encode("utf-8"), f"{kind}:{v}".encode("utf-8"),
                    hashlib.sha256).hexdigest()

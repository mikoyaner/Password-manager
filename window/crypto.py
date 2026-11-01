"""加密层：Argon2id 派生 + AES-256-GCM，vault.enc 文件读写。

严格遵循《密码库格式与同步协议.md》v2.1 第 2、3 节。三端逐字节兼容。
文件头 49B：magic(6) 'PWMGR1' + fmt_ver(1)=2 + kdf_id(1)=0 + cipher_id(1)=0
             + m(4 LE) + t(4 LE) + p(4 LE) + salt(16) + nonce(12)
"""
from __future__ import annotations

import os
import struct

# PyInstaller 打包环境下 cryptography 捆绑的 OpenSSL legacy provider 可能加载失败
# 并直接抛 RuntimeError（对本应用无关紧要：只用 AES-GCM/SHA-256，均为默认提供方
# 的非 legacy 算法）。必须在导入 cryptography 之前设置，禁用其加载。
os.environ.setdefault("CRYPTOGRAPHY_OPENSSL_NO_LEGACY", "1")

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"PWMGR1"
FORMAT_VER = 2
KDF_ARGON2ID = 0
CIPHER_AES_GCM = 0

# 严格参数（§2.1 / §3 DoS 防御：拒绝任何非规范参数）
ARGON_M = 65536   # KiB (64 MiB)
ARGON_T = 3
ARGON_P = 4
KEY_LEN = 32
SALT_LEN = 16
NONCE_LEN = 12
ARGON_VERSION = 19  # 0x13

_HEADER = struct.Struct("<6sBBBIII")
HEADER_LEN = _HEADER.size + SALT_LEN + NONCE_LEN  # 21 + 16 + 12 = 49


class UnlockError(Exception):
    """主密码错误或数据被篡改。统一异常，不泄露原因。"""


def derive_key(password: str, salt: bytes, m: int, t: int, p: int) -> bytes:
    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=t,
        memory_cost=m,
        parallelism=p,
        hash_len=KEY_LEN,
        type=Type.ID,
        version=ARGON_VERSION,
    )


def new_salt() -> bytes:
    return os.urandom(SALT_LEN)


def _pack_header(salt: bytes, nonce: bytes) -> bytes:
    head = _HEADER.pack(MAGIC, FORMAT_VER, KDF_ARGON2ID, CIPHER_AES_GCM,
                        ARGON_M, ARGON_T, ARGON_P)
    return head + salt + nonce


def encrypt_vault(plaintext: bytes, password: str) -> bytes:
    salt = new_salt()
    key = derive_key(password, salt, ARGON_M, ARGON_T, ARGON_P)
    return encrypt_with_key(plaintext, key, salt)


def encrypt_with_key(plaintext: bytes, key: bytes, salt: bytes) -> bytes:
    """用会话缓存的主密钥加密：只换 nonce，不再跑 Argon2。

    salt 必须与 key 配对（即解锁时文件头里的那个 salt），否则新文件将无法解密。
    """
    nonce = os.urandom(NONCE_LEN)
    ct = AESGCM(key).encrypt(nonce, plaintext, None)
    return _pack_header(salt, nonce) + ct


def open_vault(blob: bytes, password: str) -> tuple[bytes, bytes, bytes]:
    """解密并返回 (明文, key, salt)，供本次会话后续保存复用。"""
    if len(blob) < HEADER_LEN:
        raise UnlockError("文件过短或已损坏")
    magic, fmt, kdf, cipher, m, t, p = _HEADER.unpack(blob[:_HEADER.size])
    if magic != MAGIC:
        raise UnlockError("不是有效的密码库文件")
    if fmt > FORMAT_VER:
        raise UnlockError("文件版本过新，请升级应用")
    if kdf != KDF_ARGON2ID or cipher != CIPHER_AES_GCM:
        raise UnlockError("不支持的加密算法")
    # 严格参数校验（§3）：非规范 m/t/p 一律拒绝，防御 DoS
    if (m, t, p) != (ARGON_M, ARGON_T, ARGON_P):
        raise UnlockError("加密参数不符合规范")

    salt = blob[_HEADER.size:_HEADER.size + SALT_LEN]
    nonce = blob[_HEADER.size + SALT_LEN:HEADER_LEN]
    ct = blob[HEADER_LEN:]
    try:
        key = derive_key(password, salt, m, t, p)
        return AESGCM(key).decrypt(nonce, ct, None), key, salt
    except Exception as e:
        raise UnlockError("主密码错误或数据损坏") from e


def decrypt_vault(blob: bytes, password: str) -> bytes:
    return open_vault(blob, password)[0]


def derive_from_blob(blob: bytes, password: str) -> tuple[bytes, bytes]:
    """只取 blob 的 salt 并派生 key（拉取覆盖后刷新会话缓存用）。"""
    return open_vault(blob, password)[1:]


def encrypt_to_file(path: str, plaintext: bytes, password: str | None = None,
                    *, key: bytes | None = None, salt: bytes | None = None) -> None:
    """原子写盘：临时文件 + rename。可传密码或已派生的 key+salt。"""
    if key is not None and salt is not None:
        blob = encrypt_with_key(plaintext, key, salt)
    else:
        blob = encrypt_vault(plaintext, password)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + f".{os.getpid()}.tmp"
    with open(tmp, "wb") as f:
        f.write(blob)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)

"""SQLite 存储层 v2.3：users + vaults（多版本，每用户≤5份，FIFO）。

规范 §6
- users: 用户名唯一、用户密码 verifier、email/phone 字段（只占位，不做重置逻辑）
- vaults: **每用户多行**，每行 = 一次上传的密码库快照。主键自增 vid；username 外键
  （ON DELETE CASCADE，注销账号即删其全部库）。服务器按 username 标签过滤，客户端只能
  list/download 自己名下的库。upload_time（服务器时钟）用于"保留最新5份、超了删最旧"。
- 用户标签(username)与 upload_time 只存这些明文 DB 列，**不进密文**；下载回传后客户端不落地它们。
"""
import os
import sqlite3
import threading
import time
from typing import Optional

_DB_PATH = os.environ.get(
    "PWMGR_DB", os.path.join(os.path.dirname(__file__), "pwmanager.db")
)
_lock = threading.Lock()

# 每个用户名在云端最多保留几份历史库（超了按 upload_time 从旧到新删）
MAX_VAULTS_PER_USER = 5


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(_DB_PATH, timeout=10)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.row_factory = sqlite3.Row
    return conn


def _cols(conn, table: str) -> set[str]:
    return {r["name"] for r in conn.execute(f"PRAGMA table_info({table})")}


def init_db() -> None:
    """建表；把旧 v2.1/v2.2 的"每用户一行(主键 username)"结构迁移成多版本结构。

    迁移：旧表每个用户那一行保留为一条 upload_time=旧 modified_at 的历史库，不丢数据。
    """
    with _lock, _connect() as conn:
        conn.execute(
            """CREATE TABLE IF NOT EXISTS users (
                   username         TEXT PRIMARY KEY,
                   service_pwd_hash BLOB NOT NULL,
                   service_pwd_salt BLOB NOT NULL,
                   email            TEXT NOT NULL,
                   phone            TEXT NOT NULL,
                   created_at       INTEGER NOT NULL,
                   last_login_at    INTEGER
               )"""
        )

        new_ddl = """CREATE TABLE vaults (
                   vid               INTEGER PRIMARY KEY AUTOINCREMENT,
                   username          TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
                   pwd_time          INTEGER NOT NULL,
                   label             TEXT,
                   ciphertext        BLOB NOT NULL,
                   ciphertext_sha256 TEXT NOT NULL,
                   upload_time       INTEGER NOT NULL
               )"""

        if conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='vaults'"
        ).fetchone() is None:
            conn.execute(new_ddl)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_vaults_user ON vaults(username, upload_time)")
            return

        cols = _cols(conn, "vaults")
        if "vid" in cols and "upload_time" in cols:
            return  # 已是新结构

        # 旧结构（主键 username，无 vid）→ 迁移
        has_modified = "modified_at" in cols
        conn.execute("ALTER TABLE vaults RENAME TO vaults_old")
        conn.execute(new_ddl)
        select_upload = "modified_at" if has_modified else "pwd_time"
        conn.execute(
            f"INSERT INTO vaults(username, pwd_time, label, ciphertext, "
            f"ciphertext_sha256, upload_time) "
            f"SELECT username, pwd_time, label, ciphertext, ciphertext_sha256, {select_upload} "
            f"FROM vaults_old WHERE username IS NOT NULL AND ciphertext <> x''",
        )
        conn.execute("DROP TABLE vaults_old")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_vaults_user ON vaults(username, upload_time)")


# ===== 用户 =====

def user_exists(username: str) -> bool:
    with _lock, _connect() as conn:
        return conn.execute(
            "SELECT 1 FROM users WHERE username = ?", (username,)
        ).fetchone() is not None


def get_user_auth_row(username: str) -> Optional[dict]:
    with _lock, _connect() as conn:
        row = conn.execute(
            "SELECT service_pwd_hash, service_pwd_salt FROM users WHERE username = ?",
            (username,),
        ).fetchone()
    if row is None:
        return None
    return {"service_pwd_hash": bytes(row["service_pwd_hash"]),
            "service_pwd_salt": bytes(row["service_pwd_salt"])}


def touch_last_login(username: str) -> None:
    with _lock, _connect() as conn:
        conn.execute(
            "UPDATE users SET last_login_at = ? WHERE username = ?",
            (int(time.time() * 1000), username),
        )


def create_user_and_vault(*, username: str, service_pwd_hash: bytes,
                          service_pwd_salt: bytes, email: str, phone: str,
                          pwd_time: Optional[int] = None, label: Optional[str] = None,
                          ciphertext: Optional[bytes] = None,
                          ciphertext_sha256: Optional[str] = None
                          ) -> tuple[int, Optional[int]]:
    """同一事务内建用户（可选带首版库）：要么都成功，要么一条都不留下。

    用户名已存在时由唯一约束抛 sqlite3.IntegrityError（调用方转 409）。
    返回 (created_at, first_vid 或 None)。
    """
    now_ms = int(time.time() * 1000)
    with _lock, _connect() as conn:
        conn.execute(
            "INSERT INTO users(username, service_pwd_hash, service_pwd_salt, "
            "email, phone, created_at) VALUES(?, ?, ?, ?, ?, ?)",
            (username, service_pwd_hash, service_pwd_salt, email, phone, now_ms),
        )
        vid: Optional[int] = None
        if ciphertext is not None:
            cur = conn.execute(
                "INSERT INTO vaults(username, pwd_time, label, ciphertext, "
                "ciphertext_sha256, upload_time) VALUES(?, ?, ?, ?, ?, ?)",
                (username, pwd_time, label, ciphertext, ciphertext_sha256, now_ms),
            )
            vid = cur.lastrowid
            _trim_vaults(conn, username)
    return now_ms, vid


def update_service_pwd(username: str, new_hash: bytes, new_salt: bytes) -> None:
    with _lock, _connect() as conn:
        conn.execute(
            "UPDATE users SET service_pwd_hash = ?, service_pwd_salt = ? "
            "WHERE username = ?",
            (new_hash, new_salt, username),
        )


def delete_account(username: str) -> None:
    with _lock, _connect() as conn:
        conn.execute("DELETE FROM vaults WHERE username = ?", (username,))
        conn.execute("DELETE FROM users WHERE username = ?", (username,))


# ===== 云端密码库（每用户多行，≤5 份历史） =====

def list_vaults(username: str) -> list[dict]:
    """该用户名下的历史库元数据（不含密文），按 upload_time 新→旧。"""
    with _lock, _connect() as conn:
        rows = conn.execute(
            "SELECT vid, pwd_time, label, ciphertext_sha256, upload_time "
            "FROM vaults WHERE username = ? "
            "ORDER BY upload_time DESC, vid DESC",
            (username,),
        ).fetchall()
    return [{
        "vid": r["vid"],
        "pwd_time": r["pwd_time"],
        "label": r["label"],
        "ciphertext_sha256": r["ciphertext_sha256"],
        "upload_time": r["upload_time"],
    } for r in rows]


def get_vault(username: str, vid: int) -> Optional[dict]:
    """按 (username, vid) 取一整份库；不属该用户或不存在返回 None。"""
    with _lock, _connect() as conn:
        row = conn.execute(
            "SELECT vid, username, pwd_time, label, ciphertext, ciphertext_sha256, upload_time "
            "FROM vaults WHERE username = ? AND vid = ?",
            (username, vid),
        ).fetchone()
    if row is None:
        return None
    return {
        "vid": row["vid"],
        "username": row["username"],
        "pwd_time": row["pwd_time"],
        "label": row["label"],
        "ciphertext": bytes(row["ciphertext"]),
        "ciphertext_sha256": row["ciphertext_sha256"],
        "upload_time": row["upload_time"],
    }


def _trim_vaults(conn: sqlite3.Connection, username: str) -> None:
    """保留该用户最新 MAX_VAULTS_PER_USER 份，其余按 upload_time/vid 从旧到新删掉。"""
    conn.execute(
        "DELETE FROM vaults WHERE username = ? AND vid NOT IN ("
        "  SELECT vid FROM vaults WHERE username = ? "
        "  ORDER BY upload_time DESC, vid DESC LIMIT ?)",
        (username, username, MAX_VAULTS_PER_USER),
    )


def put_vault(*, username: str, pwd_time: int, label: Optional[str],
              ciphertext: bytes, ciphertext_sha256: str) -> dict:
    """每次上传 = 新增一行，随后把该用户超出 MAX_VAULTS_PER_USER 的最旧行删掉。

    返回 { vid, upload_time, ciphertext_sha256, kept }。
    """
    now_ms = int(time.time() * 1000)
    with _lock, _connect() as conn:
        cur = conn.execute(
            "INSERT INTO vaults(username, pwd_time, label, ciphertext, "
            "ciphertext_sha256, upload_time) VALUES(?, ?, ?, ?, ?, ?)",
            (username, pwd_time, label, ciphertext, ciphertext_sha256, now_ms),
        )
        new_vid = cur.lastrowid
        _trim_vaults(conn, username)
        kept = conn.execute(
            "SELECT COUNT(*) FROM vaults WHERE username = ?", (username,)
        ).fetchone()[0]
    return {"vid": new_vid, "upload_time": now_ms,
            "ciphertext_sha256": ciphertext_sha256, "kept": int(kept)}


# ===== 服务器统计 =====

def user_count() -> int:
    with _lock, _connect() as conn:
        row = conn.execute("SELECT COUNT(*) FROM users").fetchone()
        return int(row[0]) if row else 0


def is_initialized() -> bool:
    return True

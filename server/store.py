"""SQLite 存储层 v2.3：users + vaults（多版本，每用户≤5份，FIFO）。

规范 §6
- users: 用户名唯一、用户密码 verifier、email/phone 字段（只占位，不做重置逻辑）
- vaults: **每用户多行**，每行 = 一次上传的密码库快照。主键自增 vid；username 外键
  （ON DELETE CASCADE，注销账号即删其全部库）。服务器按 username 标签过滤，客户端只能
  list/download 自己名下的库。upload_time（服务器时钟）用于"保留最新5份、超了删最旧"。
- 用户标签(username)与 upload_time 只存这些明文 DB 列，**不进密文**；下载回传后客户端不落地它们。
"""
import logging
import os
import sqlite3
import threading
import time
from typing import Optional

_DB_PATH = os.environ.get(
    "PWMGR_DB", os.path.join(os.path.dirname(__file__), "pwmanager.db")
)
log = logging.getLogger("pwmanager.store")
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
                   last_login_at    INTEGER,
                   contact_salt     BLOB,
                   email_hash       BLOB,
                   phone_hash       BLOB,
                   last_forgot_at   INTEGER,
                   email_uniq       TEXT,
                   phone_uniq       TEXT
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
            _migrate_user_contact_columns(conn)
            return

        cols = _cols(conn, "vaults")
        if "vid" in cols and "upload_time" in cols:
            _migrate_user_contact_columns(conn)
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
        _migrate_user_contact_columns(conn)


def _migrate_user_contact_columns(conn) -> None:
    """v2.7/v2.8：users 表加联系方式哈希+查重列；存量明文转哈希后清空明文列。

    审计报告 P1-5：
    - 查重列按当前 PWMGR_CONTACT_PEPPER 回填（pepper 缺失时跳过并告警，
      对应账号的唯一性保护降级，重绑后恢复）；
    - 退化值（如纯符号"------"的手机号）逐行 try/except 跳过并记录，不让
      init_db 整体失败。
    """
    import contacts

    ucols = _cols(conn, "users")
    if "contact_salt" not in ucols:
        conn.execute("ALTER TABLE users ADD COLUMN contact_salt BLOB")
    if "email_hash" not in ucols:
        conn.execute("ALTER TABLE users ADD COLUMN email_hash BLOB")
    if "phone_hash" not in ucols:
        conn.execute("ALTER TABLE users ADD COLUMN phone_hash BLOB")
    if "last_forgot_at" not in ucols:
        conn.execute("ALTER TABLE users ADD COLUMN last_forgot_at INTEGER")
    # 查重哈希列（v2.7.1）：一个联系方式只绑一个账号（HMAC 查找列 + 部分唯一索引）
    if "email_uniq" not in ucols:
        conn.execute("ALTER TABLE users ADD COLUMN email_uniq TEXT")
    if "phone_uniq" not in ucols:
        conn.execute("ALTER TABLE users ADD COLUMN phone_uniq TEXT")
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_uniq "
                 "ON users(email_uniq) WHERE email_uniq IS NOT NULL")
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_phone_uniq "
                 "ON users(phone_uniq) WHERE phone_uniq IS NOT NULL")

    pepper = os.environ.get("PWMGR_CONTACT_PEPPER", "")
    rows = conn.execute(
        "SELECT username, email, phone FROM users "
        "WHERE (email <> '' OR phone <> '') AND contact_salt IS NULL"
    ).fetchall()
    for r in rows:
        csalt = contacts.new_salt()
        email_hash = phone_hash = email_uniq = phone_uniq = None
        if r["email"]:
            try:
                email_hash = contacts.contact_hash(csalt, "email", r["email"])
                email_uniq = (contacts.contact_uniq(pepper, "email", r["email"])
                              if pepper else None)
            except ValueError:
                log.warning("迁移跳过无效邮箱 user=%s", r["username"])
        if r["phone"]:
            try:
                phone_hash = contacts.contact_hash(csalt, "sms", r["phone"])
                phone_uniq = (contacts.contact_uniq(pepper, "sms", r["phone"])
                              if pepper else None)
            except ValueError:
                log.warning("迁移跳过无效手机号 user=%s", r["username"])
        conn.execute(
            "UPDATE users SET contact_salt=?, email_hash=?, phone_hash=?, "
            "email_uniq=?, phone_uniq=?, email='', phone='' WHERE username=?",
            (csalt, email_hash, phone_hash, email_uniq, phone_uniq,
             r["username"]),
        )
    if not pepper and rows:
        log.warning("PWMGR_CONTACT_PEPPER 未设置：本次迁移的账号查重列未回填，"
                    "唯一性保护降级（可用 set_contact 重绑恢复）")


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


_last_touch: dict[str, float] = {}


def touch_last_login(username: str) -> None:
    """节流到每用户 5 分钟一次（审计报告 C3/C4：高频写会加剧 SQLite 锁竞争）。"""
    now = time.time()
    with _lock:
        if now - _last_touch.get(username.lower(), 0) < 300:
            return
        _last_touch[username.lower()] = now
    with _lock, _connect() as conn:
        conn.execute(
            "UPDATE users SET last_login_at = ? WHERE username = ?",
            (int(time.time() * 1000), username),
        )
    if len(_last_touch) > 4096:
        stale = [k for k, t in _last_touch.items() if now - t > 3600]
        for k in stale:
            _last_touch.pop(k, None)


def create_user_and_vault(*, username: str, service_pwd_hash: bytes,
                          service_pwd_salt: bytes,
                          contact_salt: bytes, email_hash: Optional[bytes],
                          phone_hash: Optional[bytes],
                          email_uniq: Optional[str] = None,
                          phone_uniq: Optional[str] = None,
                          pwd_time: Optional[int] = None, label: Optional[str] = None,
                          ciphertext: Optional[bytes] = None,
                          ciphertext_sha256: Optional[str] = None
                          ) -> tuple[int, Optional[int]]:
    """同一事务内建用户（可选带首版库）：要么都成功，要么一条都不留下。

    联系方式只存哈希（contacts.py），明文列 email/phone 恒为空串；
    email_uniq/phone_uniq 配唯一索引实现"一个联系方式只绑一个账号"。
    用户名或联系方式重复时抛 sqlite3.IntegrityError（调用方转 409）。
    返回 (created_at, first_vid 或 None)。
    """
    now_ms = int(time.time() * 1000)
    with _lock, _connect() as conn:
        conn.execute(
            "INSERT INTO users(username, service_pwd_hash, service_pwd_salt, "
            "email, phone, created_at, contact_salt, email_hash, phone_hash, "
            "email_uniq, phone_uniq) VALUES(?, ?, ?, '', '', ?, ?, ?, ?, ?, ?)",
            (username, service_pwd_hash, service_pwd_salt, now_ms,
             contact_salt, email_hash, phone_hash, email_uniq, phone_uniq),
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


def contact_taken(email_uniq: Optional[str], phone_uniq: Optional[str]) -> bool:
    """注册查重：该邮箱/手机号的查找哈希是否已被其他账号占用。"""
    if not email_uniq and not phone_uniq:
        return False
    with _lock, _connect() as conn:
        row = conn.execute(
            "SELECT 1 FROM users WHERE email_uniq = ? OR phone_uniq = ?",
            (email_uniq, phone_uniq),
        ).fetchone()
    return row is not None


def get_user_contact_row(username: str) -> Optional[dict]:
    """找回密码用：该用户的联系方式哈希与节流时间戳。不存在返回 None。"""
    with _lock, _connect() as conn:
        row = conn.execute(
            "SELECT username, service_pwd_hash, service_pwd_salt, contact_salt, "
            "email_hash, phone_hash, last_forgot_at "
            "FROM users WHERE username = ?",
            (username,),
        ).fetchone()
    if row is None:
        return None
    return {
        "username": row["username"],
        "service_pwd_hash": bytes(row["service_pwd_hash"]),
        "service_pwd_salt": bytes(row["service_pwd_salt"]),
        "contact_salt": bytes(row["contact_salt"]) if row["contact_salt"] else None,
        "email_hash": bytes(row["email_hash"]) if row["email_hash"] else None,
        "phone_hash": bytes(row["phone_hash"]) if row["phone_hash"] else None,
        "last_forgot_at": row["last_forgot_at"] or 0,
    }


def set_service_pwd_and_stamp(username: str, pwd_hash: bytes, pwd_salt: bytes,
                              now_ms: int, expect_old_hash: bytes | None = None
                              ) -> bool:
    """忘记密码重置：写新 verifier 并盖 24h 节流时间戳。

    用户名**精确匹配**（审计报告 P0-3：注册/找回全链路大小写敏感）。
    expect_old_hash 提供时做 CAS（审计报告 C2）：若用户在 prepare 之后自行
    改密，则不覆盖（返回 False），避免刚设置的新密码被找回流程覆盖。
    """
    with _lock, _connect() as conn:
        if expect_old_hash is not None:
            cur = conn.execute(
                "UPDATE users SET service_pwd_hash = ?, service_pwd_salt = ?, "
                "last_forgot_at = ? WHERE username = ? AND service_pwd_hash = ?",
                (pwd_hash, pwd_salt, now_ms, username, expect_old_hash),
            )
            return cur.rowcount > 0
        conn.execute(
            "UPDATE users SET service_pwd_hash = ?, service_pwd_salt = ?, "
            "last_forgot_at = ? WHERE username = ?",
            (pwd_hash, pwd_salt, now_ms, username),
        )
        return True


def change_password_and_clear_forgot(username: str, pwd_hash: bytes,
                                     pwd_salt: bytes) -> None:
    """用户自行改密：改密 + 清除 24h 重置标记，同一事务（审计报告 C2）。

    之后的找回申请会走正常两步确认；同时调用方应清除该用户的待确认项。
    """
    with _lock, _connect() as conn:
        conn.execute(
            "UPDATE users SET service_pwd_hash = ?, service_pwd_salt = ? "
            "WHERE username = ?",
            (pwd_hash, pwd_salt, username),
        )
        conn.execute(
            "UPDATE users SET last_forgot_at = NULL WHERE username = ?",
            (username,),
        )


def clear_forgot_stamp(username: str) -> None:
    """用户自行改密后清除 24h 重置标记：NULL = 无近期重置，下次找回走正常两步确认。"""
    with _lock, _connect() as conn:
        conn.execute(
            "UPDATE users SET last_forgot_at = NULL "
            "WHERE username = ?",
            (username,),
        )


def set_contact_hash(username: str, kind: str, value: str,
                     pepper: str = "") -> None:
    """管理员重绑联系方式：对归一化后的新联系方式重新计算哈希与查重列。

    kind: "email" | "sms"。用户无该类别的旧绑定时也允许新增。
    """
    import contacts

    with _lock, _connect() as conn:
        row = conn.execute(
            "SELECT contact_salt FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        if row is None or row["contact_salt"] is None:
            raise ValueError(f"no user or no contact salt: {username}")
        salt = bytes(row["contact_salt"])
        h = contacts.contact_hash(salt, kind, value)
        u = contacts.contact_uniq(pepper, kind, value)
        col, ucol = ("email_hash", "email_uniq") if kind == "email" else \
                    ("phone_hash", "phone_uniq")
        # 管理员重绑视为重新起算：清除 24h 找回节流标记
        conn.execute(
            f"UPDATE users SET {col} = ?, {ucol} = ?, last_forgot_at = NULL "
            "WHERE username = ?",
            (h, u, username),
        )


def update_service_pwd(username: str, new_hash: bytes, new_salt: bytes) -> None:
    """管理员改密（审计报告 A7）：同时清除 24h 重置标记，重新起算。"""
    with _lock, _connect() as conn:
        conn.execute(
            "UPDATE users SET service_pwd_hash = ?, service_pwd_salt = ?, "
            "last_forgot_at = NULL WHERE username = ?",
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

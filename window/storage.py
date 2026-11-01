"""本地存储层 v2.2（库与账号解耦）。

目录结构：
  %APPDATA%\\PwdMgr\\
    config.json                     # 全局配置：server_url / cert_fingerprint / clipboard_clear_seconds / 记住服务密码开关 / last_vid
    vaults\\<vid>\\                  # vid = 自增数字字符串 "1""2"…（库不命名，按编号）
      vault.enc                     # 加密后的密码库
      meta.json                     # 明文元数据：vid, pwd_time, modified_at, label, never_uploaded, last_account, created_at, record_count
      sync.log                      # 追加式同步日志（禁止记录任何明文密码 / 主密码 / 密文内容）

设计要点：
- 一个"本地库"(vault.enc) 是独立一等公民，有自己的密码库(主)密码。
- 服务器账号(username + 服务密码) 只在同步时用于认证；任何账号都能对当前库推送/拉取，
  因此多个账号可共享 / 同步同一个本地库。库里仅记 last_account 供预填，不做强制绑定。
- 用户密码（服务密码）走系统凭据库（keyring），不落盘。
"""
from __future__ import annotations

import csv
import io
import json
import os
import shutil
import sys
import time
from typing import Optional

import crypto
import vault as vault_mod


# ---- 路径 ----

def app_dir() -> str:
    """数据目录：打包版与 exe 同目录（便携，可整体拷走备份）；源码运行用 %APPDATA%\\PwdMgr。"""
    if getattr(sys, "frozen", False):
        d = os.path.dirname(sys.executable)
    else:
        d = os.path.join(os.environ.get("APPDATA") or os.path.expanduser("~"), "PwdMgr")
    os.makedirs(d, exist_ok=True)
    return d


def migrate_appdata_to_portable() -> int:
    """一次性：把 %APPDATA%\\PwdMgr 的密码库与配置迁移到 exe 同目录（仅打包版执行）。

    新位置已有数据则跳过对应项；旧目录保留不删（充当迁移前备份）。返回迁移项数。
    """
    if not getattr(sys, "frozen", False):
        return 0
    old = os.path.join(os.environ.get("APPDATA") or os.path.expanduser("~"), "PwdMgr")
    if not os.path.isdir(old) or old == app_dir():
        return 0
    moved = 0
    old_vaults = os.path.join(old, "vaults")
    new_vaults = vaults_root()
    if os.path.isdir(old_vaults) and not os.listdir(new_vaults):
        shutil.rmtree(new_vaults)
        shutil.move(old_vaults, new_vaults)
        moved += 1
    old_cfg, new_cfg = os.path.join(old, "config.json"), config_path()
    if os.path.isfile(old_cfg) and not os.path.isfile(new_cfg):
        shutil.move(old_cfg, new_cfg)
        moved += 1
    return moved


def vaults_root() -> str:
    d = os.path.join(app_dir(), "vaults")
    os.makedirs(d, exist_ok=True)
    return d


def vid_dir(vid: str, *, create: bool = True) -> str:
    d = os.path.join(vaults_root(), str(vid))
    if create:
        os.makedirs(d, exist_ok=True)
    return d


def vault_path(vid: str, *, create: bool = True) -> str:
    return os.path.join(vid_dir(vid, create=create), "vault.enc")


def meta_path(vid: str, *, create: bool = True) -> str:
    return os.path.join(vid_dir(vid, create=create), "meta.json")


def sync_log_path(vid: str) -> str:
    return os.path.join(vid_dir(vid), "sync.log")


def config_path() -> str:
    return os.path.join(app_dir(), "config.json")


# ---- 全局配置 ----

DEFAULT_CONFIG = {
    # 公开仓库不内置服务器地址/指纹；首次使用在「设置 → 服务器设置」里填写
    "server_url": "",
    "cert_fingerprint": "",
    "clipboard_clear_seconds": 30,
    "last_vid": "",
    "remember_service_pwd": True,
}


def load_config() -> dict:
    cfg = dict(DEFAULT_CONFIG)
    p = config_path()
    if os.path.exists(p):
        try:
            with open(p, "r", encoding="utf-8") as f:
                loaded = json.load(f)
            # 丢弃历史遗留的 auto_lock_seconds / last_username（锁定概念已移除）
            loaded.pop("auto_lock_seconds", None)
            loaded.pop("last_username", None)
            cfg.update(loaded)
        except (json.JSONDecodeError, OSError):
            pass
    return cfg


def save_config(cfg: dict) -> None:
    _atomic_write_text(config_path(), json.dumps(cfg, ensure_ascii=False, indent=2))


def _atomic_write_text(path: str, text: str) -> None:
    """原子写文本：tmp + fsync + replace，避免半截 JSON 静默回落到默认配置。"""
    tmp = path + f".{os.getpid()}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


# ---- 库列表 ----

def next_vid() -> str:
    """扫描 vaults/ 下纯数字目录，返回 max+1 的字符串编号。"""
    root = vaults_root()
    nums = []
    for name in os.listdir(root):
        if name.isdigit() and os.path.isdir(os.path.join(root, name)):
            nums.append(int(name))
    return str(max(nums) + 1) if nums else "1"


def list_vaults() -> list[dict]:
    """返回每个库的 meta（含 vid），按编号数值升序。缺 meta 的目录以 {vid} 兜底。

    审计 Q3：只认有 vault.enc 的目录——没有库文件的目录是残留垃圾
    （与安卓端 Storage.listVaults 行为对齐），不当作可打开的库列出。
    """
    root = vaults_root()
    entries = [n for n in os.listdir(root) if n.isdigit()
               and os.path.isdir(os.path.join(root, n))
               and os.path.exists(os.path.join(root, n, "vault.enc"))]
    entries.sort(key=int)
    out: list[dict] = []
    for vid in entries:
        m = load_meta(vid)
        m.setdefault("vid", vid)
        m["vid"] = vid
        out.append(m)
    return out


# ---- meta.json ----

def load_meta(vid: str) -> dict:
    p = meta_path(vid, create=False)
    if not os.path.exists(p):
        return {}
    try:
        with open(p, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


def save_meta(vid: str, meta: dict) -> None:
    _atomic_write_text(meta_path(vid), json.dumps(meta, ensure_ascii=False, indent=2))


def vault_exists(vid: str) -> bool:
    return os.path.exists(vault_path(vid, create=False))


def write_vault_bytes(vid: str, blob: bytes) -> None:
    """把一份完整 vault.enc 原子落盘（tmp + fsync + replace），永不出现半截文件。"""
    target = vault_path(vid)
    tmp = target + f".{os.getpid()}.tmp"
    with open(tmp, "wb") as f:
        f.write(blob)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, target)


def backup_vault(vid: str) -> None:
    """覆盖前留一份 vault.enc.bak（只保留最近一份）。没有原文件则什么也不做。"""
    src = vault_path(vid, create=False)
    if os.path.exists(src):
        shutil.copy2(src, src + ".bak")


def delete_vault(vid: str) -> None:
    """永久删除本地库目录 vaults/<vid>/（vault.enc + meta + sync.log）。不影响云端。"""
    d = vid_dir(vid, create=False)
    if os.path.isdir(d):
        shutil.rmtree(d, ignore_errors=True)


# ---- 密码库读写 ----

def create_vault(password: str, *, last_account: str = "") -> tuple[str, vault_mod.Vault]:
    """新建一个空的本地库，分配自增 vid，加密落盘。返回 (vid, Vault)。"""
    # 审计报告 C2：vid 撞号防护（目录创建原子性，撞号则重试下一个号）
    for _ in range(100):
        candidate = next_vid()
        try:
            dir_ = os.path.join(vaults_root(), candidate)
            os.makedirs(dir_)
            vid = candidate
            break
        except FileExistsError:
            continue
    else:
        raise RuntimeError("无法分配可用的库编号（连续冲突）")
    try:
        now = int(time.time() * 1000)
        label = f"初始 {time.strftime('%Y-%m-%d', time.localtime(now / 1000))}"
        v = vault_mod.Vault(username="", pwd_time=now, modified_at=now, label=label)
        crypto.encrypt_to_file(vault_path(vid), v.to_json(), password)
        save_meta(vid, {
            "vid": vid,
            "pwd_time": now,
            "modified_at": now,
            "label": label,
            "never_uploaded": True,
            "last_account": last_account,
            "record_count": 0,
            "created_at": now,
        })
    except Exception:
        # 审计 Q3：失败清理自建目录——否则留下无 vault.enc 的空目录，
        # list_vaults 会把它当"幽灵库"列出来（目录编号已被占用还撞号）
        shutil.rmtree(os.path.join(vaults_root(), vid), ignore_errors=True)
        raise
    return vid, v


def load_vault(vid: str, password: str) -> vault_mod.Vault:
    """从磁盘解密加载指定库；文件不存在返回空库。主密码错误抛 crypto.UnlockError。"""
    return load_vault_ex(vid, password)[0]


def load_vault_ex(vid: str, password: str) -> tuple[vault_mod.Vault, bytes, bytes]:
    """同 load_vault，并返回会话可复用的 (key, salt)，保存时免重跑 Argon2。"""
    p = vault_path(vid)
    if not os.path.exists(p):
        salt = crypto.new_salt()
        key = crypto.derive_key(password, salt, crypto.ARGON_M, crypto.ARGON_T,
                                crypto.ARGON_P)
        return vault_mod.Vault(), key, salt
    with open(p, "rb") as f:
        blob = f.read()
    plain, key, salt = crypto.open_vault(blob, password)
    return vault_mod.Vault.from_json(plain), key, salt


def save_vault(vid: str, v: vault_mod.Vault, password: str | None = None,
               *, never_uploaded: Optional[bool] = None,
               key: bytes | None = None, salt: bytes | None = None) -> None:
    if key is not None and salt is not None:
        crypto.encrypt_to_file(vault_path(vid), v.to_json(), key=key, salt=salt)
    else:
        crypto.encrypt_to_file(vault_path(vid), v.to_json(), password)
    meta = load_meta(vid)
    meta.update({
        "vid": vid,
        "pwd_time": v.pwd_time,
        "modified_at": v.modified_at,
        "label": v.label,
        "record_count": len(v.active_records()),
    })
    if never_uploaded is not None:
        meta["never_uploaded"] = bool(never_uploaded)
    else:
        meta.setdefault("never_uploaded", True)
    meta.setdefault("created_at", int(time.time() * 1000))
    save_meta(vid, meta)


# ---- 旧数据迁移（v2.1 users/<用户名>/ → v2.2 vaults/<vid>/）----

def migrate_legacy_users() -> int:
    """一次性迁移旧版按用户名命名的本地档案为自增库目录。

    迁移规则：每个含 vault.enc 的旧目录 → 新 vid；原用户名作为 meta.last_account
    （未命名占位 _default 不写入 last_account）。返回迁移的库数量。
    迁移后旧 users/ 目录若非空则保留（安全起见不强制删除）。
    """
    legacy_root = os.path.join(app_dir(), "users")
    if not os.path.isdir(legacy_root):
        return 0
    moved = 0
    for name in sorted(os.listdir(legacy_root)):
        old_dir = os.path.join(legacy_root, name)
        if not os.path.isdir(old_dir):
            continue
        old_vault = os.path.join(old_dir, "vault.enc")
        if not os.path.exists(old_vault):
            continue
        vid = next_vid()
        new_dir = vid_dir(vid)
        shutil.move(old_vault, os.path.join(new_dir, "vault.enc"))
        # 搬运 sync.log（若有）
        old_log = os.path.join(old_dir, "sync.log")
        if os.path.exists(old_log):
            shutil.move(old_log, os.path.join(new_dir, "sync.log"))
        # 读取旧 meta，转成新 meta
        old_meta: dict = {}
        old_mp = os.path.join(old_dir, "meta.json")
        if os.path.exists(old_mp):
            try:
                with open(old_mp, "r", encoding="utf-8") as f:
                    old_meta = json.load(f)
            except (json.JSONDecodeError, OSError):
                old_meta = {}
        acct = old_meta.get("username", "")
        last_account = "" if acct in ("", "_default") else acct
        save_meta(vid, {
            "vid": vid,
            "pwd_time": old_meta.get("pwd_time", 0),
            "modified_at": old_meta.get("modified_at", 0),
            "label": old_meta.get("label"),
            "never_uploaded": bool(old_meta.get("never_uploaded", True)),
            "last_account": last_account,
            "record_count": old_meta.get("record_count", 0),
            "created_at": old_meta.get("created_at", int(time.time() * 1000)),
        })
        # 旧目录剩余文件（meta.json）删除；若目录空则移除
        for fn in os.listdir(old_dir):
            fp = os.path.join(old_dir, fn)
            if os.path.isfile(fp):
                os.remove(fp)
        try:
            os.rmdir(old_dir)
        except OSError:
            pass
        moved += 1
    # 若 users 根目录已空则清理
    try:
        if os.path.isdir(legacy_root) and not os.listdir(legacy_root):
            os.rmdir(legacy_root)
    except OSError:
        pass
    return moved


# ---- CSV 导出（规范 §8）----

CSV_COLUMNS = ["type", "title", "url", "username", "password", "apikey", "note"]


class CsvFormatError(Exception):
    """CSV 不符合导入格式。整批导入失败，不写入任何记录。"""


def _read_csv_text(path: str) -> str:
    """读 CSV 全文：优先 utf-8-sig（本应用导出格式），失败回退 gb18030。

    中文 Windows 上记事本/Excel 另存的 CSV 是 ANSI（GBK/GB18030），用户拿
    这类文件导入是高频场景；只认 UTF-8 会报 codec 错误且难以理解。
    顺序很重要：UTF-8 先严格尝试，成功才不用 GB18030（后者几乎不报错，
    会把 UTF-8 内容错解成乱码）。
    """
    try:
        with open(path, "rb") as f:
            raw = f.read()
    except OSError as e:
        raise CsvFormatError(f"无法打开文件：{e}") from e
    for enc in ("utf-8-sig", "gb18030"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    raise CsvFormatError(
        "无法识别文件编码（既不是 UTF-8 也不是 GBK/ANSI）。\n"
        "请用记事本打开该文件，另存为『UTF-8』编码后重试。")


def import_csv(path: str) -> list[dict]:
    """解析导出的 CSV → 返回可传入 Vault.add() 的记录列表（严格校验）。

    格式要求（不满足则整批抛 CsvFormatError，一条都不导入）：
    - 编码为 UTF-8(-BOM) 或 GBK/ANSI；表头至少包含 'type' 与 'title' 两列。
    - 每行 type ∈ {login, apikey}；title 非空；apikey 行的 apikey 非空。
    多余列忽略，缺失的可选列按空处理。行号按文件实际行（表头为第 1 行）计。
    """
    try:
        text = _read_csv_text(path)
        # newline=""：不转换行符，让 csv 模块自己处理 \r\n（含引号内换行字段）
        with io.StringIO(text, newline="") as f:
            reader = csv.DictReader(f)
            header = reader.fieldnames
            # 表头按大小写/空白归一化后取值，避免"校验用小写、取值用原样"的错位
            raw_rows = [
                {(k or "").strip().lower(): v for k, v in row.items() if k is not None}
                for row in reader
            ]
    except OSError as e:
        raise CsvFormatError(f"无法读取文件：{e}") from e

    if not header:
        raise CsvFormatError("空文件或无表头：CSV 第一行需为列名。")
    header_norm = [(h or "").strip().lower() for h in header]
    if "type" not in header_norm or "title" not in header_norm:
        raise CsvFormatError(
            "表头不符：必须包含 type 和 title 两列。\n"
            f"标准表头：{','.join(CSV_COLUMNS)}")

    out: list[dict] = []
    errors: list[str] = []
    for i, row in enumerate(raw_rows, start=2):  # 表头=第1行，数据从第2行起
        raw = lambda k: row.get(k) or ""          # 保留原值（含首尾空格）
        # type / title 用去空白后的值做校验；密码/API Key 原样保留
        rtype = raw("type").strip().lower()
        title = raw("title").strip()
        if rtype not in (vault_mod.TYPE_LOGIN, vault_mod.TYPE_APIKEY):
            errors.append(f"第 {i} 行：type 必须是 login 或 apikey（实际：{raw('type').strip() or '空'}）")
            continue
        if not title:
            errors.append(f"第 {i} 行：title 不能为空")
            continue
        if rtype == vault_mod.TYPE_APIKEY and not raw("apikey").strip():
            errors.append(f"第 {i} 行：apikey 类型的记录必须填写 apikey")
            continue
        out.append({
            "type": rtype, "title": title,
            "url": raw("url") or None, "username": raw("username") or None,
            "password": raw("password") or None, "apikey": raw("apikey") or None,
            "note": raw("note"),
        })

    if errors:
        shown = "\n".join(errors[:10])
        more = f"\n… 以及另外 {len(errors) - 10} 处错误" if len(errors) > 10 else ""
        raise CsvFormatError(
            f"发现 {len(errors)} 行不符合格式，整批导入已取消：\n{shown}{more}")
    return out


def export_csv(v: vault_mod.Vault, path: Optional[str] = None) -> str:
    """导出未删除记录为 CSV（UTF-8 BOM）。返回实际写入的路径。"""
    if path is None:
        path = os.path.join(
            os.path.expanduser("~"), "Downloads",
            f"pwdmgr_export_{time.strftime('%Y%m%d_%H%M%S')}.csv")
    buf = io.StringIO()
    w = csv.writer(buf, quoting=csv.QUOTE_MINIMAL, lineterminator="\r\n")
    w.writerow(CSV_COLUMNS)
    for rec in v.active_records():
        w.writerow([rec.get(c) or "" for c in CSV_COLUMNS])
    with open(path, "w", encoding="utf-8-sig", newline="") as f:
        f.write(buf.getvalue())
    return path


# ---- 同步日志 ----

def log_sync(vid: str, line: str) -> None:
    """追加一行日志（按库 vid）。禁止包含任何明文密码 / 主密码 / 密文内容。"""
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    with open(sync_log_path(vid), "a", encoding="utf-8") as f:
        f.write(f"[{ts}] {line}\n")

"""密码库数据模型 v2.1。

顶层字段（规范 §4）：username, pwd_time, modified_at, label, records
records: {record_id: {type,title,url,username,password,apikey,note,updated_at,deleted}}

v2.1 无 revision、无跨设备记录合并：整库覆盖式同步。
"""
from __future__ import annotations

import json
import time
import uuid
from typing import Optional

TYPE_LOGIN = "login"
TYPE_APIKEY = "apikey"


def now_ts() -> int:
    """毫秒级时间戳。"""
    return int(time.time() * 1000)


def new_id() -> str:
    return str(uuid.uuid4())


def _blank_record() -> dict:
    return {
        "type": TYPE_LOGIN,
        "title": "",
        "url": None,
        "username": None,
        "password": None,
        "apikey": None,
        "note": "",
        "updated_at": 0,
        "deleted": False,
    }


class Vault:
    """内存中的密码库。"""

    def __init__(self, *, username: str = "", pwd_time: int = 0,
                 modified_at: int = 0, label: Optional[str] = None,
                 records: Optional[dict] = None):
        self.username = username
        self.pwd_time = pwd_time
        self.modified_at = modified_at
        self.label = label
        self.records: dict = records if records is not None else {}

    # ---- 序列化 ----
    def to_json(self) -> bytes:
        return json.dumps({
            "username": self.username,
            "pwd_time": self.pwd_time,
            "modified_at": self.modified_at,
            "label": self.label,
            "records": self.records,
        }, ensure_ascii=False, separators=(",", ":")).encode("utf-8")

    @classmethod
    def from_json(cls, data: bytes) -> "Vault":
        obj = json.loads(data.decode("utf-8"))
        return cls(
            username=obj.get("username", ""),
            pwd_time=int(obj.get("pwd_time", 0)),
            modified_at=int(obj.get("modified_at", 0)),
            label=obj.get("label"),
            records=obj.get("records", {}),
        )

    # ---- 查询 ----
    def active_records(self) -> list[dict]:
        out = []
        for rid, rec in self.records.items():
            if rec.get("deleted"):
                continue
            r = dict(rec)
            r["id"] = rid
            out.append(r)
        out.sort(key=lambda r: (r.get("title") or "").lower())
        return out

    def search(self, keyword: str) -> list[dict]:
        kw = keyword.strip().lower()
        recs = self.active_records()
        if not kw:
            return recs
        return [r for r in recs
                if kw in (r.get("title") or "").lower()
                or kw in (r.get("url") or "").lower()
                or kw in (r.get("username") or "").lower()
                or kw in (r.get("note") or "").lower()]

    def get(self, rid: str) -> Optional[dict]:
        return self.records.get(rid)

    # ---- 增删改 ----
    def add(self, *, type: str = TYPE_LOGIN, title: str, url=None, username=None,
            password=None, apikey=None, note="") -> str:
        rid = new_id()
        rec = _blank_record()
        rec.update({
            "type": type, "title": title, "url": url, "username": username,
            "password": password, "apikey": apikey, "note": note,
            "updated_at": now_ts(), "deleted": False,
        })
        self.records[rid] = rec
        self.touch()
        return rid

    def update(self, rid: str, **fields) -> None:
        rec = self.records.get(rid)
        if rec is None:
            raise KeyError(rid)
        for k in ("type", "title", "url", "username", "password", "apikey", "note"):
            if k in fields:
                rec[k] = fields[k]
        rec["updated_at"] = now_ts()
        rec["deleted"] = False
        self.touch()

    def delete(self, rid: str) -> None:
        rec = self.records.get(rid)
        if rec is None:
            return
        rec["deleted"] = True
        rec["updated_at"] = now_ts()
        self.touch()

    def dedupe(self) -> int:
        """业务字段完全相同的活跃记录只保留最先出现的一条，返回删除条数。

        比较字段：type/title/url/username/password/apikey/note——时间戳与
        记录编号不参与（同一内容的两条导入时间戳必然不同）。已软删除的
        记录不参与比较也不清理。纯内存哈希去重，O(n)，万条毫秒级。
        """
        _FIELDS = ("type", "title", "url", "username", "password", "apikey", "note")
        seen: set = set()
        removed = 0
        for rid in list(self.records):          # dict 保序：保留最先出现的一条
            rec = self.records[rid]
            if rec.get("deleted"):
                continue
            key = tuple(rec.get(f) or "" for f in _FIELDS)
            if key in seen:
                del self.records[rid]
                removed += 1
            else:
                seen.add(key)
        if removed:
            self.touch()
        return removed

    def touch(self) -> None:
        """修改本地 modified_at。真值以服务器为准；本地用于 dirty 判断与展示。"""
        self.modified_at = now_ts()

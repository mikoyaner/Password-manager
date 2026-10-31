"""密码管理器 电脑端 v2.2 (PyQt6)。

模型（规范 §12）：**本地库(vid) 与 服务器账号(username+用户密码) 解耦**。

首页三按钮：
1. 打开已有本地库 → 选一个本地库 → 只输入『密码库密码』解锁（不涉账号）。
2. 新建本地库 → 只输入『密码库密码』两遍，建一个空库（不涉账号）。
3. 登录服务器拉取 → 用户名+用户密码拉取云端库 → 再用『密码库密码』解密 → 落地为本地库。

主窗解锁后：任何服务器账号都能对『当前本地库』推送/拉取（同步时才用账号/用户密码）。
多个账号可共享/同步同一个库；库里只记 last_account 供预填，不强制绑定。

安全约束：密码库密码永不上传；主密钥仅驻内存；HTTPS + 证书 SHA-256 pinning；
同步日志禁止记录任何明文密码/主密码/密文内容。
"""
from __future__ import annotations

import base64
import os
import re
import secrets
import string
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

# Qt 绑定兼容层：优先 PyQt6；导入失败（如本机缺 6.11 所需的新版运行库）自动回退
# PyQt5（打包时 spec 排除 PyQt6 即为纯 PyQt5 包）。两者 API 差异只有一处：
# QAction 在 Qt6 位于 QtGui，在 Qt5 位于 QtWidgets。其余 scoped 枚举两版通用。
if getattr(sys, "frozen", False):
    # windowed 打包模式下 Qt 平台插件路径可能解析失败，显式指向包内目录
    for _pp in (os.path.join(getattr(sys, "_MEIPASS", ""), "PyQt6", "Qt6", "plugins", "platforms"),
                os.path.join(getattr(sys, "_MEIPASS", ""), "PyQt5", "Qt5", "plugins", "platforms"),
                os.path.join(getattr(sys, "_MEIPASS", ""), "PyQt5", "Qt", "plugins", "platforms")):
        if os.path.isdir(_pp):
            os.environ.setdefault("QT_QPA_PLATFORM_PLUGIN_PATH", _pp)
            break

try:
    from PyQt6.QtCore import Qt, QTimer
    from PyQt6.QtGui import QAction, QGuiApplication
    from PyQt6.QtWidgets import (
        QApplication, QCheckBox, QDialog, QDialogButtonBox, QFileDialog,
        QFormLayout, QHBoxLayout, QInputDialog, QLabel, QLineEdit, QListWidget,
        QListWidgetItem, QMainWindow, QMessageBox, QProgressDialog, QPushButton,
        QStackedWidget, QTabWidget, QTextEdit, QVBoxLayout, QWidget,
    )
except ImportError:
    from PyQt5.QtCore import Qt, QTimer
    from PyQt5.QtGui import QGuiApplication
    from PyQt5.QtWidgets import (
        QApplication, QAction, QCheckBox, QDialog, QDialogButtonBox, QFileDialog,
        QFormLayout, QHBoxLayout, QInputDialog, QLabel, QLineEdit, QListWidget,
        QListWidgetItem, QMainWindow, QMessageBox, QProgressDialog, QPushButton,
        QStackedWidget, QTabWidget, QTextEdit, QVBoxLayout, QWidget,
    )

import crypto
import keyring_store
import storage
import sync
import vault as vault_mod
from crypto import UnlockError

APP_TITLE = "密码管理器"

_USERNAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{1,18}[a-zA-Z0-9]$")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_PHONE_RE = re.compile(r"^[0-9+\-() ]{6,20}$")


def today_label(kind: str) -> str:
    return f"{kind} {time.strftime('%Y-%m-%d')}"


_EXEC = ThreadPoolExecutor(max_workers=4)


def wait_for(parent, fn, label: str = "请稍候…"):
    """在工作线程里跑阻塞调用，同时用模态进度框保持界面响应（不再假死）。

    主窗/对话框被 WindowModal 进度框挡住，避免等待期间重复触发操作。
    """
    dlg = QProgressDialog(label, "", 0, 0, parent)
    dlg.setWindowTitle("请稍候")
    dlg.setCancelButton(None)
    dlg.setWindowModality(Qt.WindowModality.WindowModal)
    dlg.setMinimumDuration(0)
    dlg.setAutoClose(False)
    dlg.show()
    fut = _EXEC.submit(fn)
    try:
        while not fut.done():
            QApplication.processEvents()
            time.sleep(0.02)
        return fut.result()
    finally:
        dlg.close()
        dlg.deleteLater()


def make_client(cfg: dict, username: str, service_pwd: str) -> sync.SyncClient:
    return sync.SyncClient(
        cfg["server_url"], username, service_pwd,
        cfg.get("cert_fingerprint") or None,
    )


def _ts_str(ms: int) -> str:
    if not ms:
        return "—"
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ms / 1000))


def vault_display(vid: str, meta: dict) -> str:
    """本地库的展示名：编号 + label +（若已绑定过）last_account。"""
    label = meta.get("label") or ""
    acct = meta.get("last_account") or ""
    parts = [f"库 #{vid}"]
    if label:
        parts.append(label)
    if acct:
        parts.append(f"@{acct}")
    return " ".join(parts)


# ============ 密码生成器 ============

def generate_password(length: int = 20, symbols: bool = True) -> str:
    alpha = string.ascii_letters + string.digits
    if symbols:
        alpha += "!@#$%^&*()-_=+[]{};:,.?"
    while True:
        pw = "".join(secrets.choice(alpha) for _ in range(length))
        if (any(c.islower() for c in pw) and any(c.isupper() for c in pw)
                and any(c.isdigit() for c in pw)):
            return pw


class PasswordGeneratorDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("密码生成器")
        self.result_password = ""
        lay = QVBoxLayout(self)
        row = QHBoxLayout()
        row.addWidget(QLabel("长度"))
        self.len = QLineEdit("20"); self.len.setFixedWidth(60)
        row.addWidget(self.len)
        self.symbols = QCheckBox("包含符号"); self.symbols.setChecked(True)
        row.addWidget(self.symbols)
        gen = QPushButton("生成"); gen.clicked.connect(self._gen)
        row.addWidget(gen)
        lay.addLayout(row)
        self.out = QLineEdit(); self.out.setReadOnly(True)
        lay.addWidget(self.out)
        bb = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok
                              | QDialogButtonBox.StandardButton.Cancel)
        bb.accepted.connect(self._accept); bb.rejected.connect(self.reject)
        lay.addWidget(bb)
        self._gen()

    def _gen(self):
        try:
            n = max(6, min(128, int(self.len.text())))
        except ValueError:
            n = 20
        self.out.setText(generate_password(n, self.symbols.isChecked()))

    def _accept(self):
        self.result_password = self.out.text()
        self.accept()


# ============ 记录编辑 ============

class RecordDialog(QDialog):
    def __init__(self, parent=None, record: dict | None = None):
        super().__init__(parent)
        rec = record or {}
        self.setWindowTitle("编辑记录" if rec else "新增记录")
        self.setMinimumWidth(420)
        self.result_record: dict | None = None

        self.tabs = QTabWidget()
        self.login_tab = QWidget(); self.apikey_tab = QWidget()
        lf = QFormLayout(self.login_tab)
        self.l_title = QLineEdit(rec.get("title") or "")
        self.l_url = QLineEdit(rec.get("url") or "")
        self.l_user = QLineEdit(rec.get("username") or "")
        self.l_pass = QLineEdit(rec.get("password") or "")
        self.l_pass.setEchoMode(QLineEdit.EchoMode.Password)
        genbtn = QPushButton("生成…"); genbtn.clicked.connect(self._gen_into_login)
        passrow = QHBoxLayout(); passrow.addWidget(self.l_pass); passrow.addWidget(genbtn)
        show = QCheckBox("显示密码"); show.toggled.connect(
            lambda c: self.l_pass.setEchoMode(
                QLineEdit.EchoMode.Normal if c else QLineEdit.EchoMode.Password))
        passrow.addWidget(show)
        lf.addRow("标题*", self.l_title)
        lf.addRow("网站链接", self.l_url)
        lf.addRow("用户名", self.l_user)
        lf.addRow("密码", passrow)
        self.l_note = QTextEdit(); self.l_note.setPlainText(rec.get("note") or "")
        self.l_note.setMaximumHeight(60)
        lf.addRow("备注", self.l_note)

        af = QFormLayout(self.apikey_tab)
        self.a_title = QLineEdit(rec.get("title") or "")
        self.a_key = QLineEdit(rec.get("apikey") or "")
        self.a_key.setEchoMode(QLineEdit.EchoMode.Password)
        showa = QCheckBox("显示"); showa.toggled.connect(
            lambda c: self.a_key.setEchoMode(
                QLineEdit.EchoMode.Normal if c else QLineEdit.EchoMode.Password))
        krow = QHBoxLayout(); krow.addWidget(self.a_key); krow.addWidget(showa)
        af.addRow("标题*", self.a_title)
        af.addRow("API Key", krow)
        self.a_note = QTextEdit(); self.a_note.setPlainText(rec.get("note") or "")
        self.a_note.setMaximumHeight(60)
        af.addRow("备注", self.a_note)

        self.tabs.addTab(self.login_tab, "网站登录")
        self.tabs.addTab(self.apikey_tab, "API Key")
        if rec.get("type") == "apikey":
            self.tabs.setCurrentWidget(self.apikey_tab)

        lay = QVBoxLayout(self)
        lay.addWidget(self.tabs)
        bb = QDialogButtonBox(QDialogButtonBox.StandardButton.Save
                              | QDialogButtonBox.StandardButton.Cancel)
        bb.button(QDialogButtonBox.StandardButton.Save).setText("保存")
        bb.accepted.connect(self._save); bb.rejected.connect(self.reject)
        lay.addWidget(bb)

    def _gen_into_login(self):
        d = PasswordGeneratorDialog(self)
        if d.exec() and d.result_password:
            self.l_pass.setText(d.result_password)

    def _save(self):
        if self.tabs.currentWidget() is self.apikey_tab:
            title = self.a_title.text().strip()
            if not title:
                QMessageBox.warning(self, "缺少标题", "标题为必填项。"); return
            self.result_record = {
                "type": "apikey", "title": title, "url": None, "username": None,
                "password": None, "apikey": self.a_key.text(),
                "note": self.a_note.toPlainText(),
            }
        else:
            title = self.l_title.text().strip()
            if not title:
                QMessageBox.warning(self, "缺少标题", "标题为必填项。"); return
            self.result_record = {
                "type": "login", "title": title,
                "url": self.l_url.text().strip() or None,
                "username": self.l_user.text().strip() or None,
                "password": self.l_pass.text(),
                "apikey": None, "note": self.l_note.toPlainText(),
            }
        self.accept()


# ============ 首页 / 解锁 / 建档 ============

class WelcomeDialog(QDialog):
    """首页三按钮：打开已有本地库 / 新建本地库 / 登录服务器拉取。

    无本地库时『打开』禁用。
    """

    def __init__(self, has_local: bool, parent=None):
        super().__init__(parent)
        self.setWindowTitle("欢迎使用")
        self.setMinimumSize(360, 300)
        self.choice: str | None = None
        lay = QVBoxLayout(self)
        tip = QLabel("请选择：" if has_local else "首次使用：")
        tip.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lay.addWidget(tip)
        lay.addStretch(1)

        self.open_btn = QPushButton("打开已有本地库")
        self.open_btn.setMinimumHeight(48)
        self.open_btn.setEnabled(has_local)
        self.open_btn.clicked.connect(lambda: self._pick("open"))
        lay.addWidget(self.open_btn)

        new_btn = QPushButton("新建本地库")
        new_btn.setMinimumHeight(48)
        new_btn.clicked.connect(lambda: self._pick("new"))
        lay.addWidget(new_btn)

        login_btn = QPushButton("登录服务器拉取")
        login_btn.setMinimumHeight(48)
        login_btn.clicked.connect(lambda: self._pick("login"))
        lay.addWidget(login_btn)

        lay.addStretch(1)
        quit_btn = QPushButton("退出")
        quit_btn.clicked.connect(self.reject)
        lay.addWidget(quit_btn)

    def _pick(self, c: str):
        self.choice = c
        self.accept()


class VaultPickerDialog(QDialog):
    """选择一个本地库（仅按编号/label，不涉及账号）。"""

    def __init__(self, vaults: list[dict], last_vid: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle("选择本地库")
        self.setMinimumWidth(360)
        self.selected: str | None = None
        lay = QVBoxLayout(self)
        lay.addWidget(QLabel("选择要打开的本地库："))
        self.list = QListWidget()
        for m in vaults:
            vid = m.get("vid", "")
            item = QListWidgetItem(vault_display(vid, m))
            item.setData(Qt.ItemDataRole.UserRole, vid)
            self.list.addItem(item)
        row = 0
        for i, m in enumerate(vaults):
            if m.get("vid") == last_vid:
                row = i; break
        if vaults:
            self.list.setCurrentRow(row)
        lay.addWidget(self.list)
        bb = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok
                              | QDialogButtonBox.StandardButton.Cancel)
        bb.button(QDialogButtonBox.StandardButton.Ok).setText("下一步")
        bb.accepted.connect(self._ok); bb.rejected.connect(self.reject)
        lay.addWidget(bb)

    def _ok(self):
        cur = self.list.currentItem()
        if cur is None:
            QMessageBox.information(self, "请选择", "请先选择一个本地库。"); return
        self.selected = cur.data(Qt.ItemDataRole.UserRole)
        self.accept()


def server_vault_display(entry: dict) -> str:
    """云端一份库的展示名：上传时间 + label + 云端编号。"""
    ut = _ts_str(int(entry.get("upload_time") or 0))
    label = entry.get("label") or "(无标签)"
    return f"{ut} · {label} · 云端 #{entry.get('vid')}"


class ServerVaultPickerDialog(QDialog):
    """从『当前账号』名下的历史库（≤5 份，新→旧）中挑一份下载。

    只展示上传时间 / label / 云端编号，**不显示属主**（属主即当前登录账号）。
    """

    def __init__(self, vaults: list[dict], parent=None):
        super().__init__(parent)
        self.vaults = vaults
        self.selected_vid: int | None = None
        self.setWindowTitle("选择云端密码库")
        self.setMinimumWidth(420)
        lay = QVBoxLayout(self)
        lay.addWidget(QLabel(
            f"该账号在云端有 {len(vaults)} 份历史库（服务器只保留最近 5 份），选择要拉取的一份："))
        self.list = QListWidget()
        for m in vaults:
            item = QListWidgetItem(server_vault_display(m))
            item.setData(Qt.ItemDataRole.UserRole, m.get("vid"))
            self.list.addItem(item)
        if vaults:
            self.list.setCurrentRow(0)  # 默认最新一份
        lay.addWidget(self.list)
        bb = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok
                              | QDialogButtonBox.StandardButton.Cancel)
        bb.button(QDialogButtonBox.StandardButton.Ok).setText("下载这一份")
        bb.accepted.connect(self._ok); bb.rejected.connect(self.reject)
        lay.addWidget(bb)

    def _ok(self):
        cur = self.list.currentItem()
        if cur is None:
            QMessageBox.information(self, "请选择", "请先选择一份云端库。"); return
        self.selected_vid = cur.data(Qt.ItemDataRole.UserRole)
        self.accept()


class UnlockDialog(QDialog):
    """解锁本地库：只输入密码库密码。"""

    def __init__(self, vid: str, meta: dict, parent=None):
        super().__init__(parent)
        self.vid = vid
        self.setWindowTitle(f"解锁 · {vault_display(vid, meta)}")
        self.password: str | None = None
        f = QFormLayout(self)
        self.pw = QLineEdit(); self.pw.setEchoMode(QLineEdit.EchoMode.Password)
        self.pw.returnPressed.connect(self._ok)
        f.addRow("密码库密码", self.pw)
        bb = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok
                              | QDialogButtonBox.StandardButton.Cancel)
        bb.button(QDialogButtonBox.StandardButton.Ok).setText("解锁")
        bb.accepted.connect(self._ok); bb.rejected.connect(self.reject)
        f.addRow(bb)
        self.pw.setFocus()

    def _ok(self):
        if not self.pw.text():
            return
        self.password = self.pw.text()
        self.accept()


class NewVaultDialog(QDialog):
    """新建本地库：只输入密码库密码两遍。"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("新建本地库")
        self.setMinimumWidth(440)
        self.result: str | None = None
        f = QFormLayout(self)
        self.pw = QLineEdit(); self.pw.setEchoMode(QLineEdit.EchoMode.Password)
        self.pw2 = QLineEdit(); self.pw2.setEchoMode(QLineEdit.EchoMode.Password)
        f.addRow("密码库密码*", self.pw)
        f.addRow("确认密码库密码*", self.pw2)
        hint = QLabel(
            "· 密码库密码 = 本地加密主密码，**永不上传**、无法找回，请务必牢记。\n"
            "· 用户名 / 用户密码 稍后点『同步』时再填即可（账号与本地库互不绑定）。")
        hint.setWordWrap(True); f.addRow(hint)
        bb = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok
                              | QDialogButtonBox.StandardButton.Cancel)
        bb.button(QDialogButtonBox.StandardButton.Ok).setText("创建")
        bb.accepted.connect(self._ok); bb.rejected.connect(self.reject)
        f.addRow(bb)
        self.pw.setFocus()

    def _ok(self):
        if len(self.pw.text()) < 8:
            QMessageBox.warning(self, "太弱", "密码库密码至少 8 位。"); return
        if self.pw.text() != self.pw2.text():
            QMessageBox.warning(self, "不一致", "两次输入的密码库密码不一致。"); return
        self.result = self.pw.text()
        self.accept()


class LoginStep1Dialog(QDialog):
    """登录服务器 · 第 1 步：用户名 + 用户密码（服务密码）。"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("登录服务器 · 第 1 步")
        self.setMinimumWidth(420)
        self.result: dict | None = None
        f = QFormLayout(self)
        self.username = QLineEdit()
        self.service_pwd = QLineEdit(); self.service_pwd.setEchoMode(QLineEdit.EchoMode.Password)
        f.addRow("用户名", self.username)
        f.addRow("用户密码", self.service_pwd)
        hint = QLabel("第 1 步：用用户名 + 用户密码从服务器拉取云端密码库。")
        hint.setWordWrap(True); f.addRow(hint)
        bb = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok
                              | QDialogButtonBox.StandardButton.Cancel)
        bb.button(QDialogButtonBox.StandardButton.Ok).setText("下一步")
        bb.accepted.connect(self._ok); bb.rejected.connect(self.reject)
        f.addRow(bb)
        self.username.setFocus()

    def _ok(self):
        u = self.username.text().strip()
        p = self.service_pwd.text()
        if not u or not p:
            QMessageBox.warning(self, "缺少信息", "用户名和用户密码必填。"); return
        self.result = {"username": u, "service_pwd": p}
        self.accept()


class LoginStep2Dialog(QDialog):
    """登录服务器 · 第 2 步：输入密码库密码解密云端库。"""

    def __init__(self, username: str, info: dict, parent=None):
        super().__init__(parent)
        self.setWindowTitle("登录服务器 · 第 2 步")
        self.setMinimumWidth(460)
        self.username = username
        self.info = info
        self.result: str | None = None
        lay = QVBoxLayout(self)
        meta = QLabel(
            f"已找到云端密码库：{username}\n"
            f"label: {info.get('label') or '—'}\n"
            f"上传时间: {_ts_str(int(info.get('upload_time') or 0))}")
        lay.addWidget(meta)
        f = QFormLayout()
        self.vault_pwd = QLineEdit(); self.vault_pwd.setEchoMode(QLineEdit.EchoMode.Password)
        self.vault_pwd.returnPressed.connect(self._ok)
        f.addRow("密码库密码", self.vault_pwd)
        lay.addLayout(f)
        hint = QLabel("输入该密码库的密码库密码（本地解密用，不会上传）。")
        hint.setWordWrap(True); lay.addWidget(hint)
        bb = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok
                              | QDialogButtonBox.StandardButton.Cancel)
        bb.button(QDialogButtonBox.StandardButton.Ok).setText("登录")
        bb.accepted.connect(self._ok); bb.rejected.connect(self.reject)
        lay.addWidget(bb)
        self.vault_pwd.setFocus()

    def _ok(self):
        if not self.vault_pwd.text():
            return
        self.result = self.vault_pwd.text()
        self.accept()


# ============ 同步 ============

class ForgotPwdDialog(QDialog):
    """忘记密码：输入用户名 → 从服务器取管理员联系方式 → 显示自助重置说明。

    用户用**注册时的邮箱/手机号**发出「01用户名」邮件 / 「01用户名d」短信，
    服务器验证发件人哈希后自动把用户密码重置为 86868686。
    """

    def __init__(self, cfg: dict, parent=None):
        super().__init__(parent)
        self.cfg = cfg
        self.setWindowTitle("忘记密码")
        self.setMinimumWidth(500)
        lay = QVBoxLayout(self)
        f = QFormLayout()
        self.user = QLineEdit()
        f.addRow("用户名", self.user)
        lay.addLayout(f)
        btns = QHBoxLayout()
        fetch = QPushButton("获取发送说明")
        fetch.clicked.connect(self._fetch)
        close = QPushButton("关闭")
        close.clicked.connect(self.reject)
        btns.addWidget(fetch); btns.addStretch(1); btns.addWidget(close)
        lay.addLayout(btns)
        self.info = QLabel("输入你的用户名，点『获取发送说明』。")
        self.info.setWordWrap(True)
        lay.addWidget(self.info)

    def _fetch(self):
        u = self.user.text().strip()
        if not u:
            self.info.setText("请先输入用户名。")
            return
        self.info.setText("正在获取服务器联系方式…")
        try:
            # /contact 无需认证，凭据占位即可
            ct = wait_for(self, lambda: make_client(self.cfg, u, "x").contact(),
                          "正在获取…")
        except sync.SyncError as e:
            self.info.setText(f"获取失败：{e}")
            return
        admin_email = (ct or {}).get("admin_email", "")
        sms_hint = (ct or {}).get("sms_hint", "")
        email_line = f"到 **{admin_email}**" if admin_email else "——服务器未配置找回邮箱——"
        sms_line = f"到：**{sms_hint}**" if sms_hint else "——服务器未配置短信入口——"
        self.info.setText(
            f"用户名：{u}\n\n"
            f"1. 用**注册时的邮箱**发送内容「01{u}」{email_line}\n"
            f"2. 或用**注册时的手机号**发送短信「01{u}d」{sms_line}\n\n"
            "管理员核实后将自动把你的用户密码重置为 **86868686**（约 1 分钟内生效）。\n"
            "用 86868686 登录后，请立即在菜单『账户/同步 → 修改用户密码』修改。")


class SyncDialog(QDialog):
    """同步弹窗：对『当前本地库』执行推送/拉取/注册。

    - 账号（用户名+用户密码）只在此处出现，用于认证服务器；与本地库不绑定。
    - 登录：GET /vault 验证用户密码 → 展示「推送」「拉取」。
    - 注册：展开 账号/密码/确认/手机/邮箱，提交=首次推送建档（服务器只存密文）。
    这里的「账号密码」= 用户密码（服务密码），密码库密码不出现在本框内。
    """

    def __init__(self, cfg: dict, prefill_account: str, parent=None):
        super().__init__(parent)
        self.cfg = cfg
        self.result: dict | None = None
        self.setWindowTitle("同步")
        self.setMinimumWidth(540)

        outer = QVBoxLayout(self)
        self.stack = QStackedWidget()
        outer.addWidget(self.stack)
        self.stack.addWidget(self._build_auth_page(prefill_account))
        self.stack.addWidget(self._build_register_page())
        self.stack.addWidget(self._build_action_page())
        self.stack.setCurrentIndex(0)

    def _build_auth_page(self, prefill_account: str) -> QWidget:
        page = QWidget()
        lay = QVBoxLayout(page)
        f = QFormLayout()
        self.username = QLineEdit(prefill_account)
        self.service_pwd = QLineEdit(); self.service_pwd.setEchoMode(QLineEdit.EchoMode.Password)
        self.remember = QCheckBox("记住用户密码到系统凭据库")
        self.remember.setChecked(bool(self.cfg.get("remember_service_pwd", True)))
        f.addRow("账号", self.username)
        f.addRow("账号密码", self.service_pwd)
        f.addRow(self.remember)
        lay.addLayout(f)

        remembered = (keyring_store.load_service_pwd(prefill_account)
                      if (prefill_account and self.cfg.get("remember_service_pwd")) else None)
        if remembered:
            self.service_pwd.setText(remembered)

        btns = QHBoxLayout()
        self.login_btn = QPushButton("登录")
        self.register_btn = QPushButton("注册")
        self.forgot_btn = QPushButton("忘记密码")
        self.login_btn.clicked.connect(self._on_login)
        self.register_btn.clicked.connect(self._on_to_register)
        self.forgot_btn.clicked.connect(self._on_forgot)
        btns.addWidget(self.login_btn); btns.addWidget(self.register_btn)
        btns.addWidget(self.forgot_btn); btns.addStretch(1)
        lay.addLayout(btns)

        self.auth_status = QLabel("")
        self.auth_status.setWordWrap(True)
        lay.addWidget(self.auth_status)

        row = QHBoxLayout()
        self.test_btn = QPushButton("测试连接 / 健康检查")
        self.test_btn.clicked.connect(self._test)
        cancel = QPushButton("取消")
        cancel.clicked.connect(self.reject)
        row.addWidget(self.test_btn); row.addStretch(1); row.addWidget(cancel)
        lay.addLayout(row)
        return page

    def _build_register_page(self) -> QWidget:
        page = QWidget()
        lay = QVBoxLayout(page)
        f = QFormLayout()
        self.reg_user = QLineEdit(self.username.text())
        self.reg_pwd = QLineEdit(); self.reg_pwd.setEchoMode(QLineEdit.EchoMode.Password)
        self.reg_pwd2 = QLineEdit(); self.reg_pwd2.setEchoMode(QLineEdit.EchoMode.Password)
        self.reg_phone = QLineEdit()
        self.reg_email = QLineEdit()
        f.addRow("账号", self.reg_user)
        f.addRow("账号密码", self.reg_pwd)
        f.addRow("确认账号密码", self.reg_pwd2)
        f.addRow("手机号", self.reg_phone)
        f.addRow("邮箱", self.reg_email)
        lay.addLayout(f)
        tip = QLabel("· 账号密码 = 用户密码（服务密码），至少 8 位，仅存服务器端 Argon2 校验值。\n"
                     "· 手机号与邮箱至少填写一项，用于将来找回密码，只存服务器端。\n"
                     "· 注册 = 只在服务器建一个账号（云端此时零份库），**不会上传你当前的密码库**。\n"
                     "· 注册后想上传本地库：回到本页点『登录』→ 选『推送』即可（每推送一次云端多一份历史）。\n"
                     "· 账号与本地库不绑定：换一个账号『登录』即可拉取/推送到同一个本地库。")
        tip.setWordWrap(True); lay.addWidget(tip)

        btns = QHBoxLayout()
        self.do_register_btn = QPushButton("注册账号")
        back = QPushButton("返回")
        self.do_register_btn.clicked.connect(self._on_register)
        back.clicked.connect(lambda: self.stack.setCurrentIndex(0))
        btns.addWidget(self.do_register_btn); btns.addWidget(back); btns.addStretch(1)
        lay.addLayout(btns)
        return page

    def _build_action_page(self) -> QWidget:
        page = QWidget()
        lay = QVBoxLayout(page)
        self.action_info = QLabel("")
        self.action_info.setWordWrap(True)
        lay.addWidget(self.action_info)
        lay.addStretch(1)
        btns = QHBoxLayout()
        self.push_btn = QPushButton("推送到服务器（云端新增一份历史）")
        self.pull_btn = QPushButton("从服务器拉取（挑一份覆盖本地）")
        self.push_btn.clicked.connect(lambda: self._finish("push"))
        self.pull_btn.clicked.connect(lambda: self._finish("pull"))
        btns.addWidget(self.push_btn); btns.addWidget(self.pull_btn)
        lay.addLayout(btns)
        back = QPushButton("返回")
        back.clicked.connect(lambda: self.stack.setCurrentIndex(0))
        lay.addWidget(back)
        return page

    # ---- 行为 ----
    def _client(self):
        u = self.username.text().strip() or "_"
        p = self.service_pwd.text() or "_"
        return sync.SyncClient(self.cfg["server_url"], u, p,
                               self.cfg.get("cert_fingerprint") or None)

    def _on_forgot(self):
        ForgotPwdDialog(self.cfg, self).exec()

    def _on_login(self):
        u = self.username.text().strip()
        p = self.service_pwd.text()
        if not u or not p:
            self.auth_status.setText("请输入账号和账号密码。"); return
        self.auth_status.setText("登录中…")
        self.login_btn.setEnabled(False)
        self.register_btn.setEnabled(False)
        try:
            vaults = wait_for(self, self._client().list_vaults, "正在登录服务器…")
        except sync.AuthError:
            self.auth_status.setText("账号或账号密码错误。"); return
        except sync.PinError as e:
            self.auth_status.setText(f"证书指纹不匹配：{e}"); return
        except sync.SyncError as e:
            self.auth_status.setText(f"连接失败：{e}"); return
        finally:
            self.login_btn.setEnabled(True)
            self.register_btn.setEnabled(True)
        if p == "86868686":
            QMessageBox.warning(
                self, "初始密码",
                "当前使用的是找回重置后的初始密码，请立即在菜单\n"
                "『账户/同步 → 修改用户密码』中设置新密码。")
        if vaults:
            latest = vaults[0]
            self.action_info.setText(
                f"已登录：{u}\n云端有 {len(vaults)} 份历史库（保留最近 5 份）。\n"
                f"最新一份：上传={_ts_str(int(latest.get('upload_time') or 0))}  "
                f"label={latest.get('label') or '(空)'}")
        else:
            self.action_info.setText(
                f"已登录：{u}\n该账号云端还没有密码库。\n"
                f"· 想上传当前本地库 → 点『推送』。\n"
                f"· 想换一份云端库 → 先用『推送』建第一份。")
        self.stack.setCurrentIndex(2)

    def _on_to_register(self):
        u = self.username.text().strip()
        if u and (not _USERNAME_RE.match(u) or u.isdigit()):
            self.auth_status.setText(
                "账号不合法：需 3-20 位字母数字 . _ -，首尾字母数字，且不能全是数字。")
            return
        self.reg_user.setText(u)
        self.stack.setCurrentIndex(1)

    def _on_register(self):
        u = self.reg_user.text().strip()
        p = self.reg_pwd.text()
        p2 = self.reg_pwd2.text()
        phone = self.reg_phone.text().strip()
        email = self.reg_email.text().strip()
        if not _USERNAME_RE.match(u) or u.isdigit():
            QMessageBox.warning(self, "账号不合法",
                                "需 3-20 位字母数字 . _ -，首尾字母数字，且不能全是数字。"); return
        if len(p) < 8:
            QMessageBox.warning(self, "太弱", "账号密码至少 8 位。"); return
        if p != p2:
            QMessageBox.warning(self, "不一致", "两次输入的账号密码不一致。"); return
        if not phone and not email:
            QMessageBox.warning(self, "缺少联系方式", "手机号与邮箱至少填写一项。"); return
        if email and not _EMAIL_RE.match(email):
            QMessageBox.warning(self, "邮箱无效", "请填写合法邮箱。"); return
        if phone and not _PHONE_RE.match(phone):
            QMessageBox.warning(self, "手机号无效",
                                "请填写合法手机号（6-20 位数字/+/-/空格）。"); return
        self.username.setText(u)
        self.service_pwd.setText(p)
        self._finish("register", email=email, phone=phone)

    def _finish(self, mode: str, email: str = "", phone: str = ""):
        self.result = {
            "username": self.username.text().strip(),
            "service_pwd": self.service_pwd.text(),
            "mode": mode,
            "remember": self.remember.isChecked(),
            "email": email,
            "phone": phone,
        }
        self.accept()

    def _test(self):
        try:
            info = wait_for(self, self._client().health, "正在连接服务器…")
            QMessageBox.information(self, "健康",
                                     f"连接成功。服务器状态: {info.get('status', '?')}")
        except sync.PinError as e:
            QMessageBox.critical(self, "证书指纹不匹配",
                                 f"{e}\n\n请在『服务器设置』中核对/重新获取指纹。")
        except sync.SyncError as e:
            QMessageBox.critical(self, "连接失败", str(e))


# ============ 改密 ============

class ChangeVaultPwdDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("修改密码库密码")
        self.setMinimumWidth(440)
        self.result: tuple[str, str] | None = None
        f = QFormLayout(self)
        self.old = QLineEdit(); self.old.setEchoMode(QLineEdit.EchoMode.Password)
        self.new = QLineEdit(); self.new.setEchoMode(QLineEdit.EchoMode.Password)
        self.new2 = QLineEdit(); self.new2.setEchoMode(QLineEdit.EchoMode.Password)
        f.addRow("旧密码库密码", self.old)
        f.addRow("新密码库密码", self.new)
        f.addRow("确认新密码", self.new2)
        tip = QLabel("· 规范要求：改密前先导出一份明文 CSV 备份（失败则中止改密）。\n"
                     "· 修改后本地立即重新加密、并标记『未同步』。\n"
                     "· 记得随后点同步推送，否则其它设备拉到的是旧库。")
        tip.setWordWrap(True); f.addRow(tip)
        bb = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok
                              | QDialogButtonBox.StandardButton.Cancel)
        bb.accepted.connect(self._ok); bb.rejected.connect(self.reject)
        f.addRow(bb)

    def _ok(self):
        if len(self.new.text()) < 8:
            QMessageBox.warning(self, "太弱", "新密码库密码至少 8 位。"); return
        if self.new.text() != self.new2.text():
            QMessageBox.warning(self, "不一致", "两次输入的新密码不一致。"); return
        self.result = (self.old.text(), self.new.text())
        self.accept()


class ChangeServicePwdDialog(QDialog):
    def __init__(self, cfg: dict, username: str, parent=None):
        super().__init__(parent)
        self.cfg = cfg
        self.result: dict | None = None
        self.setWindowTitle("修改用户密码（服务密码）")
        self.setMinimumWidth(460)
        f = QFormLayout(self)
        self.username = QLineEdit(username)
        self.old = QLineEdit(); self.old.setEchoMode(QLineEdit.EchoMode.Password)
        self.new = QLineEdit(); self.new.setEchoMode(QLineEdit.EchoMode.Password)
        self.new2 = QLineEdit(); self.new2.setEchoMode(QLineEdit.EchoMode.Password)
        f.addRow("用户名", self.username)
        f.addRow("旧用户密码", self.old)
        f.addRow("新用户密码", self.new)
        f.addRow("确认新用户密码", self.new2)
        tip = QLabel("用户密码只在同步时用于 Basic 认证，不影响密码库文件本身。")
        tip.setWordWrap(True); f.addRow(tip)
        bb = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok
                              | QDialogButtonBox.StandardButton.Cancel)
        bb.accepted.connect(self._ok); bb.rejected.connect(self.reject)
        f.addRow(bb)
        remembered = keyring_store.load_service_pwd(username)
        if remembered:
            self.old.setText(remembered)

    def _ok(self):
        if len(self.new.text()) < 8:
            QMessageBox.warning(self, "太弱", "新用户密码至少 8 位。"); return
        if self.new.text() != self.new2.text():
            QMessageBox.warning(self, "不一致", "两次输入的新密码不一致。"); return
        self.result = {
            "username": self.username.text().strip(),
            "old": self.old.text(), "new": self.new.text(),
        }
        self.accept()


class ConfirmAccountDialog(QDialog):
    """注销云端账户前的身份确认：只需用户名 + 用户密码（无新密码校验）。"""

    def __init__(self, cfg: dict, username: str, parent=None):
        super().__init__(parent)
        self.cfg = cfg
        self.result: dict | None = None
        self.setWindowTitle("确认注销：请输入用户名与用户密码")
        self.setMinimumWidth(440)
        f = QFormLayout(self)
        self.username = QLineEdit(username)
        self.pwd = QLineEdit(); self.pwd.setEchoMode(QLineEdit.EchoMode.Password)
        self.pwd.returnPressed.connect(self._ok)
        f.addRow("用户名", self.username)
        f.addRow("用户密码", self.pwd)
        tip = QLabel("注销会永久删除该云端账号及其云端密码库（本地库保留、可重新注册）。\n"
                     "请输入该账号当前的用户密码以确认。")
        tip.setWordWrap(True); f.addRow(tip)
        bb = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok
                              | QDialogButtonBox.StandardButton.Cancel)
        bb.accepted.connect(self._ok); bb.rejected.connect(self.reject)
        f.addRow(bb)
        remembered = keyring_store.load_service_pwd(username)
        if remembered:
            self.pwd.setText(remembered)

    def _ok(self):
        u = self.username.text().strip()
        p = self.pwd.text()
        if not u or not p:
            QMessageBox.warning(self, "缺少信息", "请输入用户名和用户密码。"); return
        self.result = {"username": u, "old": p}
        self.accept()


# ============ 服务器设置 ============

class ServerSettingsDialog(QDialog):
    def __init__(self, cfg: dict, parent=None):
        super().__init__(parent)
        self.cfg = cfg
        self.setWindowTitle("服务器设置")
        self.setMinimumWidth(540)
        f = QFormLayout(self)
        self.url = QLineEdit(cfg.get("server_url", ""))
        self.fp = QLineEdit(cfg.get("cert_fingerprint", ""))
        self.clip_clear = QLineEdit(str(cfg.get("clipboard_clear_seconds", 30)))
        f.addRow("服务器地址 (https://host:port)", self.url)
        f.addRow("证书 SHA-256 指纹", self.fp)
        f.addRow("剪贴板清空 (秒, 0=禁用)", self.clip_clear)
        row = QHBoxLayout()
        fetch = QPushButton("从服务器获取指纹")
        fetch.clicked.connect(self._fetch_fp)
        row.addWidget(fetch); row.addStretch(1)
        f.addRow(row)
        tip = QLabel("· 自签证书：必须先取指纹、再 pinning，防止中间人。\n"
                     "· 获取过程临时用 insecure TLS，仅读取证书、不发送任何用户数据。")
        tip.setWordWrap(True); f.addRow(tip)
        bb = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok
                              | QDialogButtonBox.StandardButton.Cancel)
        bb.accepted.connect(self._ok); bb.rejected.connect(self.reject)
        f.addRow(bb)

    def _fetch_fp(self):
        import hashlib
        import http.client
        import ssl
        from urllib.parse import urlsplit
        u = self.url.text().strip()
        parts = urlsplit(u)
        if parts.scheme != "https" or not parts.hostname:
            QMessageBox.warning(self, "非 HTTPS", "仅支持 https://。"); return

        def fetch() -> str:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(parts.hostname, parts.port or 443,
                                                timeout=15, context=ctx)
            try:
                conn.connect()
                der = conn.sock.getpeercert(binary_form=True)
            finally:
                conn.close()
            if not der:
                raise RuntimeError("未获取到证书")
            return hashlib.sha256(der).hexdigest()

        try:
            fp = wait_for(self, fetch, "正在获取服务器证书…")
        except Exception as e:
            QMessageBox.critical(self, "获取失败", str(e)); return
        if QMessageBox.question(
                self, "确认指纹",
                f"服务器证书指纹:\n{fp}\n\n请对照运维手册确认无误后填入。填入？",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        ) == QMessageBox.StandardButton.Yes:
            self.fp.setText(fp)

    def _ok(self):
        from urllib.parse import urlsplit
        u = self.url.text().strip()
        parts = urlsplit(u)
        if parts.scheme != "https" or not parts.hostname:
            QMessageBox.warning(self, "地址无效",
                                "出于安全考虑只允许 https://host:port 形式的服务器地址。")
            return
        self.cfg["server_url"] = u
        self.cfg["cert_fingerprint"] = self.fp.text().strip().lower()
        try:
            self.cfg["clipboard_clear_seconds"] = max(0, int(self.clip_clear.text()))
        except ValueError:
            QMessageBox.warning(self, "数字无效", "秒数需为整数。"); return
        self.accept()


# ============ 主窗口 ============

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(APP_TITLE)
        self.resize(820, 540)
        self.vault: vault_mod.Vault = vault_mod.Vault()
        self.vid: str = ""
        self.vault_pwd: str | None = None
        self._key: bytes | None = None      # 会话内缓存的派生主密钥
        self._salt: bytes | None = None     # 与 _key 配对的 salt
        self.account: str = ""
        self.cfg = storage.load_config()
        self.current_id: str | None = None

        self._build_ui()
        self._build_menu()

        self.clip_timer = QTimer(self); self.clip_timer.setSingleShot(True)
        self.clip_timer.timeout.connect(self._clear_clipboard)
        self._clip_value: str = ""

    # ---- UI ----
    def _build_ui(self):
        central = QWidget(); self.setCentralWidget(central)
        lay = QVBoxLayout(central)

        top = QHBoxLayout()
        self.who = QLabel("未解锁"); self.who.setStyleSheet("font-weight:bold;")
        top.addWidget(self.who); top.addSpacing(20)
        self.search = QLineEdit(); self.search.setPlaceholderText("搜索标题/网址/用户名/备注…")
        self.search.textChanged.connect(self._refresh_list)
        top.addWidget(self.search, 1)
        for text, slot in (("新增", self._add), ("同步", self._sync),
                           ("导入CSV", self._import_csv), ("导出CSV", self._export_csv)):
            b = QPushButton(text); b.clicked.connect(slot); top.addWidget(b)
        lay.addLayout(top)

        body = QHBoxLayout()
        self.list = QListWidget(); self.list.setMinimumWidth(240)
        self.list.currentItemChanged.connect(self._on_select)
        body.addWidget(self.list, 1)
        self.detail = QTextEdit(); self.detail.setReadOnly(True)
        self.detail.setMinimumWidth(320)
        body.addWidget(self.detail, 2)
        lay.addLayout(body, 1)

        bottom = QHBoxLayout()
        self.edit_btn = QPushButton("编辑"); self.edit_btn.clicked.connect(self._edit)
        self.del_btn = QPushButton("删除"); self.del_btn.clicked.connect(self._delete)
        self.copy_user = QPushButton("复制用户名")
        self.copy_user.clicked.connect(lambda: self._copy_field("username"))
        self.copy_pass = QPushButton("复制密码")
        self.copy_pass.clicked.connect(lambda: self._copy_field("password"))
        self.copy_key = QPushButton("复制API Key")
        self.copy_key.clicked.connect(lambda: self._copy_field("apikey"))
        for b in (self.edit_btn, self.del_btn, self.copy_user, self.copy_pass, self.copy_key):
            bottom.addWidget(b)
        bottom.addStretch(1)
        self.status = QLabel("就绪")
        bottom.addWidget(self.status)
        lay.addLayout(bottom)
        self._set_buttons_enabled(False)

    def _build_menu(self):
        m_lib = self.menuBar().addMenu("本地库")
        for text, slot in (
                ("打开其他本地库…", self._switch_vault),
                ("新建本地库…", self._new_vault_menu),
                ("删除本地库…", self._delete_vault_menu),
        ):
            act = QAction(text, self); act.triggered.connect(slot); m_lib.addAction(act)
        m_acc = self.menuBar().addMenu("账户/同步")
        for text, slot in (
                ("修改密码库密码…", self._change_vault_pwd),
                ("修改用户密码…", self._change_service_pwd),
                ("注销云端账户…", self._delete_account),
        ):
            act = QAction(text, self); act.triggered.connect(slot); m_acc.addAction(act)
        m_set = self.menuBar().addMenu("设置")
        act = QAction("服务器设置…", self); act.triggered.connect(self._settings)
        m_set.addAction(act)

    def _set_status(self, t: str): self.status.setText(t)

    def _set_buttons_enabled(self, on: bool):
        for b in (self.edit_btn, self.del_btn, self.copy_user, self.copy_pass, self.copy_key):
            b.setEnabled(on)

    # ---- 启动流程 ----
    def bootstrap(self) -> bool:
        storage.migrate_legacy_users()
        vaults = storage.list_vaults()
        has_local = len(vaults) > 0
        w = WelcomeDialog(has_local, self)
        if not w.exec() or not w.choice:
            return False
        if w.choice == "login":
            return self._login_flow()
        if w.choice == "new":
            return self._new_flow()
        if w.choice == "open":
            return self._open_local_flow(vaults)
        return False

    def _open_local_flow(self, vaults: list[dict]) -> bool:
        d = VaultPickerDialog(vaults, self.cfg.get("last_vid", ""), self)
        if not d.exec() or not d.selected:
            return False
        vid = d.selected
        meta = storage.load_meta(vid)
        return self._unlock(vid, meta)

    def _new_flow(self) -> bool:
        d = NewVaultDialog(self)
        if not d.exec() or not d.result:
            return False
        vid, v = storage.create_vault(d.result)
        storage.log_sync(vid, "新建本地密码库")
        return self._unlock(vid, storage.load_meta(vid), preset_pwd=d.result)

    def _login_flow(self) -> bool:
        """登录服务器：step1 账号 → 列出名下历史库挑一份 → step2 密码库密码 → 落地为本地新库。"""
        while True:
            s1 = LoginStep1Dialog(self)
            if not s1.exec() or not s1.result:
                return False
            u = s1.result["username"]; sp = s1.result["service_pwd"]
            client = make_client(self.cfg, u, sp)
            try:
                vaults = wait_for(self, client.list_vaults, "正在登录服务器…")
            except sync.PinError as e:
                QMessageBox.critical(self, "证书指纹不匹配", str(e)); return False
            except sync.AuthError:
                QMessageBox.critical(self, "登录失败", "用户名或用户密码错误。")
                continue
            except sync.SyncError as e:
                QMessageBox.critical(self, "连接失败", str(e)); return False
            if not vaults:
                QMessageBox.critical(self, "云端无库",
                                     "该用户名在服务器上没有密码库。")
                continue
            pick = ServerVaultPickerDialog(vaults, self)
            if not pick.exec() or pick.selected_vid is None:
                return False
            try:
                info = wait_for(self, lambda: client.get_vault(pick.selected_vid),
                                "正在下载云端密码库…")
            except sync.NotFoundError:
                QMessageBox.critical(self, "云端无库", "该份库已不存在，请重试。")
                continue
            except sync.SyncError as e:
                QMessageBox.critical(self, "连接失败", str(e)); return False
            ct = base64.b64decode(info["ciphertext"]) if info.get("ciphertext") else b""
            if not ct:
                QMessageBox.critical(self, "云端为空", "该份库内容为空。")
                continue
            s2 = LoginStep2Dialog(u, info, self)
            if not s2.exec() or not s2.result:
                return False
            vp = s2.result
            try:
                plain = crypto.decrypt_vault(ct, vp)
            except UnlockError:
                if QMessageBox.question(
                        self, "密码库密码错误",
                        "密码库密码不对，要重试吗？",
                        QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                ) != QMessageBox.StandardButton.Yes:
                    return False
                continue
            v = vault_mod.Vault.from_json(plain)
            # 落地为一个全新的本地库：去除属主(username)与上传时间，不与任何账号绑定
            vid = storage.next_vid()
            storage.write_vault_bytes(vid, ct)
            storage.save_meta(vid, {
                "vid": vid,
                "pwd_time": v.pwd_time,
                "modified_at": sync.now_ms(),
                "label": v.label,
                "never_uploaded": False,
                "last_account": u,
                "record_count": len(v.active_records()),
                "created_at": sync.now_ms(),
            })
            if self.cfg.get("remember_service_pwd"):
                keyring_store.save_service_pwd(u, sp)
            else:
                keyring_store.delete_service_pwd(u)
            storage.log_sync(vid, f"登录拉取 ok @{u} 云端#{pick.selected_vid}")
            return self._unlock(vid, storage.load_meta(vid), preset_pwd=vp)

    def _unlock(self, vid: str, meta: dict, preset_pwd: str | None = None) -> bool:
        if preset_pwd is None:
            d = UnlockDialog(vid, meta, self)
            if not d.exec() or d.password is None:
                return False
            pwd = d.password
        else:
            pwd = preset_pwd
        try:
            v, key, salt = storage.load_vault_ex(vid, pwd)
        except UnlockError:
            QMessageBox.critical(self, "解锁失败", "密码库密码错误或数据损坏。")
            return False
        # 换库/重新解锁前清掉上一次复制的内容（只清我们自己写入的）
        self.clip_timer.stop()
        self._clear_clipboard()
        self.vid = vid
        self.vault_pwd = pwd
        self.vault = v
        self._key = key
        self._salt = salt
        self.account = meta.get("last_account") or ""
        self.cfg["last_vid"] = vid
        storage.save_config(self.cfg)
        self._refresh_list()
        self._refresh_header(meta)
        pending = " · 未同步" if meta.get("never_uploaded", True) else ""
        self._set_status(
            f"已解锁 · {len(v.active_records())} 条 · label={v.label or '—'}{pending}")
        return True

    def _refresh_header(self, meta: dict | None = None):
        """标题栏 / 「当前」标签统一刷新（拉取、改密后也要更新）。"""
        if not self.vid:
            return
        if meta is None:
            meta = storage.load_meta(self.vid)
        disp = vault_display(self.vid, meta)
        self.setWindowTitle(f"{APP_TITLE} · {disp}")
        self.who.setText(f"当前：{disp}")

    def _switch_vault(self):
        """切换到另一个本地库（需重新解锁目标库）。取消/失败时保持当前库不动。"""
        if QMessageBox.question(
                self, "切换本地库",
                "切换到其他本地库需要先解锁目标库。继续？",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        ) != QMessageBox.StandardButton.Yes:
            return
        if not self._open_local_flow(storage.list_vaults()):
            self._set_status("已取消切换，仍停留在当前库")

    def _new_vault_menu(self):
        if QMessageBox.question(
                self, "新建本地库",
                "新建一个本地库并切换过去？当前库保持原样（不会丢失）。",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        ) != QMessageBox.StandardButton.Yes:
            return
        if not self._new_flow():
            self._set_status("已取消新建，仍停留在当前库")

    def _delete_vault_menu(self):
        vaults = storage.list_vaults()
        if not vaults:
            QMessageBox.information(self, "无本地库", "当前没有可删除的本地库。"); return
        d = VaultPickerDialog(vaults, self.cfg.get("last_vid", ""), self)
        d.setWindowTitle("选择要删除的本地库")
        if not d.exec() or not d.selected:
            return
        vid = d.selected
        meta = storage.load_meta(vid)
        warn = ""
        if meta.get("never_uploaded"):
            warn = "\n\n⚠ 该库有【未推送到服务器】的修改，删除后无法恢复！"
        if QMessageBox.warning(
                self, "删除本地库",
                f"将永久删除本地库 #{vid}（{meta.get('label') or '无标签'}），"
                f"含 {meta.get('record_count', 0)} 条记录。\n"
                f"此操作只删本机文件，不影响云端账号/云端库。{warn}\n\n确定删除？",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        ) != QMessageBox.StandardButton.Yes:
            return
        storage.delete_vault(vid)
        if vid == self.cfg.get("last_vid"):
            self.cfg.pop("last_vid", None)
            storage.save_config(self.cfg)
        if vid == self.vid:
            # 删的是当前解锁库 → 清会话并回首页
            self._clear_session()
            if not self.bootstrap():
                self.close()
        else:
            self._set_status(f"已删除本地库 #{vid}")

    def _clear_session(self):
        self.vid = ""
        self.vault_pwd = None
        self._key = None
        self._salt = None
        self.vault = vault_mod.Vault()
        self.account = ""
        self.current_id = None
        self.clip_timer.stop()
        self._clear_clipboard()
        self.search.clear()
        self.list.clear(); self.detail.clear()
        self._set_buttons_enabled(False)
        self.who.setText("未解锁")
        self.setWindowTitle(APP_TITLE)

    # ---- 列表 ----
    def _refresh_list(self):
        self.list.clear()
        kw = self.search.text()
        recs = self.vault.search(kw) if kw else self.vault.active_records()
        for r in recs:
            icon = "🔑" if r["type"] == "apikey" else "🌐"
            item = QListWidgetItem(f"{icon} {r['title']}")
            item.setData(Qt.ItemDataRole.UserRole, r["id"])
            self.list.addItem(item)
        if self.list.count():
            self.list.setCurrentRow(0)
        else:
            self.current_id = None; self.detail.clear(); self._set_buttons_enabled(False)

    def _on_select(self, cur, _prev):
        if cur is None:
            self.current_id = None; self.detail.clear(); self._set_buttons_enabled(False)
            return
        rid = cur.data(Qt.ItemDataRole.UserRole)
        self.current_id = rid
        rec = self.vault.get(rid)
        if not rec: return
        self._set_buttons_enabled(True)
        is_key = rec["type"] == "apikey"
        self.copy_user.setVisible(not is_key)
        self.copy_pass.setVisible(not is_key)
        self.copy_key.setVisible(is_key)
        lines = [f"类型：{'API Key' if is_key else '网站登录'}",
                 f"标题：{rec['title']}"]
        if not is_key:
            lines += [f"网址：{rec.get('url') or '—'}",
                      f"用户名：{rec.get('username') or '—'}",
                      "密码：••••••（点击下方复制）"]
        else:
            lines += ["API Key：••••••（点击下方复制）"]
        if rec.get("note"):
            lines += ["", f"备注：{rec['note']}"]
        self.detail.setPlainText("\n".join(lines))

    # ---- CRUD ----
    def _add(self):
        d = RecordDialog(self)
        if d.exec() and d.result_record:
            r = d.result_record
            self.vault.add(type=r["type"], title=r["title"], url=r["url"],
                           username=r["username"], password=r["password"],
                           apikey=r["apikey"], note=r["note"])
            self._save_local(); self._refresh_list()

    def _edit(self):
        if not self.current_id: return
        rec = self.vault.get(self.current_id)
        d = RecordDialog(self, dict(rec))
        if d.exec() and d.result_record:
            self.vault.update(self.current_id, **d.result_record)
            self._save_local(); self._refresh_list()

    def _delete(self):
        if not self.current_id: return
        rec = self.vault.get(self.current_id)
        if QMessageBox.question(self, "删除", f"确定删除「{rec['title']}」？") \
                != QMessageBox.StandardButton.Yes: return
        self.vault.delete(self.current_id)
        self._save_local(); self._refresh_list()

    def _save_local(self):
        storage.save_vault(self.vid, self.vault, never_uploaded=True,
                           key=self._key, salt=self._salt)
        self._set_status(f"已保存 · {len(self.vault.active_records())} 条 · 未同步")

    # ---- 复制 ----
    def _copy_field(self, field: str):
        if not self.current_id: return
        rec = self.vault.get(self.current_id)
        val = (rec or {}).get(field) or ""
        if not val:
            self._set_status("无可复制内容"); return
        QGuiApplication.clipboard().setText(val)
        self._clip_value = val
        secs = int(self.cfg.get("clipboard_clear_seconds", 30))
        if secs > 0:
            self.clip_timer.start(secs * 1000)
        self._set_status(f"已复制，{secs} 秒后自动清空剪贴板")

    def _clear_clipboard(self):
        """只清本应用刚写入的内容；用户后来复制的东西不动。"""
        if not self._clip_value:
            return
        cb = QGuiApplication.clipboard()
        if cb.text() == self._clip_value:
            cb.clear()
        self._clip_value = ""

    def closeEvent(self, event):
        self.clip_timer.stop()
        self._clear_clipboard()
        super().closeEvent(event)

    # ---- 同步 ----
    def _sync(self):
        if not self.vid:
            QMessageBox.information(self, "未解锁", "请先解锁一个本地库。"); return
        meta = storage.load_meta(self.vid)
        prefill = meta.get("last_account") or ""
        d = SyncDialog(self.cfg, prefill, self)
        if not d.exec() or not d.result:
            return
        r = d.result
        client = make_client(self.cfg, r["username"], r["service_pwd"])
        self._set_status("处理中…")
        try:
            if r["mode"] == "register":
                self._do_register(client, r)
            elif r["mode"] == "pull":
                self._do_pull(client, r)
            else:
                self._do_push(client, r)
        except sync.PinError as e:
            self._set_status("证书校验失败")
            QMessageBox.critical(self, "证书指纹不匹配", str(e))
        except sync.AuthError as e:
            self._set_status("认证失败")
            QMessageBox.critical(self, "账号或账号密码错误", str(e))
        except sync.UsernameTakenError as e:
            self._set_status("注册失败")
            QMessageBox.critical(self, "用户名已被占用", str(e))
        except sync.NotFoundError as e:
            self._set_status("云端无库")
            QMessageBox.information(self, "云端无密码库", str(e))
        except sync.SyncError as e:
            self._set_status("同步失败")
            QMessageBox.critical(self, "同步失败", str(e))

    def _remember_service_pwd(self, r: dict):
        """同步/注册成功后才落盘凭据与开关：登录失败不会把输错的密码记进凭据库。"""
        if r["remember"]:
            keyring_store.save_service_pwd(r["username"], r["service_pwd"])
            self.cfg["remember_service_pwd"] = True
        else:
            keyring_store.delete_service_pwd(r["username"])
            self.cfg["remember_service_pwd"] = False
        storage.save_config(self.cfg)

    def _do_register(self, client: sync.SyncClient, r: dict):
        """仅创建服务器账号（云端零份库），不上传本地密码库。"""
        wait_for(self, lambda: client.register(
            service_pwd=r["service_pwd"], email=r["email"], phone=r["phone"]),
            "正在注册账号…")
        storage.log_sync(self.vid, f"注册账号 ok @{r['username']}（云端零份库，待推送）")
        self._remember_service_pwd(r)
        meta = storage.load_meta(self.vid)
        meta["last_account"] = r["username"]
        storage.save_meta(self.vid, meta)
        self.account = r["username"]
        self._refresh_header(meta)
        self._set_status(f"注册成功 · 请登录并『推送』本地库")
        QMessageBox.information(
            self, "注册成功",
            "账号已在服务器创建（云端目前零份库，未上传你的密码库）。\n\n"
            "下一步：再次打开『同步』→ 点『登录』→ 选『推送』，"
            "即可把当前本地库上传（服务器只存密文，每推送多一份历史）。")

    def _do_push(self, client: sync.SyncClient, r: dict):
        if self._key is None or self._salt is None:
            raise sync.SyncError("会话密钥缺失，请重新解锁密码库")
        blob = crypto.encrypt_with_key(self.vault.to_json(), self._key, self._salt)
        ct_b64 = base64.b64encode(blob).decode("ascii")
        resp = wait_for(self, lambda: client.put_vault(
            pwd_time=self.vault.pwd_time,
            label=self.vault.label,
            ciphertext_b64=ct_b64), "正在推送密码库…")
        storage.log_sync(self.vid,
                         f"推送 ok @{r['username']} 云端#{resp['vid']} "
                         f"保留{resp['kept']}份 sha={resp['ciphertext_sha256'][:12]}")
        self.vault.modified_at = int(resp["upload_time"])
        meta = storage.load_meta(self.vid)
        meta["last_account"] = r["username"]     # 只有推送成功后才记录账号
        storage.save_meta(self.vid, meta)
        storage.save_vault(self.vid, self.vault, never_uploaded=False,
                           key=self._key, salt=self._salt)
        self._remember_service_pwd(r)
        self.account = r["username"]
        self._refresh_header(meta)
        self._set_status(
            f"推送成功 · 云端新增第 {resp['vid']} 份（现保留 {resp['kept']}/5 份）")

    def _do_pull(self, client: sync.SyncClient, r: dict):
        vaults = wait_for(self, client.list_vaults, "正在获取云端库列表…")
        if not vaults:
            QMessageBox.information(
                self, "云端为空",
                "该账号在云端还没有密码库。请先用『推送』上传。")
            self._set_status("云端无数据")
            return
        pick = ServerVaultPickerDialog(vaults, self)
        if not pick.exec() or pick.selected_vid is None:
            self._set_status("已取消"); return
        try:
            info = wait_for(self, lambda: client.get_vault(pick.selected_vid),
                            "正在下载云端密码库…")
        except sync.NotFoundError:
            QMessageBox.information(self, "云端无该库", "该份库已不存在，请重试。")
            self._set_status("已取消"); return
        ct = base64.b64decode(info["ciphertext"]) if info.get("ciphertext") else b""
        if not ct:
            QMessageBox.information(self, "云端为空", "该份库内容为空。")
            self._set_status("云端无数据")
            return
        meta = storage.load_meta(self.vid)
        if meta.get("never_uploaded"):
            if QMessageBox.question(
                    self, "本地有未推送修改",
                    "本地尚未推送到服务器的修改会被**覆盖丢失**。确定拉取？",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            ) != QMessageBox.StandardButton.Yes:
                self._set_status("已取消"); return
        try:
            plain, key, salt = crypto.open_vault(ct, self.vault_pwd)
        except UnlockError:
            vp, ok = QInputDialog.getText(
                self, "云端密码库密码",
                "云端库无法用当前密码库密码解开，请输入云端库对应的密码库密码：",
                QLineEdit.EchoMode.Password)
            if not ok:
                self._set_status("已取消"); return
            try:
                plain, key, salt = crypto.open_vault(ct, vp)
            except UnlockError:
                QMessageBox.critical(self, "解锁失败", "云端密码库密码错误。")
                self._set_status("拉取失败"); return
            self.vault_pwd = vp
        new_v = vault_mod.Vault.from_json(plain)
        # 覆盖前留一份 .bak，并原子落盘（避免写一半崩溃导致整库损坏）
        storage.backup_vault(self.vid)
        storage.write_vault_bytes(self.vid, ct)
        meta.update({"pwd_time": new_v.pwd_time,
                     "modified_at": sync.now_ms(),
                     "label": new_v.label,
                     "never_uploaded": False,
                     "record_count": len(new_v.active_records()),
                     "last_account": r["username"]})
        storage.save_meta(self.vid, meta)
        self.vault = new_v
        self.account = r["username"]
        self._key, self._salt = key, salt
        self._refresh_list()
        self._refresh_header(meta)
        storage.log_sync(self.vid, f"拉取 ok @{r['username']} 云端#{pick.selected_vid}")
        self._remember_service_pwd(r)
        self._set_status(f"拉取成功 · {len(new_v.active_records())} 条")

    # ---- 改密 ----
    def _change_vault_pwd(self):
        if not self.vid: return
        d = ChangeVaultPwdDialog(self)
        if not d.exec() or not d.result: return
        old, new = d.result
        try:
            storage.load_vault(self.vid, old)
        except UnlockError:
            QMessageBox.critical(self, "失败", "旧密码库密码错误。"); return
        if not self._export_before_pwd_change():
            return
        now = sync.now_ms()
        if _date_str(now) != _date_str(self.vault.pwd_time):
            new_label = today_label("改密")
        else:
            new_label = self.vault.label or today_label("初始")
        self.vault.pwd_time = now
        self.vault.label = new_label
        self.vault.touch()
        # 改密 = 新 salt + 新 key；旧 key 立即丢弃
        salt = crypto.new_salt()
        key = crypto.derive_key(new, salt, crypto.ARGON_M, crypto.ARGON_T, crypto.ARGON_P)
        storage.save_vault(self.vid, self.vault, never_uploaded=True,
                           key=key, salt=salt)
        self._key, self._salt = key, salt
        self.vault_pwd = new
        self._refresh_header()
        storage.log_sync(self.vid, f"改密码库密码 label={new_label} (未同步)")
        self._set_status(f"密码库密码已修改 · label={new_label} · 待同步")

    def _export_before_pwd_change(self) -> bool:
        """规范 §12.3：改密前必须成功导出一份明文 CSV，取消/失败即中止。"""
        default = f"pwdmgr_before_pwd_change_{time.strftime('%Y%m%d_%H%M%S')}.csv"
        path, _ = QFileDialog.getSaveFileName(
            self, "改密前导出明文备份（必须）", default, "CSV 文件 (*.csv)")
        if not path:
            QMessageBox.information(
                self, "已取消改密",
                "规范要求改密码库密码前先导出一份备份；未导出，已中止改密。")
            return False
        try:
            storage.export_csv(self.vault, path)
        except OSError as e:
            QMessageBox.critical(self, "备份失败", f"导出失败，已中止改密：\n{e}")
            return False
        QMessageBox.information(self, "备份完成",
                                f"已导出到：\n{path}\n\n接下来修改密码库密码。")
        return True

    def _change_service_pwd(self):
        if not self.vid: return
        meta = storage.load_meta(self.vid)
        d = ChangeServicePwdDialog(self.cfg, meta.get("last_account") or "", self)
        if not d.exec() or not d.result: return
        r = d.result
        client = make_client(self.cfg, r["username"], r["old"])
        try:
            wait_for(self, lambda: client.change_service_pwd(r["new"]),
                     "正在修改用户密码…")
        except sync.AuthError:
            QMessageBox.critical(self, "失败", "旧用户密码错误。"); return
        except sync.SyncError as e:
            QMessageBox.critical(self, "失败", str(e)); return
        if self.cfg.get("remember_service_pwd"):
            keyring_store.save_service_pwd(r["username"], r["new"])
        else:
            keyring_store.delete_service_pwd(r["username"])
        storage.log_sync(self.vid, "改用户密码")
        QMessageBox.information(self, "完成", "用户密码已修改。")

    def _delete_account(self):
        if not self.vid: return
        meta = storage.load_meta(self.vid)
        if not meta.get("last_account"):
            QMessageBox.information(self, "无账号",
                                    "本库尚未同步过任何账号，无需注销云端账户。")
            return
        if QMessageBox.warning(
                self, "危险：注销云端账户",
                f"云端账户 {meta['last_account']} + 其云端密码库将被永久删除，本地库保留。\n\n"
                "确定继续？",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        ) != QMessageBox.StandardButton.Yes:
            return
        d = ConfirmAccountDialog(self.cfg, meta["last_account"], self)
        if not d.exec() or not d.result: return
        r = d.result
        client = make_client(self.cfg, r["username"], r["old"])
        try:
            wait_for(self, client.delete_account, "正在注销云端账户…")
        except sync.SyncError as e:
            QMessageBox.critical(self, "失败", str(e)); return
        keyring_store.delete_service_pwd(r["username"])
        storage.log_sync(self.vid, f"云端账户已注销 @{r['username']}")
        meta = storage.load_meta(self.vid)
        meta["never_uploaded"] = True
        storage.save_meta(self.vid, meta)
        QMessageBox.information(self, "完成",
                                "云端账户已注销。本地库保留，可重新注册。")

    # ---- 设置 ----
    def _settings(self):
        d = ServerSettingsDialog(self.cfg, self)
        if d.exec():
            storage.save_config(self.cfg)
            self._set_status("设置已保存")

    # ---- CSV ----
    def _import_csv(self):
        if not self.vid:
            QMessageBox.information(self, "未解锁", "请先解锁一个本地库。"); return
        cols = ",".join(storage.CSV_COLUMNS)
        if QMessageBox.warning(
                self, "导入 CSV",
                "从 CSV 文件导入记录到当前本地库。\n\n"
                f"⚠ 严格格式校验，**不符合格式的导入会整批失败**（一条都不会写入）：\n"
                f"· 第一行必须是列名，至少包含 type、title；标准表头：\n  {cols}\n"
                "· type 只能是 login 或 apikey；title 必填；apikey 行的 apikey 必填。\n\n"
                "确定选择文件？",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        ) != QMessageBox.StandardButton.Yes:
            return
        path, _ = QFileDialog.getOpenFileName(self, "导入 CSV", "", "CSV 文件 (*.csv)")
        if not path:
            return
        try:
            records = storage.import_csv(path)
        except storage.CsvFormatError as e:
            QMessageBox.critical(self, "导入失败（格式不符）",
                                 f"{e}\n\n未导入任何记录。")
            self._set_status("CSV 导入失败 · 格式不符")
            return
        if not records:
            QMessageBox.information(self, "无数据", "文件符合格式，但没有任何数据行。")
            self._set_status("CSV 无数据行")
            return
        if QMessageBox.question(
                self, "确认导入",
                f"校验通过：{len(records)} 行符合格式。\n"
                "将以**新增**方式导入当前本地库（不会覆盖已有记录）。继续？",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        ) != QMessageBox.StandardButton.Yes:
            self._set_status("已取消")
            return
        for r in records:
            self.vault.add(type=r["type"], title=r["title"], url=r["url"],
                           username=r["username"], password=r["password"],
                           apikey=r["apikey"], note=r["note"])
        self._save_local(); self._refresh_list()
        self._set_status(f"已导入 {len(records)} 条 · 未同步")
        QMessageBox.information(self, "导入成功",
                                 f"已导入 {len(records)} 条记录。请记得点『同步』推送。")

    def _export_csv(self):
        n = len(self.vault.active_records())
        if n == 0:
            QMessageBox.information(self, "无数据", "当前没有可导出的记录。"); return
        if QMessageBox.warning(
                self, "导出明文警告",
                f"将导出 {n} 条记录为 CSV，其中包含**明文密码/API Key**。\n"
                "导出文件不受加密保护，请用后及时安全删除。\n\n确定继续？",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        ) != QMessageBox.StandardButton.Yes:
            return
        default = f"pwdmgr_export_{time.strftime('%Y%m%d_%H%M%S')}.csv"
        path, _ = QFileDialog.getSaveFileName(self, "导出 CSV", default, "CSV 文件 (*.csv)")
        if not path: return
        try:
            real = storage.export_csv(self.vault, path)
            QMessageBox.information(self, "已导出",
                                     f"已导出到：\n{real}\n\n请妥善保管并及时删除该明文文件。")
        except OSError as e:
            QMessageBox.critical(self, "导出失败", str(e))


def _date_str(ms: int) -> str:
    # 与 label 的生成保持一致，用本地日期（不能用 gmtime，UTC+8 凌晨会判错"跨天"）
    return time.strftime("%Y-%m-%d", time.localtime(ms / 1000))


def main():
    missing = []
    try:
        import keyring  # noqa
    except Exception:
        missing.append("keyring")
    app = QApplication(sys.argv)
    app.setApplicationName(APP_TITLE)
    if missing:
        QMessageBox.warning(None, "缺少依赖",
                             f"未安装：{', '.join(missing)}。凭据记忆功能不可用。")
    w = MainWindow()
    if not w.bootstrap():
        return 0
    w.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())

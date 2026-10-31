# 密码管理器 · 电脑端 (Windows / PyQt6)

本地端到端加密的密码管理器桌面端。数据用主密码在本机加密后存 `vault.enc`，
可经你的乌班图服务器与其他设备同步（服务器只存密文）。

## 运行

**双击 `启动.bat` 即可**（首次会自动建虚拟环境并装依赖）。

或手动：

```bash
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
.venv\Scripts\python.exe app.py
```

## ⚠️ 重要：不要用 Anaconda 的 Python 直接跑

本机的 `python` 默认指向 Anaconda（`Anaconda 安装目录`）。Anaconda 自带的 DLL 与
PyPI 版 PyQt6 冲突，直接 `python app.py` 会报：

```
ImportError: DLL load failed while importing QtCore: 找不到指定的程序
```

**必须用本目录的独立 venv**（`启动.bat` 已自动处理）。venv 里固定使用
`PyQt6 6.7.1` 组合——6.11 版在本机有 ABI 不匹配问题，勿随意升级。

## 功能

- 主密码解锁 / 首次创建（主密码只在本机内存中用于派生密钥，绝不上传）
- 两类记录：网站登录（标题/网址/用户名/密码）、API Key（标题/key/备注）
- 搜索、新增、编辑、删除（软删除墓碑，跨设备传播）
- 内置密码生成器；一键复制，30 秒后自动清空剪贴板
- 闲置 5 分钟自动锁定
- CSV 导出（明文，导出前二次确认）
- 服务器同步（乐观锁 + 客户端明文合并）

## 数据位置

- 库文件：`%APPDATA%\PwdMgr\vault.enc`
- 配置：`%APPDATA%\PwdMgr\config.json`（不含主密码/密钥）

## 首次配置同步

「设置 → 服务器与同步设置」填写：
- 服务器地址：`https://<服务器地址>:8443`（只接受 https）
- 证书指纹：服务器自签证书的 SHA-256，见 `../server/DEPLOY.md`
- 账号：首次先在「同步 → 注册账号」建服务器账号，之后用「用户名 + 用户密码」登录（没有同步令牌）

## 模块

| 文件 | 职责 |
|---|---|
| `crypto.py` | Argon2id 派生 + AES-256-GCM，`vault.enc` 读写（规范第 2/3 节） |
| `vault.py` | 记录模型 + CRUD + 跨设备合并（规范第 4/5 节） |
| `sync.py` | 同步客户端 + 乐观锁重试（规范第 6 节） |
| `storage.py` | 本地库/配置读写 + CSV 导出（规范第 7/8 节） |
| `app.py` | PyQt6 图形界面 |

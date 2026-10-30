# 部署密码管理器同步服务器到 Ubuntu

> ⚠️ 旧版 v1 提示词（`/setup` 同步令牌、systemd），与当前 v2.3 部署不符。
> 请以 `server/DEPLOY.md` 为准；`<...>` 为占位符，使用前自行替换。

## 目标
在 `/home/<SSH 用户名>/AiWork/psd_manager` 目录下部署 FastAPI 同步服务器。

## 执行步骤

### 1. 创建项目目录
```bash
mkdir -p /home/<SSH 用户名>/AiWork/psd_manager
cd /home/<SSH 用户名>/AiWork/psd_manager
```

### 2. 创建虚拟环境并安装依赖
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install fastapi uvicorn[standard] pydantic
```

### 3. 复制以下文件到服务器目录
将本地 `E:\密码管理器\server\` 下的所有 `.py` 文件复制到 `/home/<SSH 用户名>/AiWork/psd_manager/`：
- `main.py`
- `store.py`
- `auth.py`

### 4. 创建 systemd 服务文件
创建 `/etc/systemd/system/pwdmgr-sync.service`：

```ini
[Unit]
Description=Password Manager Sync Server
After=network.target

[Service]
Type=simple
User=<SSH 用户名>
WorkingDirectory=/home/<SSH 用户名>/AiWork/psd_manager
Environment="PATH=/home/<SSH 用户名>/AiWork/psd_manager/.venv/bin"
ExecStart=/home/<SSH 用户名>/AiWork/psd_manager/.venv/bin/uvicorn main:app --host 0.0.0.0 --port 8443 --workers 1
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

### 5. 启动服务
```bash
sudo systemctl daemon-reload
sudo systemctl enable pwdmgr-sync
sudo systemctl start pwdmgr-sync
sudo systemctl status pwdmgr-sync
```

### 6. 配置防火墙（如果需要）
```bash
sudo ufw allow 8443/tcp
```

### 7. 验证服务
```bash
curl http://localhost:8443/health
# 应返回: {"status":"ok","initialized":false}
```

### 8. 首次初始化
```bash
curl -X POST http://localhost:8443/setup \
  -H "Content-Type: application/json" \
  -d '{"token": "<在此填入一个至少16字符的随机令牌>"}'
```

## 注意事项
- 服务器监听 8443 端口
- 数据库文件默认存储在 `/home/<SSH 用户名>/AiWork/psd_manager/pwmanager.db`
- 如需更改端口，修改 systemd 服务文件中的 `--port` 参数
- 日志查看：`journalctl -u pwdmgr-sync -f`

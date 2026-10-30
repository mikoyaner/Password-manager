#!/bin/bash
# 密码管理器服务器部署脚本
# 用法: ./deploy.sh [user@host]
#
# ⚠️ 旧版 v1 脚本（/setup 同步令牌 + systemd + sudo），与当前 v2.3（Basic 认证、无 sudo、nohup）不符。
# 推荐改用 server/_sync_code.py（日常更新）与 server/DEPLOY.md。下方 <...> 为占位符，使用前自行替换。

set -e

REMOTE="${1:-<SSH 用户名>@<服务器地址>}"
REMOTE_DIR="/home/<SSH 用户名>/AiWork/psd_manager"

echo "=== 正在部署到 $REMOTE:$REMOTE_DIR ==="

# 创建远程目录
ssh "$REMOTE" "mkdir -p $REMOTE_DIR"

# 复制 Python 文件
echo ">>> 复制服务器代码..."
scp main.py store.py auth.py "$REMOTE:$REMOTE_DIR/"

# 在远程服务器上执行安装
echo ">>> 安装依赖..."
ssh "$REMOTE" bash << 'EOF'
cd /home/<SSH 用户名>/AiWork/psd_manager

# 创建虚拟环境（如果不存在）
if [ ! -d ".venv" ]; then
    python3 -m venv .venv
fi

# 激活并安装
source .venv/bin/activate
pip install --upgrade pip
pip install fastapi uvicorn[standard] pydantic

# 创建 systemd 服务文件
sudo tee /etc/systemd/system/pwdmgr-sync.service > /dev/null << 'SERVICE'
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
SERVICE

# 重载 systemd 并启动
sudo systemctl daemon-reload
sudo systemctl enable pwdmgr-sync
sudo systemctl restart pwdmgr-sync

echo ">>> 服务状态:"
sudo systemctl status pwdmgr-sync --no-pager

echo ""
echo ">>> 验证健康检查:"
sleep 2
curl -s http://localhost:8443/health || echo "(等待服务启动...)"
EOF

echo ""
echo "=== 部署完成 ==="
echo ""
echo "下一步："
echo "1. 首次初始化服务器（设置同步令牌）："
echo "   curl -X POST http://<服务器地址>:8443/setup \\"
echo "     -H 'Content-Type: application/json' \\"
echo "     -d '{\"token\": \"你的至少16字符随机令牌\"}'"
echo ""
echo "2. 在桌面端和安卓端配置服务器地址: https://<服务器地址>:8443"

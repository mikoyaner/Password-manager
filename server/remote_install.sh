#!/bin/bash
# 远程安装脚本 - 在服务器上执行（无需 sudo）
# v2.1: HTTPS + 自签证书 + uvicorn 内建 TLS（因服务器无 sudo，用 8443 端口跑 HTTPS）
set -e

REMOTE_DIR="${REMOTE_DIR:-$HOME/AiWork/psd_manager}"
CERT_DIR="$REMOTE_DIR/certs"
KEY="$CERT_DIR/server.key"
CRT="$CERT_DIR/server.crt"

echo ">>> 创建虚拟环境..."
cd "$REMOTE_DIR"
if [ ! -d ".venv" ]; then
  python3 -m venv .venv
fi
source .venv/bin/activate

echo ">>> 安装依赖..."
pip install --upgrade pip
pip install fastapi "uvicorn[standard]" pydantic argon2-cffi

echo ">>> 停止旧进程..."
pkill -f "uvicorn main:app" || true
sleep 1

echo ">>> 生成自签证书（有效期 10 年）..."
mkdir -p "$CERT_DIR"
if [ ! -f "$KEY" ] || [ ! -f "$CRT" ]; then
  : "${PUBLIC_IP:?请先设置 PUBLIC_IP（服务器公网地址）}"
  openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$KEY" -out "$CRT" \
    -days 3650 -subj "/CN=psd-manager" \
    -addext "subjectAltName=IP:${PUBLIC_IP}"
  echo ">>> 证书已生成"
else
  echo ">>> 已存在证书，跳过生成"
fi

echo ">>> 证书 SHA-256 指纹（供客户端 pinning 使用）："
openssl x509 -in "$CRT" -noout -fingerprint -sha256 | sed 's/.*=//' | tr -d ':' | tr 'A-F' 'a-f'
echo ""

echo ">>> 启动服务 (nohup 后台运行, HTTPS)..."
nohup .venv/bin/uvicorn main:app --host 0.0.0.0 --port 8443 --workers 1 \
  --ssl-keyfile "$KEY" --ssl-certfile "$CRT" \
  > server.log 2>&1 &
SERVER_PID=$!
echo ">>> 服务 PID: $SERVER_PID"

sleep 3

echo ""
echo ">>> 验证健康检查 (HTTPS):"
curl -sk https://localhost:8443/health || echo "(等待服务启动...)"

echo ""
echo ">>> 查看进程:"
ps aux | grep "uvicorn main:app" | grep -v grep || true

echo ""
echo "=== 部署完成 ==="
echo ""
echo "服务已在后台运行 (PID: $SERVER_PID)"
echo "日志文件: $REMOTE_DIR/server.log"
echo ""
echo "管理命令:"
echo "  查看日志: tail -f $REMOTE_DIR/server.log"
echo "  停止服务: pkill -f 'uvicorn main:app'"
echo "  重启服务: pkill -f 'uvicorn main:app' && cd $REMOTE_DIR && nohup .venv/bin/uvicorn main:app --host 0.0.0.0 --port 8443 --workers 1 --ssl-keyfile $KEY --ssl-certfile $CRT > server.log 2>&1 &"

#!/usr/bin/env bash
# server_setup.sh —— 一次性安装/迁移脚本（在服务器上以 root 执行一次，幂等可重跑）。
#
# 前提：专用账号已按 DEPLOY.md 手动创建（本脚本只校验、不建账号）：
#   useradd --system --user-group --home-dir /opt/pwmanager --shell /usr/sbin/nologin pwmanager
#   useradd -m -s /bin/bash pwdeploy && passwd -l pwdeploy
#   （并把本机 server/deploy_key.pub 追加进 /home/pwdeploy/.ssh/authorized_keys）
#
# 用法: sudo bash server_setup.sh [旧部署目录]
#       旧目录缺省时自动探测 /home/*/AiWork/psd_manager
set -euo pipefail

TARGET=/opt/pwmanager
SERVER_DIR=$TARGET/server
DATA_DIR=$SERVER_DIR/data
CERT_DIR=$SERVER_DIR/certs
VENV_DIR=$TARGET/venv
BIN_DIR=$TARGET/bin
SUDOERS=/etc/sudoers.d/pwmanager
UNIT_SRC=$SERVER_DIR/pwmanager.service
UNIT_DST=/etc/systemd/system/pwmanager.service

log() { echo "==> $*"; }
die() { echo "!!! $*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "请以 root 执行: sudo bash $0 [旧部署目录]"

# ---- 0) 校验专用账号（用户手动创建） ----
id pwdeploy >/dev/null 2>&1 || die "账号 pwdeploy 不存在。先创建: useradd -m -s /bin/bash pwdeploy && passwd -l pwdeploy（并装好 deploy_key.pub）"
id pwmanager >/dev/null 2>&1 || die "账号 pwmanager 不存在。先创建: useradd --system --user-group --home-dir $TARGET --shell /usr/sbin/nologin pwmanager"
getent group pwmanager >/dev/null 2>&1 || die "缺少组 pwmanager。请以 root 执行: groupadd --system pwmanager && usermod -g pwmanager pwmanager（或用 useradd --system --user-group 重建账号）"

# ---- 1) 目录与属主 ----
log "创建目录结构与属主..."
mkdir -p "$DATA_DIR" "$CERT_DIR" "$VENV_DIR" "$BIN_DIR"
chown pwdeploy:pwmanager "$SERVER_DIR" 2>/dev/null || chown pwdeploy:pwdeploy "$SERVER_DIR"
chmod 750 "$SERVER_DIR"
chown pwdeploy:pwmanager "$CERT_DIR"; chmod 750 "$CERT_DIR"
chown pwmanager:pwmanager "$DATA_DIR"; chmod 700 "$DATA_DIR"   # 唯一可写：数据库目录
chown -R pwdeploy:pwmanager "$VENV_DIR"
chmod -R g+rX "$VENV_DIR"   # 服务（组 pwmanager）只需读/执行，不需要写
chown root:root "$BIN_DIR"; chmod 755 "$BIN_DIR"
chown root:root "$TARGET"; chmod 755 "$TARGET"

# ---- 1.5) 复制代码文件：脚本所在目录（deploy_via_python 上传位置）→ $SERVER_DIR ----
SRC_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ "$SRC_DIR" != "$SERVER_DIR" ] && [ -f "$SRC_DIR/pwmanager.service" ]; then
  log "复制代码文件: $SRC_DIR -> $SERVER_DIR"
  for f in main.py store.py auth.py manage.py requirements.txt pwmanager.service server_setup.sh; do
    [ -f "$SRC_DIR/$f" ] && cp -a "$SRC_DIR/$f" "$SERVER_DIR/$f"
  done
fi

# ---- 2) manage.py 包装脚本（以 pwmanager 身份运行；加载 admin.env 供 set_contact 取 pepper）----
cat > "$BIN_DIR/manage-as-service.sh" <<'EOF'
#!/bin/sh
set -a
PWMGR_DB=/opt/pwmanager/server/data/pwmanager.db
[ -f /opt/pwmanager/server/admin.env ] && . /opt/pwmanager/server/admin.env
set +a
exec /opt/pwmanager/venv/bin/python /opt/pwmanager/server/manage.py "$@"
EOF
chown root:root "$BIN_DIR/manage-as-service.sh"; chmod 755 "$BIN_DIR/manage-as-service.sh"

# ---- 3) sudoers 白名单（pwdeploy 能做的 root 操作仅限这些） ----
# 不要给 pwdeploy 安装 unit / daemon-reload 的权限：unit 源文件在它可写的目录里，
# 允许 install 等于允许它改写 ExecStart 再以 root 启动，直接提权。
log "安装 sudoers 白名单..."
cat > "$SUDOERS" <<'EOF'
pwdeploy ALL=(root) NOPASSWD: /usr/bin/systemctl restart pwmanager.service, /usr/bin/systemctl stop pwmanager.service, /usr/bin/systemctl start pwmanager.service, /usr/bin/systemctl status pwmanager.service
pwdeploy ALL=(root) NOPASSWD: /usr/bin/systemctl daemon-reload
pwdeploy ALL=(root) NOPASSWD: /usr/bin/install -m 0644 /opt/pwmanager/server/pwmanager.service /etc/systemd/system/pwmanager.service
pwdeploy ALL=(root) NOPASSWD: /usr/bin/install -m 0644 /opt/pwmanager/server/pwmanager-mail.service /etc/systemd/system/pwmanager-mail.service
pwdeploy ALL=(root) NOPASSWD: /usr/bin/install -m 0644 /opt/pwmanager/server/pwmanager-mail.timer /etc/systemd/system/pwmanager-mail.timer
pwdeploy ALL=(pwmanager) NOPASSWD: /opt/pwmanager/bin/manage-as-service.sh *
EOF
chown root:root "$SUDOERS"; chmod 440 "$SUDOERS"
visudo -c -f "$SUDOERS" >/dev/null || { rm -f "$SUDOERS"; die "sudoers 语法校验失败，已移除 $SUDOERS"; }
# 附赠：允许 pwdeploy 读 journal（服务日志），重新登录后生效
usermod -aG systemd-journal pwdeploy 2>/dev/null || true

# ---- 4) 代码文件权限 + 安装 systemd 单元 ----
for f in main.py store.py auth.py manage.py mail_worker.py requirements.txt \
         pwmanager.service pwmanager-mail.service pwmanager-mail.timer server_setup.sh; do
  [ -f "$SERVER_DIR/$f" ] && chown pwdeploy:pwmanager "$SERVER_DIR/$f" && chmod 640 "$SERVER_DIR/$f"
done
[ -f "$UNIT_SRC" ] || die "缺少 $UNIT_SRC（先运行 deploy_via_python.py 上传）"
install -m 644 "$UNIT_SRC" "$UNIT_DST"
for u in pwmanager-mail.service pwmanager-mail.timer; do
  [ -f "$SERVER_DIR/$u" ] && install -m 644 "$SERVER_DIR/$u" "/etc/systemd/system/$u"
done

# 管理员配置（找回密码）：已存在则不覆盖；token 首次自动生成
ADMIN_ENV="$SERVER_DIR/admin.env"
if [ ! -f "$ADMIN_ENV" ]; then
  log "生成 admin.env 模板（请填入 IMAP/SMTP 授权码与管理员邮箱）..."
  cat > "$ADMIN_ENV" <<EOF
# 找回密码（管理员侧）配置。修改后: systemctl restart pwmanager && systemctl restart pwmanager-mail.timer
PWMGR_ADMIN_EMAIL=
PWMGR_IMAP_HOST=imap.qq.com
PWMGR_IMAP_USER=
PWMGR_IMAP_PASS=
PWMGR_SMTP_HOST=smtp.qq.com
PWMGR_SMTP_PORT=465
PWMGR_SMTP_USER=
PWMGR_SMTP_PASS=
PWMGR_SMS_HOOK_TOKEN=$(openssl rand -hex 32 2>/dev/null || head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')
PWMGR_CONTACT_PEPPER=$(openssl rand -hex 32 2>/dev/null || head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')
PWMGR_ADMIN_SMS_HINT=
EOF
fi
# 幂等补键：旧版模板缺的键补齐；token/pepper 为空则自动生成
for k in PWMGR_ADMIN_EMAIL PWMGR_IMAP_HOST PWMGR_IMAP_USER PWMGR_IMAP_PASS \
         PWMGR_SMTP_HOST PWMGR_SMTP_PORT PWMGR_SMTP_USER PWMGR_SMTP_PASS \
         PWMGR_SMS_HOOK_TOKEN PWMGR_CONTACT_PEPPER PWMGR_ADMIN_SMS_HINT; do
  grep -q "^$k=" "$ADMIN_ENV" || echo "$k=" >> "$ADMIN_ENV"
done
gen_hex() { openssl rand -hex 32 2>/dev/null || head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n'; }
grep -qE "^PWMGR_SMS_HOOK_TOKEN=..*" "$ADMIN_ENV" || \
  sed -i "s/^PWMGR_SMS_HOOK_TOKEN=.*/PWMGR_SMS_HOOK_TOKEN=$(gen_hex)/" "$ADMIN_ENV"
grep -qE "^PWMGR_CONTACT_PEPPER=..*" "$ADMIN_ENV" || \
  sed -i "s/^PWMGR_CONTACT_PEPPER=.*/PWMGR_CONTACT_PEPPER=$(gen_hex)/" "$ADMIN_ENV"
chown root:pwmanager "$ADMIN_ENV"; chmod 640 "$ADMIN_ENV"
chmod 640 "$ADMIN_ENV"
systemctl daemon-reload
systemctl enable --now pwmanager-mail.timer >/dev/null 2>&1 || true

# ---- 5) venv 与依赖 ----
if [ ! -x "$VENV_DIR/bin/python" ]; then
  log "创建 venv 并安装依赖..."
  sudo -u pwdeploy python3 -m venv "$VENV_DIR"
  sudo -u pwdeploy "$VENV_DIR/bin/pip" install --upgrade pip -q
  sudo -u pwdeploy "$VENV_DIR/bin/pip" install -r "$SERVER_DIR/requirements.txt" -q
fi

# ---- 6) 迁移旧部署的数据与证书（原文件保留在旧目录，充当备份） ----
OLD_DIR="${1:-}"
if [ -z "$OLD_DIR" ]; then
  OLD_DIR=$(ls -d /home/*/AiWork/psd_manager 2>/dev/null | head -1 || true)
fi
if [ -n "${OLD_DIR:-}" ] && [ -d "$OLD_DIR" ] && [ "$OLD_DIR" != "$SERVER_DIR" ]; then
  log "发现旧部署目录: $OLD_DIR"
  pkill -f 'uvicorn main:app' 2>/dev/null || true   # 停旧 nohup 进程，保证 DB 不在写入中被拷
  sleep 1
  if [ -f "$OLD_DIR/pwmanager.db" ] && [ ! -f "$DATA_DIR/pwmanager.db" ]; then
    cp -a "$OLD_DIR"/pwmanager.db "$DATA_DIR/" 2>/dev/null || true
    for ext in -wal -shm; do
      [ -f "$OLD_DIR/pwmanager.db$ext" ] && cp -a "$OLD_DIR/pwmanager.db$ext" "$DATA_DIR/" || true
    done
    chown pwmanager:pwmanager "$DATA_DIR"/pwmanager.db* 2>/dev/null || true
    chmod 600 "$DATA_DIR"/pwmanager.db* 2>/dev/null || true
    log "数据库已迁移（原文件保留在旧目录）"
  fi
  if [ -f "$OLD_DIR/certs/server.crt" ] && [ ! -f "$CERT_DIR/server.crt" ]; then
    cp -a "$OLD_DIR/certs/server.crt" "$OLD_DIR/certs/server.key" "$CERT_DIR/"
    chown pwdeploy:pwmanager "$CERT_DIR"/server.crt "$CERT_DIR"/server.key
    chmod 644 "$CERT_DIR"/server.crt; chmod 640 "$CERT_DIR"/server.key
    log "证书已搬运（指纹不变，客户端无需更新）"
  fi
else
  log "未发现旧部署目录（或已迁移）。如需指定: sudo bash $0 /home/<用户>/AiWork/psd_manager"
fi

# 没有任何证书时生成自签证书（10 年，SAN=公网 IP）
if [ ! -f "$CERT_DIR/server.crt" ]; then
  PUB_IP=${PUBLIC_IP:-$(hostname -I 2>/dev/null | awk '{print $1}')}
  log "生成新的自签证书（SAN: $PUB_IP）..."
  if [ -n "$PUB_IP" ]; then
    openssl req -x509 -newkey rsa:2048 -keyout "$CERT_DIR/server.key" -out "$CERT_DIR/server.crt" \
      -days 3650 -nodes -subj "/CN=psd-manager" -addext "subjectAltName=IP:$PUB_IP"
  else
    openssl req -x509 -newkey rsa:2048 -keyout "$CERT_DIR/server.key" -out "$CERT_DIR/server.crt" \
      -days 3650 -nodes -subj "/CN=psd-manager"
  fi
  chown pwdeploy:pwmanager "$CERT_DIR"/server.crt "$CERT_DIR"/server.key
  chmod 644 "$CERT_DIR"/server.crt; chmod 640 "$CERT_DIR"/server.key
fi

# ---- 7) 启动与健康检查 ----
log "启动 systemd 服务..."
systemctl daemon-reload
systemctl enable pwmanager.service >/dev/null 2>&1 || true
systemctl restart pwmanager.service
sleep 2

systemctl --no-pager -n 10 status pwmanager.service | head -12 || true
echo -n "健康检查: "
curl -sk https://127.0.0.1:8443/health || die "健康检查失败，查看日志: journalctl -u pwmanager.service -n 50"
echo
echo -n "证书 SHA-256 指纹: "
openssl x509 -in "$CERT_DIR/server.crt" -noout -fingerprint -sha256 | sed 's/.*=//' | tr -d ':' | tr 'A-F' 'a-f'
log "全部完成。沙箱强度自检: systemd-analyze security pwmanager.service"
log "验证只写数据目录: sudo -u pwmanager touch /opt/pwmanager/server/test  （应被拒绝）"

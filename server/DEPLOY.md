# 服务器部署（v2.6：双账号 + systemd 沙箱 + 密钥部署）

目标：Ubuntu。服务以专用低权限账号 `pwmanager` 运行在 systemd 沙箱里，
**内核级保证它只能写数据库目录**；部署走专用账号 `pwdeploy` + SSH 密钥，本机不存任何密码。

```
本机 (deploy_key) ──SSH──> pwdeploy ──白名单 sudo──> systemctl restart pwmanager.service
                                                     │ 以 pwmanager 身份运行（nologin）
                                              /opt/pwmanager/server/data/   ← 唯一可写
```

> 角色分工：`pwdeploy` = 有大门钥匙的“物业”（部署代码/证书、白名单重启）；
> `pwmanager` = 不配钥匙的“保险柜值班员”（运行服务，只写 `data/`）。
> systemd unit 只由 root 安装一次；sudoers 刻意不含 `install`/`daemon-reload`，
> 否则 pwdeploy 能改写 `ExecStart` 再让 root 启动，等于提权。

## 0. 前置

- 一台可 SSH 登录的 Ubuntu 服务器（systemd ≥ 242，20.04+ 均满足）
- 本地 Python 3.10+ 与 `paramiko`
- 服务器开放 8443（云安全组/防火墙）
- 唯一需要 root 的操作：第一步建账号 + 跑一次 `server_setup.sh`；之后日常部署零 root、零密码

## 1. 第一步：在服务器上创建专用账号（root 执行，用户名固定）

```bash
# 服务运行账号：nologin 系统账号，不能登录（--user-group 确保存在同名组）
useradd --system --user-group --home-dir /opt/pwmanager --shell /usr/sbin/nologin pwmanager

# 部署账号：可登录，锁定密码（只允许密钥认证）
useradd -m -s /bin/bash pwdeploy
passwd -l pwdeploy

# 安装部署公钥（本机 server/deploy_key.pub 的内容）
mkdir -p /home/pwdeploy/.ssh && chmod 700 /home/pwdeploy/.ssh
echo '<deploy_key.pub 的内容>' \
  >> /home/pwdeploy/.ssh/authorized_keys
chmod 600 /home/pwdeploy/.ssh/authorized_keys
chown -R pwdeploy:pwdeploy /home/pwdeploy/.ssh
```

可选加固（推荐）：只允许 pwdeploy 用密钥登录——

```bash
cat > /etc/ssh/sshd_config.d/pwdeploy.conf <<'EOF'
Match User pwdeploy
    PasswordAuthentication no
    KbdInteractiveAuthentication no
EOF
systemctl reload sshd
```

> 你原本的日常管理账号**保持原样**，继续用于服务器管理；它不再承担密码管理器的
> 部署与运行。原部署目录里的数据会在第 3 步被**复制**（不是移动）到新位置。

## 2. 第二步：配置本机凭据（只填一次）

```bash
cd server
cp .env.example .env
```

编辑 `server/.env`：

```dotenv
PWMGR_SSH_HOST=<服务器地址>
PWMGR_SSH_USER=pwdeploy
PWMGR_REMOTE_DIR=/opt/pwmanager/server
PWMGR_SSH_KEY=deploy_key
# 首次迁移旧 nohup 部署时填写（不填则自动探测 /home/*/AiWork/psd_manager）：
#PWMGR_OLD_DIR=/home/<旧SSH用户>/AiWork/psd_manager
# 过渡期（还没建 pwdeploy / 没装公钥）可临时用：
#PWMGR_SSH_PASSWORD=<过渡期 SSH 密码>
```

- 密钥认证优先；`PWMGR_SSH_PASSWORD` 只作过渡，切换后从 `.env` **删除**。
- 首次连接时脚本会打印服务器主机指纹，确认后填入 `PWMGR_SSH_HOST_FINGERPRINT`
  启用强校验（不符即拒绝，不发任何凭据）。
- `server/.env`、`deploy_key(.pub)` 均已被 `.gitignore` 排除，**不要提交**；
  也可用同名环境变量覆盖（CI 用）。

## 3. 第三步：首次安装 / 迁移（需要一次 root）

先确认自己属于哪种情况：

**A. 新服务器，SSH 账号有 root/sudo**
```dotenv
PWMGR_SSH_USER=<root 或 sudo 账号>
PWMGR_REMOTE_DIR=/opt/pwmanager/server
# 若要把旧部署的数据/证书搬过来：
#PWMGR_OLD_DIR=/home/<旧账号>/AiWork/psd_manager
```
```bash
cd server
python deploy_via_python.py     # 上传到 /opt 并自动执行 server_setup.sh
```

**B. 旧部署还在，当前只有旧账号（无 root）**
1. 先把 `.env` 的 `PWMGR_REMOTE_DIR` 设为**旧部署目录**，运行 `python deploy_via_python.py`
   把新代码和 `server_setup.sh` 上传到旧目录；
2. 再由有 sudo 的账号执行（旧目录同时作为迁移源）：
```bash
sudo bash /home/<旧账号>/AiWork/psd_manager/server_setup.sh /home/<旧账号>/AiWork/psd_manager
```
3. 完成后把 `.env` 的 `PWMGR_REMOTE_DIR` 改回 `/opt/pwmanager/server`，运行 `python _sync_code.py`。

**C. 普通账号且 `/opt` 不可写**
`deploy_via_python.py` 会在上传前直接提示权限不足，并给出 A/B 两种做法，不会卡在 sftp 报错。

`server_setup.sh`（幂等，可重跑）会依次：校验两账号及 `pwmanager` 组 → 建 `/opt/pwmanager`
目录结构与属主 → 安装 sudoers 白名单（`visudo -c` 校验）→ 安装 systemd 单元 → 建 venv 装依赖
→ 停旧 nohup 进程 → **复制** `pwmanager.db(+wal/shm)` 与 `certs/` 到新目录（保指纹，客户端零改动）
→ `systemctl enable --now` → 健康检查 + 打印证书指纹。

服务器上的最终布局：

```
/opt/pwmanager/
├── venv/                     pwdeploy 所有（pip 依赖；服务只读执行）
├── bin/manage-as-service.sh  root 所有（运维工具包装：以 pwmanager 身份 + 正确 PWMGR_DB）
└── server/                   pwdeploy:pwmanager 0750
    ├── main.py / store.py / auth.py / manage.py   0640
    ├── certs/  (0750)        server.key 0640 / server.crt 0644
    └── data/  pwmanager:pwmanager 0700            ← 服务的唯一可写目录
```

## 4. 第四步：验证沙箱

```bash
# 1) 用户层面：数据目录可写、代码目录不可写
sudo -u pwmanager touch /opt/pwmanager/server/data/.t && sudo -u pwmanager rm /opt/pwmanager/server/data/.t
sudo -u pwmanager touch /opt/pwmanager/server/test      # 因目录权限被拒

# 2) 沙箱层面：用与服务相同的 systemd 限制跑一次，验证"只能写 data"
sudo systemd-run --quiet --pipe --wait --uid=pwmanager --gid=pwmanager \
  -p ProtectSystem=strict -p ReadWritePaths=/opt/pwmanager/server/data \
  /usr/bin/touch /tmp/test        # 这里才应失败（普通 sudo -u 不受沙箱限制，会成功）

# 3) 沙箱暴露面评分
systemd-analyze security pwmanager.service

# 4) 数据迁移正确性：写一条数据 → systemctl restart → 数据仍在
```

## 5. 日常更新（保留证书/数据库）

```bash
cd server
python _sync_code.py
```

自动探测服务形态：服务器上有 `pwmanager.service` 就 `sudo -n systemctl restart`（走 sudoers
白名单），否则维持旧的 pkill/nohup 路径。只上传 4 个 py，先备份为 `*.bak_<时间戳>`，
远端语法自检失败则中止不重启。

## 6. 服务管理 / 日志

```bash
sudo systemctl restart pwmanager.service      # pwdeploy 免密可用（白名单）
sudo systemctl status pwmanager.service       # 含最近日志
journalctl -u pwmanager.service -n 50 --no-pager   # pwdeploy 在 systemd-journal 组（重登录后生效）
```

注意：`systemctl` 之外 pwdeploy 没有任何 root 能力；沙箱内服务也改不了代码目录
（代码目录属 pwdeploy），二者各守其位。

## 7. 账号运维（云端用户管理）

```bash
sudo -u pwmanager /opt/pwmanager/bin/manage-as-service.sh list_users
sudo -u pwmanager /opt/pwmanager/bin/manage-as-service.sh delete_user <username>   # 级联删云端库
sudo -u pwmanager /opt/pwmanager/bin/manage-as-service.sh reset_password <username> <new>
```

## 7.5 忘记密码：管理员侧配置（v2.8 两步确认）

**流程**（客户端「忘记密码」弹窗会展示给用户）：
1. 用户用**注册时的邮箱**发送「01用户名」到管理员收件邮箱；
2. 系统自动回复一封**确认码**邮件（8 位、15 分钟有效）；
3. 用户**回复那封邮件**（或用同一邮箱再发一封），正文中包含确认码；
4. 系统校验通过后，生成**随机临时密码**回复给用户；用户用它登录并立即改密。

安全设计（审计报告 P0-1）：不存在固定密码；确认码证明"能收信"，
伪造发件人拿不到任何凭据；临时密码绝不写日志；24h 每账号限一次重置。

**配置**（部署时自动拆分为两个文件，root 权限）：
- `/opt/pwmanager/api.env`（root:pwmanager 640）：管理员邮箱、短信提示、
  `PWMGR_SMS_HOOK_TOKEN`、`PWMGR_CONTACT_PEPPER`（一次性设置后勿改，改了会使
  查重列失效）；
- `/opt/pwmanager/mail.env`（root:root 600）：IMAP/SMTP 服务器与**授权码**
  （不是邮箱登录密码；QQ/126/189 需在网页设置开启 IMAP/SMTP 并生成授权码）。

旧版 admin.env 会在重跑 setup 时自动拆分迁移并删除。

**启用/验证**：
```bash
sudo systemctl restart pwmanager pwmanager-mail.timer
curl -sk https://127.0.0.1:8443/contact      # 应返回管理员邮箱
# 用任意邮箱发一封正文 01<测试用户名> 的邮件 → 约 1 分钟内收到确认码邮件
```

**手动兜底**（自动流程不可用时，生成随机临时密码打印一次）：
```bash
sudo -u pwmanager /opt/pwmanager/bin/manage-as-service.sh forgot_reset <用户名> <发件人邮箱或手机号>
# 重新绑定用户的找回联系方式（含 @ 为邮箱，否则为手机号）：
sudo -u pwmanager /opt/pwmanager/bin/manage-as-service.sh set_contact <用户名> <新邮箱或手机号>
```

**注意事项**：
- worker 只处理**未读**且**60 分钟内**的邮件——用户发送后不要打开/移动它；
- /contact 有匿名限流；建议把管理员邮箱配置为**专用别名邮箱**，避免暴露个人邮箱；
- 短信通道无下行能力：短信仅作为提醒管理员的信号（日志/审计可见），临时密码
  需管理员线下告知用户；
- pwdeploy 的 sudoers 已收紧（无 daemon-reload/install），unit 更新由 root 重跑
  本脚本完成。

## 8. 证书指纹

```bash
openssl x509 -in /opt/pwmanager/server/certs/server.crt -noout -fingerprint -sha256
```

把输出（去冒号、小写）填进桌面端/安卓端。迁移时证书是**原样搬运**，指纹不变、客户端零改动。
轮换证书：先发新证书 → 所有客户端更新指纹 → 再切换。

## 9. 客户端设置

- 服务器地址：`https://<服务器地址>:8443`（两端都强制 https，`http://` 会被拒绝）
- 证书 SHA-256 指纹：见上一步
- 公开仓库版本默认地址/指纹为空，首次必须手动填写

## 10. 过渡期与旧路径

- 还没建专用账号时：`_sync_code.py` 仍可工作（自动走旧 pkill/nohup 路径）；
  `python deploy_via_python.py --legacy` 走旧版 `remote_install.sh`（用户目录 + nohup，不推荐）。
- 新链路（`_sync_code.py` 显示"服务形态: systemd"）跑通后，旧路径即弃用。

## 11. 稳定后清理（可选）

新链路稳定运行数天后：

```bash
# 旧目录可删（数据库/证书已复制走；确认 /opt/pwmanager/server/data/pwmanager.db 可用后再删）
rm -rf /home/<你的账号>/AiWork/psd_manager
# 若该账号是当年专为项目开的（非日常管理号），可禁用或删除
sudo usermod -L <旧账号>      # 禁用登录；日常管理号则保留原样
```

## 12. 安全要点

- `server/.env`、`deploy_key(.pub)`、`certs/`、`*.db`、`*.log` 不应进入仓库（均已在 .gitignore）
- 部署私钥 `deploy_key` 权限保持 600；建议设 passphrase 并存进你自己的密码管理器
- SSH 主机指纹未配置时脚本只警告不拦截；确认后写入 `PWMGR_SSH_HOST_FINGERPRINT` 启用强校验
- 同一 IP 连续 5 次认证失败锁 15 分钟；请求体按实际字节限 12 MiB（chunked 也拦）
- 直连 uvicorn 默认不信任 `X-Forwarded-For`；仅在可信反代后设 `PWMGR_TRUST_PROXY=1`

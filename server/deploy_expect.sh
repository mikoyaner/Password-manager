#!/bin/bash
# 使用 SSH_ASKPASS 或 expect 进行自动部署
#
# ⚠️ 旧版脚本，与当前 v2.3 部署方式不符；推荐改用 server/_sync_code.py 与 server/DEPLOY.md。
# <...> 为占位符，使用前自行替换；密码从环境变量 PWD_REMOTE_PASS 读取，不要写进文件。

REMOTE_USER="<SSH 用户名>"
REMOTE_HOST="<服务器地址>"
REMOTE_PASS="${PWD_REMOTE_PASS:?请先设置环境变量 PWD_REMOTE_PASS}"
REMOTE_DIR="/home/<SSH 用户名>/AiWork/psd_manager"

echo "=== 正在部署到 $REMOTE_USER@$REMOTE_HOST:$REMOTE_DIR ==="

# 方法1: 尝试使用 sshpass (如果安装的话)
if command -v sshpass &>/dev/null; then
    echo ">>> 使用 sshpass..."
    SSHPASS_CMD="sshpass -p '$REMOTE_PASS'"
else
    # 方法2: 使用 expect
    if ! command -v expect &>/dev/null; then
        echo "错误: 需要安装 sshpass 或 expect"
        echo "安装方法:"
        echo "  Windows (Git Bash): choco install sshpass 或手动执行 scp"
        echo "  Ubuntu: sudo apt install sshpass"
        exit 1
    fi

    # 使用 expect 脚本
    cat > /tmp/deploy_remote.exp << 'EXPECT_EOF'
#!/usr/bin/expect -f
set timeout 300
set password [lindex $argv 0]
set remote_user [lindex $argv 1]
set remote_host [lindex $argv 2]
set remote_dir [lindex $argv 3]

# 步骤1: 创建远程目录
spawn ssh $remote_user@$remote_host "mkdir -p $remote_dir"
expect {
    "password:" { send "$password\r"; exp_continue }
    eof
}

# 步骤2: 复制文件
spawn scp main.py store.py auth.py $remote_user@$remote_host:$remote_dir/
expect {
    "password:" { send "$password\r"; exp_continue }
    eof
}

# 步骤3: 远程安装
spawn ssh $remote_user@$remote_host "bash -s" < remote_install.sh
expect {
    "password:" { send "$password\r"; exp_continue }
    eof
}

expect eof
EXPECT_EOF

    chmod +x /tmp/deploy_remote.exp
    expect /tmp/deploy_remote.exp "$REMOTE_PASS" "$REMOTE_USER" "$REMOTE_HOST" "$REMOTE_DIR"
    rm -f /tmp/deploy_remote.exp
    exit $?
fi

# 如果使用 sshpass
$SSHPASS_CMD ssh -o StrictHostKeyChecking=no $REMOTE_USER@$REMOTE_HOST "mkdir -p $REMOTE_DIR"
$SSHPASS_CMD scp main.py store.py auth.py $REMOTE_USER@$REMOTE_HOST:$REMOTE_DIR/
$SSHPASS_CMD ssh -o StrictHostKeyChecking=no $REMOTE_USER@$REMOTE_HOST "bash -s" < remote_install.sh

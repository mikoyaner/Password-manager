# 密码管理器

本地端到端加密的跨设备密码管理器。**三端**：

```
window/  电脑端   Python 3 + PyQt6
安卓/    手机端   Java + Android SDK (minSdk 26 / compileSdk 34)
server/  同步服务器  Python + FastAPI + SQLite，uvicorn 内建 HTTPS（你的服务器地址:8443）
```

三端加密格式与同步协议**逐字节兼容**。改任何一处加密/协议，先改权威规范 [`密码库格式与同步协议.md`](密码库格式与同步协议.md)。
深度运维见 [`项目运维手册.md`](项目运维手册.md)（v2.6，已同步更新）。

## 当前模型（v2.6，务必理解再动手）

- **两种密码，别混**：
  - **用户密码（服务密码）**：登录你自己服务器账号用，服务器只存 verifier hash，从不存明文。
  - **密码库密码（主密钥）**：本机加密整个库用，**仅驻内存，永不落盘、永不上云**。
- **本地库按 vid 编号**（`1`、`2`…），与服务器账号解耦；首页三按钮：打开本地库 / 新建本地库 / 登录服务器拉取。
- **云端每账号 ≤5 份历史版本，FIFO 淘汰**；整库覆盖式同步，无记录级合并。
- **改密语义**：改密码库密码只重新加密**本地当前库**，服务器无感；下次「推送」才在云端追加一个新版本。
- **会话免重复解锁（v2.4）**：本进程内解锁过的库，切走再回来免输；**从最近任务划走或进程被杀**才需重输。
- 加密：Argon2id(m=65536,t=3,p=4,v1.3) → AES-256-GCM；`vault.enc` 49 字节头，每次加密新生成 salt(16)+nonce(12)。
- 传输：HTTPS + **证书 SHA-256 指纹固定(pinning)**（自签证书）。

## 本机环境速查

| 用途 | 路径 / 值 |
|---|---|
| JDK 17 | `D:\Android\jdk-17` |
| Gradle 8.7 | `D:\Android\gradle\gradle-8.7\bin\gradle.bat` |
| Gradle 镜像脚本 | `D:\Android\mirror-init.gradle`（`-I` 传入） |
| Android SDK | `D:\Android SDK`（`local.properties` 里 `sdk.dir`） |
| adb | `D:\Android SDK\platform-tools\adb.exe` |
| 桌面/脚本 Python | `python`（含 paramiko） |
| 服务器 | `<服务器地址>:8443`；`.env`（模板 `.env.example`，已被 gitignore）里填主机/账号/私钥/部署目录 |

## 首次配置（必须）

```bash
cd server && cp .env.example .env
# 编辑 .env：
# PWMGR_SSH_HOST=<服务器地址>
# PWMGR_SSH_USER=pwdeploy
# PWMGR_REMOTE_DIR=/opt/pwmanager/server
# PWMGR_SSH_KEY=deploy_key            # 或私钥的绝对路径
# PWMGR_SSH_PASSWORD=<密码>            # 仅过渡期，切换密钥后删除
# PWMGR_SSH_HOST_FINGERPRINT=SHA256:...  # 首次连接打印后填入，启用强校验
# PWMGR_OLD_DIR=<旧部署目录>            # 仅首次迁移需要
```

- `server/.env`、`server/deploy_key` **不要提交**；也可用同名环境变量覆盖。
- 桌面端/安卓端在「设置」里填 `https://<服务器地址>:8443` 和证书 SHA-256 指纹。
- 两端只接受 `https://`；代码默认值为空，首次使用必须手动填写。
- 该私钥/旧密码若曾以明文形式存在过，请先轮换，再发布仓库。

---

## 服务器上的两个账号（v2.6，先看懂再部署）

v2.6 把“能进门的人”和“守着账本的人”拆成了两个账号，像小区物业和保险柜值班员：

| 账号 | 类比 | 能做什么 | 不能做什么 |
|---|---|---|---|
| `pwdeploy` | 物业换灯泡的师傅：有大门钥匙，能进楼换设备、拉电闸 | 用私钥 SSH 登录；上传/替换服务代码与证书；`sudo systemctl restart/status/start/stop pwmanager.service`（白名单）；通过 `manage-as-service.sh` 让值班员执行查/删账号等有限命令 | 不能直接打开账本（`data/` 0700 属 `pwmanager`）；没有通用 sudo，**不能安装/修改 systemd unit**，改不了系统配置 |
| `pwmanager` | 保险柜值班员：不配大门钥匙，只在保险柜房间工作 | 运行 uvicorn；读代码/证书/venv；只写 `/opt/pwmanager/server/data`（数据库） | 不能登录（nologin）；不能改代码/证书/系统；systemd 沙箱（`ProtectSystem=strict`、无 capabilities） |

为什么非要拆成两个人：

- **换代码的人不需要能直接翻账本，看账本的人不需要能进大门。**
- 任意一个被攻破，损失只到一半：值班员被控制，最多破坏数据库（里面只有 verifier 和密文），改不了代码/证书；物业师傅被控制，也只能通过白名单脚本执行有限命令，不能直接读数据库文件、不能安装 unit 来提权。
- unit 的安装只由 root 在初始化时做一次；`sudoers` 里刻意**不包含** `install` / `daemon-reload`——否则师傅能改 unit 的 `ExecStart` 再让 root 启动，等于拿到整栋楼的万能钥匙。
- 以前那个“一把钥匙什么都干”的个人账号已经退役；日常管理账号保留原样，但不再参与本项目的部署和运行。

一句话记住：
- **pwdeploy = 送货 + 拉闸重启**（部署）
- **pwmanager = 待在保险柜房间 + 只碰账本**（运行服务）

---

# 一、常用命令

## 安卓：构建 APK
```bash
cd "E:/密码管理器/安卓"
export JAVA_HOME="D:/Android/jdk-17"
"D:/Android/gradle/gradle-8.7/bin/gradle.bat" --init-script "D:/Android/mirror-init.gradle" assembleDebug
# 产物：安卓/app/build/outputs/apk/debug/app-debug.apk
```

## 安卓：装到 BlueStacks 调试
```bash
ADB="D:/Android SDK/platform-tools/adb.exe"
"$ADB" devices                       # 若 offline："$ADB" reconnect offline
"$ADB" install -r "E:/密码管理器/安卓/app/build/outputs/apk/debug/app-debug.apk"
"$ADB" shell am force-stop com.pwdmgr
"$ADB" shell am start -n com.pwdmgr/.HomeActivity
"$ADB" shell input tap <x> <y>       # 屏幕 1080 宽
"$ADB" shell dumpsys activity activities | grep mResumedActivity
```
截图 / 取 UI（**Git Bash 会改写 `/sdcard` 路径，务必先关路径转换**）：
```bash
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'
"$ADB" exec-out screencap -p > /d/Android/s.png
"$ADB" shell uiautomator dump /sdcard/wd.xml && "$ADB" pull /sdcard/wd.xml /d/Android/wd.xml
```
> `uiautomator dump` 常抢跑抓到旧界面；以 `screencap` 截图为准。

## 服务器：同步代码并重启（保留证书）
```bash
cd "E:/密码管理器/server"
PYTHONIOENCODING=utf-8 python _sync_code.py
# 上传 main.py/store.py → py_compile 自检 → 重启 uvicorn(带 --ssl-*) → 打印证书指纹 + 日志
```

## 服务器：临时挂 APK 下载路由（手机连不上电脑时用）
```bash
cd "E:/密码管理器/server"
PYTHONIOENCODING=utf-8 python _apk_serve.py serve    # 注入带令牌的 /app.apk 路由 + 上传 APK + 重启
#   命令会打印一次性下载链接：https://<服务器地址>:8443/app.apk?t=<TOKEN>
PYTHONIOENCODING=utf-8 python _apk_serve.py revert   # 用完还原 main.py + 删 APK + 重启
```
`serve` 会生成一次性令牌；若远端已有旧版注入路由（令牌未知）会拒绝并提示先 `revert`。

## 服务器：健康检查 / 端点
```bash
curl -sk https://<服务器地址>:8443/health
# 端点：/health /register /vaults /vault/{vid} /vault(PUT) /change_service_pwd /account(DELETE)
# 直连 uvicorn 时不信任 X-Forwarded-For；若以后放到可信反代后面，启动前设 PWMGR_TRUST_PROXY=1
# 请求体按实际接收字节限 12 MiB（含 chunked，超限 413）
```

## 服务器：清除云端账号与密码库
> 删账号会**连带删掉其名下所有云端库**（DB `ON DELETE CASCADE`），**不可恢复**。
> 这只清云端；各设备**本地库不受影响**，要清本地见下「删本地库」。

先看有哪些账号（`manage_remote.py` 自动处理新/旧两种部署形态）：
```bash
cd "E:/密码管理器/server"
python manage_remote.py list_users
```

删某个账号（把 `xjh` 换成目标用户名；服务器端执行，**不需要用户密码**）：
```bash
cd "E:/密码管理器/server"
python manage_remote.py delete_user xjh
```

重置某个账号的用户密码：
```bash
python manage_remote.py reset_password xjh <新用户密码>
```

或在**已登录设备上**走 HTTP 注销（需要该账号的用户密码）：
```bash
curl -k -X DELETE https://<服务器地址>:8443/account -u '用户名:用户密码' -H 'Content-Type: application/json' -d '{"confirm":true}'
```

删本地库（云端删了不会动本地，两边独立）：
```bash
rm -rf "%APPDATA%\PwdMgr\vaults\1"     # 电脑端：删 vid=1 单库；删整个 vaults 目录=清空全部
"D:/Android SDK/platform-tools/adb.exe" uninstall com.pwdmgr   # 安卓端：App 无逐库删除入口，卸载即清私有数据
```

## 桌面端：运行
```bash
# 方式1：双击 window/启动.bat
# 方式2：
python E:\密码管理器\window\app.py
```
本地数据：`%APPDATA%\PwdMgr\vaults\<vid>\{vault.enc,meta.json,sync.log}`，配置 `%APPDATA%\PwdMgr\config.json`。

---

# 二、遇到问题怎么办

## 构建 / 编译
| 现象 | 原因 & 处理 |
|---|---|
| javac 报「找不到符号」但方法在文档里存在 | 本机 android-34 桩 jar 被裁剪：`SaveInfo` 没有 `SAVE_ACTION_*`（改用 `SAVE_DATA_TYPE_PASSWORD`），`Activity` 本来就没有 `onTaskRemoved`（那是 `Service` 的回调，别在 Activity 上写）。用 `javap` 核对真实签名。 |
| 不确定某 API 真实签名 | `javap -cp "D:/Android SDK/platforms/android-34/android.jar" <类名>`（内部类用 `$`，如 `'android.app.assist.AssistStructure$ViewNode'`）。 |
| 构建日志中文乱码 | Gradle 输出是 GBK：`python -c "print(open(r'...log','rb').read().decode('gbk','replace'))"`。 |
| `dl.google.com` 拉依赖卡住 | 用 `-I D:/Android/mirror-init.gradle`（阿里云/腾讯镜像）；必要时 `curl --ssl-no-revoke`。 |
| 路径含中文报错 | `安卓/gradle.properties` 已设 `android.overridePathCheck=true`。 |

## adb / 模拟器
| 现象 | 处理 |
|---|---|
| `adb: failed to stat remote object 'C:/Program Files/Git/sdcard/...'` | Git Bash 路径转换，先 `export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'`。 |
| `uiautomator dump` 抓到旧界面 | 抢跑，改用 `screencap` 截图判断；或 `dumpsys activity` 看 `mResumedActivity`。 |
| 设备 `offline` | `"$ADB" reconnect offline`，仍不行 `"$ADB" kill-server && "$ADB" start-server`。 |
| 点击没反应 | 单次 tap 偶发丢失，重试或 `input swipe x y x y 120`；坐标用 1080 宽的 bounds。 |

## 同步 / 服务器
| 现象 | 原因 & 处理 |
|---|---|
| 登录/推拉 401 | 用户名或**用户密码**错（v2 是账号+用户密码，**不是**旧的同步令牌）。用户名规则 `^[a-zA-Z0-9][a-zA-Z0-9._-]{1,18}[a-zA-Z0-9]$`，拒全数字/`..`。 |
| 「连接被拒 / 证书指纹不匹配」 | 重装证书后 SHA-256 指纹变了，**必须同步更新到桌面端和安卓端设置**。取指纹：`openssl x509 -in certs/server.crt -noout -fingerprint -sha256`。 |
| 8443 完全连不通 | 云安全组没放开 8443（BCE 面板加规则）；或 uvicorn 没起：`ssh` 后 `ps aux | grep uvicorn`，看 `server.log`。 |
| 上传被拒（体积/参数） | 密文上限 8 MiB；解密端严格校验 Argon2 m=65536/t=3/p=4，非规范参数一律拒。 |
| 拉取报「无该份或不属于本账号」 | 属主隔离正常；确认选的是本账号的云端份。 |

## 解锁 / 加密
| 现象 | 处理 |
|---|---|
| 「密码库密码错误或数据损坏」 | GCM 校验失败：密码错、或 `vault.enc` 损坏/被篡改。 |
| 桌面启动 DLL 冲突 | 用 `python`，别混系统/其它 Python。 |
| 切库/返回后仍要重输 | 检查是否进程已被系统杀（内存态丢失属正常）；会话表只在同进程内有效。 |
| 划掉最近任务后仍能免输 | 锁定由 `LockService.onTaskRemoved` 触发（Activity 没有这个回调）。若系统连 Service 一起强杀、且进程缓存存活，属 ROM 行为；重启 App 或进程回收后必锁。 |

## 自动填充（安卓）
- Chrome/Edge/Firefox/Brave 等自带密码管理的浏览器**不会把网页密码框交给第三方 autofill**（系统限制，非 bug）。捕获只对第三方 App 的原生登录页生效，需真机迭代字段识别。
- 需在「设置→密码与自动填充」把本 App 选为自动填充服务（App 内有跳转按钮）。未解锁时只提示先解锁，绝不明文外泄。
- 保存：系统的保存提示（`SAVE_DATA_TYPE_PASSWORD`）确认后**直接入库**，同 URL+用户名+密码自动去重；不再弹二次确认页（避免 Android 10+ 后台起 Activity 被拦）。

## 传输安全
- 两端**只接受 `https://`** 服务器地址；填 `http://` 会在设置保存或首次请求时直接拒绝（Basic 认证会把用户密码带上，不能走明文）。

---

## 安全红线（改代码前默念）
- 密码库密码/派生密钥**永不**落盘、**永不**上传、**永不**写进同步日志。
- 同步日志、CSV 导出禁止记录任何明文密码/主密码/密文内容；CSV 为明文，导出前二次确认。
- 服务器只存密文 blob + 用户密码 verifier hash。
- 每次重装自签证书，指纹要同步到两端。
# Password-manager
# mikoyaner-Password-manager
# Password-manager

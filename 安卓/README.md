# 密码管理器 · 手机端 (安卓 / Java)

本地端到端加密的密码管理器安卓端。数据用主密码在本机加密后存 App 私有目录，
可经你的乌班图服务器与电脑端同步（服务器只存密文）。

**与电脑端 (`window/`) 加密格式逐字节兼容**，同一主密码即可跨设备互解、合并、同步。

## 构建

用 **Android Studio**（Giraffe 或更新）打开本目录 `安卓/`，或命令行：

```bash
cd 安卓
./gradlew assembleDebug      # 生成 app/build/outputs/apk/debug/app-debug.apk
./gradlew assembleRelease    # 需配置签名，见下
```

> 环境要求：JDK 17、Android SDK 34、Gradle 8.x（Android Studio 自带）。
> `minSdk 26`（Android 8.0）—— 因为用到 `java.util.Base64` 和 `java.nio.file`。

### 依赖

- `androidx.appcompat` —— UI 基础
- `org.bouncycastle:bcprov-jdk18on` —— Argon2id（标准 JCE 不含 Argon2）

## 已验证的兼容性（本机 javac + Bouncy Castle 对拍）

`javatest/` 下是**仅用于本地验证、不打进 APK** 的测试类，已跑通：

- `CrossTest` —— Java 解密 Python(电脑端) 加密的库、Java 加密后 Python 能解，
  中文/密码/API Key 全部正确；错误密码拒绝、篡改检测一致。
- `MergeTest` —— `Vault.merge` 与 Python 版逻辑一致（新旧胜出、删除墓碑传播、相等时远程胜）。
- `SyncTest` —— 对着真实 FastAPI 服务器跑双设备并发同步、乐观锁重拉合并。
- **跨平台全链路** —— 电脑(Python)上传 → 手机(Java)下拉解密读取 → 手机新增上传 → 电脑下拉读取，全部字段正确。

复跑方式（需 JDK 15+ 与 `bcprov`/`json` 两个 jar）：

```bash
javac -encoding UTF-8 -cp "libs/bcprov.jar:libs/json.jar" -d out \
  app/src/main/java/com/pwdmgr/{Crypto,Vault,SyncClient,PasswordGen}.java \
  javatest/*.java
# 起服务器后：
java -cp "out:libs/bcprov.jar:libs/json.jar" com.pwdmgr.SyncTest https://<服务器地址>:8443 <证书指纹>
```

## 功能

- 主密码解锁 / 首次创建（主密码仅内存中派生密钥，绝不落盘/上传）
- 两类记录：网站登录、API Key
- 搜索、新增、编辑、删除（软删除墓碑，跨设备传播）
- 内置密码生成器（SecureRandom）；复制后定时清空剪贴板
- 闲置自动锁定（默认 5 分钟）
- CSV 导出（明文，导出前二次确认，导出到 App 外部私有目录）
- 服务器同步（乐观锁 + 客户端明文合并 + 自签证书指纹固定）

## 数据位置

- 库文件：App 私有内部存储 `filesDir/vault.enc`
- 配置：`SharedPreferences (pwdmgr_config)`，不含主密码/密钥
- 已在 `data_extraction_rules.xml` 中禁止系统/云备份导出密文库

## 首次配置同步

主界面右上菜单「服务器与同步设置」填写：
- 服务器地址：`https://<服务器地址>:8443`（只接受 https）
- 证书指纹：服务器自签证书的 SHA-256，见 `../server/DEPLOY.md`
- 账号：首次先在「同步 → 注册账号」建服务器账号，之后用「用户名 + 用户密码」登录（没有同步令牌）
- 点「测试连接」验证连通性

## 模块

| 文件 | 职责 |
|---|---|
| `Crypto.java` | Argon2id + AES-256-GCM，`vault.enc` 读写（规范第 2/3 节） |
| `Vault.java` | 记录模型 + CRUD + 合并（规范第 4/5 节） |
| `SyncClient.java` | 同步客户端 + 乐观锁重试 + 证书 pinning（规范第 6 节） |
| `Storage.java` | 本地库/配置读写 + CSV 导出（规范第 7/8 节） |
| `VaultHolder.java` | 内存态：已解锁的库/主密码 + 自动锁判定 |
| `PasswordGen.java` | 密码生成器 |
| `*Activity.java` | 解锁 / 主界面 / 记录编辑 / 设置 |

## Release 签名

`android/` 下生成 keystore 后，在 `app/build.gradle` 配 `signingConfigs`，
或用 Android Studio 的 Build → Generate Signed Bundle/APK。切勿把 keystore 提交进仓库。

# 安卓端 v2.3 实现方案（从现有 v1 工程改造）

> 权威协议见根目录《密码库格式与同步协议.md》(v2.3)。本文只讲**安卓 Java 端如何对齐**，
> 逐模块给出改动点与代码骨架。目标：与已部署的 FastAPI 服务器、已上线的电脑端 **三端逐字节兼容**。

---

## 0. 现状差距（v1 工程 → v2.3）

现有 `安卓/` 是 **v1**：单一 `sync_token` + `Bearer` 认证 + `revision` 乐观锁 + 客户端明文合并 +
单个 `filesDir/vault.enc` + `FORMAT_VER=1` + 闲置自动锁。这些在 v2.x 全部作废。

| 维度 | v1（现状） | v2.3（要改成） |
|---|---|---|
| 认证 | `Authorization: Bearer <token>`，`/setup` | **HTTP Basic**（`username` + 用户密码），无 `/setup` |
| 密码 | 单一「主密码」 | **两把**：用户密码(登录服务器) + 密码库密码(本地加密，永不上传) |
| 库文件 | 单个 `vault.enc` | 多个本地库 `filesDir/vaults/<vid>/{vault.enc,meta.json,sync.log}` |
| 库/账号关系 | 绑定 | **解耦**：任何账号可对当前库推拉，仅 `last_account` 预填 |
| 云端库 | 每用户一行，revision 递增 | **每用户 ≤5 份历史**，每次 PUT 新增一行，FIFO 淘汰 |
| 端点 | `GET/PUT /vault`(带 base_revision) | `GET /vaults`(列表) / `GET /vault/{vid}`(下载) / `PUT /vault`(新增) / `POST /register` / `POST /change_service_pwd` / `DELETE /account` |
| 冲突 | 客户端 merge + 乐观锁重试 | **无合并**：整库覆盖式；拉取时从 ≤5 份挑一份 |
| 文件格式 | `PWMGR1` fmt_ver=1 | `PWMGR1` **fmt_ver=2** + 严格 m/t/p 校验 |
| 顶层 JSON | `{revision, records}` | `{username, pwd_time, modified_at, label, records}` |
| 自动锁 | 闲置 5 分钟锁 | **移除**锁定概念 |

**依赖不变**：`bcprov-jdk18on`(Argon2id)、`appcompat`、`org.json`(Android 自带)。
新增建议：`androidx.security:security-crypto:1.1.0-alpha06`（`EncryptedSharedPreferences` 存服务密码，替代桌面 keyring）。

---

## 1. 模块改造总览

```
Crypto.java     → fmt_ver=2 + 严格参数校验 + encryptToFile 原子写（小改）
Vault.java      → 顶层字段换掉；删 revision/merge；加 pwd_time/label/modified_at/username（中改）
SyncClient.java → 全重写：Basic 认证 + 多版本端点，删 token/revision/merge/sync()（大改）
Storage.java    → 全重写：vid 多库目录 + meta.json + 配置项 + 服务密码加密存储（大改）
VaultHolder.java→ 去自动锁；加 currentVid（小改）
MainActivity    → 去自动锁/去 revision 显示；同步改推拉对话框（中改）
UnlockActivity  → 改「只输密码库密码」；新建/解锁（中改）
SettingsActivity→ 去 token；服务器地址/指纹/改用户密码/销号（中改）
新增 HomeActivity（首页三按钮 + 本地库列表）
新增 布局：activity_home.xml、dialog_sync.xml、dialog_server_vault_picker.xml 等
```

---

## 2. Crypto.java（对齐 §2/§3）

改动：
- `FORMAT_VER = 2`（MAGIC 仍是 `PWMGR1`，与电脑端一致）。
- 解密时**严格校验** `(m,t,p)==(65536,3,4)`，非规范参数一律 `UnlockException`（防 DoS）。
- 加 `encryptToFile(File, byte[] plain, String password)`：临时文件 + `getFD().sync()` + rename，
  与 Storage 现有 `saveVault` 的原子写合并。

```java
public static final int FORMAT_VER = 2;   // 改这里

// decryptVault 内，读到 m/t/p 后加：
if (m != ARGON_M || t != ARGON_T || p != ARGON_P)
    throw new UnlockException("加密参数不符合规范");
```

> 其余（header 49B 小端布局、Argon2id v1.3、AES-256-GCM）与 v1 完全相同，跨端已对拍过，不动。

---

## 3. Vault.java（对齐 §4）

顶层字段替换，删除 `revision` 与 `merge()`。

```java
public String username = "";      // 库内展示字段，非云端属主
public long pwdTime = 0;          // 密码库密码设定时刻(ms)，建库/改密时更新
public long modifiedAt = 0;       // 内容最后修改时刻(ms)，touch() 更新
public String label = null;       // 展示标签 ≤30

public byte[] toJson() throws JSONException {
    JSONObject root = new JSONObject();
    root.put("username", username);
    root.put("pwd_time", pwdTime);
    root.put("modified_at", modifiedAt);
    root.put("label", label == null ? JSONObject.NULL : label);
    root.put("records", records);
    return root.toString().getBytes(StandardCharsets.UTF_8);
}

public static Vault fromJson(byte[] data) throws JSONException {
    JSONObject root = new JSONObject(new String(data, StandardCharsets.UTF_8));
    Vault v = new Vault();
    v.username   = root.optString("username", "");
    v.pwdTime    = root.optLong("pwd_time", 0);
    v.modifiedAt = root.optLong("modified_at", 0);
    v.label      = root.isNull("label") ? null : root.optString("label", null);
    JSONObject recs = root.optJSONObject("records");
    if (recs != null) {
        Iterator<String> it = recs.keys();
        while (it.hasNext()) { String k = it.next(); v.records.put(k, recs.getJSONObject(k)); }
    }
    return v;
}

public void touch() { this.modifiedAt = nowTs(); }   // add/update/delete 内调用
```

- `add/update/delete`：末尾调 `touch()`（v1 里 delete 只置 updated_at，现在统一 touch）。
- **删除** `revision` 字段、`merge()`、`Vault(int revision)` 构造。记录级字段不变。

---

## 4. SyncClient.java（对齐 §7，全重写）

去掉 `token`/`setup`/`getVault()`/`putVault(baseRevision)`/`sync()`/`ConflictException`。
认证改 Basic；新增多版本端点。**证书 pinning 逻辑（configureTls/verifyFingerprint）原样保留。**

```java
public class SyncClient {
    public static class SyncException extends Exception { public SyncException(String m){super(m);} }
    public static class AuthException extends SyncException { public AuthException(String m){super(m);} }
    public static class PinException extends SyncException { public PinException(String m){super(m);} }
    public static class UsernameTakenException extends SyncException { public UsernameTakenException(String m){super(m);} }
    public static class NotFoundException extends SyncException { public NotFoundException(String m){super(m);} }

    private final String base, username, servicePwd, certFingerprint;

    public SyncClient(String serverUrl, String username, String servicePwd, String certFp) {
        this.base = serverUrl.replaceAll("/+$","");
        this.username = username; this.servicePwd = servicePwd; this.certFingerprint = certFp;
    }

    private String basicHeader() {
        String raw = username + ":" + servicePwd;
        return "Basic " + Base64.getEncoder().encodeToString(raw.getBytes(StandardCharsets.UTF_8));
    }

    // request(path, method, jsonBody, boolean auth)：auth=true 时加 Authorization: Basic
    // 其余（先 connect 再 verifyFingerprint 再发 body、状态码→异常映射）沿用 v1。
    // 状态映射：401→AuthException；404→NotFoundException；409(register)→UsernameTakenException；其余非2xx→SyncException。

    public JSONObject health() throws SyncException { /* GET /health 无认证 */ }

    /** POST /register：仅注册则 ciphertext 传 null（云端零份库）。返回 {created_at, first_vid}。 */
    public JSONObject register(String servicePwd, String email, String phone,
                               Long pwdTime, String label, byte[] ciphertext) throws SyncException {
        JSONObject body = new JSONObject();
        body.put("username", username); body.put("service_pwd", servicePwd);
        body.put("email", email); body.put("phone", phone);
        if (ciphertext != null) {
            body.put("pwd_time", pwdTime); body.put("label", label==null?JSONObject.NULL:label);
            body.put("ciphertext", Base64.getEncoder().encodeToString(ciphertext));
        }
        /* POST /register (无认证) */
    }

    /** GET /vaults → 数组，每项 {vid,pwd_time,label,ciphertext_sha256,upload_time}（新→旧，≤5）。 */
    public JSONArray listVaults() throws SyncException { /* GET /vaults，auth=true，取 body.optJSONArray("vaults") */ }

    /** GET /vault/{vid} → {vid,pwd_time,label,upload_time,ciphertext(b64),ciphertext_sha256}。 */
    public JSONObject getVault(int vid) throws SyncException { /* GET /vault/"+vid，auth=true */ }

    /** PUT /vault：每次新增一份。返回 {vid, upload_time, ciphertext_sha256, kept}。 */
    public JSONObject putVault(long pwdTime, String label, byte[] ciphertext) throws SyncException {
        JSONObject body = new JSONObject();
        body.put("pwd_time", pwdTime);
        body.put("label", label==null?JSONObject.NULL:label);
        body.put("ciphertext", Base64.getEncoder().encodeToString(ciphertext));
        /* PUT /vault，auth=true */
    }

    public JSONObject changeServicePwd(String oldPwd, String newPwd) throws SyncException { /* POST /change_service_pwd */ }
    public JSONObject deleteAccount() throws SyncException { /* DELETE /account body {"confirm":true} */ }
}
```

要点：
- **不做任何合并/重试**：推送就是 `putVault(当前库密文)`；拉取就是 `getVault(挑中的 vid)`。
- `ciphertext` 字段是**完整 vault.enc 字节**（含 49B 头），base64 后放进 JSON；下载时 base64 解码回字节直接落盘。
- 下载响应**不含属主**（服务器已剥离），客户端也不把 `upload_time` 落地到库内。

---

## 5. Storage.java（对齐 §6/§9.2，全重写）

改成 vid 多库目录模型，镜像电脑端 `window/storage.py`。

```java
// 目录：filesDir/vaults/<vid>/{vault.enc, meta.json, sync.log}
private File vaultsRoot() { File d = new File(ctx.getFilesDir(), "vaults"); d.mkdirs(); return d; }
private File vidDir(String vid) { File d = new File(vaultsRoot(), vid); d.mkdirs(); return d; }
private File vaultFile(String vid) { return new File(vidDir(vid), "vault.enc"); }
private File metaFile(String vid)  { return new File(vidDir(vid), "meta.json"); }

public String nextVid() { /* 扫 vaults/ 下纯数字目录取 max+1，无则 "1" */ }
public List<JSONObject> listVaults() { /* 数字目录升序，各 loadMeta 并塞入 vid */ }
public boolean vaultExists(String vid) { return vaultFile(vid).exists(); }
public void deleteVault(String vid) { /* 递归删 vidDir(vid,false) */ }

public JSONObject loadMeta(String vid)  { /* 读 meta.json，缺/坏返回空 */ }
public void saveMeta(String vid, JSONObject meta) { /* 写 meta.json */ }

public JSONObject createVault(String password) { /* 新 vid + 空 Vault(pwdTime=modifiedAt=now, label="初始 yyyy-MM-dd") + 加密落盘 + meta(never_uploaded=true) */ }
public Vault loadVault(String vid, String password) { /* 读 vault.enc → Crypto.decryptVault → Vault.fromJson */ }
public void saveVault(String vid, Vault v, String password, Boolean neverUploaded) { /* 加密原子写 + 更新 meta */ }
```

meta.json 字段（与桌面一致）：`vid, pwd_time, modified_at, label, never_uploaded, last_account, record_count, created_at`。

**配置（SharedPreferences `pwdmgr_config`）**：
- 去：`sync_token`、`auto_lock_seconds`。
- 留/加：`server_url`(默认空，首次在设置里填 `https://<服务器地址>:8443`)、`cert_fingerprint`(默认空，填服务器证书 SHA-256)、
  `clipboard_clear_seconds`、`last_vid`、`remember_service_pwd`。

**服务密码存储**（替代桌面 keyring）：用 `EncryptedSharedPreferences`（`masterKey` 走 AndroidKeyStore）
存 `username → service_pwd`。`remember_service_pwd=false` 时不写、每次同步询问。

```java
// 新增 SecretStore.java
EncryptedSharedPreferences 文件名 "pwdmgr_secrets"
saveServicePwd(String user, String pwd) / loadServicePwd(String user) / deleteServicePwd(String user)
```

> 密码库密码（主密钥）**任何情况下都不落盘**，只在 `VaultHolder` 内存里。

---

## 6. VaultHolder.java

- 删 `autoLockSeconds` / `shouldAutoLock()` / 闲置判定（锁定概念移除）。
- 加 `String currentVid`；`unlock(vid, vault, password)`；`lock()` 清 vid/vault/password。

---

## 7. Activity 与 UI 流程

### 7.1 新增 HomeActivity（首页三按钮，镜像桌面首页）
- 按钮①「打开本地库」→ 列 `storage.listVaults()` 选一个 → `UnlockActivity(vid)` 只输**密码库密码** → MainActivity。
- 按钮②「新建本地库」→ 输密码库密码×2 → `storage.createVault(pwd)` → 直接进 MainActivity。
- 按钮③「登录服务器拉取」→ 弹「账号+用户密码」→ `listVaults()` → 云端选库对话框挑一份 →
  `getVault(vid)` → 弹「密码库密码」解密 → **落地为新 vid** → 进 MainActivity。
- 列表下方展示各本地库：`库 #vid · label · @last_account · N 条`。

### 7.2 UnlockActivity
- 只输入**密码库密码**（不再叫主密码；文案统一）。仅解锁已有 vid；新建走 HomeActivity 的按钮②。

### 7.3 MainActivity
- 去自动锁、去 `revision` 显示（状态行改「已解锁 · N 条 · label=…」）。
- 「同步」按钮 → 弹 `dialog_sync`（同步对话框，镜像桌面 SyncDialog）：
  1. 登录页：账号(预填 `last_account`) + 用户密码 + [记住]；按钮「登录」「注册」。
  2. 登录 = `listVaults()` 验证凭据并显示「云端有 K 份历史库」。
  3. 动作页：「推送到服务器（云端新增一份）」/「从服务器拉取（挑一份覆盖本地）」。
     - 推送：`putVault(vault.pwdTime, vault.label, 当前密文)` → 更新 modified_at=upload_time、never_uploaded=false → 状态「云端新增第 vid 份（保留 kept/5）」。
     - 拉取：`listVaults()` → `dialog_server_vault_picker`（列 ≤5 份：`上传时间 · label · 云端#vid`，默认最新）→ `getVault(vid)` → 用当前密码库密码解密(失败询问) → **覆盖当前 vid** 内容；若 `never_uploaded` 先二次确认。
  4. 注册页：账号/用户密码/确认/手机/邮箱 → `register(...)`（不带密文，云端零份库）。
- 记录 CRUD / 搜索 / 复制清剪贴板 / CSV 导出：沿用 v1，仅 `vault()` 取当前 vid 的库、`persist()` 调 `saveVault(currentVid, ...)`。

### 7.4 SettingsActivity
- 去 `sync_token` 输入。
- 保留：服务器地址、证书指纹、「测试连接」(调 `health()`)。
- 新增：「改用户密码」(需当前账号+旧/新用户密码 → `changeServicePwd`)、「注销账号」(`deleteAccount`，二次警告)。

### 7.5 布局资源
- 新增 `activity_home.xml`（三按钮 + ListView 本地库）。
- 新增 `dialog_sync.xml`（用 `ViewSwitcher` 或 `Fragment` 做 登录/注册/动作 三页）。
- 新增 `dialog_server_vault_picker.xml`（ListView 云端历史库）。
- `AndroidManifest.xml`：`HomeActivity` 设为 LAUNCHER（替换 UnlockActivity 当前入口）。

---

## 8. 安全约束（必须逐条满足，与桌面/协议一致）

- 密码库密码**永不上传**、不落盘；主密钥仅内存。
- 用户密码只进 `EncryptedSharedPreferences`（勾选「记住」时），且只用于 Basic 认证。
- HTTPS + 证书 SHA-256 pinning：**发任何数据前**先握手验指纹（v1 已实现，保留）。
- `sync.log` 禁止记录明文密码/主密钥/密文内容；只记 vid、动作、云端 vid/kept、sha 前缀。
- CSV 导出明文前二次确认警告。
- 用户名规则 `^[a-zA-Z0-9][a-zA-Z0-9._-]{1,18}[a-zA-Z0-9]$` 且非全数字（客户端预校验，服务器权威）。
- 密文 ≤ 8 MiB（客户端可选预检，服务器 413 兜底）。

---

## 9. 测试与验收

1. **对拍（javatest，本机 javac+bcprov，不打进 APK）**：
   - `CrossTest`：改喂 v2 fmt_ver=2 的库；Java 解 Python 加密的库、Java 加密 Python 能解（含中文/特殊字符）。
   - `SyncTest`：对真实服务器跑 v2.3 全链路——注册(零库) → 推送多份(验证 ≤5 FIFO) → `listVaults` → 选一份下载解密 → 属主隔离(换账号取不到)。
2. **构建**：`cd 安卓 && ./gradlew assembleDebug`（JDK17 / SDK34 / Gradle8.7；镜像与路径见记忆）。
3. **走查**：BlueStacks/真机（模拟器可能受 hypervisor 限制，优先真机）。与电脑端互推互拉验证跨端兼容。
4. **端到端**：手机推送 → 电脑登录拉到同一份；电脑改密推送 → 手机列出多份挑一份拉取解密。

---

## 10. 建议实施顺序（对应任务 #28–#32）

1. #28 Crypto + Vault（格式打底，先过 CrossTest）。
2. #29 SyncClient（Basic + 多版本端点，先过 SyncTest 无 UI）。
3. #30 Storage（vid 多库 + 配置 + SecretStore）。
4. #31 Activity/UI（HomeActivity + 同步对话框 + 选库对话框 + Settings）。
5. #32 构建 + 真机走查 + 跨端互解验收。

> 每步完成后跑对应测试再进下一步。UI 层最后做，因为逻辑层可先无头/命令行验证。

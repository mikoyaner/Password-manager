package com.pwdmgr;

import android.content.Context;
import android.content.SharedPreferences;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.Locale;

/**
 * 本地存储层 v2.3（库与账号解耦，多版本云端）。镜像电脑端 window/storage.py。
 *
 * 目录：filesDir/vaults/<vid>/{vault.enc, meta.json, sync.log}
 *   - vid = 自增数字字符串 "1""2"…（本地库不命名，按编号）
 * 配置：SharedPreferences(pwdmgr_config)，不含任何密码/密钥。
 * 服务密码：走 SecretStore（EncryptedSharedPreferences），不落普通偏好、绝不上云明文。
 * 密码库密码（主密钥）：仅内存（VaultHolder），永不落盘。
 */
public class Storage {

    private static final String VAULT_FILE = "vault.enc";
    private static final String META_FILE = "meta.json";
    private static final String LOG_FILE = "sync.log";
    private static final String PREFS = "pwdmgr_config";

    private final Context ctx;

    public Storage(Context ctx) { this.ctx = ctx.getApplicationContext(); }

    // ---- 路径 ----
    private File vaultsRoot() {
        File d = new File(ctx.getFilesDir(), "vaults");
        if (!d.exists()) d.mkdirs();
        return d;
    }

    private File vidDir(String vid, boolean create) {
        File d = new File(vaultsRoot(), vid);
        if (create && !d.exists()) d.mkdirs();
        return d;
    }

    private File vaultFile(String vid, boolean create) {
        return new File(vidDir(vid, create), VAULT_FILE);
    }

    public File vaultFile(String vid) { return vaultFile(vid, true); }
    private File metaFile(String vid) { return new File(vidDir(vid, true), META_FILE); }
    private File logFile(String vid) { return new File(vidDir(vid, true), LOG_FILE); }

    // ---- 库列表 ----

    public boolean anyVaultExists() {
        String[] names = vaultsRoot().list();
        if (names == null) return false;
        for (String n : names) {
            if (n.matches("\\d+") && new File(vaultsRoot(), n + "/" + VAULT_FILE).exists()) return true;
        }
        return false;
    }

    /** 扫纯数字目录取 max+1；无则 "1"。 */
    public String nextVid() {
        int max = 0;
        String[] names = vaultsRoot().list();
        if (names != null) {
            for (String n : names) {
                if (n.matches("\\d+") && new File(vaultsRoot(), n).isDirectory()) {
                    max = Math.max(max, Integer.parseInt(n));
                }
            }
        }
        return String.valueOf(max + 1);
    }

    /** 各库 meta（含 vid），按编号数值升序。 */
    public ArrayList<JSONObject> listVaults() {
        ArrayList<String> vids = new ArrayList<>();
        String[] names = vaultsRoot().list();
        if (names != null) {
            for (String n : names) {
                if (n.matches("\\d+") && new File(vaultsRoot(), n).isDirectory()
                        && new File(vaultsRoot(), n + "/" + VAULT_FILE).exists()) {
                    vids.add(n);
                }
            }
        }
        vids.sort((a, b) -> Integer.compare(Integer.parseInt(a), Integer.parseInt(b)));
        ArrayList<JSONObject> out = new ArrayList<>();
        for (String vid : vids) {
            JSONObject m = loadMeta(vid);
            try { m.put("vid", vid); } catch (JSONException ignore) {}
            out.add(m);
        }
        return out;
    }

    public boolean vaultExists(String vid) { return vaultFile(vid, false).exists(); }

    /** 永久删除本地库目录（不影响云端）。 */
    public void deleteVault(String vid) {
        deleteRecursive(vidDir(vid, false));
    }

    private static void deleteRecursive(File f) {
        if (f == null || !f.exists()) return;
        if (f.isDirectory()) {
            File[] kids = f.listFiles();
            if (kids != null) for (File k : kids) deleteRecursive(k);
        }
        //noinspection ResultOfMethodCallIgnored
        f.delete();
    }

    // ---- meta.json ----

    public JSONObject loadMeta(String vid) {
        File f = metaFile(vid);
        if (!f.exists()) return new JSONObject();
        try {
            byte[] b = Files.readAllBytes(f.toPath());
            return new JSONObject(new String(b, StandardCharsets.UTF_8));
        } catch (Exception e) {
            return new JSONObject();
        }
    }

    public void saveMeta(String vid, JSONObject meta) {
        try {
            writeAtomic(metaFile(vid), meta.toString(2).getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new RuntimeException("写 meta 失败: " + e.getMessage());
        }
    }

    // ---- 密码库读写 ----

    /** 新建本地库的返回值：vid + 内存库 + 会话 key/salt。 */
    public static class NewVault {
        public final String vid;
        public final Vault vault;
        public final byte[] key;
        public final byte[] salt;

        NewVault(String vid, Vault vault, byte[] key, byte[] salt) {
            this.vid = vid;
            this.vault = vault;
            this.key = key;
            this.salt = salt;
        }
    }

    /** 新建空本地库，分配 vid。 */
    public NewVault createVault(String password, String lastAccount) throws Exception {
        String vid = nextVid();
        long now = System.currentTimeMillis();
        String label = "初始 " + new SimpleDateFormat("yyyy-MM-dd", Locale.US).format(new Date(now));
        Vault v = new Vault();
        v.username = "";
        v.pwdTime = now;
        v.modifiedAt = now;
        v.label = label;
        byte[] salt = Crypto.newSalt();
        byte[] key = Crypto.deriveKey(password, salt,
                Crypto.ARGON_M, Crypto.ARGON_T, Crypto.ARGON_P);
        writeAtomic(vaultFile(vid), Crypto.encryptVault(v.toJson(), key, salt));
        JSONObject meta = new JSONObject();
        meta.put("vid", vid);
        meta.put("pwd_time", now);
        meta.put("modified_at", now);
        meta.put("label", label);
        meta.put("never_uploaded", true);
        meta.put("last_account", lastAccount == null ? "" : lastAccount);
        meta.put("record_count", 0);
        meta.put("created_at", now);
        saveMeta(vid, meta);
        return new NewVault(vid, v, key, salt);
    }

    /** 解锁结果：库 + 会话 key/salt（后续保存复用，避免每次重跑 Argon2）。 */
    public static class OpenedVault {
        public final Vault vault;
        public final byte[] key;
        public final byte[] salt;

        OpenedVault(Vault vault, byte[] key, byte[] salt) {
            this.vault = vault;
            this.key = key;
            this.salt = salt;
        }
    }

    public OpenedVault loadVaultEx(String vid, String password) throws Exception {
        File f = vaultFile(vid, false);
        if (!f.exists()) {
            // 文件缺失：给出一组可用的 key/salt，首次保存时据此创建文件
            byte[] salt = Crypto.newSalt();
            byte[] key = Crypto.deriveKey(password, salt,
                    Crypto.ARGON_M, Crypto.ARGON_T, Crypto.ARGON_P);
            return new OpenedVault(new Vault(), key, salt);
        }
        byte[] blob = Files.readAllBytes(f.toPath());
        Crypto.Opened o = Crypto.openVault(blob, password);
        return new OpenedVault(Vault.fromJson(o.plaintext), o.key, o.salt);
    }

    public Vault loadVault(String vid, String password)
            throws IOException, Crypto.UnlockException, JSONException {
        File f = vaultFile(vid, false);
        if (!f.exists()) return new Vault();
        byte[] blob = Files.readAllBytes(f.toPath());
        return Vault.fromJson(Crypto.decryptVault(blob, password));
    }

    /** 保存：复用会话 key/salt。任何本地改动默认标记"未同步"，直到推送成功。 */
    public void saveVault(String vid, Vault v, byte[] key, byte[] salt,
                          Boolean neverUploaded) throws Exception {
        writeAtomic(vaultFile(vid), Crypto.encryptVault(v.toJson(), key, salt));
        JSONObject meta = loadMeta(vid);
        meta.put("vid", vid);
        meta.put("pwd_time", v.pwdTime);
        meta.put("modified_at", v.modifiedAt);
        meta.put("label", v.label == null ? JSONObject.NULL : v.label);
        meta.put("record_count", v.activeRecords().size());
        meta.put("never_uploaded", neverUploaded == null ? true : neverUploaded);
        if (!meta.has("created_at")) meta.put("created_at", System.currentTimeMillis());
        saveMeta(vid, meta);
    }

    /**
     * 审计报告 A4/A5：保存一份**已在 UI 线程序列化并加密**的库快照。
     * 后台线程只写文件与 meta，不触碰共享 Vault 对象（零并发序列化风险）。
     * pwdTime/modifiedAt/label/recordCount 由调用方在 UI 线程捕获后传入。
     */
    public void saveVaultSnapshot(String vid, byte[] encryptedBlob, long pwdTime,
                                  long modifiedAt, String label, int recordCount,
                                  boolean neverUploaded) throws Exception {
        writeAtomic(vaultFile(vid), encryptedBlob);
        JSONObject meta = loadMeta(vid);
        meta.put("vid", vid);
        meta.put("pwd_time", pwdTime);
        meta.put("modified_at", modifiedAt);
        meta.put("label", label == null ? JSONObject.NULL : label);
        meta.put("record_count", recordCount);
        meta.put("never_uploaded", neverUploaded);
        if (!meta.has("created_at")) meta.put("created_at", System.currentTimeMillis());
        writeAtomic(metaFile(vid), meta.toString(2).getBytes(StandardCharsets.UTF_8));
    }

    /** 读某库当前落盘的完整 vault.enc 字节（含 49B 头），用于推送。 */
    public byte[] readVaultBytes(String vid) throws IOException {
        return Files.readAllBytes(vaultFile(vid, false).toPath());
    }

    /** 拉取覆盖：把云端某份密文直接写入当前 vid 目录并刷新 meta（不改 vid）。 */
    public void overwriteFromBytes(String vid, byte[] vaultEncBytes, Vault parsed,
                                   String lastAccount) throws Exception {
        long now = System.currentTimeMillis();
        writeAtomic(vaultFile(vid), vaultEncBytes);
        JSONObject meta = loadMeta(vid);
        meta.put("vid", vid);
        meta.put("pwd_time", parsed.pwdTime);
        meta.put("modified_at", now);
        meta.put("label", parsed.label == null ? JSONObject.NULL : parsed.label);
        meta.put("record_count", parsed.activeRecords().size());
        // 内容现在与云端某一份一致，不再算"未上传"
        meta.put("never_uploaded", false);
        if (lastAccount != null) meta.put("last_account", lastAccount);
        if (!meta.has("created_at")) meta.put("created_at", now);
        saveMeta(vid, meta);
    }

    /** 把已解密出的云端库落地为全新本地 vid（去除属主/上传时间，不覆盖既有库）。 */
    public String landNewVaultFromBytes(byte[] vaultEncBytes, Vault parsed, String lastAccount) throws Exception {
        String vid = nextVid();
        long now = System.currentTimeMillis();
        writeAtomic(vaultFile(vid), vaultEncBytes);
        JSONObject meta = new JSONObject();
        meta.put("vid", vid);
        meta.put("pwd_time", parsed.pwdTime);
        meta.put("modified_at", now);
        meta.put("label", parsed.label == null ? JSONObject.NULL : parsed.label);
        meta.put("never_uploaded", false);
        meta.put("last_account", lastAccount == null ? "" : lastAccount);
        meta.put("record_count", parsed.activeRecords().size());
        meta.put("created_at", now);
        saveMeta(vid, meta);
        return vid;
    }

    /** 原子写：临时文件 + sync + rename。 */
    /** 审计报告 B3：全进程共享一把 IO 锁，串行化 vault.enc/meta 的原子写。 */
    private static final Object VAULT_IO_LOCK = new Object();

    private static void writeAtomic(File target, byte[] data) throws IOException {
        File parent = target.getParentFile();
        if (parent != null && !parent.exists()) parent.mkdirs();
        // 审计报告 B3：tmp 名唯一（线程 id + 纳秒），并发保存不再互相踩踏
        File tmp = new File(target.getParentFile(),
                target.getName() + ".tmp." + Thread.currentThread().getId()
                        + "-" + System.nanoTime());
        synchronized (VAULT_IO_LOCK) {
            try (FileOutputStream fos = new FileOutputStream(tmp)) {
                fos.write(data);
                fos.getFD().sync();
            }
            if (!tmp.renameTo(target)) {
                // 同卷 rename 失败（极罕见）：退化为直接写目标（仍在锁内，串行安全）
                try (FileOutputStream fos = new FileOutputStream(target)) {
                    fos.write(data);
                    fos.getFD().sync();
                }
                //noinspection ResultOfMethodCallIgnored
                tmp.delete();
            }
        }
    }

    // ---- 同步日志（禁止记录明文密码/主密钥/密文内容）----
    public void logSync(String vid, String line) {
        synchronized (VAULT_IO_LOCK) {
            try {
                File f = logFile(vid);
                String stamp = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(new Date());
                String entry = stamp + "  " + line + "\n";
                try (FileOutputStream fos = new FileOutputStream(f, true)) {
                    fos.write(entry.getBytes(StandardCharsets.UTF_8));
                }
            } catch (Exception ignore) {}
        }
    }

    // ---- 配置（SharedPreferences，不含密码/密钥）----
    private SharedPreferences prefs() { return ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE); }

    public String getServerUrl() { return prefs().getString("server_url", ""); }
    public String getCertFingerprint() { return prefs().getString("cert_fingerprint", ""); }
    public int getClipboardClearSeconds() { return prefs().getInt("clipboard_clear_seconds", 30); }
    public String getLastVid() { return prefs().getString("last_vid", ""); }
    public String getLastAccount() { return prefs().getString("last_account", ""); }
    public boolean getRememberServicePwd() { return prefs().getBoolean("remember_service_pwd", true); }

    public void setServerUrl(String v) { prefs().edit().putString("server_url", v).apply(); }
    public void setCertFingerprint(String v) { prefs().edit().putString("cert_fingerprint", v).apply(); }
    public void setClipboardClearSeconds(int v) { prefs().edit().putInt("clipboard_clear_seconds", v).apply(); }
    public void setLastVid(String v) { prefs().edit().putString("last_vid", v).apply(); }
    public void setLastAccount(String v) { prefs().edit().putString("last_account", v).apply(); }
    public void setRememberServicePwd(boolean v) { prefs().edit().putBoolean("remember_service_pwd", v).apply(); }

    // ---- CSV 导出（明文，导出前二次确认在 UI 层做）----
    private static final String[] COLS = {"type", "title", "url", "username", "password", "apikey", "note"};

    private static String csvField(String s) {
        if (s == null) s = "";
        boolean needQuote = s.contains(",") || s.contains("\"") || s.contains("\n") || s.contains("\r");
        String esc = s.replace("\"", "\"\"");
        return needQuote ? "\"" + esc + "\"" : esc;
    }

    public File exportCsv(Vault v, File dest) throws Exception {
        StringBuilder sb = new StringBuilder();
        sb.append('\uFEFF'); // UTF-8 BOM
        sb.append(String.join(",", COLS)).append("\r\n");
        for (JSONObject rec : v.activeRecords()) {
            for (int i = 0; i < COLS.length; i++) {
                if (i > 0) sb.append(',');
                String val = rec.isNull(COLS[i]) ? "" : rec.optString(COLS[i], "");
                sb.append(csvField(val));
            }
            sb.append("\r\n");
        }
        try (FileOutputStream fos = new FileOutputStream(dest)) {
            fos.write(sb.toString().getBytes(StandardCharsets.UTF_8));
        }
        return dest;
    }

    public static String defaultExportName() {
        return "pwdmgr_export_" + new SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(new Date()) + ".csv";
    }
}

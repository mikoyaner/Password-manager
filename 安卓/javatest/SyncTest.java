package com.pwdmgr;

import org.json.JSONArray;
import org.json.JSONObject;

import java.nio.charset.StandardCharsets;

/**
 * Java 端到端同步测试 v2.3（仅本地 javac 用，不进 APK）。
 * 用法: java SyncTest <serverUrl> [certFingerprint]
 *   serverUrl 例：https://<服务器地址>:8443（只接受 https）
 *   certFingerprint 可选；自签证书需填，留空走系统默认信任。
 *
 * 覆盖：注册(零库) → 多版本推送(≤5 FIFO) → 列出(新→旧) → 选一份下载解密 →
 *       属主隔离(换账号取不到) → 改用户密码 → 注销账号 → 错误密码被拒。
 */
public class SyncTest {
    static int passed = 0;
    static void check(boolean c, String msg) {
        if (!c) { System.out.println("FAIL: " + msg); System.exit(1); }
        passed++; System.out.println("OK: " + msg);
    }

    static String runId() {
        return "t" + (System.currentTimeMillis() % 100000000L);
    }

    static byte[] vaultBytes(Vault v, String vaultPw) throws Exception {
        byte[] salt = Crypto.newSalt();
        byte[] key = Crypto.deriveKey(vaultPw, salt, Crypto.ARGON_M, Crypto.ARGON_T, Crypto.ARGON_P);
        return Crypto.encryptVault(v.toJson(), key, salt);
    }

    public static void main(String[] args) throws Exception {
        String url = args[0];
        String fp = args.length > 1 && !args[1].isEmpty() ? args[1] : null;
        String userA = runId() + "a";
        String userB = runId() + "b";
        String spwd = "S3rvice-pw!";
        String vaultPw = "Vault-Passw0rd-123";
        System.out.println("# userA=" + userA + "  userB=" + userB + "  url=" + url);

        // health
        SyncClient h = new SyncClient(url, userA, spwd, fp);
        check(h.health() != null, "health 可达");

        // 注册 A（零库）
        SyncClient a = new SyncClient(url, userA, spwd, fp);
        a.register(spwd, userA + "@t.example", "", null, null, null);
        check(a.listVaults().length() == 0, "A 注册后云端 0 份");

        // 推送多份，验证 FIFO ≤5
        int pushed = 7;
        int firstVid = -1, lastVid = -1;
        for (int i = 1; i <= pushed; i++) {
            Vault v = new Vault();
            v.pwdTime = System.currentTimeMillis();
            v.label = "版本" + i;
            v.add("login", "Rec" + i, "https://e" + i + ".com", "u" + i, "p" + i, null, "note" + i);
            JSONObject resp = a.putVault(v.pwdTime, v.label, vaultBytes(v, vaultPw));
            int vid = resp.getInt("vid");
            int kept = resp.getInt("kept");
            if (i == 1) firstVid = vid;
            lastVid = vid;
            check(kept == Math.min(i, 5), "第 " + i + " 次推送 kept=" + kept);
        }
        JSONArray list = a.listVaults();
        check(list.length() == 5, "FIFO 上限 5 份（实际 " + list.length() + "）");
        // 新→旧：首项应是最新 lastVid
        check(list.getJSONObject(0).getInt("vid") == lastVid, "列表按上传时间新→旧");
        // 最早的 firstVid 已被淘汰
        boolean firstGone = true;
        for (int i = 0; i < list.length(); i++)
            if (list.getJSONObject(i).getInt("vid") == firstVid) firstGone = false;
        check(firstGone, "最旧版本已被淘汰");

        // 选一份下载并解密，验证记录
        int pickVid = list.getJSONObject(1).getInt("vid");
        JSONObject entry = a.getVault(pickVid);
        byte[] cipher = java.util.Base64.getDecoder().decode(entry.getString("ciphertext"));
        Vault down = Vault.fromJson(Crypto.decryptVault(cipher, vaultPw));
        check(down.activeRecords().size() == 1, "下载的库有 1 条记录");
        check(down.activeRecords().get(0).getString("title").startsWith("Rec"), "记录内容可解密");
        // 下载响应不含属主字段
        check(!entry.has("username"), "下载响应剥离 owner");

        // 属主隔离：B 取不到 A 的库
        SyncClient b = new SyncClient(url, userB, spwd, fp);
        b.register(spwd, userB + "@t.example", "", null, null, null);
        try {
            b.getVault(pickVid);
            check(false, "跨账号 getVault 应 404");
        } catch (SyncClient.NotFoundException e) {
            check(true, "属主隔离：B 取不到 A 的份(404)");
        }
        check(b.listVaults().length() == 0, "B 只见自己的库(0 份)");

        // 改用户密码
        a.changeServicePwd("N3w-service-pw!");
        try {
            new SyncClient(url, userA, spwd, fp).listVaults();
            check(false, "旧用户密码应 401");
        } catch (SyncClient.AuthException e) {
            check(true, "改密后旧用户密码被拒");
        }
        check(new SyncClient(url, userA, "N3w-service-pw!", fp).listVaults().length() == 5,
                "新用户密码可登录且仍 5 份");

        // 错误用户密码
        try {
            new SyncClient(url, userA, "wrong-pw", fp).listVaults();
            check(false, "错误密码应抛 AuthException");
        } catch (SyncClient.AuthException e) {
            check(true, "错误用户密码被拒绝");
        }

        // 注销 B（B 用注册时的 spwd 认证），验证账号删除后不可用
        b.deleteAccount();
        try {
            new SyncClient(url, userB, spwd, fp).listVaults();
            check(false, "注销后账号应 401");
        } catch (SyncClient.AuthException e) {
            check(true, "注销后账号不可用");
        }

        System.out.println("\nALL JAVA SYNC TESTS v2.3 PASSED (" + passed + ")");
    }
}

package com.pwdmgr;

import android.content.Context;
import android.content.SharedPreferences;

import androidx.security.crypto.EncryptedSharedPreferences;
import androidx.security.crypto.MasterKey;

/**
 * 服务密码（用户密码）加密存储，替代桌面端系统凭据库(keyring)。
 * 主密钥走 AndroidKeyStore；仅在用户勾选「记住用户密码」时写入。
 * 密码库密码（主密钥）绝不进这里。
 */
public final class SecretStore {

    private static final String FILE = "pwdmgr_secrets";

    private SecretStore() {}

    private static SharedPreferences prefs(Context ctx) {
        try {
            MasterKey key = new MasterKey.Builder(ctx.getApplicationContext())
                    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                    .build();
            return EncryptedSharedPreferences.create(
                    ctx.getApplicationContext(), FILE, key,
                    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM);
        } catch (Exception e) {
            // 主密钥损坏等极端情况：退化为不存储（每次询问），绝不明文落盘
            return null;
        }
    }

    public static void saveServicePwd(Context ctx, String user, String pwd) {
        SharedPreferences p = prefs(ctx);
        if (p != null) p.edit().putString(user, pwd).apply();
    }

    public static String loadServicePwd(Context ctx, String user) {
        if (user == null || user.isEmpty()) return null;
        SharedPreferences p = prefs(ctx);
        return p == null ? null : p.getString(user, null);
    }

    public static void deleteServicePwd(Context ctx, String user) {
        SharedPreferences p = prefs(ctx);
        if (p != null && user != null) p.edit().remove(user).apply();
    }
}

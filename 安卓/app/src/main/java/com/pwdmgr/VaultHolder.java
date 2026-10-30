package com.pwdmgr;

import android.content.Context;

import java.util.HashMap;
import java.util.Map;

/**
 * 本次进程内已解锁的库（会话）。密码库密码与派生 key 仅驻内存，
 * 绝不落盘、绝不上云。从最近任务划走 / 进程被杀即清空。
 */
public class VaultHolder {

    private static final VaultHolder INSTANCE = new VaultHolder();

    public static VaultHolder get() { return INSTANCE; }

    /** 由 PwdMgrApp 注入，用于启停"任务移除"监听服务。 */
    private static Context appCtx;

    public static void init(Context ctx) {
        appCtx = ctx == null ? null : ctx.getApplicationContext();
    }

    private static class Session {
        Vault vault;
        String password;
        byte[] key;   // Argon2id 派生结果，保存时复用
        byte[] salt;  // vault.enc 文件头 salt（key 与它绑定）

        Session(Vault v, String p, byte[] k, byte[] s) {
            vault = v;
            password = p;
            key = k;
            salt = s;
        }
    }

    private final Map<String, Session> sessions = new HashMap<>();
    private String currentVid;

    public boolean isUnlocked() {
        return currentVid != null && sessions.containsKey(currentVid);
    }

    public boolean isUnlocked(String vid) {
        return vid != null && sessions.containsKey(vid);
    }

    public void unlock(String vid, Vault v, String pw, byte[] key, byte[] salt) {
        sessions.put(vid, new Session(v, pw, key, salt));
        currentVid = vid;
        LockService.start(appCtx);   // 让 Service 在"划走最近任务"时收到 onTaskRemoved
    }

    /** 切回本进程已解锁过的库；返回 false 表示需要重新输入密码。 */
    public boolean resume(String vid) {
        if (sessions.containsKey(vid)) {
            currentVid = vid;
            LockService.start(appCtx);
            return true;
        }
        return false;
    }

    /** 删除本地库时丢弃其会话；若是当前库则一并清空 currentVid。 */
    public void drop(String vid) {
        sessions.remove(vid);
        if (vid != null && vid.equals(currentVid)) currentVid = null;
        if (sessions.isEmpty()) LockService.stop(appCtx);
    }

    public String getVid() { return currentVid; }

    public Vault getVault() {
        Session s = currentVid == null ? null : sessions.get(currentVid);
        return s == null ? null : s.vault;
    }

    public String getPassword() {
        Session s = currentVid == null ? null : sessions.get(currentVid);
        return s == null ? null : s.password;
    }

    public byte[] getKey() {
        Session s = currentVid == null ? null : sessions.get(currentVid);
        return s == null ? null : s.key;
    }

    public byte[] getSalt() {
        Session s = currentVid == null ? null : sessions.get(currentVid);
        return s == null ? null : s.salt;
    }

    public void setPassword(String pw) {
        Session s = currentVid == null ? null : sessions.get(currentVid);
        if (s != null) s.password = pw;
    }

    /** 改密码库密码后，同时替换 key/salt（下一次保存沿用新 key）。 */
    public void setCredentials(String pw, byte[] key, byte[] salt) {
        Session s = currentVid == null ? null : sessions.get(currentVid);
        if (s != null) {
            s.password = pw;
            s.key = key;
            s.salt = salt;
        }
    }

    /** 覆盖某库内容（拉取）后同步会话对象；不改变"当前库"指针。 */
    public void updateSession(String vid, Vault v, String pw, byte[] key, byte[] salt) {
        Session s = vid == null ? null : sessions.get(vid);
        if (s != null) {
            s.vault = v;
            s.password = pw;
            s.key = key;
            s.salt = salt;
        }
    }

    public void clearAll() {
        for (Session s : sessions.values()) {
            if (s.key != null) java.util.Arrays.fill(s.key, (byte) 0);
        }
        sessions.clear();
        currentVid = null;
        LockService.stop(appCtx);
    }
}

package com.pwdmgr;

import android.content.Context;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 本次进程内已解锁的库（会话）。密码库密码与派生 key 仅驻内存，
 * 绝不落盘、绝不上云。从最近任务划走 / 进程被杀即清空。
 *
 * 并发安全（审计报告 B1/B2）：sessions 用 ConcurrentHashMap，currentVid 用
 * volatile；复合操作（unlock/resume/drop/updateSession/clearAll）在实例锁内；
 * key/salt 的 getter 返回**副本**——后台任务持有的是克隆，clearAll 只断引用
 * 不就地清零，在途加密不会被清零密钥破坏。
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
        byte[] key;   // Argon2id 派生结果，保存时复用（视为不可变，对外只出副本）
        byte[] salt;  // vault.enc 文件头 salt（key 与它绑定）

        Session(Vault v, String p, byte[] k, byte[] s) {
            vault = v;
            password = p;
            key = k;
            salt = s;
        }
    }

    private final Map<String, Session> sessions = new ConcurrentHashMap<>();
    private volatile String currentVid;
    private final Object lock = new Object();   // 复合操作互斥

    public boolean isUnlocked() {
        String vid = currentVid;
        return vid != null && sessions.containsKey(vid);
    }

    public boolean isUnlocked(String vid) {
        return vid != null && sessions.containsKey(vid);
    }

    public void unlock(String vid, Vault v, String pw, byte[] key, byte[] salt) {
        synchronized (lock) {
            sessions.put(vid, new Session(v, pw, key, salt));
            currentVid = vid;
        }
        LockService.start(appCtx);   // 让 Service 在"划走最近任务"时收到 onTaskRemoved
    }

    /** 切回本进程已解锁过的库；返回 false 表示需要重新输入密码。 */
    public boolean resume(String vid) {
        synchronized (lock) {
            if (sessions.containsKey(vid)) {
                currentVid = vid;
                LockService.start(appCtx);
                return true;
            }
        }
        return false;
    }

    /** 删除本地库时丢弃其会话；若是当前库则一并清空 currentVid。 */
    public void drop(String vid) {
        boolean empty;
        synchronized (lock) {
            sessions.remove(vid);
            if (vid != null && vid.equals(currentVid)) currentVid = null;
            empty = sessions.isEmpty();
        }
        if (empty) LockService.stop(appCtx);
    }

    public String getVid() { return currentVid; }

    public Vault getVault() {
        String vid = currentVid;
        Session s = vid == null ? null : sessions.get(vid);
        return s == null ? null : s.vault;
    }

    public String getPassword() {
        String vid = currentVid;
        Session s = vid == null ? null : sessions.get(vid);
        return s == null ? null : s.password;
    }

    /** 返回 key 的副本（审计报告 B2：后台在途加密不受 clearAll 影响）。 */
    public byte[] getKey() {
        String vid = currentVid;
        Session s = vid == null ? null : sessions.get(vid);
        return s == null ? null : s.key.clone();
    }

    /** 返回 salt 的副本（同上）。 */
    public byte[] getSalt() {
        String vid = currentVid;
        Session s = vid == null ? null : sessions.get(vid);
        return s == null ? null : s.salt.clone();
    }

    public void setPassword(String pw) {
        synchronized (lock) {
            String vid = currentVid;
            Session s = vid == null ? null : sessions.get(vid);
            if (s != null) s.password = pw;
        }
    }

    /** 改密码库密码后，同时替换 key/salt（下一次保存沿用新 key）。 */
    public void setCredentials(String pw, byte[] key, byte[] salt) {
        synchronized (lock) {
            String vid = currentVid;
            Session s = vid == null ? null : sessions.get(vid);
            if (s != null) {
                s.password = pw;
                s.key = key;
                s.salt = salt;
            }
        }
    }

    /** 覆盖某库内容（拉取）后同步会话对象；不改变"当前库"指针。 */
    public void updateSession(String vid, Vault v, String pw, byte[] key, byte[] salt) {
        synchronized (lock) {
            Session s = sessions.get(vid);
            if (s != null) {
                s.vault = v;
                s.password = pw;
                s.key = key;
                s.salt = salt;
            }
        }
    }

    public void clearAll() {
        // 审计报告 B2：key/salt 视为不可变，getter 返回副本——这里只断引用，
        // 不就地清零（后台在途任务持有的副本不受影响，避免写出零密钥库）
        synchronized (lock) {
            sessions.clear();
            currentVid = null;
        }
        LockService.stop(appCtx);
    }
}

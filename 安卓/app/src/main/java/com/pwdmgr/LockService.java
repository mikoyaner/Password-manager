package com.pwdmgr;

import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.os.IBinder;
import android.util.Log;

/**
 * 只为一个回调而存在：Service.onTaskRemoved 才是"用户从最近任务划走"的通知
 * （Activity 没有这个回调）。收到即清空内存里的密码库密码与派生 key。
 */
public class LockService extends Service {

    static void start(Context c) {
        if (c == null) return;
        try {
            c.startService(new Intent(c, LockService.class));
        } catch (Exception ignore) {}
    }

    static void stop(Context c) {
        if (c == null) return;
        try {
            c.stopService(new Intent(c, LockService.class));
        } catch (Exception ignore) {}
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        return START_NOT_STICKY;
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    @Override
    public void onTaskRemoved(Intent rootIntent) {
        Log.i("PwdMgr", "onTaskRemoved: clearing unlocked session");
        VaultHolder.get().clearAll();
        ClipboardGuard.clearIfOurs(this);
        stopSelf();
    }
}

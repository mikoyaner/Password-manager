package com.pwdmgr;

import android.app.Application;

/** 保存全局 Context，供会话层在解锁时启动"任务移除"监听服务。 */
public class PwdMgrApp extends Application {

    @Override
    public void onCreate() {
        super.onCreate();
        VaultHolder.init(this);
    }
}

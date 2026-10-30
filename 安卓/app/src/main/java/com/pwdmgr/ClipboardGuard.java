package com.pwdmgr;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;

/** 记录"我们最后复制进剪贴板的值"，只清自己写的，别把用户后来复制的东西抹掉。 */
public final class ClipboardGuard {

    private static volatile String value;

    private ClipboardGuard() {}

    public static void set(String v) { value = v; }

    public static void clearIfOurs(Context c) {
        String v = value;
        value = null;
        if (v == null || c == null) return;
        try {
            ClipboardManager cm =
                    (ClipboardManager) c.getSystemService(Context.CLIPBOARD_SERVICE);
            if (cm == null) return;
            ClipData cur = cm.getPrimaryClip();
            if (cur != null && cur.getItemCount() > 0) {
                CharSequence t = cur.getItemAt(0).coerceToText(c);
                if (t != null && v.contentEquals(t)) {
                    cm.setPrimaryClip(ClipData.newPlainText("", ""));
                }
            }
        } catch (Exception ignore) {}
    }
}

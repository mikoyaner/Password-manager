package com.pwdmgr;

import androidx.appcompat.app.AlertDialog;

/** AlertDialog 小工具：校验失败时保持弹窗打开，避免用户重填整张表单。 */
public final class Ui {

    private Ui() {}

    /**
     * 让正按钮的点击逻辑完全由 action 控制：
     * 校验通过时 action 自行调用 d.dismiss()，失败时直接 return 即可。
     * 构造 AlertDialog 时正按钮 listener 传 null。
     */
    public static AlertDialog keepOpen(AlertDialog d, Runnable action) {
        d.setOnShowListener(x -> d.getButton(android.content.DialogInterface.BUTTON_POSITIVE)
                .setOnClickListener(v -> action.run()));
        return d;
    }
}

package com.pwdmgr;

import android.widget.EditText;
import android.widget.Toast;

import org.json.JSONObject;

import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;

/**
 * 忘记密码（v2.7）：输入用户名 → 从服务器 /contact 取管理员联系方式 →
 * 显示自助重置说明。用户用注册时的邮箱/手机号发出「01用户名」邮件 /
 * 「01用户名d」短信，服务器验证发件人哈希后自动把用户密码重置为 86868686。
 * 邮件联系方式与验证逻辑见服务端 contacts.py / forgot.py。
 */
public final class ForgotPwd {

    public static final String INIT_PWD = "86868686";

    private ForgotPwd() {}

    public static void show(final AppCompatActivity act, final Storage storage) {
        final EditText input = new EditText(act);
        input.setHint("你的用户名");
        input.setSingleLine(true);
        new AlertDialog.Builder(act)
                .setTitle("忘记密码")
                .setMessage("输入你的用户名，获取自助重置说明。")
                .setView(input)
                .setPositiveButton("获取发送说明", (d, w) ->
                        fetchAndShow(act, storage, input.getText().toString().trim()))
                .setNegativeButton("取消", null)
                .show();
    }

    private static void fetchAndShow(final AppCompatActivity act, final Storage storage,
                                     final String username) {
        if (username.isEmpty()) {
            Toast.makeText(act, "请先输入用户名", Toast.LENGTH_SHORT).show();
            return;
        }
        Toast.makeText(act, "获取中…", Toast.LENGTH_SHORT).show();
        new Thread(() -> {
            String msg;
            try {
                // /contact 无需认证；凭据占位，仍走指纹校验
                SyncClient c = new SyncClient(storage.getServerUrl(), username, "x",
                        storage.getCertFingerprint().isEmpty() ? null : storage.getCertFingerprint());
                JSONObject ct = c.contact();
                String email = ct.optString("admin_email", "");
                String hint = ct.optString("sms_hint", "");
                msg = "用户名：" + username + "\n\n"
                        + "1. 用注册时的邮箱发送内容「01" + username + "」到 "
                        + (email.isEmpty() ? "（服务器未配置找回邮箱）" : email) + "\n"
                        + "2. 或用注册时的手机号发送短信「01" + username + "d」"
                        + (hint.isEmpty() ? "（服务器未配置短信入口）" : "：" + hint) + "\n\n"
                        + "管理员核实后将自动把你的用户密码重置为 " + INIT_PWD
                        + "（约 1 分钟内生效）。\n用 " + INIT_PWD + " 登录后请立即修改用户密码。";
            } catch (final Exception e) {
                msg = "获取失败: " + e.getMessage();
            }
            final String m = msg;
            act.runOnUiThread(() -> new AlertDialog.Builder(act)
                    .setTitle("自助重置说明")
                    .setMessage(m)
                    .setPositiveButton("好", null)
                    .show());
        }).start();
    }

    /** 用初始密码登录成功后提醒立即修改。 */
    public static void warnIfInitialPwd(final AppCompatActivity act, String servicePwd) {
        if (!INIT_PWD.equals(servicePwd)) return;
        act.runOnUiThread(() -> new AlertDialog.Builder(act)
                .setTitle("初始密码")
                .setMessage("当前使用的是找回重置后的初始密码，请立即在"
                        + "『设置 → 修改用户密码』中设置新密码。")
                .setPositiveButton("知道了", null)
                .show());
    }
}

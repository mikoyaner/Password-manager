package com.pwdmgr;

import android.widget.EditText;
import android.widget.Toast;

import org.json.JSONObject;

import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;

/**
 * 忘记密码（v2.8 两步确认）：输入用户名 → 从服务器 /contact 取管理员联系方式 →
 * 显示自助重置说明。流程：
 *   1) 用注册时的邮箱发送「01用户名」到管理员邮箱；
 *   2) 系统自动回复一封确认码邮件（15 分钟有效）；
 *   3) 回复那封邮件（或用同一邮箱再发一封），正文中包含确认码；
 *   4) 系统再把随机临时密码发到该邮箱，用它登录并立即修改密码。
 * 安全：全程不存在固定密码；确认码证明"能收信"，伪造发件人拿不到任何凭据。
 */
public final class ForgotPwd {

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
                        + "2. 系统自动回复一封确认码邮件（15 分钟内有效）\n"
                        + "3. 复制确认码，新建一封空白邮件（收件人同上）粘贴确认码后发送"
                        + "——不要直接回复原邮件\n"
                        + "4. 系统再把随机临时密码发到你的邮箱，用它登录并立即修改密码\n\n"
                        + "短信通道：" + (hint.isEmpty() ? "（服务器未配置，人工处理较慢）" : hint);
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
}

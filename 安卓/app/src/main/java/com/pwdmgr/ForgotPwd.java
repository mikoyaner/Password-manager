package com.pwdmgr;

import android.app.Dialog;

import org.json.JSONObject;

import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;

/**
 * 忘记密码（v2.8 两步确认）：打开即显示完整自助重置步骤（不依赖服务器连通、
 * 不输用户名）。已配置服务器地址时后台静默拉 /contact 补充管理员邮箱与短信
 * 入口；未配置或网络不通保持占位文案。
 * 流程：
 *   1) 用注册时的邮箱发送「01用户名」到管理员邮箱；
 *   2) 系统自动回复一封确认码邮件（15 分钟有效）；
 *   3) 新建一封空白邮件（不要直接回复原邮件），正文粘贴确认码后发送；
 *   4) 系统再把随机临时密码发到该邮箱，用它登录并立即修改密码。
 * 24h 内已重置且未改密时再次申请，直接收到新临时密码（免确认码）。
 * 安全：全程不存在固定密码；确认码证明"能收信"，伪造发件人拿不到任何凭据。
 */
public final class ForgotPwd {

    private ForgotPwd() {}

    public static void show(final AppCompatActivity act, final Storage storage) {
        final AlertDialog dlg = new AlertDialog.Builder(act)
                .setTitle("忘记密码 · 自助重置步骤")
                .setMessage(render("", ""))
                .setPositiveButton("好", null)
                .show();
        final String url = storage.getServerUrl();
        if (url == null || url.trim().isEmpty()) return;
        // 可选增强：后台拉联系方式回填（失败静默，占位文案保持可读）
        new Thread(() -> {
            String email = "", hint = "";
            try {
                // /contact 无需认证；凭据占位，仍走指纹校验
                SyncClient c = new SyncClient(url, "contact-check", "x",
                        storage.getCertFingerprint().isEmpty() ? null : storage.getCertFingerprint());
                JSONObject ct = c.contact();
                email = ct.optString("admin_email", "");
                hint = ct.optString("sms_hint", "");
            } catch (Exception ignored) {
                return;   // 未配置/网络不通：保持占位文案
            }
            final String e2 = email, h2 = hint;
            act.runOnUiThread(() -> {
                if (dlg.isShowing()) dlg.setMessage(render(e2, h2));
            });
        }).start();
    }

    private static String render(String email, String hint) {
        String emailLine = email.isEmpty()
                ? "发到管理员邮箱（部署时配置；不清楚请向管理员索取）"
                : "发到管理员邮箱 " + email;
        String smsLine = hint.isEmpty()
                ? "短信通道为人工处理（较慢），推荐使用邮箱"
                : "发短信「01你的用户名d」到 " + hint;
        return "操作步骤（邮箱，推荐）\n"
                + "1. 用注册时的邮箱给管理员邮箱发一封邮件，正文只写：01你的用户名\n"
                + "   (" + emailLine + ")\n"
                + "2. 约 1 分钟内收到系统自动回复的 8 位确认码（15 分钟内有效）\n"
                + "3. 新建一封空白邮件（不要直接回复原邮件），收件人同上，正文粘贴确认码后发送\n"
                + "4. 收到系统发来的随机临时密码，用它登录并立即修改用户密码\n\n"
                + "24 小时内再次申请：已重置过且未改密时，再次发「01你的用户名」跳过确认码，"
                + "直接收到新的临时密码。\n\n"
                + "短信通道（可选）：" + smsLine + "。服务器不存任何明文联系方式。";
    }
}

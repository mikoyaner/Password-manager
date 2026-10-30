package com.pwdmgr;

import org.json.JSONObject;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.regex.Pattern;

/** 跨 UI 复用的小工具：用户名校验、云端/本地库展示标签。 */
public final class Account {

    private Account() {}

    // ^[a-zA-Z0-9][a-zA-Z0-9._-]{1,18}[a-zA-Z0-9]$ 且非全数字
    private static final Pattern P = Pattern.compile("^[a-zA-Z0-9][a-zA-Z0-9._-]{1,18}[a-zA-Z0-9]$");

    public static boolean validUsername(String u) {
        if (u == null) return false;
        if (!P.matcher(u).matches()) return false;
        return !u.matches("\\d+");   // 拒绝全数字
    }

    /** 本地库列表标签：库 #vid · label · @account · N 条 · 未上传/已同步。 */
    public static String localVaultLabel(JSONObject meta) {
        String vid = meta.optString("vid");
        String label = meta.isNull("label") ? "" : meta.optString("label", "");
        String acct = meta.optString("last_account", "");
        int n = meta.optInt("record_count", 0);
        boolean neverUploaded = meta.optBoolean("never_uploaded", true);
        StringBuilder sb = new StringBuilder();
        sb.append("库 #").append(vid);
        if (!label.isEmpty()) sb.append(" · ").append(label);
        if (!acct.isEmpty()) sb.append(" · @").append(acct);
        sb.append(" · ").append(n).append(" 条");
        sb.append(neverUploaded ? " · 未上传" : " · 已同步");
        return sb.toString();
    }

    /** 云端历史库项标签：上传时间 · label · 云端#vid。 */
    public static String serverVaultLabel(JSONObject v) {
        long ut = v.optLong("upload_time", 0);
        String time = ut == 0 ? "?" : new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(new Date(ut));
        String label = v.isNull("label") ? "" : v.optString("label", "");
        StringBuilder sb = new StringBuilder();
        sb.append(time);
        if (!label.isEmpty()) sb.append(" · ").append(label);
        sb.append(" · 云端 #").append(v.optInt("vid"));
        return sb.toString();
    }

    /** 毫秒时间戳格式化（展示用）。 */
    public static String fmt(long ms) {
        if (ms == 0) return "—";
        return new SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.US).format(new Date(ms));
    }
}

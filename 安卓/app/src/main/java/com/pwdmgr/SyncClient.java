package com.pwdmgr;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import java.util.Base64;

/**
 * 同步客户端 v2.3（规范 §7）。
 *
 * - HTTP Basic 认证（username + 用户密码/服务密码）；无 token、无 revision、无乐观锁。
 * - 云端多版本：PUT 每次新增一份；GET /vaults 列 ≤5 份；GET /vault/{vid} 下载指定一份。
 * - 自签 HTTPS：信任链放行但连接后校验证书 SHA-256 指纹（pinning），不符拒绝发送任何数据。
 * - 整库覆盖式：不做客户端合并。
 */
public class SyncClient {

    public static class SyncException extends Exception {
        public SyncException(String m) { super(m); }
    }
    public static class AuthException extends SyncException {
        public AuthException(String m) { super(m); }
    }
    public static class PinException extends SyncException {
        public PinException(String m) { super(m); }
    }
    public static class UsernameTakenException extends SyncException {
        public UsernameTakenException(String m) { super(m); }
    }
    public static class NotFoundException extends SyncException {
        public NotFoundException(String m) { super(m); }
    }

    private final String base;
    private final String username;
    private String servicePwd;
    private final String certFingerprint; // 可为 null

    public SyncClient(String serverUrl, String username, String servicePwd, String certFingerprint) {
        this.base = serverUrl.replaceAll("/+$", "");
        this.username = username;
        this.servicePwd = servicePwd;
        this.certFingerprint = certFingerprint;
    }

    private String basicHeader() {
        String raw = username + ":" + servicePwd;
        return "Basic " + Base64.getEncoder().encodeToString(raw.getBytes(StandardCharsets.UTF_8));
    }

    // ---- HTTP 底层 ----
    private static class Resp {
        int status; String body;
        Resp(int s, String b) { status = s; body = b; }
        JSONObject json() throws Exception { return new JSONObject(body); }
    }

    private Resp request(String path, String method, String jsonBody, boolean auth) throws SyncException {
        if (base.isEmpty()) {
            throw new SyncException("尚未配置服务器地址：请先在设置中填写 https://host:port");
        }
        if (!base.startsWith("https://")) {
            // Basic 认证会把用户密码带上，明文 HTTP 一律拒绝
            throw new SyncException("出于安全考虑，服务器地址必须是 https://host:port");
        }
        HttpURLConnection conn = null;
        try {
            URL url = new URL(base + path);
            conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod(method);
            conn.setConnectTimeout(30000);
            conn.setReadTimeout(30000);
            conn.setRequestProperty("Content-Type", "application/json");
            if (auth) conn.setRequestProperty("Authorization", basicHeader());
            if (conn instanceof HttpsURLConnection) {
                configureTls((HttpsURLConnection) conn);
            }
            if (jsonBody != null) conn.setDoOutput(true);
            // 先 TLS 握手 + 验指纹，通过后才发送任何应用层数据
            conn.connect();
            if (conn instanceof HttpsURLConnection) {
                verifyFingerprint(conn);
            }
            if (jsonBody != null) {
                try (OutputStream os = conn.getOutputStream()) {
                    os.write(jsonBody.getBytes(StandardCharsets.UTF_8));
                }
            }
            int status = conn.getResponseCode();
            InputStream is = (status >= 200 && status < 400)
                    ? conn.getInputStream() : conn.getErrorStream();
            String body = is == null ? "" : readAll(is);
            return new Resp(status, body);
        } catch (SyncException e) {
            throw e;
        } catch (Exception e) {
            throw new SyncException("无法连接服务器: " + e.getMessage());
        } finally {
            if (conn != null) conn.disconnect();
        }
    }

    private static String readAll(InputStream is) throws Exception {
        ByteArrayOutputStream bo = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = is.read(buf)) > 0) bo.write(buf, 0, n);
        return new String(bo.toByteArray(), StandardCharsets.UTF_8);
    }

    /** 自签证书 pinning：放行信任链，随后校验指纹；未配置指纹则用系统默认信任。 */
    private void configureTls(HttpsURLConnection conn) throws SyncException {
        if (certFingerprint == null || certFingerprint.isEmpty()) return;
        try {
            TrustManager[] trustAll = new TrustManager[]{ new X509TrustManager() {
                public void checkClientTrusted(java.security.cert.X509Certificate[] c, String a) {}
                public void checkServerTrusted(java.security.cert.X509Certificate[] c, String a) {}
                public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                    return new java.security.cert.X509Certificate[0];
                }
            }};
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(null, trustAll, new java.security.SecureRandom());
            conn.setSSLSocketFactory(ctx.getSocketFactory());
            conn.setHostnameVerifier((h, s) -> true);
        } catch (Exception e) {
            throw new SyncException("TLS 配置失败: " + e.getMessage());
        }
    }

    /** 连接建立后校验服务器证书 SHA-256 指纹（十六进制，无冒号）。 */
    private void verifyFingerprint(HttpURLConnection conn) throws SyncException {
        if (certFingerprint == null || certFingerprint.isEmpty()) return;
        if (!(conn instanceof HttpsURLConnection)) return;
        try {
            java.security.cert.Certificate[] certs =
                    ((HttpsURLConnection) conn).getServerCertificates();
            if (certs == null || certs.length == 0) throw new PinException("无服务器证书");
            byte[] der = certs[0].getEncoded();
            byte[] dig = java.security.MessageDigest.getInstance("SHA-256").digest(der);
            StringBuilder sb = new StringBuilder();
            for (byte b : dig) sb.append(String.format("%02x", b));
            String actual = sb.toString();
            String expect = certFingerprint.replaceAll(":", "").toLowerCase();
            if (!actual.equalsIgnoreCase(expect)) {
                throw new PinException("服务器证书指纹不匹配，可能存在中间人攻击，已拒绝连接");
            }
        } catch (SyncException e) {
            throw e;
        } catch (Exception e) {
            throw new SyncException("证书校验失败: " + e.getMessage());
        }
    }

    private static String extractErr(String body) {
        try {
            JSONObject o = new JSONObject(body);
            Object d = o.opt("detail");
            if (d instanceof JSONObject) return ((JSONObject) d).optString("error", "unknown");
            if (d instanceof String) return (String) d;
        } catch (Exception ignore) {}
        return "unknown";
    }

    // ---- 无认证端点 ----

    public JSONObject health() throws SyncException {
        Resp r = request("/health", "GET", null, false);
        if (r.status != 200) throw new SyncException("health 失败: " + r.status);
        try { return r.json(); } catch (Exception e) { throw new SyncException("health 响应解析失败"); }
    }

    /**
     * POST /register：注册账号。ciphertext 为 null 时仅建账号（云端零份库）；
     * 非 null 时同时上传首版（pwdTime 必填）。返回 {created_at, first_vid}。
     */
    public JSONObject register(String servicePwd, String email, String phone,
                               Long pwdTime, String label, byte[] ciphertext) throws SyncException {
        try {
            JSONObject body = new JSONObject();
            body.put("username", username);
            body.put("service_pwd", servicePwd);
            body.put("email", email == null ? "" : email);
            body.put("phone", phone == null ? "" : phone);
            if (ciphertext != null) {
                body.put("pwd_time", pwdTime == null ? 0L : (long) pwdTime);
                body.put("label", label == null ? JSONObject.NULL : label);
                body.put("ciphertext", Base64.getEncoder().encodeToString(ciphertext));
            }
            Resp r = request("/register", "POST", body.toString(), false);
            if (r.status == 409) throw new UsernameTakenException("用户名已被占用");
            if (r.status != 200) throw new SyncException("注册失败 (" + r.status + "): " + extractErr(r.body));
            return r.json();
        } catch (SyncException e) {
            throw e;
        } catch (Exception e) {
            throw new SyncException("注册请求构造失败: " + e.getMessage());
        }
    }

    // ---- 需 Basic 认证端点 ----

    /** GET /vaults → 本账号名下 ≤5 份历史库元数据（新→旧，不含密文、不显示属主）。 */
    public JSONArray listVaults() throws SyncException {
        Resp r = request("/vaults", "GET", null, true);
        if (r.status == 401) throw new AuthException("用户名或用户密码错误");
        if (r.status != 200) throw new SyncException("GET /vaults 失败 (" + r.status + "): " + extractErr(r.body));
        try {
            return r.json().optJSONArray("vaults");
        } catch (Exception e) {
            throw new SyncException("GET /vaults 解析失败: " + e.getMessage());
        }
    }

    /** GET /vault/{vid} → {vid,pwd_time,label,upload_time,ciphertext(b64),ciphertext_sha256}。 */
    public JSONObject getVault(int vid) throws SyncException {
        Resp r = request("/vault/" + vid, "GET", null, true);
        if (r.status == 401) throw new AuthException("用户名或用户密码错误");
        if (r.status == 404) throw new NotFoundException("云端无该份密码库（或不属于本账号）");
        if (r.status != 200) throw new SyncException("GET /vault 失败 (" + r.status + "): " + extractErr(r.body));
        try { return r.json(); }
        catch (Exception e) { throw new SyncException("GET /vault 解析失败: " + e.getMessage()); }
    }

    /** PUT /vault：每次上传新增一份。返回 {vid, upload_time, ciphertext_sha256, kept}。 */
    public JSONObject putVault(long pwdTime, String label, byte[] ciphertext) throws SyncException {
        try {
            JSONObject body = new JSONObject();
            body.put("pwd_time", pwdTime);
            body.put("label", label == null ? JSONObject.NULL : label);
            body.put("ciphertext", Base64.getEncoder().encodeToString(ciphertext));
            Resp r = request("/vault", "PUT", body.toString(), true);
            if (r.status == 401) throw new AuthException("用户名或用户密码错误");
            if (r.status != 200) throw new SyncException("PUT /vault 失败 (" + r.status + "): " + extractErr(r.body));
            return r.json();
        } catch (SyncException e) {
            throw e;
        } catch (Exception e) {
            throw new SyncException("PUT 请求构造失败: " + e.getMessage());
        }
    }

    /** 改用户密码（服务密码）。当前密码由 Basic 认证证明。 */
    public JSONObject changeServicePwd(String newPwd) throws SyncException {
        try {
            JSONObject body = new JSONObject();
            body.put("new_pwd", newPwd);
            Resp r = request("/change_service_pwd", "POST", body.toString(), true);
            if (r.status == 401) throw new AuthException("旧用户密码错误");
            if (r.status != 200) throw new SyncException("改用户密码失败 (" + r.status + "): " + extractErr(r.body));
            this.servicePwd = newPwd; // 便于后续调用
            return r.json();
        } catch (SyncException e) {
            throw e;
        } catch (Exception e) {
            throw new SyncException("改用户密码请求构造失败: " + e.getMessage());
        }
    }

    /** DELETE /account：注销账号，级联删其全部云端库。 */
    public JSONObject deleteAccount() throws SyncException {
        try {
            Resp r = request("/account", "DELETE", "{\"confirm\":true}", true);
            if (r.status == 401) throw new AuthException("用户名或用户密码错误");
            if (r.status != 200) throw new SyncException("注销账户失败 (" + r.status + "): " + extractErr(r.body));
            return r.json();
        } catch (SyncException e) {
            throw e;
        } catch (Exception e) {
            throw new SyncException("注销请求构造失败: " + e.getMessage());
        }
    }
}

package com.pwdmgr;

import android.app.PendingIntent;
import android.app.assist.AssistStructure;
import android.content.Intent;
import android.os.CancellationSignal;
import android.service.autofill.AutofillService;
import android.service.autofill.Dataset;
import android.service.autofill.FillCallback;
import android.service.autofill.FillContext;
import android.service.autofill.FillRequest;
import android.service.autofill.FillResponse;
import android.service.autofill.SaveCallback;
import android.service.autofill.SaveInfo;
import android.service.autofill.SaveRequest;
import android.text.TextUtils;
import android.view.View;
import android.view.autofill.AutofillId;
import android.view.autofill.AutofillValue;
import android.widget.RemoteViews;

import org.json.JSONObject;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * 自动填充服务（Android Autofill 框架）。
 * 仅在本机库已解锁（VaultHolder 内存态）时提供填充/捕获；库密码绝不落盘、绝不上云。
 * 注意：Chrome/Edge 等自带密码管理的浏览器不会把网页密码框交给第三方 autofill，属系统限制。
 */
public class PwdMgrAutofillService extends AutofillService {

    /** 审计报告 B5：单线程 executor 串行执行落库（避免并发保存/ANR）。 */
    private final java.util.concurrent.ExecutorService saveExecutor =
            java.util.concurrent.Executors.newSingleThreadExecutor();

    @Override
    public void onFillRequest(FillRequest request, CancellationSignal cancel, FillCallback callback) {
        List<FillContext> ctxs = request.getFillContexts();
        AssistStructure structure = ctxs.get(ctxs.size() - 1).getStructure();
        Parsed pf = parse(structure);

        if (pf.passwordId == null) { // 页面没有密码框，不参与
            callback.onSuccess(null);
            return;
        }

        VaultHolder h = VaultHolder.get();
        FillResponse.Builder resp = new FillResponse.Builder();

        if (!h.isUnlocked()) {
            // 未解锁：要求先认证（打开 App 解锁），不暴露任何凭据
            Intent unlock = new Intent(this, HomeActivity.class)
                    .putExtra("autofill_unlock", true)
                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            PendingIntent pi = PendingIntent.getActivity(this, 100, unlock,
                    PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
            List<AutofillId> all = new ArrayList<>();
            if (pf.usernameId != null) all.add(pf.usernameId);
            all.add(pf.passwordId);
            resp.setAuthentication(all.toArray(new AutofillId[0]),
                    pi.getIntentSender(), presentation("打开密码管理器以解锁"));
            callback.onSuccess(resp.build());
            return;
        }

        try {
            String pkg = lower(packageOf(structure));
            String domain = pf.webDomain == null ? "" : pf.webDomain.toLowerCase(Locale.US);
            Vault v = h.getVault();
            List<JSONObject> recs = v.activeRecords();
            int added = 0;
            for (JSONObject r : recs) {
                if (added >= 5) break;
                if ("apikey".equals(r.optString("type"))) continue;
                String pass = r.isNull("password") ? "" : r.optString("password");
                if (pass.isEmpty()) continue;
                if (!matches(r, pkg, domain)) continue;
                String user = r.isNull("username") ? "" : r.optString("username");
                Dataset.Builder ds = new Dataset.Builder(
                        presentation(r.optString("title") + " · " + user));
                if (pf.usernameId != null)
                    ds.setValue(pf.usernameId, AutofillValue.forText(user));
                ds.setValue(pf.passwordId, AutofillValue.forText(pass));
                resp.addDataset(ds.build());
                added++;
            }

            // 捕获（保存）：声明数据类型为"用户名 + 密码"，系统据此给出正确的保存提示
            List<AutofillId> req = new ArrayList<>();
            req.add(pf.passwordId);
            if (pf.usernameId != null) req.add(pf.usernameId);
            SaveInfo.Builder sb = new SaveInfo.Builder(
                    SaveInfo.SAVE_DATA_TYPE_PASSWORD | SaveInfo.SAVE_DATA_TYPE_USERNAME,
                    req.toArray(new AutofillId[0]));
            if (pf.usernameId != null) sb.setOptionalIds(new AutofillId[]{pf.usernameId});
            sb.setDescription("是否保存这条凭据到密码管理器？");
            resp.setSaveInfo(sb.build());

            callback.onSuccess(resp.build());
        } catch (Exception e) {
            callback.onFailure("填充失败: " + e.getMessage());
        }
    }

    @Override
    public void onSaveRequest(SaveRequest request, SaveCallback callback) {
        List<FillContext> ctxs = request.getFillContexts();
        AssistStructure structure = ctxs.get(ctxs.size() - 1).getStructure();
        Parsed pf = parse(structure);
        String pass = pf.passwordValue;
        if (pf.passwordId == null || TextUtils.isEmpty(pass)) {
            callback.onFailure("未捕获到密码");
            return;
        }
        VaultHolder h = VaultHolder.get();
        if (!h.isUnlocked() || h.getVault() == null) {
            // 未解锁时没有主密钥可用；系统已问过是否保存，但这里无法加密落盘
            callback.onFailure("密码管理器未解锁");
            return;
        }
        String pkg = packageOf(structure);
        String url = TextUtils.isEmpty(pf.webDomain) ? "" : "https://" + pf.webDomain;
        String title = !TextUtils.isEmpty(pf.webDomain) ? pf.webDomain : pkg;
        String user = pf.usernameValue == null ? "" : pf.usernameValue;
        // 审计报告 B5：落库放到单线程 executor（避免服务主线程 AES-GCM+全库重写
        // 造成 ANR），回调在落库**之后**诚实返回，不做"先成功后失败"
        final String fTitle = title;
        final String fUrl = url;
        final String fUser = user;
        final String fPass = pass;
        saveExecutor.execute(() -> {
            try {
                Vault v = h.getVault();
                if (v == null) {   // 排队期间会话可能被清
                    callback.onFailure("密码管理器未解锁");
                    return;
                }
                Storage storage = new Storage(this);
                boolean dup;
                byte[] blob = null;
                long pwdTime = 0;
                long modifiedAt = 0;
                String label = null;
                int recCount = 0;
                // B4 残留修复：去重 + 新增 + 序列化 + 加密全部在 Vault 自己的
                // 监视器锁内（与 UI 线程的 add/update 互斥），锁外只写文件；
                // key/salt 用原子快照（B2 残留：避免两次调用间的错配对）
                synchronized (v) {
                    dup = hasSameLogin(v, fUrl, fUser, fPass);
                    if (!dup) {
                        v.add(Vault.TYPE_LOGIN, fTitle,
                                fUrl.isEmpty() ? null : fUrl,
                                fUser.isEmpty() ? null : fUser,
                                fPass, null, "自动捕获");
                        VaultHolder.KeySalt ks = h.getKeySalt();
                        blob = Crypto.encryptVault(v.toJson(), ks.key, ks.salt);
                        pwdTime = v.pwdTime;
                        modifiedAt = v.modifiedAt;
                        label = v.label;
                        recCount = v.activeRecords().size();
                    }
                }
                if (dup) {
                    callback.onSuccess();   // 重复凭据：无事可做
                    return;
                }
                storage.saveVaultSnapshot(h.getVid(), blob, pwdTime, modifiedAt,
                                          label, recCount, true);
                storage.logSync(h.getVid(), "自动捕获保存 " + fTitle + " / " + fUser);
                callback.onSuccess();
            } catch (Exception e) {
                callback.onFailure("保存失败: " + e.getMessage());
            }
        });
    }

    /** 同 URL + 同用户名 + 同密码视为重复，避免每次登录都新增一条。 */
    private static boolean hasSameLogin(Vault v, String url, String user, String pass) {
        try {
            for (JSONObject r : v.activeRecords()) {
                if (!Vault.TYPE_LOGIN.equals(r.optString("type"))) continue;
                String rp = r.isNull("password") ? "" : r.optString("password");
                String ru = r.isNull("username") ? "" : r.optString("username");
                String rurl = r.isNull("url") ? "" : r.optString("url");
                if (pass.equals(rp) && user.equals(ru) && url.equals(rurl)) return true;
            }
        } catch (Exception ignore) {}
        return false;
    }

    // ---- 结构解析 ----

    static class Parsed {
        AutofillId usernameId, passwordId;
        String usernameValue, passwordValue;
        String webDomain;
    }

    private Parsed parse(AssistStructure s) {
        Parsed p = new Parsed();
        for (int w = 0; w < s.getWindowNodeCount(); w++) {
            AssistStructure.WindowNode win = s.getWindowNodeAt(w);
            if (win == null) continue;
            walk(win.getRootViewNode(), p);
        }
        return p;
    }

    private void walk(AssistStructure.ViewNode n, Parsed p) {
        if (n == null) return;
        if (p.webDomain == null && n.getWebDomain() != null) p.webDomain = n.getWebDomain();
        AutofillId id = n.getAutofillId();
        if (id != null && n.getImportantForAutofill() != View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS) {
            String hint = lower(n.getHint());
            String cls = lower(n.getClassName());
            boolean isPass = hasHint(n, View.AUTOFILL_HINT_PASSWORD)
                    || containsAny(hint, "password", "密码")
                    || containsAny(cls, "password");
            boolean isUser = !isPass && (hasHint(n, View.AUTOFILL_HINT_USERNAME)
                    || hasHint(n, View.AUTOFILL_HINT_EMAIL_ADDRESS)
                    || hasHint(n, View.AUTOFILL_HINT_NAME)
                    || containsAny(hint, "用户名", "邮箱", "账号", "user", "email", "account", "login"));
            if (isPass && p.passwordId == null) {
                p.passwordId = id;
                p.passwordValue = text(n);
            } else if (isUser && p.usernameId == null) {
                p.usernameId = id;
                p.usernameValue = text(n);
            }
        }
        for (int i = 0; i < n.getChildCount(); i++) walk(n.getChildAt(i), p);
    }

    private static String packageOf(AssistStructure s) {
        try {
            if (s.getActivityComponent() != null) return s.getActivityComponent().getPackageName();
        } catch (Exception ignore) {}
        return "";
    }

    private static String text(AssistStructure.ViewNode n) {
        AutofillValue av = n.getAutofillValue();
        if (av != null && av.isText()) {
            CharSequence c = av.getTextValue();
            if (c != null) return c.toString();
        }
        CharSequence tv = n.getText();
        return tv == null ? null : tv.toString();
    }

    private static boolean hasHint(AssistStructure.ViewNode n, String target) {
        String[] hints = n.getAutofillHints();
        if (hints == null) return false;
        for (String h : hints) if (h != null && target.contentEquals(h)) return true;
        return false;
    }

    private static String lower(String s) { return s == null ? null : s.toLowerCase(Locale.US); }

    private static boolean containsAny(String hay, String... needles) {
        if (hay == null) return false;
        for (String x : needles) if (x != null && hay.contains(x)) return true;
        return false;
    }

    /**
     * 记录是否与当前包名/域名相关。
     * 域名必须按 host 边界匹配（相等或子域），绝不能用子串——否则
     * example.com.evil.cn / notexample.com 这类仿冒域名也会拿到凭据。
     */
    private static boolean matches(JSONObject r, String pkg, String domain) {
        String title = lower(r.optString("title"));
        if (!domain.isEmpty()) {
            String site = normalizeHost(domain);
            String recHost = normalizeHost(hostOf(r.optString("url")));
            if (!site.isEmpty() && !recHost.isEmpty() && hostMatches(site, recHost)) return true;
            // 没有网址的记录：只接受标题与主机名完全相同（不做子串兜底）
            if (recHost.isEmpty() && !site.isEmpty() && site.equals(title)) return true;
        }
        if (!pkg.isEmpty()) {
            String last = pkg.contains(".") ? pkg.substring(pkg.lastIndexOf('.') + 1) : pkg;
            if (last.length() > 2 && title != null && title.contains(last)) return true;
        }
        return false;
    }

    /** a 与 b 是同一主机，或一方是另一方的子域。 */
    private static boolean hostMatches(String a, String b) {
        return a.equals(b) || a.endsWith("." + b) || b.endsWith("." + a);
    }

    private static String hostOf(String url) {
        if (url == null) return "";
        String u = url.trim().toLowerCase(Locale.US);
        int p = u.indexOf("://");
        if (p >= 0) u = u.substring(p + 3);
        int slash = u.indexOf('/');
        if (slash >= 0) u = u.substring(0, slash);
        int q = u.indexOf('?');
        if (q >= 0) u = u.substring(0, q);
        int at = u.lastIndexOf('@');   // 去掉 userinfo
        if (at >= 0) u = u.substring(at + 1);
        int colon = u.indexOf(':');    // 去端口
        if (colon >= 0) u = u.substring(0, colon);
        return u;
    }

    /** 去 www. 前缀，便于 example.com 与 www.example.com 互认。 */
    private static String normalizeHost(String host) {
        if (host == null) return "";
        String h = host.trim().toLowerCase(Locale.US);
        if (h.endsWith(".")) h = h.substring(0, h.length() - 1);
        if (h.startsWith("www.")) h = h.substring(4);
        return h;
    }

    private RemoteViews presentation(String label) {
        RemoteViews rv = new RemoteViews(getPackageName(), R.layout.autofill_item);
        rv.setTextViewText(R.id.autofill_text, label);
        return rv;
    }
}

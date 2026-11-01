package com.pwdmgr;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.ListView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/** 主界面：列表 + 搜索 + 详情 + 操作 + 同步（推拉）。所有加解密在本地，密码库密码仅内存。 */
public class MainActivity extends AppCompatActivity {

    private Storage storage;
    private ListView list;
    private TextView detail, status;
    private EditText search;
    private Button editBtn, delBtn, copyUser, copyPass, copyKey;

    private final List<JSONObject> shown = new ArrayList<>();
    private String currentId = null;

    private final Handler handler = new Handler(Looper.getMainLooper());
    private Runnable clipClearRunnable;

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        setContentView(R.layout.activity_main);
        storage = new Storage(this);

        list = findViewById(R.id.list);
        detail = findViewById(R.id.detail);
        status = findViewById(R.id.status);
        search = findViewById(R.id.search);
        editBtn = findViewById(R.id.edit);
        delBtn = findViewById(R.id.delete);
        copyUser = findViewById(R.id.copy_user);
        copyPass = findViewById(R.id.copy_pass);
        copyKey = findViewById(R.id.copy_key);
        findViewById(R.id.add).setOnClickListener(v -> addRecord());
        findViewById(R.id.sync).setOnClickListener(v -> startSync());
        findViewById(R.id.exportCsv).setOnClickListener(v -> exportCsv());
        findViewById(R.id.switchVault).setOnClickListener(v -> switchVault());

        editBtn.setOnClickListener(v -> editRecord());
        delBtn.setOnClickListener(v -> deleteRecord());
        copyUser.setOnClickListener(v -> copyField("username"));
        copyPass.setOnClickListener(v -> copyField("password"));
        copyKey.setOnClickListener(v -> copyField("apikey"));

        search.addTextChangedListener(new TextWatcher() {
            public void beforeTextChanged(CharSequence s, int a, int c, int d) {}
            public void onTextChanged(CharSequence s, int a, int c, int d) {}
            public void afterTextChanged(Editable e) { refreshList(); }
        });

        list.setOnItemClickListener((parent, view, pos, id) -> select(pos));
        setButtonsEnabled(false);
    }

    @Override
    protected void onResume() {
        super.onResume();
        VaultHolder h = VaultHolder.get();
        if (!h.isUnlocked()) {
            startActivity(new Intent(this, HomeActivity.class));
            finish();
            return;
        }
        refreshList();
    }

    private String vid() { return VaultHolder.get().getVid(); }
    private Vault vault() { return VaultHolder.get().getVault(); }
    private String password() { return VaultHolder.get().getPassword(); }

    // ---- 列表 ----
    private void refreshList() {
        if (vault() == null) return;
        shown.clear();
        try {
            String kw = search.getText().toString();
            List<JSONObject> recs = (kw == null || kw.trim().isEmpty())
                    ? vault().activeRecords() : vault().search(kw);
            shown.addAll(recs);
        } catch (Exception e) {
            toast("加载失败: " + e.getMessage()); return;
        }
        List<String> labels = new ArrayList<>();
        for (JSONObject r : shown) {
            String icon = "apikey".equals(r.optString("type")) ? "[Key] " : "[Web] ";
            labels.add(icon + r.optString("title"));
        }
        ArrayAdapter<String> ad = new ArrayAdapter<>(this,
                android.R.layout.simple_list_item_1, labels);
        list.setAdapter(ad);
        String label = vault().label == null ? "" : vault().label;
        status.setText("库 #" + vid() + (label.isEmpty() ? "" : " · " + label) + " · 已解锁 · " + shown.size() + " 条");
        if (!shown.isEmpty()) select(0);
        else { currentId = null; detail.setText(""); setButtonsEnabled(false); }
    }

    private void select(int pos) {
        if (pos < 0 || pos >= shown.size()) return;
        JSONObject r = shown.get(pos);
        currentId = r.optString("id");
        setButtonsEnabled(true);
        boolean isKey = "apikey".equals(r.optString("type"));
        copyUser.setVisibility(isKey ? View.GONE : View.VISIBLE);
        copyPass.setVisibility(isKey ? View.GONE : View.VISIBLE);
        copyKey.setVisibility(isKey ? View.VISIBLE : View.GONE);
        StringBuilder sb = new StringBuilder();
        sb.append("类型：").append(isKey ? "API Key" : "网站登录").append("\n");
        sb.append("标题：").append(r.optString("title")).append("\n");
        if (!isKey) {
            sb.append("网址：").append(nullToDash(r.optString("url"))).append("\n");
            sb.append("用户名：").append(nullToDash(r.optString("username"))).append("\n");
            sb.append("密码：••••••（点下方复制）\n");
        } else {
            sb.append("API Key：••••••（点下方复制）\n");
        }
        String note = r.optString("note");
        if (note != null && !note.isEmpty()) sb.append("\n备注：").append(note);
        sb.append("\n最近修改：").append(Account.fmt(vault().modifiedAt));
        detail.setText(sb.toString());
    }

    private static String nullToDash(String s) { return (s == null || s.isEmpty() || "null".equals(s)) ? "—" : s; }

    private void setButtonsEnabled(boolean on) {
        for (Button b : new Button[]{editBtn, delBtn, copyUser, copyPass, copyKey}) b.setEnabled(on);
    }

    // ---- 增删改 ----
    private void addRecord() { startActivity(new Intent(this, RecordEditActivity.class)); }

    private void editRecord() {
        if (currentId == null) return;
        Intent i = new Intent(this, RecordEditActivity.class);
        i.putExtra("id", currentId);
        startActivity(i);
    }

    private void deleteRecord() {
        if (currentId == null) return;
        JSONObject rec = vault().get(currentId);
        String title = rec == null ? "" : rec.optString("title");
        new AlertDialog.Builder(this)
                .setTitle("删除").setMessage("确定删除「" + title + "」？")
                .setPositiveButton("删除", (d, w) -> {
                    try {
                        vault().delete(currentId);
                        persist();
                        refreshList();
                    } catch (Exception e) { toast("删除失败: " + e.getMessage()); }
                })
                .setNegativeButton("取消", null).show();
    }

    /** 本地保存：复用会话 key/salt，并把库标记为"未同步"（推送成功后才会清）。 */
    private void persist() {
        VaultHolder h = VaultHolder.get();
        if (h.getVault() == null || h.getVid() == null) return;
        try {
            VaultHolder.KeySalt ks = VaultHolder.get().getKeySalt();
            storage.saveVault(h.getVid(), h.getVault(), ks.key, ks.salt, true);
        } catch (Exception e) {
            toast("保存失败: " + e.getMessage());
        }
    }

    // ---- 复制 + 定时清空剪贴板 ----
    private void copyField(String field) {
        if (currentId == null) return;
        JSONObject rec = vault().get(currentId);
        String val = rec == null ? null : (rec.isNull(field) ? "" : rec.optString(field));
        if (val == null || val.isEmpty()) { status.setText("无可复制内容"); return; }
        ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        cm.setPrimaryClip(ClipData.newPlainText("pwdmgr", val));
        ClipboardGuard.set(val);
        int secs = storage.getClipboardClearSeconds();
        if (clipClearRunnable != null) handler.removeCallbacks(clipClearRunnable);
        if (secs > 0) {
            clipClearRunnable = () -> ClipboardGuard.clearIfOurs(this);
            handler.postDelayed(clipClearRunnable, secs * 1000L);
        }
        status.setText("已复制，" + secs + " 秒后自动清空剪贴板");
    }

    // ---- 同步：登录 → 动作（推送/拉取） ----
    private void startSync() {
        View dlg = LayoutInflater.from(this).inflate(R.layout.dialog_login, null);
        EditText acct = dlg.findViewById(R.id.account);
        EditText spwd = dlg.findViewById(R.id.service_pwd);
        CheckBox remember = dlg.findViewById(R.id.remember);
        JSONObject meta = storage.loadMeta(vid());
        String lastAcct = meta.optString("last_account", "");
        if (lastAcct.isEmpty()) lastAcct = storage.getLastAccount();
        acct.setText(lastAcct);
        boolean rem = storage.getRememberServicePwd();
        remember.setChecked(rem);
        if (rem && !lastAcct.isEmpty()) {
            String saved = SecretStore.loadServicePwd(this, lastAcct);
            if (saved != null) spwd.setText(saved);
        }
        AlertDialog d = new AlertDialog.Builder(this).setTitle("同步 · 当前库 #" + vid())
                .setView(dlg)
                .setNeutralButton("注册账号", (dd, w) -> showRegister())
                .setPositiveButton("登录", null)
                .setNegativeButton("取消", null).create();
        dlg.findViewById(R.id.forgot).setOnClickListener(v -> ForgotPwd.show(this, storage));
        Ui.keepOpen(d, () -> {
            String u = acct.getText().toString().trim();
            String p = spwd.getText().toString();
            boolean rm = remember.isChecked();
            if (!Account.validUsername(u)) { toast("用户名不合规"); return; }
            if (p.isEmpty()) { toast("请输入用户密码"); return; }
            storage.setRememberServicePwd(rm);
            d.dismiss();
            loginAndChooseAction(u, p, rm);
        });
        d.show();
    }

    private void loginAndChooseAction(String account, String servicePwd, boolean remember) {
        status.setText("登录中…");
        new Thread(() -> {
            try {
                SyncClient c = newClient(account, servicePwd);
                JSONArray vaults = c.listVaults();
                if (remember) SecretStore.saveServicePwd(this, account, servicePwd);
                else SecretStore.deleteServicePwd(this, account);
                storage.setLastAccount(account);
                runOnUiThread(() -> {
                    if (isFinishing() || isDestroyed()) return;
                    int k = vaults == null ? 0 : vaults.length();
                    status.setText("已登录 @" + account + " · 云端 " + k + " 份");
                    chooseAction(account, servicePwd, vaults, k);
                });
            } catch (SyncClient.AuthException e) {
                runOnUiThread(() -> { status.setText("登录失败"); toast("用户名或用户密码错误"); });
            } catch (SyncClient.PinException e) {
                runOnUiThread(() -> { status.setText("连接被拒"); toast(e.getMessage()); });
            } catch (Exception e) {
                runOnUiThread(() -> { status.setText("登录失败"); toast("连接失败: " + e.getMessage()); });
            }
        }).start();
    }

    private void chooseAction(String account, String servicePwd, JSONArray cloudVaults, int k) {
        String[] actions = {"推送到服务器（云端新增一份）", "从服务器拉取（选一份覆盖本地）"};
        new AlertDialog.Builder(this).setTitle("选择同步动作")
                .setItems(actions, (d, which) -> {
                    if (which == 0) confirmPush(account, servicePwd);
                    else pullFromServer(account, servicePwd, cloudVaults, k);
                })
                .setNegativeButton("取消", null).show();
    }

    // ---- 推送 ----
    private void confirmPush(String account, String servicePwd) {
        JSONObject meta = storage.loadMeta(vid());
        if (meta.optBoolean("never_uploaded", true)) {
            new AlertDialog.Builder(this).setTitle("首次推送")
                    .setMessage("当前库 #" + vid() + " 有尚未上传的改动。将把它推送到 @" + account
                            + " 名下，云端新增一份（每账号最多 5 份，最旧的自动淘汰）。")
                    .setPositiveButton("推送", (d, w) -> doPush(account, servicePwd))
                    .setNegativeButton("取消", null).show();
        } else {
            doPush(account, servicePwd);
        }
    }

    private void doPush(String account, String servicePwd) {
        // 一次性捕获，防止中途切库导致把 meta/密文写到别的 vid
        final String vid0 = vid();
        final Vault v0 = vault();
        // B2 残留修复：一次性原子取 key/salt 快照（分两次调用中间可能被改密错配）
        VaultHolder.KeySalt ks = VaultHolder.get().getKeySalt();
        final byte[] key = ks == null ? null : ks.key;
        final byte[] salt = ks == null ? null : ks.salt;
        if (vid0 == null || v0 == null) { toast("请先在首页打开一个库"); return; }
        // 审计报告 A4/A5：UI 线程一次性完成序列化+加密快照；后台零共享可变状态
        final byte[] blob;
        final long pwdTime = v0.pwdTime;
        final String label = v0.label;
        final long modifiedAt = v0.modifiedAt;
        final int recCount;
        final long seq0 = v0.dirtySeq;   // 快门号：上传期间又改过就不盖章
        try {
            blob = Crypto.encryptVault(v0.toJson(), key, salt);
            recCount = v0.activeRecords().size();
        } catch (Exception e) {
            toast("序列化失败: " + e.getMessage());
            return;
        }
        status.setText("推送中…");
        new Thread(() -> {
            try {
                // 后台只写快照字节与 meta，不触碰共享 Vault 对象
                storage.saveVaultSnapshot(vid0, blob, pwdTime, modifiedAt,
                                          label, recCount, true);
                SyncClient c = newClient(account, servicePwd);
                JSONObject resp = c.putVault(pwdTime, label, blob);
                int cloudVid = resp.optInt("vid");
                long uploadTime = resp.optLong("upload_time");
                int kept = resp.optInt("kept");
                boolean unchanged = v0.dirtySeq == seq0;
                JSONObject meta = storage.loadMeta(vid0);
                meta.put("last_account", account);
                if (unchanged) {
                    meta.put("never_uploaded", false);
                    if (uploadTime > 0) {
                        meta.put("modified_at", uploadTime);
                        v0.modifiedAt = uploadTime; // 详情页"最近修改"同步刷新
                    }
                }
                storage.saveMeta(vid0, meta);
                storage.setLastAccount(account);
                storage.logSync(vid0, "推送 ok @" + account + " 云端#" + cloudVid
                        + " 保留" + kept + "/5" + (unchanged ? "" : " (期间有本地修改)"));
                runOnUiThread(() -> {
                    if (isFinishing() || isDestroyed()) return;
                    if (vid0.equals(vid())) refreshList();
                    status.setText(unchanged
                            ? "推送成功 · 云端新增第 " + cloudVid + " 份（现保留 " + kept + "/5 份）"
                            : "推送成功，但期间有新修改，云端是旧快照，请再推送一次");
                });
            } catch (SyncClient.AuthException e) {
                runOnUiThread(() -> { if (isFinishing()) return; status.setText("推送失败"); toast("用户密码错误"); });
            } catch (Exception e) {
                runOnUiThread(() -> { if (isFinishing()) return; status.setText("推送失败"); toast("推送失败: " + e.getMessage()); });
            }
        }).start();
    }

    // ---- 拉取 ----
    private void pullFromServer(String account, String servicePwd, JSONArray cloudVaults, int k) {
        if (k == 0) { toast("云端暂无可拉取的库"); return; }
        final String vid0 = vid();
        final ArrayList<JSONObject> items = new ArrayList<>();
        String[] labels = new String[cloudVaults.length()];
        for (int i = 0; i < cloudVaults.length(); i++) {
            JSONObject v = cloudVaults.optJSONObject(i);
            items.add(v);
            labels[i] = Account.serverVaultLabel(v);
        }
        new AlertDialog.Builder(this).setTitle("选择云端库（最新在前）")
                .setItems(labels, (d, which) -> {
                    JSONObject chosen = items.get(which);
                    int cloudVid = chosen.optInt("vid");
                    boolean neverUploaded = storage.loadMeta(vid0).optBoolean("never_uploaded", true);
                    if (neverUploaded) {
                        new AlertDialog.Builder(this).setTitle("确认覆盖")
                                .setMessage("本地库 #" + vid0 + " 有尚未推送的改动，拉取将覆盖且不可恢复。继续？")
                                .setPositiveButton("覆盖", (dd, ww) ->
                                        downloadAndOverwrite(account, servicePwd, cloudVid, vid0))
                                .setNegativeButton("取消", null).show();
                    } else {
                        downloadAndOverwrite(account, servicePwd, cloudVid, vid0);
                    }
                })
                .setNegativeButton("取消", null).show();
    }

    private void downloadAndOverwrite(String account, String servicePwd, int cloudVid, String vid0) {
        final String pw0 = password();
        status.setText("下载中…");
        new Thread(() -> {
            try {
                SyncClient c = newClient(account, servicePwd);
                JSONObject entry = c.getVault(cloudVid);
                byte[] bytes = Base64.getDecoder().decode(entry.getString("ciphertext"));
                runOnUiThread(() -> {
                    if (isFinishing() || isDestroyed()) return;
                    tryOverwrite(vid0, account, bytes, cloudVid, pw0);
                });
            } catch (SyncClient.NotFoundException e) {
                runOnUiThread(() -> { if (isFinishing()) return; status.setText("拉取失败"); toast("云端无该份或不属于本账号"); });
            } catch (SyncClient.AuthException e) {
                runOnUiThread(() -> { if (isFinishing()) return; status.setText("拉取失败"); toast("用户密码错误"); });
            } catch (Exception e) {
                runOnUiThread(() -> { if (isFinishing()) return; status.setText("拉取失败"); toast("下载失败: " + e.getMessage()); });
            }
        }).start();
    }

    /** 用给定密码库密码尝试解密并覆盖指定 vid；失败则询问其它密码。 */
    private void tryOverwrite(String vid0, String account, byte[] bytes, int cloudVid, String pw) {
        try {
            Crypto.Opened opened = Crypto.openVault(bytes, pw);
            Vault parsed = Vault.fromJson(opened.plaintext);
            applyOverwrite(vid0, account, bytes, parsed, opened.key, opened.salt, pw, cloudVid);
        } catch (Crypto.UnlockException e) {
            askPasswordToOverwrite(vid0, account, bytes, cloudVid);
        } catch (Exception e) {
            toast("解密失败: " + e.getMessage());
        }
    }

    private void askPasswordToOverwrite(String vid0, String account, byte[] bytes, int cloudVid) {
        View dlg = LayoutInflater.from(this).inflate(R.layout.dialog_password, null);
        dlg.findViewById(R.id.pw2_label).setVisibility(View.GONE);
        dlg.findViewById(R.id.pw2).setVisibility(View.GONE);
        ((TextView) dlg.findViewById(R.id.desc)).setText("当前密码库密码无法解密云端这份。请输入该云端库的密码库密码。");
        EditText pw = dlg.findViewById(R.id.pw);
        AlertDialog d = new AlertDialog.Builder(this).setTitle("输入密码库密码").setView(dlg)
                .setPositiveButton("解密", null)
                .setNegativeButton("取消", null).create();
        Ui.keepOpen(d, () -> {
            String p = pw.getText().toString();
            try {
                Crypto.Opened opened = Crypto.openVault(bytes, p);
                Vault parsed = Vault.fromJson(opened.plaintext);
                d.dismiss();
                applyOverwrite(vid0, account, bytes, parsed, opened.key, opened.salt, p, cloudVid);
            } catch (Crypto.UnlockException e) {
                toast("密码库密码错误或数据损坏");
            } catch (Exception e) {
                toast("解密失败: " + e.getMessage());
            }
        });
        d.show();
    }

    private void applyOverwrite(String vid0, String account, byte[] bytes, Vault parsed,
                                byte[] key, byte[] salt, String pw, int cloudVid) {
        try {
            storage.overwriteFromBytes(vid0, bytes, parsed, account);
            storage.logSync(vid0, "拉取覆盖 ok @" + account + " 云端#" + cloudVid);
            // 若该库仍是解锁会话，替换其内容/凭据；不改变"当前库"指针
            VaultHolder.get().updateSession(vid0, parsed, pw, key, salt);
            boolean current = vid0.equals(VaultHolder.get().getVid());
            if (current) {
                refreshList();
                status.setText("拉取成功 · 已用云端 #" + cloudVid + " 覆盖本地库 #" + vid0);
            } else {
                toast("库 #" + vid0 + " 已用云端 #" + cloudVid + " 覆盖（当前库未变）");
            }
        } catch (Exception e) {
            toast("覆盖失败: " + e.getMessage());
        }
    }

    // ---- 注册（同步场景下） ----
    private void showRegister() {
        View dlg = LayoutInflater.from(this).inflate(R.layout.dialog_register, null);
        EditText acct = dlg.findViewById(R.id.account);
        EditText p1 = dlg.findViewById(R.id.service_pwd);
        EditText p2 = dlg.findViewById(R.id.service_pwd2);
        EditText phone = dlg.findViewById(R.id.phone);
        EditText email = dlg.findViewById(R.id.email);
        AlertDialog d = new AlertDialog.Builder(this).setTitle("注册服务器账号").setView(dlg)
                .setPositiveButton("注册", null)
                .setNegativeButton("取消", null).create();
        Ui.keepOpen(d, () -> {
            String u = acct.getText().toString().trim();
            String p = p1.getText().toString();
            if (!Account.validUsername(u)) { toast("用户名不合规"); return; }
            if (p.length() < 8) { toast("用户密码至少 8 位"); return; }
            if (!p.equals(p2.getText().toString())) { toast("两次密码不一致"); return; }
            String ph = phone.getText().toString().trim();
            String em = email.getText().toString().trim();
            if (ph.isEmpty() && em.isEmpty()) { toast("手机号与邮箱至少填一项"); return; }
            d.dismiss();
            doRegister(u, p, ph, em);
        });
        d.show();
    }

    private void doRegister(String account, String servicePwd, String phone, String email) {
        new Thread(() -> {
            try {
                SyncClient c = newClient(account, servicePwd);
                c.register(servicePwd, email, phone, null, null, null);
                runOnUiThread(() -> toast("注册成功，可登录后推拉"));
            } catch (SyncClient.UsernameTakenException e) {
                runOnUiThread(() -> toast("用户名已被占用"));
            } catch (Exception e) {
                runOnUiThread(() -> toast("注册失败: " + e.getMessage()));
            }
        }).start();
    }

    private SyncClient newClient(String account, String servicePwd) {
        String fp = storage.getCertFingerprint();
        return new SyncClient(storage.getServerUrl(), account, servicePwd, fp.isEmpty() ? null : fp);
    }

    // ---- CSV 导出 ----
    private void exportCsv() {
        int n;
        try { n = vault().activeRecords().size(); } catch (Exception e) { n = 0; }
        if (n == 0) { toast("当前没有可导出的记录"); return; }
        new AlertDialog.Builder(this)
                .setTitle("导出明文警告")
                .setMessage("将导出 " + n + " 条记录为 CSV，包含明文密码/API Key。\n"
                        + "导出文件不受加密保护，请用后及时删除。\n\n导出到 App 外部 Documents 目录。")
                .setPositiveButton("继续", (d, w) -> doExport())
                .setNegativeButton("取消", null).show();
    }

    private void doExport() {
        try {
            File dir = getExternalFilesDir(null);
            if (dir == null) dir = getFilesDir();
            File dest = new File(dir, Storage.defaultExportName());
            storage.exportCsv(vault(), dest);
            new AlertDialog.Builder(this).setTitle("已导出")
                    .setMessage("已导出到：\n" + dest.getAbsolutePath() + "\n\n请妥善保管并及时删除该明文文件。")
                    .setPositiveButton("好", null).show();
        } catch (Exception e) {
            toast("导出失败: " + e.getMessage());
        }
    }

    // ---- 切换库：清内存回到首页 ----
    private void switchVault() {
        if (clipClearRunnable != null) handler.removeCallbacks(clipClearRunnable);
        ClipboardGuard.clearIfOurs(this);
        // 只回首页换库，保留本进程已解锁会话（切回来免重输）；划走最近任务才清空。
        startActivity(new Intent(this, HomeActivity.class));
        finish();
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.main_menu, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        if (item.getItemId() == R.id.menu_settings) {
            startActivity(new Intent(this, SettingsActivity.class));
            return true;
        }
        return super.onOptionsItemSelected(item);
    }

    private void toast(String m) { Toast.makeText(this, m, Toast.LENGTH_SHORT).show(); }
}

package com.pwdmgr;

import android.os.Bundle;
import android.content.Intent;
import android.text.InputType;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.Toast;

import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;

import org.json.JSONObject;

import java.io.File;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

/** 服务器设置 + 账号操作（改用户密码 / 注销）。不含令牌，服务密码走 SecretStore。 */
public class SettingsActivity extends AppCompatActivity {

    private Storage storage;
    private EditText url, fingerprint, clipSecs;

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        setContentView(R.layout.activity_settings);
        storage = new Storage(this);

        url = findViewById(R.id.server_url);
        fingerprint = findViewById(R.id.cert_fp);
        clipSecs = findViewById(R.id.clip_secs);

        url.setText(storage.getServerUrl());
        fingerprint.setText(storage.getCertFingerprint());
        clipSecs.setText(String.valueOf(storage.getClipboardClearSeconds()));

        Button save = findViewById(R.id.save);
        Button test = findViewById(R.id.test_conn);
        save.setOnClickListener(v -> saveConfig());
        test.setOnClickListener(v -> testConnection());
        findViewById(R.id.change_vault_pwd).setOnClickListener(v -> showChangeVaultPwd());
        findViewById(R.id.enable_autofill).setOnClickListener(v -> openAutofillPicker());
        findViewById(R.id.change_pwd).setOnClickListener(v -> showChangePwd());
        findViewById(R.id.delete_account).setOnClickListener(v -> showDeleteAccount());
    }

    // ---- 设为系统自动填充服务 ----
    private void openAutofillPicker() {
        try {
            android.content.ComponentName svc =
                    new android.content.ComponentName(getPackageName(), PwdMgrAutofillService.class.getName());
            Intent i = new Intent(android.provider.Settings.ACTION_REQUEST_SET_AUTOFILL_SERVICE);
            i.setData(android.net.Uri.parse("package:" + svc.flattenToShortString()));
            startActivity(i);
        } catch (Exception e) {
            toast("此系统不支持自动填充设置，请在系统设置→密码与自动填充中手动选择");
        }
    }

    // ---- 改密码库密码（本机主密钥，仅覆盖当前 vid，服务器无感）----
    private void showChangeVaultPwd() {
        final VaultHolder holder = VaultHolder.get();
        if (!holder.isUnlocked()) {
            toast("请先在首页打开一个库");
            return;
        }
        final String vid = holder.getVid();
        EditText cur = input("当前密码库密码", true);
        EditText np1 = input("新密码库密码（至少 8 位）", true);
        EditText np2 = input("确认新密码库密码", true);
        LinearLayout box = verticalBox(cur, np1, np2);
        AlertDialog d = new AlertDialog.Builder(this)
                .setTitle("修改密码库密码 · 库 #" + vid).setView(box)
                .setMessage("仅在本机用新密码重新加密当前库，不会上传服务器。\n"
                        + "规范要求：改密前先导出一份明文 CSV 备份。")
                .setPositiveButton("修改", null)
                .setNegativeButton("取消", null).create();
        Ui.keepOpen(d, () -> {
            String c = cur.getText().toString();
            String p1 = np1.getText().toString();
            String p2 = np2.getText().toString();
            if (!c.equals(holder.getPassword())) { toast("当前密码库密码错误"); return; }
            if (p1.length() < 8) { toast("新密码库密码至少 8 位"); return; }
            if (!p1.equals(p2)) { toast("两次输入的新密码不一致"); return; }
            if (!exportBeforePwdChange(holder)) return;  // 导出失败则中止改密
            d.dismiss();
            changeVaultPwd(vid, holder, p1);
        });
        d.show();
    }

    /** 规范 §12.3：改密前必须成功导出一份 CSV，失败则禁止改密。 */
    private boolean exportBeforePwdChange(VaultHolder holder) {
        Vault v = holder.getVault();
        if (v == null) return false;
        try {
            File dir = getExternalFilesDir(null);
            if (dir == null) dir = getFilesDir();
            String name = "pwdmgr_before_pwd_change_"
                    + new SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(new Date()) + ".csv";
            File dest = new File(dir, name);
            storage.exportCsv(v, dest);
            toast("改密前备份已导出：\n" + dest.getAbsolutePath());
            return true;
        } catch (Exception e) {
            toast("改密前导出备份失败，已中止：" + e.getMessage());
            return false;
        }
    }

    private void changeVaultPwd(String vid, VaultHolder holder, String newPwd) {
        // Vault 是 UI 线程与后台线程共享对象：label/pwdTime/touch 只能在 UI 线程改，
        // 后台只做 Argon2 派生与落盘，避免与界面并发读写 JSONObject。
        final Vault v = holder.getVault();
        long now = System.currentTimeMillis();
        String today = new SimpleDateFormat("yyyy-MM-dd", Locale.US).format(new Date(now));
        String oldDay = new SimpleDateFormat("yyyy-MM-dd", Locale.US).format(new Date(v.pwdTime));
        final long oldPwdTime = v.pwdTime;
        final String oldLabel = v.label;
        if (!today.equals(oldDay)) v.label = "改密 " + today;   // §5.3：跨天才换 label
        v.pwdTime = now;
        v.touch();
        toast("重新加密中…");
        new Thread(() -> {
            try {
                byte[] salt = Crypto.newSalt();
                byte[] key = Crypto.deriveKey(newPwd, salt,
                        Crypto.ARGON_M, Crypto.ARGON_T, Crypto.ARGON_P);
                storage.saveVault(vid, v, key, salt, true); // 未推送前一直标记未同步
                holder.setCredentials(newPwd, key, salt);
                storage.logSync(vid, "改密码库密码 label=" + v.label + " (未同步)");
                runOnUiThread(() -> toast("密码库密码已修改（记得重新推送以更新云端）"));
            } catch (Exception e) {
                // 落盘失败：把内存里的 label/pwdTime 也回滚，避免界面与实际文件不一致
                v.pwdTime = oldPwdTime;
                v.label = oldLabel;
                v.touch();
                runOnUiThread(() -> toast("修改失败: " + e.getMessage()));
            }
        }).start();
    }

    private void saveConfig() {
        String u = url.getText().toString().trim();
        if (!u.startsWith("https://") || u.length() <= "https://".length()) {
            toast("出于安全考虑只允许 https://host:port 形式的服务器地址");
            return;
        }
        storage.setServerUrl(u);
        storage.setCertFingerprint(fingerprint.getText().toString().trim());
        int secs;
        try { secs = Integer.parseInt(clipSecs.getText().toString().trim()); }
        catch (Exception e) { secs = 30; }
        storage.setClipboardClearSeconds(Math.max(0, secs));
        toast("设置已保存");
        finish();
    }

    private void testConnection() {
        String u = url.getText().toString().trim();
        String fp = fingerprint.getText().toString().trim();
        if (u.isEmpty()) { toast("请先填写服务器地址"); return; }
        toast("测试中…");
        new Thread(() -> {
            try {
                SyncClient c = new SyncClient(u, "health-check", "x", fp.isEmpty() ? null : fp);
                JSONObject h = c.health();
                boolean ok = "ok".equals(h.optString("status"));
                runOnUiThread(() -> toast(ok ? "连接成功 · 服务器可达" : "响应异常"));
            } catch (SyncClient.PinException e) {
                runOnUiThread(() -> toast("证书指纹不匹配：" + e.getMessage()));
            } catch (Exception e) {
                runOnUiThread(() -> toast("连接失败: " + e.getMessage()));
            }
        }).start();
    }

    // ---- 改用户密码 ----
    private void showChangePwd() {
        EditText account = input("用户名", false);
        EditText oldPwd = input("当前用户密码", true);
        EditText newPwd = input("新用户密码", true);
        EditText newPwd2 = input("确认新用户密码", true);
        LinearLayout box = verticalBox(account, oldPwd, newPwd, newPwd2);
        AlertDialog d = new AlertDialog.Builder(this).setTitle("修改用户密码").setView(box)
                .setPositiveButton("修改", null)
                .setNegativeButton("取消", null).create();
        Ui.keepOpen(d, () -> {
            String u = account.getText().toString().trim();
            String op = oldPwd.getText().toString();
            String np = newPwd.getText().toString();
            if (!Account.validUsername(u)) { toast("用户名不合规"); return; }
            if (np.length() < 8) { toast("新用户密码至少 8 位"); return; }
            if (!np.equals(newPwd2.getText().toString())) { toast("两次输入的新密码不一致"); return; }
            d.dismiss();
            changePwd(u, op, np);
        });
        d.show();
    }

    private void changePwd(String account, String oldPwd, String newPwd) {
        toast("提交中…");
        new Thread(() -> {
            try {
                SyncClient c = newClient(account, oldPwd);
                c.changeServicePwd(newPwd);
                if (storage.getRememberServicePwd()) {
                    SecretStore.saveServicePwd(this, account, newPwd);
                } else {
                    SecretStore.deleteServicePwd(this, account);
                }
                storage.setLastAccount(account);
                runOnUiThread(() -> toast("用户密码已修改"));
            } catch (SyncClient.AuthException e) {
                runOnUiThread(() -> toast("当前用户密码错误"));
            } catch (Exception e) {
                runOnUiThread(() -> toast("修改失败: " + e.getMessage()));
            }
        }).start();
    }

    // ---- 注销账号 ----
    private void showDeleteAccount() {
        new AlertDialog.Builder(this).setTitle("注销服务器账号")
                .setMessage("这将永久删除该账号在服务器上的全部云端库（不可恢复）。\n本地库不受影响。\n\n确认继续？")
                .setPositiveButton("继续", (d, w) -> askDeleteCreds())
                .setNegativeButton("取消", null).show();
    }

    private void askDeleteCreds() {
        EditText account = input("用户名", false);
        EditText pwd = input("用户密码", true);
        account.setText(storage.getLastAccount());
        if (!storage.getLastAccount().isEmpty()) {
            String saved = SecretStore.loadServicePwd(this, storage.getLastAccount());
            if (saved != null) pwd.setText(saved);
        }
        LinearLayout box = verticalBox(account, pwd);
        AlertDialog d = new AlertDialog.Builder(this).setTitle("确认注销").setView(box)
                .setPositiveButton("注销", null)
                .setNegativeButton("取消", null).create();
        Ui.keepOpen(d, () -> {
            String u = account.getText().toString().trim();
            String p = pwd.getText().toString();
            if (!Account.validUsername(u)) { toast("用户名不合规"); return; }
            if (p.isEmpty()) { toast("请输入用户密码"); return; }
            d.dismiss();
            deleteAccount(u, p);
        });
        d.show();
    }

    private void deleteAccount(String account, String pwd) {
        toast("提交中…");
        new Thread(() -> {
            try {
                SyncClient c = newClient(account, pwd);
                c.deleteAccount();
                SecretStore.deleteServicePwd(this, account);
                runOnUiThread(() -> toast("账号已注销，云端库已全部删除"));
            } catch (SyncClient.AuthException e) {
                runOnUiThread(() -> toast("用户名或用户密码错误"));
            } catch (Exception e) {
                runOnUiThread(() -> toast("注销失败: " + e.getMessage()));
            }
        }).start();
    }

    private SyncClient newClient(String account, String servicePwd) {
        String fp = storage.getCertFingerprint();
        return new SyncClient(storage.getServerUrl(), account, servicePwd, fp.isEmpty() ? null : fp);
    }

    private EditText input(String hint, boolean password) {
        EditText e = new EditText(this);
        e.setHint(hint);
        e.setInputType(password ? InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD
                : InputType.TYPE_CLASS_TEXT);
        return e;
    }

    private LinearLayout verticalBox(View... views) {
        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        int pad = (int) (16 * getResources().getDisplayMetrics().density);
        box.setPadding(pad, pad, pad, pad);
        for (View v : views) box.addView(v);
        return box;
    }

    private void toast(String m) { Toast.makeText(this, m, Toast.LENGTH_SHORT).show(); }
}

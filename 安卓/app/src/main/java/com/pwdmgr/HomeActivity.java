package com.pwdmgr;

import android.content.Intent;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.ListView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.Base64;

/**
 * 首页（v2.3）：三按钮 —— 打开本地库 / 新建本地库 / 登录服务器拉取，外加本地库列表。
 * 镜像电脑端首页。替代旧 UnlockActivity 成为 LAUNCHER 入口。
 */
public class HomeActivity extends AppCompatActivity {

    private Storage storage;
    private ListView vaultList;
    private boolean autofillUnlock;   // 由自动填充的认证 PendingIntent 拉起

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        setContentView(R.layout.activity_home);
        storage = new Storage(this);
        autofillUnlock = getIntent() != null
                && getIntent().getBooleanExtra("autofill_unlock", false);
        vaultList = findViewById(R.id.vault_list);

        findViewById(R.id.open_local).setOnClickListener(v -> pickLocalVault());
        findViewById(R.id.new_local).setOnClickListener(v -> newLocalVault());
        findViewById(R.id.pull_cloud).setOnClickListener(v -> startPullCloud());
        findViewById(R.id.refresh).setOnClickListener(v -> refreshVaultList());
        findViewById(R.id.menu_settings).setOnClickListener(v ->
                startActivity(new Intent(this, SettingsActivity.class)));

        vaultList.setOnItemClickListener((p, view, pos, id) -> {
            JSONObject m = (JSONObject) view.getTag();
            if (m != null) openExisting(m.optString("vid"));
        });
        // 长按删除本地库（只删本机文件，不动云端）
        vaultList.setOnItemLongClickListener((p, view, pos, id) -> {
            JSONObject m = (JSONObject) view.getTag();
            if (m != null) confirmDeleteVault(m.optString("vid"), Account.localVaultLabel(m));
            return true;
        });
    }

    @Override
    protected void onResume() {
        super.onResume();
        refreshVaultList();
    }

    // ---- 本地库列表 ----
    private void refreshVaultList() {
        ArrayList<JSONObject> metas = storage.listVaults();
        ArrayList<String> labels = new ArrayList<>();
        for (JSONObject m : metas) labels.add(Account.localVaultLabel(m));
        vaultList.setAdapter(new android.widget.ArrayAdapter<>(this,
                android.R.layout.simple_list_item_1, labels) {
            @Override
            public View getView(int position, View convertView, android.view.ViewGroup parent) {
                View v = super.getView(position, convertView, parent);
                ((TextView) v).setTag(metas.get(position));
                return v;
            }
        });
    }

    private void pickLocalVault() {
        ArrayList<JSONObject> metas = storage.listVaults();
        if (metas.isEmpty()) { toast("本机还没有密码库，请先新建或从服务器拉取"); return; }
        String[] labels = new String[metas.size()];
        for (int i = 0; i < metas.size(); i++) labels[i] = Account.localVaultLabel(metas.get(i));
        new AlertDialog.Builder(this).setTitle("打开本地库")
                .setItems(labels, (d, which) -> openExisting(metas.get(which).optString("vid")))
                .setNegativeButton("取消", null).show();
    }

    private void openExisting(String vid) {
        storage.setLastVid(vid);
        // 本进程已解锁过该库 → 直接设为当前进入，免再输密码。
        if (VaultHolder.get().resume(vid)) {
            enterMain();
            return;
        }
        Intent i = new Intent(this, UnlockActivity.class);
        i.putExtra("vid", vid);
        i.putExtra("autofill_unlock", autofillUnlock);
        startActivity(i);
    }

    /** 进入主界面；若是自动填充的认证流程，关闭本页以让系统重新发起填充。 */
    private void enterMain() {
        startActivity(new Intent(this, MainActivity.class));
        if (autofillUnlock) finish();
    }

    /** 长按删除：永久删除本机 vaults/<vid>/，云端与其它库不受影响。 */
    private void confirmDeleteVault(String vid, String label) {
        boolean isCurrent = vid.equals(VaultHolder.get().getVid());
        String extra = isCurrent ? "\n\n该库当前处于解锁状态，删除后会立即回到首页。" : "";
        new AlertDialog.Builder(this).setTitle("删除本地库 #" + vid)
                .setMessage("将永久删除本机的「" + label + "」，含 vault.enc / meta / 日志。\n"
                        + "只删本机文件，不影响云端账号与云端历史库。" + extra
                        + "\n\n确定删除？")
                .setPositiveButton("删除", (d, w) -> {
                    storage.deleteVault(vid);
                    VaultHolder.get().drop(vid);
                    if (vid.equals(storage.getLastVid())) storage.setLastVid("");
                    refreshVaultList();
                    toast("已删除本地库 #" + vid);
                })
                .setNegativeButton("取消", null).show();
    }

    // ---- 新建本地库 ----
    private void newLocalVault() {
        View dlg = LayoutInflater.from(this).inflate(R.layout.dialog_password, null);
        EditText pw = dlg.findViewById(R.id.pw);
        EditText pw2 = dlg.findViewById(R.id.pw2);
        AlertDialog d = new AlertDialog.Builder(this)
                .setTitle("新建本地库").setView(dlg)
                .setPositiveButton("创建", null)
                .setNegativeButton("取消", null).create();
        Ui.keepOpen(d, () -> {
            String p = pw.getText().toString();
            if (p.length() < 8) { toast("密码库密码至少 8 位"); return; }
            if (!p.equals(pw2.getText().toString())) { toast("两次输入不一致"); return; }
            try {
                Storage.NewVault nv = storage.createVault(p, storage.getLastAccount());
                VaultHolder.get().unlock(nv.vid, nv.vault, p, nv.key, nv.salt);
                storage.setLastVid(nv.vid);
                d.dismiss();
                enterMain();
            } catch (Exception e) {
                toast("创建失败: " + e.getMessage());
            }
        });
        d.show();
    }

    // ---- 登录服务器拉取（落地为新 vid）----
    private void startPullCloud() {
        View dlg = LayoutInflater.from(this).inflate(R.layout.dialog_login, null);
        EditText acct = dlg.findViewById(R.id.account);
        EditText spwd = dlg.findViewById(R.id.service_pwd);
        CheckBox remember = dlg.findViewById(R.id.remember);
        String lastAcct = storage.getLastAccount();
        boolean rem = storage.getRememberServicePwd();
        acct.setText(lastAcct);
        remember.setChecked(rem);
        if (rem && !lastAcct.isEmpty()) {
            String saved = SecretStore.loadServicePwd(this, lastAcct);
            if (saved != null) spwd.setText(saved);
        }
        AlertDialog d = new AlertDialog.Builder(this)
                .setTitle("登录服务器")
                .setView(dlg)
                .setNeutralButton("注册账号", (dd, w) -> showRegister())
                .setPositiveButton("登录", null)
                .setNegativeButton("取消", null).create();
        dlg.findViewById(R.id.forgot).setOnClickListener(v -> ForgotPwd.show(this, storage));
        Ui.keepOpen(d, () -> {
            String u = acct.getText().toString().trim();
            String p = spwd.getText().toString();
            boolean rm = remember.isChecked();
            if (!Account.validUsername(u)) {
                toast("用户名不合规（字母数字，可含 . _ -，3-20 位，不能全数字）"); return;
            }
            if (p.isEmpty()) { toast("请输入用户密码"); return; }
            storage.setRememberServicePwd(rm);
            d.dismiss();
            loginAndList(u, p, rm);
        });
        d.show();
    }

    /** 认证并列出云端库；成功后弹选库对话框。 */
    private void loginAndList(String account, String servicePwd, boolean remember) {
        toast("登录中…");
        new Thread(() -> {
            try {
                SyncClient c = new SyncClient(storage.getServerUrl(), account, servicePwd,
                        storage.getCertFingerprint().isEmpty() ? null : storage.getCertFingerprint());
                JSONArray vaults = c.listVaults();
                if (remember) SecretStore.saveServicePwd(this, account, servicePwd);
                else SecretStore.deleteServicePwd(this, account);
                storage.setLastAccount(account);
                runOnUiThread(() -> {
                    ForgotPwd.warnIfInitialPwd(this, servicePwd);
                    int k = vaults == null ? 0 : vaults.length();
                    if (k == 0) {
                        new AlertDialog.Builder(this).setTitle("登录成功")
                                .setMessage("账号 " + account + " 云端暂无密码库。\n"
                                        + "可先「新建本地库」再在同步里推送。")
                                .setPositiveButton("好", null).show();
                        return;
                    }
                    pickCloudVault(account, servicePwd, vaults);
                });
            } catch (SyncClient.AuthException e) {
                runOnUiThread(() -> toast("用户名或用户密码错误"));
            } catch (SyncClient.PinException e) {
                runOnUiThread(() -> toast(e.getMessage()));
            } catch (Exception e) {
                runOnUiThread(() -> toast("连接失败: " + e.getMessage()));
            }
        }).start();
    }

    private void pickCloudVault(String account, String servicePwd, JSONArray vaults) {
        final ArrayList<JSONObject> items = new ArrayList<>();
        String[] labels = new String[vaults.length()];
        for (int i = 0; i < vaults.length(); i++) {
            JSONObject v = vaults.optJSONObject(i);
            items.add(v);
            labels[i] = Account.serverVaultLabel(v);
        }
        new AlertDialog.Builder(this).setTitle("选择云端库（共 " + vaults.length() + " 份，最新在前）")
                .setItems(labels, (d, which) -> {
                    JSONObject chosen = items.get(which);
                    int cloudVid = chosen.optInt("vid");
                    downloadAndDecrypt(account, servicePwd, cloudVid);
                })
                .setNegativeButton("取消", null).show();
    }

    /** 下载指定云端份，再询问密码库密码解密，成功则落地为新本地 vid。 */
    private void downloadAndDecrypt(String account, String servicePwd, int cloudVid) {
        new Thread(() -> {
            try {
                SyncClient c = new SyncClient(storage.getServerUrl(), account, servicePwd,
                        storage.getCertFingerprint().isEmpty() ? null : storage.getCertFingerprint());
                JSONObject entry = c.getVault(cloudVid);
                byte[] bytes = Base64.getDecoder().decode(entry.getString("ciphertext"));
                runOnUiThread(() -> askVaultPasswordForCloud(bytes, account, cloudVid));
            } catch (SyncClient.NotFoundException e) {
                runOnUiThread(() -> toast("云端无该份或不属于本账号"));
            } catch (SyncClient.AuthException e) {
                runOnUiThread(() -> toast("用户密码错误"));
            } catch (Exception e) {
                runOnUiThread(() -> toast("下载失败: " + e.getMessage()));
            }
        }).start();
    }

    private void askVaultPasswordForCloud(byte[] vaultEncBytes, String account, int cloudVid) {
        View dlg = LayoutInflater.from(this).inflate(R.layout.dialog_password, null);
        dlg.findViewById(R.id.pw2_label).setVisibility(View.GONE);
        dlg.findViewById(R.id.pw2).setVisibility(View.GONE);
        TextView desc = dlg.findViewById(R.id.desc);
        desc.setText("请输入该云端库的密码库密码以解密。它用于本机加密，服务器不保存。");
        EditText pw = dlg.findViewById(R.id.pw);
        AlertDialog d = new AlertDialog.Builder(this).setTitle("解密云端库").setView(dlg)
                .setPositiveButton("解密", null)
                .setNegativeButton("取消", null).create();
        Ui.keepOpen(d, () -> {
            String p = pw.getText().toString();
            try {
                Crypto.Opened opened = Crypto.openVault(vaultEncBytes, p);
                Vault parsed = Vault.fromJson(opened.plaintext);
                String vid = storage.landNewVaultFromBytes(vaultEncBytes, parsed, account);
                storage.logSync(vid, "登录拉取 ok @" + account + " 云端#" + cloudVid);
                VaultHolder.get().unlock(vid, parsed, p, opened.key, opened.salt);
                storage.setLastVid(vid);
                storage.setLastAccount(account);
                d.dismiss();
                enterMain();
            } catch (Crypto.UnlockException e) {
                toast("密码库密码错误或数据损坏");
            } catch (Exception e) {
                toast("解密失败: " + e.getMessage());
            }
        });
        d.show();
    }

    // ---- 注册账号（仅建服务器账号，云端零份库）----
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
                SyncClient c = new SyncClient(storage.getServerUrl(), account, servicePwd,
                        storage.getCertFingerprint().isEmpty() ? null : storage.getCertFingerprint());
                c.register(servicePwd, email, phone, null, null, null);
                storage.setLastAccount(account);
                runOnUiThread(() -> {
                    toast("注册成功，请登录拉取");
                    startPullCloud();
                });
            } catch (SyncClient.UsernameTakenException e) {
                runOnUiThread(() -> toast("用户名已被占用"));
            } catch (Exception e) {
                runOnUiThread(() -> toast("注册失败: " + e.getMessage()));
            }
        }).start();
    }

    private void toast(String m) { Toast.makeText(this, m, Toast.LENGTH_SHORT).show(); }
}

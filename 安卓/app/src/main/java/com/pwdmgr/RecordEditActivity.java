package com.pwdmgr;

import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.RadioButton;
import android.widget.RadioGroup;
import android.widget.Toast;

import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;

import org.json.JSONObject;

/** 新增 / 编辑记录。type=login 显示网址/用户名/密码；type=apikey 显示 key。 */
public class RecordEditActivity extends AppCompatActivity {

    private Storage storage;
    private String editId = null;

    private RadioGroup typeGroup;
    private RadioButton typeLogin, typeApikey;
    private EditText title, url, username, password, apikey, note;
    private View loginFields, apikeyFields;

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        setContentView(R.layout.activity_record_edit);
        storage = new Storage(this);

        typeGroup = findViewById(R.id.type_group);
        typeLogin = findViewById(R.id.type_login);
        typeApikey = findViewById(R.id.type_apikey);
        title = findViewById(R.id.title);
        url = findViewById(R.id.url);
        username = findViewById(R.id.username);
        password = findViewById(R.id.password);
        apikey = findViewById(R.id.apikey);
        note = findViewById(R.id.note);
        loginFields = findViewById(R.id.login_fields);
        apikeyFields = findViewById(R.id.apikey_fields);

        findViewById(R.id.gen_password).setOnClickListener(v -> showGenerator(password));
        findViewById(R.id.gen_apikey).setOnClickListener(v -> showGenerator(apikey));
        findViewById(R.id.save).setOnClickListener(v -> save());
        findViewById(R.id.cancel).setOnClickListener(v -> finish());

        typeGroup.setOnCheckedChangeListener((g, id) -> updateVisibility());

        if (!VaultHolder.get().isUnlocked()) {
            toast("会话已锁定，请重新打开密码库");
            finish();
            return;
        }

        editId = getIntent().getStringExtra("id");
        if (editId != null) {
            JSONObject rec = VaultHolder.get().getVault().get(editId);
            if (rec != null) {
                setTitle("编辑记录");
                if ("apikey".equals(rec.optString("type"))) typeApikey.setChecked(true);
                else typeLogin.setChecked(true);
                title.setText(rec.optString("title"));
                url.setText(rec.isNull("url") ? "" : rec.optString("url"));
                username.setText(rec.isNull("username") ? "" : rec.optString("username"));
                password.setText(rec.isNull("password") ? "" : rec.optString("password"));
                apikey.setText(rec.isNull("apikey") ? "" : rec.optString("apikey"));
                note.setText(rec.isNull("note") ? "" : rec.optString("note"));
            }
        } else {
            setTitle("新增记录");
        }
        updateVisibility();
    }

    @Override
    protected void onResume() {
        super.onResume();
        if (!VaultHolder.get().isUnlocked()) {
            // 会话已被清（划掉最近任务/进程重建）→ 不能在这里落库，回首页重新解锁
            toast("会话已锁定，请重新打开密码库");
            finish();
        }
    }

    private void updateVisibility() {
        boolean isKey = typeApikey.isChecked();
        loginFields.setVisibility(isKey ? View.GONE : View.VISIBLE);
        apikeyFields.setVisibility(isKey ? View.VISIBLE : View.GONE);
    }

    private void showGenerator(EditText target) {
        View dlg = getLayoutInflater().inflate(R.layout.dialog_generator, null);
        EditText lenInput = dlg.findViewById(R.id.gen_len);
        CheckBox symbols = dlg.findViewById(R.id.gen_symbols);
        EditText out = dlg.findViewById(R.id.gen_out);
        Button regen = dlg.findViewById(R.id.gen_regen);
        lenInput.setText("20");
        Runnable gen = () -> {
            int n = 20;
            try { n = Integer.parseInt(lenInput.getText().toString().trim()); } catch (Exception ignore) {}
            out.setText(PasswordGen.generate(n, symbols.isChecked()));
        };
        regen.setOnClickListener(v -> gen.run());
        gen.run();
        new AlertDialog.Builder(this).setTitle("密码生成器").setView(dlg)
                .setPositiveButton("使用", (d, w) -> target.setText(out.getText().toString()))
                .setNegativeButton("取消", null).show();
    }

    private void save() {
        String t = title.getText().toString().trim();
        if (t.isEmpty()) { toast("标题为必填项"); return; }
        boolean isKey = typeApikey.isChecked();
        try {
            Vault v = VaultHolder.get().getVault();
            if (isKey) {
                String key = apikey.getText().toString();
                String n = note.getText().toString();
                if (editId == null) v.add("apikey", t, null, null, null, key, n);
                else v.update(editId, "apikey", t, null, null, null, key, n);
            } else {
                String u = emptyToNull(url.getText().toString());
                String un = emptyToNull(username.getText().toString());
                String p = password.getText().toString();
                String n = note.getText().toString();
                if (editId == null) v.add("login", t, u, un, p, null, n);
                else v.update(editId, "login", t, u, un, p, null, n);
            }
            VaultHolder.KeySalt ks = VaultHolder.get().getKeySalt();
            if (ks == null) {
                // 审计报告 S6：会话刚被清时明确提示——输入保留在输入框里，
                // 重新解锁后用户可直接再点保存
                toast("会话已锁定，请重新解锁后重试保存");
                return;
            }
            storage.saveVault(VaultHolder.get().getVid(), v,
                    ks.key, ks.salt, true);
            finish();
        } catch (Exception e) {
            toast("保存失败: " + e.getMessage());
        }
    }

    private static String emptyToNull(String s) {
        s = s.trim();
        return s.isEmpty() ? null : s;
    }

    private void toast(String m) { Toast.makeText(this, m, Toast.LENGTH_SHORT).show(); }
}

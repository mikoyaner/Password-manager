package com.pwdmgr;

import android.content.Intent;
import android.os.Bundle;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import org.json.JSONObject;

/** 解锁已有本地库（vid）。只输入密码库密码，绝不上传、不落盘。 */
public class UnlockActivity extends AppCompatActivity {

    private Storage storage;
    private String vid;
    private EditText pw;

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        setContentView(R.layout.activity_unlock);
        storage = new Storage(this);
        vid = getIntent().getStringExtra("vid");
        if (vid == null || !storage.vaultExists(vid)) {
            toast("库不存在，请返回首页");
            startActivity(new Intent(this, HomeActivity.class));
            finish();
            return;
        }

        JSONObject meta = storage.loadMeta(vid);
        TextView hint = findViewById(R.id.hint);
        String label = meta.isNull("label") ? "" : meta.optString("label", "");
        hint.setText("库 #" + vid + (label.isEmpty() ? "" : " · " + label) + " — 请输入密码库密码解锁。");

        pw = findViewById(R.id.pw);
        Button ok = findViewById(R.id.ok);
        ok.setOnClickListener(v -> submit());
    }

    private void submit() {
        String p = pw.getText().toString();
        try {
            Storage.OpenedVault opened = storage.loadVaultEx(vid, p);
            VaultHolder.get().unlock(vid, opened.vault, p, opened.key, opened.salt);
            storage.setLastVid(vid);
            startActivity(new Intent(this, MainActivity.class));
            if (getIntent().getBooleanExtra("autofill_unlock", false)) {
                // 自动填充认证流程：连同首页一起关闭，让系统重新发起填充请求
                finishAffinity();
            } else {
                finish();
            }
        } catch (Crypto.UnlockException e) {
            toast("密码库密码错误或数据损坏");
        } catch (Exception e) {
            toast("打开失败: " + e.getMessage());
        }
    }

    private void toast(String m) { Toast.makeText(this, m, Toast.LENGTH_SHORT).show(); }
}

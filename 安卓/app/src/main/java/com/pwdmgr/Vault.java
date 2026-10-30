package com.pwdmgr;

import org.json.JSONException;
import org.json.JSONObject;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Iterator;
import java.util.List;
import java.util.UUID;

/**
 * 密码库数据模型（规范 §4）。整库覆盖式同步，无记录级合并、无 revision。
 * 顶层字段：username, pwd_time, modified_at, label, records。
 * 与电脑端 window/vault.py 逐字节兼容。
 */
public class Vault {

    public static final String TYPE_LOGIN = "login";
    public static final String TYPE_APIKEY = "apikey";

    /** 库内展示字段（非云端属主标签）。 */
    public String username = "";
    /** 密码库密码设定时刻(ms)：建库/改密时更新。纯元数据。 */
    public long pwdTime = 0;
    /** 内容最后修改时刻(ms)：touch() 更新；PUT 成功后用服务器 upload_time 刷新。 */
    public long modifiedAt = 0;
    /** 展示标签 ≤30。 */
    public String label = null;
    /** 本地内容修改计数（不入编、不同步）：推送前后比对，判断期间是否又改过。 */
    public long dirtySeq = 0;

    /** id -> record JSONObject */
    public final JSONObject records = new JSONObject();

    public Vault() {}

    public static long nowTs() { return System.currentTimeMillis(); }

    public static String newId() { return UUID.randomUUID().toString(); }

    // ---- 序列化 ----
    public byte[] toJson() throws JSONException {
        JSONObject root = new JSONObject();
        root.put("username", username);
        root.put("pwd_time", pwdTime);
        root.put("modified_at", modifiedAt);
        root.put("label", label == null ? JSONObject.NULL : label);
        root.put("records", records);
        return root.toString().getBytes(StandardCharsets.UTF_8);
    }

    public static Vault fromJson(byte[] data) throws JSONException {
        JSONObject root = new JSONObject(new String(data, StandardCharsets.UTF_8));
        Vault v = new Vault();
        v.username = root.optString("username", "");
        v.pwdTime = root.optLong("pwd_time", 0);
        v.modifiedAt = root.optLong("modified_at", 0);
        v.label = root.isNull("label") ? null : root.optString("label", null);
        JSONObject recs = root.optJSONObject("records");
        if (recs != null) {
            Iterator<String> it = recs.keys();
            while (it.hasNext()) {
                String k = it.next();
                v.records.put(k, recs.getJSONObject(k));
            }
        }
        return v;
    }

    // ---- 查询 ----
    private static String optStr(JSONObject o, String k) {
        return o.isNull(k) ? null : o.optString(k, null);
    }

    /** 未删除记录，附带 id 字段，按 title 排序。 */
    public List<JSONObject> activeRecords() throws JSONException {
        List<JSONObject> out = new ArrayList<>();
        Iterator<String> it = records.keys();
        while (it.hasNext()) {
            String id = it.next();
            JSONObject rec = records.getJSONObject(id);
            if (rec.optBoolean("deleted", false)) continue;
            JSONObject copy = new JSONObject(rec.toString());
            copy.put("id", id);
            out.add(copy);
        }
        out.sort(Comparator.comparing(r -> {
            String t = optStr((JSONObject) r, "title");
            return t == null ? "" : t.toLowerCase();
        }));
        return out;
    }

    public List<JSONObject> search(String keyword) throws JSONException {
        List<JSONObject> all = activeRecords();
        if (keyword == null || keyword.trim().isEmpty()) return all;
        String kw = keyword.trim().toLowerCase();
        List<JSONObject> out = new ArrayList<>();
        for (JSONObject r : all) {
            String hay = ((optStr(r, "title")) + " " + (optStr(r, "url")) + " "
                    + (optStr(r, "username")) + " " + (optStr(r, "note"))).toLowerCase();
            if (hay.contains(kw)) out.add(r);
        }
        return out;
    }

    public JSONObject get(String id) {
        return records.optJSONObject(id);
    }

    // ---- 增删改 ----
    public String add(String type, String title, String url, String username,
                      String password, String apikey, String note) throws JSONException {
        String id = newId();
        JSONObject rec = new JSONObject();
        rec.put("type", type);
        rec.put("title", title);
        rec.put("url", url == null ? JSONObject.NULL : url);
        rec.put("username", username == null ? JSONObject.NULL : username);
        rec.put("password", password == null ? JSONObject.NULL : password);
        rec.put("apikey", apikey == null ? JSONObject.NULL : apikey);
        rec.put("note", note == null ? "" : note);
        rec.put("updated_at", nowTs());
        rec.put("deleted", false);
        records.put(id, rec);
        touch();
        return id;
    }

    public void update(String id, String type, String title, String url, String username,
                       String password, String apikey, String note) throws JSONException {
        JSONObject rec = records.getJSONObject(id);
        rec.put("type", type);
        rec.put("title", title);
        rec.put("url", url == null ? JSONObject.NULL : url);
        rec.put("username", username == null ? JSONObject.NULL : username);
        rec.put("password", password == null ? JSONObject.NULL : password);
        rec.put("apikey", apikey == null ? JSONObject.NULL : apikey);
        rec.put("note", note == null ? "" : note);
        rec.put("updated_at", nowTs());
        rec.put("deleted", false);
        touch();
    }

    /** 软删除（墓碑）。 */
    public void delete(String id) throws JSONException {
        JSONObject rec = records.optJSONObject(id);
        if (rec == null) return;
        rec.put("deleted", true);
        rec.put("updated_at", nowTs());
        touch();
    }

    /** 修改本地 modified_at。真值以服务器 upload_time 为准；本地用于展示。 */
    public void touch() {
        this.modifiedAt = nowTs();
        this.dirtySeq++;
    }
}

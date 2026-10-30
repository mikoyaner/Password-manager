package com.pwdmgr;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

/**
 * 跨语言对拍测试（仅本地 javac 用，不进 APK）。
 * 用法: java CrossTest <py.enc> <out_java.enc> <password>
 *  1) 解密 Python 生成的 py.enc，打印明文 JSON
 *  2) 用 Java 加密一段已知 JSON 写到 out_java.enc，供 Python 解密验证
 */
public class CrossTest {
    public static void main(String[] args) throws Exception {
        String pyEnc = args[0], outJava = args[1], pw = args[2];

        // 1. 解密 Python 的库
        byte[] blob = Files.readAllBytes(Paths.get(pyEnc));
        byte[] plain = Crypto.decryptVault(blob, pw);
        String json = new String(plain, StandardCharsets.UTF_8);
        System.out.println("JAVA_DECRYPTED_PY:" + json);

        // 校验能解析并读回字段
        Vault v = Vault.fromJson(plain);
        int active = v.activeRecords().size();
        System.out.println("JAVA_ACTIVE_COUNT:" + active);

        // 2. Java 端新增一条并重新加密，供 Python 解密验证
        v.add("apikey", "Java生成的Key", null, null, null, "sk-from-java", "来自安卓");
        byte[] outPlain = v.toJson();
        byte[] salt = Crypto.newSalt();
        byte[] key = Crypto.deriveKey(pw, salt, Crypto.ARGON_M, Crypto.ARGON_T, Crypto.ARGON_P);
        byte[] enc = Crypto.encryptVault(outPlain, key, salt);
        Files.write(Paths.get(outJava), enc);
        System.out.println("JAVA_ENCRYPTED_OK:header=" + enc.length + ",magic="
                + new String(enc, 0, 6, StandardCharsets.US_ASCII));

        // 3. 错误密码必须失败
        try {
            Crypto.decryptVault(blob, "wrong-password-xx");
            System.out.println("JAVA_WRONGPW:FAIL(no exception)");
        } catch (Crypto.UnlockException e) {
            System.out.println("JAVA_WRONGPW:OK");
        }

        // 4. 篡改检测
        byte[] bad = blob.clone();
        bad[bad.length - 1] ^= 0xFF;
        try {
            Crypto.decryptVault(bad, pw);
            System.out.println("JAVA_TAMPER:FAIL(no exception)");
        } catch (Crypto.UnlockException e) {
            System.out.println("JAVA_TAMPER:OK");
        }
    }
}

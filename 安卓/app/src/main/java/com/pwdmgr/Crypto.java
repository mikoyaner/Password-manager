package com.pwdmgr;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * 加密层：Argon2id 派生 + AES-256-GCM，vault.enc 文件读写。
 * 严格遵循工作区根目录《密码库格式与同步协议.md》第 2/3 节。
 * 与电脑端 window/crypto.py 逐字节兼容。
 */
public final class Crypto {

    public static final byte[] MAGIC = "PWMGR1".getBytes(StandardCharsets.US_ASCII);
    public static final int FORMAT_VER = 2;
    public static final int KDF_ARGON2ID = 0;
    public static final int CIPHER_AES_GCM = 0;

    public static final int ARGON_M = 65536; // KiB (64 MB)
    public static final int ARGON_T = 3;
    public static final int ARGON_P = 4;
    public static final int KEY_LEN = 32;
    public static final int SALT_LEN = 16;
    public static final int NONCE_LEN = 12;
    public static final int TAG_BITS = 128;
    public static final int HEADER_LEN = 6 + 1 + 1 + 1 + 4 + 4 + 4 + SALT_LEN + NONCE_LEN; // 49

    private static final SecureRandom RNG = new SecureRandom();

    private Crypto() {}

    public static class UnlockException extends Exception {
        public UnlockException(String m) { super(m); }
    }

    /** 解密结果：明文 + 派生好的 key 与文件头 salt（供会话内复用，避免每次保存重跑 Argon2）。 */
    public static class Opened {
        public final byte[] plaintext;
        public final byte[] key;
        public final byte[] salt;

        Opened(byte[] plaintext, byte[] key, byte[] salt) {
            this.plaintext = plaintext;
            this.key = key;
            this.salt = salt;
        }
    }

    public static byte[] newSalt() {
        byte[] salt = new byte[SALT_LEN];
        RNG.nextBytes(salt);
        return salt;
    }

    /** Argon2id 派生 32 字节密钥。version 0x13 (v1.3)。 */
    public static byte[] deriveKey(String password, byte[] salt, int m, int t, int p) {
        Argon2Parameters params = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                .withSalt(salt)
                .withMemoryAsKB(m)
                .withIterations(t)
                .withParallelism(p)
                .build();
        Argon2BytesGenerator gen = new Argon2BytesGenerator();
        gen.init(params);
        byte[] key = new byte[KEY_LEN];
        gen.generateBytes(password.getBytes(StandardCharsets.UTF_8), key);
        return key;
    }

    /** 用会话 key/salt 加密：只换 nonce，不再跑 Argon2。 */
    public static byte[] encryptVault(byte[] plaintext, byte[] key, byte[] salt) throws Exception {
        byte[] nonce = new byte[NONCE_LEN];
        RNG.nextBytes(nonce);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"),
                new GCMParameterSpec(TAG_BITS, nonce));
        byte[] ct = cipher.doFinal(plaintext); // 密文尾部含 16 字节 tag

        ByteBuffer buf = ByteBuffer.allocate(HEADER_LEN + ct.length);
        buf.order(ByteOrder.LITTLE_ENDIAN);
        buf.put(MAGIC);
        buf.put((byte) FORMAT_VER);
        buf.put((byte) KDF_ARGON2ID);
        buf.put((byte) CIPHER_AES_GCM);
        buf.putInt(ARGON_M);
        buf.putInt(ARGON_T);
        buf.putInt(ARGON_P);
        buf.put(salt);
        buf.put(nonce);
        buf.put(ct);
        return buf.array();
    }

    /** 从完整 vault.enc 字节解出明文 JSON。主密码错误/篡改抛 UnlockException。 */
    public static byte[] decryptVault(byte[] blob, String password) throws UnlockException {
        return openVault(blob, password).plaintext;
    }

    /** 解密并保留派生出的 key/salt，供本次会话后续保存复用。 */
    public static Opened openVault(byte[] blob, String password) throws UnlockException {
        if (blob == null || blob.length < HEADER_LEN) {
            throw new UnlockException("文件过短或已损坏");
        }
        ByteBuffer buf = ByteBuffer.wrap(blob);
        buf.order(ByteOrder.LITTLE_ENDIAN);
        byte[] magic = new byte[6];
        buf.get(magic);
        if (!Arrays.equals(magic, MAGIC)) throw new UnlockException("不是有效的密码库文件");
        int fmt = buf.get() & 0xFF;
        int kdf = buf.get() & 0xFF;
        int cipherId = buf.get() & 0xFF;
        if (fmt > FORMAT_VER) throw new UnlockException("文件版本过新，请升级应用");
        if (kdf != KDF_ARGON2ID || cipherId != CIPHER_AES_GCM)
            throw new UnlockException("不支持的加密算法");
        int m = buf.getInt();
        int t = buf.getInt();
        int p = buf.getInt();
        // 严格参数校验（§3 DoS 防御）：非规范 m/t/p 一律拒绝
        if (m != ARGON_M || t != ARGON_T || p != ARGON_P)
            throw new UnlockException("加密参数不符合规范");
        byte[] salt = new byte[SALT_LEN];
        buf.get(salt);
        byte[] nonce = new byte[NONCE_LEN];
        buf.get(nonce);
        byte[] ct = new byte[blob.length - HEADER_LEN];
        buf.get(ct);

        try {
            byte[] key = deriveKey(password, salt, m, t, p);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(TAG_BITS, nonce));
            return new Opened(cipher.doFinal(ct), key, salt);
        } catch (Exception e) {
            throw new UnlockException("主密码错误或数据损坏");
        }
    }
}

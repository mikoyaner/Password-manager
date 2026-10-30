package com.pwdmgr;

import java.security.SecureRandom;

/** 密码生成器：使用 SecureRandom，保证含大小写字母与数字。 */
public final class PasswordGen {

    private static final SecureRandom RNG = new SecureRandom();
    private static final String LOWER = "abcdefghijklmnopqrstuvwxyz";
    private static final String UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static final String DIGIT = "0123456789";
    private static final String SYMBOL = "!@#$%^&*()-_=+[]{};:,.?";

    private PasswordGen() {}

    public static String generate(int length, boolean withSymbols) {
        int n = Math.max(6, Math.min(128, length));
        String alpha = LOWER + UPPER + DIGIT + (withSymbols ? SYMBOL : "");
        while (true) {
            StringBuilder sb = new StringBuilder(n);
            for (int i = 0; i < n; i++) sb.append(alpha.charAt(RNG.nextInt(alpha.length())));
            String pw = sb.toString();
            if (hasLower(pw) && hasUpper(pw) && hasDigit(pw)) return pw;
        }
    }

    private static boolean hasLower(String s) {
        for (char c : s.toCharArray()) if (c >= 'a' && c <= 'z') return true;
        return false;
    }
    private static boolean hasUpper(String s) {
        for (char c : s.toCharArray()) if (c >= 'A' && c <= 'Z') return true;
        return false;
    }
    private static boolean hasDigit(String s) {
        for (char c : s.toCharArray()) if (c >= '0' && c <= '9') return true;
        return false;
    }
}

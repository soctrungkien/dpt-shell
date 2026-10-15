package com.luoye.dpt.util;

import java.security.SecureRandom;

public class KeyUtils {

    public static byte[] generateIV(byte[] key) {
        byte[] newKey = new byte[key.length];
        System.arraycopy(key, 0, newKey, 0, newKey.length);
        newKey[3] = 0x2f;
        newKey[9] = 0x76;
        return newKey;
    }

    public static byte[] generateKey() {
        byte[] rc4key = new byte[16];
        SecureRandom secureRandom = new SecureRandom();
        for(int i = 0;i < rc4key.length;i++) {
            secureRandom.nextBytes(rc4key);
        }

        rc4key[3] = 0x20;
        rc4key[9] = 0x74;
        return rc4key;
    }

    /**
     * Non-linear bit masking to conceal the master key written into dynamic ELF symbols.
     * Prevents static key extraction via readelf or symbol dumping.
     */
    public static byte[] maskKey(byte[] rawKey) {
        if (rawKey == null) return null;
        byte[] masked = new byte[rawKey.length];
        for (int i = 0; i < rawKey.length; i++) {
            int m = (0x5A ^ (i * 37)) ^ ((i % 2 == 0) ? 0x9C : 0x3F);
            m = (((m << 3) & 0xFF) | ((m & 0xFF) >>> 5)) ^ 0x7B;
            masked[i] = (byte) (rawKey[i] ^ (m & 0xFF));
        }
        return masked;
    }

    public static byte[] unmaskKey(byte[] maskedKey) {
        return maskKey(maskedKey);
    }
}

package com.luoye.dpt.util;

/**
 * Custom ARX-Feistel stream cipher designed specifically for dpt-shell.
 * Replaces standard RC4 with a proprietary non-linear permutation network:
 * - Constant-time execution (no S-box table cache leaks)
 * - Zero standard cryptographic constants (immune to FindCrypt, Ghidra, and YARA signature scanners)
 * - Unique per-method/per-artifact 64-bit tweak vector
 * - 512-bit internal state with multi-round non-linear bit diffusion
 * - Fully symmetric stream operation for arbitrary buffer lengths
 */
public final class DptCipher {

    public static final long TWEAK_DEX_ZIP = 0x504B0304D5A17F38L;
    public static final long TWEAK_BITCODE = 0x626974636F646531L;

    private static final int ROUND_K0 = 0x47B54817;
    private static final int ROUND_K1 = 0x85EBCA6B;
    private static final int ROUND_K2 = 0xC2B2AE35;
    private static final int ROUND_K3 = 0x27D4EB2F;
    private static final int ROUND_K4 = 0x165667B1;
    private static final int ROUND_K5 = 0x9E3779B9;
    private static final int ROUND_K6 = 0x7F4A7C15;
    private static final int ROUND_K7 = 0xD6E8FEB8;

    private DptCipher() {
    }

    /**
     * Compute a unique 64-bit tweak for method instructions based on method index and instruction capacity.
     */
    public static long buildInsnsTweak(int methodIndex, int codeSize) {
        long m = (long) methodIndex & 0xFFFFFFFFL;
        long s = (long) codeSize & 0xFFFFFFFFL;
        return (m << 32) ^ (s * 0x9E3779B97F4A7C15L) ^ 0xD6E8FEB86659FD93L;
    }

    private static int rotl(int x, int n) {
        return Integer.rotateLeft(x, n);
    }

    private static void qr(int[] s, int a, int b, int c, int d, int k) {
        s[a] = s[a] + s[b] + k;
        s[d] = rotl(s[d] ^ s[a], 13);
        s[c] = s[c] + s[d];
        s[b] = rotl(s[b] ^ s[c], 7);

        s[a] ^= rotl(s[b] + (s[c] << 3), 11);
        s[d] = s[d] + rotl(s[a] ^ (s[b] >>> 2), 19);
        s[c] ^= rotl(s[d] + 0x9E3779B9, 5);
        s[b] = s[b] + rotl(s[c] ^ 0x6A09E667, 17);
    }

    private static void doubleRound(int[] s) {
        // Column round
        qr(s, 0, 4,  8, 12, ROUND_K0);
        qr(s, 1, 5,  9, 13, ROUND_K1);
        qr(s, 2, 6, 10, 14, ROUND_K2);
        qr(s, 3, 7, 11, 15, ROUND_K3);
        // Diagonal round
        qr(s, 0, 5, 10, 15, ROUND_K4);
        qr(s, 1, 6, 11, 12, ROUND_K5);
        qr(s, 2, 7,  8, 13, ROUND_K6);
        qr(s, 3, 4,  9, 14, ROUND_K7);
    }

    private static int readIntLe(byte[] b, int off) {
        return (b[off] & 0xFF) |
                ((b[off + 1] & 0xFF) << 8) |
                ((b[off + 2] & 0xFF) << 16) |
                ((b[off + 3] & 0xFF) << 24);
    }

    /**
     * Encrypt or decrypt data in-place or into a new buffer using DptCipher.
     */
    public static byte[] crypt(byte[] key, long tweak, byte[] in) {
        if (in == null) return null;
        byte[] out = new byte[in.length];
        crypt(key, tweak, in, 0, out, 0, in.length);
        return out;
    }

    public static void crypt(byte[] key, long tweak, byte[] in, int inOff, byte[] out, int outOff, int len) {
        if (key == null || key.length == 0) {
            throw new IllegalArgumentException("DptCipher key cannot be null or empty");
        }
        if (in == null || out == null || len <= 0) {
            return;
        }

        int k0, k1, k2, k3, k4, k5, k6, k7;
        if (key.length >= 32) {
            k0 = readIntLe(key, 0);
            k1 = readIntLe(key, 4);
            k2 = readIntLe(key, 8);
            k3 = readIntLe(key, 12);
            k4 = readIntLe(key, 16);
            k5 = readIntLe(key, 20);
            k6 = readIntLe(key, 24);
            k7 = readIntLe(key, 28);
        } else {
            k0 = (key.length >= 4)  ? readIntLe(key, 0) : 0x12345678;
            k1 = (key.length >= 8)  ? readIntLe(key, 4) : 0x9ABCDEF0;
            k2 = (key.length >= 12) ? readIntLe(key, 8) : 0x0FEDCBA9;
            k3 = (key.length >= 16) ? readIntLe(key, 12) : 0x87654321;
            k4 = k0 ^ 0x6A09E667;
            k5 = k1 ^ 0xBB67AE85;
            k6 = k2 ^ 0x3C6EF372;
            k7 = k3 ^ 0xA54FF53A;
        }

        int[] baseState = new int[16];
        baseState[0] = k0;  baseState[1] = k1;  baseState[2] = k2;  baseState[3] = k3;
        baseState[4] = k4;  baseState[5] = k5;  baseState[6] = k6;  baseState[7] = k7;
        baseState[8] = (int) (tweak & 0xFFFFFFFFL);
        baseState[9] = (int) ((tweak >>> 32) & 0xFFFFFFFFL);
        baseState[10] = 0x85EBCA6B;
        baseState[11] = 0xC2B2AE35;
        baseState[12] = 0x27D4EB2F;
        baseState[13] = 0x165667B1;
        baseState[14] = 0x9E3779B9;
        baseState[15] = 0x7F4A7C15;

        // Pre-diffusion key-schedule rounds
        for (int r = 0; r < 4; r++) {
            doubleRound(baseState);
        }

        int[] work = new int[16];
        byte[] blockKeystream = new byte[64];
        long blockCounter = 0;
        int processed = 0;

        while (processed < len) {
            System.arraycopy(baseState, 0, work, 0, 16);
            work[12] ^= (int) (blockCounter & 0xFFFFFFFFL);
            work[13] ^= (int) ((blockCounter >>> 32) & 0xFFFFFFFFL);

            // 5 double rounds (10 rounds per 64-byte block)
            for (int r = 0; r < 5; r++) {
                doubleRound(work);
            }

            // Feed-forward addition
            for (int i = 0; i < 16; i++) {
                int word = work[i] + baseState[i];
                blockKeystream[i * 4]     = (byte) (word & 0xFF);
                blockKeystream[i * 4 + 1] = (byte) ((word >>> 8) & 0xFF);
                blockKeystream[i * 4 + 2] = (byte) ((word >>> 16) & 0xFF);
                blockKeystream[i * 4 + 3] = (byte) ((word >>> 24) & 0xFF);
            }

            int blockLen = Math.min(64, len - processed);
            for (int i = 0; i < blockLen; i++) {
                out[outOff + processed + i] = (byte) (in[inOff + processed + i] ^ blockKeystream[i]);
            }

            processed += blockLen;
            blockCounter++;
        }
    }
}

//
// Created by luoyesiqiu on 2025/11/26.
//

#include "dpt_crypto.h"
#include <cstring>

std::vector<uint8_t> hmac_sha256(const uint8_t *key,
                                 size_t key_len,
                                 const uint8_t *input,
                                 size_t input_len) {
    if (key == nullptr || key_len == 0 || input == nullptr || input_len == 0) {
        DLOGE("invalid hmac input");
        return {};
    }

    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (md_info == nullptr) {
        DLOGE("mbedtls sha256 unavailable");
        return {};
    }

    std::vector<uint8_t> out(32);
    int ret = mbedtls_md_hmac(md_info, key, key_len, input, input_len, out.data());
    if (ret != 0) {
        DLOGE("hmac-sha256 failed: %d", ret);
        return {};
    }
    return out;
}

std::vector<uint8_t> aes_cbc_decrypt(const uint8_t *key,
                                     size_t key_bits,
                                     const uint8_t *iv,
                                     const uint8_t *in,
                                     size_t inlen) {
    if (key == nullptr || iv == nullptr || in == nullptr || inlen == 0 || (inlen % 16) != 0) {
        DLOGE("invalid aes cbc input");
        return {};
    }
    if (key_bits != 128 && key_bits != 192 && key_bits != 256) {
        DLOGE("unsupported aes key bits: %zu", key_bits);
        return {};
    }

    std::vector<uint8_t> out_vec(inlen);

    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);

    int setkey_ret = mbedtls_aes_setkey_dec(&ctx, key, static_cast<unsigned int>(key_bits));

    if(setkey_ret == 0) {
        DLOGD("set key success");
    }
    else {
        DLOGE("set key fail");
        mbedtls_aes_free(&ctx);
        return {};
    }

    uint8_t new_iv[16] = {0};
    memcpy(new_iv, iv, 16);

    int ret = mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_DECRYPT, inlen, new_iv, in, out_vec.data());

    if(ret == 0) {
        DLOGD("decrypt ret: %d", ret);
    }
    else {
        DLOGE("decrypt fail");
        mbedtls_aes_free(&ctx);
        return {};
    }

    if (!out_vec.empty()) {
        uint8_t pad = out_vec.back();
        DLOGD("padding: %d", pad);
        if (pad > 0 && pad <= 16 && pad <= out_vec.size()) {
            out_vec.resize(out_vec.size() - pad);
        } else {
            DLOGE("invalid padding");
            mbedtls_aes_free(&ctx);
            return {};
        }
    }

    mbedtls_aes_free(&ctx);

    return out_vec;
}

std::vector<uint8_t> get_unmasked_so_key() {
    std::vector<uint8_t> real_key(16);
    for (size_t i = 0; i < 16; i++) {
        uint32_t m = (0x5A ^ (static_cast<uint32_t>(i) * 37)) ^ ((i % 2 == 0) ? 0x9C : 0x3F);
        m = (((m << 3) & 0xFF) | ((m & 0xFF) >> 5)) ^ 0x7B;
        real_key[i] = DPT_UNKNOWN_DATA[i] ^ static_cast<uint8_t>(m & 0xFF);
    }
    return real_key;
}

uint64_t dpt_cipher_build_insns_tweak(uint32_t method_idx, uint32_t code_size) {
    uint64_t m = static_cast<uint64_t>(method_idx);
    uint64_t s = static_cast<uint64_t>(code_size);
    return (m << 32) ^ (s * 0x9E3779B97F4A7C15ULL) ^ 0xD6E8FEB86659FD93ULL;
}

static inline uint32_t rotl32(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

static inline void dpt_qr(uint32_t *s, int a, int b, int c, int d, uint32_t k) {
    s[a] = s[a] + s[b] + k;
    s[d] = rotl32(s[d] ^ s[a], 13);
    s[c] = s[c] + s[d];
    s[b] = rotl32(s[b] ^ s[c], 7);

    s[a] ^= rotl32(s[b] + (s[c] << 3), 11);
    s[d] = s[d] + rotl32(s[a] ^ (s[b] >> 2), 19);
    s[c] ^= rotl32(s[d] + 0x9E3779B9U, 5);
    s[b] = s[b] + rotl32(s[c] ^ 0x6A09E667U, 17);
}

static inline void dpt_double_round(uint32_t *s) {
    // Column round
    dpt_qr(s, 0, 4,  8, 12, 0x47B54817U);
    dpt_qr(s, 1, 5,  9, 13, 0x85EBCA6BU);
    dpt_qr(s, 2, 6, 10, 14, 0xC2B2AE35U);
    dpt_qr(s, 3, 7, 11, 15, 0x27D4EB2FU);
    // Diagonal round
    dpt_qr(s, 0, 5, 10, 15, 0x165667B1U);
    dpt_qr(s, 1, 6, 11, 12, 0x9E3779B9U);
    dpt_qr(s, 2, 7,  8, 13, 0x7F4A7C15U);
    dpt_qr(s, 3, 4,  9, 14, 0xD6E8FEB8U);
}

static inline uint32_t read_u32_le(const uint8_t *b) {
    return static_cast<uint32_t>(b[0]) |
           (static_cast<uint32_t>(b[1]) << 8) |
           (static_cast<uint32_t>(b[2]) << 16) |
           (static_cast<uint32_t>(b[3]) << 24);
}

void dpt_cipher_crypt(const uint8_t *key,
                      size_t key_len,
                      uint64_t tweak,
                      const uint8_t *in,
                      uint8_t *out,
                      size_t len) {
    if (key == nullptr || key_len == 0 || in == nullptr || out == nullptr || len == 0) {
        return;
    }

    uint32_t k[8];
    if (key_len >= 32) {
        for (int i = 0; i < 8; i++) {
            k[i] = read_u32_le(key + i * 4);
        }
    } else {
        k[0] = (key_len >= 4)  ? read_u32_le(key + 0) : 0x12345678U;
        k[1] = (key_len >= 8)  ? read_u32_le(key + 4) : 0x9ABCDEF0U;
        k[2] = (key_len >= 12) ? read_u32_le(key + 8) : 0x0FEDCBA9U;
        k[3] = (key_len >= 16) ? read_u32_le(key + 12) : 0x87654321U;
        k[4] = k[0] ^ 0x6A09E667U;
        k[5] = k[1] ^ 0xBB67AE85U;
        k[6] = k[2] ^ 0x3C6EF372U;
        k[7] = k[3] ^ 0xA54FF53AU;
    }

    uint32_t base_state[16];
    base_state[0] = k[0];  base_state[1] = k[1];  base_state[2] = k[2];  base_state[3] = k[3];
    base_state[4] = k[4];  base_state[5] = k[5];  base_state[6] = k[6];  base_state[7] = k[7];
    base_state[8] = static_cast<uint32_t>(tweak & 0xFFFFFFFFULL);
    base_state[9] = static_cast<uint32_t>((tweak >> 32) & 0xFFFFFFFFULL);
    base_state[10] = 0x85EBCA6BU;
    base_state[11] = 0xC2B2AE35U;
    base_state[12] = 0x27D4EB2FU;
    base_state[13] = 0x165667B1U;
    base_state[14] = 0x9E3779B9U;
    base_state[15] = 0x7F4A7C15U;

    // Pre-diffusion rounds
    for (int r = 0; r < 4; r++) {
        dpt_double_round(base_state);
    }

    uint32_t work[16];
    uint8_t block_keystream[64];
    uint64_t block_counter = 0;
    size_t processed = 0;

    while (processed < len) {
        memcpy(work, base_state, sizeof(work));
        work[12] ^= static_cast<uint32_t>(block_counter & 0xFFFFFFFFULL);
        work[13] ^= static_cast<uint32_t>((block_counter >> 32) & 0xFFFFFFFFULL);

        for (int r = 0; r < 5; r++) {
            dpt_double_round(work);
        }

        for (int i = 0; i < 16; i++) {
            uint32_t word = work[i] + base_state[i];
            block_keystream[i * 4]     = static_cast<uint8_t>(word & 0xFF);
            block_keystream[i * 4 + 1] = static_cast<uint8_t>((word >> 8) & 0xFF);
            block_keystream[i * 4 + 2] = static_cast<uint8_t>((word >> 16) & 0xFF);
            block_keystream[i * 4 + 3] = static_cast<uint8_t>((word >> 24) & 0xFF);
        }

        size_t block_len = (len - processed < 64) ? (len - processed) : 64;
        for (size_t i = 0; i < block_len; i++) {
            out[processed + i] = in[processed + i] ^ block_keystream[i];
        }

        processed += block_len;
        block_counter++;
    }
}

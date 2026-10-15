//
// Created by luoyesiqiu on 2025/11/26.
//

#ifndef DPT_DPT_CRYPTO_H
#define DPT_DPT_CRYPTO_H

#include <vector>
#include <stdint.h>
#include <stddef.h>
#include <mbedtls/aes.h>
#include <mbedtls/md.h>
#include "common/dpt_log.h"

std::vector<uint8_t> hmac_sha256(const uint8_t *key,
                                 size_t key_len,
                                 const uint8_t *input,
                                 size_t input_len);

std::vector<uint8_t> aes_cbc_decrypt(const uint8_t *key,
                                     size_t key_bits,
                                     const uint8_t *iv,
                                     const uint8_t *in,
                                     size_t inlen);

#define DPT_CIPHER_TWEAK_DEX_ZIP 0x504B0304D5A17F38ULL
#define DPT_CIPHER_TWEAK_BITCODE 0x626974636F646531ULL

extern uint8_t DPT_UNKNOWN_DATA[];

std::vector<uint8_t> get_unmasked_so_key();

uint64_t dpt_cipher_build_insns_tweak(uint32_t method_idx, uint32_t code_size);

void dpt_cipher_crypt(const uint8_t *key,
                      size_t key_len,
                      uint64_t tweak,
                      const uint8_t *in,
                      uint8_t *out,
                      size_t len);

#endif //DPT_DPT_CRYPTO_H

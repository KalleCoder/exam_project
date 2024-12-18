#ifndef SECURITY_H
#define SECURITY_H

#include <Arduino.h>
#include <mbedtls/md.h>
#include <mbedtls/pk.h>
#include <mbedtls/aes.h>
#include <mbedtls/sha256.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

constexpr int AES_SIZE{32};
constexpr int DER_SIZE{294};
constexpr int RSA_SIZE{256};
constexpr int HASH_SIZE{32};
constexpr int EXPONENT{65537};
constexpr int AES_BLOCK_SIZE{16};

static mbedtls_aes_context aes_ctx;
static mbedtls_md_context_t hmac_ctx;
static mbedtls_pk_context rsa_pub_ctx;
static mbedtls_pk_context rsa_keys_ctx;
static mbedtls_entropy_context entropy;
static mbedtls_ctr_drbg_context ctr_drbg;
static mbedtls_sha256_context sha256_ctx;

static uint8_t aes_key[AES_SIZE]{0};
static uint8_t enc_iv[AES_BLOCK_SIZE]{0};
static uint8_t dec_iv[AES_BLOCK_SIZE]{0};

static uint8_t SEC_KEY[32] = {
    0x29, 0x49, 0xDE, 0xC2, 0x3E, 0x1E, 0x34, 0xB5, 0x2D, 0x22,
    0xB5, 0xBA, 0x4C, 0x34, 0x23, 0x3A, 0x9D, 0x3F, 0xE2, 0x97,
    0x14, 0xBE, 0x24, 0x62, 0x81, 0x0C, 0x86, 0xB1, 0xF6, 0x92,
    0x54, 0xD6};

static void print(const uint8_t *data, size_t size);

static void print(const char *msg, size_t size);

void process_command(uint8_t command, uint8_t *payload, size_t length);

void wait_for_session_request();

void compute_HMAC(uint8_t *hmac, const uint8_t *message, size_t message_len, const uint8_t *key, size_t key_len);

#endif
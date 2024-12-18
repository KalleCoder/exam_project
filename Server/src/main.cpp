#include "../lib/security/security.h"

void setup()
{
  Serial.begin(115200);
  // RNG Initialization
  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&ctr_drbg);
  for (size_t i = 0; i < sizeof(aes_key); i++)
  {
    aes_key[i] = random(256);
  }
  assert(0 == mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func,
                                    &entropy, aes_key, sizeof(aes_key)));

  // SHA-256
  mbedtls_sha256_init(&sha256_ctx);

  // HMAC-SHA256
  mbedtls_md_init(&hmac_ctx);
  assert(0 == mbedtls_md_setup(&hmac_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1));

  // AES-256
  mbedtls_aes_init(&aes_ctx);
  mbedtls_ctr_drbg_random(&ctr_drbg, enc_iv, sizeof(enc_iv));
  memcpy(dec_iv, enc_iv, sizeof(dec_iv)); // enc_iv and dec_iv shall be the same
  mbedtls_ctr_drbg_random(&ctr_drbg, aes_key, sizeof(aes_key));
  assert(0 == mbedtls_aes_setkey_enc(&aes_ctx, aes_key, sizeof(aes_key) * CHAR_BIT));

  // RSA-2048
  mbedtls_pk_init(&rsa_keys_ctx);
  assert(0 == mbedtls_pk_setup(&rsa_keys_ctx, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA)));
  assert(0 == mbedtls_rsa_gen_key(mbedtls_pk_rsa(rsa_keys_ctx), mbedtls_ctr_drbg_random,
                                  &ctr_drbg, RSA_SIZE * CHAR_BIT, EXPONENT));
}

void loop()
{
  wait_for_session_request();
}

// #include "../lib/security/security.h"
#include <Arduino.h>
#include <mbedtls/md.h>
#include <mbedtls/pk.h>
#include <mbedtls/aes.h>
#include <mbedtls/sha256.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/error.h>

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

void wait_for_session_request()
{
  uint8_t buffer[DER_SIZE] = {0};
  uint8_t encrypted_aes_key[RSA_SIZE] = {0};
  uint8_t encrypted_iv[RSA_SIZE] = {0};
  size_t bytesRead = 0;
  uint8_t aes_key[AES_SIZE] = {0};

  // Step 1: Wait for the client's public RSA key
  while (!Serial.available())
  {
    // Serial.println("Waiting for client to initiate session...");
    delay(100); // Polling for incoming data
  }

  bytesRead = Serial.readBytes(buffer, DER_SIZE);
  if (bytesRead == DER_SIZE)
  {
    // Import the client's public RSA key
    int return_thing = mbedtls_pk_parse_public_key(&rsa_pub_ctx, buffer, DER_SIZE);
    if (return_thing != 0)
    {
      Serial.print("Error importing public key: ");
      Serial.println(return_thing);
    }
    else
    {
      Serial.println("Client public key imported successfully.");
    }

    // Wait until there are enough bytes available
    while (Serial.available() < 256)
    {
      delay(100);
    }

    // Step 2: Wait for the encrypted AES key
    bytesRead = Serial.readBytes(encrypted_aes_key, RSA_SIZE);
    if (bytesRead == RSA_SIZE)
    {

      // Wait until there are enough bytes available
      while (Serial.available() < 256)
      {
        delay(100);
      }

      // Step 3: Wait for the encrypted IV
      bytesRead = Serial.readBytes(encrypted_iv, RSA_SIZE);
      if (bytesRead == RSA_SIZE)
      {

        Serial.print("Encrypted AES Key: ");
        for (int i = 0; i < RSA_SIZE; i++)
        {
          Serial.print(encrypted_aes_key[i], HEX);
          Serial.print(" ");
        }
        Serial.println();
        // Step 4: Decrypt the AES key
        size_t length; // AES key size
        int ret = -1;

        // Attempt to decrypt the AES key
        ret = mbedtls_pk_decrypt(
            &rsa_keys_ctx,           // Private key context
            encrypted_aes_key,       // Input: Encrypted data
            RSA_SIZE,                // Input length
            aes_key,                 // Output: Decrypted data
            &length,                 // Output length
            AES_SIZE,                // Max output buffer size
            mbedtls_ctr_drbg_random, // RNG function
            &ctr_drbg                // RNG context
        );

        if (ret == 0)
        {
          // Step 5: Decrypt the IV
          ret = mbedtls_pk_decrypt(&rsa_keys_ctx, encrypted_iv, RSA_SIZE, dec_iv,
                                   &length, sizeof(dec_iv), mbedtls_ctr_drbg_random, &ctr_drbg);

          if (ret == 0)
          {
            // Step 6: Send acknowledgment
            Serial.println("ACK");
            Serial.println("Session established successfully. Ready for communication.");
          }
          else
          {
            Serial.print("Error during IV decryption: ");
            Serial.println(ret);
          }
        }
        else
        {
          delay(500);
          char error_buf[100];
          mbedtls_strerror(ret, error_buf, sizeof(error_buf));
          Serial.print("Decryption error: ");
          Serial.println(error_buf);
        }
      }
      else
      {
        Serial.println("Error: Encrypted IV not fully received.");
      }
    }
    else
    {
      Serial.print("Error: Expected ");
      Serial.print(RSA_SIZE);
      Serial.print(" bytes, but received ");
      Serial.println(bytesRead);
    }
  }
  else
  {
    Serial.println("Error: Invalid public key received.");
  }
}

void setup()
{
  delay(2000);

  Serial.begin(115200);

  // Initialize entropy and RNG
  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&ctr_drbg);
  const char *pers = "rsa_key_gen";
  int ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                  (const unsigned char *)pers, strlen(pers));
  if (ret != 0)
  {
    char error_buf[100];
    mbedtls_strerror(ret, error_buf, sizeof(error_buf));
    Serial.print("RNG initialization failed: ");
    Serial.println(error_buf);
    return;
  }
  Serial.println("RNG initialization successful.");

  // Initialize and generate RSA key
  mbedtls_pk_init(&rsa_keys_ctx);
  ret = mbedtls_pk_setup(&rsa_keys_ctx, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
  if (ret != 0)
  {
    char error_buf[100];
    mbedtls_strerror(ret, error_buf, sizeof(error_buf));
    Serial.print("PK setup failed: ");
    Serial.println(error_buf);
    return;
  }

  ret = mbedtls_rsa_gen_key(mbedtls_pk_rsa(rsa_keys_ctx), mbedtls_ctr_drbg_random,
                            &ctr_drbg, RSA_SIZE * CHAR_BIT, EXPONENT); // shouldnt it be 256??
  if (ret != 0)
  {
    char error_buf[100];
    mbedtls_strerror(ret, error_buf, sizeof(error_buf));
    Serial.print("RSA key generation failed: ");
    Serial.println(error_buf);
    return;
  }
  Serial.println("RSA key generation successful.");

  // Verify the key type
  if (!mbedtls_pk_can_do(&rsa_keys_ctx, MBEDTLS_PK_RSA))
  {
    Serial.println("Generated key is not of RSA type.");
    return;
  }
  else
  {
    Serial.println("Generated key verified as RSA.");
  }

  // Initialize SHA-256
  mbedtls_sha256_init(&sha256_ctx);
  Serial.println("SHA-256 context initialized.");

  // Initialize HMAC-SHA256
  mbedtls_md_init(&hmac_ctx);
  ret = mbedtls_md_setup(&hmac_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
  if (ret != 0)
  {
    char error_buf[100];
    mbedtls_strerror(ret, error_buf, sizeof(error_buf));
    Serial.print("HMAC-SHA256 setup failed: ");
    Serial.println(error_buf);
    return;
  }
  Serial.println("HMAC-SHA256 context initialized.");

  // Initialize AES-256
  mbedtls_aes_init(&aes_ctx);
  mbedtls_ctr_drbg_random(&ctr_drbg, enc_iv, sizeof(enc_iv));   // Generate IV
  memcpy(dec_iv, enc_iv, sizeof(dec_iv));                       // Copy IV for decryption
  mbedtls_ctr_drbg_random(&ctr_drbg, aes_key, sizeof(aes_key)); // Generate AES key
  ret = mbedtls_aes_setkey_enc(&aes_ctx, aes_key, sizeof(aes_key) * 8);
  if (ret != 0)
  {
    char error_buf[100];
    mbedtls_strerror(ret, error_buf, sizeof(error_buf));
    Serial.print("AES-256 setup failed: ");
    Serial.println(error_buf);
    return;
  }
  Serial.println("AES-256 context initialized.");
}

void loop()
{
  wait_for_session_request();
}

/* Serial.print("Decrypted AES key: ");
      for (int i = 0; i < AES_SIZE; i++)
      {
          Serial.print(aes_key[i], HEX);
      }
      Serial.println();

      Serial.print("Decrypted IV: ");
      for (int i = 0; i < sizeof(iv); i++)
      {
          Serial.print(iv[i], HEX);
      }
      Serial.println();

      Serial.print("Decrypted IV: ");
      print(iv, sizeof(iv)); */
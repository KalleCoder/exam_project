#include <Arduino.h>
#include <mbedtls/md.h>
#include <mbedtls/pk.h>
#include <mbedtls/aes.h>
#include <mbedtls/sha256.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/error.h>
#include <mbedtls/base64.h>

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

// Example Base64-encoded string
// static const char *SECRET = "Fj2-;wu3Ur=ARl2!Tqi6IuKM3nG]8z1+";

static uint8_t SEC_KEY[32] = {
    0x29, 0x49, 0xDE, 0xC2, 0x3E, 0x1E, 0x34, 0xB5, 0x2D, 0x22,
    0xB5, 0xBA, 0x4C, 0x34, 0x23, 0x3A, 0x9D, 0x3F, 0xE2, 0x97,
    0x14, 0xBE, 0x24, 0x62, 0x81, 0x0C, 0x86, 0xB1, 0xF6, 0x92,
    0x54, 0xD6};

#define RED_LED 26
#define GREEN_LED 23
#define BLUE_LED 21

static void blink_red(int times, int duration)
{
    for (int i = 0; i < times; i++)
    {
        digitalWrite(RED_LED, HIGH); // Turn LED ON
        delay(duration);
        digitalWrite(RED_LED, LOW); // Turn LED OFF
        delay(duration);
    }
}

static void blink_green(int times, int duration)
{
    for (int i = 0; i < times; i++)
    {
        digitalWrite(GREEN_LED, HIGH); // Turn LED ON
        delay(duration);
        digitalWrite(GREEN_LED, LOW); // Turn LED OFF
        delay(duration);
    }
}

static void blink_blue(int times, int duration)
{
    for (int i = 0; i < times; i++)
    {
        digitalWrite(BLUE_LED, HIGH); // Turn LED ON
        delay(duration);
        digitalWrite(BLUE_LED, LOW); // Turn LED OFF
        delay(duration);
    }
}

// Function to verify the hash
bool verify_hash(const uint8_t *public_key, size_t public_key_size, const uint8_t *expected_hash)
{
    uint8_t computed_hash[HASH_SIZE];

    // Compute the SHA-256 hash of the public key
    mbedtls_sha256_init(&sha256_ctx);
    mbedtls_sha256_starts(&sha256_ctx, 0); // 0 for SHA-256 (not SHA-224)
    mbedtls_sha256_update(&sha256_ctx, public_key, public_key_size);
    mbedtls_sha256_finish(&sha256_ctx, computed_hash);

    // Compare the computed hash with the expected hash
    for (size_t i = 0; i < HASH_SIZE; i++)
    {
        if (computed_hash[i] != expected_hash[i])
        {
            return false; // Hashes don't match
        }
    }

    return true; // Hashes match
}

bool verify_hmac_signature(const uint8_t *public_key, size_t public_key_size, const uint8_t *received_hmac, size_t hmac_size)
{
    uint8_t computed_hmac[HASH_SIZE];

    // Compute HMAC-SHA256 of the public key
    mbedtls_md_hmac_starts(&hmac_ctx, SEC_KEY, sizeof(SEC_KEY));
    mbedtls_md_hmac_update(&hmac_ctx, public_key, public_key_size);
    mbedtls_md_hmac_finish(&hmac_ctx, computed_hmac);

    // Compare the computed HMAC with the received HMAC
    if (memcmp(computed_hmac, received_hmac, hmac_size) != 0)
    {
        Serial.println("HMAC signature verification failed.");
        return false; // HMAC doesn't match
    }
    return true; // HMAC matches
}

void setup()
{
    pinMode(RED_LED, OUTPUT);
    digitalWrite(RED_LED, LOW);
    pinMode(GREEN_LED, OUTPUT);
    digitalWrite(GREEN_LED, LOW);
    pinMode(BLUE_LED, OUTPUT);

    blink_blue(5, 200);

    Serial.begin(115200);

    // Initialize mbedtls entropy context and random number generation
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

void exchange_keys()
{
    // Initialize RSA contexts for server keys
    // mbedtls_pk_init(&rsa_pub_ctx);
    mbedtls_pk_init(&rsa_keys_ctx);
    // mbedtls_pk_init(&rsa_client_public_key_ctx);

    // FIRST WE GET RSA KEY
    while (Serial.available() != 240)
    {
        blink_blue(1, 100); // Optional: blink to indicate waiting
        Serial.print("Waiting... Available bytes: ");
        Serial.println(Serial.available());
    }

    // Read the  public key (first part)
    uint8_t client_pub_key[RSA_SIZE];
    Serial.print("Received RSA: ");
    for (size_t i = 0; i < 32; i++)
    {
        client_pub_key[i] = Serial.read();
        uint8_t byte = client_pub_key[i];
        Serial.print((byte >> 4) & 0x0F, HEX); // Print the upper nibble (first half)
        Serial.print(byte & 0x0F, HEX);        // Print the lower nibble (second half)
    }

    // =============== THE WE GET HMAC
    while (Serial.available() != 32)
    {
        blink_blue(1, 100); // Optional: blink to indicate waiting
        Serial.print("Waiting... Available bytes: ");
        Serial.println(Serial.available());
    }
    uint8_t client_HMAC[HASH_SIZE];
    // Read the hash of the public key (second part)
    for (size_t i = 0; i < HASH_SIZE; i++)
    {
        client_HMAC[i] = Serial.read();
    }

    // Optionally print the received data (e.g., the hash of the public key)
    Serial.print("Received HMAC: ");
    for (size_t i = 0; i < HASH_SIZE; i++)
    {
        uint8_t byte = client_HMAC[i];
        Serial.print((byte >> 4) & 0x0F, HEX); // Print the upper nibble (first half)
        Serial.print(byte & 0x0F, HEX);        // Print the lower nibble (second half)
    }
    Serial.println();

    // Verify HMAC signature of the public key
    bool is_hmac_valid = verify_hmac_signature(client_pub_key, RSA_SIZE, client_HMAC, HASH_SIZE);

    if (is_hmac_valid)
    {
        blink_green(5, 500); // Indicate success if both hash and HMAC are valid
    }
    else
    {
        blink_red(5, 500); // Indicate failure if hash or HMAC is invalid
    }

    // ===================== THE WE GET HASH
    while (Serial.available() != HASH_SIZE)
    {
        blink_blue(1, 100); // Optional: blink to indicate waiting
        Serial.print("Waiting... Available bytes: ");
        Serial.println(Serial.available());
    }

    uint8_t signed_pub_key_hash[HASH_SIZE];
    // Read the hash of the public key (second part)
    for (size_t i = 0; i < HASH_SIZE; i++)
    {
        signed_pub_key_hash[i] = Serial.read();
    }

    // Optionally print the received data (e.g., the hash of the public key)
    Serial.print("Received hash: ");
    for (size_t i = 0; i < HASH_SIZE; i++)
    {
        uint8_t byte = signed_pub_key_hash[i];
        Serial.print((byte >> 4) & 0x0F, HEX); // Print the upper nibble (first half)
        Serial.print(byte & 0x0F, HEX);        // Print the lower nibble (second half)
    }
    Serial.println();

    // Verify the hash
    bool is_hash_valid = verify_hash(client_pub_key, RSA_SIZE, signed_pub_key_hash);
    if (is_hash_valid)
    {
        blink_green(5, 500);
    }
    else
    {
        blink_red(5, 500);
    }

    // Save the first public key

    // ======================  THE FIRST KEY RECIVED ========================0

    /*
    // Step 5: Import the decrypted public key into the server's context
    if (mbedtls_pk_parse_public_key(&keys.rsa_client_public_key_ctx, decrypted_client_pub_key, decrypted_client_pub_key_len) != 0)
    {
       Serial.println("Failed to parse the client's public key.");
       return;
    }

    // Step 6: Encrypt the server's public key using the client's public key
    unsigned char server_pub_key_encrypted[DER_SIZE];
    size_t server_pub_key_encrypted_len = sizeof(server_pub_key_encrypted);

    if (mbedtls_pk_encrypt(&keys.rsa_client_public_key_ctx, (unsigned char *)pub_key, strlen(pub_key),
                          (unsigned char *)server_pub_key_encrypted, &server_pub_key_encrypted_len,
                          RSA_SIZE, mbedtls_ctr_drbg_random, &ctr_drbg) != 0)
    {
       Serial.println("Failed to encrypt the server's public key.");
       return;
    }

    // Step 7: Hash the encrypted server public key (before sending it to the client)
    unsigned char hashed_server_pub_key[HASH_SIZE];
    mbedtls_sha256_init(&sha256_ctx);
    mbedtls_sha256_starts(&sha256_ctx, 0);
    mbedtls_sha256_update(&sha256_ctx, server_pub_key_encrypted, server_pub_key_encrypted_len);
    mbedtls_sha256_finish(&sha256_ctx, hashed_server_pub_key);
    mbedtls_sha256_free(&sha256_ctx);

    // Step 8: Send the encrypted and hashed server public key to the client via serial
    Serial.println("Sending Encrypted Server Public Key to Client...");
    for (size_t i = 0; i < server_pub_key_encrypted_len; i++)
    {
       Serial.write(server_pub_key_encrypted[i]);
    }

    // Serial.println("Sending Hashed Server Public Key...");
    for (size_t i = 0; i < HASH_SIZE; i++)
    {
       Serial.write(hashed_server_pub_key[i]);
    }

    // Serial.println("Server's Public Key Encrypted and Hashed.");

    // Step 9: Wait to receive the new encrypted client public key
    // Serial.println("Waiting for the encrypted new client public key...");
    while (Serial.available() < RSA_SIZE + HASH_SIZE)
    {
       delay(10); // Wait for enough data to be available (RSA public key + hash)
    }

    uint8_t encrypted_new_client_pub_key[RSA_SIZE];
    uint8_t received_hash[HASH_SIZE];

    // Read the encrypted new public key and the hash from the client
    for (size_t i = 0; i < RSA_SIZE; i++)
    {
       encrypted_new_client_pub_key[i] = Serial.read();
    }

    for (size_t i = 0; i < HASH_SIZE; i++)
    {
       received_hash[i] = Serial.read();
    }

    // Step 10: Decrypt the received encrypted public key using the server's private key
    unsigned char decrypted_new_client_pub_key[RSA_SIZE];
    size_t decrypted_new_client_pub_key_len = RSA_SIZE;

    if (mbedtls_pk_decrypt(&keys.rsa_priv_ctx, encrypted_new_client_pub_key, RSA_SIZE,
                          decrypted_new_client_pub_key, &decrypted_new_client_pub_key_len,
                          RSA_SIZE, mbedtls_ctr_drbg_random, &ctr_drbg) != 0)
    {
       // Serial.println("Failed to decrypt the new client public key.");
       return;
    }

    // Step 11: Hash the decrypted new public key
    unsigned char new_client_pub_key_hash[HASH_SIZE];
    mbedtls_sha256_init(&sha256_ctx);
    mbedtls_sha256_starts(&sha256_ctx, 0);
    mbedtls_sha256_update(&sha256_ctx, decrypted_new_client_pub_key, RSA_SIZE);
    mbedtls_sha256_finish(&sha256_ctx, new_client_pub_key_hash);
    mbedtls_sha256_free(&sha256_ctx);

    // Step 12: Verify the hash with the received hash from the client
    if (memcmp(new_client_pub_key_hash, received_hash, HASH_SIZE) != 0)
    {
       // Serial.println("Hash verification failed! The new public key is invalid.");
    }
    else
    {
       // Step 13: Update the server's client public key with the new one
       memcpy(decrypted_client_pub_key, decrypted_new_client_pub_key, RSA_SIZE);
       // Serial.println("The new client public key is valid and has been updated.");
    } */
}

void loop()
{
    exchange_keys();
}
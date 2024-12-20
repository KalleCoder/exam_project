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
    0x46, 0x6A, 0x32, 0x2D, 0x3B, 0x77, 0x75, 0x33,
    0x55, 0x72, 0x3D, 0x41, 0x52, 0x6C, 0x32, 0x21,
    0x54, 0x71, 0x69, 0x36, 0x49, 0x75, 0x4B, 0x4D,
    0x33, 0x6E, 0x47, 0x5D, 0x38, 0x7A, 0x31, 0x2B};

static uint8_t client_public_key[DER_SIZE]; // Global variable to store the client’s public key
static uint8_t server_public_key[DER_SIZE]; // Global variable to store the Servers’s public key

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

    // Debugging: Print computed hash
    // Serial.print("Computed Hash: ");
    for (size_t i = 0; i < HASH_SIZE; i++)
    {
        uint8_t byte = computed_hash[i];
        /* Serial.print((byte >> 4) & 0x0F, HEX); // Upper nibble
        Serial.print(byte & 0x0F, HEX);        // Lower nibble */
    }
    // Serial.println();

    // Compare the computed hash with the expected hash using memcmp
    if (memcmp(computed_hash, expected_hash, HASH_SIZE) != 0)
    {
        Serial.println("Hashes don't match!");
        return false; // Hashes don't match
    }

    return true; // Hashes match
}

bool send_hash(const uint8_t *data)
{
    bool status{false};

    uint8_t hash[HASH_SIZE]{0};

    if (0 == mbedtls_sha256_starts_ret(&sha256_ctx, 0))
    {
        // hash the message
        if (0 == mbedtls_sha256_update_ret(&sha256_ctx, data, sizeof(data)))
        {
            // Give the hash also using the secret key
            if (0 == mbedtls_sha256_update_ret(&sha256_ctx, SEC_KEY, sizeof(SEC_KEY)))
            {
                if (0 == mbedtls_sha256_finish_ret(&sha256_ctx, hash))
                {
                    // Then send the hash
                    Serial.write(hash, HASH_SIZE);
                    Serial.println("Sent data with hash!");
                    status = true;
                }
            }
        }
    }

    return status;
}

bool verify_hmac_signature(const uint8_t *public_key, size_t public_key_size, const uint8_t *received_hmac, size_t hmac_size)
{
    uint8_t computed_hmac[HASH_SIZE];

    // compute HMAC-SHA256 of the public key
    mbedtls_md_hmac_starts(&hmac_ctx, SEC_KEY, sizeof(SEC_KEY));
    mbedtls_md_hmac_update(&hmac_ctx, public_key, public_key_size);
    mbedtls_md_hmac_finish(&hmac_ctx, computed_hmac);

    // Compare the computed HMAC with the received HMAC
    if (memcmp(computed_hmac, received_hmac, hmac_size) != 0)
    {
        Serial.println("HMAC signature verification failed.");
        Serial.print("Computed HMAC: ");
        for (size_t i = 0; i < HASH_SIZE; i++)
        {
            uint8_t byte = computed_hmac[i];
            Serial.print((byte >> 4) & 0x0F, HEX); // Print the upper nibble (first half)
            Serial.print(byte & 0x0F, HEX);        // Print the lower nibble (second half)
        }
        Serial.println();
        return false; // HMAC doesn't match
    }
    // Serial.println("HMAC signature verification Succeded!.");
    return true; // HMAC matches
}

// void send_encrypted_server_key(uint8_t *server_public_key)
void send_encrypted_server_key(void)
{
    // here we export the servers public key to the global buffer: server_public_key!
    // we get the key from our initilized rsa_keys_ctx
    int ret = mbedtls_pk_write_pubkey_der(&rsa_keys_ctx, server_public_key, DER_SIZE);
    if (ret != DER_SIZE)
    {
        delay(500);
        char error_buf[100];
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));
        Serial.print("Failed to write public key in DER format, error code: ");
        Serial.println(error_buf);
        return;
    }

    // here we transfer over the public key we got from the Client into rsa_pub_ctx
    // so the buffer client_public_key contains the public key from the client
    mbedtls_pk_init(&rsa_pub_ctx);
    ret = mbedtls_pk_parse_public_key(&rsa_pub_ctx, client_public_key, DER_SIZE);
    if (ret != 0)
    {
        // Handle error
        delay(500);
        char error_buf[100];
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));
        Serial.print("Failed to parse public key, error code: ");
        Serial.println(error_buf);
        return;
    }

    // here we check if we got the correct type!
    if (MBEDTLS_PK_RSA != mbedtls_pk_get_type(&rsa_pub_ctx))
    {
        Serial.println("Failed the MBEDTLS_PK_RSA!");
        return;
    }

    // Public key is bigger than RSA_SIZE at 294 bytes
    // so we first split it into two parts
    uint8_t part1[DER_SIZE / 2]{0}; // Buffer for first half
    uint8_t part2[DER_SIZE / 2]{0}; // Buffer for second half

    // Send the encrypted server public key (For example, send it via Serial)
    Serial.print("Server public key: ");
    for (size_t i = 0; i < DER_SIZE; i++)
    {
        // Serial.print(server_public_key[i], HEX);
        uint8_t byte = server_public_key[i];
        Serial.print((byte >> 4) & 0x0F, HEX); // Print the upper nibble (first half)
        Serial.print(byte & 0x0F, HEX);        // Print the lower nibble (second half)
        Serial.print(" ");
    }
    Serial.println();

    // Populate the buffers with the respective halves of the key
    memcpy(part1, server_public_key, (DER_SIZE / 2));
    memcpy(part2, server_public_key + (DER_SIZE / 2), (DER_SIZE / 2));

    /* // Send the encrypted server public key (For example, send it via Serial)
    Serial.print("Part 1 public key: ");
    for (size_t i = 0; i < (DER_SIZE / 2); i++)
    {
        uint8_t byte = part1[i];
        Serial.print((byte >> 4) & 0x0F, HEX); // Print the upper nibble (first half)
        Serial.print(byte & 0x0F, HEX);        // Print the lower nibble (second half)
        Serial.print(" ");
    }
    Serial.println();

    // Send the encrypted server public key (For example, send it via Serial)
    Serial.print("Part 2 public key: ");
    for (size_t i = 0; i < (DER_SIZE / 2); i++)
    {
        uint8_t byte = part2[i];
        Serial.print((byte >> 4) & 0x0F, HEX); // Print the upper nibble (first half)
        Serial.print(byte & 0x0F, HEX);        // Print the lower nibble (second half)
        Serial.print(" ");
    }
    Serial.println(); */

    // lets start sedning the first key
    // Now, we will encrypt the server's public key using the client's public key
    uint8_t encrypted_server_key_part_1[RSA_SIZE]{0}; // Buffer to hold the encrypted server public key part 1
    size_t encrypted_len_part_1;

    // Encrypt the server's public key using the client’s public key
    ret = mbedtls_pk_encrypt(&rsa_pub_ctx, part1, (DER_SIZE / 2), encrypted_server_key_part_1, &encrypted_len_part_1, sizeof(encrypted_server_key_part_1), mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0)
    {
        delay(500);
        char error_buf[100];
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));
        Serial.print("Encryption failed, error: ");
        Serial.println(error_buf);
        return;
    }

    // Send the encrypted server public key (For example, send it via Serial)
    Serial.print("Encrypted server public key part 1: ");
    for (size_t i = 0; i < encrypted_len_part_1; i++)
    {
        Serial.print(encrypted_server_key_part_1[i], HEX);
        Serial.print(" ");
    }
    Serial.println();

    // here we send it
    Serial.write(encrypted_server_key_part_1, RSA_SIZE);

    // ========= SECOND PART OF PUBLIC KEY ==========
    uint8_t encrypted_server_key_part_2[RSA_SIZE]{0}; // Buffer to hold the encrypted server public key
    size_t encrypted_len_part_2;

    // lets we send the second part of the key!
    // Encrypt the server's public key using the client’s public key
    ret = mbedtls_pk_encrypt(&rsa_pub_ctx, part2, (DER_SIZE / 2), encrypted_server_key_part_2, &encrypted_len_part_2, sizeof(encrypted_server_key_part_2), mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0)
    {
        delay(500);
        char error_buf[100];
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));
        Serial.print("Encryption failed, error: ");
        Serial.println(error_buf);
        return;
    }

    // Send the encrypted server public key (For example, send it via Serial)
    Serial.print("Encrypted server public key part 2: ");
    for (size_t i = 0; i < encrypted_len_part_2; i++)
    {
        Serial.print(encrypted_server_key_part_2[i], HEX);
        Serial.print(" ");
    }
    Serial.println();

    // here we send it
    Serial.write(encrypted_server_key_part_2, RSA_SIZE);

    // The hash should "contain" the unencrypted server public key
    // so you can the veryfy the hash after decrypting the two parts and putting them together
    if (!send_hash(server_public_key))
    {
        Serial.println("Failed to send hash!");
    }

    // Clean up the client public key context
    mbedtls_pk_free(&rsa_pub_ctx);
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

    // signing that it can start echanging keys
    blink_green(2, 500);

    // FIRST WE GET RSA KEY

    // Read the  public key (first part)
    uint8_t client_pub_key[DER_SIZE];
    size_t received_bytes = 0;

    while (received_bytes < DER_SIZE)
    {
        if (Serial.available() > 0)
        {
            client_pub_key[received_bytes] = Serial.read();
            received_bytes++;
        }
        else
        {
            // blink_blue(1, 1)
            delay(1); // Allow time for data to arrive
        }
    }

    // Empty the serial buffer by reading and discarding any remaining data
    while (Serial.available() > 0)
    {
        Serial.read(); // Read and discard remaining bytes
    }

    /* // Print the entire key
    Serial.print("Received public key: ");
    for (size_t i = 0; i < DER_SIZE; i++)
    {
        Serial.print(client_pub_key[i], HEX);
        Serial.print(" ");
    }
    Serial.println(); */

    // =============== THE WE GET HMAC
    while (Serial.available() != 32)
    {
        /* blink_blue(1, 100); // Optional: blink to indicate waiting
        Serial.print("Waiting... Available bytes: ");
        Serial.println(Serial.available()); */
        delay(100);
    }
    uint8_t client_HMAC[HASH_SIZE];
    // Read the hash of the public key (second part)
    for (size_t i = 0; i < HASH_SIZE; i++)
    {
        client_HMAC[i] = Serial.read();
    }

    // Optionally print the received data (e.g., the hash of the public key)
    /* Serial.print("Received HMAC: ");
    for (size_t i = 0; i < HASH_SIZE; i++)
    {
        uint8_t byte = client_HMAC[i];
        Serial.print((byte >> 4) & 0x0F, HEX); // Print the upper nibble (first half)
        Serial.print(byte & 0x0F, HEX);        // Print the lower nibble (second half)
    }
    Serial.println(); */

    // Verify HMAC signature of the public key
    bool is_hmac_valid = verify_hmac_signature(client_pub_key, DER_SIZE, client_HMAC, HASH_SIZE);

    if (is_hmac_valid)
    {
        Serial.println("HMAC is valid");
        // blink_green(5, 500); // Indicate success if both hash and HMAC are valid
    }
    else
    {
        Serial.println("HMAC is not valid");
        // blink_red(5, 500); // Indicate failure if hash or HMAC is invalid
    }

    // ===================== THE WE GET HASH
    while (Serial.available() != HASH_SIZE)
    {
        /* blink_blue(1, 100); // Optional: blink to indicate waiting
        Serial.print("Waiting... Available bytes: ");
        Serial.println(Serial.available()); */
        delay(100);
    }

    uint8_t signed_pub_key_hash[HASH_SIZE];
    // Read the hash of the public key (second part)
    for (size_t i = 0; i < HASH_SIZE; i++)
    {
        signed_pub_key_hash[i] = Serial.read();
    }

    // Optionally print the received data (e.g., the hash of the public key)
    /* Serial.print("Received hash: ");
    for (size_t i = 0; i < HASH_SIZE; i++)
    {
        uint8_t byte = signed_pub_key_hash[i];
        Serial.print((byte >> 4) & 0x0F, HEX); // Print the upper nibble (first half)
        Serial.print(byte & 0x0F, HEX);        // Print the lower nibble (second half)
    }
    Serial.println(); */

    // Verify the hash
    bool is_hash_valid = verify_hash(client_pub_key, DER_SIZE, signed_pub_key_hash);
    if (is_hash_valid)
    {
        Serial.println("Hash is valid");
        // blink_green(5, 500);
    }
    else
    {
        Serial.println("Hash not valid");
        // blink_red(5, 500);
    }

    // Save the first public key
    if (is_hash_valid && is_hmac_valid)
    {
        // Save the received public key to the global static variable
        memcpy(client_public_key, client_pub_key, DER_SIZE);

        send_encrypted_server_key();
    }

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

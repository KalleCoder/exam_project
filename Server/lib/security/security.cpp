#include "security.h"

static uint8_t iv[16] = {0};

static int MAX_MESSAGE_SIZE = 50;

static int HMAC_SIZE = 256;

static void print(const uint8_t *data, size_t size)
{
    for (size_t i = 0; i < size; i++)
    {
        Serial.printf("%02X ", data[i]);
    }
    Serial.println("\n");
}

static void print(const char *msg, size_t size)
{
    for (size_t i = 0; i < size; i++)
    {
        Serial.printf("%c", msg[i]);
    }
    Serial.println("\n");
}

void end_session()
{
    // Step 1: Notify the client about the session termination
    Serial.println("Ending session...");

    // Step 2: Clear sensitive data from memory
    // Zero out sensitive keys and IVs
    memset(aes_key, 0, AES_SIZE);
    memset(iv, 0, sizeof(iv));

    // If any other sensitive buffers or contexts were used, clear them too
    // e.g., zero out other keys, buffers, or nonces

    // Step 3: Free cryptographic contexts
    mbedtls_pk_free(&rsa_keys_ctx); // Free the RSA context
    mbedtls_aes_free(&aes_ctx);     // Free the AES context
    Serial.println("Cryptographic contexts cleaned up.");

    // Step 4: Reset the communication channel
    Serial.flush(); // Ensure all data is sent out

    // Step 5: Optionally reset relay, sensors, or devices that were active
    /* resetRelay();   // Reset the relay (if used)
    resetSensors(); // Reset any sensors if applicable
    Serial.println("Communication channel and devices reset."); */

    // Final message indicating session termination
    Serial.println("Session ended successfully.");
}

void send_response(void *response, bool is_float)
{
    uint8_t encrypted_response[MAX_MESSAGE_SIZE] = {0};
    uint8_t iv[16] = {0};
    size_t response_length = 0;
    size_t encrypted_length;
    uint8_t hmac_response[HMAC_SIZE] = {0};

    // Determine the response length and convert the response to bytes
    if (is_float)
    {
        // Convert the float to uint16_t by multiplying by 100
        float float_value = *(float *)response;
        uint16_t int_value = (uint16_t)(float_value * 100); // Multiply by 100 and cast to uint16_t
        response_length = sizeof(uint16_t);
        memcpy(encrypted_response, &int_value, sizeof(uint16_t)); // Store the uint16_t in the buffer
    }
    else
    {
        // Convert the bool to a byte array (1 byte for true/false)
        bool bool_value = *(bool *)response;
        response_length = sizeof(bool);
        encrypted_response[0] = bool_value ? 1 : 0;
    }

    // Generate a new IV for the response
    mbedtls_ctr_drbg_random(&ctr_drbg, iv, sizeof(iv));

    // Encrypt the response
    mbedtls_aes_context aes_ctx;
    mbedtls_aes_init(&aes_ctx);
    mbedtls_aes_setkey_enc(&aes_ctx, aes_key, AES_SIZE * 8);
    assert(0 == mbedtls_aes_crypt_cbc(&aes_ctx, MBEDTLS_AES_ENCRYPT, response_length, iv,
                                      encrypted_response, encrypted_response));
    mbedtls_aes_free(&aes_ctx);

    // Compute HMAC for the response
    compute_HMAC(hmac_response, encrypted_response, response_length, aes_key, AES_SIZE);

    // Send Encrypted Response
    Serial.write(iv, sizeof(iv));                      // Send IV
    Serial.write(encrypted_response, response_length); // Send the encrypted message
    Serial.write(hmac_response, HMAC_SIZE);            // Send HMAC for integrity

    Serial.println("Response sent to client.");
}

void compute_HMAC(uint8_t *hmac, const uint8_t *message, size_t message_len, const uint8_t *key, size_t key_len)
{
    mbedtls_md_context_t hmac_ctx;
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

    mbedtls_md_init(&hmac_ctx);
    mbedtls_md_setup(&hmac_ctx, md_info, 1);
    mbedtls_md_hmac_starts(&hmac_ctx, key, key_len);
    mbedtls_md_hmac_update(&hmac_ctx, message, message_len);
    mbedtls_md_hmac_finish(&hmac_ctx, hmac);
    mbedtls_md_free(&hmac_ctx);
}

void process_incoming_message()
{
    uint8_t encrypted_aes_key[RSA_SIZE] = {0};
    uint8_t encrypted_iv[RSA_SIZE] = {0};
    uint8_t encrypted_message[MAX_MESSAGE_SIZE] = {0};
    uint8_t hmac_received[HMAC_SIZE] = {0};
    uint8_t aes_key[AES_SIZE] = {0};
    uint8_t iv[16] = {0};
    uint8_t decrypted_message[MAX_MESSAGE_SIZE] = {0};
    uint8_t hmac_computed[HMAC_SIZE] = {0};
    size_t decrypted_length;

    Serial.println("Waiting for a message from the client...");

    // Step 1: Receive Encrypted AES Key
    if (Serial.readBytes(encrypted_aes_key, RSA_SIZE) != RSA_SIZE)
    {
        Serial.println("Error: Failed to receive encrypted AES key.");
    }

    // Step 2: Receive Encrypted IV
    if (Serial.readBytes(encrypted_iv, RSA_SIZE) != RSA_SIZE)
    {
        Serial.println("Error: Failed to receive encrypted IV.");
    }

    // Step 3: Receive Encrypted Message
    size_t message_length = Serial.available(); // Ensure dynamic size handling
    if (message_length == 0 || message_length > MAX_MESSAGE_SIZE)
    {
        Serial.println("Error: Invalid message size.");
    }
    Serial.readBytes(encrypted_message, message_length);

    // Step 4: Receive HMAC
    if (Serial.readBytes(hmac_received, HMAC_SIZE) != HMAC_SIZE)
    {
        Serial.println("Error: Failed to receive HMAC.");
    }

    // Step 5: Decrypt AES Key
    assert(0 == mbedtls_pk_decrypt(&rsa_keys_ctx, encrypted_aes_key, RSA_SIZE, aes_key,
                                   &decrypted_length, AES_SIZE, mbedtls_ctr_drbg_random, &ctr_drbg));
    Serial.println("AES key decrypted successfully.");

    // Step 6: Decrypt IV
    assert(0 == mbedtls_pk_decrypt(&rsa_keys_ctx, encrypted_iv, RSA_SIZE, iv,
                                   &decrypted_length, sizeof(iv), mbedtls_ctr_drbg_random, &ctr_drbg));
    Serial.println("IV decrypted successfully.");

    // Step 7: Decrypt Message
    mbedtls_aes_context aes_ctx;
    mbedtls_aes_init(&aes_ctx);
    mbedtls_aes_setkey_dec(&aes_ctx, aes_key, AES_SIZE * 8);
    assert(0 == mbedtls_aes_crypt_cbc(&aes_ctx, MBEDTLS_AES_DECRYPT, message_length, iv,
                                      encrypted_message, decrypted_message));
    mbedtls_aes_free(&aes_ctx);
    Serial.println("Message decrypted successfully.");

    // Step 8: Verify HMAC
    compute_HMAC(hmac_computed, decrypted_message, message_length, aes_key, AES_SIZE);
    if (memcmp(hmac_computed, hmac_received, HMAC_SIZE) != 0)
    {
        Serial.println("Error: HMAC integrity check failed.");
    }
    Serial.println("Message integrity verified.");

    // Remove padding
    size_t padding_len = decrypted_message[message_length - 1];
    size_t actual_message_length = message_length - padding_len;
    decrypted_message[actual_message_length] = '\0'; // Null-terminate for printing
    Serial.print("Received message: ");
    Serial.println((char *)decrypted_message);

    // here you have switch cases for to send temp, toggle relay or end session
    // Determine the message type and respond accordingly
    if ((char *)decrypted_message == "temp")
    {
        // Respond with a temperature (float converted to uint16_t)
        float temp = 22.5;          // Example temperature value
        send_response(&temp, true); // true indicates sending a float
    }
    else if ((char *)decrypted_message == "relay")
    {
        // Respond with relay status (bool)
        bool relay_status = true;            // Example: relay is on
        send_response(&relay_status, false); // false indicates sending a bool
    }
    else if ((char *)decrypted_message == "end")
    {
        // Handle session termination
        Serial.println("Session ended by client.");
        end_session();
        // Optionally, handle clean-up or state change here.
    }
    else
    {
        Serial.println("Unknown command received.");
    }
}

void wait_for_session_request()
{
    uint8_t buffer[DER_SIZE] = {0};
    uint8_t encrypted_aes_key[RSA_SIZE] = {0};
    uint8_t encrypted_iv[RSA_SIZE] = {0};
    size_t bytesRead;
    uint8_t aes_key[AES_SIZE] = {0};

    // Step 1: Wait for the client's public RSA key
    while (!Serial.available())
    {
        // Serial.println("Waiting for client to initiate session...");
        delay(1000); // Polling for incoming data
    }

    bytesRead = Serial.readBytes(buffer, DER_SIZE);
    if (bytesRead == DER_SIZE)
    {
        // Serial.println("Valid public key received.");

        // Import the client's public RSA key
        int return_thing = mbedtls_pk_parse_public_key(&rsa_pub_ctx, buffer, DER_SIZE);
        if (return_thing != 0)
        {
            // Serial.print("Error importing public key: ");
            Serial.println(return_thing);
        }
        else
        {
            // Serial.println("Client public key imported successfully.");
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
            while (Serial.available() < 256)
            {
                delay(100);
            }
            // Step 3: Wait for the encrypted IV
            bytesRead = Serial.readBytes(encrypted_iv, RSA_SIZE);
            if (bytesRead != RSA_SIZE)
            {
                Serial.println("Error: Encrypted IV not fully received.");
            }

            // Step 4: Decrypt the AES key
            size_t decrypted_length;
            int ret = mbedtls_pk_decrypt(&rsa_keys_ctx, encrypted_aes_key, RSA_SIZE, aes_key,
                                         &decrypted_length, AES_SIZE, mbedtls_ctr_drbg_random, &ctr_drbg);
            if (ret != 0)
            {
                Serial.print("Error during AES key decryption: ");
                Serial.println(ret);
            }

            /* Serial.print("Decrypted AES key: ");
            print(aes_key, AES_SIZE); */

            // Step 5: Decrypt the IV
            ret == mbedtls_pk_decrypt(&rsa_keys_ctx, encrypted_iv, RSA_SIZE, iv,
                                      &decrypted_length, sizeof(iv), mbedtls_ctr_drbg_random, &ctr_drbg);
            if (ret != 0)
            {
                Serial.print("Error during IV decryption: ");
                Serial.println(ret);
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

            // Step 6: Send acknowledgment
            Serial.println("ACK");
            Serial.println("Session established successfully. Ready for communication.");
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

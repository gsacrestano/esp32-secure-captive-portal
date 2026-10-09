#include "crypto_cipher.h"

#include <esp_random.h>
#include <mbedtls/aes.h>
#include <mbedtls/platform_util.h>

#include <cstdlib>
#include <cstring>

namespace
{
uint8_t session_aes_key[32];
bool is_key_set = false;

// Function to add PKCS#7 padding to the input data to reache 16 bytes AES dimensions
size_t apply_pkcs7_padding(uint8_t* buffer, size_t data_len, size_t block_size)
{
    uint8_t padding_value = block_size - (data_len % block_size);
    for (size_t i = 0; i < padding_value; i++)
    {
        buffer[data_len + i] = padding_value;
    }
    return data_len + padding_value;
}
}  // namespace

namespace crypto_cipher
{
void set_session_key(const uint8_t key[32])
{
    memcpy(session_aes_key, key, 32);
    is_key_set = true;
}

bool encrypt_data(const uint8_t* input, size_t input_len, uint8_t* output, size_t max_output_len,
                  size_t* out_len)
{
    if (!is_key_set || input == nullptr || output == nullptr || out_len == nullptr)
    {
        return false;
    }

    // Calculate required padded payload size (multiples of 16 bytes)
    size_t padding_len = 16 - (input_len % 16);
    size_t padded_len = input_len + padding_len;
    size_t total_required_len = 16 + padded_len;  // 16 bytes IV + ciphertext

    // Ensure the caller's destination buffer is large enough
    if (max_output_len < total_required_len) return false;

    // Allocate temporary buffer for the padded input
    uint8_t* padded_input = static_cast<uint8_t*>(malloc(padded_len));
    if (!padded_input) return false;

    memcpy(padded_input, input, input_len);
    apply_pkcs7_padding(padded_input, input_len, 16);

    // Generate random 16-byte IV directly into the beginning of the output buffer
    uint8_t* iv = output;
    esp_fill_random(iv, 16);

    // CBC mode modifies the IV buffer during operation; use a working copy
    uint8_t iv_working_copy[16];
    memcpy(iv_working_copy, iv, 16);

    // Setup hardware-accelerated AES-256 context
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);

    int ret = mbedtls_aes_setkey_enc(&aes, session_aes_key, 256);
    if (ret != 0)
    {
        free(padded_input);
        mbedtls_aes_free(&aes);
        return false;
    }

    // Encrypt directly into the destination buffer starting at offset 16
    ret = mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, padded_len, iv_working_copy,
                                padded_input, output + 16);

    // Free intermediate resources
    free(padded_input);
    mbedtls_aes_free(&aes);

    if (ret != 0)
    {
        return false;
    }

    *out_len = total_required_len;
    return true;
}
bool decrypt_data(const uint8_t* input, size_t input_len, uint8_t* output, size_t max_output_len,
                  size_t* out_len)
{
    if (!is_key_set || input == nullptr || output == nullptr || out_len == nullptr)
    {
        return false;
    }
    if (input_len < 32 || ((input_len - 16) % 16 != 0))
    {
        return false;
    }

    size_t ct_len = input_len - 16;

    if (max_output_len < ct_len)
    {
        return false;
    }

    const uint8_t* iv = input;
    const uint8_t* ciphertext = input + 16;

    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);

    int ret = mbedtls_aes_setkey_dec(&aes, session_aes_key, 256);
    if (ret != 0)
    {
        mbedtls_aes_free(&aes);
        return false;
    }

    uint8_t iv_copy[16];
    memcpy(iv_copy, iv, 16);

    ret = mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, ct_len, iv_copy, ciphertext, output);

    mbedtls_aes_free(&aes);

    if (ret != 0)
    {
        return false;
    }

    uint8_t pad_val = output[ct_len - 1];
    if (pad_val == 0 || pad_val > 16)
    {
        return false;  // Invalid padding bytes
    }

    for (size_t i = 0; i < pad_val; ++i)
    {
        if (output[ct_len - 1 - i] != pad_val)
        {
            return false;  // Padding corrupted
        }
    }

    *out_len = ct_len - pad_val;
    return true;
}

}  // namespace crypto_cipher
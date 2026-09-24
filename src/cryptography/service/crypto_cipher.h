#pragma once

#include <cstddef>
#include <cstdint>

namespace crypto_cipher
{
/**
 * @brief Encrypts plaintext data using AES-256.
 *
 * @param input Pointer to the raw plaintext input bytes.
 * @param input_len Length of the input data in bytes.
 * @param output Destination buffer for the ciphertext.
 * @param max_output_len Capacity of the destination buffer.
 * @param out_len Pointer to store the actual written ciphertext length.
 * @return true if encryption succeeded, false otherwise.
 */
bool encrypt_data(const uint8_t* input, size_t input_len, uint8_t* output, size_t max_output_len,
                  size_t* out_len);

void set_session_key(const uint8_t key[32]);
}  // namespace crypto_cipher
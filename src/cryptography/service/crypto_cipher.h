/**
 * @file crypto_cipher.h
 * @brief AES-256-CBC encryption and session key management.
 */

#pragma once

#include <cstddef>
#include <cstdint>

namespace crypto_cipher
{
/**
 * @brief Encrypts plaintext using AES-256-CBC with PKCS#7 padding.
 * @details Prepends a randomly generated 16-byte IV to the resulting ciphertext.
 *          The destination buffer must hold at least (16 + input_len + padding) bytes.
 * @param[in]  input          Pointer to the plaintext bytes.
 * @param[in]  input_len      Length of the plaintext in bytes.
 * @param[out] output         Destination buffer storing [16-byte IV][ciphertext].
 * @param[in]  max_output_len Total capacity of the destination buffer.
 * @param[out] out_len        Pointer receiving the total written length (IV + ciphertext).
 * @return True on success, false if the key is not set, parameters are invalid, or encryption
 * fails.
 */
bool encrypt_data(const uint8_t* input, size_t input_len, uint8_t* output, size_t max_output_len,
                  size_t* out_len);

bool decrypt_data(const uint8_t* input, size_t input_len, uint8_t* output, size_t max_output_len,
                  size_t* out_len);

/**
 * @brief Stores the 32-byte AES-256 session key internally.
 * @param[in] key Pointer to the 32-byte symmetric key array.
 */
void set_session_key(const uint8_t key[32]);
}  // namespace crypto_cipher
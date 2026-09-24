/**
 * @file session_orchestrator.h
 * @brief High-level session orchestration for ECDH key exchange and AES encryption.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

namespace session_orchestrator
{
/**
 * @brief Generates a local ECDH keypair and outputs the Base64-encoded public key.
 * @param[out] response_string      Destination buffer for the null-terminated Base64 public key.
 * @param[in]  response_string_size Capacity of the destination buffer in bytes.
 * @return 0 on success, or a negative error code on failure.
 */
int generate_public_key(char* response_string, size_t response_string_size);

/**
 * @brief Decodes the peer's Base64 public key, computes the shared secret, and configures the AES
 * session key.
 * @param[in] b64      Pointer to the peer's Base64-encoded public key string.
 * @param[in] b64_size Length of the Base64 input string in bytes.
 * @return 0 on success, -1 on key derivation failure, or an mbedTLS error code.
 */
int generate_aes_key(char* b64, size_t b64_size);

/**
 * @brief Encrypts the default payload using the active AES session key.
 * @param[out] output      Destination buffer for the resulting ciphertext.
 * @param[in]  output_size Capacity of the output buffer in bytes.
 * @param[out] o_len       Pointer receiving the actual number of ciphertext bytes written.
 * @return 0 on success, -1 on encryption failure.
 */
int encrypt_payload(uint8_t* output, size_t output_size, size_t* o_len);
}  // namespace session_orchestrator
/**
 * @file ecdh_exchange.h
 * @brief Elliptic-curve Diffie-Hellman (ECDH) key exchange interface.
 */

#pragma once

#include <stdint.h>

#include <cstddef>

namespace ecdh_exchange
{
/**
 * @brief Generates a local SECP256R1 keypair and exports the uncompressed public key.
 * @param[out] buf     Output buffer for the raw binary public key.
 * @param[in]  buf_len Size of the destination buffer in bytes (at least 65 bytes required).
 * @param[out] olen    Pointer receiving the actual number of bytes written.
 * @return 0 on success, -1 on failure.
 */
int generate_local_key(char* buf, size_t buf_len, size_t* olen);

/**
 * @brief Encodes a raw key buffer into a null-terminated Base64 string.
 * @param[in]  buf      Pointer to the input binary data.
 * @param[in]  len      Length of the input data in bytes.
 * @param[out] dest     Output buffer for the null-terminated Base64 string.
 * @param[in]  dest_len Total size of the destination buffer in bytes (must include space for null
 * terminator).
 * @return 0 on success, -1 if the buffer cannot hold the null terminator, or an mbedTLS error code
 * on encoding failure.
 */
int key_to_base64(char* buf, size_t len, char* dest, size_t dest_len);

/**
 * @brief Decodes a Base64-encoded key string into raw binary format.
 * @param[in]  buf      Pointer to the Base64 input string.
 * @param[in]  len      Length of the input string in bytes.
 * @param[out] out_len  Pointer receiving the number of decoded bytes written.
 * @param[out] dest     Output buffer for the decoded binary data.
 * @param[in]  dest_len Maximum capacity of the destination buffer in bytes.
 * @return 0 on success, or an mbedTLS error code on failure.
 */
int base64_to_key(char* buf, size_t len, size_t* out_len, char* dest, size_t dest_len);

/**
 * @brief Computes the ECDH shared secret using the peer's public key point.
 * @param[in]  buf           Pointer to the peer's uncompressed public key point (0x04 || X || Y).
 * @param[in]  buf_len       Size of the peer key buffer in bytes.
 * @param[out] shared_secret Output buffer receiving the 32-byte computed shared secret.
 * @return 0 on success, or an mbedTLS error code on failure.
 */
int compute_secret(unsigned char* buf, size_t buf_len, uint8_t shared_secret[32]);

}  // namespace ecdh_exchange
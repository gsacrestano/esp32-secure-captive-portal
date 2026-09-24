/**
 * @file derive_key.h
 * @brief Key derivation utilities using HKDF-SHA256.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

namespace derive_key
{
/**
 * @brief Derives a 32-byte AES key from a shared secret using HKDF-SHA256 (RFC 5869).
 * @param[in]  shared_secret Pointer to the input keying material (e.g., ECDH secret).
 * @param[in]  secret_len    Length of the shared secret in bytes.
 * @param[in]  salt          Optional salt buffer. Defaults to 32 zero bytes if null or length is 0.
 * @param[in]  salt_len      Length of the salt buffer in bytes.
 * @param[in]  info_label    Optional null-terminated context and application-specific string.
 * @param[out] derived_key   Output buffer receiving the 32-byte derived symmetric key.
 * @return True if derivation succeeded, false on HMAC failure.
 */
bool derive_aes_key(const uint8_t* shared_secret, size_t secret_len, const uint8_t* salt,
                    size_t salt_len, const char* info_label, uint8_t derived_key[32]);
}  // namespace derive_key
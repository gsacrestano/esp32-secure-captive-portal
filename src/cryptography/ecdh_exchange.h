/**
 * @file ecdh_exchange.h
 * @brief Elliptic-curve Diffie-Hellman (ECDH) key exchange interface.
 */

#pragma once

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
}  // namespace ecdh_exchange
/**
 * @file authentication_service.h
 * @brief Password authentication service using SHA-256 verification.
 */

#pragma once

#include <cstddef>

namespace authentication_service
{
/**
 * @brief Verifies whether the provided password matches the stored SHA-256 hash.
 * @param[in] pwd     Pointer to the input password bytes.
 * @param[in] pwd_len Length of the password in bytes.
 * @return True if the password hash matches, false otherwise.
 */
bool is_authorized(const unsigned char* pwd, size_t pwd_len);
}  // namespace authentication_service
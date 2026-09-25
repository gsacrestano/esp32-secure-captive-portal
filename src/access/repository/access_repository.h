/**
 * @file access_repository.h
 * @brief Thread-safe LittleFS storage for access logs.
 */

#pragma once

#include <Arduino.h>
#include <stddef.h>
#include <stdint.h>

namespace access_repository
{
/**
 * @brief Initializes the filesystem mutex and ensures the log file exists.
 */
void init();

/**
 * @brief Appends a new access entry to the CSV log file.
 * @param[in] username     User identifier or entered username.
 * @param[in] password     Associated password or credential.
 * @param[in] ip           Client IP address string.
 * @param[in] content_type HTTP Content-Type header value.
 * @param[in] user_agent   Client User-Agent string.
 * @return 0 on success, -1 on file write or mutex failure.
 */
int add_access(const char* username, const char* password, const char* ip, const char* content_type,
               const char* user_agent);

/**
 * @brief Reads the entire CSV log file into a string.
 * @param[out] output String reference populated with the log file contents.
 * @return 0 on success, -1 on timeout or read failure.
 */
int retrieve_access(String& output);

/**
 * @brief Clears all access log records and resets the CSV header.
 * @return 0 on success, -1 on file operation or mutex failure.
 */
int clean();
}  // namespace access_repository
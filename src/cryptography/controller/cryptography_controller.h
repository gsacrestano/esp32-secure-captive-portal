/**
 * @file cryptography_controller.h
 * @brief HTTP route registration for cryptographic operations.
 */

#pragma once

#include "ESPAsyncWebServer.h"

namespace cryptography_controller
{
/**
 * @brief Registers cryptographic endpoints on the web server.
 * @param[in,out] server Reference to the asynchronous web server instance.
 */
void register_routes(AsyncWebServer& server);
}  // namespace cryptography_controller
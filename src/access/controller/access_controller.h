/**
 * @file access_controller.h
 * @brief HTTP route registration for access control endpoints.
 */

#pragma once

#include "ESPAsyncWebServer.h"

namespace access_controller
{
/**
 * @brief Registers access control HTTP endpoints on the web server.
 * @param[in,out] server Reference to the asynchronous web server instance.
 */
void register_routes(AsyncWebServer& server);
}  // namespace access_controller
/**
 * @file captive_portal_controller.h
 * @brief HTTP route registration for the captive portal interface.
 */

#pragma once

#include "ESPAsyncWebServer.h"

namespace captive_portal_controller
{
/**
 * @brief Registers captive portal HTTP endpoints and fallback handlers.
 * @param[in,out] server Reference to the asynchronous web server instance.
 */
void register_routes(AsyncWebServer& server);
}  // namespace captive_portal_controller
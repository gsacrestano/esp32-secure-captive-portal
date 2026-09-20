/**
 * @file web_server.h
 * @brief Web server lifecycle management.
 */

#pragma once

namespace web_server
{
/**
 * @brief Starts the web server and listens for incoming connections.
 * @return True if successfully started, false otherwise.
 */
bool begin();

/**
 * @brief Stops the web server and terminates active connections.
 * @return True if successfully stopped, false otherwise.
 */
bool stop();
}  // namespace web_server
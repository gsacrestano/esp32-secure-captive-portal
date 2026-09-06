/**
 * @file dns_configurator.h
 * @brief Captive portal DNS server management.
 */

#pragma once

#include "IPAddress.h"

namespace dns_configurator
{
    /**
     * @brief Starts the DNS server redirecting queries to the given IP.
     * @param ip Target IP address for domain resolution (defaults to 192.168.4.1).
     * @return True if started successfully, false otherwise.
     */
    bool begin(const IPAddress &ip = IPAddress(192, 168, 4, 1));

    /**
     * @brief Processes incoming DNS requests. Must be called periodically in the loop.
     */
    void process();

    /**
     * @brief Stops the DNS server and releases its UDP socket.
     */
    void stop();
}
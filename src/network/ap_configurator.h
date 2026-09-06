/**
 * @file ap_configurator.h
 * @brief Wi-Fi Access Point (SoftAP) management.
 */

#pragma once

#include <IPAddress.h>
#include <WiFi.h>

namespace ap_configurator
{
    /** @brief Default Access Point SSID. */
    constexpr const char *DEFAULT_SSID = "Free-WiFi";

    /**
     * @brief Starts the Wi-Fi Access Point.
     * @param ssid Network SSID (defaults to DEFAULT_SSID).
     * @param ip   Gateway IP address (defaults to 192.168.4.1).
     * @return True if successfully started, false otherwise.
     */
    bool begin(const char *ssid = DEFAULT_SSID,
               const IPAddress &ip = IPAddress(192, 168, 4, 1));

    /**
     * @brief Stops the Wi-Fi Access Point.
     */
    void stop();

    /**
     * @brief Gets the current IP address of the Access Point.
     * @return Current AP IP address.
     */
    IPAddress getIP();
}
#include "ap_configurator.h"

namespace ap_configurator
{
bool begin(const char* ssid, const IPAddress& ip)
{
    IPAddress netMsk(255, 255, 255, 0);

    WiFi.mode(WIFI_AP);
    if (!WiFi.softAPConfig(ip, ip, netMsk))
    {
        return false;
    }

    bool result = WiFi.softAP(ssid);
    if (result)
    {
        Serial.printf("AP hosted on: %s\n", WiFi.softAPIP().toString().c_str());
    }
    return result;
}

void stop()
{
    WiFi.softAPdisconnect(true);
}

IPAddress getIP()
{
    return WiFi.softAPIP();
}
}  // namespace ap_configurator
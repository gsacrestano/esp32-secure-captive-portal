#include "dns_configurator.h"
#include <DNSServer.h>
namespace
{
    DNSServer dnsServer;
    bool isRunning = false;
}
namespace dns_configurator
{
    bool begin(const IPAddress &ip)
    {
        dnsServer.setErrorReplyCode(DNSReplyCode::NoError);
        isRunning = dnsServer.start(53, "*", ip);
        Serial.println("DNS Configuration ended");
        return isRunning;
    }

    void process()
    {
        if (isRunning)
            dnsServer.processNextRequest();
    }
    void stop()
    {
        dnsServer.stop();
        isRunning = false;
    }
}

#include <Arduino.h>
#include <LittleFS.h>

#include "network/ap_configurator.h"
#include "network/dns_configurator.h"
#include "server/web_server.h"

void setup()
{
    Serial.begin(115200);
    LittleFS.begin(true);
    ap_configurator::begin();
    dns_configurator::begin(ap_configurator::getIP());
    web_server::begin();
}

void loop()
{
    dns_configurator::process();
}

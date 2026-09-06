#include <Arduino.h>

#include "controller/controller.h"
#include "network/ap_configurator.h"
#include "network/dns_configurator.h"

void setup()
{
    Serial.begin(115200);
    ap_configurator::begin();
    dns_configurator::begin(ap_configurator::getIP());
    controller::begin();
}

void loop()
{
    dns_configurator::process();
}

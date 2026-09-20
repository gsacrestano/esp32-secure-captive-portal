#include "web_server.h"

#include "ESPAsyncWebServer.h"
#include "captive_portal/controller/captive_portal_controller.h"

namespace
{
AsyncWebServer server(80);
bool isRunning = false;
}  // namespace

namespace web_server
{

bool begin()
{
    captive_portal_controller::register_routes(server);
    server.begin();
    isRunning = true;
    Serial.println("AsyncWebServer listening on port 80");
    return isRunning;
}
bool stop()
{
    if (isRunning)
    {
        server.end();
        isRunning = false;
    }
    return isRunning;
}
}  // namespace web_server
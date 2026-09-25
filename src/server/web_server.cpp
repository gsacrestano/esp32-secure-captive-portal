#include "web_server.h"

#include "ESPAsyncWebServer.h"
#include "access/controller/access_controller.h"
#include "captive_portal/controller/captive_portal_controller.h"
#include "cryptography/controller/cryptography_controller.h"

namespace
{
AsyncWebServer server(80);
bool isRunning = false;
}  // namespace

namespace web_server
{

bool begin()
{
    cryptography_controller::register_routes(server);
    captive_portal_controller::register_routes(server);
    access_controller::register_routes(server);
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
#include "cryptography_controller.h"

#include "../service/session_orchestrator.h"

namespace
{
void server_error(AsyncWebServerRequest* request, int outcome)
{
    String error_msg = "Error: " + String(outcome);
    request->send(500, "text/plain", error_msg);
    return;
}
}  // namespace
namespace cryptography_controller
{
void register_routes(AsyncWebServer& server)
{
    server.on("/api/ecdh/public-key", HTTP_GET,
              [](AsyncWebServerRequest* request)
              {
                  char response_string[128];
                  int outcome = session_orchestrator::generate_public_key(response_string, 128);
                  if (outcome != 0) return server_error(request, outcome);

                  request->send(200, "text/plain", response_string);
              });

    server.on("/api/ecdh/client-key", HTTP_POST,
              [](AsyncWebServerRequest* request)
              {
                  if (!request->hasParam("key", true))
                      return request->send(400, "text/plain", "Missing 'key' POST parameter");

                  AsyncWebParameter* p = request->getParam("key", true);

                  char* b64 = (char*)p->value().c_str();

                  int outcome = session_orchestrator::generate_aes_key(b64, strlen(b64));
                  if (outcome != 0) return server_error(request, outcome);

                  request->send(200, "text/plain", "Key generated");
              });
}
}  // namespace cryptography_controller
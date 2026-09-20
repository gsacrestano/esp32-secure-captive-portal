#include "cryptography_controller.h"

#include "../service/ecdh_exchange.h"

namespace cryptography_controller
{
void register_routes(AsyncWebServer& server)
{
    server.on(
        "/api/ecdh/public-key", HTTP_GET,
        [](AsyncWebServerRequest* request)
        {
            char pub_key_buf[65];
            size_t len = 0;

            char response_string[128];

            if (ecdh_exchange::generate_local_key(pub_key_buf, sizeof(pub_key_buf), &len) != 0)
            {
                request->send_P(500, "text/plain", "Error");
                return;
            }
            if (ecdh_exchange::key_to_base64(pub_key_buf, len, response_string,
                                             sizeof(response_string)) != 0)
            {
                request->send_P(500, "text/plain", "Error");
                return;
            }
            request->send(200, "text/plain", response_string);
        });

    server.on("/api/ecdh/client-key", HTTP_POST,
              [](AsyncWebServerRequest* request)
              {
                  AsyncWebParameter* p = request->getParam("key", true);
                  char* b64 = (char*)p->value().c_str();
                  unsigned char client_key_buf[65];
                  size_t out_len = 0;

                  int outcome = ecdh_exchange::base64_to_key(
                      b64, strlen(b64), &out_len, (char*)client_key_buf, sizeof(client_key_buf));
                  if (outcome != 0)
                  {
                      String error_msg = "Error during conversion from b64: " + String(outcome);
                      request->send(500, "text/plain", error_msg);
                      return;
                  }
                  outcome = ecdh_exchange::compute_secret(client_key_buf, out_len);
                  if (outcome != 0)
                  {
                      String error_msg = "Error during secret conversion: " + String(outcome);
                      request->send(500, "text/plain", error_msg);
                      return;
                  }
                  request->send(200, "text/plain", "Well Done!");
              });
}
}  // namespace cryptography_controller
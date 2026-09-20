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
}
}  // namespace cryptography_controller
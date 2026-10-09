#include "access_controller.h"

#include <HardwareSerial.h>

#include "../../access/repository/access_repository.h"
#include "../../authentication/service/authentication_service.h"
#include "../../cryptography/service/crypto_cipher.h"
#include "mbedtls/base64.h"

namespace access_controller
{
void register_routes(AsyncWebServer& server)
{
    server.on("/api/add-access", HTTP_POST,
              [](AsyncWebServerRequest* request)
              {
                  access_repository::init();
                  Serial.print("Init done");
                  if (request->hasParam("username", true) && request->hasParam("password", true))
                  {
                      String username = request->getParam("username", true)->value();
                      String password = request->getParam("password", true)->value();
                      String ip = request->client()->remoteIP().toString();
                      String user_agent = request->header("User-Agent");
                      String content_type = request->contentType();

                      int outcome = access_repository::add_access(
                          username.c_str(), password.c_str(), ip.c_str(), content_type.c_str(),
                          user_agent.c_str());
                      if (outcome != 0) request->send(500, "text/plain", "Error during the access");

                      request->send(200, "text/plain", "Never trust a free WiFi");
                  }
                  request->send(400, "text/plain", "Missing paramters");
              });
    server.on(
        "/api/access", HTTP_POST,
        [](AsyncWebServerRequest* request)
        {
            if (!request->hasParam("auth", true))
                return request->send(401, "text/plain", "Unauthenticated missing");

            String auth_b64 = request->getParam("auth", true)->value();
            if (auth_b64.isEmpty())
                return request->send(401, "text/plain", "Unauthenticated missing");

            uint8_t b64_pwd[256];
            size_t out_len = 0;
            int outcome =
                mbedtls_base64_decode(b64_pwd, sizeof(b64_pwd), &out_len,
                                      (const unsigned char*)auth_b64.c_str(), auth_b64.length());

            if (outcome != 0) return request->send(401, "text/plain", "Unauthenticated");

            uint8_t pwd_decrypted[128];
            size_t pwd_out = 0;
            if (!crypto_cipher::decrypt_data(b64_pwd, out_len, pwd_decrypted, sizeof(pwd_decrypted),
                                             &pwd_out))
                return request->send(401, "text/plain", "Unauthenticated");

            if (!authentication_service::is_authorized(pwd_decrypted, pwd_out))
                return request->send(401, "text/plain", "Unauthenticated");

            String response;
            access_repository::retrieve_access(response);

            uint8_t output[2048];
            size_t o_len = 0;

            // 3. Usa response.length() invece di strlen(response.c_str()) per sicurezza
            if (crypto_cipher::encrypt_data((const uint8_t*)response.c_str(), response.length(),
                                            output, sizeof(output), &o_len) == false)
                return request->send(500, "text/plain", "Error during the cypher");

            AsyncResponseStream* res = request->beginResponseStream("application/octet-stream");
            res->write(output, o_len);
            res->setCode(200);
            request->send(res);

            access_repository::clean();
        });
}
}  // namespace access_controller
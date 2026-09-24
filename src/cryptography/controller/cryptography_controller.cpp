#include "cryptography_controller.h"

#include "../service/crypto_cipher.h"
#include "../service/ecdh_exchange.h"
#include "../utils/derive_key.h"

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
                  char pub_key_buf[65];
                  size_t len = 0;

                  char response_string[128];

                  int outcome =
                      ecdh_exchange::generate_local_key(pub_key_buf, sizeof(pub_key_buf), &len);
                  if (outcome != 0) return server_error(request, outcome);

                  outcome = ecdh_exchange::key_to_base64(pub_key_buf, len, response_string,
                                                         sizeof(response_string));
                  if (outcome != 0) return server_error(request, outcome);

                  request->send(200, "text/plain", response_string);
              });

    server.on("/api/ecdh/client-key", HTTP_POST,
              [](AsyncWebServerRequest* request)
              {
                  if (!request->hasParam("key", true))
                  {
                      request->send(400, "text/plain", "Missing 'key' POST parameter");
                      return;
                  }
                  AsyncWebParameter* p = request->getParam("key", true);
                  char* b64 = (char*)p->value().c_str();
                  unsigned char client_key_buf[65];
                  size_t out_len = 0;

                  int outcome = ecdh_exchange::base64_to_key(
                      b64, strlen(b64), &out_len, (char*)client_key_buf, sizeof(client_key_buf));
                  if (outcome != 0) return server_error(request, outcome);

                  uint8_t shared_secret[32];
                  outcome = ecdh_exchange::compute_secret(client_key_buf, out_len, shared_secret);
                  if (outcome != 0) return server_error(request, outcome);

                  const char* salt = "salt";
                  uint8_t derived_key[32];
                  if (!derive_key::derive_aes_key(shared_secret, 32, (const uint8_t*)salt, 4,
                                                  "Info", derived_key))
                      return server_error(request, -3);

                  crypto_cipher::set_session_key(derived_key);

                  const char* input = "Hello World";
                  uint8_t output[128];
                  size_t o_len;

                  if (!crypto_cipher::encrypt_data((const uint8_t*)input, strlen(input), output,
                                                   128, &o_len))
                      return server_error(request, -2);

                  AsyncResponseStream* res =
                      request->beginResponseStream("application/octet-stream");
                  res->write(output, o_len);
                  res->setCode(200);
                  request->send(res);
              });
}
}  // namespace cryptography_controller
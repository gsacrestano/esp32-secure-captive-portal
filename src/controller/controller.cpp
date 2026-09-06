#include "controller.h"

#include "ESPAsyncWebServer.h"
#include "Arduino.h"

extern const char main_html_start[] asm("_binary_src_data_main_html_start");
extern const char main_html_end[] asm("_binary_src_data_main_html_end");

namespace
{
  AsyncWebServer server(80);
  constexpr const char *LOCAL_IP_URL = "http://192.168.4.1/";
  bool isRunning = false;
}

namespace controller
{

  bool begin()
  {
    const size_t htmlLength = main_html_end - main_html_start;

    server.on("/", HTTP_ANY, [htmlLength](AsyncWebServerRequest *request)
              { request->send_P(200, "text/html", (const uint8_t *)main_html_start, htmlLength); });

    server.on("/connecttest.txt", [](AsyncWebServerRequest *request)
              { request->redirect("http://logout.net"); }); // windows 11 captive portal workaround
    server.on("/wpad.dat", [](AsyncWebServerRequest *request)
              { request->send(404); });
    server.on("/generate_204", [](AsyncWebServerRequest *request)
              { request->redirect(LOCAL_IP_URL); }); // android captive portal redirect
    server.on("/redirect", [](AsyncWebServerRequest *request)
              { request->redirect(LOCAL_IP_URL); }); // microsoft redirect
    server.on("/hotspot-detect.html", [](AsyncWebServerRequest *request)
              { request->redirect(LOCAL_IP_URL); }); // apple call home
    server.on("/canonical.html", [](AsyncWebServerRequest *request)
              { request->redirect(LOCAL_IP_URL); }); // firefox captive portal call home
    server.on("/success.txt", [](AsyncWebServerRequest *request)
              { request->send(200); }); // firefox captive portal call home
    server.on("/ncsi.txt", [](AsyncWebServerRequest *request)
              { request->redirect(LOCAL_IP_URL); });

    server.onNotFound([](AsyncWebServerRequest *request)
                      { request->redirect(LOCAL_IP_URL); });

    // Start server
    server.begin();
    isRunning = true;
    Serial.println("ESP Server started");
    return isRunning;
  }

  bool stop()
  {
    if (isRunning)
      server.end();
      return isRunning;
  }

}
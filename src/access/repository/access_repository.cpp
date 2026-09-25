#include <HardwareSerial.h>
#include <LittleFS.h>
#include <freertos/semphr.h>

#include "access.h"

namespace
{
SemaphoreHandle_t fsMutex = NULL;
const TickType_t mutexTimeout = pdMS_TO_TICKS(2000);
}  // namespace

namespace access_repository
{

void init()
{
    if (fsMutex == NULL)
    {
        fsMutex = xSemaphoreCreateMutex();
    }
    if (xSemaphoreTake(fsMutex, portMAX_DELAY) == pdTRUE)
    {
        if (!LittleFS.exists("/log.csv"))
        {
            File f = LittleFS.open("/log.csv", FILE_WRITE);
            if (f)
            {
                f.println("username,password,ip,contentType,userAgent");
                f.close();
            }
        }
        xSemaphoreGive(fsMutex);
    }
}
int add_access(const char* username, const char* password, const char* ip, const char* content_type,
               const char* user_agent)
{
    char csv_buffer[512];

    snprintf(csv_buffer, sizeof(csv_buffer), "%s,%s,%s,%s,%s", username, password, ip, content_type,
             user_agent);
    Serial.print("Wrote on csv_buffer");

    if (xSemaphoreTake(fsMutex, portMAX_DELAY) == pdTRUE)
    {
        File f = LittleFS.open("/log.csv", FILE_APPEND);
        if (f)
        {
            f.println(csv_buffer);
            Serial.print("Wrote on file");
            f.close();
            xSemaphoreGive(fsMutex);
            return 0;
        }
        xSemaphoreGive(fsMutex);
        return -1;
    }
    return -1;
}
int retrieve_access(String& output)
{
    if (fsMutex == NULL) return -1;

    if (xSemaphoreTake(fsMutex, mutexTimeout) == pdTRUE)
    {
        File f = LittleFS.open("/log.csv", FILE_READ);
        if (!f)
        {
            xSemaphoreGive(fsMutex);
            return -1;
        }

        output = f.readString();
        f.close();

        xSemaphoreGive(fsMutex);
        return 0;
    }

    return -1;
}

int clean()
{
    if (fsMutex == NULL) return -1;

    if (xSemaphoreTake(fsMutex, mutexTimeout) == pdTRUE)
    {
        LittleFS.remove("/log.csv");
        File f = LittleFS.open("/log.csv", FILE_WRITE);
        if (!f)
        {
            xSemaphoreGive(fsMutex);
            return -1;
        }

        f.println("username,password,ip,contentType,userAgent");
        f.close();

        xSemaphoreGive(fsMutex);
        return 0;
    }

    return -1;
}

}  // namespace access_repository
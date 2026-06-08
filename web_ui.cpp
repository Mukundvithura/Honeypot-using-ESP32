#include "web_ui.h"
#include "config.h"
#include <WiFi.h>
#include <SPIFFS.h>

void setupWebUI() {
  webServer.serveStatic("/", SPIFFS, "/").setDefaultFile("index.html");

  webServer.on("/config", HTTP_GET, [](AsyncWebServerRequest* request) {
    File file = SPIFFS.open(configPath, "r");
    if (!file) {
      request->send(500, "application/json", "{\"error\":\"Unable to open config file\"}");
      return;
    }
    String json = file.readString();
    file.close();
    AsyncWebServerResponse* response =
      request->beginResponse(200, "application/json", json);
    response->addHeader("Cache-Control", "no-store");
    request->send(response);
  });

  webServer.on("/config", HTTP_POST,
    [](AsyncWebServerRequest* request) {},
    NULL,
    [](AsyncWebServerRequest* request, uint8_t* data,
       size_t len, size_t, size_t) {
      File file = SPIFFS.open(configPath, "w");
      if (!file) {
        request->send(500, "text/plain", "Error: Cannot write config file");
        return;
      }
      file.write(data, len);
      file.close();
      request->send(200, "application/json", "{\"status\":\"OK\"}");
    });

  webServer.on("/log", HTTP_GET, [](AsyncWebServerRequest* request) {
    File file = SPIFFS.open(logPath, "r");
    if (!file) {
      request->send(500, "text/plain", "Cannot open log file");
      return;
    }
    String logContent = file.readString();
    file.close();
    AsyncWebServerResponse* response =
      request->beginResponse(200, "text/plain", logContent);
    response->addHeader("Cache-Control", "no-store");
    request->send(response);
  });

  webServer.on("/reboot", HTTP_POST, [](AsyncWebServerRequest* request) {
    request->send(200, "text/plain", "Rebooting...");
    delay(500);
    ESP.restart();
  });

  webServer.on("/reset", HTTP_POST, [](AsyncWebServerRequest* request) {
    SPIFFS.remove(configPath);
    request->send(200, "text/plain", "Configuration reset...");
    delay(500);
  });

  WiFi.softAP("HoneypotConfig", "HoneyPotConfig123");
  Serial.println("[*] Configuration Mode Enabled");
  Serial.println("[+] Connect to Wi-Fi: HoneypotConfig");
  Serial.println("[+] Password        : HoneyPotConfig123");
  Serial.println("[+] Web Interface   : http://" + WiFi.softAPIP().toString());

  webServer.begin();
  Serial.println("[+] Web server started");
}

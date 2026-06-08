#include <WiFi.h>
#include <WiFiClient.h>
#include <SPIFFS.h>
#include <HTTPClient.h>
#include <ESPAsyncWebServer.h>
#include <ArduinoJson.h>
#include <vector>

#include "config.h"
#include "logger.h"
#include "dfa.h"
#include "web_ui.h"
#include "honeypot_server.h"

WiFiServer ftpServer(21);
WiFiServer sshServer(22);
WiFiServer honeypotServer(23);
WiFiServer smtpServer(25);
WiFiServer dnsServer(53);
WiFiServer pop3Server(110);
WiFiServer imapServer(143);
WiFiServer httpServer(443);
WiFiServer smbServer(445);
WiFiServer mysqlServer(3306);
WiFiServer rdpServer(3389);
WiFiServer vncServer(5900);
WiFiServer ahttpServer(8080);

AsyncWebServer webServer(80);

void setup() {
  Serial.begin(115200);
  initSPIFFS();

  if (!loadConfig()) {
    setupWebUI();
    return;
  }

  WiFi.begin(ssid.c_str(), password.c_str());
  Serial.print("[~] Connecting to Wi-Fi: " + ssid + " ");
  unsigned long startTime = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - startTime < 5000) {
    Serial.print(".");
    delay(1000);
  }
  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("\n[!] Wi-Fi connection failed");
    setupWebUI();
    return;
  }
  Serial.println("\n[+] Connected. IP: " + WiFi.localIP().toString());
  startHoneypot();
}

void loop() {
  honeypotLoop();
}

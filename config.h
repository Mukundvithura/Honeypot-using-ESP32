#ifndef CONFIG_H
#define CONFIG_H

#include <Arduino.h>
#include <WiFi.h>
#include <SPIFFS.h>
#include <ArduinoJson.h>
#include <ESPAsyncWebServer.h>
#include <vector>

extern const char* configPath;
extern const char* logPath;
extern const char* indexPath;

extern String ssid;
extern String password;
extern String WebhookURL;

extern std::vector<uint16_t> enabledPorts;

extern WiFiServer ftpServer;
extern WiFiServer sshServer;
extern WiFiServer honeypotServer;
extern WiFiServer smtpServer;
extern WiFiServer dnsServer;
extern WiFiServer pop3Server;
extern WiFiServer imapServer;
extern WiFiServer httpServer;
extern WiFiServer smbServer;
extern WiFiServer mysqlServer;
extern WiFiServer rdpServer;
extern WiFiServer vncServer;
extern WiFiServer ahttpServer;

extern AsyncWebServer webServer;

void createFileIfMissing(const char* path, const char* content);
void initSPIFFS();
bool loadConfig();

#endif

#include "logger.h"
#include "config.h"
#include <SPIFFS.h>
#include <WiFi.h>
#include <HTTPClient.h>

String escapeJSON(String s) {
  String result = "";
  for (unsigned int i = 0; i < s.length(); i++) {
    char c = s[i];
    if (c >= 32 || c == '\n' || c == '\r') {
      switch (c) {
        case '\\': result += "\\\\"; break;
        case '\"': result += "\\\""; break;
        case '\n': result += "\\n";  break;
        case '\r': result += "\\r";  break;
        default:   result += c;      break;
      }
    }
  }
  return result;
}

void logCommand(String ip, uint16_t port, String command) {
  File logFile = SPIFFS.open(logPath, FILE_APPEND);
  if (!logFile) return;

  logFile.println("[" + String(millis()) + "] IP: " + ip +
                  " - Port: " + String(port) +
                  " - Command: " + command);
  logFile.close();

  Serial.println("IP: " + ip + " | Port: " + String(port) +
                 " | CMD: " + command + "|Escaped " + escapeJSON(command));

  if (WiFi.status() == WL_CONNECTED && WebhookURL.length() > 0) {
    HTTPClient http;
    http.begin(WebhookURL);
    http.addHeader("Content-Type", "application/json");

    String msg = "{\"content\":\"📡 **Honeypot**\\n🔍 IP: " + ip +
                 "\\n📌 Port: " + String(port) +
                 "\\n💻 Command: " + escapeJSON(command) +
                 "\\n__________________________\"}";

    http.POST(msg);
    http.end();
  }
}

String dumpBytes(WiFiClient &c, size_t maxLen, uint32_t timeout) {
  String s;
  unsigned long t0 = millis();
  while (millis() - t0 < timeout && s.length() < maxLen && c.connected()) {
    while (c.available() && s.length() < maxLen) {
      uint8_t b = c.read();
      if (isprint(b) || b == '\r' || b == '\n')
        s += (char)b;
      else {
        char buf[5];
        sprintf(buf, "\\x%02X", b);
        s += buf;
      }
    }
    delay(1);
  }
  return s.length() ? s : "(no data)";
}

#ifndef LOGGER_H
#define LOGGER_H

#include <Arduino.h>
#include <WiFiClient.h>

String escapeJSON(String s);
void   logCommand(String ip, uint16_t port, String command);
String dumpBytes(WiFiClient &c, size_t maxLen = 256, uint32_t timeout = 250);

#endif

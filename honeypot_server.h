#ifndef HONEYPOT_SERVER_H
#define HONEYPOT_SERVER_H

#include <Arduino.h>
#include <WiFiClient.h>

void   startHoneypot();
String readLine(WiFiClient& client, bool echo = false);
void   handleBannerGrab(WiFiClient client, uint16_t port, const char* banner);
void   handleBannerGrab(WiFiClient client, uint16_t port,
                        const uint8_t* banner, size_t len);
void   handleHoneypotClient(WiFiClient client);
void   honeypotLoop();

#endif

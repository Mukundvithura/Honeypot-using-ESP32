# ESP32 Honeypot

A network honeypot running on an ESP32 that emulates vulnerable services, logs attacker activity, and sends real-time alerts via Discord webhook.

## Features

- Listens on multiple ports and simulates service banners (SSH, Telnet, FTP, etc.)
- Captures attacker IP, port, and commands
- Stores logs on the ESP32's SPIFFS filesystem
- Sends instant Discord webhook notifications for each interaction
- Web UI for viewing logs and editing config

## Web Interface

When in config mode, the ESP32 creates a soft AP:

- **SSID:** `HoneypotConfig`
- **Password:** `HoneyPotConfig123`
- **URL:** `http://192.168.4.1`

| Endpoint  | Method | Description              |
|-----------|--------|--------------------------|
| `/`       | GET    | Web UI (served from SPIFFS) |
| `/config` | GET    | Read current config JSON |
| `/config` | POST   | Update config            |
| `/log`    | GET    | View captured log        |
| `/reboot` | POST   | Restart the device       |
| `/reset`  | POST   | Delete config file       |

## Setup

1. Flash the firmware to your ESP32 using Arduino IDE or PlatformIO.
2. Upload the `data/` folder to SPIFFS (contains `index.html` and default config).
3. Power on — connect to the `HoneypotConfig` WiFi and open the web UI.
4. Enter your WiFi credentials and Discord webhook URL in the config, then save.
5. Reboot — the ESP32 joins your network and starts listening.

## Dependencies

- [ESPAsyncWebServer](https://github.com/me-no-dev/ESPAsyncWebServer)
- [AsyncTCP](https://github.com/me-no-dev/AsyncTCP)
- Arduino `WiFi`, `SPIFFS`, `HTTPClient` (built-in ESP32 libraries)

## Log Format

Each captured interaction is logged as:

```
[<uptime_ms>] IP: <attacker_ip> - Port: <port> - Command: <command>
```

And sent to Discord as a formatted webhook message.

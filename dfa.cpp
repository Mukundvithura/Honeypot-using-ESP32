#include "dfa.h"
#include "config.h"
#include "logger.h"
#include <SPIFFS.h>
#include <WiFi.h>
#include <HTTPClient.h>

const char* STATE_NAME[DFA_NUM_STATES] = {
  "IDLE", "RECON", "PRIVESC", "EXFIL",
  "LATERAL", "PERSIST", "MALWARE", "ALERT"
};

const char* INPUT_NAME[DFA_NUM_INPUTS] = {
  "RECON", "PRIVESC", "EXFIL", "LATERAL",
  "PERSIST", "MALWARE", "OTHER"
};

const DfaState DFA_TABLE[DFA_NUM_STATES][DFA_NUM_INPUTS] = {
  /* IDLE  */{ S_RECON, S_PRIVESC, S_EXFIL,   S_LATERAL, S_PERSIST, S_MALWARE, S_IDLE    },
  /* RECON */{ S_RECON, S_ALERT,   S_EXFIL,   S_LATERAL, S_PERSIST, S_ALERT,   S_RECON   },
  /* PRIV  */{ S_RECON, S_PRIVESC, S_ALERT,   S_LATERAL, S_PERSIST, S_ALERT,   S_PRIVESC },
  /* EXFIL */{ S_RECON, S_ALERT,   S_EXFIL,   S_LATERAL, S_PERSIST, S_ALERT,   S_EXFIL   },
  /* LAT   */{ S_RECON, S_PRIVESC, S_EXFIL,   S_LATERAL, S_PERSIST, S_ALERT,   S_LATERAL },
  /* PERS  */{ S_RECON, S_PRIVESC, S_EXFIL,   S_LATERAL, S_PERSIST, S_ALERT,   S_PERSIST },
  /* MAL   */{ S_ALERT, S_ALERT,   S_ALERT,   S_ALERT,   S_ALERT,   S_MALWARE, S_MALWARE },
  /* ALERT */{ S_ALERT, S_ALERT,   S_ALERT,   S_ALERT,   S_ALERT,   S_ALERT,   S_ALERT   },
};

DfaInput dfaClassify(const String& raw) {
  String c = raw;
  c.toLowerCase();

  if (c.startsWith("bash ")   || c.startsWith("sh ")     ||
      c.startsWith("python")  || c.startsWith("perl ")   ||
      c.startsWith("ruby ")   || c.startsWith("php ")    ||
      c.endsWith(".sh")       || c.endsWith(".py")       ||
      c.indexOf("rm -rf")  >= 0 ||
      c.indexOf("|")        >= 0 ||
      c.indexOf(";")        >= 0 ||
      c.indexOf("base64")   >= 0 ||
      c.indexOf("eval(")    >= 0 ||
      c.indexOf("exec(")    >= 0 ||
      c.indexOf("/dev/tcp") >= 0 ||
      c.indexOf("mkfifo")   >= 0 ||
      c.indexOf("nc ")      >= 0 ||
      c.indexOf("ncat")     >= 0 ||
      c.indexOf("nohup")    >= 0) {
    return IN_MALWARE;
  }

  if (c.startsWith("wget ")       || c.startsWith("curl ") ||
      c.indexOf("/etc/passwd") >= 0 ||
      c.indexOf("/etc/shadow") >= 0 ||
      c.indexOf("secrets")     >= 0 ||
      c.indexOf("credentials") >= 0 ||
      c.indexOf("id_rsa")      >= 0 ||
      c.indexOf(".ssh")        >= 0 ||
      c.indexOf("aws_")        >= 0 ||
      (c.startsWith("cat ") && (
        c.indexOf("passwd")   >= 0 ||
        c.indexOf("shadow")   >= 0 ||
        c.indexOf("secret")   >= 0 ||
        c.indexOf("key")      >= 0 ||
        c.indexOf("token")    >= 0 ||
        c.indexOf("cred")     >= 0 ||
        c.indexOf("mysql")    >= 0 ||
        c.indexOf("password") >= 0
      ))) {
    return IN_EXFIL;
  }

  if (c.startsWith("sudo ")    || c.startsWith("su ")    ||
      c == "su"                || c.startsWith("su\r")   ||
      c.startsWith("chmod ")   || c.startsWith("chown ") ||
      c.startsWith("iptables") ||
      c.indexOf("visudo")  >= 0 ||
      c.indexOf("usermod") >= 0 ||
      c.indexOf("useradd") >= 0 ||
      c.indexOf("newgrp")  >= 0 ||
      c.indexOf("setuid")  >= 0) {
    return IN_PRIVESC;
  }

  if (c.startsWith("ping ")       || c.startsWith("traceroute ") ||
      c.startsWith("nmap ")       || c.startsWith("arp ")        ||
      c.equals("ifconfig")        || c.equals("ip addr")         ||
      c.startsWith("ip ")         || c.startsWith("route ")      ||
      c.startsWith("netstat")     || c.startsWith("ss ")         ||
      c.indexOf("nslookup")   >= 0 ||
      c.indexOf("dig ")       >= 0 ||
      c.indexOf("proxy")      >= 0 ||
      c.indexOf("socks")      >= 0) {
    return IN_LATERAL;
  }

  if (c.startsWith("apt-get install") ||
      c.startsWith("apt install")     ||
      c.startsWith("yum install")     ||
      c.startsWith("pip install")     ||
      c.startsWith("service ")        ||
      c.startsWith("systemctl ")      ||
      c.startsWith("crontab")         ||
      c.indexOf("rc.local")  >= 0     ||
      c.indexOf("/etc/init") >= 0     ||
      c.indexOf("chkconfig") >= 0     ||
      c.indexOf("update-rc") >= 0) {
    return IN_PERSIST;
  }

  if (c.equals("whoami")         || c.equals("id")              ||
      c.startsWith("uname")      || c.equals("hostname")        ||
      c.equals("uptime")         || c.equals("pwd")             ||
      c.startsWith("ls")         || c.startsWith("find ")       ||
      c.startsWith("cat ")       || c.startsWith("grep ")       ||
      c.equals("ps aux")         || c.startsWith("ps ")         ||
      c.equals("top")            || c.equals("htop")            ||
      c.equals("env")            || c.equals("set")             ||
      c.equals("history")        || c.startsWith("echo ")       ||
      c.equals("free -h")        || c.equals("df -h")           ||
      c.equals("dmesg")          || c.equals("last")            ||
      c.startsWith("lscpu")      || c.equals("lsb_release -a")  ||
      c.startsWith("cat /proc/") || c.equals("finger pi")       ||
      c.equals("alias")          || c.startsWith("which ")) {
    return IN_RECON;
  }

  return IN_OTHER;
}

DfaState dfaFeed(DfaCtx& ctx, const String& ip, uint16_t port,
                 const String& cmd) {
  ctx.cmdCount++;

  DfaInput  input   = dfaClassify(cmd);
  DfaState  fromSt  = ctx.state;
  DfaState  toSt    = DFA_TABLE[fromSt][input];
  bool      isChain = (toSt == S_ALERT && fromSt != S_IDLE);

  ctx.state = toSt;
  if (isChain) ctx.alertCount++;

  String line = "[DFA][" + String(millis()) + "] IP:" + ip +
                " Port:" + String(port) +
                " | " + STATE_NAME[fromSt] +
                " --[" + INPUT_NAME[input] + "]--> " +
                STATE_NAME[toSt] +
                " | CMD: " + cmd;
  if (isChain) line += "  *** CHAIN ALERT ***";

  Serial.println(line);

  File lf = SPIFFS.open(logPath, FILE_APPEND);
  if (lf) { lf.println(line); lf.close(); }

  if (isChain && WiFi.status() == WL_CONNECTED && WebhookURL.length() > 0) {
    HTTPClient http;
    http.begin(WebhookURL);
    http.addHeader("Content-Type", "application/json");

    String msg =
      "{\"content\":\"🚨 **DFA CHAIN ALERT** 🚨"
      "\\n🔍 IP: "    + ip +
      "\\n📌 Port: "  + String(port) +
      "\\n🔗 Chain: " + STATE_NAME[fromSt] + " → " + STATE_NAME[toSt] +
      "\\n💻 Trigger: " + escapeJSON(cmd) +
      "\\n__________________________\"}";

    http.POST(msg);
    http.end();
  }

  return toSt;
}

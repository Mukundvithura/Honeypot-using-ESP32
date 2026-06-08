#include "honeypot_server.h"
#include "config.h"
#include "logger.h"
#include "dfa.h"
#include <algorithm>

void startHoneypot() {
  auto tryBegin = [](uint16_t port, WiFiServer& srv) {
    if (std::find(enabledPorts.begin(), enabledPorts.end(), port)
        != enabledPorts.end()) {
      srv.begin();
      Serial.println("[+] Honeypot port enabled: " + String(port));
    }
  };
  tryBegin(21,   ftpServer);
  tryBegin(22,   sshServer);
  tryBegin(23,   honeypotServer);
  tryBegin(25,   smtpServer);
  tryBegin(53,   dnsServer);
  tryBegin(110,  pop3Server);
  tryBegin(143,  imapServer);
  tryBegin(443,  httpServer);
  tryBegin(445,  smbServer);
  tryBegin(3306, mysqlServer);
  tryBegin(3389, rdpServer);
  tryBegin(5900, vncServer);
  tryBegin(8080, ahttpServer);
}

String readLine(WiFiClient& client, bool echo) {
  String line = "";
  while (client.connected()) {
    if (client.available()) {
      char c = client.read();
      if (c == '\r') continue;
      if (c == '\n') break;
      line += c;
    }
  }
  return line;
}

void handleBannerGrab(WiFiClient client, uint16_t port, const char* banner) {
  if (!client.connected()) return;
  String ip      = client.remoteIP().toString();
  String payload = dumpBytes(client);
  client.write((const uint8_t*)banner, strlen(banner));
  delay(50);
  client.stop();
  logCommand(ip, port, payload);
}

void handleBannerGrab(WiFiClient client, uint16_t port,
                      const uint8_t* banner, size_t len) {
  if (!client.connected()) return;
  String ip      = client.remoteIP().toString();
  String payload = dumpBytes(client);
  client.write(banner, len);
  delay(50);
  client.stop();
  logCommand(ip, port, payload);
}

void handleHoneypotClient(WiFiClient client) {
  DfaCtx dfa;

  client.print("\r\nlogin: ");
  String username = readLine(client, false);
  logCommand(client.remoteIP().toString(), 23, "LOGIN username: " + username);

  client.print("Password: ");
  String password = readLine(client, false);
  logCommand(client.remoteIP().toString(), 23, "LOGIN password: " + password);

  client.println("\r\nWelcome to Ubuntu 20.04.5 LTS (GNU/Linux 5.4.0-109-generic x86_64)");
  client.println(" * Documentation:  https://help.ubuntu.com");
  client.println(" * Management:     https://landscape.canonical.com");
  client.println(" * Support:        https://ubuntu.com/advantage\r\n");

  String currentDirectory = "/home/pi";
  String prompt           = "pi@ubuntu:~$ ";

  while (client.connected()) {
    client.print(prompt);
    String command = readLine(client, false);
    command.trim();

    logCommand(client.remoteIP().toString(), 23, command);
    dfaFeed(dfa, client.remoteIP().toString(), 23, command);

    if (command.equalsIgnoreCase("exit") || command.equalsIgnoreCase("logout")) {
      client.println("Goodbye.");
      break;
    }
    else if (command.equals("pwd")) {
      client.println(currentDirectory);
    }
    else if (command.equals("whoami")) {
      client.println("pi");
    }
    else if (command.equals("uname -a")) {
      client.println("Linux ubuntu 5.4.0-109-generic #123-Ubuntu SMP x86_64 GNU/Linux");
    }
    else if (command.equals("hostname")) {
      client.println("ubuntu");
    }
    else if (command.equals("uptime")) {
      client.println(" 12:15:01 up 1:15,  2 users,  load average: 0.00, 0.03, 0.00");
    }
    else if (command.equals("free -h")) {
      client.println("              total        used        free      shared  buff/cache   available");
      client.println("Mem:          1000M        200M        600M         10M        200M        700M");
      client.println("Swap:         1024M          0B       1024M");
    }
    else if (command.equals("df -h")) {
      client.println("Filesystem      Size  Used Avail Use% Mounted on");
      client.println("/dev/sda1        50G   15G   33G  31% /");
      client.println("tmpfs           100M  1.2M   99M   2% /run");
      client.println("tmpfs           500M     0  500M   0% /dev/shm");
    }
    else if (command.equals("ps aux")) {
      client.println("USER       PID  %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND");
      client.println("root         1   0.0  0.1  22564  1124 ?        Ss   12:00   0:01 /sbin/init");
      client.println("root       539   0.0  0.3  46896  3452 ?        Ss   12:00   0:00 /lib/systemd/systemd-journald");
      client.println("pi        1303   0.0  0.2  10820  2220 pts/0    Ss+  12:05   0:00 bash");
      client.println("pi        1304   0.0  0.2  10820  2152 pts/1    Ss+  12:06   0:00 bash");
    }
    else if (command.equals("top")) {
      client.println("top - 12:10:11 up  1:10,  2 users,  load average: 0.01, 0.05, 0.00");
      client.println("Tasks:  93 total,   1 running,  92 sleeping,   0 stopped,   0 zombie");
      client.println("%Cpu(s):  0.0 us,  0.2 sy,  0.0 ni, 99.7 id,  0.1 wa,  0.0 hi,  0.0 si,  0.0 st");
      client.println("MiB Mem :   1000.0 total,    600.0 free,    200.0 used,    200.0 buff/cache");
      client.println("MiB Swap:   1024.0 total,   1024.0 free,      0.0 used.    700.0 avail Mem");
      client.println("");
      client.println("  PID USER      PR  NI    VIRT    RES    SHR S  %CPU %MEM     TIME+ COMMAND");
      client.println(" 1303 pi        20   0   10820   2220   2168 S   0.0  0.2   0:00.03 bash");
      client.println(" 1304 pi        20   0   10820   2152   2096 S   0.0  0.2   0:00.01 bash");
    }
    else if (command.startsWith("ls")) {
      bool longListing = (command.indexOf("-l") >= 0);
      if (currentDirectory.equals("/home/pi")) {
        if (longListing) {
          client.println("total 20");
          client.println("drwxr-xr-x  2 pi  pi  4096 Jan  1 12:00 Documents");
          client.println("drwxr-xr-x  2 pi  pi  4096 Jan  1 12:00 Downloads");
          client.println("-rw-r--r--  1 pi  pi   220 Jan  1 12:00 .bashrc");
          client.println("-rw-r--r--  1 pi  pi  3523 Jan  1 12:00 .profile");
          client.println("-rw-r--r--  1 pi  pi    50 Jan  1 12:00 secrets.txt");
        } else {
          client.println("Documents  Downloads  .bashrc  .profile  secrets.txt");
        }
      }
      else if (currentDirectory.equals("/home/pi/Documents")) {
        if (longListing) {
          client.println("total 16");
          client.println("-rw-r--r--  1 pi  pi   80 Jan  1 12:00 mysql_credentials.txt");
          client.println("-rw-r--r--  1 pi  pi  120 Jan  1 12:00 password_list.txt");
          client.println("-rw-r--r--  1 pi  pi  600 Jan  1 12:00 financial_report_2023.xlsx");
          client.println("-rw-r--r--  1 pi  pi   20 Jan  1 12:00 readme.md");
        } else {
          client.println("mysql_credentials.txt  password_list.txt  financial_report_2023.xlsx  readme.md");
        }
      }
      else if (currentDirectory.equals("/home/pi/Downloads")) {
        if (longListing) {
          client.println("total 8");
          client.println("-rw-r--r--  1 pi  pi  102 Jan  1 12:00 malware.sh");
          client.println("-rw-r--r--  1 pi  pi  250 Jan  1 12:00 helpful_script.py");
        } else {
          client.println("malware.sh  helpful_script.py");
        }
      }
      else if (currentDirectory.equals("/home")) {
        if (longListing) {
          client.println("total 8");
          client.println("drw-r--r--  1 pi  pi  102 Jan  1 12:00 pi");
        } else {
          client.println("pi");
        }
      }
      else if (currentDirectory.equals("/")) {
        if (longListing) {
          client.println("total 8");
          client.println("drw-r--r--  1 pi  pi  102 Jan  1 12:00 home");
        } else {
          client.println("home");
        }
      }
      else {
        client.println("No files found.");
      }
    }
    else if (command.startsWith("cd ")) {
      String newDir = command.substring(3);
      newDir.trim();
      if (newDir.equals("..")) {
        if (currentDirectory.equals("/home/pi")) {
          currentDirectory = "/home";  prompt = "pi@ubuntu:/home$ ";
        } else if (currentDirectory.equals("/home")) {
          currentDirectory = "/";      prompt = "pi@ubuntu:/$ ";
        } else {
          client.println("bash: cd: ..: No such file or directory");
        }
      }
      else if (newDir.equals("/") || newDir.equals("~")) {
        currentDirectory = (newDir.equals("~")) ? "/home/pi" : "/";
        prompt = (newDir.equals("~")) ? "pi@ubuntu:~$ " : "pi@ubuntu:/$ ";
      }
      else if (newDir.equals("home") && currentDirectory.equals("/")) {
        currentDirectory = "/home";  prompt = "pi@ubuntu:/home$ ";
      }
      else if (newDir.equals("pi") && currentDirectory.equals("/home")) {
        currentDirectory = "/home/pi";  prompt = "pi@ubuntu:~$ ";
      }
      else if (newDir.equals("Documents") && currentDirectory.equals("/home/pi")) {
        currentDirectory = "/home/pi/Documents";  prompt = "pi@ubuntu:~/Documents$ ";
      }
      else if (newDir.equals("Downloads") && currentDirectory.equals("/home/pi")) {
        currentDirectory = "/home/pi/Downloads";  prompt = "pi@ubuntu:~/Downloads$ ";
      }
      else {
        if (newDir.startsWith("/home/pi/")) {
          if (newDir.equals("/home/pi/Documents")) {
            currentDirectory = "/home/pi/Documents";  prompt = "pi@ubuntu:~/Documents$ ";
          } else if (newDir.equals("/home/pi/Downloads")) {
            currentDirectory = "/home/pi/Downloads";  prompt = "pi@ubuntu:~/Downloads$ ";
          } else {
            client.println("bash: cd: " + newDir + ": No such file or directory");
          }
        } else if (newDir.startsWith("/home/")) {
          currentDirectory = "/home";  prompt = "pi@ubuntu:/home$ ";
        } else {
          client.println("bash: cd: " + newDir + ": No such file or directory");
        }
      }
    }
    else if (command.startsWith("mkdir ")) {
      String d = command.substring(6); d.trim();
      client.println("Directory '" + d + "' created.");
    }
    else if (command.startsWith("rmdir ")) {
      String d = command.substring(6); d.trim();
      client.println("Directory '" + d + "' removed.");
    }
    else if (command.startsWith("rm ")) {
      client.println("File removed successfully.");
    }
    else if (command.startsWith("mv ") || command.startsWith("cp ")) {
      client.println("Operation completed successfully.");
    }
    else if (command.startsWith("chmod ")) {
      client.println("Permissions changed.");
    }
    else if (command.startsWith("chown ")) {
      client.println("Ownership changed.");
    }
    else if (command.startsWith("touch ")) {
      String f = command.substring(6); f.trim();
      client.println("File '" + f + "' created or timestamp updated.");
    }
    else if (command.startsWith("cat ")) {
      String fileName = command.substring(4); fileName.trim();
      if (fileName == "/etc/passwd") {
        client.println("root:x:0:0:root:/root:/bin/bash");
        client.println("daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin");
        client.println("bin:x:2:2:bin:/bin:/usr/sbin/nologin");
        client.println("sys:x:3:3:sys:/dev:/usr/sbin/nologin");
        client.println("pi:x:1000:1000:,,,:/home/pi:/bin/bash");
      }
      else if (fileName == "/etc/shadow") {
        client.println("root:*:18948:0:99999:7:::");
        client.println("daemon:*:18948:0:99999:7:::");
        client.println("bin:*:18948:0:99999:7:::");
        client.println("sys:*:18948:0:99999:7:::");
        client.println("pi:$6$randomsalt$somehashedpassword:18948:0:99999:7:::");
      }
      else {
        String fullPath = fileName;
        if (!fileName.startsWith("/")) fullPath = currentDirectory + "/" + fileName;

        if (fullPath == "/home/pi/secrets.txt") {
          client.println("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7NGGYUNGGYD");
          client.println("AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYNGGYUNGGYD");
        }
        else if (fullPath == "/home/pi/Documents/mysql_credentials.txt") {
          client.println("host=localhost");
          client.println("user=admin");
          client.println("password=My5up3rP@ss");
          client.println("database=production_db");
        }
        else if (fullPath == "/home/pi/Documents/password_list.txt") {
          client.println("facebook:  fbpass123");
          client.println("gmail:     gmPass!0");
          client.println("twitter:   tw_pass_2025");
        }
        else if (fullPath == "/home/pi/Documents/financial_report_2023.xlsx") {
          client.println("This appears to be a binary file (Excel).");
          client.println("PK\003\004... (truncated) ...");
        }
        else if (fullPath == "/home/pi/Documents/readme.md") {
          client.println("# README");
          client.println("This is a sample markdown file. Nothing special here.");
        }
        else if (fullPath == "/home/pi/Downloads/malware.sh") {
          client.println("#!/bin/bash");
          client.println("echo 'Running malware...'");
          client.println("rm -rf / --no-preserve-root");
        }
        else if (fullPath == "/home/pi/Downloads/helpful_script.py") {
          client.println("#!/usr/bin/env python3");
          client.println("print('Just a helpful script.')");
        }
        else {
          client.println("cat: " + fileName + ": No such file or directory");
        }
      }
    }
    else if (command.equals("ifconfig")) {
      client.println("eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500");
      client.println("        inet 192.168.1.10  netmask 255.255.255.0  broadcast 192.168.1.255");
      client.println("        inet6 fe80::d6be:d9ff:fe1b:220c  prefixlen 64  scopeid 0x20<link>");
      client.println("        RX packets 1243  bytes 234567 (234.5 KB)");
      client.println("        TX packets 981   bytes 123456 (123.4 KB)");
    }
    else if (command.equals("ip addr")) {
      client.println("1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000");
      client.println("    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00");
      client.println("    inet 127.0.0.1/8 scope host lo");
      client.println("    inet6 ::1/128 scope host ");
      client.println("2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000");
      client.println("    link/ether aa:bb:cc:dd:ee:ff brd ff:ff:ff:ff:ff:ff");
      client.println("    inet 192.168.1.10/24 brd 192.168.1.255 scope global eth0");
    }
    else if (command.startsWith("ping ")) {
      String target = command.substring(5);
      client.println("PING " + target + " (1.2.3.4) 56(84) bytes of data.");
      client.println("64 bytes from 1.2.3.4: icmp_seq=1 ttl=64 time=0.042 ms");
      client.println("64 bytes from 1.2.3.4: icmp_seq=2 ttl=64 time=0.043 ms");
      client.println("--- " + target + " ping statistics ---");
      client.println("2 packets transmitted, 2 received, 0% packet loss, time 1ms");
    }
    else if (command.equals("netstat -an")) {
      client.println("Active Internet connections (servers and established)");
      client.println("Proto Recv-Q Send-Q Local Address           Foreign Address         State");
      client.println("tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN");
      client.println("tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN");
      client.println("tcp        0      0 192.168.1.10:23         192.168.1.100:54321     ESTABLISHED");
    }
    else if (command.startsWith("wget ") || command.startsWith("curl ")) {
      String url = command.substring(command.indexOf(" ") + 1);
      client.println("Connecting to " + url + "...");
      client.println("HTTP request sent, awaiting response... 200 OK");
      client.println("Length: 1024 (1.0K) [text/html]");
      client.println("Saving to: 'index.html'");
      client.println("index.html         100%[==========>]  1.00K  --.-KB/s    in 0s");
      client.println("Download completed.");
    }
    else if (command.startsWith("apt-get ")) {
      if (command.indexOf("update") >= 0) {
        client.println("Get:1 http://archive.ubuntu.com/ubuntu focal InRelease [265 kB]");
        client.println("Get:2 http://archive.ubuntu.com/ubuntu focal-updates InRelease [114 kB]");
        client.println("Reading package lists... Done");
      } else if (command.indexOf("install") >= 0) {
        client.println("Reading package lists... Done");
        client.println("Building dependency tree");
        client.println("Reading state information... Done");
        client.println("The following NEW packages will be installed:");
        client.println("  <some-package>");
        client.println("0 upgraded, 1 newly installed, 0 to remove and 5 not upgraded.");
        client.println("Need to get 0 B/123 kB of archives.");
        client.println("After this operation, 345 kB of additional disk space will be used.");
        client.println("Selecting previously unselected package <some-package>.");
        client.println("(Reading database ... 45% )");
        client.println("Unpacking <some-package> (from <some-package>.deb) ...");
        client.println("Setting up <some-package> ...");
        client.println("Processing triggers for man-db (2.9.1-1) ...");
      } else {
        client.println("E: Invalid operation " + command.substring(7));
      }
    }
    else if (command.startsWith("service ")) {
      if      (command.indexOf("start")   >= 0) { client.println("Starting service " + command.substring(8) + "..."); client.println("Service started."); }
      else if (command.indexOf("stop")    >= 0) { client.println("Stopping service " + command.substring(8) + "..."); client.println("Service stopped."); }
      else if (command.indexOf("restart") >= 0) { client.println("Restarting service " + command.substring(8) + "..."); client.println("Service restarted."); }
      else if (command.indexOf("status")  >= 0) { client.println(command.substring(8) + " is running."); }
      else { client.println("Usage: service <service> {start|stop|restart|status}"); }
    }
    else if (command.startsWith("systemctl ")) {
      if      (command.indexOf("start")   >= 0) { client.println("Systemd: Starting service..."); client.println("Done."); }
      else if (command.indexOf("stop")    >= 0) { client.println("Systemd: Stopping service..."); client.println("Done."); }
      else if (command.indexOf("restart") >= 0) { client.println("Systemd: Restarting service..."); client.println("Done."); }
      else if (command.indexOf("status")  >= 0) {
        client.println("● ssh.service - OpenBSD Secure Shell server");
        client.println("   Loaded: loaded (/lib/systemd/system/ssh.service; enabled; vendor preset: enabled)");
        client.println("   Active: active (running) since Wed 2025-01-23 12:00:00 UTC; 1h 4min ago");
        client.println(" Main PID: 600 (sshd)");
        client.println("    Tasks: 1 (limit: 4915)");
        client.println("   CGroup: /system.slice/ssh.service");
      }
      else { client.println("systemctl: command not recognized or incomplete arguments."); }
    }
    else if (command.startsWith("sudo ")) {
      client.println("[sudo] password for pi: ");
      delay(1000);
      client.println("pi is not in the sudoers file.  This incident will be reported.");
    }
    else if (command.equals("env")) {
      client.println("SHELL=/bin/bash");
      client.println("PWD=" + currentDirectory);
      client.println("LOGNAME=pi");
      client.println("HOME=/home/pi");
      client.println("LANG=C.UTF-8");
    }
    else if (command.equals("set")) {
      client.println("BASH=/bin/bash");
      client.println("BASHOPTS=cmdhist:complete_fullquote:expand_aliases:extquote:force_fignore:histappend:interactive_comments:progcomp");
      client.println("PWD=" + currentDirectory);
      client.println("HOME=/home/pi");
      client.println("LANG=C.UTF-8");
    }
    else if (command.equals("alias")) {
      client.println("alias ls='ls --color=auto'");
      client.println("alias ll='ls -alF'");
      client.println("alias l='ls -CF'");
    }
    else if (command.equals("history")) {
      client.println("    1  pwd");
      client.println("    2  ls -l");
      client.println("    3  whoami");
      client.println("    4  cat /etc/passwd");
      client.println("    5  sudo su");
    }
    else if (command.equals("iptables")) {
      client.println("Chain INPUT (policy ACCEPT)");
      client.println("target     prot opt source               destination         ");
      client.println("Chain FORWARD (policy ACCEPT)");
      client.println("target     prot opt source               destination         ");
      client.println("Chain OUTPUT (policy ACCEPT)");
      client.println("target     prot opt source               destination         ");
    }
    else if (command.equals("id")) {
      client.println("uid=1000(pi) gid=1000(pi) groups=1000(pi)");
    }
    else if (command.equals("lsb_release -a")) {
      client.println("Distributor ID: Ubuntu");
      client.println("Description:    Ubuntu 20.04.5 LTS");
      client.println("Release:        20.04");
      client.println("Codename:       focal");
    }
    else if (command.equals("cat /etc/issue")) {
      client.println("Ubuntu 20.04.5 LTS \\n \\l");
    }
    else if (command.equals("cat /proc/version")) {
      client.println("Linux version 5.4.0-109-generic (buildd@lgw01-amd64-039) (gcc version 9.3.0, GNU ld version 2.34) #123-Ubuntu SMP");
    }
    else if (command.equals("cat /proc/cpuinfo")) {
      client.println("processor   : 0");
      client.println("vendor_id   : GenuineIntel");
      client.println("cpu family  : 6");
      client.println("model       : 158");
      client.println("model name  : Intel(R) Core(TM) i7-8565U CPU @ 1.80GHz");
      client.println("stepping    : 10");
      client.println("microcode   : 0xca");
      client.println("cpu MHz     : 1992.000");
      client.println("cache size  : 8192 KB");
    }
    else if (command.equals("lscpu")) {
      client.println("Architecture:        x86_64");
      client.println("CPU op-mode(s):      32-bit, 64-bit");
      client.println("Byte Order:          Little Endian");
      client.println("CPU(s):              4");
      client.println("Vendor ID:           GenuineIntel");
      client.println("Model name:          Intel(R) Core(TM) i7-8565U CPU @ 1.80GHz");
      client.println("CPU MHz:             1992.000");
    }
    else if (command.equals("dmesg")) {
      client.println("[    0.000000] Booting Linux on physical CPU 0");
      client.println("[    0.123456] Linux version 5.4.0-109-generic (buildd@lgw01-amd64-039) (gcc version 9.3.0, GNU ld version 2.34) #123-Ubuntu SMP");
    }
    else if (command.equals("last")) {
      client.println("pi     pts/0        192.168.1.10    Wed Feb  3 12:00   still logged in");
      client.println("reboot system boot  5.4.0-109-generic Wed Feb  3 11:55   still running");
    }
    else if (command.equals("finger pi")) {
      client.println("Login: pi");
      client.println("Name:  ");
      client.println("Directory: /home/pi");
      client.println("Shell: /bin/bash");
    }
    else if (command.length() == 0) {
    }
    else {
      client.println("bash: " + command + ": command not found");
    }
  }

  client.stop();
  Serial.println("Client disconnected.");
}

void honeypotLoop() {
  auto nowMs   = []() { return (uint32_t)millis(); };
  auto nbWrite = [](WiFiClient& c, const uint8_t* p, size_t n) {
    size_t w = c.write(p, n); c.flush(); return w;
  };

  if (WiFiClient c = honeypotServer.available()) {
    const uint8_t telnetNegotiation[] = {255, 251, 1, 255, 251, 3, 255, 253, 3};
    c.write(telnetNegotiation, sizeof(telnetNegotiation));
    delay(10);
    handleHoneypotClient(c);
  }

  if (WiFiClient c = ftpServer.available())
    handleBannerGrab(c, 21, "220 ProFTPD 1.3.7c Server (Debian) [::ffff:192.168.1.10]\r\n");

  if (WiFiClient c = sshServer.available()) {
    if (!c) return;
    String ip = c.remoteIP().toString();
    c.print("SSH-2.0-OpenSSH_8.5p1 Debian-1");
    logCommand(ip, 22, dumpBytes(c));
    unsigned long t0 = millis();
    while (c.connected() && millis() - t0 < 3000) delay(1);
    c.stop();
  }

  if (WiFiClient c = smtpServer.available())
    handleBannerGrab(c, 25, "220 mail.local ESMTP Exim 4.94.2\r\n");

  if (WiFiClient c = pop3Server.available())
    handleBannerGrab(c, 110, "+OK Dovecot ready.\r\n");

  if (WiFiClient c = imapServer.available())
    handleBannerGrab(c, 143, "* OK [CAPABILITY IMAP4rev1 LITERAL+ SASL-IR LOGIN-REFERRALS ID ENABLE IDLE] Dovecot ready.\r\n");

  if (WiFiClient c = httpServer.available())
    handleBannerGrab(c, 443,
      "HTTP/1.1 200 OK\r\n"
      "Server: Apache/2.4.52 (Debian)\r\n"
      "Content-Type: text/html\r\n"
      "Content-Length: 44\r\n\r\n"
      "<html><body><h1>It works!</h1></body></html>");

  if (WiFiClient c = vncServer.available())
    handleBannerGrab(c, 5900, "RFB 003.008\n");

  if (WiFiClient c = dnsServer.available()) {
    uint8_t query[514];
    int n = c.read(query, sizeof(query));
    if (n < 14) { c.stop(); return; }
    uint16_t id = (query[2] << 8) | query[3];
    static uint8_t dnsResp[] = {
      0x00, 0x00, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
      0x07, 'v', 'e', 'r', 's', 'i', 'o', 'n', 0x04, 'b', 'i', 'n', 'd', 0x00,
      0x00, 0x10, 0x00, 0x03, 0xC0, 0x0C, 0x00, 0x10, 0x00, 0x03, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x07, 0x06, '9', '.', '1', '6', '.', '3'
    };
    dnsResp[0] = id >> 8; dnsResp[1] = id & 0xFF;
    uint16_t dnsLen = sizeof(dnsResp);
    uint8_t tcp[dnsLen + 2];
    tcp[0] = dnsLen >> 8; tcp[1] = dnsLen & 0xFF;
    memcpy(tcp + 2, dnsResp, dnsLen);
    handleBannerGrab(c, 53, tcp, dnsLen + 2);
  }

  if (WiFiClient c = smbServer.available()) {
    static const uint8_t SMB_CORE[] = {
      0xFF, 0x53, 0x4D, 0x42, 0x72, 0x00, 0x00, 0x00,
      0x88, 0x07, 0xC8, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x11, 0x02, 0x00, 0x01, 0x00, 0x20,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      'W', 'i', 'n', '7', ' ', 'L', 'M', ' ', '0', '.', '1', '2', 0x00
    };
    uint32_t len = sizeof(SMB_CORE);
    uint8_t pkt[len + 4];
    pkt[0] = 0x00; pkt[1] = (len >> 16) & 0xFF;
    pkt[2] = (len >> 8) & 0xFF; pkt[3] = len & 0xFF;
    memcpy(pkt + 4, SMB_CORE, len);
    handleBannerGrab(c, 445, pkt, len + 4);
  }

  if (WiFiClient c = mysqlServer.available()) {
    static const uint8_t MYSQL_PAY[] = {
      0x0A, '5', '.', '7', '.', '3', '3', 0x00,
      0x08, 0x00, 0x00, 0x00,
      'r', 'a', 'n', 'd', 's', 'a', 'l', 't', 0x00,
      0xFF, 0xF7, 0x08, 0x02, 0x00, 0xFF, 0xC7, 0x15,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      'r', 'a', 'n', 'd', 's', 'a', 'l', 't', '2', 0x00,
      'm', 'y', 's', 'q', 'l', '_', 'n', 'a', 't', 'i', 'v', 'e', '_',
      'p', 'a', 's', 's', 'w', 'o', 'r', 'd', 0x00
    };
    uint8_t pkt[sizeof(MYSQL_PAY) + 4];
    pkt[0] = sizeof(MYSQL_PAY) & 0xFF;
    pkt[1] = (sizeof(MYSQL_PAY) >> 8)  & 0xFF;
    pkt[2] = (sizeof(MYSQL_PAY) >> 16) & 0xFF;
    pkt[3] = 0x00;
    memcpy(pkt + 4, MYSQL_PAY, sizeof(MYSQL_PAY));
    handleBannerGrab(c, 3306, pkt, sizeof(pkt));
  }

  if (WiFiClient c = rdpServer.available()) {
    static const uint8_t RDP_CC[] = {
      0x03, 0x00, 0x00, 0x13,
      0x0E, 0xD0, 0x00, 0x00,
      0x12, 0x34, 0x00, 0x02,
      0x00, 0x08, 0x00
    };
    handleBannerGrab(c, 3389, RDP_CC, sizeof(RDP_CC));
  }

  if (WiFiClient c = ahttpServer.available())
    handleBannerGrab(c, 8080,
      "HTTP/1.1 200 OK\r\n"
      "Server: Apache/2.4.52 (Debian)\r\n"
      "Content-Type: text/html\r\n"
      "Content-Length: 44\r\n\r\n"
      "<html><body><h1>It works!</h1></body></html>");

  delay(10);
}

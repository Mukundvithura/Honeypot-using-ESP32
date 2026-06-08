#include "config.h"

const char* configPath = "/config.json";
const char* logPath    = "/honeypot_logs.txt";
const char* indexPath  = "/index.html";

String ssid, password, WebhookURL;
std::vector<uint16_t> enabledPorts;

void createFileIfMissing(const char* path, const char* content) {
  if (!SPIFFS.exists(path)) {
    File f = SPIFFS.open(path, FILE_WRITE);
    if (f) {
      f.print(content);
      f.close();
      Serial.println(String("[+] Create : ") + path);
    } else {
      Serial.println(String("[!] Fail to create : ") + path);
    }
  }
}

void initSPIFFS() {
  if (!SPIFFS.begin(true)) {
    Serial.println("[!] Error SPIFFS");
    return;
  }
  createFileIfMissing(configPath, "{\"ssid\":\"\",\"password\":\"\",\"webhook\":\"\",\"ports\":[21,22,23,25,53,110,143,443,445,3306,3389,5900,8080]}");
  createFileIfMissing(logPath, "");
  createFileIfMissing(indexPath,
    "<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'>"
    "<meta name='viewport' content='width=device-width,initial-scale=1'>"
    "<title>ESP32 Honeypot</title><style>"
    "*{margin:0;padding:0;box-sizing:border-box;}"
    "body{background:#0a0e1a;color:#c9d1d9;font-family:'Courier New',monospace;min-height:100vh;padding:20px;}"
    ".header{text-align:center;padding:30px 0 20px;}"
    ".header h1{font-size:1.8em;color:#58a6ff;letter-spacing:3px;text-transform:uppercase;}"
    ".header p{color:#8b949e;font-size:0.8em;margin-top:5px;letter-spacing:2px;}"
    ".container{max-width:520px;margin:0 auto;}"
    ".card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:24px;margin-bottom:16px;}"
    ".card-title{color:#58a6ff;font-size:0.75em;letter-spacing:2px;text-transform:uppercase;margin-bottom:16px;border-bottom:1px solid #21262d;padding-bottom:8px;}"
    "label{display:block;color:#8b949e;font-size:0.75em;letter-spacing:1px;margin-top:14px;margin-bottom:4px;text-transform:uppercase;}"
    "input:not([type=checkbox]){width:100%;background:#0d1117;border:1px solid #30363d;color:#c9d1d9;padding:10px 12px;border-radius:6px;font-family:'Courier New',monospace;font-size:0.9em;outline:none;transition:border-color 0.2s;}"
    "input:not([type=checkbox]):focus{border-color:#58a6ff;}"
    ".ports-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-top:8px;}"
    ".port-item{display:flex;align-items:center;gap:6px;background:#0d1117;border:1px solid #30363d;border-radius:5px;padding:7px 10px;cursor:pointer;transition:border-color 0.2s;}"
    ".port-item.on{border-color:#238636;background:#0d2a12;}"
    ".port-item input{width:auto;accent-color:#3fb950;}"
    ".port-item span{font-size:0.78em;color:#8b949e;}"
    ".port-item.on span{color:#3fb950;}"
    ".btn-row{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:8px;}"
    "button{padding:10px 16px;border:1px solid;border-radius:6px;cursor:pointer;font-family:'Courier New',monospace;font-size:0.8em;letter-spacing:1px;text-transform:uppercase;transition:all 0.2s;}"
    "#save{grid-column:1/-1;background:#238636;border-color:#2ea043;color:#fff;margin-top:14px;}"
    "#save:hover{background:#2ea043;}"
    "#reboot{background:transparent;border-color:#58a6ff;color:#58a6ff;}"
    "#reboot:hover{background:#1c3553;}"
    "#reset{background:transparent;border-color:#f85149;color:#f85149;}"
    "#reset:hover{background:#3d1c1c;}"
    "#showconfig{background:transparent;border-color:#8b949e;color:#8b949e;}"
    "#showconfig:hover{background:#21262d;}"
    "#showlog{background:transparent;border-color:#d29922;color:#d29922;}"
    "#showlog:hover{background:#2e2005;}"
    "#output{display:none;margin-top:14px;background:#0d1117;border:1px solid #30363d;border-radius:6px;padding:14px;font-size:0.78em;color:#3fb950;white-space:pre-wrap;max-height:280px;overflow:auto;}"
    "#status{font-size:0.75em;color:#3fb950;text-align:center;margin-top:10px;display:none;}"
    "</style></head><body>"
    "<div class='header'><h1>[ HONEYPOT ]</h1><p>ESP32 Network Sensor</p></div>"
    "<div class='container'>"
    "<div class='card'>"
    "<div class='card-title'>// Network Credentials</div>"
    "<form id='form'>"
    "<label>SSID</label><input name='ssid' placeholder='Wi-Fi network name' required>"
    "<label>Password</label><input name='password' type='password' placeholder='Wi-Fi password' required>"
    "<label>Webhook URL</label><input name='webhook' placeholder='https://...'>"
    "<label style='margin-top:18px;'>Active Ports</label>"
    "<div class='ports-grid'>"
    "<label class='port-item'><input type='checkbox' name='ports' value='21'><span>FTP 21</span></label>"
    "<label class='port-item'><input type='checkbox' name='ports' value='22'><span>SSH 22</span></label>"
    "<label class='port-item'><input type='checkbox' name='ports' value='23'><span>Telnet 23</span></label>"
    "<label class='port-item'><input type='checkbox' name='ports' value='25'><span>SMTP 25</span></label>"
    "<label class='port-item'><input type='checkbox' name='ports' value='53'><span>DNS 53</span></label>"
    "<label class='port-item'><input type='checkbox' name='ports' value='110'><span>POP3 110</span></label>"
    "<label class='port-item'><input type='checkbox' name='ports' value='143'><span>IMAP 143</span></label>"
    "<label class='port-item'><input type='checkbox' name='ports' value='443'><span>HTTPS 443</span></label>"
    "<label class='port-item'><input type='checkbox' name='ports' value='445'><span>SMB 445</span></label>"
    "<label class='port-item'><input type='checkbox' name='ports' value='3306'><span>MySQL 3306</span></label>"
    "<label class='port-item'><input type='checkbox' name='ports' value='3389'><span>RDP 3389</span></label>"
    "<label class='port-item'><input type='checkbox' name='ports' value='5900'><span>VNC 5900</span></label>"
    "<label class='port-item'><input type='checkbox' name='ports' value='8080'><span>HTTP 8080</span></label>"
    "</div>"
    "<button id='save' type='submit'>Save Configuration</button>"
    "<p id='status'></p>"
    "</form></div>"
    "<div class='card'>"
    "<div class='card-title'>// Device Controls</div>"
    "<div class='btn-row'>"
    "<button id='reboot' type='button'>Reboot</button>"
    "<button id='reset' type='button'>Reset Config</button>"
    "<button id='showconfig' type='button'>Show Config</button>"
    "<button id='showlog' type='button'>Show Logs</button>"
    "</div><pre id='output'></pre></div></div>"
    "<script>"
    "fetch('/config').then(r=>r.json()).then(c=>{"
    "for(let k in c){"
    "  if(k==='ports'){"
    "    c[k].forEach(p=>{"
    "      let cb=document.querySelector(`input[name=ports][value='${p}']`);"
    "      if(cb){cb.checked=true;cb.closest('.port-item').classList.add('on');}"
    "    });"
    "  }else{"
    "    let el=document.querySelector(`[name=${k}]`);"
    "    if(el)el.value=c[k];"
    "  }"
    "}});"
    "document.querySelectorAll('.port-item input').forEach(cb=>{"
    "  cb.addEventListener('change',()=>cb.closest('.port-item').classList.toggle('on',cb.checked));"
    "});"
    "document.getElementById('form').onsubmit=e=>{"
    "e.preventDefault();"
    "let form=e.target;"
    "let data=new FormData(form);"
    "let ports=[];"
    "form.querySelectorAll('input[name=ports]:checked').forEach(cb=>ports.push(parseInt(cb.value)));"
    "let obj=Object.fromEntries(Array.from(data.entries()).filter(([k])=>k!=='ports'));"
    "obj.ports=ports;"
    "fetch('/config',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(obj)}).then(()=>{"
    "  let s=document.getElementById('status');"
    "  s.style.display='block';s.textContent='// Configuration saved.';"
    "  setTimeout(()=>s.style.display='none',3000);"
    "});};"
    "document.getElementById('reboot').onclick=()=>{"
    "fetch('/reboot',{method:'POST'}).then(()=>alert('Rebooting...'));};"
    "document.getElementById('reset').onclick=()=>{"
    "if(confirm('Reset configuration?')){"
    "fetch('/reset',{method:'POST'}).then(()=>alert('Config reset.'));}};"
    "document.getElementById('showlog').onclick=()=>{"
    "fetch('/log').then(r=>r.text()).then(t=>{let o=document.getElementById('output');o.style.display='block';o.textContent=t;});};"
    "document.getElementById('showconfig').onclick=()=>{"
    "fetch('/config').then(r=>r.json()).then(c=>{let o=document.getElementById('output');o.style.display='block';o.textContent=JSON.stringify(c,null,2);});};"
    "</script></body></html>");
}

bool loadConfig() {
  File file = SPIFFS.open(configPath, "r");
  if (!file || file.size() == 0) return false;

  JsonDocument doc;
  DeserializationError err = deserializeJson(doc, file);
  file.close();
  if (err) return false;

  ssid       = doc["ssid"].as<String>();
  password   = doc["password"].as<String>();
  WebhookURL = doc["webhook"].as<String>();

  enabledPorts.clear();
  for (JsonVariant port : doc["ports"].as<JsonArray>()) {
    enabledPorts.push_back(port.as<uint16_t>());
  }

  return ssid.length() > 0 && password.length() > 0;
}

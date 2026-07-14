#ifndef CONFIG_H
#define CONFIG_H

// --- Identité BLE ---
#define DEVICE_NAME         "Galaxy S23 Prime+"
#define SERVICE_UUID        "4fafc201-1fb5-459e-8fcc-c5c9c331914b"
#define CHAR_CMD_UUID       "beb5483e-36e1-4688-b7f5-ea07361b26a8"
#define CHAR_RSP_UUID       "beb5483e-36e1-4688-b7f5-ea07361b26a9"

// --- BLE Communication ---
#define BLE_CHUNK_SIZE      500
#define BLE_CHUNK_DELAY_MS  30

// --- Authentification ---
#define AUTH_PIN            "9876"
#define AUTH_TIMEOUT_MS     30000
#define AUTH_MAX_ATTEMPTS   3

// --- Scan WiFi ---
#define MAX_SCAN_RESULTS    20

// --- Sniffer ---
#define SNIFFER_TIMEOUT_MS  30000

// --- Handshake ---
#define HANDSHAKE_TIMEOUT   60000
#define MAX_EAPOL_FRAMES    4
#define FRAME_MAX_SIZE      512
#define FRAME_MAX_COUNT     50
#define MAX_BEACON_STORE    2
#define MAX_AUTH_STORE      4
#define MAX_ASSOC_STORE     4
#define MAX_DATA_STORE      20

// --- Beacon Spam ---
#define BEACON_SPAM_CHANNEL     1
#define BEACON_SPAM_DELAY_MS    10
#define BEACON_RANDOM_SSID_LEN  8
#define MAX_BEACONS             20
#define DEAUTH_COUNT            50
#define DEAUTH_DELAY_US         1000
#define BEACON_INTERVAL_MS      100

// --- Evil Portal ---
#define PORTAL_AP_IP            "192.168.4.1"
#define PORTAL_AP_GATEWAY       "192.168.4.1"
#define PORTAL_AP_NETMASK       "255.255.255.0"
#define PORTAL_AP_SSID          "Free_WiFi"
#define PORTAL_AP_PASSWORD      ""
#define PORTAL_AP_CHANNEL       6
#define PORTAL_MAX_CLIENTS      4
#define PORTAL_DNS_PORT         53
#define PORTAL_HTTP_PORT        80
#define PORTAL_CRED_BUF_SIZE    4
#define PORTAL_HTML_SIZE        2048

// --- Karma Attack ---
#define KARMA_PROBE_TIMEOUT_MS  5000
#define KARMA_MAX_SSIDS         20
#define KARMA_BEACON_INTERVAL_MS 50

#endif

// ============================================================
//  Channel Hopping
// ============================================================
#define HOP_INTERVAL_MS     500
#define HOP_MIN_CHANNEL     1
#define HOP_MAX_CHANNEL     13

// ============================================================
//  PMKID
// ============================================================
#define PMKID_TIMEOUT       30000
#define MAX_PMKID_CAPTURE   10

// ============================================================
//  Evil Twin
// ============================================================
#define TWIN_MAX_CLIENTS    8

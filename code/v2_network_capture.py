"""
╔══════════════════════════════════════════════════════════════╗
║   AI-IDS  —  VERSION 2: NETWORK-WIDE TRAFFIC MONITOR        ║
║   Promiscuous mode — sees ALL devices on your local network  ║
║   ARP mapping, device discovery, per-device traffic stats    ║
╚══════════════════════════════════════════════════════════════╝

REQUIREMENTS:
  pip install scapy rich

ON WINDOWS:
  - Install Npcap from https://npcap.com
  - *** MUST run as Administrator ***  (promiscuous mode requires it)
  - Right-click terminal → "Run as administrator"
  - Then activate venv and run this script

WHAT THIS SEES vs VERSION 1:
  ✓ All packets sent TO your laptop (same as v1)
  ✓ All broadcast packets from every device (ARP, mDNS, DHCP)
  ✓ All packets FROM other devices directed at your laptop
  ✓ ARP table — maps every device IP ↔ MAC on the network
  ✗ Encrypted unicast between two OTHER devices (phone ↔ router)
     — this requires a managed switch with port mirroring (Phase 2)

USAGE:
  python v2_network_capture.py                      # auto-picks interface
  python v2_network_capture.py --iface "Wi-Fi"      # specify interface
  python v2_network_capture.py --list               # list interfaces
  python v2_network_capture.py --save capture.pcap  # also save to PCAP
  python v2_network_capture.py --scan               # active ARP scan first
"""

import argparse
import threading
import time
import sys
from collections import defaultdict, deque
from datetime import datetime

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

try:
    from scapy.all import (
        sniff, get_if_list, get_if_addr, conf,
        IP, IPv6, TCP, UDP, ICMP, ARP, DNS, DNSQR,
        Ether, BOOTP, DHCP, wrpcap, srp, sendp
    )
except ImportError:
    print("[ERROR] Scapy not installed.  Run:  pip install scapy")
    sys.exit(1)

try:
    from rich.console import Console
    from rich.table import Table
    from rich.live import Live
    from rich.layout import Layout
    from rich.panel import Panel
    from rich.text import Text
    from rich import box
except ImportError:
    print("[ERROR] Rich not installed.  Run:  pip install rich")
    sys.exit(1)


# ══════════════════════════════════════════════════════════════════════════════
#  GLOBAL STATE
# ══════════════════════════════════════════════════════════════════════════════

console = Console()
lock = threading.Lock()
stop_event = threading.Event()

stats = {
    "total_packets":  0,
    "total_bytes":    0,
    "tcp":            0,
    "udp":            0,
    "icmp":           0,
    "arp":            0,
    "dns":            0,
    "other":          0,
    "start_time":     time.time(),
}

# Recent packet log
recent_packets = deque(maxlen=60)

# ── Device registry ──────────────────────────────────────────────────────────
# { mac: { ip, hostname, first_seen, last_seen, bytes_sent, packets_sent,
#           bytes_recv, packets_recv, protocols: set() } }
devices = {}

# ── ARP table (for spoofing detection) ──────────────────────────────────────
# { ip: mac }  — first observed mapping; alerts on change
arp_table = {}
arp_alerts = deque(maxlen=20)

# ── Flow tracker ─────────────────────────────────────────────────────────────
# { (src_ip, dst_ip, sport, dport, proto): FlowInfo }
flows = defaultdict(lambda: {
    "packets": 0, "bytes": 0,
    "start": time.time(), "last_seen": time.time(),
    "src_mac": "", "dst_mac": "",
    "flags": set(),
})

# ── DNS log ──────────────────────────────────────────────────────────────────
dns_log = deque(maxlen=40)

# ── Broadcast/multicast log ──────────────────────────────────────────────────
broadcast_log = deque(maxlen=20)

# ── PCAP saving ──────────────────────────────────────────────────────────────
captured_packets = []
save_pcap = None


# ══════════════════════════════════════════════════════════════════════════════
#  HELPERS
# ══════════════════════════════════════════════════════════════════════════════

KNOWN_PORTS = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET",
    25: "SMTP", 53: "DNS", 67: "DHCP-S", 68: "DHCP-C",
    80: "HTTP", 110: "POP3", 123: "NTP", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 546: "DHCPv6", 547: "DHCPv6",
    993: "IMAPS", 995: "POP3S", 1900: "SSDP/UPnP",
    3306: "MySQL", 3389: "RDP", 5353: "mDNS",
    5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-ALT",
    8443: "HTTPS-ALT", 27017: "MongoDB",
}

TCP_FLAGS = {
    0x01: "FIN", 0x02: "SYN", 0x04: "RST",
    0x08: "PSH", 0x10: "ACK", 0x20: "URG",
}

PROTO_COLOR = {
    "TCP": "bright_cyan", "UDP": "bright_green",
    "ICMP": "bright_yellow", "ARP": "bright_magenta",
    "DNS": "bright_blue", "HTTP": "green",
    "HTTPS": "bright_green", "mDNS": "blue",
    "DHCP": "bright_magenta", "SSDP": "magenta",
    "OTHER": "white",
}

BROADCAST_MACS = {"ff:ff:ff:ff:ff:ff", "FF:FF:FF:FF:FF:FF"}
MULTICAST_PREFIXES = ("01:00:5e", "33:33")

def is_broadcast(mac):
    return mac in BROADCAST_MACS

def is_multicast(mac):
    return any(mac.lower().startswith(p) for p in MULTICAST_PREFIXES)

def fmt_bytes(n):
    if n < 1024:        return f"{n} B"
    if n < 1024**2:     return f"{n/1024:.1f} KB"
    if n < 1024**3:     return f"{n/1024**2:.1f} MB"
    return               f"{n/1024**3:.1f} GB"

def get_tcp_flags(f):
    return "+".join(n for b, n in TCP_FLAGS.items() if int(f) & b) or "—"

def get_service(port):
    return KNOWN_PORTS.get(port, str(port))

def get_protocol(pkt):
    if pkt.haslayer(ARP):  return "ARP"
    if pkt.haslayer(DNS):
        if pkt.haslayer(UDP) and pkt[UDP].dport == 5353:
            return "mDNS"
        return "DNS"
    if pkt.haslayer(BOOTP): return "DHCP"
    if pkt.haslayer(TCP):
        dp = pkt[TCP].dport; sp = pkt[TCP].sport
        if 80  in (dp, sp): return "HTTP"
        if 443 in (dp, sp): return "HTTPS"
        return "TCP"
    if pkt.haslayer(UDP):
        dp = pkt[UDP].dport; sp = pkt[UDP].sport
        if 1900 in (dp, sp): return "SSDP"
        return "UDP"
    if pkt.haslayer(ICMP): return "ICMP"
    return "OTHER"

def short_mac(mac):
    """Last 3 octets of MAC for compact display."""
    parts = mac.split(":")
    return ":".join(parts[-3:]) if len(parts) == 6 else mac

def device_label(mac, ip, local_ip, local_mac):
    """Human label for a device."""
    if mac == local_mac or ip == local_ip:
        return f"[bold bright_yellow]THIS LAPTOP[/]"
    if is_broadcast(mac):
        return "[dim]BROADCAST[/]"
    if is_multicast(mac):
        return "[dim]MULTICAST[/]"
    d = devices.get(mac, {})
    hostname = d.get("hostname", "")
    if hostname:
        return f"[bright_white]{hostname}[/] [dim]({ip})[/]"
    return f"[bright_white]{ip}[/] [dim]{short_mac(mac)}[/]"

def ensure_device(mac, ip):
    """Create or update device entry."""
    if not mac or mac == "00:00:00:00:00:00":
        return
    if mac not in devices:
        devices[mac] = {
            "ip": ip,
            "mac": mac,
            "hostname": "",
            "first_seen": datetime.now().strftime("%H:%M:%S"),
            "last_seen":  datetime.now().strftime("%H:%M:%S"),
            "bytes_sent":    0,
            "packets_sent":  0,
            "bytes_recv":    0,
            "packets_recv":  0,
            "protocols":  set(),
        }
    else:
        devices[mac]["ip"] = ip
        devices[mac]["last_seen"] = datetime.now().strftime("%H:%M:%S")


# ══════════════════════════════════════════════════════════════════════════════
#  ARP SPOOF DETECTOR
# ══════════════════════════════════════════════════════════════════════════════

def check_arp_spoof(ip, mac):
    """
    Maintain a ground-truth ARP table.
    If we see the same IP mapped to a NEW MAC → possible ARP poisoning.
    """
    if ip in arp_table:
        known_mac = arp_table[ip]
        if known_mac != mac:
            alert = {
                "time": datetime.now().strftime("%H:%M:%S"),
                "ip":   ip,
                "old_mac": known_mac,
                "new_mac": mac,
                "msg":  f"⚠  ARP SPOOF ALERT: {ip} was {known_mac} → now {mac}",
            }
            arp_alerts.appendleft(alert)
            console.log(f"[bold red]{alert['msg']}[/]")
    else:
        arp_table[ip] = mac


# ══════════════════════════════════════════════════════════════════════════════
#  PACKET PROCESSOR
# ══════════════════════════════════════════════════════════════════════════════

def process_packet(pkt, local_ip, local_mac):
    with lock:
        if save_pcap is not None:
            captured_packets.append(pkt)

        pkt_len = len(pkt)
        stats["total_packets"] += 1
        stats["total_bytes"]   += pkt_len
        ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]

        # Extract Ethernet layer info
        src_mac = pkt[Ether].src if pkt.haslayer(Ether) else "unknown"
        dst_mac = pkt[Ether].dst if pkt.haslayer(Ether) else "unknown"
        proto   = get_protocol(pkt)

        # ── ARP ──────────────────────────────────────────────────────────────
        if pkt.haslayer(ARP):
            stats["arp"] += 1
            arp = pkt[ARP]
            op  = "WHO-HAS" if arp.op == 1 else "IS-AT"

            ensure_device(arp.hwsrc, arp.psrc)
            check_arp_spoof(arp.psrc, arp.hwsrc)

            if arp.psrc:
                devices.get(arp.hwsrc, {})
                d = devices.get(arp.hwsrc)
                if d:
                    d["bytes_sent"]   += pkt_len
                    d["packets_sent"] += 1
                    d["protocols"].add("ARP")

            is_bc = is_broadcast(dst_mac) or is_multicast(dst_mac)
            entry = {
                "time":    ts,
                "proto":   "ARP",
                "src_ip":  arp.psrc,
                "dst_ip":  arp.pdst,
                "src_mac": src_mac,
                "dst_mac": dst_mac,
                "info":    f"ARP {op}  {arp.psrc} → {arp.pdst}",
                "size":    pkt_len,
                "color":   PROTO_COLOR["ARP"],
                "is_bc":   is_bc,
            }
            recent_packets.appendleft(entry)
            if is_bc:
                broadcast_log.appendleft(entry)
            return

        # ── Requires IP layer ────────────────────────────────────────────────
        if not pkt.haslayer(IP):
            stats["other"] += 1
            return

        ip_layer = pkt[IP]
        src_ip   = ip_layer.src
        dst_ip   = ip_layer.dst

        # Update device registry
        ensure_device(src_mac, src_ip)
        ensure_device(dst_mac, dst_ip)

        src_dev = devices.get(src_mac)
        dst_dev = devices.get(dst_mac)

        if src_dev:
            src_dev["bytes_sent"]   += pkt_len
            src_dev["packets_sent"] += 1
            src_dev["protocols"].add(proto)
            src_dev["ip"] = src_ip

        if dst_dev and not is_broadcast(dst_mac) and not is_multicast(dst_mac):
            dst_dev["bytes_recv"]   += pkt_len
            dst_dev["packets_recv"] += 1

        is_bc = is_broadcast(dst_mac) or is_multicast(dst_mac)

        # ── DNS / mDNS ───────────────────────────────────────────────────────
        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            stats["dns"] += 1
            qname = pkt[DNSQR].qname.decode(errors="replace").rstrip(".")
            dns_log.appendleft({
                "time":    ts,
                "query":   qname,
                "src_ip":  src_ip,
                "src_mac": src_mac,
                "type":    "mDNS" if proto == "mDNS" else "DNS",
            })
            # Attempt hostname extraction from mDNS
            if proto == "mDNS" and src_dev and qname.endswith(".local"):
                src_dev["hostname"] = qname.replace(".local", "")
            info = f"Query: {qname}"

        # ── DHCP hostname extraction ─────────────────────────────────────────
        elif pkt.haslayer(DHCP):
            stats["udp"] += 1
            info = "DHCP"
            try:
                for opt in pkt[DHCP].options:
                    if isinstance(opt, tuple) and opt[0] == "hostname":
                        hostname = opt[1].decode(errors="replace")
                        if src_dev:
                            src_dev["hostname"] = hostname
                        info = f"DHCP hostname={hostname}"
                        break
            except Exception:
                pass

        # ── TCP ──────────────────────────────────────────────────────────────
        elif pkt.haslayer(TCP):
            stats["tcp"] += 1
            tcp = pkt[TCP]
            flags_str   = get_tcp_flags(tcp.flags)
            sport_name  = get_service(tcp.sport)
            dport_name  = get_service(tcp.dport)
            info = f"{sport_name} → {dport_name}  [{flags_str}]"

            fk = (src_ip, dst_ip, tcp.sport, tcp.dport, "TCP")
            flows[fk]["packets"]  += 1
            flows[fk]["bytes"]    += pkt_len
            flows[fk]["last_seen"] = time.time()
            flows[fk]["src_mac"]   = src_mac
            flows[fk]["flags"].add(flags_str)

        # ── UDP ──────────────────────────────────────────────────────────────
        elif pkt.haslayer(UDP):
            stats["udp"] += 1
            udp = pkt[UDP]
            sport_name = get_service(udp.sport)
            dport_name = get_service(udp.dport)
            info = f"{sport_name} → {dport_name}"

            fk = (src_ip, dst_ip, udp.sport, udp.dport, "UDP")
            flows[fk]["packets"]  += 1
            flows[fk]["bytes"]    += pkt_len
            flows[fk]["last_seen"] = time.time()
            flows[fk]["src_mac"]   = src_mac

        # ── ICMP ─────────────────────────────────────────────────────────────
        elif pkt.haslayer(ICMP):
            stats["icmp"] += 1
            types = {0: "Echo Reply", 3: "Unreachable", 8: "Echo Request", 11: "TTL Exceeded"}
            info = types.get(pkt[ICMP].type, f"Type {pkt[ICMP].type}")

        else:
            stats["other"] += 1
            info = f"Proto {ip_layer.proto}"

        entry = {
            "time":    ts,
            "proto":   proto,
            "src_ip":  src_ip,
            "dst_ip":  dst_ip,
            "src_mac": src_mac,
            "dst_mac": dst_mac,
            "info":    info,
            "size":    pkt_len,
            "color":   PROTO_COLOR.get(proto, "white"),
            "is_bc":   is_bc,
        }
        recent_packets.appendleft(entry)
        if is_bc:
            broadcast_log.appendleft(entry)


# ══════════════════════════════════════════════════════════════════════════════
#  ACTIVE ARP SCAN  (optional --scan flag)
# ══════════════════════════════════════════════════════════════════════════════

def active_arp_scan(iface, local_ip):
    """
    Send ARP WHO-HAS to the entire /24 subnet to discover all devices.
    Results populate the devices dict before passive capture begins.
    """
    subnet = ".".join(local_ip.split(".")[:3]) + ".0/24"
    console.print(f"\n[bold bright_yellow]Active ARP scan on {subnet} ...[/]")
    try:
        answered, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet),
            iface=iface,
            timeout=3,
            verbose=False,
        )
        with lock:
            for _, rcv in answered:
                mac = rcv[Ether].src
                ip  = rcv[ARP].psrc
                ensure_device(mac, ip)
                arp_table[ip] = mac
        console.print(f"[bright_green]Found {len(answered)} devices on the network.[/]\n")
    except Exception as e:
        console.print(f"[bright_red]ARP scan failed: {e}[/]\n")


# ══════════════════════════════════════════════════════════════════════════════
#  DASHBOARD
# ══════════════════════════════════════════════════════════════════════════════

def build_dashboard(iface, local_ip, local_mac, bpf_filter):
    elapsed = max(time.time() - stats["start_time"], 0.001)
    pps = stats["total_packets"] / elapsed
    bps = stats["total_bytes"]   / elapsed
    uptime = time.strftime("%H:%M:%S", time.gmtime(elapsed))

    # ── HEADER ───────────────────────────────────────────────────────────────
    header_txt = (
        f"[bold bright_white]AI-IDS v2 — Network-Wide Monitor[/]  │  "
        f"[bright_cyan]{iface}[/]  │  "
        f"My IP: [bright_yellow]{local_ip}[/]  │  "
        f"My MAC: [bright_yellow]{local_mac}[/]  │  "
        f"Uptime: [bright_green]{uptime}[/]  │  "
        f"[bold bright_magenta]PROMISCUOUS MODE ON[/]"
    )

    # ── STATS BAR ────────────────────────────────────────────────────────────
    st = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    for _ in range(9): st.add_column(justify="center")
    st.add_row(
        f"[white]TOTAL\n[bold]{stats['total_packets']:,}[/][/]",
        f"[bright_cyan]TCP\n[bold]{stats['tcp']:,}[/][/]",
        f"[bright_green]UDP\n[bold]{stats['udp']:,}[/][/]",
        f"[bright_yellow]ICMP\n[bold]{stats['icmp']:,}[/][/]",
        f"[bright_magenta]ARP\n[bold]{stats['arp']:,}[/][/]",
        f"[bright_blue]DNS\n[bold]{stats['dns']:,}[/][/]",
        f"[bright_red]Pkt/s\n[bold]{pps:.1f}[/][/]",
        f"[white]Throughput\n[bold]{fmt_bytes(int(bps))}/s[/][/]",
        f"[bright_yellow]Devices\n[bold]{len(devices)}[/][/]",
    )

    # ── DEVICE TABLE ─────────────────────────────────────────────────────────
    dev_table = Table(
        title=f"[bold]Devices on Network ({len(devices)} discovered)[/]",
        box=box.SIMPLE_HEAD, show_lines=False, padding=(0, 1),
    )
    dev_table.add_column("IP Address",   width=16)
    dev_table.add_column("MAC Address",  width=19)
    dev_table.add_column("Hostname",     width=18)
    dev_table.add_column("First Seen",   width=10)
    dev_table.add_column("Last Seen",    width=10)
    dev_table.add_column("Sent",         justify="right", width=9)
    dev_table.add_column("Recv",         justify="right", width=9)
    dev_table.add_column("Protocols",    min_width=20)

    with lock:
        sorted_devs = sorted(
            devices.values(),
            key=lambda d: d["bytes_sent"] + d["bytes_recv"],
            reverse=True
        )

    for d in sorted_devs[:12]:
        is_me = (d["ip"] == local_ip or d["mac"] == local_mac)
        ip_label  = f"[bold bright_yellow]{d['ip']}[/]" if is_me else d["ip"]
        mac_label = f"[bold bright_yellow]{d['mac']}[/]" if is_me else f"[dim]{d['mac']}[/]"
        hostname  = d.get("hostname") or ("(this laptop)" if is_me else "—")
        protocols = " ".join(sorted(d["protocols"]))[:22] or "—"
        dev_table.add_row(
            ip_label, mac_label, hostname,
            d["first_seen"], d["last_seen"],
            fmt_bytes(d["bytes_sent"]),
            fmt_bytes(d["bytes_recv"]),
            protocols,
        )

    # ── LIVE PACKET STREAM ───────────────────────────────────────────────────
    pkt_table = Table(
        title="[bold]Live Packet Stream[/]",
        box=box.SIMPLE_HEAD, show_lines=False, padding=(0, 1),
    )
    pkt_table.add_column("Time",      width=13)
    pkt_table.add_column("Protocol",  width=8,  justify="center")
    pkt_table.add_column("Src IP",    width=16)
    pkt_table.add_column("Src MAC",   width=19)
    pkt_table.add_column("Dst IP",    width=16)
    pkt_table.add_column("Info",      min_width=32)
    pkt_table.add_column("Size",      width=8,  justify="right")

    with lock:
        pkt_snap = list(recent_packets)

    for p in pkt_snap[:22]:
        bc_style = " [dim](BC)[/]" if p.get("is_bc") else ""
        pkt_table.add_row(
            p["time"],
            f"[{p['color']}]{p['proto']}[/]",
            p.get("src_ip", ""),
            f"[dim]{p.get('src_mac', '')}[/]",
            p.get("dst_ip", "") + bc_style,
            p["info"][:50],
            fmt_bytes(p["size"]),
        )

    # ── ARP TABLE ────────────────────────────────────────────────────────────
    arp_tbl = Table(
        title="[bold]ARP Table (IP ↔ MAC)[/]",
        box=box.SIMPLE_HEAD, show_lines=False, padding=(0, 1),
    )
    arp_tbl.add_column("IP Address", width=17)
    arp_tbl.add_column("MAC Address", width=20)

    with lock:
        arp_snap = dict(arp_table)

    for ip_addr, mac_addr in list(arp_snap.items())[:12]:
        is_me = (ip_addr == local_ip)
        arp_tbl.add_row(
            f"[bright_yellow]{ip_addr}[/]" if is_me else ip_addr,
            f"[bright_yellow]{mac_addr}[/]" if is_me else f"[dim]{mac_addr}[/]",
        )

    # ── DNS LOG ──────────────────────────────────────────────────────────────
    dns_tbl = Table(
        title="[bold]DNS / mDNS Queries[/]",
        box=box.SIMPLE_HEAD, show_lines=False, padding=(0, 1),
    )
    dns_tbl.add_column("Time",   width=10)
    dns_tbl.add_column("Type",   width=6)
    dns_tbl.add_column("From",   width=15)
    dns_tbl.add_column("Query",  min_width=25)

    with lock:
        dns_snap = list(dns_log)

    for d in dns_snap[:10]:
        dns_tbl.add_row(d["time"], d.get("type","DNS"), d["src_ip"], d["query"][:38])

    # ── ARP ALERTS ───────────────────────────────────────────────────────────
    with lock:
        alert_snap = list(arp_alerts)

    alert_panel_content = "[dim]No ARP anomalies detected.[/]"
    if alert_snap:
        lines = []
        for a in alert_snap[:5]:
            lines.append(
                f"[bold red]{a['time']}[/]  {a['ip']}  "
                f"[dim]{a['old_mac']}[/] → [bright_red]{a['new_mac']}[/]"
            )
        alert_panel_content = "\n".join(lines)

    # ── ACTIVE FLOWS ─────────────────────────────────────────────────────────
    flow_tbl = Table(
        title="[bold]Active Flows[/]",
        box=box.SIMPLE_HEAD, show_lines=False, padding=(0, 1),
    )
    flow_tbl.add_column("Src IP:Port",  width=22)
    flow_tbl.add_column("Dst IP:Port",  width=22)
    flow_tbl.add_column("Proto", width=6)
    flow_tbl.add_column("Pkts",  justify="right", width=6)
    flow_tbl.add_column("Bytes", justify="right", width=9)

    now = time.time()
    with lock:
        active_flows = sorted(
            [(k, v) for k, v in flows.items() if now - v["last_seen"] < 30],
            key=lambda x: x[1]["bytes"], reverse=True
        )
    for (si, di, sp, dp, pr), fd in active_flows[:8]:
        flow_tbl.add_row(
            f"{si}:{sp}", f"{di}:{dp}", pr,
            str(fd["packets"]), fmt_bytes(fd["bytes"]),
        )

    # ── BROADCAST LOG ────────────────────────────────────────────────────────
    bc_tbl = Table(
        title="[bold]Broadcast / Multicast[/]",
        box=box.SIMPLE_HEAD, show_lines=False, padding=(0, 1),
    )
    bc_tbl.add_column("Time",   width=10)
    bc_tbl.add_column("Proto",  width=7)
    bc_tbl.add_column("From",   width=15)
    bc_tbl.add_column("Info",   min_width=22)

    with lock:
        bc_snap = list(broadcast_log)

    for b in bc_snap[:8]:
        bc_tbl.add_row(
            b["time"],
            f"[{b['color']}]{b['proto']}[/]",
            b.get("src_ip",""),
            b["info"][:30],
        )

    # ── FOOTER ───────────────────────────────────────────────────────────────
    footer = (
        "[dim]Ctrl+C to stop  │  "
        "← = inbound to laptop   → = outbound from laptop  │  "
        "BC = broadcast / multicast[/]"
    )
    if save_pcap:
        footer += f"  │  [bright_yellow]Saving → {save_pcap}[/]"

    # ── ASSEMBLE ─────────────────────────────────────────────────────────────
    layout = Layout()
    layout.split_column(
        Layout(Panel(header_txt, box=box.ROUNDED, style="bold"), size=3),
        Layout(Panel(st, box=box.ROUNDED, title="Statistics"), size=5),
        Layout(Panel(dev_table, box=box.ROUNDED), size=16, name="devices"),
        Layout(name="mid1"),
        Layout(name="mid2"),
        Layout(Panel(pkt_table, box=box.ROUNDED), name="packets"),
        Layout(Text(footer, justify="center"), size=1),
    )
    layout["mid1"].split_row(
        Layout(Panel(arp_tbl,  box=box.ROUNDED)),
        Layout(Panel(dns_tbl,  box=box.ROUNDED)),
        Layout(Panel(bc_tbl,   box=box.ROUNDED)),
    )
    layout["mid2"].split_row(
        Layout(Panel(flow_tbl, box=box.ROUNDED)),
        Layout(Panel(
            Text(alert_panel_content),
            title="[bold bright_red]⚠  ARP Spoof Alerts[/]",
            box=box.ROUNDED,
            style="red" if alert_snap else "",
        )),
    )

    return layout


# ══════════════════════════════════════════════════════════════════════════════
#  CAPTURE THREAD
# ══════════════════════════════════════════════════════════════════════════════

def start_capture(iface, local_ip, local_mac, bpf_filter):
    def callback(pkt):
        if stop_event.is_set():
            return True
        process_packet(pkt, local_ip, local_mac)

    sniff(
        iface=iface,
        prn=callback,
        filter=bpf_filter,
        store=False,
        promisc=True,                   # ← THE KEY LINE for Version 2
        stop_filter=lambda _: stop_event.is_set(),
    )


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════════════

def get_friendly_names():
    """Map NPF GUIDs → human-readable adapter names via scapy's ifaces dict."""
    mapping = {}
    try:
        for name, iface_obj in conf.ifaces.items():
            desc  = getattr(iface_obj, "description", "") or ""
            fname = getattr(iface_obj, "name", "") or ""
            label = fname if fname else desc
            if label:
                mapping[name] = label
    except Exception:
        pass
    return mapping


def list_interfaces():
    console.print("\n[bold bright_cyan]Available network interfaces:[/]\n")
    ifaces   = get_if_list()
    friendly = get_friendly_names()

    console.print(f"  {'#':<5} {'IP Address':<18} {'Friendly Name':<28} {'NPF Identifier'}")
    console.print(f"  {'─'*5} {'─'*18} {'─'*28} {'─'*45}")

    for i, iface in enumerate(ifaces):
        try:    ip = get_if_addr(iface)
        except: ip = "0.0.0.0"

        label   = friendly.get(iface, "")
        has_ip  = ip not in ("0.0.0.0", "unknown", "")
        is_loop = ip == "127.0.0.1"

        if has_ip and not is_loop:
            console.print(
                f"  [bold bright_green][{i}][/]  "
                f"[bright_green]{ip:<18}[/]"
                f"[bright_white]{label:<28}[/]"
                f"[dim]{iface}[/]"
                f"  [bold bright_green]← ACTIVE[/]"
            )
        elif is_loop:
            console.print(f"  [dim][{i}]  {ip:<18}{label:<28}{iface}  (loopback)[/]")
        else:
            console.print(f"  [{i}]  [dim]{ip:<18}[/]{label:<28}[dim]{iface}[/]")

    console.print()
    console.print("[dim]Use the NPF identifier with --iface. ACTIVE = has a real IP.[/]\n")


def pick_interface():
    """Auto-select first non-loopback interface that has a real IP."""
    for iface in get_if_list():
        try:
            ip = get_if_addr(iface)
            if ip and ip not in ("0.0.0.0", "127.0.0.1", "unknown", ""):
                return iface
        except Exception:
            continue
    for iface in get_if_list():
        if "loop" not in iface.lower() and iface.lower() != "lo":
            return iface
    return get_if_list()[0] if get_if_list() else None


def main():
    parser = argparse.ArgumentParser(
        description="AI-IDS Version 2 — Network-Wide Promiscuous Monitor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--iface",  "-i", type=str,  default=None)
    parser.add_argument("--list",   "-l", action="store_true",
                        help="List interfaces and exit")
    parser.add_argument("--filter", "-f", type=str,  default=None,
                        help="BPF filter e.g. 'tcp', 'not arp'")
    parser.add_argument("--save",   "-s", type=str,  default=None,
                        help="Save packets to .pcap file")
    parser.add_argument("--scan",         action="store_true",
                        help="Run active ARP scan first to discover devices")
    args = parser.parse_args()

    if args.list:
        list_interfaces()
        return

    global save_pcap
    save_pcap = args.save

    iface = args.iface or pick_interface()
    if not iface:
        console.print("[bold red]No network interface found.[/]")
        sys.exit(1)

    try:
        local_ip  = get_if_addr(iface)
        local_mac = conf.ifaces[iface].mac if iface in conf.ifaces else "unknown"
    except Exception:
        local_ip  = "unknown"
        local_mac = "unknown"

    friendly = get_friendly_names()
    friendly_label = friendly.get(iface, iface)

    bpf_filter = args.filter

    console.print(f"\n[bold bright_green]Starting AI-IDS Version 2 — Network-Wide Monitor[/]")
    console.print(f"  Interface       : [bright_cyan]{friendly_label}[/]")
    console.print(f"  NPF ID          : [dim]{iface}[/]")
    console.print(f"  My IP           : [bright_yellow]{local_ip}[/]")
    console.print(f"  My MAC          : [bright_yellow]{local_mac}[/]")
    console.print(f"  Promiscuous     : [bold bright_magenta]ENABLED[/]")
    console.print(f"  BPF Filter      : [bright_magenta]{bpf_filter or 'none (all traffic)'}[/]")
    console.print(f"  ARP Spoof Detect: [bright_green]ENABLED[/]")
    if save_pcap:
        console.print(f"  Saving to       : [bright_yellow]{save_pcap}[/]")

    if local_ip in ("0.0.0.0", "unknown", ""):
        console.print(
            "\n[bold yellow]⚠  Warning:[/] Selected interface has no IP. "
            "Run [bright_cyan]--list[/] to find the active one."
        )

    # Optional active ARP scan
    if args.scan:
        active_arp_scan(iface, local_ip)

    console.print("\n[dim]Capture starting in 1 second...  (Ctrl+C to stop)[/]\n")
    time.sleep(1)

    # Register this laptop in device list
    ensure_device(local_mac, local_ip)
    if local_mac != "unknown":
        devices[local_mac]["hostname"] = "THIS LAPTOP"
        arp_table[local_ip] = local_mac

    # Start capture thread
    t = threading.Thread(
        target=start_capture,
        args=(iface, local_ip, local_mac, bpf_filter),
        daemon=True,
    )
    t.start()

    try:
        with Live(
            build_dashboard(iface, local_ip, local_mac, bpf_filter),
            refresh_per_second=2,
            screen=True,
        ) as live:
            while not stop_event.is_set():
                time.sleep(0.5)
                live.update(build_dashboard(iface, local_ip, local_mac, bpf_filter))

    except KeyboardInterrupt:
        pass
    finally:
        stop_event.set()
        console.print("\n[bold bright_yellow]Capture stopped.[/]")
        console.print(f"  Packets captured : [white]{stats['total_packets']:,}[/]")
        console.print(f"  Data captured    : [white]{fmt_bytes(stats['total_bytes'])}[/]")
        console.print(f"  Devices seen     : [bright_yellow]{len(devices)}[/]")
        console.print(f"  ARP entries      : [bright_magenta]{len(arp_table)}[/]")
        console.print(f"  ARP spoof alerts : [bright_red]{len(arp_alerts)}[/]")

        if save_pcap and captured_packets:
            console.print(f"\n[dim]Saving {len(captured_packets)} packets to {save_pcap}...[/]")
            try:
                wrpcap(save_pcap, captured_packets)
                console.print(f"[bright_green]Saved → {save_pcap}[/]")
            except Exception as e:
                console.print(f"[bright_red]Save failed: {e}[/]")

        console.print()


if __name__ == "__main__":
    main()

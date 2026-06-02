"""
╔══════════════════════════════════════════════════════════════╗
║   AI-IDS  —  VERSION 1: HOST-ONLY TRAFFIC MONITOR           ║
║   Captures and displays YOUR OWN machine's network traffic   ║
║   No ML model yet — pure visibility into what's happening    ║
╚══════════════════════════════════════════════════════════════╝

REQUIREMENTS:
  pip install scapy rich

ON WINDOWS:
  - Install Npcap from https://npcap.com  (required for Scapy)
  - Run this script as Administrator (right-click → Run as admin)

USAGE:
  python v1_host_capture.py                     # auto-picks interface
  python v1_host_capture.py --iface "Wi-Fi"     # specify interface
  python v1_host_capture.py --list              # list all interfaces
  python v1_host_capture.py --filter tcp        # only TCP traffic
  python v1_host_capture.py --save capture.pcap # also save to file
"""

import argparse
import threading
import time
import os
import sys
from collections import defaultdict, deque
from datetime import datetime

# ── Scapy import (suppress IPv6 warning on Windows) ──────────────────────────
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

try:
    from scapy.all import (
        sniff, get_if_list, get_if_addr, conf,
        IP, IPv6, TCP, UDP, ICMP, ARP, DNS, DNSQR, Raw,
        wrpcap, Ether
    )
except ImportError:
    print("[ERROR] Scapy not installed. Run:  pip install scapy")
    sys.exit(1)

try:
    from rich.console import Console
    from rich.table import Table
    from rich.live import Live
    from rich.layout import Layout
    from rich.panel import Panel
    from rich.text import Text
    from rich.columns import Columns
    from rich import box
    from rich.progress import Progress, BarColumn, TextColumn
except ImportError:
    print("[ERROR] Rich not installed. Run:  pip install rich")
    sys.exit(1)


# ══════════════════════════════════════════════════════════════════════════════
#  GLOBAL STATE
# ══════════════════════════════════════════════════════════════════════════════

console = Console()

# Thread-safe counters and logs
lock = threading.Lock()

stats = {
    "total_packets":   0,
    "tcp_packets":     0,
    "udp_packets":     0,
    "icmp_packets":    0,
    "arp_packets":     0,
    "dns_queries":     0,
    "other_packets":   0,
    "total_bytes":     0,
    "start_time":      time.time(),
}

# Recent packet log — last 50 entries shown in dashboard
recent_packets = deque(maxlen=50)

# Flow tracker: { (src_ip, dst_ip, sport, dport, proto): FlowInfo }
flows = defaultdict(lambda: {
    "packets": 0,
    "bytes": 0,
    "start": time.time(),
    "last_seen": time.time(),
    "flags": set(),
})

# Top talkers: { ip: bytes_sent }
top_talkers = defaultdict(int)

# DNS queries seen
dns_log = deque(maxlen=30)

# Capture stop event
stop_event = threading.Event()

# Collected packets (for optional PCAP save)
captured_packets = []
save_pcap = None  # set to filename if --save given


# ══════════════════════════════════════════════════════════════════════════════
#  PROTOCOL HELPERS
# ══════════════════════════════════════════════════════════════════════════════

PROTOCOL_COLORS = {
    "TCP":   "bright_cyan",
    "UDP":   "bright_green",
    "ICMP":  "bright_yellow",
    "ARP":   "bright_magenta",
    "DNS":   "bright_blue",
    "OTHER": "white",
    "HTTP":  "green",
    "HTTPS": "bright_green",
}

KNOWN_PORTS = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET",
    25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 993: "IMAPS", 995: "POP3S",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    6379: "Redis", 8080: "HTTP-ALT", 8443: "HTTPS-ALT",
    27017: "MongoDB",
}

TCP_FLAGS = {
    0x01: "FIN", 0x02: "SYN", 0x04: "RST",
    0x08: "PSH", 0x10: "ACK", 0x20: "URG",
}

def get_tcp_flag_str(flags_int):
    """Convert TCP flags integer to readable string like SYN+ACK."""
    active = [name for bit, name in TCP_FLAGS.items() if flags_int & bit]
    return "+".join(active) if active else "NONE"

def get_service(port):
    """Return service name for a port number, or the port number itself."""
    return KNOWN_PORTS.get(port, str(port))

def format_bytes(n):
    """Human-readable byte count."""
    if n < 1024:
        return f"{n} B"
    elif n < 1024 ** 2:
        return f"{n/1024:.1f} KB"
    elif n < 1024 ** 3:
        return f"{n/1024**2:.1f} MB"
    return f"{n/1024**3:.1f} GB"

def get_protocol(pkt):
    """Determine the most descriptive protocol label for a packet."""
    if pkt.haslayer(ARP):
        return "ARP"
    if pkt.haslayer(DNS):
        return "DNS"
    if pkt.haslayer(TCP):
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
        if 80 in (sport, dport):
            return "HTTP"
        if 443 in (sport, dport):
            return "HTTPS"
        return "TCP"
    if pkt.haslayer(UDP):
        return "UDP"
    if pkt.haslayer(ICMP):
        return "ICMP"
    return "OTHER"

def get_direction_arrow(src_ip, local_ip):
    """Return → (outbound) or ← (inbound) relative to this machine."""
    if src_ip == local_ip:
        return "[bold bright_red]→[/]"   # outgoing
    return "[bold bright_green]←[/]"      # incoming


# ══════════════════════════════════════════════════════════════════════════════
#  PACKET PROCESSOR
# ══════════════════════════════════════════════════════════════════════════════

def process_packet(pkt, local_ip):
    """Called for every captured packet. Updates all global state."""
    global save_pcap

    with lock:
        # Save to PCAP list if requested
        if save_pcap:
            captured_packets.append(pkt)

        pkt_len = len(pkt)
        stats["total_packets"] += 1
        stats["total_bytes"] += pkt_len
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]

        # ── ARP ──────────────────────────────────────────────────────────────
        if pkt.haslayer(ARP):
            stats["arp_packets"] += 1
            arp = pkt[ARP]
            op = "WHO-HAS" if arp.op == 1 else "IS-AT"
            entry = {
                "time": timestamp,
                "proto": "ARP",
                "src": arp.psrc,
                "dst": arp.pdst,
                "info": f"ARP {op}  {arp.psrc} → {arp.pdst}",
                "size": pkt_len,
                "color": PROTOCOL_COLORS["ARP"],
                "direction": "→" if arp.psrc == local_ip else "←",
            }
            recent_packets.appendleft(entry)
            return

        # ── IP layer required for everything below ────────────────────────────
        if not pkt.haslayer(IP):
            stats["other_packets"] += 1
            return

        ip = pkt[IP]
        src = ip.src
        dst = ip.dst
        proto = get_protocol(pkt)

        top_talkers[src] += pkt_len

        # ── DNS ──────────────────────────────────────────────────────────────
        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            stats["dns_queries"] += 1
            qname = pkt[DNSQR].qname.decode(errors="replace").rstrip(".")
            dns_log.appendleft({
                "time": timestamp,
                "query": qname,
                "src": src,
            })
            info = f"Query: {qname}"
        # ── TCP ──────────────────────────────────────────────────────────────
        elif pkt.haslayer(TCP):
            stats["tcp_packets"] += 1
            tcp = pkt[TCP]
            flags_str = get_tcp_flag_str(int(tcp.flags))
            sport_name = get_service(tcp.sport)
            dport_name = get_service(tcp.dport)
            info = f"{sport_name} → {dport_name}  [{flags_str}]"

            flow_key = (src, dst, tcp.sport, tcp.dport, "TCP")
            flows[flow_key]["packets"] += 1
            flows[flow_key]["bytes"] += pkt_len
            flows[flow_key]["last_seen"] = time.time()
            flows[flow_key]["flags"].add(flags_str)

        # ── UDP ──────────────────────────────────────────────────────────────
        elif pkt.haslayer(UDP):
            stats["udp_packets"] += 1
            udp = pkt[UDP]
            sport_name = get_service(udp.sport)
            dport_name = get_service(udp.dport)
            info = f"{sport_name} → {dport_name}"

            flow_key = (src, dst, udp.sport, udp.dport, "UDP")
            flows[flow_key]["packets"] += 1
            flows[flow_key]["bytes"] += pkt_len
            flows[flow_key]["last_seen"] = time.time()

        # ── ICMP ─────────────────────────────────────────────────────────────
        elif pkt.haslayer(ICMP):
            stats["icmp_packets"] += 1
            icmp = pkt[ICMP]
            icmp_types = {0: "Echo Reply", 3: "Dest Unreachable", 8: "Echo Request", 11: "TTL Exceeded"}
            info = icmp_types.get(icmp.type, f"Type {icmp.type}")

        else:
            stats["other_packets"] += 1
            info = f"Protocol {ip.proto}"

        direction = "→" if src == local_ip else "←"

        entry = {
            "time":      timestamp,
            "proto":     proto,
            "src":       src,
            "dst":       dst,
            "info":      info,
            "size":      pkt_len,
            "color":     PROTOCOL_COLORS.get(proto, "white"),
            "direction": direction,
        }
        recent_packets.appendleft(entry)


# ══════════════════════════════════════════════════════════════════════════════
#  DASHBOARD BUILDER
# ══════════════════════════════════════════════════════════════════════════════

def build_dashboard(iface, local_ip, bpf_filter):
    """Build the Rich layout shown in the live display."""

    elapsed = time.time() - stats["start_time"]
    pps = stats["total_packets"] / elapsed if elapsed > 0 else 0
    bps = stats["total_bytes"] / elapsed if elapsed > 0 else 0

    # ── HEADER PANEL ─────────────────────────────────────────────────────────
    uptime = time.strftime("%H:%M:%S", time.gmtime(elapsed))
    header_text = (
        f"[bold bright_white]AI-IDS v1 — Host Monitor[/]  │  "
        f"Interface: [bright_cyan]{iface}[/]  │  "
        f"Local IP: [bright_yellow]{local_ip}[/]  │  "
        f"Filter: [bright_magenta]{bpf_filter or 'none'}[/]  │  "
        f"Uptime: [bright_green]{uptime}[/]"
    )

    # ── STATS ROW ────────────────────────────────────────────────────────────
    stats_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    stats_table.add_column(justify="center")
    stats_table.add_column(justify="center")
    stats_table.add_column(justify="center")
    stats_table.add_column(justify="center")
    stats_table.add_column(justify="center")
    stats_table.add_column(justify="center")
    stats_table.add_column(justify="center")
    stats_table.add_column(justify="center")

    stats_table.add_row(
        f"[bright_white]TOTAL\n[bold]{stats['total_packets']:,}[/][/]",
        f"[bright_cyan]TCP\n[bold]{stats['tcp_packets']:,}[/][/]",
        f"[bright_green]UDP\n[bold]{stats['udp_packets']:,}[/][/]",
        f"[bright_yellow]ICMP\n[bold]{stats['icmp_packets']:,}[/][/]",
        f"[bright_magenta]ARP\n[bold]{stats['arp_packets']:,}[/][/]",
        f"[bright_blue]DNS\n[bold]{stats['dns_queries']:,}[/][/]",
        f"[bright_red]Pkt/s\n[bold]{pps:.1f}[/][/]",
        f"[bright_white]Throughput\n[bold]{format_bytes(int(bps))}/s[/][/]",
    )

    # ── RECENT PACKETS TABLE ─────────────────────────────────────────────────
    pkt_table = Table(
        title="[bold]Live Packet Stream[/]",
        box=box.SIMPLE_HEAD,
        show_lines=False,
        padding=(0, 1),
    )
    pkt_table.add_column("Time",      style="dim",          width=13)
    pkt_table.add_column("Dir",       justify="center",     width=3)
    pkt_table.add_column("Protocol",  justify="center",     width=8)
    pkt_table.add_column("Source IP",                       width=16)
    pkt_table.add_column("Dest IP",                         width=16)
    pkt_table.add_column("Info",                            min_width=30)
    pkt_table.add_column("Size",      justify="right",      width=8)

    with lock:
        snapshot = list(recent_packets)

    for p in snapshot[:30]:
        pkt_table.add_row(
            p["time"],
            p["direction"],
            f"[{p['color']}]{p['proto']}[/]",
            p.get("src", ""),
            p.get("dst", ""),
            p["info"][:55],
            format_bytes(p["size"]),
        )

    # ── TOP TALKERS TABLE ────────────────────────────────────────────────────
    talkers_table = Table(
        title="[bold]Top Talkers[/]",
        box=box.SIMPLE_HEAD,
        show_lines=False,
        padding=(0, 1),
    )
    talkers_table.add_column("IP Address",  width=18)
    talkers_table.add_column("Data Sent",   justify="right", width=10)

    with lock:
        top = sorted(top_talkers.items(), key=lambda x: x[1], reverse=True)[:8]
    for ip_addr, nbytes in top:
        label = "[bright_yellow]YOU[/] " if ip_addr == local_ip else ""
        talkers_table.add_row(f"{label}{ip_addr}", format_bytes(nbytes))

    # ── DNS LOG ──────────────────────────────────────────────────────────────
    dns_table = Table(
        title="[bold]DNS Queries[/]",
        box=box.SIMPLE_HEAD,
        show_lines=False,
        padding=(0, 1),
    )
    dns_table.add_column("Time",   width=10)
    dns_table.add_column("Query",  min_width=28)
    dns_table.add_column("From",   width=16)

    with lock:
        dns_snapshot = list(dns_log)
    for d in dns_snapshot[:10]:
        dns_table.add_row(d["time"], d["query"][:40], d["src"])

    # ── ACTIVE FLOWS ─────────────────────────────────────────────────────────
    flow_table = Table(
        title="[bold]Active Flows[/]",
        box=box.SIMPLE_HEAD,
        show_lines=False,
        padding=(0, 1),
    )
    flow_table.add_column("Source",   width=20)
    flow_table.add_column("Dest",     width=20)
    flow_table.add_column("Proto",    width=6)
    flow_table.add_column("Pkts",     justify="right", width=6)
    flow_table.add_column("Bytes",    justify="right", width=9)
    flow_table.add_column("Flags",    width=20)

    now = time.time()
    with lock:
        # Only show flows active in last 30 seconds
        active = {
            k: v for k, v in flows.items()
            if now - v["last_seen"] < 30
        }
        # Sort by bytes descending
        sorted_flows = sorted(active.items(), key=lambda x: x[1]["bytes"], reverse=True)

    for (src, dst, sp, dp, proto), fdata in sorted_flows[:10]:
        flow_table.add_row(
            f"{src}:{sp}",
            f"{dst}:{dp}",
            proto,
            str(fdata["packets"]),
            format_bytes(fdata["bytes"]),
            " ".join(list(fdata["flags"])[:3]),
        )

    # ── ASSEMBLE LAYOUT ──────────────────────────────────────────────────────
    footer = "[dim]Press Ctrl+C to stop capture"
    if save_pcap:
        footer += f"  │  Saving to [bright_yellow]{save_pcap}[/]"

    layout = Layout()
    layout.split_column(
        Layout(Panel(header_text, box=box.ROUNDED, style="bold"), size=3),
        Layout(Panel(stats_table, box=box.ROUNDED, title="Statistics"), size=5),
        Layout(name="middle"),
        Layout(Panel(pkt_table, box=box.ROUNDED), name="packets"),
        Layout(Text(footer, justify="center"), size=1),
    )
    layout["middle"].split_row(
        Layout(Panel(talkers_table, box=box.ROUNDED)),
        Layout(Panel(dns_table, box=box.ROUNDED)),
        Layout(Panel(flow_table, box=box.ROUNDED)),
    )

    return layout


# ══════════════════════════════════════════════════════════════════════════════
#  CAPTURE THREAD
# ══════════════════════════════════════════════════════════════════════════════

def start_capture(iface, local_ip, bpf_filter):
    """Run Scapy sniff() in a background thread."""
    def pkt_callback(pkt):
        if stop_event.is_set():
            return True  # returning True stops the sniffer
        process_packet(pkt, local_ip)

    sniff(
        iface=iface,
        prn=pkt_callback,
        filter=bpf_filter,
        store=False,          # don't store in Scapy memory (we manage our own)
        stop_filter=lambda _: stop_event.is_set(),
    )


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════════════

def get_friendly_names():
    """
    On Windows, map NPF GUIDs to human-readable adapter names
    by reading the registry via 'getmac /fo csv /v' or via scapy's
    ifaces dict (which contains description strings).
    Returns { npf_name: friendly_label }
    """
    mapping = {}
    try:
        # scapy stores iface info in conf.ifaces
        for name, iface_obj in conf.ifaces.items():
            desc  = getattr(iface_obj, "description", "") or ""
            fname = getattr(iface_obj, "name", "")  or ""
            label = fname if fname else desc
            if label:
                mapping[name] = label
    except Exception:
        pass
    return mapping


def list_interfaces():
    """Print all available network interfaces with friendly names."""
    console.print("\n[bold bright_cyan]Available network interfaces:[/]\n")
    ifaces   = get_if_list()
    friendly = get_friendly_names()

    # Header
    console.print(f"  {'#':<5} {'IP Address':<18} {'Friendly Name':<28} {'NPF Identifier'}")
    console.print(f"  {'─'*5} {'─'*18} {'─'*28} {'─'*45}")

    for i, iface in enumerate(ifaces):
        try:    ip = get_if_addr(iface)
        except: ip = "0.0.0.0"

        label = friendly.get(iface, "")

        # Highlight the most likely active interface
        has_ip = ip not in ("0.0.0.0", "unknown", "")
        is_loop = ip == "127.0.0.1"

        if has_ip and not is_loop:
            # Active non-loopback — highlight green
            console.print(
                f"  [bold bright_green][{i}][/]  "
                f"[bright_green]{ip:<18}[/]"
                f"[bright_white]{label:<28}[/]"
                f"[dim]{iface}[/]"
                f"  [bold bright_green]← ACTIVE[/]"
            )
        elif is_loop:
            console.print(
                f"  [dim][{i}]  {ip:<18}{label:<28}{iface}  (loopback)[/]"
            )
        else:
            console.print(
                f"  [{i}]  [dim]{ip:<18}[/]{label:<28}[dim]{iface}[/]"
            )

    console.print()
    console.print("[dim]Use --iface with the NPF identifier or friendly name.[/]")
    console.print("[dim]The green ACTIVE interfaces are the ones receiving real traffic.[/]\n")


def pick_interface():
    """
    Auto-select the best interface:
    Priority: real IP (not 0.0.0.0, not loopback) → first match wins.
    """
    ifaces = get_if_list()

    # First pass: non-loopback with a real IP
    for iface in ifaces:
        try:
            ip = get_if_addr(iface)
            if ip and ip not in ("0.0.0.0", "127.0.0.1", "unknown", ""):
                return iface
        except Exception:
            continue

    # Fallback: any non-loopback
    for iface in ifaces:
        if "loop" not in iface.lower() and iface.lower() != "lo":
            return iface

    return ifaces[0] if ifaces else None


def main():
    parser = argparse.ArgumentParser(
        description="AI-IDS Version 1 — Host-Only Traffic Monitor",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--iface",  "-i", type=str, default=None,
                        help="Network interface name (e.g. 'Wi-Fi', 'Ethernet')")
    parser.add_argument("--list",   "-l", action="store_true",
                        help="List all available network interfaces and exit")
    parser.add_argument("--filter", "-f", type=str, default=None,
                        help="BPF filter string (e.g. 'tcp', 'udp port 53', 'host 192.168.1.1')")
    parser.add_argument("--save",   "-s", type=str, default=None,
                        help="Save captured packets to a .pcap file")
    args = parser.parse_args()

    if args.list:
        list_interfaces()
        return

    global save_pcap
    save_pcap = args.save

    # Select interface
    iface = args.iface or pick_interface()
    if not iface:
        console.print("[bold red]No network interface found. Check Npcap is installed.[/]")
        sys.exit(1)

    # Get local IP and friendly name
    try:
        local_ip = get_if_addr(iface)
    except Exception:
        local_ip = "unknown"

    friendly = get_friendly_names()
    friendly_label = friendly.get(iface, iface)

    bpf_filter = args.filter

    console.print(f"\n[bold bright_green]Starting AI-IDS Version 1 — Host Monitor[/]")
    console.print(f"  Interface : [bright_cyan]{friendly_label}[/]")
    console.print(f"  NPF ID    : [dim]{iface}[/]")
    console.print(f"  Local IP  : [bright_yellow]{local_ip}[/]")
    console.print(f"  Filter    : [bright_magenta]{bpf_filter or 'all traffic'}[/]")
    if save_pcap:
        console.print(f"  Saving to : [bright_yellow]{save_pcap}[/]")

    if local_ip in ("0.0.0.0", "unknown", ""):
        console.print(
            "\n[bold yellow]⚠  Warning:[/] Selected interface has no IP address. "
            "Run [bright_cyan]--list[/] to see active interfaces."
        )
    console.print("\n[dim]Starting capture... (Ctrl+C to stop)[/]\n")
    time.sleep(1)

    # Start capture in background thread
    capture_thread = threading.Thread(
        target=start_capture,
        args=(iface, local_ip, bpf_filter),
        daemon=True
    )
    capture_thread.start()

    # Live dashboard
    try:
        with Live(
            build_dashboard(iface, local_ip, bpf_filter),
            refresh_per_second=2,
            screen=True,
        ) as live:
            while not stop_event.is_set():
                time.sleep(0.5)
                live.update(build_dashboard(iface, local_ip, bpf_filter))

    except KeyboardInterrupt:
        pass
    finally:
        stop_event.set()
        console.print("\n[bold bright_yellow]Capture stopped.[/]")
        console.print(f"  Total packets : [bright_white]{stats['total_packets']:,}[/]")
        console.print(f"  Total data    : [bright_white]{format_bytes(stats['total_bytes'])}[/]")
        console.print(f"  TCP           : [bright_cyan]{stats['tcp_packets']:,}[/]")
        console.print(f"  UDP           : [bright_green]{stats['udp_packets']:,}[/]")
        console.print(f"  DNS queries   : [bright_blue]{stats['dns_queries']:,}[/]")

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

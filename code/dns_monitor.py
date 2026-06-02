"""
╔══════════════════════════════════════════════════════════════╗
║   AI-IDS  —  DNS MONITOR                                     ║
║   Shows every DNS query from every device on the network     ║
║   Reveals which sites each device is visiting in real time   ║
╚══════════════════════════════════════════════════════════════╝

USAGE:
  python dns_monitor.py
  python dns_monitor.py --iface "\\Device\\NPF_{...}"
  python dns_monitor.py --list
  python dns_monitor.py --save dns_log.txt   # also write to file

RUN AS ADMINISTRATOR for promiscuous mode (sees other devices).
Without admin, you only see your own laptop's DNS queries.
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
        DNS, DNSQR, DNSRR, UDP, IP, Ether
    )
except ImportError:
    print("[ERROR] Run:  pip install scapy")
    sys.exit(1)

try:
    from rich.console import Console
    from rich.table import Table
    from rich.live import Live
    from rich.panel import Panel
    from rich.layout import Layout
    from rich.text import Text
    from rich import box
except ImportError:
    print("[ERROR] Run:  pip install rich")
    sys.exit(1)


# ══════════════════════════════════════════════════════════════════════════════
#  GLOBAL STATE
# ══════════════════════════════════════════════════════════════════════════════

console = Console()
lock    = threading.Lock()
stop_event = threading.Event()

# Full chronological query log
all_queries = deque(maxlen=500)

# Per-device query history  { ip: deque of domain strings }
per_device  = defaultdict(lambda: deque(maxlen=200))

# Per-device query count    { ip: int }
device_count = defaultdict(int)

# Device name map           { ip: friendly_name }
device_names = {}

# Domain frequency          { domain: count }
domain_freq  = defaultdict(int)

# Stats
stats = {
    "total":      0,
    "start_time": time.time(),
}

# Optional file save
save_file = None


# ══════════════════════════════════════════════════════════════════════════════
#  KNOWN DEVICE HINTS  (expand this with MACs you discover from v2)
# ══════════════════════════════════════════════════════════════════════════════

# Add entries here after running v2 to identify your devices:
# { "192.168.1.xxx": "My Phone" }
DEVICE_HINTS = {
    "192.168.1.140": "Huawei Y9",
    "192.168.1.85":  "Tecno Spark",
    "192.168.1.212": "My Laptop",
    "192.168.1.146": "User 1"
}

# Query types
QTYPES = {
    1:  "A",      # IPv4 address lookup  ← most common, website visits
    2:  "NS",     # Name server
    5:  "CNAME",  # Alias
    15: "MX",     # Mail server
    16: "TXT",    # Text record
    28: "AAAA",   # IPv6 address lookup
    33: "SRV",    # Service record
    255:"ANY",
}

# Categories for common domains (for color coding)
def categorise(domain):
    d = domain.lower()
    if any(x in d for x in ["google", "youtube", "gmail", "gstatic", "ggpht", "googleapis"]):
        return "google",    "bright_red"
    if any(x in d for x in ["facebook", "instagram", "whatsapp", "fbcdn", "fb.com"]):
        return "meta",      "bright_blue"
    if any(x in d for x in ["microsoft", "msedge", "msftncsi", "live.com", "office", "azure", "windows"]):
        return "microsoft", "bright_cyan"
    if any(x in d for x in ["apple", "icloud", "itunes", "mzstatic"]):
        return "apple",     "white"
    if any(x in d for x in ["twitter", "x.com", "twimg"]):
        return "twitter",   "bright_cyan"
    if any(x in d for x in ["tiktok", "bytedance", "musical.ly"]):
        return "tiktok",    "bright_magenta"
    if any(x in d for x in ["netflix", "nflxvideo", "nflximg"]):
        return "netflix",   "bright_red"
    if any(x in d for x in ["amazon", "amazonaws", "cloudfront"]):
        return "amazon",    "bright_yellow"
    if any(x in d for x in ["snapchat", "snap.com"]):
        return "snapchat",  "yellow"
    if any(x in d for x in ["spotify"]):
        return "spotify",   "bright_green"
    if any(x in d for x in ["telegram", "t.me"]):
        return "telegram",  "bright_cyan"
    if any(x in d for x in ["doubleclick", "googlesyndication", "adservice", "adsystem", "ads."]):
        return "ads",       "bright_red"
    if any(x in d for x in ["analytics", "telemetry", "tracking", "metrics", "collect"]):
        return "tracker",   "yellow"
    return "other", "white"


# ══════════════════════════════════════════════════════════════════════════════
#  PACKET PROCESSOR
# ══════════════════════════════════════════════════════════════════════════════

def process_packet(pkt, local_ip):
    if not (pkt.haslayer(DNS) and pkt.haslayer(DNSQR) and pkt.haslayer(IP)):
        return

    # Only capture queries (qr=0), not responses (qr=1)
    if pkt[DNS].qr != 0:
        return

    src_ip  = pkt[IP].src
    src_mac = pkt[Ether].src if pkt.haslayer(Ether) else "unknown"
    ts      = datetime.now().strftime("%H:%M:%S.%f")[:-3]

    try:
        domain = pkt[DNSQR].qname.decode(errors="replace").rstrip(".")
    except Exception:
        return

    qtype_int = pkt[DNSQR].qtype
    qtype_str = QTYPES.get(qtype_int, str(qtype_int))

    # Only care about A and AAAA (actual site visits), skip noise
    # Comment out the next 2 lines if you want ALL query types
    if qtype_int not in (1, 28):
        return

    category, color = categorise(domain)

    # Friendly device label
    if src_ip == local_ip:
        device_label = "THIS LAPTOP"
    elif src_ip in device_names:
        device_label = device_names[src_ip]
    elif src_ip in DEVICE_HINTS:
        device_label = DEVICE_HINTS[src_ip]
        device_names[src_ip] = device_label
    else:
        device_label = src_ip

    entry = {
        "time":    ts,
        "src_ip":  src_ip,
        "src_mac": src_mac,
        "device":  device_label,
        "domain":  domain,
        "qtype":   qtype_str,
        "category": category,
        "color":   color,
        "is_me":   src_ip == local_ip,
    }

    with lock:
        all_queries.appendleft(entry)
        per_device[src_ip].appendleft(domain)
        device_count[src_ip] += 1
        domain_freq[domain]  += 1
        stats["total"]       += 1

        if save_file:
            try:
                with open(save_file, "a") as f:
                    f.write(f"{ts}\t{src_ip}\t{src_mac}\t{domain}\t{qtype_str}\t{category}\n")
            except Exception:
                pass


# ══════════════════════════════════════════════════════════════════════════════
#  DASHBOARD
# ══════════════════════════════════════════════════════════════════════════════

def build_dashboard(local_ip):
    elapsed = max(time.time() - stats["start_time"], 0.001)
    qps     = stats["total"] / elapsed
    uptime  = time.strftime("%H:%M:%S", time.gmtime(elapsed))

    with lock:
        queries_snap = list(all_queries)
        per_dev_snap = {ip: list(q) for ip, q in per_device.items()}
        dev_cnt_snap = dict(device_count)
        freq_snap    = dict(domain_freq)

    # ── HEADER ───────────────────────────────────────────────────────────────
    header = (
        f"[bold bright_white]AI-IDS — DNS Monitor[/]  │  "
        f"Total queries: [bright_yellow]{stats['total']}[/]  │  "
        f"Devices active: [bright_cyan]{len(per_dev_snap)}[/]  │  "
        f"Queries/sec: [bright_red]{qps:.1f}[/]  │  "
        f"Uptime: [bright_green]{uptime}[/]  │  "
        f"[dim]PROMISCUOUS ON — seeing all devices[/]"
    )

    # ── LIVE QUERY STREAM ─────────────────────────────────────────────────────
    stream = Table(
        title="[bold]Live DNS Query Stream — What every device is looking up[/]",
        box=box.SIMPLE_HEAD, show_lines=False, padding=(0, 1),
    )
    stream.add_column("Time",       width=14)
    stream.add_column("Device",     width=18)
    stream.add_column("IP",         width=16)
    stream.add_column("Category",   width=12)
    stream.add_column("Domain / Site",  min_width=38)
    stream.add_column("Type", width=5, justify="center")

    for q in queries_snap[:35]:
        me_tag = " [bold bright_yellow](YOU)[/]" if q["is_me"] else ""
        stream.add_row(
            q["time"],
            f"[bright_white]{q['device']}[/]{me_tag}",
            f"[dim]{q['src_ip']}[/]",
            f"[{q['color']}]{q['category']}[/]",
            f"[{q['color']}]{q['domain']}[/]",
            f"[dim]{q['qtype']}[/]",
        )

    # ── PER DEVICE SUMMARY ───────────────────────────────────────────────────
    dev_table = Table(
        title="[bold]Per-Device Activity Summary[/]",
        box=box.SIMPLE_HEAD, show_lines=False, padding=(0, 1),
    )
    dev_table.add_column("Device / IP",      width=20)
    dev_table.add_column("Queries",          width=8,  justify="right")
    dev_table.add_column("Recent domains visited", min_width=55)

    sorted_devs = sorted(dev_cnt_snap.items(), key=lambda x: x[1], reverse=True)

    for ip, count in sorted_devs:
        is_me = ip == local_ip
        label = "THIS LAPTOP" if is_me else device_names.get(ip, DEVICE_HINTS.get(ip, ip))
        recent = per_dev_snap.get(ip, [])
        # Deduplicate while preserving order
        seen = set()
        unique = []
        for d in recent:
            if d not in seen:
                seen.add(d)
                unique.append(d)
        domains_str = "  •  ".join(unique[:6])
        if len(unique) > 6:
            domains_str += f"  [dim]+{len(unique)-6} more[/]"

        style = "bold bright_yellow" if is_me else "bright_white"
        dev_table.add_row(
            f"[{style}]{label}[/]",
            f"[bright_red]{count}[/]",
            f"[dim]{domains_str}[/]",
        )

    # ── TOP DOMAINS ───────────────────────────────────────────────────────────
    top_table = Table(
        title="[bold]Most Queried Domains (all devices)[/]",
        box=box.SIMPLE_HEAD, show_lines=False, padding=(0, 1),
    )
    top_table.add_column("Count",   width=7,  justify="right")
    top_table.add_column("Category", width=12)
    top_table.add_column("Domain",  min_width=40)

    top_domains = sorted(freq_snap.items(), key=lambda x: x[1], reverse=True)[:15]
    for domain, count in top_domains:
        cat, color = categorise(domain)
        top_table.add_row(
            f"[bright_red]{count}[/]",
            f"[{color}]{cat}[/]",
            f"[{color}]{domain}[/]",
        )

    # ── CATEGORY BREAKDOWN ────────────────────────────────────────────────────
    cat_counts = defaultdict(int)
    with lock:
        for q in queries_snap:
            cat_counts[q["category"]] += 1

    cat_table = Table(
        title="[bold]By Category[/]",
        box=box.SIMPLE_HEAD, show_lines=False, padding=(0, 1),
    )
    cat_table.add_column("Category",  width=12)
    cat_table.add_column("Queries",   width=8, justify="right")

    for cat, cnt in sorted(cat_counts.items(), key=lambda x: x[1], reverse=True):
        _, color = categorise(cat + ".com")
        cat_table.add_row(f"[{color}]{cat}[/]", f"[bright_red]{cnt}[/]")

    # ── FOOTER ────────────────────────────────────────────────────────────────
    footer_parts = ["[dim]Ctrl+C to stop"]
    if save_file:
        footer_parts.append(f"Saving to [bright_yellow]{save_file}[/]")
    footer_parts.append(
        "Tip: run v2 first to get device names, then add them to DEVICE_HINTS in this script[/]"
    )
    footer = "  │  ".join(footer_parts)

    # ── LAYOUT ───────────────────────────────────────────────────────────────
    layout = Layout()
    layout.split_column(
        Layout(Panel(header, box=box.ROUNDED, style="bold"), size=3),
        Layout(Panel(dev_table,  box=box.ROUNDED), size=12, name="devices"),
        Layout(Panel(stream,     box=box.ROUNDED), name="stream"),
        Layout(name="bottom"),
        Layout(Text(footer, justify="center"), size=1),
    )
    layout["bottom"].split_row(
        Layout(Panel(top_table,  box=box.ROUNDED)),
        Layout(Panel(cat_table,  box=box.ROUNDED)),
    )

    return layout


# ══════════════════════════════════════════════════════════════════════════════
#  HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def get_friendly_names():
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
                f"[bright_green]{ip:<18}[/]{label:<28}[dim]{iface}[/]"
                f"  [bold bright_green]← ACTIVE[/]"
            )
        elif is_loop:
            console.print(f"  [dim][{i}]  {ip:<18}{label:<28}{iface}  (loopback)[/]")
        else:
            console.print(f"  [{i}]  [dim]{ip:<18}[/]{label:<28}[dim]{iface}[/]")
    console.print()


def pick_interface():
    for iface in get_if_list():
        try:
            ip = get_if_addr(iface)
            if ip and ip not in ("0.0.0.0", "127.0.0.1", "unknown", ""):
                return iface
        except Exception:
            continue
    ifaces = get_if_list()
    return ifaces[0] if ifaces else None


# ══════════════════════════════════════════════════════════════════════════════
#  CAPTURE THREAD
# ══════════════════════════════════════════════════════════════════════════════

def start_capture(iface, local_ip):
    def callback(pkt):
        if stop_event.is_set():
            return True
        process_packet(pkt, local_ip)

    sniff(
        iface=iface,
        prn=callback,
        filter="udp port 53",    # DNS only — keeps this script fast and focused
        store=False,
        promisc=True,            # See ALL devices, not just this laptop
        stop_filter=lambda _: stop_event.is_set(),
    )


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="AI-IDS DNS Monitor — See what every device on the network is visiting"
    )
    parser.add_argument("--iface",  "-i", type=str, default=None)
    parser.add_argument("--list",   "-l", action="store_true")
    parser.add_argument("--save",   "-s", type=str, default=None,
                        help="Save DNS log to a text file")
    args = parser.parse_args()

    if args.list:
        list_interfaces()
        return

    global save_file
    save_file = args.save

    iface = args.iface or pick_interface()
    if not iface:
        console.print("[bold red]No interface found.[/]")
        sys.exit(1)

    try:    local_ip = get_if_addr(iface)
    except: local_ip = "unknown"

    friendly = get_friendly_names()
    label    = friendly.get(iface, iface)

    # Pre-populate device hints from DEVICE_HINTS
    device_names.update(DEVICE_HINTS)

    console.print(f"\n[bold bright_green]AI-IDS DNS Monitor[/]")
    console.print(f"  Interface  : [bright_cyan]{label}[/]")
    console.print(f"  My IP      : [bright_yellow]{local_ip}[/]")
    console.print(f"  Mode       : [bold bright_magenta]Promiscuous — all devices[/]")
    console.print(f"  Filter     : [bright_green]UDP port 53 (DNS queries only)[/]")
    if save_file:
        console.print(f"  Saving to  : [bright_yellow]{save_file}[/]")
    console.print()
    console.print(
        "[dim]Tip: edit DEVICE_HINTS at the top of this script to name your devices.\n"
        "     Get IPs + MACs from v2_network_capture.py first.[/]\n"
    )
    console.print("[dim]Starting in 1 second...[/]\n")
    time.sleep(1)

    if save_file:
        with open(save_file, "w") as f:
            f.write("time\tsrc_ip\tsrc_mac\tdomain\tqtype\tcategory\n")

    t = threading.Thread(
        target=start_capture,
        args=(iface, local_ip),
        daemon=True,
    )
    t.start()

    try:
        with Live(
            build_dashboard(local_ip),
            refresh_per_second=2,
            screen=True,
        ) as live:
            while not stop_event.is_set():
                time.sleep(0.5)
                live.update(build_dashboard(local_ip))
    except KeyboardInterrupt:
        pass
    finally:
        stop_event.set()
        console.print(f"\n[bold bright_yellow]Stopped.[/]  Total DNS queries captured: [bright_white]{stats['total']}[/]")
        console.print(f"Devices seen: [bright_cyan]{len(per_device)}[/]")
        if save_file:
            console.print(f"Log saved to: [bright_green]{save_file}[/]")

        # Print final per-device summary
        console.print("\n[bold]Final summary per device:[/]\n")
        for ip, domains in per_device.items():
            label = device_names.get(ip, DEVICE_HINTS.get(ip, ip))
            unique = list(dict.fromkeys(domains))
            console.print(f"  [bright_yellow]{label}[/] ({ip}) — {device_count[ip]} queries")
            for d in unique[:10]:
                cat, color = categorise(d)
                console.print(f"    [{color}]• {d}[/]")
            if len(unique) > 10:
                console.print(f"    [dim]... and {len(unique)-10} more[/]")
            console.print()


if __name__ == "__main__":
    main()

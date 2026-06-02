"""
╔══════════════════════════════════════════════════════════════╗
║   AI-IDS  —  PCAP READER & ANALYSER                         ║
║   Read and summarise any .pcap file from your captures       ║
╚══════════════════════════════════════════════════════════════╝

USAGE:
  python pcap_reader.py capture_v1.pcap
  python pcap_reader.py capture.pcap --top 20
  python pcap_reader.py capture_v1.pcap --show-packets 50
  python pcap_reader.py capture_v1.pcap --filter-ip 192.168.1.212
  python pcap_reader.py capture_v1.pcap --export summary.txt
"""

import argparse
import sys
from collections import defaultdict, Counter
from datetime import datetime

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

try:
    from scapy.all import rdpcap, IP, TCP, UDP, ICMP, ARP, DNS, DNSQR, Ether
except ImportError:
    print("[ERROR] Run:  pip install scapy")
    sys.exit(1)

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich import box
    from rich.rule import Rule
except ImportError:
    print("[ERROR] Run:  pip install rich")
    sys.exit(1)

console = Console()

# ─────────────────────────────────────────────────────────────────────────────

KNOWN_PORTS = {
    20:"FTP-DATA",21:"FTP",22:"SSH",23:"TELNET",25:"SMTP",
    53:"DNS",67:"DHCP",68:"DHCP",80:"HTTP",110:"POP3",
    143:"IMAP",443:"HTTPS",445:"SMB",993:"IMAPS",995:"POP3S",
    3306:"MySQL",3389:"RDP",5432:"PostgreSQL",8080:"HTTP-ALT",
    8443:"HTTPS-ALT",27017:"MongoDB",
}

TCP_FLAGS = {
    0x01:"FIN",0x02:"SYN",0x04:"RST",
    0x08:"PSH",0x10:"ACK",0x20:"URG",
}

def flag_str(f):
    return "+".join(n for b,n in TCP_FLAGS.items() if int(f)&b) or "—"

def svc(port):
    return KNOWN_PORTS.get(port, str(port))

def fmt_bytes(n):
    if n < 1024:      return f"{n} B"
    if n < 1024**2:   return f"{n/1024:.1f} KB"
    if n < 1024**3:   return f"{n/1024**2:.1f} MB"
    return                   f"{n/1024**3:.2f} GB"

def proto_color(p):
    return {
        "HTTPS":"bright_green","HTTP":"green","DNS":"bright_blue",
        "TCP":"bright_cyan","UDP":"bright_green","ICMP":"bright_yellow",
        "ARP":"bright_magenta","OTHER":"white",
    }.get(p,"white")

def get_proto(pkt):
    if pkt.haslayer(ARP):  return "ARP"
    if pkt.haslayer(DNS):  return "DNS"
    if pkt.haslayer(TCP):
        sp,dp = pkt[TCP].sport, pkt[TCP].dport
        if 443 in (sp,dp): return "HTTPS"
        if 80  in (sp,dp): return "HTTP"
        return "TCP"
    if pkt.haslayer(UDP):  return "UDP"
    if pkt.haslayer(ICMP): return "ICMP"
    return "OTHER"


# ─────────────────────────────────────────────────────────────────────────────

def analyse(pcap_path, top_n=15, show_packets=30, filter_ip=None, export=None):

    console.print(f"\n[bold bright_cyan]Loading {pcap_path} ...[/]")

    try:
        packets = rdpcap(pcap_path)
    except FileNotFoundError:
        console.print(f"[bold red]File not found: {pcap_path}[/]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[bold red]Could not read PCAP: {e}[/]")
        sys.exit(1)

    total = len(packets)
    console.print(f"[bright_green]Loaded {total:,} packets.[/]\n")

    # ── PASS 1: collect all stats ─────────────────────────────────────────────
    proto_counts  = Counter()
    proto_bytes   = defaultdict(int)
    ip_sent       = defaultdict(int)       # { ip: bytes }
    ip_recv       = defaultdict(int)
    ip_sent_pkts  = defaultdict(int)
    conversations = defaultdict(lambda: {"pkts":0,"bytes":0,"flags":set()})
    dns_queries   = []
    total_bytes   = 0
    timestamps    = []

    # For packet list display
    packet_rows = []

    for pkt in packets:
        pkt_len = len(pkt)
        total_bytes += pkt_len

        # Timestamp
        try:
            ts = datetime.fromtimestamp(float(pkt.time)).strftime("%H:%M:%S.%f")[:-3]
            timestamps.append(float(pkt.time))
        except Exception:
            ts = "—"

        proto = get_proto(pkt)
        proto_counts[proto] += 1
        proto_bytes[proto]  += pkt_len

        # ── ARP ──────────────────────────────────────────────────────────
        if pkt.haslayer(ARP):
            arp = pkt[ARP]
            op  = "WHO-HAS" if arp.op==1 else "IS-AT"
            info = f"ARP {op}  {arp.psrc} → {arp.pdst}"
            src_ip = arp.psrc or "—"
            dst_ip = arp.pdst or "—"
            flags_display = "—"

        # ── IP ───────────────────────────────────────────────────────────
        elif pkt.haslayer(IP):
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst

            # Filter by IP if requested
            if filter_ip and filter_ip not in (src_ip, dst_ip):
                continue

            ip_sent[src_ip] += pkt_len
            ip_recv[dst_ip] += pkt_len
            ip_sent_pkts[src_ip] += 1

            if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
                if pkt[DNS].qr == 0:  # query only
                    try:
                        qname = pkt[DNSQR].qname.decode(errors="replace").rstrip(".")
                        dns_queries.append({"time": ts, "src": src_ip, "query": qname})
                    except Exception:
                        pass
                info = "DNS query"
                flags_display = "—"

            elif pkt.haslayer(TCP):
                tcp = pkt[TCP]
                fs  = flag_str(tcp.flags)
                info = f"{svc(tcp.sport)} → {svc(tcp.dport)}  [{fs}]"
                flags_display = fs
                ck = (src_ip, dst_ip, tcp.sport, tcp.dport, "TCP")
                conversations[ck]["pkts"]  += 1
                conversations[ck]["bytes"] += pkt_len
                conversations[ck]["flags"].add(fs)

            elif pkt.haslayer(UDP):
                udp = pkt[UDP]
                info = f"{svc(udp.sport)} → {svc(udp.dport)}"
                flags_display = "—"
                ck = (src_ip, dst_ip, udp.sport, udp.dport, "UDP")
                conversations[ck]["pkts"]  += 1
                conversations[ck]["bytes"] += pkt_len

            elif pkt.haslayer(ICMP):
                types = {0:"Echo Reply",3:"Unreachable",8:"Echo Request",11:"TTL Exceeded"}
                info = types.get(pkt[ICMP].type, f"Type {pkt[ICMP].type}")
                flags_display = "—"

            else:
                info = f"Proto {pkt[IP].proto}"
                flags_display = "—"
        else:
            src_ip = "—"
            dst_ip = "—"
            info   = "Non-IP"
            flags_display = "—"

        packet_rows.append({
            "ts": ts, "proto": proto, "src": src_ip,
            "dst": dst_ip, "info": info, "size": pkt_len,
            "flags": flags_display,
        })

    # ── Duration ─────────────────────────────────────────────────────────────
    if len(timestamps) >= 2:
        duration = timestamps[-1] - timestamps[0]
        dur_str  = f"{duration:.1f} seconds"
        pps      = total / duration if duration > 0 else 0
        bps      = total_bytes / duration if duration > 0 else 0
    else:
        dur_str  = "< 1 second"
        pps      = 0
        bps      = 0

    start_ts = datetime.fromtimestamp(timestamps[0]).strftime("%Y-%m-%d %H:%M:%S") if timestamps else "—"
    end_ts   = datetime.fromtimestamp(timestamps[-1]).strftime("%Y-%m-%d %H:%M:%S") if timestamps else "—"


    # ══════════════════════════════════════════════════════════════════════════
    #  OUTPUT
    # ══════════════════════════════════════════════════════════════════════════

    lines = []   # collect for optional export

    def out(text=""):
        console.print(text)
        lines.append(console.highlighter(text) if isinstance(text, str) else "")

    # ── SUMMARY PANEL ────────────────────────────────────────────────────────
    console.rule("[bold bright_white]PCAP Summary[/]")
    summary = Table(box=box.SIMPLE, show_header=False, padding=(0,3))
    summary.add_column(style="bright_white", width=22)
    summary.add_column(style="bright_yellow")
    summary.add_row("File",          pcap_path)
    summary.add_row("Total packets", f"{total:,}")
    summary.add_row("Total data",    fmt_bytes(total_bytes))
    summary.add_row("Duration",      dur_str)
    summary.add_row("Start time",    start_ts)
    summary.add_row("End time",      end_ts)
    summary.add_row("Avg pkt/s",     f"{pps:.1f}")
    summary.add_row("Avg throughput",f"{fmt_bytes(int(bps))}/s")
    if filter_ip:
        summary.add_row("Filtered to IP", f"[bright_cyan]{filter_ip}[/]")
    console.print(summary)

    # ── PROTOCOL BREAKDOWN ───────────────────────────────────────────────────
    console.rule("[bold bright_white]Protocol Breakdown[/]")
    pt = Table(box=box.SIMPLE_HEAD, padding=(0,2))
    pt.add_column("Protocol",  width=10)
    pt.add_column("Packets",   justify="right", width=10)
    pt.add_column("% of total",justify="right", width=12)
    pt.add_column("Bytes",     justify="right", width=12)
    pt.add_column("Bar")

    for proto, cnt in proto_counts.most_common():
        pct  = cnt / total * 100
        bar  = "█" * int(pct / 2)
        col  = proto_color(proto)
        pt.add_row(
            f"[{col}]{proto}[/]",
            f"{cnt:,}",
            f"{pct:.1f}%",
            fmt_bytes(proto_bytes[proto]),
            f"[{col}]{bar}[/]",
        )
    console.print(pt)

    # ── TOP TALKERS ───────────────────────────────────────────────────────────
    console.rule("[bold bright_white]Top Talkers (by bytes sent)[/]")
    tt = Table(box=box.SIMPLE_HEAD, padding=(0,2))
    tt.add_column("IP Address",   width=18)
    tt.add_column("Pkts sent",    justify="right", width=10)
    tt.add_column("Bytes sent",   justify="right", width=12)
    tt.add_column("Bytes recv",   justify="right", width=12)

    top_senders = sorted(ip_sent.items(), key=lambda x: x[1], reverse=True)[:top_n]
    for ip_addr, sent in top_senders:
        recv = ip_recv.get(ip_addr, 0)
        pkts = ip_sent_pkts.get(ip_addr, 0)
        tt.add_row(ip_addr, f"{pkts:,}", fmt_bytes(sent), fmt_bytes(recv))
    console.print(tt)

    # ── TOP CONVERSATIONS ────────────────────────────────────────────────────
    console.rule("[bold bright_white]Top Conversations (flows)[/]")
    ct = Table(box=box.SIMPLE_HEAD, padding=(0,1))
    ct.add_column("Source",       width=22)
    ct.add_column("Destination",  width=22)
    ct.add_column("Proto", width=6)
    ct.add_column("Pkts",  justify="right", width=6)
    ct.add_column("Bytes", justify="right", width=10)
    ct.add_column("Flags seen",   width=25)

    top_convos = sorted(conversations.items(), key=lambda x: x[1]["bytes"], reverse=True)[:top_n]
    for (si,di,sp,dp,pr), data in top_convos:
        col = "bright_cyan" if pr=="TCP" else "bright_green"
        ct.add_row(
            f"{si}:{sp}",
            f"{di}:{dp}",
            f"[{col}]{pr}[/]",
            str(data["pkts"]),
            fmt_bytes(data["bytes"]),
            "  ".join(sorted(data["flags"]))[:25],
        )
    console.print(ct)

    # ── DNS QUERIES ───────────────────────────────────────────────────────────
    if dns_queries:
        console.rule("[bold bright_white]DNS Queries (sites visited)[/]")
        dt = Table(box=box.SIMPLE_HEAD, padding=(0,2))
        dt.add_column("Time",   width=14)
        dt.add_column("From",   width=18)
        dt.add_column("Domain queried", min_width=40)

        # Deduplicate but keep order
        seen_dns = set()
        unique_dns = []
        for q in dns_queries:
            key = (q["src"], q["query"])
            if key not in seen_dns:
                seen_dns.add(key)
                unique_dns.append(q)

        for q in unique_dns[:30]:
            dt.add_row(q["time"], q["src"], f"[bright_blue]{q['query']}[/]")

        console.print(dt)
        console.print(f"[dim]Total unique DNS queries: {len(seen_dns)}[/]\n")

    # ── ANOMALY HINTS ─────────────────────────────────────────────────────────
    console.rule("[bold bright_white]Anomaly Indicators[/]")
    anomalies_found = False

    # Check 1: SYN flood / port scan — many SYN with no ACK from one IP
    syn_counts   = defaultdict(int)
    synack_counts= defaultdict(int)
    for pkt in packets:
        if pkt.haslayer(TCP) and pkt.haslayer(IP):
            f = int(pkt[TCP].flags)
            src = pkt[IP].src
            if f & 0x02 and not (f & 0x10):  # SYN but no ACK
                syn_counts[src] += 1
            if f & 0x12 == 0x12:              # SYN+ACK
                synack_counts[src] += 1

    for ip_addr, count in syn_counts.items():
        if count > 20:
            anomalies_found = True
            console.print(
                f"  [bold bright_red]⚠  PORT SCAN / SYN FLOOD:[/] "
                f"[bright_white]{ip_addr}[/] sent [bright_red]{count}[/] SYN-only packets "
                f"(completed: {synack_counts.get(ip_addr,0)})"
            )

    # Check 2: Single IP dominating traffic
    if top_senders:
        top_ip, top_bytes = top_senders[0]
        if total_bytes > 0 and top_bytes / total_bytes > 0.7:
            anomalies_found = True
            console.print(
                f"  [bold bright_yellow]⚠  TRAFFIC DOMINANCE:[/] "
                f"[bright_white]{top_ip}[/] accounts for "
                f"[bright_yellow]{top_bytes/total_bytes*100:.0f}%[/] of total traffic"
            )

    # Check 3: Very high packet rate
    if pps > 500:
        anomalies_found = True
        console.print(
            f"  [bold bright_red]⚠  HIGH PACKET RATE:[/] "
            f"[bright_red]{pps:.0f} pkt/s[/] — potential flood or scan"
        )

    # Check 4: ARP — check for repeated IS-AT from same IP with different MACs
    arp_map = defaultdict(set)  # { ip: set of MACs }
    for pkt in packets:
        if pkt.haslayer(ARP) and pkt[ARP].op == 2:  # IS-AT replies
            arp_map[pkt[ARP].psrc].add(pkt[ARP].hwsrc)
    for ip_addr, macs in arp_map.items():
        if len(macs) > 1:
            anomalies_found = True
            console.print(
                f"  [bold bright_red]⚠  ARP SPOOFING:[/] "
                f"[bright_white]{ip_addr}[/] seen with [bright_red]{len(macs)}[/] "
                f"different MACs: {', '.join(macs)}"
            )

    # Check 5: Large outbound transfers to unknown IPs
    known_prefixes = ("192.168.", "10.", "172.", "127.")
    for ip_addr, sent in ip_sent.items():
        recv = ip_recv.get(ip_addr, 0)
        is_external = not any(ip_addr.startswith(p) for p in known_prefixes)
        if is_external and sent > 500_000 and sent > recv * 5:
            anomalies_found = True
            console.print(
                f"  [bold bright_yellow]⚠  LARGE OUTBOUND:[/] "
                f"[bright_white]{ip_addr}[/] — sent {fmt_bytes(sent)}, "
                f"received only {fmt_bytes(recv)} "
                f"(possible exfiltration)"
            )

    if not anomalies_found:
        console.print("  [bright_green]✓  No obvious anomalies detected in this capture.[/]")
        console.print(
            "  [dim]This looks like normal traffic. "
            "To see anomalies, run an nmap scan and capture that.[/]"
        )

    # ── PACKET LIST ───────────────────────────────────────────────────────────
    if show_packets and show_packets > 0:
        console.rule(f"[bold bright_white]First {show_packets} Packets[/]")
        pl = Table(box=box.SIMPLE_HEAD, padding=(0,1), show_lines=False)
        pl.add_column("#",       width=6,  justify="right")
        pl.add_column("Time",    width=14)
        pl.add_column("Proto",   width=8,  justify="center")
        pl.add_column("Source",  width=18)
        pl.add_column("Dest",    width=18)
        pl.add_column("Info",    min_width=30)
        pl.add_column("Size",    width=8,  justify="right")

        for i, row in enumerate(packet_rows[:show_packets], 1):
            col = proto_color(row["proto"])
            pl.add_row(
                str(i),
                row["ts"],
                f"[{col}]{row['proto']}[/]",
                row["src"],
                row["dst"],
                row["info"][:45],
                fmt_bytes(row["size"]),
            )
        console.print(pl)

    # ── EXPORT ───────────────────────────────────────────────────────────────
    if export:
        try:
            with open(export, "w", encoding="utf-8") as f:
                f.write(f"PCAP Analysis: {pcap_path}\n")
                f.write(f"Total packets: {total:,}\n")
                f.write(f"Total bytes: {fmt_bytes(total_bytes)}\n")
                f.write(f"Duration: {dur_str}\n")
                f.write(f"Start: {start_ts}  End: {end_ts}\n\n")
                f.write("=== DNS Queries ===\n")
                for q in dns_queries:
                    f.write(f"{q['time']}\t{q['src']}\t{q['query']}\n")
                f.write("\n=== Top Conversations ===\n")
                for (si,di,sp,dp,pr), data in top_convos:
                    f.write(f"{si}:{sp} → {di}:{dp}  {pr}  {data['pkts']} pkts  {fmt_bytes(data['bytes'])}\n")
            console.print(f"\n[bright_green]Summary exported to {export}[/]")
        except Exception as e:
            console.print(f"[bright_red]Export failed: {e}[/]")

    console.print()


# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="AI-IDS PCAP Reader — analyse a captured .pcap file"
    )
    parser.add_argument("pcap",             type=str,
                        help="Path to .pcap file")
    parser.add_argument("--top",            type=int, default=15,
                        help="Number of top entries to show (default 15)")
    parser.add_argument("--show-packets",   type=int, default=30,
                        help="Number of individual packets to list (default 30, 0 to skip)")
    parser.add_argument("--filter-ip",      type=str, default=None,
                        help="Only show packets involving this IP address")
    parser.add_argument("--export",         type=str, default=None,
                        help="Export text summary to a file")
    args = parser.parse_args()

    analyse(
        pcap_path    = args.pcap,
        top_n        = args.top,
        show_packets = args.show_packets,
        filter_ip    = args.filter_ip,
        export       = args.export,
    )


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
ids_classic.py
──────────────
Rule-based Intrusion Detection System — NO machine learning.

Detects threats using behavioral thresholds:
  - Port scan (SYN flood to many ports from one IP)
  - DDoS / SYN flood (very high packet rate to one destination)
  - Brute force (repeated short connections to same port)
  - ARP poisoning (IP→MAC mapping change)
  - DNS exfiltration (unusually large DNS query volume)
  - ICMP flood
  - Data exfiltration (large outbound to unknown external IP)

USAGE
─────
  # List interfaces
  python ids_classic.py --list

  # Host-only (v1)
  python ids_classic.py --iface "\\Device\\NPF_{...}" --email-to admin@example.com

  # Network-wide promiscuous (v2)
  python ids_classic.py --iface "\\Device\\NPF_{...}" --network --email-to admin@example.com

  # Replay a saved PCAP
  python ids_classic.py --pcap captures/with_attack.pcap --email-to admin@example.com

  # Send test email then exit
  python ids_classic.py --test-email --email-to admin@example.com

  # Export last 24h events to CSV
  python ids_classic.py --report --hours 24

  # Custom alert email
  python ids_classic.py --iface "..." --email-to security@myorg.com --email-pass MyP@ss
"""

import os
import sys
import time
import queue
import threading
import logging
from collections import defaultdict, deque
from datetime import datetime
from typing import Optional

import click

# Suppress Scapy IPv6 warning
import logging as _lg
_lg.getLogger("scapy.runtime").setLevel(_lg.ERROR)

# ── Project imports ────────────────────────────────────────────────────────────
sys.path.insert(0, os.path.dirname(__file__))
from core.capture   import CaptureEngine, FlowRecord
from core.alerter   import EmailAlerter, DEFAULT_SENDER, DEFAULT_SMTP_HOST, DEFAULT_SMTP_PORT, DEFAULT_RECIPIENT, DEFAULT_PASSWORD
from core.database  import EventDB
import core.dashboard as dash

# ── Logging ────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("ids.classic")

# ── Detection thresholds ───────────────────────────────────────────────────────
THR = {
    # Port scan: >N distinct destination ports from one src IP within window
    "port_scan_ports":       15,
    # SYN flood: >N SYN packets per second from one src IP
    "syn_flood_pps":         50,
    # Brute force: >N connection attempts to same dst port in window
    "brute_force_attempts":  10,
    # ICMP flood: >N ICMP packets per second
    "icmp_flood_pps":        30,
    # DNS: >N DNS queries per minute from one host
    "dns_flood_qpm":         100,
    # Large outbound: bytes sent > N to a single external IP
    "exfil_bytes":           5_000_000,    # 5 MB
    # ARP: a source MAC changes its IP mapping
    "arp_spoof":             True,
    # Minimum packets in a flow to bother evaluating
    "min_flow_packets":      3,
}


class RuleEngine:
    """
    Stateful rule engine.
    Called once per completed FlowRecord; returns list of (attack_name, details) tuples.
    """

    def __init__(self, local_ip: str = ""):
        self.local_ip = local_ip

        # State for multi-flow detection
        self._syn_tracker:    dict = defaultdict(list)   # src_ip → [timestamps]
        self._port_tracker:   dict = defaultdict(set)    # src_ip → {dst_ports}
        self._brute_tracker:  dict = defaultdict(list)   # (src,dport) → [timestamps]
        self._icmp_tracker:   dict = defaultdict(list)   # src_ip → [timestamps]
        self._dns_tracker:    dict = defaultdict(list)   # src_ip → [timestamps]
        self._arp_table:      dict = {}                  # ip → mac
        self._lock = threading.Lock()

    def _prune(self, lst: list, window_secs: float = 60.0):
        """Remove entries older than window_secs."""
        cutoff = time.time() - window_secs
        while lst and lst[0] < cutoff:
            lst.pop(0)

    def evaluate(self, fr: FlowRecord) -> list:
        if fr.packets < THR["min_flow_packets"] and fr.arp_op == "":
            return []

        findings = []
        now = time.time()

        with self._lock:

            # ── ARP poisoning ────────────────────────────────────────────────
            if fr.protocol == "ARP" and fr.arp_op == "IS-AT":
                known_mac = self._arp_table.get(fr.src_ip)
                if known_mac and known_mac != fr.src_mac and fr.src_mac:
                    findings.append(("ARP Poisoning", {
                        "IP":       fr.src_ip,
                        "Old MAC":  known_mac,
                        "New MAC":  fr.src_mac,
                        "Severity": "CRITICAL",
                    }))
                if fr.src_ip and fr.src_mac:
                    self._arp_table[fr.src_ip] = fr.src_mac

            # ── Port scan ────────────────────────────────────────────────────
            if fr.protocol == "TCP" and fr.syn_count > 0:
                ports = self._port_tracker[fr.src_ip]
                ports.add(fr.dst_port)
                if len(ports) >= THR["port_scan_ports"]:
                    findings.append(("Port Scan", {
                        "Attacker":     fr.src_ip,
                        "Ports probed": len(ports),
                        "SYN count":    fr.syn_count,
                        "Severity":     "HIGH",
                    }))
                    # Don't clear — keep tracking for escalation

            # ── SYN flood ────────────────────────────────────────────────────
            if fr.protocol == "TCP" and fr.syn_count > 0:
                events = self._syn_tracker[fr.src_ip]
                events.extend([now] * fr.syn_count)
                self._prune(events, 1.0)  # 1-second window
                if len(events) >= THR["syn_flood_pps"]:
                    findings.append(("SYN Flood / DDoS", {
                        "Attacker":   fr.src_ip,
                        "Target":     fr.dst_ip,
                        "SYN/sec":    len(events),
                        "Threshold":  THR["syn_flood_pps"],
                        "Severity":   "CRITICAL",
                    }))
                    self._syn_tracker[fr.src_ip] = []  # reset after alert

            # ── Brute force ──────────────────────────────────────────────────
            if fr.protocol == "TCP" and fr.fin_count + fr.rst_count > 0:
                key = (fr.src_ip, fr.dst_port)
                attempts = self._brute_tracker[key]
                attempts.append(now)
                self._prune(attempts, 60.0)
                if len(attempts) >= THR["brute_force_attempts"]:
                    service = _port_service(fr.dst_port)
                    findings.append((f"Brute Force ({service})", {
                        "Attacker":  fr.src_ip,
                        "Target":    f"{fr.dst_ip}:{fr.dst_port}",
                        "Service":   service,
                        "Attempts":  len(attempts),
                        "Severity":  "HIGH",
                    }))
                    self._brute_tracker[key] = []

            # ── ICMP flood ───────────────────────────────────────────────────
            if fr.protocol == "ICMP":
                events = self._icmp_tracker[fr.src_ip]
                events.extend([now] * fr.packets)
                self._prune(events, 1.0)
                if len(events) >= THR["icmp_flood_pps"]:
                    findings.append(("ICMP Flood", {
                        "Attacker":   fr.src_ip,
                        "ICMP/sec":   len(events),
                        "Threshold":  THR["icmp_flood_pps"],
                        "Severity":   "MEDIUM",
                    }))
                    self._icmp_tracker[fr.src_ip] = []

            # ── DNS flood ────────────────────────────────────────────────────
            if fr.protocol == "UDP" and fr.dst_port == 53:
                events = self._dns_tracker[fr.src_ip]
                events.append(now)
                self._prune(events, 60.0)
                if len(events) >= THR["dns_flood_qpm"]:
                    findings.append(("DNS Flood / Exfiltration", {
                        "Source":      fr.src_ip,
                        "Queries/min": len(events),
                        "Threshold":   THR["dns_flood_qpm"],
                        "Severity":    "MEDIUM",
                    }))
                    self._dns_tracker[fr.src_ip] = []

            # ── Data exfiltration ────────────────────────────────────────────
            _private = ("192.168.", "10.", "172.", "127.")
            is_external = not any(fr.dst_ip.startswith(p) for p in _private)
            if is_external and fr.src_ip == self.local_ip and fr.fwd_bytes >= THR["exfil_bytes"]:
                findings.append(("Data Exfiltration", {
                    "Source":      fr.src_ip,
                    "Destination": fr.dst_ip,
                    "Data sent":   f"{fr.fwd_bytes/1024/1024:.1f} MB",
                    "Threshold":   f"{THR['exfil_bytes']//1024//1024} MB",
                    "Severity":    "HIGH",
                }))

        return findings


def _port_service(port: int) -> str:
    services = {22: "SSH", 21: "FTP", 23: "Telnet", 25: "SMTP",
                80: "HTTP", 443: "HTTPS", 3389: "RDP", 3306: "MySQL",
                5432: "PostgreSQL", 6379: "Redis"}
    return services.get(port, f"port/{port}")


# ── Main processor ─────────────────────────────────────────────────────────────

def run_detection(
    flow_queue:  queue.Queue,
    alerter:     EmailAlerter,
    db:          EventDB,
    stop_event:  threading.Event,
    mode_label:  str,
):
    """Consume flows from queue, run rules, alert on findings."""
    engine = RuleEngine()

    while not stop_event.is_set() or not flow_queue.empty():
        try:
            fr: FlowRecord = flow_queue.get(timeout=1.0)
        except queue.Empty:
            continue

        dash.inc_flow()
        findings = engine.evaluate(fr)

        for attack_type, details in findings:
            ts  = datetime.now().strftime("%H:%M:%S")
            alert = {
                "time":        ts,
                "src_ip":      fr.src_ip,
                "dst_ip":      fr.dst_ip,
                "attack_type": attack_type,
                "confidence":  None,
                "model":       "Rule Engine",
                "alerted":     False,
            }

            alerted = alerter.send_alert(
                src_ip=fr.src_ip,
                dst_ip=fr.dst_ip,
                attack_type=attack_type,
                confidence=None,
                details={
                    "Protocol":  fr.protocol,
                    "Src Port":  str(fr.src_port),
                    "Dst Port":  str(fr.dst_port),
                    "Packets":   str(fr.packets),
                    "Bytes":     str(fr.bytes_total),
                    "Duration":  f"{fr.duration:.2f}s",
                    **details,
                },
                app_mode=f"Classic IDS ({mode_label})",
            )
            alert["alerted"] = alerted
            dash.push_alert(alert)
            dash.print_simple_alert(alert)

            db.log_event(
                src_ip=fr.src_ip, dst_ip=fr.dst_ip,
                attack_type=attack_type,
                src_port=fr.src_port, dst_port=fr.dst_port,
                protocol=fr.protocol, packets=fr.packets,
                bytes_total=fr.bytes_total, duration=fr.duration,
                alerted=alerted, app_mode=f"Classic IDS ({mode_label})",
                notes=str(details),
            )


# ── CLI ────────────────────────────────────────────────────────────────────────

@click.group(invoke_without_command=True)
@click.pass_context
def cli(ctx):
    """
    AI-IDS Classic — Rule-Based Intrusion Detection System

    \b
    Examples:
      python ids_classic.py --list
      python ids_classic.py --iface "\\Device\\NPF_{...}" --email-to you@example.com
      python ids_classic.py --iface "\\Device\\NPF_{...}" --network
      python ids_classic.py --pcap captures/attack.pcap --email-to you@example.com
      python ids_classic.py --test-email --email-to you@example.com
      python ids_classic.py --report --hours 24
    """
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@cli.command("start")
@click.option("--iface",      "-i", default="", help="Network interface NPF name")
@click.option("--network",    "-n", is_flag=True, help="v2: promiscuous / network-wide mode")
@click.option("--pcap",       "-p", default="", help="Replay a saved .pcap file instead of live capture")
@click.option("--email-to",   "-e", default=DEFAULT_RECIPIENT, show_default=True,
              help="Alert recipient email address")
@click.option("--email-pass",       default=DEFAULT_PASSWORD, envvar="IDS_EMAIL_PASS",
              help="SMTP password (or set IDS_EMAIL_PASS env var)")
@click.option("--suppress",         default=5, show_default=True,
              help="Minutes to suppress duplicate alerts per source IP")
@click.option("--window",           default=5.0, show_default=True,
              help="Flow aggregation window in seconds")
@click.option("--dry-run",          is_flag=True, help="Log alerts but don't actually send email")
@click.option("--no-dashboard",     is_flag=True, help="Plain log output instead of Rich dashboard")
@click.option("--db",               default="db/ids_classic_events.db", show_default=True,
              help="SQLite database file path")
def start_cmd(iface, network, pcap, email_to, email_pass, suppress, window, dry_run, no_dashboard, db):
    """Start the Classic IDS (rule-based detection)."""

    # Auto-pick interface if not specified
    if not iface and not pcap:
        iface, local_ip = CaptureEngine.get_active_interface()
        if not iface:
            click.echo("[ERROR] No active interface found. Use --list to see options.")
            sys.exit(1)
    elif iface:
        try:
            from scapy.all import get_if_addr
            local_ip = get_if_addr(iface)
        except Exception:
            local_ip = ""
    else:
        local_ip = "127.0.0.1"

    mode_label = "v2-Network" if network else "v1-Host"
    smtp_pass  = email_pass or os.environ.get("IDS_EMAIL_PASS", "")

    # Print banner
    click.echo(f"\n{'='*60}")
    click.echo(f"  AI-IDS Classic — Rule-Based IDS")
    click.echo(f"{'='*60}")
    click.echo(f"  Mode       : {mode_label}")
    if pcap:
        click.echo(f"  Source     : PCAP replay — {pcap}")
    else:
        click.echo(f"  Interface  : {iface}")
        click.echo(f"  Local IP   : {local_ip}")
        click.echo(f"  Promiscuous: {'YES' if network else 'No'}")
    click.echo(f"  Alert →    : {email_to}")
    click.echo(f"  Dry run    : {'YES — no emails sent' if dry_run else 'No'}")
    click.echo(f"  DB         : {db}")
    click.echo(f"{'='*60}\n")

    if not smtp_pass and not dry_run:
        click.echo("[WARNING] No email password set. Use --email-pass or IDS_EMAIL_PASS env var.")
        click.echo("          Use --dry-run to test without sending emails.\n")

    # Init components
    flow_q     = queue.Queue()
    stop_event = threading.Event()
    alerter    = EmailAlerter(
        recipient=email_to,
        password=smtp_pass,
        suppress_minutes=suppress,
        dry_run=dry_run,
    )
    event_db   = EventDB(db)

    # Start detection thread
    det_thread = threading.Thread(
        target=run_detection,
        args=(flow_q, alerter, event_db, stop_event, mode_label),
        daemon=True, name="detector",
    )
    det_thread.start()

    # Start capture
    engine = CaptureEngine(
        out_queue=flow_q,
        interface=iface,
        pcap_file=pcap,
        promiscuous=network,
        window_seconds=window,
        local_ip=local_ip,
        stop_event=stop_event,
    )

    try:
        if pcap:
            click.echo(f"Replaying {pcap} ...")
            engine.replay_pcap()
            time.sleep(window + 1)  # let flows expire
            stop_event.set()
            det_thread.join(timeout=10)
            _print_summary(event_db, alerter)
        else:
            engine.start_live()
            click.echo("Capture running. Press Ctrl+C to stop.\n")

            if not no_dashboard:
                try:
                    from rich.live import Live
                    with Live(
                        dash.build_layout(
                            "AI-IDS Classic", mode_label,
                            iface, local_ip, email_to,
                        ),
                        refresh_per_second=2, screen=True,
                    ) as live:
                        while not stop_event.is_set():
                            time.sleep(0.5)
                            live.update(dash.build_layout(
                                "AI-IDS Classic", mode_label,
                                iface, local_ip, email_to,
                            ))
                except ImportError:
                    while not stop_event.is_set():
                        time.sleep(1)
            else:
                while not stop_event.is_set():
                    time.sleep(1)

    except KeyboardInterrupt:
        click.echo("\nStopping ...")
    finally:
        stop_event.set()
        engine.stop()
        det_thread.join(timeout=5)
        _print_summary(event_db, alerter)


@cli.command("list")
def list_cmd():
    """List all available network interfaces."""
    click.echo("\nAvailable interfaces:\n")
    click.echo(f"  {'#':<4} {'IP':<18} {'Friendly':<28} NPF Identifier")
    click.echo(f"  {'─'*4} {'─'*18} {'─'*28} {'─'*45}")
    for i, (npf, ip, friendly) in enumerate(CaptureEngine.list_interfaces()):
        active = " ← ACTIVE" if ip not in ("0.0.0.0","127.0.0.1","unknown","","") else ""
        click.echo(f"  {i:<4} {ip:<18} {friendly[:26]:<28} {npf}{active}")
    click.echo()


@cli.command("test-email")
@click.option("--email-to",  "-e", required=True, help="Recipient address")
@click.option("--email-pass",      default="", envvar="IDS_EMAIL_PASS", help="SMTP password")
def test_email_cmd(email_to, email_pass):
    """Send a test alert email to verify SMTP configuration."""
    alerter = EmailAlerter(recipient=email_to, password=email_pass)
    click.echo(f"Sending test email to {email_to} ...")
    ok = alerter.send_test()
    if ok:
        click.echo("[OK] Test email sent successfully.")
    else:
        click.echo("[FAIL] Email failed. Check password and SMTP settings.")


@cli.command("report")
@click.option("--hours",  default=24,    show_default=True, help="Hours of history to export")
@click.option("--out",    default="",    help="Output CSV path (default: ids_report_<ts>.csv)")
@click.option("--db",     default="db/ids_classic_events.db", show_default=True)
@click.option("--stats",  is_flag=True,  help="Print summary statistics")
def report_cmd(hours, out, db, stats):
    """Export event log to CSV and/or print statistics."""
    event_db = EventDB(db)
    if stats:
        s = event_db.get_stats()
        click.echo(f"\nTotal events : {s['total']}")
        click.echo(f"Alerts sent  : {s['alerted']}")
        click.echo(f"\nTop attack types:")
        for att, cnt in s["by_attack"]:
            click.echo(f"  {att:<35} {cnt}")
        click.echo(f"\nTop source IPs:")
        for ip, cnt in s["by_src"]:
            click.echo(f"  {ip:<20} {cnt}")
        click.echo()
    out_path = out or f"ids_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    n = event_db.export_csv(out_path, hours)
    click.echo(f"Exported {n} events → {out_path}")


def _print_summary(db: EventDB, alerter: EmailAlerter):
    s = db.get_stats()
    click.echo(f"\n{'='*50}")
    click.echo(f"  Session Summary")
    click.echo(f"{'='*50}")
    click.echo(f"  Flows processed : {dash.flows_processed:,}")
    click.echo(f"  Threats detected: {dash.threats_detected:,}")
    click.echo(f"  Emails sent     : {alerter.sent_count}")
    click.echo(f"  Alerts suppressed: {alerter.suppressed_count}")
    click.echo(f"  Total in DB     : {s['total']}")
    click.echo()


if __name__ == "__main__":
    cli()

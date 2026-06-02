"""
core/dashboard.py
─────────────────
Rich terminal dashboard used by both IDS apps.
Renders live statistics, recent alerts, and system status.
"""

import time
from collections import deque
from datetime import datetime
from typing import List, Dict, Optional

try:
    from rich.layout import Layout
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich.console import Console
    from rich import box
    RICH_OK = True
except ImportError:
    RICH_OK = False


console = Console() if RICH_OK else None

# ── Alert log (shared, thread-safe via GIL on append) ────────────────────────
recent_alerts: deque = deque(maxlen=80)
flows_processed:   int = 0
threats_detected:  int = 0
packets_seen:      int = 0
start_time:        float = time.time()


def push_alert(alert: dict):
    recent_alerts.appendleft(alert)
    global threats_detected
    threats_detected += 1


def inc_flow():
    global flows_processed
    flows_processed += 1


def inc_packets(n: int = 1):
    global packets_seen
    packets_seen += n


def build_layout(
    app_name:     str,
    mode:         str,
    interface:    str,
    local_ip:     str,
    email_to:     str,
    extra_status: str = "",
) -> "Layout":
    if not RICH_OK:
        raise RuntimeError("rich not installed")

    elapsed  = time.time() - start_time
    uptime   = time.strftime("%H:%M:%S", time.gmtime(elapsed))
    fpm      = flows_processed / max(elapsed / 60, 1)

    # ── Header ────────────────────────────────────────────────────────────────
    header_txt = (
        f"[bold bright_white]{app_name}[/]  │  "
        f"Mode: [bright_cyan]{mode}[/]  │  "
        f"Interface: [bright_yellow]{interface}[/]  │  "
        f"IP: [bright_yellow]{local_ip}[/]  │  "
        f"Alert → [bright_blue]{email_to}[/]  │  "
        f"Uptime: [bright_green]{uptime}[/]"
    )
    if extra_status:
        header_txt += f"  │  {extra_status}"

    # ── Stats bar ─────────────────────────────────────────────────────────────
    st = Table(box=box.SIMPLE, show_header=False, padding=(0, 3))
    for _ in range(5):
        st.add_column(justify="center")
    st.add_row(
        f"[white]Packets\n[bold]{packets_seen:,}[/][/]",
        f"[bright_cyan]Flows\n[bold]{flows_processed:,}[/][/]",
        f"[bright_red]Threats\n[bold]{threats_detected:,}[/][/]",
        f"[bright_yellow]Flows/min\n[bold]{fpm:.1f}[/][/]",
        f"[bright_green]Alerts sent\n[bold]{sum(1 for a in recent_alerts if a.get('alerted'))}[/][/]",
    )

    # ── Alert table ───────────────────────────────────────────────────────────
    at = Table(
        title=f"[bold]Recent Detections[/] [dim]({len(recent_alerts)} total)[/]",
        box=box.SIMPLE_HEAD, show_lines=False, padding=(0, 1),
    )
    at.add_column("Time",        width=12)
    at.add_column("Source IP",   width=17)
    at.add_column("Dest IP",     width=17)
    at.add_column("Attack",      width=22)
    at.add_column("Confidence",  width=11, justify="right")
    at.add_column("Model",       width=12)
    at.add_column("✉",           width=3,  justify="center")

    for a in list(recent_alerts)[:25]:
        conf_str = f"{a.get('confidence',0)*100:.1f}%" if a.get('confidence') is not None else "—"
        mail_str = "[bright_green]✓[/]" if a.get("alerted") else "[dim]—[/]"
        at.add_row(
            a.get("time", ""),
            f"[bright_red]{a.get('src_ip','')}[/]",
            a.get("dst_ip", ""),
            f"[bright_yellow]{a.get('attack_type','')}[/]",
            conf_str,
            f"[dim]{a.get('model','')}[/]",
            mail_str,
        )

    # ── Assemble ──────────────────────────────────────────────────────────────
    layout = Layout()
    layout.split_column(
        Layout(Panel(header_txt, box=box.ROUNDED, style="bold"), size=3),
        Layout(Panel(st, box=box.ROUNDED, title="Statistics"), size=5),
        Layout(Panel(at, box=box.ROUNDED), name="alerts"),
        Layout(
            Text("[dim]Ctrl+C to stop  │  All times local  │  "
                 "Duplicate alerts suppressed for 5 minutes per source IP[/]",
                 justify="center"),
            size=1
        ),
    )
    return layout


def print_simple_alert(alert: dict):
    """Fallback console print when Rich live display is not active."""
    ts  = alert.get("time", datetime.now().strftime("%H:%M:%S"))
    src = alert.get("src_ip", "?")
    att = alert.get("attack_type", "UNKNOWN")
    con = alert.get("confidence")
    con_str = f" [{con*100:.1f}%]" if con is not None else ""
    mod = alert.get("model", "")
    print(f"[{ts}] ⚠  {att}{con_str} from {src}  model={mod}")

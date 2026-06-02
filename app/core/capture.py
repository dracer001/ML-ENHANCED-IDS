"""
core/capture.py
───────────────
Shared packet capture and flow aggregation engine.
Used by both ids_classic.py and ids_ai.py.

Supports:
  - Live capture on a named interface (v1 host / v2 network-wide with promisc)
  - Offline replay of a saved .pcap file
  - Configurable flow window (default 5 seconds)
  - Emits completed FlowRecord objects to a queue for downstream processing
"""

import time
import threading
import ipaddress
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional
import queue
import logging

log = logging.getLogger("ids.capture")

# ── Try importing Scapy quietly ───────────────────────────────────────────────
import logging as _log
_log.getLogger("scapy.runtime").setLevel(_log.ERROR)

try:
    from scapy.all import (
        sniff, rdpcap, get_if_list, get_if_addr, conf,
        IP, IPv6, TCP, UDP, ICMP, ARP, DNS, DNSQR, Ether,
    )
    SCAPY_OK = True
except ImportError as e:
    SCAPY_OK = False
    print(f"[ERROR] Scapy import failed: {e}")
    print("  Run: pip install scapy")
    print("  Also ensure Npcap is installed from npcap.com")

    # Define stubs so the rest of the module doesn't NameError
    def get_if_list(): return []
    def get_if_addr(iface): return "0.0.0.0"
    class conf:
        ifaces = {}


# ── Flow record ───────────────────────────────────────────────────────────────

@dataclass
class FlowRecord:
    """One completed network flow — 5-tuple key + computed statistics."""

    src_ip:   str
    dst_ip:   str
    src_port: int
    dst_port: int
    protocol: str  # TCP / UDP / ICMP / ARP / OTHER

    src_mac:  str = ""
    dst_mac:  str = ""

    # Packet-level accumulators
    packets:      int = 0
    bytes_total:  int = 0
    start_time:   float = field(default_factory=time.time)
    last_seen:    float = field(default_factory=time.time)

    # Per-direction
    fwd_pkts:   int = 0
    bwd_pkts:   int = 0
    fwd_bytes:  int = 0
    bwd_bytes:  int = 0

    # TCP flags
    syn_count:  int = 0
    ack_count:  int = 0
    fin_count:  int = 0
    rst_count:  int = 0
    psh_count:  int = 0
    urg_count:  int = 0

    # Packet length stats
    pkt_lengths: list = field(default_factory=list)

    # IAT stats (inter-arrival times in seconds)
    iat_list:    list = field(default_factory=list)
    last_pkt_ts: float = 0.0

    # DNS hostname (if captured)
    dns_query:   str = ""

    # ARP operation
    arp_op:      str = ""

    @property
    def duration(self) -> float:
        return max(self.last_seen - self.start_time, 1e-6)

    @property
    def pkt_per_sec(self) -> float:
        return self.packets / self.duration

    @property
    def bytes_per_sec(self) -> float:
        return self.bytes_total / self.duration

    @property
    def avg_pkt_len(self) -> float:
        return sum(self.pkt_lengths) / len(self.pkt_lengths) if self.pkt_lengths else 0

    @property
    def std_pkt_len(self) -> float:
        if len(self.pkt_lengths) < 2:
            return 0.0
        mean = self.avg_pkt_len
        return (sum((x - mean)**2 for x in self.pkt_lengths) / len(self.pkt_lengths)) ** 0.5

    @property
    def syn_ratio(self) -> float:
        return self.syn_count / max(self.packets, 1)

    @property
    def ack_ratio(self) -> float:
        return self.ack_count / max(self.packets, 1)

    @property
    def fwd_bwd_ratio(self) -> float:
        return self.fwd_pkts / max(self.bwd_pkts, 1)

    def to_feature_vector(self, n_features: int = 77):
        """
        Produce a numpy-compatible feature vector matching CICIDS2017 feature ordering.
        Returns a list of floats padded/truncated to n_features.
        """
        feats = [
            self.duration * 1_000_000,        # Flow Duration (microseconds)
            self.fwd_pkts,                     # Total Fwd Packets
            self.bwd_pkts,                     # Total Backward Packets
            self.fwd_bytes,                    # Total Length of Fwd Packets
            self.bwd_bytes,                    # Total Length of Bwd Packets
            self.fwd_bytes / max(self.fwd_pkts, 1),   # Fwd Packet Length Max (approx)
            self.fwd_bytes / max(self.fwd_pkts, 1),   # Fwd Packet Length Min (approx)
            self.fwd_bytes / max(self.fwd_pkts, 1),   # Fwd Packet Length Mean
            0.0,                               # Fwd Packet Length Std
            self.bwd_bytes / max(self.bwd_pkts, 1),   # Bwd Packet Length Max (approx)
            self.bwd_bytes / max(self.bwd_pkts, 1),   # Bwd Packet Length Min (approx)
            self.bwd_bytes / max(self.bwd_pkts, 1),   # Bwd Packet Length Mean
            0.0,                               # Bwd Packet Length Std
            self.bytes_per_sec,                # Flow Bytes/s
            self.pkt_per_sec,                  # Flow Packets/s
            float(sum(self.iat_list)) / max(len(self.iat_list), 1),   # Flow IAT Mean
            self.std_pkt_len,                  # Flow IAT Std
            max(self.iat_list, default=0),     # Flow IAT Max
            min(self.iat_list, default=0),     # Flow IAT Min
            float(sum(self.iat_list[:len(self.iat_list)//2 or 1])) / max(len(self.iat_list)//2, 1),  # Fwd IAT Mean
            0.0, 0.0, 0.0, 0.0,               # Fwd IAT std/max/min/total placeholders
            0.0, 0.0, 0.0, 0.0, 0.0,          # Bwd IAT placeholders
            self.syn_count,                    # Fwd PSH Flags (approx)
            self.psh_count,                    # Bwd PSH Flags
            self.urg_count,                    # Fwd URG Flags
            0.0,                               # Bwd URG Flags
            0.0,                               # Fwd Header Length
            0.0,                               # Bwd Header Length
            self.fwd_pkts / max(self.duration, 1e-6),   # Fwd Packets/s
            self.bwd_pkts / max(self.duration, 1e-6),   # Bwd Packets/s
            self.avg_pkt_len,                  # Packet Length Min
            self.avg_pkt_len,                  # Packet Length Max
            self.avg_pkt_len,                  # Packet Length Mean
            self.std_pkt_len,                  # Packet Length Std
            self.avg_pkt_len * self.packets,   # Packet Length Variance
            self.fin_count,                    # FIN Flag Count
            self.syn_count,                    # SYN Flag Count
            self.rst_count,                    # RST Flag Count
            self.psh_count,                    # PSH Flag Count
            self.ack_count,                    # ACK Flag Count
            self.urg_count,                    # URG Flag Count
            0.0, 0.0,                          # CWE/ECE Flag Count
            self.fwd_bwd_ratio,                # Down/Up Ratio
            self.avg_pkt_len,                  # Average Packet Size
            self.fwd_bytes / max(self.fwd_pkts, 1),   # Avg Fwd Segment Size
            self.bwd_bytes / max(self.bwd_pkts, 1),   # Avg Bwd Segment Size
            0.0,                               # Fwd Header Length.1
            0.0, 0.0,                          # Fwd/Bwd Avg Bulk Rate
            0.0, 0.0,                          # Subflow Fwd/Bwd Packets
            0.0, 0.0,                          # Subflow Fwd/Bwd Bytes
            0.0, 0.0,                          # Init Win bytes fwd/bwd
            0.0,                               # act_data_pkt_fwd
            0.0,                               # min_seg_size_forward
            float(sum(self.iat_list)) / max(len(self.iat_list), 1),  # Active Mean
            0.0, 0.0, 0.0,                     # Active Std/Max/Min
            float(sum(self.iat_list)) / max(len(self.iat_list), 1),  # Idle Mean
            0.0, 0.0, 0.0,                     # Idle Std/Max/Min
        ]
        # Pad or truncate to exactly n_features
        if len(feats) < n_features:
            feats += [0.0] * (n_features - len(feats))
        return feats[:n_features]

    def summary(self) -> str:
        return (
            f"{self.src_ip}:{self.src_port} → {self.dst_ip}:{self.dst_port} "
            f"[{self.protocol}] {self.packets}pkts {self.bytes_total}B "
            f"{self.duration:.2f}s"
        )


# ── Flow aggregator ───────────────────────────────────────────────────────────

class FlowAggregator:
    """
    Maintains a table of active flows keyed by 5-tuple.
    Expires flows older than window_seconds and pushes them to out_queue.
    """

    def __init__(self, out_queue: queue.Queue, window_seconds: float = 5.0, local_ip: str = ""):
        self.flows: dict = {}
        self.out_queue = out_queue
        self.window = window_seconds
        self.local_ip = local_ip
        self._lock = threading.Lock()

    def _flow_key(self, pkt) -> Optional[tuple]:
        """Return 5-tuple key for a packet, or None if not IP/ARP."""
        if pkt.haslayer(ARP):
            return (pkt[ARP].psrc, pkt[ARP].pdst, 0, 0, "ARP")
        if not pkt.haslayer(IP):
            return None
        ip = pkt[IP]
        if pkt.haslayer(TCP):
            return (ip.src, ip.dst, pkt[TCP].sport, pkt[TCP].dport, "TCP")
        if pkt.haslayer(UDP):
            return (ip.src, ip.dst, pkt[UDP].sport, pkt[UDP].dport, "UDP")
        if pkt.haslayer(ICMP):
            return (ip.src, ip.dst, 0, 0, "ICMP")
        return (ip.src, ip.dst, 0, 0, "OTHER")

    def process(self, pkt):
        """Add packet to the appropriate flow, expire stale flows."""
        now = time.time()
        key = self._flow_key(pkt)
        if key is None:
            return

        src_ip, dst_ip, sport, dport, proto = key
        pkt_len = len(pkt)
        src_mac = pkt[Ether].src if pkt.haslayer(Ether) else ""
        dst_mac = pkt[Ether].dst if pkt.haslayer(Ether) else ""

        with self._lock:
            if key not in self.flows:
                self.flows[key] = FlowRecord(
                    src_ip=src_ip, dst_ip=dst_ip,
                    src_port=sport, dst_port=dport,
                    protocol=proto,
                    src_mac=src_mac, dst_mac=dst_mac,
                    start_time=now, last_pkt_ts=now,
                )
            fr = self.flows[key]
            fr.packets     += 1
            fr.bytes_total += pkt_len
            fr.last_seen    = now

            # IAT
            if fr.last_pkt_ts > 0:
                fr.iat_list.append(now - fr.last_pkt_ts)
            fr.last_pkt_ts = now

            # Direction
            if src_ip == self.local_ip:
                fr.fwd_pkts  += 1
                fr.fwd_bytes += pkt_len
            else:
                fr.bwd_pkts  += 1
                fr.bwd_bytes += pkt_len

            # Packet length
            fr.pkt_lengths.append(pkt_len)

            # TCP flags
            if pkt.haslayer(TCP):
                flags = int(pkt[TCP].flags)
                if flags & 0x02: fr.syn_count += 1
                if flags & 0x10: fr.ack_count += 1
                if flags & 0x01: fr.fin_count += 1
                if flags & 0x04: fr.rst_count += 1
                if flags & 0x08: fr.psh_count += 1
                if flags & 0x20: fr.urg_count += 1

            # DNS query
            if pkt.haslayer(DNS) and pkt.haslayer(DNSQR) and fr.dns_query == "":
                try:
                    fr.dns_query = pkt[DNSQR].qname.decode(errors="replace").rstrip(".")
                except Exception:
                    pass

            # ARP op
            if pkt.haslayer(ARP):
                fr.arp_op = "WHO-HAS" if pkt[ARP].op == 1 else "IS-AT"

            # Expire stale flows
            expired = [k for k, v in self.flows.items() if now - v.last_seen >= self.window]
            for k in expired:
                self.out_queue.put(self.flows.pop(k))

    def flush_all(self):
        """Force-emit all remaining flows (called on shutdown)."""
        with self._lock:
            for fr in self.flows.values():
                self.out_queue.put(fr)
            self.flows.clear()


# ── Capture runner ────────────────────────────────────────────────────────────

class CaptureEngine:
    """
    Runs either live capture or PCAP replay.
    Feeds packets to a FlowAggregator and emits FlowRecords via out_queue.
    """

    def __init__(
        self,
        out_queue:      queue.Queue,
        interface:      str = "",
        pcap_file:      str = "",
        promiscuous:    bool = False,
        bpf_filter:     str = "",
        window_seconds: float = 5.0,
        local_ip:       str = "",
        stop_event:     Optional[threading.Event] = None,
    ):
        if not SCAPY_OK:
            raise RuntimeError("Scapy not installed. Run: pip install scapy")

        self.interface   = interface
        self.pcap_file   = pcap_file
        self.promiscuous = promiscuous
        self.bpf_filter  = bpf_filter
        self.local_ip    = local_ip
        self.stop_event  = stop_event or threading.Event()

        self.aggregator  = FlowAggregator(out_queue, window_seconds, local_ip)
        self._thread: Optional[threading.Thread] = None

    def _pkt_callback(self, pkt):
        if self.stop_event.is_set():
            return True
        self.aggregator.process(pkt)

    def start_live(self):
        """Start live capture in a background thread."""
        def _run():
            log.info(f"Live capture started on {self.interface} "
                     f"(promisc={self.promiscuous})")
            sniff(
                iface=self.interface,
                prn=self._pkt_callback,
                filter=self.bpf_filter or None,
                store=False,
                promisc=self.promiscuous,
                stop_filter=lambda _: self.stop_event.is_set(),
            )
            self.aggregator.flush_all()
            log.info("Live capture stopped.")

        self._thread = threading.Thread(target=_run, daemon=True, name="capture")
        self._thread.start()

    def replay_pcap(self):
        """Replay a saved PCAP file synchronously (blocking)."""
        if not self.pcap_file:
            raise ValueError("No PCAP file specified")
        log.info(f"Replaying PCAP: {self.pcap_file}")
        pkts = rdpcap(self.pcap_file)
        log.info(f"Loaded {len(pkts)} packets")
        for pkt in pkts:
            if self.stop_event.is_set():
                break
            self._pkt_callback(pkt)
        self.aggregator.flush_all()
        log.info("PCAP replay complete.")

    def stop(self):
        self.stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)

    @staticmethod
    def list_interfaces() -> list:
        """Return list of (npf_name, local_ip, friendly_name) tuples."""
        result = []
        for iface in get_if_list():
            try:
                ip = get_if_addr(iface)
            except Exception:
                ip = "0.0.0.0"
            friendly = ""
            try:
                friendly = getattr(conf.ifaces.get(iface), "description", "") or \
                           getattr(conf.ifaces.get(iface), "name", "") or ""
            except Exception:
                pass
            result.append((iface, ip, friendly))
        return result

    @staticmethod
    def get_active_interface() -> tuple:
        """Return (npf_name, local_ip) for the first interface with a real IP."""
        for iface, ip, _ in CaptureEngine.list_interfaces():
            if ip and ip not in ("0.0.0.0", "127.0.0.1", "unknown", ""):
                return iface, ip
        return "", ""

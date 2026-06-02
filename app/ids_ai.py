#!/usr/bin/env python3
"""
ids_ai.py
─────────
AI-Enhanced Intrusion Detection System.
Uses trained ML/DL models to classify network flows.

MODELS AVAILABLE
─────────────────
  xgboost     XGBoost (default) — 99.88% acc, lowest FPR, fastest inference
  rf          Random Forest    — 99.26% acc, very reliable
  cnn         1D CNN           — best cross-dataset generalisation (64.6% UNSW)
  lstm        LSTM             — good temporal pattern detection
  all         Run ALL 4 models — email reports which model(s) caught the threat

USAGE
─────
  # List interfaces
  python ids_ai.py --list

  # Host-only (v1) with default model (xgboost)
  python ids_ai.py start --iface "\\Device\\NPF_{...}" --email-to admin@example.com

  # Network-wide promiscuous (v2)
  python ids_ai.py start --iface "\\Device\\NPF_{...}" --network

  # Choose a specific model
  python ids_ai.py start --iface "\\Device\\NPF_{...}" --model lstm

  # Use ALL models — email shows which caught the intrusion
  python ids_ai.py start --iface "\\Device\\NPF_{...}" --model all

  # Replay a saved PCAP
  python ids_ai.py start --pcap captures/attack.pcap --model all

  # Test email
  python ids_ai.py test-email --email-to admin@example.com

  # Export report
  python ids_ai.py report --hours 24 --stats
"""

import os
import sys
import time
import queue
import threading
import logging
import json
from datetime import datetime
from typing import Optional, Dict, List

import click
import numpy as np

import logging as _lg
_lg.getLogger("scapy.runtime").setLevel(_lg.ERROR)

sys.path.insert(0, os.path.dirname(__file__))
from core.capture   import CaptureEngine, FlowRecord
from core.alerter   import EmailAlerter, DEFAULT_SENDER, DEFAULT_SMTP_HOST, DEFAULT_SMTP_PORT, DEFAULT_RECIPIENT, DEFAULT_PASSWORD
from core.database  import EventDB
import core.dashboard as dash

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("ids.ai")

# ── Default paths ──────────────────────────────────────────────────────────────
DEFAULT_MODELS_DIR = os.path.join(os.path.dirname(__file__),"..\\", "models")
DEFAULT_THRESHOLD  = 0.70   # minimum confidence to flag as threat

# ── Class names (from label_encoder_remap) ────────────────────────────────────
# These match the 13 classes after dropping Heartbleed + SQL Injection
ATTACK_CLASSES = [
    "BENIGN",
    "Bot",
    "DDoS",
    "DoS GoldenEye",
    "DoS Hulk",
    "DoS Slowhttptest",
    "DoS Slowloris",
    "FTP-Patator",
    "Infiltration",
    "PortScan",
    "SSH-Patator",
    "Web Attack Brute Force",
    "Web Attack XSS",
]


# ── Model loader ──────────────────────────────────────────────────────────────

class ModelRegistry:
    """
    Loads and caches trained models and the scaler.
    Supports: xgboost, rf, cnn, lstm
    """

    def __init__(self, models_dir: str = DEFAULT_MODELS_DIR):
        self.models_dir = models_dir
        self._models: Dict[str, object] = {}
        self._scaler = None
        self._le_remap = None
        self._n_features = 77
        self._lock = threading.Lock()

    def _load_scaler(self):
        if self._scaler is not None:
            return
        import joblib
        path = os.path.join(self.models_dir, "scaler.pkl")
        if not os.path.exists(path):
            raise FileNotFoundError(
                f"scaler.pkl not found in {self.models_dir}.\n"
                f"Run the training notebook first to generate model files."
            )
        self._scaler = joblib.load(path)
        log.info(f"Scaler loaded from {path}")

        # Load label encoder if available
        le_path = os.path.join(self.models_dir, "label_encoder_remap.pkl")
        if os.path.exists(le_path):
            self._le_remap = joblib.load(le_path)
            log.info("Label encoder loaded")

    def load(self, name: str):
        """Load a model by name. Returns the loaded model object."""
        with self._lock:
            if name in self._models:
                return self._models[name]

            self._load_scaler()

            model_files = {
                "xgboost": ["xgb_model.pkl"],
                "rf":      ["rf_model.pkl"],
                "cnn":     ["cnn_model.keras", "cnn_model.h5"],
                "lstm":    ["lstm_model.keras", "lstm_model.h5"],
            }

            if name not in model_files:
                raise ValueError(f"Unknown model '{name}'. Choose: xgboost, rf, cnn, lstm")

            loaded = None
            for filename in model_files[name]:
                path = os.path.join(self.models_dir, filename)
                if os.path.exists(path):
                    if filename.endswith(".pkl"):
                        import joblib
                        loaded = joblib.load(path)
                    else:
                        import tensorflow as tf
                        loaded = tf.keras.models.load_model(path)
                    log.info(f"Model '{name}' loaded from {path}")
                    break

            if loaded is None:
                raise FileNotFoundError(
                    f"No model file found for '{name}' in {self.models_dir}.\n"
                    f"Expected one of: {model_files[name]}"
                )

            self._models[name] = loaded
            return loaded

    def load_all(self, names: List[str]) -> Dict[str, object]:
        """Load multiple models. Returns {name: model}."""
        result = {}
        for name in names:
            try:
                result[name] = self.load(name)
            except Exception as e:
                log.warning(f"Could not load model '{name}': {e}")
        return result

    def preprocess(self, fr: FlowRecord) -> Optional[np.ndarray]:
        """Convert a FlowRecord to a scaled numpy feature vector."""
        self._load_scaler()
        feats = fr.to_feature_vector(self._n_features)
        arr   = np.array(feats, dtype=np.float32).reshape(1, -1)
        arr   = np.nan_to_num(arr, nan=0.0, posinf=0.0, neginf=0.0)
        return self._scaler.transform(arr)

    def class_name(self, idx: int) -> str:
        """Return human-readable class name for a label index."""
        if self._le_remap is not None:
            try:
                orig_idx = self._le_remap.classes_[idx]
                return ATTACK_CLASSES[orig_idx] if orig_idx < len(ATTACK_CLASSES) else str(idx)
            except Exception:
                pass
        return ATTACK_CLASSES[idx] if idx < len(ATTACK_CLASSES) else f"Class-{idx}"

    @property
    def n_features(self) -> int:
        return self._n_features


# ── Inference ─────────────────────────────────────────────────────────────────

TIMESTEPS = 10   # must match training

class Inferencer:
    """
    Runs inference on a scaled feature vector using one or more models.
    Returns { model_name: (predicted_class_idx, confidence, class_name) }
    """

    def __init__(self, registry: ModelRegistry, threshold: float = DEFAULT_THRESHOLD):
        self.registry  = registry
        self.threshold = threshold
        self._lstm_buffer: List[np.ndarray] = []   # rolling window for LSTM

    def _predict_sklearn(self, model, X: np.ndarray):
        probs = model.predict_proba(X)[0]
        idx   = int(np.argmax(probs))
        return idx, float(probs[idx])

    def _predict_keras(self, model, X: np.ndarray, is_lstm: bool = False):
        if is_lstm:
            self._lstm_buffer.append(X[0])
            if len(self._lstm_buffer) > TIMESTEPS:
                self._lstm_buffer.pop(0)
            if len(self._lstm_buffer) < TIMESTEPS:
                return 0, 0.0  # not enough history yet
            seq   = np.array(self._lstm_buffer, dtype=np.float32).reshape(1, TIMESTEPS, -1)
            probs = model.predict(seq, verbose=0)[0]
        else:
            X_cnn = X.reshape(1, self.registry.n_features, 1)
            probs = model.predict(X_cnn, verbose=0)[0]
        idx = int(np.argmax(probs))
        return idx, float(probs[idx])

    def run(self, model_name: str, model, X: np.ndarray):
        """Run inference for a single model. Returns (class_idx, confidence)."""
        is_keras = hasattr(model, "predict") and not hasattr(model, "predict_proba")
        is_lstm  = model_name == "lstm"
        try:
            if is_keras:
                return self._predict_keras(model, X, is_lstm)
            else:
                return self._predict_sklearn(model, X)
        except Exception as e:
            log.debug(f"Inference error ({model_name}): {e}")
            return 0, 0.0

    def run_all(self, models: Dict[str, object], X: np.ndarray) -> Dict:
        """Run all loaded models and return results dict."""
        results = {}
        for name, model in models.items():
            idx, conf = self.run(name, model, X)
            results[name] = {
                "class_idx":  idx,
                "confidence": conf,
                "class_name": self.registry.class_name(idx),
                "is_threat":  idx != 0 and conf >= self.threshold,
            }
        return results


# ── Detection processor ───────────────────────────────────────────────────────

def run_detection(
    flow_queue:  queue.Queue,
    alerter:     EmailAlerter,
    db:          EventDB,
    stop_event:  threading.Event,
    registry:    ModelRegistry,
    models:      Dict[str, object],
    threshold:   float,
    mode_label:  str,
    use_all:     bool,
):
    inferencer = Inferencer(registry, threshold)

    while not stop_event.is_set() or not flow_queue.empty():
        try:
            fr: FlowRecord = flow_queue.get(timeout=1.0)
        except queue.Empty:
            continue

        dash.inc_flow()

        # Preprocess
        try:
            X = registry.preprocess(fr)
        except Exception as e:
            log.debug(f"Preprocess failed: {e}")
            continue

        # Inference
        if use_all:
            results = inferencer.run_all(models, X)
            catching_models = {n: r for n, r in results.items() if r["is_threat"]}

            if not catching_models:
                continue

            # Determine the most confident detection
            best_model = max(catching_models, key=lambda n: catching_models[n]["confidence"])
            best       = catching_models[best_model]
            attack_type = best["class_name"]
            confidence  = best["confidence"]

            model_agreement = ", ".join(
                f"{n}({r['class_name']} {r['confidence']*100:.0f}%)"
                for n, r in catching_models.items()
            )
            all_results_str = " | ".join(
                f"{n}:{r['class_name']}({r['confidence']*100:.0f}%)"
                for n, r in results.items()
            )

            details = {
                "Protocol":      fr.protocol,
                "Src Port":      str(fr.src_port),
                "Dst Port":      str(fr.dst_port),
                "Packets":       str(fr.packets),
                "Bytes":         str(fr.bytes_total),
                "Duration":      f"{fr.duration:.2f}s",
                "Pkt/s":         f"{fr.pkt_per_sec:.1f}",
                "SYN count":     str(fr.syn_count),
                "Models caught": model_agreement,
                "All results":   all_results_str,
            }

            model_used = f"all({'+'.join(catching_models.keys())})"

        else:
            # Single model
            single_name   = list(models.keys())[0]
            single_model  = models[single_name]
            idx, conf     = inferencer.run(single_name, single_model, X)
            class_name    = registry.class_name(idx)

            if idx == 0 or conf < threshold:
                continue

            attack_type = class_name
            confidence  = conf
            model_used  = single_name
            details = {
                "Protocol":   fr.protocol,
                "Src Port":   str(fr.src_port),
                "Dst Port":   str(fr.dst_port),
                "Packets":    str(fr.packets),
                "Bytes":      str(fr.bytes_total),
                "Duration":   f"{fr.duration:.2f}s",
                "Pkt/s":      f"{fr.pkt_per_sec:.1f}",
                "SYN count":  str(fr.syn_count),
                "Confidence": f"{conf*100:.2f}%",
            }

        # Alert
        ts     = datetime.now().strftime("%H:%M:%S")
        alert  = {
            "time":        ts,
            "src_ip":      fr.src_ip,
            "dst_ip":      fr.dst_ip,
            "attack_type": attack_type,
            "confidence":  confidence,
            "model":       model_used,
            "alerted":     False,
        }

        alerted = alerter.send_alert(
            src_ip=fr.src_ip,
            dst_ip=fr.dst_ip,
            attack_type=attack_type,
            confidence=confidence,
            details=details,
            app_mode=f"AI-IDS ({mode_label}) [{model_used}]",
        )
        alert["alerted"] = alerted
        dash.push_alert(alert)
        dash.print_simple_alert(alert)

        db.log_event(
            src_ip=fr.src_ip, dst_ip=fr.dst_ip,
            attack_type=attack_type, confidence=confidence,
            model_used=model_used,
            src_port=fr.src_port, dst_port=fr.dst_port,
            protocol=fr.protocol, packets=fr.packets,
            bytes_total=fr.bytes_total, duration=fr.duration,
            alerted=alerted, app_mode=f"AI-IDS ({mode_label})",
            notes=json.dumps(details),
        )


# ── CLI ────────────────────────────────────────────────────────────────────────

@click.group()
def cli():
    """
    AI-IDS — Machine Learning Enhanced Intrusion Detection System

    \b
    Models: xgboost (default) | rf | cnn | lstm | all
    Modes:  v1-host (default) | --network (v2 promiscuous)
    Source: live interface    | --pcap <file>
    """
    pass


@cli.command("start")
@click.option("--iface",       "-i", default="",     help="Network interface NPF name")
@click.option("--network",     "-n", is_flag=True,   help="v2: promiscuous / network-wide mode")
@click.option("--pcap",        "-p", default="",     help="Replay a saved .pcap file")
@click.option("--model",       "-m", default="xgboost",
              type=click.Choice(["xgboost","rf","cnn","lstm","all"], case_sensitive=False),
              show_default=True, help="Model to use for detection")
@click.option("--threshold",   "-t", default=DEFAULT_THRESHOLD, show_default=True,
              help="Minimum confidence to flag a flow as threat (0.0–1.0)")
@click.option("--email-to",    "-e", default=DEFAULT_RECIPIENT, show_default=True,
              help="Alert recipient email")
@click.option("--email-pass",        default=DEFAULT_PASSWORD, envvar="IDS_EMAIL_PASS",
              help="SMTP password (or IDS_EMAIL_PASS env var)")
@click.option("--suppress",          default=5, show_default=True,
              help="Suppress duplicate alerts per IP for N minutes")
@click.option("--window",            default=5.0, show_default=True,
              help="Flow aggregation window in seconds")
@click.option("--models-dir",        default=DEFAULT_MODELS_DIR, show_default=True,
              help="Directory containing trained model files")
@click.option("--dry-run",           is_flag=True, help="Log alerts but don't send email")
@click.option("--no-dashboard",      is_flag=True, help="Plain log output only")
@click.option("--db",                default="db/ids_ai_events.db", show_default=True,
              help="SQLite event database path")
def start_cmd(iface, network, pcap, model, threshold, email_to, email_pass,
              suppress, window, models_dir, dry_run, no_dashboard, db):
    """Start the AI-Enhanced IDS."""

    # Auto-pick interface
    if not iface and not pcap:
        iface, local_ip = CaptureEngine.get_active_interface()
        if not iface:
            click.echo("[ERROR] No active interface. Use --list to see options.")
            sys.exit(1)
    elif iface:
        try:
            from scapy.all import get_if_addr
            local_ip = get_if_addr(iface)
        except Exception:
            local_ip = ""
    else:
        local_ip = "127.0.0.1"

    use_all    = model.lower() == "all"
    mode_label = "v2-Network" if network else "v1-Host"
    smtp_pass  = email_pass or os.environ.get("IDS_EMAIL_PASS", "")
    model_names = ["xgboost","rf","cnn","lstm"] if use_all else [model.lower()]

    # Banner
    click.echo(f"\n{'='*60}")
    click.echo(f"  AI-IDS — Machine Learning Enhanced IDS")
    click.echo(f"{'='*60}")
    click.echo(f"  Mode       : {mode_label}")
    if pcap:
        click.echo(f"  Source     : PCAP replay — {pcap}")
    else:
        click.echo(f"  Interface  : {iface}")
        click.echo(f"  Local IP   : {local_ip}")
        click.echo(f"  Promiscuous: {'YES' if network else 'No'}")
    click.echo(f"  Model(s)   : {', '.join(model_names)}")
    click.echo(f"  Threshold  : {threshold*100:.0f}%")
    click.echo(f"  Alert →    : {email_to}")
    click.echo(f"  Models dir : {models_dir}")
    click.echo(f"  Dry run    : {'YES — no emails sent' if dry_run else 'No'}")
    click.echo(f"{'='*60}\n")

    if not smtp_pass and not dry_run:
        click.echo("[WARNING] No email password. Use --email-pass or IDS_EMAIL_PASS env var.")
        click.echo("          Use --dry-run to test without sending emails.\n")

    # Load models
    registry = ModelRegistry(models_dir)
    click.echo("Loading models ...")
    try:
        loaded_models = registry.load_all(model_names)
    except Exception as e:
        click.echo(f"[ERROR] Failed to load models: {e}")
        sys.exit(1)

    if not loaded_models:
        click.echo(f"[ERROR] No models loaded from {models_dir}")
        click.echo("Ensure model files exist: xgb_model.pkl, rf_model.pkl, "
                   "cnn_model.keras, lstm_model.keras")
        sys.exit(1)

    click.echo(f"Loaded: {', '.join(loaded_models.keys())}\n")

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

    # Detection thread
    det_thread = threading.Thread(
        target=run_detection,
        args=(flow_q, alerter, event_db, stop_event,
              registry, loaded_models, threshold, mode_label, use_all),
        daemon=True, name="ai-detector",
    )
    det_thread.start()

    # Capture engine
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
            time.sleep(window + 2)
            stop_event.set()
            det_thread.join(timeout=15)
            _print_summary(event_db, alerter, loaded_models)
        else:
            engine.start_live()
            click.echo("Capture running. Press Ctrl+C to stop.\n")
            extra = f"Model: [bright_magenta]{'+'.join(loaded_models.keys())}[/]  Threshold: {threshold*100:.0f}%"

            if not no_dashboard:
                try:
                    from rich.live import Live
                    with Live(
                        dash.build_layout("AI-IDS ML", mode_label, iface, local_ip, email_to, extra),
                        refresh_per_second=2, screen=True,
                    ) as live:
                        while not stop_event.is_set():
                            time.sleep(0.5)
                            live.update(
                                dash.build_layout("AI-IDS ML", mode_label, iface, local_ip, email_to, extra)
                            )
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
        _print_summary(event_db, alerter, loaded_models)


@cli.command("list")
def list_cmd():
    """List available network interfaces."""
    click.echo("\nAvailable interfaces:\n")
    click.echo(f"  {'#':<4} {'IP':<18} {'Friendly':<28} NPF Identifier")
    click.echo(f"  {'─'*4} {'─'*18} {'─'*28} {'─'*45}")
    for i, (npf, ip, friendly) in enumerate(CaptureEngine.list_interfaces()):
        active = " ← ACTIVE" if ip not in ("0.0.0.0","127.0.0.1","unknown","","") else ""
        click.echo(f"  {i:<4} {ip:<18} {friendly[:26]:<28} {npf}{active}")
    click.echo()


@cli.command("models")
@click.option("--models-dir", default=DEFAULT_MODELS_DIR, show_default=True)
def models_cmd(models_dir):
    """Show which model files are present."""
    click.echo(f"\nModel files in {models_dir}:\n")
    checks = {
        "xgboost": ["xgb_model.pkl"],
        "rf":      ["rf_model.pkl"],
        "cnn":     ["cnn_model.keras","cnn_model.h5"],
        "lstm":    ["lstm_model.keras","lstm_model.h5"],
        "scaler":  ["scaler.pkl"],
        "encoder": ["label_encoder_remap.pkl"],
    }
    for name, files in checks.items():
        found = next((f for f in files if os.path.exists(os.path.join(models_dir, f))), None)
        if found:
            size = os.path.getsize(os.path.join(models_dir, found)) / 1024
            click.echo(f"  [OK] {name:<12} {found}  ({size:.0f} KB)")
        else:
            click.echo(f"  [--] {name:<12} not found (expected: {files[0]})")
    click.echo()


@cli.command("test-email")
@click.option("--email-to",  "-e", required=True)
@click.option("--email-pass",      default="", envvar="IDS_EMAIL_PASS")
def test_email_cmd(email_to, email_pass):
    """Send a test alert email."""
    alerter = EmailAlerter(recipient=email_to, password=email_pass)
    click.echo(f"Sending test email to {email_to} ...")
    ok = alerter.send_test()
    click.echo("[OK] Sent." if ok else "[FAIL] Check password/SMTP settings.")


@cli.command("report")
@click.option("--hours",  default=24,               show_default=True)
@click.option("--out",    default="")
@click.option("--db",     default="db/ids_ai_events.db", show_default=True)
@click.option("--stats",  is_flag=True)
def report_cmd(hours, out, db, stats):
    """Export event log to CSV and/or print statistics."""
    event_db = EventDB(db)
    if stats:
        s = event_db.get_stats()
        click.echo(f"\nTotal events : {s['total']}")
        click.echo(f"Alerts sent  : {s['alerted']}")
        click.echo(f"\nTop attack types:")
        for att, cnt in s["by_attack"]:
            click.echo(f"  {att:<40} {cnt}")
        click.echo(f"\nTop source IPs:")
        for ip, cnt in s["by_src"]:
            click.echo(f"  {ip:<20} {cnt}")
    out_path = out or f"ids_ai_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    n = event_db.export_csv(out_path, hours)
    click.echo(f"\nExported {n} events → {out_path}")


def _print_summary(db: EventDB, alerter: EmailAlerter, models: dict):
    s = db.get_stats()
    click.echo(f"\n{'='*50}")
    click.echo(f"  Session Summary — AI-IDS")
    click.echo(f"{'='*50}")
    click.echo(f"  Models used      : {', '.join(models.keys())}")
    click.echo(f"  Flows processed  : {dash.flows_processed:,}")
    click.echo(f"  Threats detected : {dash.threats_detected:,}")
    click.echo(f"  Emails sent      : {alerter.sent_count}")
    click.echo(f"  Suppressed alerts: {alerter.suppressed_count}")
    click.echo(f"  Total in DB      : {s['total']}")
    if s["by_attack"]:
        click.echo(f"\n  Top detections:")
        for att, cnt in s["by_attack"][:5]:
            click.echo(f"    {att:<35} {cnt}x")
    click.echo()


if __name__ == "__main__":
    cli()

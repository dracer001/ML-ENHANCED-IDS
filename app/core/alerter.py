"""
core/alerter.py
───────────────
Email alerter with duplicate suppression.
Sends over SMTP with SSL (port 465 by default). Credentials come from
environment variables or CLI flags, never from this file.
"""

import os
import smtplib
import ssl
import threading
import time
import logging
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime
from typing import Optional

log = logging.getLogger("ids.alerter")

# ── SMTP settings ─────────────────────────────────────────────────────────────
# Nothing secret lives in this file. Set these as environment variables, or pass
# the matching command-line flags (--email-to, --email-pass):
#
#   IDS_EMAIL_PASS   SMTP password for the sender account   (required to send)
#   IDS_ALERT_TO     where alerts are delivered              (or use --email-to)
#   IDS_SENDER       sender address / SMTP login
#   IDS_SMTP_HOST    SMTP server (SSL)
#   IDS_SMTP_PORT    SMTP SSL port, default 465
DEFAULT_SMTP_HOST = os.environ.get("IDS_SMTP_HOST", "mail.example.com")
DEFAULT_SMTP_PORT = int(os.environ.get("IDS_SMTP_PORT", "465"))
DEFAULT_SENDER    = os.environ.get("IDS_SENDER", "ids@example.com")
DEFAULT_RECIPIENT = os.environ.get("IDS_ALERT_TO", "")
DEFAULT_PASSWORD  = os.environ.get("IDS_EMAIL_PASS", "")


class EmailAlerter:
    """
    Thread-safe email alerter.
    Suppresses duplicate alerts from the same source IP within suppress_minutes.
    """

    def __init__(
        self,
        recipient:        str = DEFAULT_RECIPIENT,
        sender:           str = DEFAULT_SENDER,
        password:         str = DEFAULT_PASSWORD,
        smtp_host:        str = DEFAULT_SMTP_HOST,
        smtp_port:        int = DEFAULT_SMTP_PORT,
        suppress_minutes: int = 5,
        dry_run:          bool = False,
    ):
        self.recipient        = recipient
        self.sender           = sender
        self.password         = password
        self.smtp_host        = smtp_host
        self.smtp_port        = smtp_port
        self.suppress_secs    = suppress_minutes * 60
        self.dry_run          = dry_run

        self._lock            = threading.Lock()
        self._last_sent: dict = {}   # { src_ip: timestamp }
        self.sent_count       = 0
        self.suppressed_count = 0

    def _is_suppressed(self, src_ip: str) -> bool:
        now = time.time()
        last = self._last_sent.get(src_ip, 0)
        return (now - last) < self.suppress_secs

    def _record_sent(self, src_ip: str):
        self._last_sent[src_ip] = time.time()

    def send_alert(
        self,
        src_ip:      str,
        dst_ip:      str,
        attack_type: str,
        confidence:  Optional[float],
        details:     dict,
        app_mode:    str = "Classic IDS",
    ) -> bool:
        """
        Send an email alert.
        Returns True if email was sent, False if suppressed or failed.
        """
        with self._lock:
            if self._is_suppressed(src_ip):
                self.suppressed_count += 1
                log.debug(f"Alert suppressed for {src_ip} (cooldown active)")
                return False

        subject = f"[IDS ALERT] {attack_type} detected from {src_ip}"
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Build plain-text body
        body_lines = [
            f"AI-Enhanced Intrusion Detection System — {app_mode}",
            f"{'='*55}",
            f"",
            f"ALERT DETAILS",
            f"─────────────",
            f"Timestamp    : {ts}",
            f"Attack Type  : {attack_type}",
            f"Source IP    : {src_ip}",
            f"Destination  : {dst_ip}",
        ]
        if confidence is not None:
            body_lines.append(f"Confidence   : {confidence*100:.1f}%")

        body_lines += [
            f"",
            f"FLOW STATISTICS",
            f"───────────────",
        ]
        for k, v in details.items():
            body_lines.append(f"{k:<18}: {v}")

        body_lines += [
            f"",
            f"─────────────────────────────────────────────────────",
            f"This alert was generated automatically by the IDS.",
            f"Please review the event and take appropriate action.",
        ]

        # HTML version
        html_rows = "".join(
            f"<tr><td style='padding:4px 12px;color:#555;'>{k}</td>"
            f"<td style='padding:4px 12px;font-weight:500;'>{v}</td></tr>"
            for k, v in details.items()
        )
        conf_row = (
            f"<tr><td style='padding:4px 12px;color:#555;'>Confidence</td>"
            f"<td style='padding:4px 12px;font-weight:500;'>{confidence*100:.1f}%</td></tr>"
            if confidence is not None else ""
        )
        html = f"""
<html><body style="font-family:Arial,sans-serif;font-size:14px;color:#222;">
<div style="max-width:600px;margin:0 auto;border:1px solid #ddd;border-radius:6px;overflow:hidden;">
  <div style="background:#B91C1C;color:#fff;padding:16px 20px;">
    <h2 style="margin:0;font-size:18px;">&#9888; IDS Alert — {attack_type}</h2>
    <p style="margin:4px 0 0;font-size:13px;opacity:.85;">{app_mode} &bull; {ts}</p>
  </div>
  <div style="padding:20px;">
    <table style="border-collapse:collapse;width:100%;background:#FEF2F2;border-radius:4px;">
      <tr><td style='padding:4px 12px;color:#555;'>Source IP</td>
          <td style='padding:4px 12px;font-weight:600;color:#B91C1C;'>{src_ip}</td></tr>
      <tr><td style='padding:4px 12px;color:#555;'>Destination</td>
          <td style='padding:4px 12px;font-weight:500;'>{dst_ip}</td></tr>
      {conf_row}
    </table>
    <h3 style="font-size:14px;margin:16px 0 6px;">Flow Statistics</h3>
    <table style="border-collapse:collapse;width:100%;border:1px solid #eee;">{html_rows}</table>
    <p style="font-size:12px;color:#888;margin-top:16px;">
      This alert was generated automatically by the IDS system.
    </p>
  </div>
</div>
</body></html>"""

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = f"AI-IDS System <{self.sender}>"
        msg["To"]      = self.recipient
        msg.attach(MIMEText("\n".join(body_lines), "plain"))
        msg.attach(MIMEText(html, "html"))

        if self.dry_run:
            log.info(f"[DRY RUN] Would send alert: {subject}")
            with self._lock:
                self._record_sent(src_ip)
                self.sent_count += 1
            return True

        if not self.password or not self.recipient:
            missing = "password (IDS_EMAIL_PASS / --email-pass)" if not self.password \
                      else "recipient (IDS_ALERT_TO / --email-to)"
            log.error(f"Email not sent: no {missing} set.")
            return False

        try:
            ctx = ssl.create_default_context()
            with smtplib.SMTP_SSL(self.smtp_host, self.smtp_port, context=ctx) as srv:
                srv.login(self.sender, self.password)
                srv.sendmail(self.sender, self.recipient, msg.as_string())
            with self._lock:
                self._record_sent(src_ip)
                self.sent_count += 1
            log.info(f"Alert sent to {self.recipient}: {attack_type} from {src_ip}")
            return True
        except Exception as e:
            log.error(f"Email failed: {e}")
            return False

    def send_test(self) -> bool:
        """Send a test email to verify SMTP configuration."""
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        return self.send_alert(
            src_ip="127.0.0.1",
            dst_ip="TEST",
            attack_type="TEST ALERT",
            confidence=1.0,
            details={
                "Note":    "This is a test alert from the IDS system",
                "Time":    ts,
                "SMTP":    f"{self.smtp_host}:{self.smtp_port}",
                "Sender":  self.sender,
            },
            app_mode="System Test",
        )

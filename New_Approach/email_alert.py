# email_alert.py
# CogSOC — THE HANDS: Email Alert Module
# Dedicated email alerting with rich templates, digest mode, and escalation tracking
# Usage: from email_alert import EmailAlertEngine

import smtplib
import json
import os
from datetime import datetime, timezone, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from collections import defaultdict

# ══════════════════════════════════════════════
#  CONFIGURATION
# ══════════════════════════════════════════════
DEFAULT_CONFIG = {
    'enabled'        : False,
    'smtp_server'    : 'smtp.gmail.com',
    'smtp_port'      : 587,
    'sender'         : 'cybersecabs@gmail.com',
    'password'       : 'rqzu dzvy xzdd xgtr',                        # Gmail App Password
    'recipients'     : ['rangharabbas@gmail.com'],
    'cooldown_secs'  : 300,         # 5 min between emails per IP
    'digest_interval': 900,         # 15 min digest cycle
    'escalation_threshold': 3,      # escalation email after 3 severity bumps
    'min_severity'   : 'HIGH',      # only email for HIGH+ (HIGH, CRITICAL)
    'dashboard_url'  : 'http://localhost:8050',
}

SEV_RANK = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
SEV_COLORS = {
    'CRITICAL': '#ef4444',
    'HIGH'    : '#f59e0b',
    'MEDIUM'  : '#3b82f6',
    'LOW'     : '#6b7280',
}


# ══════════════════════════════════════════════
#  EMAIL ALERT ENGINE
# ══════════════════════════════════════════════
class EmailAlertEngine:
    """
    Professional email alerting for CogSOC incidents.

    Features:
      - Real-time alerts for CRITICAL/HIGH incidents
      - Digest emails (batch summary every N minutes)
      - Escalation alerts when severity auto-upgrades
      - Session summary email on shutdown
      - Per-IP rate limiting to prevent inbox flood
      - Rich HTML email templates
    """

    def __init__(self, config=None):
        self.cfg = {**DEFAULT_CONFIG, **(config or {})}
        self._rate_limiter = {}          # {ip: last_sent_datetime}
        self._digest_queue = []          # queued alerts for next digest
        self._last_digest = datetime.now(timezone.utc)
        self._sent_count = 0
        self._failed_count = 0
        self._escalation_tracker = defaultdict(int)  # {ip: escalation_count}
        print(f"[EMAIL] Engine initialized | "
              f"Enabled={self.cfg['enabled']} | "
              f"Recipients={', '.join(self.cfg['recipients'])} | "
              f"Min severity={self.cfg['min_severity']}")

    # ── Public API ──────────────────────────────

    def on_incident(self, incident_data):
        """
        Called when an incident is created or updated.
        Decides whether to send immediate alert, queue for digest, or skip.

        incident_data dict keys:
          incident_id, src_ip, dst_ip/victims, severity, attack_type/primary_attack,
          event_count, mitre_technique, mitre_tactic, sensor, blocked,
          classification, status, avg_confidence
        """
        if not self.cfg['enabled']:
            return

        sev = incident_data.get('severity', 'LOW')
        src_ip = incident_data.get('src_ip', '?')
        min_sev = self.cfg['min_severity']

        # Below minimum severity → queue for digest only
        if SEV_RANK.get(sev, 0) < SEV_RANK.get(min_sev, 3):
            self._digest_queue.append(incident_data)
            return

        # Rate limit check
        if self._is_rate_limited(src_ip):
            self._digest_queue.append(incident_data)
            return

        # Send immediate alert
        self._send_incident_alert(incident_data)

    def on_escalation(self, src_ip, old_severity, new_severity, incident_data):
        """Called when an incident's severity is auto-escalated."""
        if not self.cfg['enabled']:
            return
        self._escalation_tracker[src_ip] += 1
        if self._escalation_tracker[src_ip] >= self.cfg['escalation_threshold']:
            self._send_escalation_alert(src_ip, old_severity, new_severity, incident_data)
            self._escalation_tracker[src_ip] = 0  # reset after sending

    def check_digest(self):
        """Call periodically. Sends digest email if interval has elapsed."""
        if not self.cfg['enabled'] or not self._digest_queue:
            return
        now = datetime.now(timezone.utc)
        elapsed = (now - self._last_digest).total_seconds()
        if elapsed >= self.cfg['digest_interval']:
            self._send_digest()
            self._last_digest = now

    def send_session_summary(self, incidents, stats):
        """
        Send end-of-session summary email.
        incidents: list of incident dicts from IncidentCorrelationEngine
        stats: dict with total_analyzed, total_alerts, total_blocked, elapsed
        """
        if not self.cfg['enabled']:
            return
        self._send_session_email(incidents, stats)

    def get_stats(self):
        return {
            'sent': self._sent_count,
            'failed': self._failed_count,
            'queued': len(self._digest_queue),
        }

    # ── Rate Limiting ───────────────────────────

    def _is_rate_limited(self, ip):
        now = datetime.now(timezone.utc)
        last = self._rate_limiter.get(ip)
        if last and (now - last).total_seconds() < self.cfg['cooldown_secs']:
            return True
        return False

    def _mark_sent(self, ip):
        self._rate_limiter[ip] = datetime.now(timezone.utc)

    # ── Email Senders ───────────────────────────

    def _send_smtp(self, subject, html_body):
        """Send an HTML email via SMTP."""
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = self.cfg['sender']
        msg['To'] = ', '.join(self.cfg['recipients'])
        msg.attach(MIMEText(html_body, 'html'))

        try:
            with smtplib.SMTP(self.cfg['smtp_server'], self.cfg['smtp_port']) as server:
                server.starttls()
                server.login(self.cfg['sender'], self.cfg['password'])
                server.send_message(msg)
            self._sent_count += 1
            return True
        except Exception as e:
            self._failed_count += 1
            print(f"  [EMAIL] Send failed: {e}")
            return False

    def _send_incident_alert(self, inc):
        """Send real-time incident alert email."""
        sev = inc.get('severity', 'MEDIUM')
        src_ip = inc.get('src_ip', '?')
        attack = inc.get('primary_attack', inc.get('attack_type', 'Unknown'))
        inc_id = inc.get('incident_id', 'N/A')
        dst = inc.get('victims', inc.get('dst_ip', '?'))
        if isinstance(dst, (set, list)):
            dst = ', '.join(list(dst)[:3])
        events = inc.get('event_count', inc.get('alert_count', 1))
        mitre = inc.get('mitre_technique', '')
        sensor = inc.get('sensor', inc.get('sensor_name', 'unknown'))
        blocked = inc.get('blocked', False)
        conf = inc.get('avg_confidence', inc.get('confidence', 0))
        classification = inc.get('classification', {})
        phase = classification.get('phase', 'N/A')
        signals = classification.get('signals', [])
        is_campaign = classification.get('is_campaign', False)
        now = datetime.now(timezone.utc)

        sev_color = SEV_COLORS.get(sev, '#6b7280')
        blocked_text = 'AUTO-BLOCKED' if blocked else 'NEEDS REVIEW'
        blocked_color = '#10b981' if blocked else '#ef4444'

        signals_html = ''
        if signals:
            items = ''.join(f'<li style="color:#94a3b8;font-size:13px">{s}</li>' for s in signals[:5])
            signals_html = f'<ul style="margin:8px 0;padding-left:16px">{items}</ul>'

        campaign_html = ''
        if is_campaign:
            campaign_html = ('<div style="background:rgba(239,68,68,0.15);border:1px solid #ef4444;'
                           'border-radius:6px;padding:10px;margin-top:12px;color:#fca5a5;font-size:13px">'
                           '&#9888; MULTI-VECTOR CAMPAIGN DETECTED — This IP is using multiple attack vectors</div>')

        html = f"""
        <div style="font-family:Arial,sans-serif;max-width:640px;margin:0 auto;
                    background:#0f172a;color:#e2e8f0;border-radius:12px;overflow:hidden">
          <div style="background:linear-gradient(135deg,#1e1b4b,#0f172a);padding:20px 24px;
                      border-bottom:3px solid {sev_color}">
            <h2 style="margin:0;color:#fff">&#128737; CogSOC Security Alert</h2>
            <p style="margin:4px 0 0;color:#94a3b8;font-size:13px">AI-Driven Autonomous Defense | THE HANDS Module</p>
          </div>
          <div style="padding:24px">
            <div style="background:rgba(239,68,68,0.08);border:1px solid {sev_color};
                        border-radius:8px;padding:16px;margin-bottom:16px">
              <span style="background:{sev_color};color:#fff;padding:4px 12px;
                           border-radius:20px;font-size:12px;font-weight:700">{sev}</span>
              <span style="background:{blocked_color};color:#fff;padding:4px 12px;
                           border-radius:20px;font-size:12px;font-weight:700;margin-left:8px">{blocked_text}</span>
              <h3 style="margin:12px 0 4px;color:#fff">{attack}</h3>
              <p style="margin:0;color:#94a3b8;font-size:13px">Incident: {inc_id} | Phase: {phase}</p>
            </div>
            <table style="width:100%;font-size:14px;color:#cbd5e1;border-collapse:collapse">
              <tr><td style="padding:8px 0;color:#64748b;width:140px">Attacker IP</td>
                  <td style="padding:8px 0"><strong style="color:#ef4444">{src_ip}</strong></td></tr>
              <tr><td style="padding:8px 0;color:#64748b">Victim(s)</td>
                  <td style="padding:8px 0"><strong>{dst}</strong></td></tr>
              <tr><td style="padding:8px 0;color:#64748b">Events</td>
                  <td style="padding:8px 0">{events}</td></tr>
              <tr><td style="padding:8px 0;color:#64748b">Avg Confidence</td>
                  <td style="padding:8px 0">{conf:.1f}%</td></tr>
              <tr><td style="padding:8px 0;color:#64748b">MITRE ATT&CK</td>
                  <td style="padding:8px 0">{mitre}</td></tr>
              <tr><td style="padding:8px 0;color:#64748b">Sensor</td>
                  <td style="padding:8px 0">{sensor}</td></tr>
              <tr><td style="padding:8px 0;color:#64748b">Time</td>
                  <td style="padding:8px 0">{now.strftime('%Y-%m-%d %H:%M:%S UTC')}</td></tr>
            </table>
            {signals_html}
            {campaign_html}
            <div style="margin-top:20px;padding:12px;background:rgba(59,130,246,0.1);
                        border-radius:8px;font-size:12px;color:#94a3b8">
              View dashboard: <a href="{self.cfg['dashboard_url']}" style="color:#3b82f6">{self.cfg['dashboard_url']}</a>
            </div>
          </div>
        </div>"""

        subject = f"[CogSOC {sev}] {attack} from {src_ip} ({events} events)"
        if self._send_smtp(subject, html):
            self._mark_sent(src_ip)
            print(f"  [EMAIL] Alert sent: {inc_id} | {src_ip} | {attack}")

    def _send_escalation_alert(self, src_ip, old_sev, new_sev, inc):
        """Send escalation notification."""
        inc_id = inc.get('incident_id', 'N/A')
        attack = inc.get('primary_attack', inc.get('attack_type', 'Unknown'))
        events = inc.get('event_count', 0)
        new_color = SEV_COLORS.get(new_sev, '#6b7280')

        html = f"""
        <div style="font-family:Arial,sans-serif;max-width:640px;margin:0 auto;
                    background:#0f172a;color:#e2e8f0;border-radius:12px;overflow:hidden">
          <div style="background:linear-gradient(135deg,#7f1d1d,#0f172a);padding:20px 24px;
                      border-bottom:3px solid {new_color}">
            <h2 style="margin:0;color:#fff">&#9888; SEVERITY ESCALATION</h2>
            <p style="margin:4px 0 0;color:#fca5a5;font-size:13px">Incident {inc_id} has been escalated</p>
          </div>
          <div style="padding:24px">
            <div style="text-align:center;margin:20px 0">
              <span style="background:{SEV_COLORS.get(old_sev,'#6b7280')};color:#fff;padding:8px 20px;
                           border-radius:20px;font-size:16px;font-weight:700">{old_sev}</span>
              <span style="color:#64748b;font-size:24px;margin:0 16px">&#10140;</span>
              <span style="background:{new_color};color:#fff;padding:8px 20px;
                           border-radius:20px;font-size:16px;font-weight:700">{new_sev}</span>
            </div>
            <table style="width:100%;font-size:14px;color:#cbd5e1;border-collapse:collapse">
              <tr><td style="padding:8px 0;color:#64748b">Attacker</td>
                  <td style="padding:8px 0"><strong style="color:#ef4444">{src_ip}</strong></td></tr>
              <tr><td style="padding:8px 0;color:#64748b">Attack</td>
                  <td style="padding:8px 0">{attack}</td></tr>
              <tr><td style="padding:8px 0;color:#64748b">Total Events</td>
                  <td style="padding:8px 0">{events}</td></tr>
            </table>
          </div>
        </div>"""

        subject = f"[CogSOC ESCALATION] {old_sev} -> {new_sev} | {src_ip}"
        if self._send_smtp(subject, html):
            print(f"  [EMAIL] Escalation alert: {src_ip} {old_sev}->{new_sev}")

    def _send_digest(self):
        """Send batched digest of queued alerts."""
        if not self._digest_queue:
            return

        count = len(self._digest_queue)
        # Group by severity
        by_sev = defaultdict(list)
        for inc in self._digest_queue:
            by_sev[inc.get('severity', 'LOW')].append(inc)

        rows = ''
        for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            for inc in by_sev.get(sev, []):
                src = inc.get('src_ip', '?')
                attack = inc.get('primary_attack', inc.get('attack_type', '?'))[:30]
                evts = inc.get('event_count', inc.get('alert_count', 1))
                color = SEV_COLORS.get(sev, '#6b7280')
                rows += (f'<tr><td style="padding:6px 8px;border-bottom:1px solid #1e293b">'
                         f'<span style="color:{color};font-weight:700">{sev}</span></td>'
                         f'<td style="padding:6px 8px;border-bottom:1px solid #1e293b;color:#ef4444">{src}</td>'
                         f'<td style="padding:6px 8px;border-bottom:1px solid #1e293b">{attack}</td>'
                         f'<td style="padding:6px 8px;border-bottom:1px solid #1e293b;text-align:right">{evts}</td></tr>')

        html = f"""
        <div style="font-family:Arial,sans-serif;max-width:640px;margin:0 auto;
                    background:#0f172a;color:#e2e8f0;border-radius:12px;overflow:hidden">
          <div style="background:linear-gradient(135deg,#1e1b4b,#0f172a);padding:20px 24px;
                      border-bottom:3px solid #3b82f6">
            <h2 style="margin:0;color:#fff">&#128202; CogSOC Alert Digest</h2>
            <p style="margin:4px 0 0;color:#94a3b8;font-size:13px">{count} alerts in the last {self.cfg['digest_interval']//60} minutes</p>
          </div>
          <div style="padding:24px">
            <table style="width:100%;font-size:13px;color:#cbd5e1;border-collapse:collapse">
              <tr style="color:#64748b">
                <th style="padding:8px;text-align:left">Severity</th>
                <th style="padding:8px;text-align:left">Source IP</th>
                <th style="padding:8px;text-align:left">Attack</th>
                <th style="padding:8px;text-align:right">Events</th>
              </tr>
              {rows}
            </table>
          </div>
        </div>"""

        subject = f"[CogSOC Digest] {count} alerts — {datetime.now(timezone.utc).strftime('%H:%M UTC')}"
        if self._send_smtp(subject, html):
            print(f"  [EMAIL] Digest sent: {count} alerts")
        self._digest_queue = []

    def _send_session_email(self, incidents, stats):
        """Send end-of-session summary."""
        total = stats.get('total_analyzed', 0)
        alerts = stats.get('total_alerts', 0)
        blocked = stats.get('total_blocked', 0)
        elapsed = stats.get('elapsed', 0)
        runtime = f"{int(elapsed//60)}m {int(elapsed%60)}s"

        rows = ''
        for i, inc in enumerate(incidents[:15], 1):
            sev = inc.get('severity', 'LOW')
            src = inc.get('src_ip', '?')
            attack = inc.get('classification', {}).get('category', inc.get('primary_attack', '?'))[:28]
            evts = inc.get('event_count', 0)
            color = SEV_COLORS.get(sev, '#6b7280')
            rows += (f'<tr><td style="padding:6px 8px;border-bottom:1px solid #1e293b">{i}</td>'
                     f'<td style="padding:6px 8px;border-bottom:1px solid #1e293b;color:#ef4444">{src}</td>'
                     f'<td style="padding:6px 8px;border-bottom:1px solid #1e293b">{attack}</td>'
                     f'<td style="padding:6px 8px;border-bottom:1px solid #1e293b">'
                     f'<span style="color:{color};font-weight:700">{sev}</span></td>'
                     f'<td style="padding:6px 8px;border-bottom:1px solid #1e293b;text-align:right">{evts}</td></tr>')

        html = f"""
        <div style="font-family:Arial,sans-serif;max-width:640px;margin:0 auto;
                    background:#0f172a;color:#e2e8f0;border-radius:12px;overflow:hidden">
          <div style="background:linear-gradient(135deg,#1e1b4b,#0f172a);padding:20px 24px;
                      border-bottom:3px solid #10b981">
            <h2 style="margin:0;color:#fff">&#128737; CogSOC Session Report</h2>
            <p style="margin:4px 0 0;color:#94a3b8;font-size:13px">Monitoring session completed</p>
          </div>
          <div style="padding:24px">
            <div style="display:flex;gap:12px;margin-bottom:20px;flex-wrap:wrap">
              <div style="flex:1;min-width:120px;background:#1e293b;border-radius:8px;padding:12px;text-align:center">
                <div style="color:#64748b;font-size:11px">RUNTIME</div>
                <div style="color:#fff;font-size:18px;font-weight:700">{runtime}</div>
              </div>
              <div style="flex:1;min-width:120px;background:#1e293b;border-radius:8px;padding:12px;text-align:center">
                <div style="color:#64748b;font-size:11px">FLOWS</div>
                <div style="color:#fff;font-size:18px;font-weight:700">{total:,}</div>
              </div>
              <div style="flex:1;min-width:120px;background:#1e293b;border-radius:8px;padding:12px;text-align:center">
                <div style="color:#64748b;font-size:11px">ALERTS</div>
                <div style="color:#f59e0b;font-size:18px;font-weight:700">{alerts:,}</div>
              </div>
              <div style="flex:1;min-width:120px;background:#1e293b;border-radius:8px;padding:12px;text-align:center">
                <div style="color:#64748b;font-size:11px">BLOCKED</div>
                <div style="color:#ef4444;font-size:18px;font-weight:700">{blocked}</div>
              </div>
            </div>
            <h3 style="color:#fff;margin:0 0 12px">Top Incidents</h3>
            <table style="width:100%;font-size:13px;color:#cbd5e1;border-collapse:collapse">
              <tr style="color:#64748b">
                <th style="padding:8px;text-align:left">#</th>
                <th style="padding:8px;text-align:left">Attacker</th>
                <th style="padding:8px;text-align:left">Attack</th>
                <th style="padding:8px;text-align:left">Severity</th>
                <th style="padding:8px;text-align:right">Events</th>
              </tr>
              {rows}
            </table>
          </div>
        </div>"""

        subject = f"[CogSOC Report] {alerts} alerts, {blocked} blocked — {runtime}"
        if self._send_smtp(subject, html):
            print(f"  [EMAIL] Session summary sent ({len(incidents)} incidents)")

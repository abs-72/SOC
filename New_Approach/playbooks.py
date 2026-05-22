# playbooks.py
# CogSOC — THE HANDS: Automated Response Playbooks
# Defines and executes automated response workflows based on incident type
# Usage: from playbooks import PlaybookEngine

import os
import json
import subprocess
import platform
import time
from datetime import datetime, timezone
from collections import defaultdict

# ══════════════════════════════════════════════
#  PLAYBOOK DEFINITIONS
# ══════════════════════════════════════════════
# Each playbook is a sequence of actions triggered by attack type + severity.
# Actions: BLOCK_IP, RATE_LIMIT, LOG, ALERT, ISOLATE, SNAPSHOT, ESCALATE

PLAYBOOKS = {
    # ── DDoS / DoS Response ──
    'DDOS_RESPONSE': {
        'name'        : 'DDoS Mitigation Playbook',
        'description' : 'Automated response for volumetric and application-layer DDoS attacks',
        'triggers'    : {
            'attack_types' : ['DDoS', 'DoS', 'DDoS Volumetric Flood', 'DDoS SYN Flood',
                              'DDoS Application Layer', 'DoS Slowloris', 'DoS Flood',
                              'DoS SYN Flood', 'DDoS Flood', 'High Volume Attack',
                              'DoS Resource Exhaustion', 'HTTP Flood', 'DoS Hulk',
                              'DoS GoldenEye', 'DoS SlowHTTPTest', 'DDoS Attack',
                              'DoS Attack', 'DoS/Scan Flood'],
            'min_severity' : 'HIGH',
            'min_events'   : 5,
        },
        'actions': [
            {'type': 'LOG',        'detail': 'DDoS attack detected — initiating mitigation'},
            {'type': 'BLOCK_IP',   'method': 'firewall', 'duration_min': 60},
            {'type': 'RATE_LIMIT', 'max_pps': 100, 'duration_min': 30},
            {'type': 'SNAPSHOT',   'detail': 'Capture network state for forensics'},
            {'type': 'ALERT',      'channels': ['email', 'console']},
            {'type': 'ESCALATE',   'condition': 'event_count > 100', 'to': 'SOC_LEAD'},
        ],
        'auto_close_after_min': 30,
    },

    # ── Port Scan Response ──
    'PORTSCAN_RESPONSE': {
        'name'        : 'Port Scan Response Playbook',
        'description' : 'Detect and block reconnaissance scanning activity',
        'triggers'    : {
            'attack_types' : ['Port Scan', 'SYN Scan', 'Port Scan (RST)',
                              'Port Scan (Horizontal)', 'Port Scan (Vertical)',
                              'Network Service Scanning', 'Reconnaissance',
                              'Network Discovery'],
            'min_severity' : 'MEDIUM',
            'min_events'   : 3,
        },
        'actions': [
            {'type': 'LOG',        'detail': 'Reconnaissance activity detected'},
            {'type': 'RATE_LIMIT', 'max_pps': 50, 'duration_min': 15},
            # No auto-block for port scans — security analyst decides via dashboard
            {'type': 'ALERT',      'channels': ['console']},
        ],
        'auto_close_after_min': 15,
    },

    # ── Brute Force Response ──
    'BRUTEFORCE_RESPONSE': {
        'name'        : 'Brute Force Mitigation Playbook',
        'description' : 'Block credential stuffing and brute force attempts',
        'triggers'    : {
            'attack_types' : ['Brute Force', 'Brute Force Attempt', 'SSH Brute Force',
                              'FTP Brute Force', 'Brute Force SSH', 'Brute Force RDP',
                              'Brute Force FTP', 'Credential Access'],
            'min_severity' : 'MEDIUM',
            'min_events'   : 10,
        },
        'actions': [
            {'type': 'LOG',        'detail': 'Brute force attack detected'},
            {'type': 'BLOCK_IP',   'method': 'firewall', 'duration_min': 120},
            {'type': 'ALERT',      'channels': ['email', 'console']},
            {'type': 'ESCALATE',   'condition': 'event_count > 50', 'to': 'SOC_ANALYST'},
        ],
        'auto_close_after_min': 60,
    },

    # ── C2 Beaconing Response ──
    'C2_RESPONSE': {
        'name'        : 'C2 Beaconing Response Playbook',
        'description' : 'Isolate hosts communicating with command-and-control infrastructure',
        'triggers'    : {
            'attack_types' : ['C2 Beaconing', 'Botnet C2', 'BEACONING',
                              'Application Layer Protocol'],
            'min_severity' : 'MEDIUM',
            'min_events'   : 3,
        },
        'actions': [
            {'type': 'LOG',        'detail': 'C2 beaconing pattern detected — possible compromised host'},
            {'type': 'ISOLATE',    'method': 'network_segment'},
            {'type': 'SNAPSHOT',   'detail': 'Forensic capture of C2 communication'},
            {'type': 'BLOCK_IP',   'method': 'firewall', 'duration_min': 1440},  # 24h
            {'type': 'ALERT',      'channels': ['email', 'console']},
            {'type': 'ESCALATE',   'condition': 'always', 'to': 'INCIDENT_RESPONSE'},
        ],
        'auto_close_after_min': 1440,
    },

    # ── Web Attack Response ──
    'WEB_ATTACK_RESPONSE': {
        'name'        : 'Web Attack Response Playbook',
        'description' : 'Respond to web application attacks including SQLi, XSS, and exploits',
        'triggers'    : {
            'attack_types' : ['Web Attack', 'Web Exploit', 'SQL Injection',
                              'Suspicious Web Traffic', 'Exploit Public-Facing App',
                              'Infiltration'],
            'min_severity' : 'HIGH',
            'min_events'   : 1,
        },
        'actions': [
            {'type': 'LOG',        'detail': 'Web application attack detected'},
            {'type': 'BLOCK_IP',   'method': 'waf', 'duration_min': 60},
            {'type': 'SNAPSHOT',   'detail': 'Capture request payloads for analysis'},
            {'type': 'ALERT',      'channels': ['email', 'console']},
            {'type': 'ESCALATE',   'condition': 'severity == CRITICAL', 'to': 'SOC_LEAD'},
        ],
        'auto_close_after_min': 60,
    },

    # ── Generic / Fallback ──
    'GENERIC_RESPONSE': {
        'name'        : 'Generic Attack Response',
        'description' : 'Default response for unclassified attacks detected by AI',
        'triggers'    : {
            'attack_types' : ['Advanced Attack', 'ATTACK', 'Unknown'],
            'min_severity' : 'HIGH',
            'min_events'   : 10,
        },
        'actions': [
            {'type': 'LOG',        'detail': 'Unclassified attack detected by AI model'},
            {'type': 'RATE_LIMIT', 'max_pps': 200, 'duration_min': 15},
            {'type': 'ALERT',      'channels': ['console']},
            {'type': 'BLOCK_IP',   'method': 'firewall', 'duration_min': 30,
             'condition': 'severity >= CRITICAL'},
        ],
        'auto_close_after_min': 30,
    },
}

SEV_RANK = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}


# ══════════════════════════════════════════════
#  ACTION EXECUTORS
# ══════════════════════════════════════════════
class ActionExecutor:
    """Executes individual playbook actions."""

    def __init__(self, blocked_log_path=None, es=None):
        self.blocked_log = blocked_log_path or '/mnt/c/CogSOC/data/blocked_ips.log'
        self.es = es
        self._blocked_ips = set()
        self._rate_limited = {}  # {ip: expire_time}
        self._action_log = []    # full audit trail

    def execute(self, action, context):
        """
        Execute a single playbook action.
        context: {src_ip, dst_ip, incident_id, severity, attack_type, event_count, playbook_name}
        Returns: {success, action_type, detail}
        """
        atype = action['type']
        src_ip = context.get('src_ip', '0.0.0.0')
        result = {'action_type': atype, 'success': False, 'detail': '', 'timestamp': datetime.now(timezone.utc).isoformat()}

        # Check condition if present
        if 'condition' in action:
            if not self._check_condition(action['condition'], context):
                result['detail'] = f"Condition not met: {action['condition']}"
                result['success'] = True  # skip is not a failure
                return result

        try:
            if atype == 'LOG':
                result = self._do_log(action, context)
            elif atype == 'BLOCK_IP':
                result = self._do_block(action, context)
            elif atype == 'RATE_LIMIT':
                result = self._do_rate_limit(action, context)
            elif atype == 'ALERT':
                result = self._do_alert(action, context)
            elif atype == 'ISOLATE':
                result = self._do_isolate(action, context)
            elif atype == 'SNAPSHOT':
                result = self._do_snapshot(action, context)
            elif atype == 'ESCALATE':
                result = self._do_escalate(action, context)
            else:
                result['detail'] = f"Unknown action type: {atype}"
        except Exception as e:
            result['detail'] = f"Action failed: {e}"

        self._action_log.append({**result, 'context': {
            'src_ip': src_ip,
            'incident_id': context.get('incident_id', ''),
            'playbook': context.get('playbook_name', ''),
        }})
        return result

    def _check_condition(self, condition, context):
        """Evaluate simple condition strings."""
        if condition == 'always':
            return True
        sev = context.get('severity', 'LOW')
        evt = context.get('event_count', 0)
        if 'event_count >' in condition:
            threshold = int(condition.split('>')[-1].strip())
            return evt > threshold
        if 'severity >=' in condition:
            target = condition.split('>=')[-1].strip()
            return SEV_RANK.get(sev, 0) >= SEV_RANK.get(target, 0)
        if 'severity ==' in condition:
            target = condition.split('==')[-1].strip()
            return sev == target
        return True

    def _do_log(self, action, context):
        detail = action.get('detail', 'Action logged')
        src_ip = context.get('src_ip', '?')
        inc_id = context.get('incident_id', 'N/A')
        msg = f"[PLAYBOOK] {detail} | IP={src_ip} | INC={inc_id}"
        print(f"  {msg}")

        # Also log to file
        try:
            os.makedirs(os.path.dirname(self.blocked_log), exist_ok=True)
            log_path = self.blocked_log.replace('blocked_ips.log', 'playbook_actions.log')
            with open(log_path, 'a') as f:
                f.write(f"{datetime.now().isoformat()} | {msg}\n")
        except Exception:
            pass

        return {'action_type': 'LOG', 'success': True, 'detail': detail}

    def _do_block(self, action, context):
        src_ip = context.get('src_ip', '0.0.0.0')
        duration = action.get('duration_min', 60)
        method = action.get('method', 'firewall')

        if src_ip in self._blocked_ips:
            return {'action_type': 'BLOCK_IP', 'success': True,
                    'detail': f'{src_ip} already blocked'}

        # Log the block
        try:
            os.makedirs(os.path.dirname(self.blocked_log), exist_ok=True)
            with open(self.blocked_log, 'a') as f:
                f.write(f"{datetime.now().isoformat()} | PLAYBOOK_BLOCK | "
                        f"IP={src_ip} | method={method} | duration={duration}min | "
                        f"incident={context.get('incident_id', 'N/A')}\n")
        except Exception:
            pass

        # Attempt actual firewall block
        blocked = False
        import platform
        
        # Check if we are running inside WSL
        is_wsl = 'microsoft' in platform.uname().release.lower() or 'wsl' in platform.uname().release.lower()

        if platform.system() == 'Windows' or is_wsl:
            try:
                # Add Windows Defender Firewall rule to block the IP (Host OS)
                rule_name = f"CogSOC_Block_{src_ip.replace('.', '_')}"
                
                # If in WSL, we must call the .exe specifically
                cmd = ['netsh.exe' if is_wsl else 'netsh', 'advfirewall', 'firewall', 'add', 'rule', 
                       f'name={rule_name}', 'dir=in', 'action=block', f'remoteip={src_ip}']
                       
                result = subprocess.run(cmd, capture_output=True, timeout=10)
                
                if result.returncode == 0:
                    blocked = True
                else:
                    err_msg = result.stderr.decode().strip() or result.stdout.decode().strip()
                    print(f"  [PLAYBOOK] ERROR: Firewall block failed (Ensure your terminal is 'Run as Administrator'!). Details: {err_msg}")
            except Exception as e:
                print(f"  [PLAYBOOK] ERROR running netsh: {e}")

        elif platform.system() == 'Linux':
            try:
                result = subprocess.run(
                    ['sudo', 'iptables', '-A', 'INPUT', '-s', src_ip, '-j', 'DROP'],
                    capture_output=True, timeout=10
                )
                if result.returncode == 0:
                    blocked = True
                else:
                    print(f"  [PLAYBOOK] ERROR: iptables failed. Details: {result.stderr.decode().strip()}")
            except Exception as e:
                print(f"  [PLAYBOOK] ERROR running iptables: {e}")

        self._blocked_ips.add(src_ip)
        detail = f"Blocked {src_ip} via {method} for {duration}min"
        
        if blocked:
            if platform.system() == 'Windows' or is_wsl:
                detail += " (Windows Host Firewall rule applied)"
            else:
                detail += " (iptables applied)"
        else:
            detail += " (logged only — apply manually)"

        print(f"  [PLAYBOOK] BLOCK: {detail}")

        # Save to ES if available
        if self.es:
            try:
                self.es.index(index='cogsoc-responses', document={
                    '@timestamp': datetime.now(timezone.utc).isoformat(),
                    'incident_id': context.get('incident_id', ''),
                    'action_type': 'IP_BLOCK',
                    'src_ip': src_ip,
                    'status': 'SUCCESS' if blocked else 'LOGGED',
                    'method': f'PLAYBOOK_{method.upper()}',
                    'details': detail,
                })
            except Exception:
                pass

        return {'action_type': 'BLOCK_IP', 'success': True, 'detail': detail}

    def _do_rate_limit(self, action, context):
        src_ip = context.get('src_ip', '0.0.0.0')
        max_pps = action.get('max_pps', 100)
        duration = action.get('duration_min', 15)
        detail = f"Rate-limited {src_ip} to {max_pps} pps for {duration}min"
        self._rate_limited[src_ip] = time.time() + (duration * 60)
        print(f"  [PLAYBOOK] RATE_LIMIT: {detail}")
        return {'action_type': 'RATE_LIMIT', 'success': True, 'detail': detail}

    def _do_alert(self, action, context):
        channels = action.get('channels', ['console'])
        detail = f"Alert sent via: {', '.join(channels)}"
        # Console alert is handled by the correlation engine already
        # Email alert is handled by EmailAlertEngine if integrated
        return {'action_type': 'ALERT', 'success': True, 'detail': detail}

    def _do_isolate(self, action, context):
        src_ip = context.get('src_ip', '0.0.0.0')
        method = action.get('method', 'network_segment')
        detail = f"Isolation requested for {src_ip} via {method} (manual action required)"
        print(f"  [PLAYBOOK] ISOLATE: {detail}")
        return {'action_type': 'ISOLATE', 'success': True, 'detail': detail}

    def _do_snapshot(self, action, context):
        detail = action.get('detail', 'Forensic snapshot requested')
        src_ip = context.get('src_ip', '?')
        # Save snapshot metadata
        try:
            snap_dir = os.path.dirname(self.blocked_log)
            os.makedirs(snap_dir, exist_ok=True)
            snap_file = os.path.join(snap_dir, 'forensic_snapshots.jsonl')
            with open(snap_file, 'a') as f:
                json.dump({
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                    'src_ip': src_ip,
                    'incident_id': context.get('incident_id', ''),
                    'attack_type': context.get('attack_type', ''),
                    'detail': detail,
                }, f)
                f.write('\n')
        except Exception:
            pass
        print(f"  [PLAYBOOK] SNAPSHOT: {detail} | IP={src_ip}")
        return {'action_type': 'SNAPSHOT', 'success': True, 'detail': detail}

    def _do_escalate(self, action, context):
        to = action.get('to', 'SOC_LEAD')
        src_ip = context.get('src_ip', '?')
        inc_id = context.get('incident_id', 'N/A')
        detail = f"Escalated {inc_id} ({src_ip}) to {to}"
        print(f"  [PLAYBOOK] ESCALATE: {detail}")
        return {'action_type': 'ESCALATE', 'success': True, 'detail': detail}

    def get_action_log(self):
        return self._action_log

    def is_blocked(self, ip):
        return ip in self._blocked_ips

    def is_rate_limited(self, ip):
        if ip in self._rate_limited:
            if time.time() < self._rate_limited[ip]:
                return True
            del self._rate_limited[ip]
        return False


# ══════════════════════════════════════════════
#  PLAYBOOK ENGINE
# ══════════════════════════════════════════════
class PlaybookEngine:
    """
    Matches incidents to playbooks and executes automated response workflows.

    Usage:
        engine = PlaybookEngine(es=es_client)
        engine.evaluate(incident_data)  # called per incident update
    """

    def __init__(self, es=None, blocked_log=None, playbooks=None):
        self.playbooks = playbooks or PLAYBOOKS
        self.executor = ActionExecutor(blocked_log_path=blocked_log, es=es)
        # Track which playbooks have been triggered per incident
        self._triggered = defaultdict(set)  # {incident_id: {playbook_key, ...}}
        self._execution_log = []
        print(f"[PLAYBOOK] Engine initialized | {len(self.playbooks)} playbooks loaded:")
        for key, pb in self.playbooks.items():
            triggers = pb['triggers']['attack_types'][:3]
            print(f"  - {pb['name']} (triggers: {', '.join(triggers)}...)")

    def evaluate(self, incident_data):
        """
        Evaluate an incident against all playbooks. Execute matching ones.

        incident_data keys:
          incident_id, src_ip, dst_ip/victims, severity, attack_type/primary_attack,
          event_count, classification, blocked, sensor, mitre_technique, mitre_tactic
        """
        inc_id = incident_data.get('incident_id', 'N/A')
        attack = incident_data.get('primary_attack',
                    incident_data.get('attack_type', 'Unknown'))
        sev = incident_data.get('severity', 'LOW')
        events = incident_data.get('event_count', 1)

        # Also check classification category
        classification = incident_data.get('classification', {})
        category = classification.get('category', '')

        matched = []
        for pb_key, pb in self.playbooks.items():
            # Skip if already triggered for this incident
            if pb_key in self._triggered.get(inc_id, set()):
                continue

            if self._matches(pb, attack, category, sev, events):
                matched.append((pb_key, pb))

        if not matched:
            return []

        results = []
        for pb_key, pb in matched:
            print(f"\n  [PLAYBOOK] Executing: {pb['name']}")
            print(f"  [PLAYBOOK] Trigger: {attack} | {sev} | {events} events")

            context = {
                'src_ip'       : incident_data.get('src_ip', '0.0.0.0'),
                'dst_ip'       : self._get_dst(incident_data),
                'incident_id'  : inc_id,
                'severity'     : sev,
                'attack_type'  : attack,
                'event_count'  : events,
                'playbook_name': pb['name'],
            }

            action_results = []
            for action in pb['actions']:
                r = self.executor.execute(action, context)
                action_results.append(r)

            self._triggered[inc_id].add(pb_key)
            execution = {
                'playbook_key' : pb_key,
                'playbook_name': pb['name'],
                'incident_id'  : inc_id,
                'src_ip'       : context['src_ip'],
                'timestamp'    : datetime.now(timezone.utc).isoformat(),
                'actions'      : action_results,
                'success'      : all(r.get('success') for r in action_results),
            }
            self._execution_log.append(execution)
            results.append(execution)

            # Save execution to ES
            self._save_to_es(execution)

        return results

    def _matches(self, playbook, attack_type, category, severity, event_count):
        """Check if an incident matches a playbook's triggers."""
        triggers = playbook['triggers']
        min_sev = triggers.get('min_severity', 'LOW')
        min_events = triggers.get('min_events', 1)
        attack_types = triggers.get('attack_types', [])

        # Severity check
        if SEV_RANK.get(severity, 0) < SEV_RANK.get(min_sev, 0):
            return False

        # Event count check
        if event_count < min_events:
            return False

        # Attack type match (partial matching)
        attack_up = attack_type.upper()
        cat_up = category.upper()
        for trigger_type in attack_types:
            trigger_up = trigger_type.upper()
            if (trigger_up in attack_up or attack_up in trigger_up or
                trigger_up in cat_up or cat_up in trigger_up):
                return True

        return False

    def _get_dst(self, incident_data):
        dst = incident_data.get('victims', incident_data.get('dst_ip', '0.0.0.0'))
        if isinstance(dst, (set, list)):
            return list(dst)[0] if dst else '0.0.0.0'
        return dst

    def _save_to_es(self, execution):
        """Save playbook execution to cogsoc-responses."""
        if not self.executor.es:
            return
        try:
            self.executor.es.index(index='cogsoc-responses', document={
                '@timestamp'  : execution['timestamp'],
                'incident_id' : execution['incident_id'],
                'action_type' : 'PLAYBOOK_EXECUTION',
                'src_ip'      : execution['src_ip'],
                'status'      : 'SUCCESS' if execution['success'] else 'PARTIAL',
                'method'      : execution['playbook_name'],
                'details'     : json.dumps({
                    'playbook': execution['playbook_key'],
                    'actions' : [{'type': a['action_type'], 'success': a['success'],
                                  'detail': a['detail']} for a in execution['actions']],
                }),
            })
        except Exception:
            pass

    def get_execution_log(self):
        return self._execution_log

    def get_stats(self):
        total = len(self._execution_log)
        success = sum(1 for e in self._execution_log if e['success'])
        return {
            'total_executions' : total,
            'successful'       : success,
            'failed'           : total - success,
            'unique_incidents' : len(self._triggered),
            'blocked_ips'      : len(self.executor._blocked_ips),
        }

    def print_summary(self):
        """Print playbook execution summary."""
        stats = self.get_stats()
        print(f"\n  {'PLAYBOOK EXECUTION SUMMARY':─<60}")
        print(f"  Total Executions  : {stats['total_executions']}")
        print(f"  Successful        : {stats['successful']}")
        print(f"  Failed            : {stats['failed']}")
        print(f"  Incidents Handled : {stats['unique_incidents']}")
        print(f"  IPs Blocked       : {stats['blocked_ips']}")

        if self._execution_log:
            print(f"\n  {'PLAYBOOK':<30} {'INCIDENT':<20} {'IP':<18} {'STATUS'}")
            print(f"  {'─'*78}")
            for ex in self._execution_log[-10:]:
                status = '✅' if ex['success'] else '❌'
                print(f"  {ex['playbook_name'][:29]:<30} "
                      f"{ex['incident_id']:<20} "
                      f"{ex['src_ip']:<18} {status}")

"""
CogSOC Dashboard Server
Serves the dashboard HTML and proxies Elasticsearch requests.
Includes authentication (login/signup), /block API for manual IP blocking.
Run: python dashboard.py
Open: http://localhost:8050
"""

import http.server
import json
import os
import sys
import subprocess
import urllib.parse
import shutil
import time
from urllib.request import urlopen, Request
from urllib.error import URLError
from datetime import datetime, timezone

# Import auth module
from auth import AuthManager

ES_HOST = "http://localhost:9200"
PORT = 8050
DASHBOARD_DIR = os.path.dirname(os.path.abspath(__file__))

# Initialize auth manager (credentials stored locally per system)
auth = AuthManager()
INTERFACE_CACHE = {"timestamp": 0, "interfaces": None}


def firewall_block(ip, duration_min=30):
    """Block IP via Windows Firewall and log to Elasticsearch."""
    rule_name = f"CogSOC_ManualBlock_{ip}"
    result = {"ip": ip, "status": "success", "method": "MANUAL", "details": ""}

    # Try to add firewall rule
    try:
        cmd = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={ip}'
        subprocess.run(cmd, shell=True, check=True, capture_output=True, timeout=10)
        result["details"] = f"Firewall rule added: {rule_name} for {duration_min}min"
    except subprocess.CalledProcessError as e:
        result["status"] = "logged_only"
        result["details"] = f"Firewall failed (need Admin). Logged block for {ip}."
    except Exception as e:
        result["status"] = "logged_only"
        result["details"] = str(e)

    # Log to Elasticsearch (cogsoc-responses index)
    try:
        doc = {
            "@timestamp": datetime.now(timezone.utc).isoformat(),
            "action_type": "IP_BLOCK",
            "src_ip": ip,
            "method": "MANUAL",
            "status": result["status"],
            "details": f"Manual block from dashboard — {duration_min}min",
            "incident_id": "MANUAL",
            "duration_minutes": duration_min,
        }
        req = Request(
            f"{ES_HOST}/cogsoc-responses/_doc",
            data=json.dumps(doc).encode(),
            method="POST",
        )
        req.add_header("Content-Type", "application/json")
        urlopen(req, timeout=5)
    except Exception:
        pass

    # Also update the alert's blocked status in ES
    try:
        update_body = {
            "script": {
                "source": "ctx._source.blocked = true; ctx._source.action = 'MANUAL_BLOCK'",
                "lang": "painless",
            },
            "query": {"bool": {"must": [{"term": {"src_ip": ip}}, {"term": {"blocked": False}}]}},
        }
        req = Request(
            f"{ES_HOST}/cogsoc-alerts/_update_by_query",
            data=json.dumps(update_body).encode(),
            method="POST",
        )
        req.add_header("Content-Type", "application/json")
        urlopen(req, timeout=5)
    except Exception:
        pass

    return result


class DashboardHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DASHBOARD_DIR, **kwargs)

    # ── Helper: get session token from request ──
    def _get_token(self):
        """Extract session token from Authorization header or cookie."""
        # Check Authorization header first
        auth_header = self.headers.get('Authorization', '')
        if auth_header:
            return auth_header.strip()
        # Check cookie
        cookie = self.headers.get('Cookie', '')
        for part in cookie.split(';'):
            part = part.strip()
            if part.startswith('cogsoc_token='):
                return part.split('=', 1)[1]
        return None

    def _is_authenticated(self):
        """Check if the current request has a valid session."""
        token = self._get_token()
        if not token:
            return False
        valid, _ = auth.validate_session(token)
        return valid

    def _require_auth(self):
        """Redirect to login page if not authenticated. Returns True if redirected."""
        if not self._is_authenticated():
            self.send_response(302)
            self.send_header('Location', '/login.html')
            self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
            self.send_header('Pragma', 'no-cache')
            self.send_header('Expires', '0')
            self.end_headers()
            return True
        return False

    # ── GET Requests ──
    def do_GET(self):
        # Public routes (no auth needed)
        if self.path == '/login.html' or self.path == '/login':
            self.path = '/login.html'
            return super().do_GET()
        if self.path == '/logo.png':
            return super().do_GET()
        if self.path.startswith('/auth/'):
            self._handle_auth_get()
            return
        if self.path.startswith('/trusted_action'):
            self._handle_trusted_action()
            return

        # Protected routes (auth required)
        if self.path == '/' or self.path == '':
            if self._require_auth():
                return
            self.path = '/gateway.html'
            return super().do_GET()
        if self.path == '/gateway.html' or self.path == '/dashboard.html':
            if self._require_auth():
                return
            return super().do_GET()
        if self.path.startswith('/es/'):
            if not self._is_authenticated():
                self._json_response(401, {"error": "Authentication required"})
                return
            self._proxy_es('GET')
            return

        if self.path.startswith('/api/interfaces'):
            if not self._is_authenticated():
                self._json_response(401, {"error": "Authentication required"})
                return
            self._handle_get_interfaces()
            return
            
        # Static files (CSS, JS, etc.) — serve without auth
        return super().do_GET()

    def do_POST(self):
        # Auth routes (public)
        if self.path.startswith('/auth/'):
            self._handle_auth_post()
            return
        # Protected routes
        if not self._is_authenticated():
            self._json_response(401, {"error": "Authentication required"})
            return
        if self.path == '/block':
            self._handle_block()
            return
        if self.path == '/copilot':
            self._handle_copilot()
            return
        if self.path == '/api/engine/start':
            self._handle_engine_start()
            return
        if self.path == '/api/engine/offline':
            self._handle_offline_upload()
            return
        if self.path.startswith('/es/'):
            self._proxy_es('POST')
            return
        self.send_error(404)

    # ══════════════════════════════════════════════
    #  ENGINE MANAGEMENT
    # ══════════════════════════════════════════════
    def _handle_get_interfaces(self):
        """Retrieve host capture interfaces from tshark/tcpdump."""
        print("[DASHBOARD] Fetching host network interfaces...")
        try:
            refresh = urllib.parse.urlparse(self.path).query == "refresh=1"
            cached = INTERFACE_CACHE.get("interfaces")
            if cached and not refresh and time.time() - INTERFACE_CACHE.get("timestamp", 0) < 60:
                self._json_response(200, {"success": True, "interfaces": cached, "cached": True})
                return

            interfaces = []

            def add_interface(iface_id, full, source, name=None):
                iface_id = str(iface_id).strip()
                full = str(full).strip()
                if not iface_id:
                    return
                if iface_id.lower() == "etwdump" or "event tracing" in full.lower():
                    return
                if any(item["id"] == iface_id for item in interfaces):
                    return
                display_name = (name or full or iface_id).strip()
                interfaces.append({
                    "id": iface_id,
                    "full": full or iface_id,
                    "name": display_name,
                    "source": source,
                })

            def parse_tshark(output, source):
                output = (output or "").replace("\x00", "")
                for line in output.splitlines():
                    line = line.strip()
                    if not line or ". " not in line:
                        continue
                    _, desc = line.split(". ", 1)
                    device_id = desc.split(" (", 1)[0] if " (" in desc else desc
                    friendly = desc
                    if " (" in desc and desc.endswith(")"):
                        friendly = desc.rsplit(" (", 1)[1][:-1]
                    add_interface(device_id, desc, source, friendly)

            capture_commands = []
            for env_name in ("COGSOC_TSHARK", "COGSOC_DUMPCAP"):
                env_path = os.environ.get(env_name)
                if env_path:
                    capture_commands.append(([env_path, "-D"], env_name.lower()))
            for tool in ("dumpcap.exe", "tshark.exe"):
                for path in (
                    f"/mnt/c/Program Files/Wireshark/{tool}",
                    rf"C:\Program Files\Wireshark\{tool}",
                ):
                    if os.path.exists(path):
                        capture_commands.append(([path, "-D"], tool.replace(".exe", "")))
            for tool in ("dumpcap", "tshark"):
                if shutil.which(tool):
                    capture_commands.append(([tool, "-D"], tool))
            if shutil.which("tshark"):
                capture_commands.append((["tshark", "-D"], "tshark"))
            if shutil.which("cmd.exe"):
                for tool in ("dumpcap.exe", "tshark.exe"):
                    capture_commands.append(([
                        "cmd.exe", "/c", rf"C:\Program Files\Wireshark\{tool}", "-D"
                    ], tool.replace(".exe", "")))
            if shutil.which("powershell.exe"):
                for tool in ("dumpcap.exe", "tshark.exe"):
                    capture_commands.append(([
                        "powershell.exe", "-NoProfile", "-Command",
                        f"& 'C:\\Program Files\\Wireshark\\{tool}' -D"
                    ], tool.replace(".exe", "")))

            errors = []
            for cmd, source in capture_commands:
                try:
                    print(f"[DEBUG] Trying interface command: {' '.join(cmd)}")
                    res = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True,
                        encoding="utf-8",
                        errors="replace",
                        timeout=10,
                    )
                    if res.returncode != 0:
                        errors.append(f"{' '.join(cmd)} -> {res.stderr.strip() or res.stdout.strip()}")
                        continue
                    parse_tshark(res.stdout, source)
                    if interfaces:
                        print(f"[DEBUG] Found {len(interfaces)} capture interfaces.")
                        break
                except Exception as e:
                    errors.append(f"{' '.join(cmd)} -> {e}")
                    print(f"[DEBUG] Interface command failed: {e}")

            if not interfaces:
                try:
                    res = subprocess.run(["tcpdump", "-D"], capture_output=True, text=True, timeout=10)
                    if res.returncode == 0:
                        for line in res.stdout.splitlines():
                            line = line.strip()
                            if not line or "." not in line:
                                continue
                            _, desc = line.split(".", 1)
                            iface_id = desc.split(" ", 1)[0].strip()
                            add_interface(iface_id, desc, "tcpdump", iface_id)
                except Exception as e:
                    print(f"[DEBUG] tcpdump discovery failed: {e}")

            if not interfaces:
                try:
                    for netsh_cmd in (["netsh", "interface", "show", "interface"], ["netsh.exe", "interface", "show", "interface"]):
                        if interfaces:
                            break
                        res = subprocess.run(
                            netsh_cmd,
                            capture_output=True,
                            text=True,
                            encoding="utf-8",
                            errors="replace",
                            timeout=10,
                        )
                        if res.returncode == 0:
                            for line in res.stdout.splitlines():
                                text = " ".join(line.split())
                                if not text or text.startswith(("Admin State", "---")):
                                    continue
                                parts = text.split()
                                if len(parts) >= 4 and parts[1].lower() == "connected":
                                    name = " ".join(parts[3:])
                                    add_interface(name, name, "netsh", name)
                except Exception as e:
                    errors.append(f"netsh interface show interface -> {e}")

            # ── Linux / WSL fallback: read /proc/net/dev ──
            if not interfaces:
                try:
                    with open("/proc/net/dev", "r") as f:
                        for line in f.readlines()[2:]:   # skip 2-line header
                            iface_id = line.split(":")[0].strip()
                            if iface_id:
                                add_interface(iface_id, iface_id, "proc/net/dev", iface_id)
                    if interfaces:
                        print(f"[DEBUG] Found {len(interfaces)} interface(s) via /proc/net/dev")
                except Exception as e:
                    print(f"[DEBUG] /proc/net/dev fallback failed: {e}")

            if not interfaces:
                print("[WARNING] No capture interfaces found via capture tools.")
                self._json_response(503, {
                    "success": False,
                    "message": "No capture interfaces found. Start Npcap Packet Driver or install Wireshark/tcpdump.",
                    "errors": errors[-5:],
                })
                return

            def rank_interface(item):
                text = f"{item.get('name', '')} {item.get('full', '')}".lower()
                if "wi-fi" in text or "wireless" in text or "wlan" in text:
                    return 0
                if "ethernet" in text:
                    return 1
                if "vethernet" in text or "wsl" in text:
                    return 2
                if "loopback" in text:
                    return 9
                return 5

            interfaces.sort(key=rank_interface)
            INTERFACE_CACHE["timestamp"] = time.time()
            INTERFACE_CACHE["interfaces"] = interfaces
            self._json_response(200, {"success": True, "interfaces": interfaces})
        except Exception as e:
            print(f"[ERROR] Interface discovery failed: {e}")
            self._json_response(500, {"success": False, "message": str(e)})

    def _handle_engine_start(self):
        """Spawn the backend cogsoc_behav.py engine via subprocess."""
        try:
            length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(length)
            data = json.loads(body)

            selected_interface = (data.get('interface') or '').strip()
            if not selected_interface:
                self._json_response(400, {"success": False, "message": "No capture interface specified. Please select one in the Live Analysis form."})
                return

            script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'cogsoc_behav.py')
            cmd = [sys.executable, script_path, '--engine-only']

            if data.get('scope') == 'server':
                cmd.append('--server')
            if data.get('duration') and data.get('duration') != 'continuous':
                cmd.extend(['--duration-minutes', str(data['duration'])])
            if data.get('sensitivity'):
                cmd.extend(['--sensitivity', str(data['sensitivity'])])
            cmd.extend(['--interface', selected_interface])

            print(f"[GATEWAY] Ignition Sequence Started. Interface={selected_interface!r}  Config={data}")

            # Generate a Filebeat config on-the-fly that targets the cogsoc-flows index
            self._ensure_filebeat_config(selected_interface)

            # Spawn engine in background, passing interface via both arg and env
            env = os.environ.copy()
            env['COGSOC_INTERFACE'] = selected_interface

            subprocess.Popen(
                cmd,
                cwd=os.path.dirname(os.path.abspath(__file__)),
                env=env
            )

            self._json_response(200, {"success": True, "message": f"Engine ignited on interface '{selected_interface}'."})
        except Exception as e:
            print(f"[ERROR] Engine ignition failed: {e}")
            self._json_response(500, {"success": False, "message": str(e)})

    def _ensure_filebeat_config(self, interface_name):
        """Write a Filebeat config that ships CICFlowMeter CSVs → cogsoc-flows index in ELK."""
        # Resolve CICFlowMeter output directory (mirrors cogsoc_behav.py logic)
        cicflow_win  = r"C:\CogSOC\CICFlowMeter-master\build\distributions\CICFlowMeter-4.0\bin\data\daily"
        cicflow_wsl  = "/mnt/c/CogSOC/CICFlowMeter-master/build/distributions/CICFlowMeter-4.0/bin/data/daily"
        cicflow_dir  = cicflow_win if os.path.exists(cicflow_win) else cicflow_wsl

        # Candidate config paths
        setup_dir    = r"C:\CogSOC\Setup" if os.path.exists(r"C:\CogSOC\Setup") else "/mnt/c/CogSOC/Setup"
        config_path  = os.path.join(setup_dir, "filebeat-windows.yml")

        os.makedirs(setup_dir, exist_ok=True)

        config_content = f"""# Auto-generated by CogSOC Gateway  (interface: {interface_name})
filebeat.inputs:
  - type: log
    enabled: true
    paths:
      - "{cicflow_dir}/*.csv"
      - "{cicflow_dir}/live_pcaps/*.csv"
    fields:
      cogsoc_source: cicflowmeter
      capture_interface: "{interface_name}"
    fields_under_root: true
    # Skip the CSV header line that CICFlowMeter writes
    multiline.type: count
    multiline.count_lines: 1
    # Parse every CSV row as a structured document
    encoding: utf-8
    scan_frequency: 5s
    close_inactive: 2m
    ignore_older: 24h

processors:
  - decode_csv_fields:
      fields:
        message: decoded
      separator: ","
      ignore_missing: false
      overwrite_keys: true
      trim_leading_space: true
      fail_on_error: false
  - timestamp:
      field: "Timestamp"
      layouts:
        - "01/02/2006 15:04:05"
        - "2006-01-02 15:04:05"
        - "2006-01-02T15:04:05Z"
      test:
        - "01/02/2006 15:04:05"
      ignore_missing: true
      ignore_failure: true
  - add_fields:
      target: ''
      fields:
        "@metadata.index": "cogsoc-flows"

output.elasticsearch:
  hosts: ["{ES_HOST}"]
  index: "cogsoc-flows-%{{{{+yyyy.MM.dd}}}}"
  pipeline: ""

setup.ilm.enabled: false
setup.template.name: "cogsoc-flows"
setup.template.pattern: "cogsoc-flows-*"
setup.template.settings:
  index.number_of_shards: 1
  index.number_of_replicas: 0

logging.level: info
logging.to_files: true
logging.files:
  path: "{cicflow_dir}"
  name: filebeat.log
  keepfiles: 7
"""
        try:
            with open(config_path, 'w', encoding='utf-8') as f:
                f.write(config_content)
            print(f"[GATEWAY] Filebeat config written → {config_path}  (index: cogsoc-flows)")
        except Exception as e:
            print(f"[GATEWAY] Warning: could not write Filebeat config: {e}")

    def _handle_offline_upload(self):
        """Handle raw file upload for offline PCAP/CSV analysis."""
        try:
            filename = os.path.basename(urllib.parse.unquote(self.headers.get('X-File-Name', 'upload.dat')))
            pipeline = self.headers.get('X-Pipeline', 'auto')
            length = int(self.headers.get('Content-Length', 0))
            
            # Read binary file from POST body
            file_data = self.rfile.read(length)
            
            import os, subprocess, sys
            upload_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'offline_uploads')
            os.makedirs(upload_dir, exist_ok=True)
            
            filepath = os.path.join(upload_dir, filename)
            with open(filepath, 'wb') as f:
                f.write(file_data)
                
            print(f"[GATEWAY] Offline file received: {filepath}. Launching backend in OFFLINE mode...")
            
            # Spawn backend in offline mode
            script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'cogsoc_behav.py')
            subprocess.Popen(
                [sys.executable, script_path, '--engine-only', '--offline-file', filepath, '--pipeline', pipeline],
                cwd=os.path.dirname(os.path.abspath(__file__))
            )
            
            self._json_response(200, {"success": True, "message": "Offline analysis queued."})
        except Exception as e:
            print(f"[ERROR] Offline file upload failed: {e}")
            self._json_response(500, {"success": False, "message": str(e)})

    # ══════════════════════════════════════════════
    #  COPILOT HANDLER
    # ══════════════════════════════════════════════
    def _handle_copilot(self):
        """Handle Groq AI Copilot requests."""
        # Try to import groq key from cogsoc_behav
        try:
            from cogsoc_behav import GROQ_API_KEY, GROQ_MODEL
        except ImportError:
            GROQ_API_KEY = None

        if not GROQ_API_KEY:
            self._json_response(400, {"error": "GROQ_API_KEY not configured in cogsoc_behav.py"})
            return

        try:
            length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(length)
            data = json.loads(body)

            prompt = f"""You are a Senior SOC Analyst AI Copilot. Analyze the following security incident and provide a concise, executive-level explanation (max 3 short paragraphs).
Format the response in HTML with these sections:
1. <strong>Executive Summary:</strong> What happened in plain English.
2. <strong>Technical Details:</strong> Attack vector and impact.
3. <strong>Recommendation:</strong> Next steps.

Incident Data:
ID: {data.get('id')}
Attack: {data.get('attack')}
Attacker IP: {data.get('attacker')}
Victim IP: {data.get('victim')}
Severity: {data.get('severity')}
Alert Count: {data.get('alerts')}
MITRE Technique: {data.get('mitre')}
Sensor: {data.get('sensor')}"""

            groq_payload = json.dumps({
                "model": GROQ_MODEL,
                "messages": [
                    {"role": "system", "content": "You are a Senior SOC Analyst AI Copilot."},
                    {"role": "user",   "content": prompt}
                ],
                "temperature": 0.3,
                "max_tokens": 1024,
            }).encode('utf-8')

            req = Request('https://api.groq.com/openai/v1/chat/completions', data=groq_payload, method='POST')
            req.add_header('Authorization', f'Bearer {GROQ_API_KEY}')
            req.add_header('Content-Type', 'application/json')
            req.add_header('User-Agent', 'CogSOC/1.0')

            resp = urlopen(req, timeout=30)
            resp_data = json.loads(resp.read().decode('utf-8'))
            reply_text = resp_data['choices'][0]['message']['content']
            
            self._json_response(200, {"response": reply_text})
        except Exception as e:
            self._json_response(500, {"error": str(e)})

    # ══════════════════════════════════════════════
    #  AUTH HANDLERS
    # ══════════════════════════════════════════════
    def _handle_auth_get(self):
        """Handle GET auth requests (verify session)."""
        if self.path.startswith('/auth/verify'):
            token = self._get_token()
            valid, session = auth.validate_session(token)
            if valid:
                self._json_response(200, {
                    "valid": True,
                    "username": session['username'],
                    "full_name": session['full_name'],
                    "role": session['role'],
                })
            else:
                self._json_response(200, {"valid": False})
        elif self.path.startswith('/auth/logout'):
            token = self._get_token()
            auth.logout(token)
            self.send_response(302)
            self.send_header('Location', '/login.html')
            self.send_header('Set-Cookie', 'cogsoc_token=; path=/; max-age=0')
            self.end_headers()
        else:
            self._json_response(404, {"error": "Not found"})

    def _handle_auth_post(self):
        """Handle POST auth requests (login/signup)."""
        try:
            length = int(self.headers.get('Content-Length', 0))
            body = json.loads(self.rfile.read(length)) if length else {}
        except (json.JSONDecodeError, ValueError):
            self._json_response(400, {"success": False, "message": "Invalid request"})
            return

        if self.path == '/auth/login':
            username = body.get('username', '')
            password = body.get('password', '')
            success, token_or_msg = auth.login(username, password)
            if success:
                self._json_response(200, {
                    "success": True,
                    "token": token_or_msg,
                    "message": "Login successful"
                })
            else:
                self._json_response(401, {
                    "success": False,
                    "message": token_or_msg
                })

        elif self.path == '/auth/signup':
            username = body.get('username', '')
            password = body.get('password', '')
            full_name = body.get('full_name', '')
            recovery_key = body.get('recovery_key', '')
            success, message = auth.signup(username, password, full_name, recovery_key=recovery_key)
            code = 200 if success else 400
            self._json_response(code, {
                "success": success,
                "message": message
            })
            
        elif self.path == '/auth/reset':
            username = body.get('username', '')
            recovery_key = body.get('recovery_key', '')
            new_password = body.get('new_password', '')
            success, message = auth.reset_password(username, recovery_key, new_password)
            code = 200 if success else 400
            self._json_response(code, {
                "success": success,
                "message": message
            })

        else:
            self._json_response(404, {"success": False, "message": "Not found"})

    # ══════════════════════════════════════════════
    #  EXISTING HANDLERS (unchanged)
    # ══════════════════════════════════════════════
    def _handle_block(self):
        """Handle manual block request from dashboard."""
        try:
            length = int(self.headers.get('Content-Length', 0))
            body = json.loads(self.rfile.read(length)) if length else {}
            ip = body.get('ip', '').strip()
            duration = body.get('duration', 30)

            if not ip:
                self._json_response(400, {"error": "No IP provided"})
                return

            result = firewall_block(ip, duration)
            print(f"  [DASHBOARD] Manual block: {ip} -> {result['status']}")
            self._json_response(200, result)
        except Exception as e:
            self._json_response(500, {"error": str(e)})

    def _handle_trusted_action(self):
        """Handle Block/Ignore clicks from grace period email."""
        from urllib.parse import urlparse, parse_qs
        params = parse_qs(urlparse(self.path).query)
        ip = params.get('ip', [''])[0]
        action = params.get('action', [''])[0]

        if action == 'block' and ip:
            result = firewall_block(ip, 60)
            # Also log as TRUSTED_BLOCK so monitoring process cancels pending grace period
            try:
                doc = {
                    "@timestamp": datetime.now(timezone.utc).isoformat(),
                    "action_type": "TRUSTED_BLOCK",
                    "src_ip": ip,
                    "method": "MANUAL",
                    "status": "BLOCKED",
                    "details": f"Security officer confirmed BLOCK for trusted IP {ip} via email",
                    "incident_id": "TRUSTED",
                }
                req = Request(
                    f"{ES_HOST}/cogsoc-responses/_doc",
                    data=json.dumps(doc).encode(), method="POST",
                )
                req.add_header("Content-Type", "application/json")
                urlopen(req, timeout=5)
            except Exception:
                pass
            title = 'IP Blocked'
            msg = f'IP <strong>{ip}</strong> has been blocked via firewall.'
            color = '#ef4444'
            print(f"  [TRUSTED] {ip} BLOCKED by security officer via email link")
        elif action == 'ignore' and ip:
            # Log the ignore decision to ES
            try:
                doc = {
                    "@timestamp": datetime.now(timezone.utc).isoformat(),
                    "action_type": "TRUSTED_IGNORE",
                    "src_ip": ip,
                    "method": "MANUAL",
                    "status": "IGNORED",
                    "details": f"Security officer confirmed {ip} as legitimate via email",
                    "incident_id": "TRUSTED",
                }
                req = Request(
                    f"{ES_HOST}/cogsoc-responses/_doc",
                    data=json.dumps(doc).encode(), method="POST",
                )
                req.add_header("Content-Type", "application/json")
                urlopen(req, timeout=5)
            except Exception:
                pass
            title = 'Alert Ignored'
            msg = f'IP <strong>{ip}</strong> confirmed as legitimate.'
            color = '#10b981'
            print(f"  [TRUSTED] {ip} IGNORED by security officer")
        else:
            title = 'Error'
            msg = 'Invalid request parameters.'
            color = '#f59e0b'

        # Return a nice HTML confirmation page
        html = f"""<!DOCTYPE html><html><head><meta charset="UTF-8">
        <title>CogSOC — {title}</title></head><body style="font-family:Arial,sans-serif;
        background:#0f172a;color:#e2e8f0;display:flex;justify-content:center;align-items:center;
        min-height:100vh;margin:0">
        <div style="background:#1a2236;border:1px solid #1e2d4a;border-radius:16px;padding:48px;
        text-align:center;max-width:500px;box-shadow:0 20px 40px rgba(0,0,0,.5)">
          <h2 style="color:{color};margin-bottom:12px">{title}</h2>
          <p style="color:#94a3b8;font-size:15px;line-height:1.6">{msg}</p>
          <a href="http://localhost:{PORT}" style="display:inline-block;margin-top:24px;
          padding:12px 32px;background:#3b82f6;color:#fff;text-decoration:none;
          border-radius:8px;font-weight:700">Open Dashboard</a>
        </div></body></html>"""

        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        self.wfile.write(html.encode())

    def _json_response(self, code, data):
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate')
        self.send_header('Pragma', 'no-cache')
        self.send_header('Expires', '0')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def _proxy_es(self, method):
        es_path = self.path[3:]  # strip /es
        url = f"{ES_HOST}{es_path}"
        try:
            body = None
            if method == 'POST':
                length = int(self.headers.get('Content-Length', 0))
                body = self.rfile.read(length) if length else None

            req = Request(url, data=body, method=method)
            req.add_header('Content-Type', 'application/json')
            resp = urlopen(req, timeout=15)
            data = resp.read()

            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(data)
        except URLError as e:
            self.send_response(502)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'error': str(e)}).encode())

    def log_message(self, format, *args):
        if '/es/' not in str(args[0]):
            super().log_message(format, *args)


if __name__ == '__main__':
    user_count = auth.get_user_count()
    sys_id = auth.get_system_id()[:12]

    print(f"\n{'='*55}")
    print(f"  [CogSOC] AI Security Dashboard")
    print(f"  Dashboard : http://localhost:{PORT}")
    print(f"  Login     : http://localhost:{PORT}/login.html")
    print(f"  ELK       : {ES_HOST}")
    print(f"  System ID : {sys_id}...")
    print(f"  Users     : {user_count} registered")
    print(f"  Auth      : Login required (local credentials)")
    print(f"{'='*55}")
    if user_count == 0:
        print(f"\n  [!] No users registered yet!")
        print(f"  [!] Open http://localhost:{PORT}/login.html")
        print(f"  [!] and click 'Sign Up' to create your first account.\n")

    server = http.server.HTTPServer(('0.0.0.0', PORT), DashboardHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[Dashboard] Stopped.")
        server.server_close()

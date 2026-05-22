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
ACTIVE_PROCESSES = []
ENGINE_RUNNING = False


def _kill_active_engines():
    """Kill ALL existing CogSOC engine processes before starting new ones.
    Also kills any stale tshark/cfm/filebeat processes that may hold the
    Npcap adapter lock."""
    global ACTIVE_PROCESSES, ENGINE_RUNNING

    killed = 0

    # 1. Kill tracked child processes
    for p in ACTIVE_PROCESSES:
        try:
            if p.poll() is None:  # still running
                subprocess.call(
                    ['taskkill', '/F', '/T', '/PID', str(p.pid)],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                )
                killed += 1
        except Exception:
            pass
    ACTIVE_PROCESSES.clear()

    # 2. Kill stale system-wide processes that lock the Npcap adapter
    for proc_name in ['tshark.exe', 'dumpcap.exe', 'filebeat.exe']:
        try:
            subprocess.call(
                ['taskkill', '/F', '/IM', proc_name],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
        except Exception:
            pass

    # 3. Kill any orphaned cogsoc_behav / traffic_capture python processes
    #    (but NOT our own dashboard.py)
    try:
        import re
        result = subprocess.run(
            ['wmic', 'process', 'where',
             "name='python.exe' or name='python3.exe'",
             'get', 'processid,commandline'],
            capture_output=True, text=True, timeout=5,
        )
        my_pid = os.getpid()
        for line in result.stdout.splitlines():
            if ('cogsoc_behav' in line or 'traffic_capture' in line):
                # Extract PID (last number on the line)
                nums = re.findall(r'\d+', line)
                if nums:
                    pid = int(nums[-1])
                    if pid != my_pid:
                        subprocess.call(
                            ['taskkill', '/F', '/T', '/PID', str(pid)],
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                        )
                        killed += 1
    except Exception:
        pass

    ENGINE_RUNNING = False
    if killed:
        print(f"[GATEWAY] Cleaned up {killed} old engine process(es)")
        time.sleep(1)  # brief pause so Npcap adapter is released
    return killed


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

        if self.path.startswith('/api/engine/status'):
            if not self._is_authenticated():
                self._json_response(401, {"error": "Authentication required"})
                return
            alive = sum(1 for p in ACTIVE_PROCESSES if p.poll() is None)
            self._json_response(200, {
                "running": ENGINE_RUNNING and alive > 0,
                "processes": alive,
                "total_spawned": len(ACTIVE_PROCESSES),
            })
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
        if self.path == '/api/engine/stop':
            self._handle_engine_stop()
            return
        if self.path == '/api/feedback':
            self._handle_feedback()
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
        print("[DASHBOARD] Fetching host network interfaces (Hardcoded)...")
        try:
            interfaces = [
                {"id": "\\Device\\NPF_{E2EF1819-72DD-478B-ADE3-43FA305A77E7}", "full": "Wi-Fi", "name": "Wi-Fi", "source": "hardcoded"}
            ]
            self._json_response(200, {"success": True, "interfaces": interfaces})
        except Exception as e:
            print(f"[ERROR] Interface discovery failed: {e}")
            self._json_response(500, {"success": False, "message": str(e)})

    def _handle_engine_start(self):
        """
        Spawn cogsoc_behav.py --engine-only in the background.
        This triggers automatic CICFlowMeter capture + Filebeat pipeline.
        IMPORTANT: Kills ALL existing engine processes first to prevent
        Npcap adapter lock conflicts from zombie tshark processes.
        """
        global ENGINE_RUNNING
        try:
            length = int(self.headers.get('Content-Length', 0))
            body   = self.rfile.read(length)
            data   = json.loads(body)

            interface = (data.get('interface') or '').strip()
            
            if interface.lower() == "auto":
                interface = "\\Device\\NPF_{E2EF1819-72DD-478B-ADE3-43FA305A77E7}"
                    
            if not interface:
                self._json_response(400, {
                    "success": False,
                    "message": "No capture interface provided."
                })
                return

            # ╔══════════════════════════════════════════════╗
            # ║  KILL OLD ENGINES BEFORE STARTING NEW ONES   ║
            # ║  This prevents tshark Npcap adapter locks    ║
            # ╚══════════════════════════════════════════════╝
            old_killed = _kill_active_engines()
            if old_killed:
                print(f"[GATEWAY] Cleaned up {old_killed} stale process(es) before restart")

            script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'cogsoc_behav.py')
            capture_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'traffic_capture.py')
            
            cmd_ai = [sys.executable, '-u', script_path, '--engine-only']
            cmd_cap = [sys.executable, '-u', capture_path]

            # Pass selected interface — critical for CICFlowMeter to know what to capture
            cmd_ai.extend(['--interface', interface])
            cmd_cap.extend(['--interface', interface])

            if data.get('scope') == 'server':
                cmd_ai.append('--server')
            if data.get('duration') and str(data.get('duration')) not in ('continuous', ''):
                cmd_ai.extend(['--duration-minutes', str(data['duration'])])
                cmd_cap.extend(['--duration-minutes', str(data['duration'])])
            if data.get('sensitivity'):
                cmd_ai.extend(['--sensitivity', str(data['sensitivity'])])
                cmd_cap.extend(['--sensitivity', str(data['sensitivity'])])

            # Propagate via env too so any module that reads os.environ gets it
            env = os.environ.copy()
            env['COGSOC_INTERFACE'] = interface
            env['COGSOC_LIVE_CHUNK_SECONDS'] = '3'  # 3-second capture chunks for very fast UI updates

            print(f"[GATEWAY] ═══════════════════════════════════════")
            print(f"[GATEWAY]  Igniting CogSOC Distributed Engines")
            print(f"[GATEWAY]  Interface : {interface}")
            print(f"[GATEWAY]  Sensitivity: {data.get('sensitivity', 'medium')}")
            print(f"[GATEWAY]  Duration  : {data.get('duration', 'continuous')}")
            if old_killed:
                print(f"[GATEWAY]  Cleanup   : Killed {old_killed} old process(es)")
            print(f"[GATEWAY] ═══════════════════════════════════════")

            # Spawn AI Analysis Engine
            p1 = subprocess.Popen(
                cmd_ai,
                cwd=os.path.dirname(os.path.abspath(__file__)),
                env=env,
            )
            ACTIVE_PROCESSES.append(p1)
            
            if interface.lower() != 'none':
                # Spawn Traffic Capture Engine
                p2 = subprocess.Popen(
                    cmd_cap,
                    cwd=os.path.dirname(os.path.abspath(__file__)),
                    env=env,
                )
                ACTIVE_PROCESSES.append(p2)
                msg = f"Distributed engines ignited on interface '{interface}'. Traffic capture & AI starting in parallel..."
            else:
                msg = "AI Analysis engine ignited (Fetching from ELK). Traffic capture bypassed."

            ENGINE_RUNNING = True
            self._json_response(200, {
                "success": True,
                "message": msg
            })
        except Exception as e:
            print(f"[ERROR] Engine ignition failed: {e}")
            self._json_response(500, {"success": False, "message": str(e)})

    def _handle_engine_stop(self):
        """Stop all running engine processes."""
        global ENGINE_RUNNING
        try:
            killed = _kill_active_engines()
            ENGINE_RUNNING = False
            print(f"[GATEWAY] Engine stopped. Killed {killed} process(es).")
            self._json_response(200, {
                "success": True,
                "message": f"Engine stopped. {killed} process(es) terminated."
            })
        except Exception as e:
            print(f"[ERROR] Engine stop failed: {e}")
            self._json_response(500, {"success": False, "message": str(e)})

    def _handle_feedback(self):
        """Handle analyst disposition (True/False Positive) and update Elasticsearch."""
        try:
            length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(length)
            data = json.loads(body)
            doc_id = data.get('doc_id')
            feedback = data.get('feedback')

            if not doc_id or not feedback:
                self._json_response(400, {"success": False, "message": "Missing doc_id or feedback"})
                return

            print(f"[FEEDBACK] Alert {doc_id} marked as {feedback}")
            es_url = "http://localhost:9200/cogsoc-alerts/_update/" + urllib.parse.quote(doc_id)
            
            update_body = {
                "doc": {
                    "feedback": feedback,
                    "action": "CLOSED_FP" if "FP" in feedback or "Benign" in feedback else "CONFIRMED_TP"
                }
            }
            
            req = urllib.request.Request(es_url, data=json.dumps(update_body).encode('utf-8'),
                                         headers={'Content-Type': 'application/json'}, method='POST')
            try:
                with urllib.request.urlopen(req) as response:
                    res_data = json.loads(response.read().decode())
                    if res_data.get('result') in ['updated', 'noop']:
                        self._json_response(200, {"success": True})
                    else:
                        self._json_response(500, {"success": False, "message": str(res_data)})
            except urllib.error.URLError as e:
                self._json_response(500, {"success": False, "message": str(e)})
                
        except Exception as e:
            print(f"[ERROR] Feedback processing failed: {e}")
            self._json_response(500, {"success": False, "message": str(e)})

    def _handle_offline_upload(self):
        """Handle raw file upload for offline PCAP/CSV analysis."""
        try:
            filename = os.path.basename(urllib.parse.unquote(self.headers.get('X-File-Name', 'upload.dat')))
            pipeline = self.headers.get('X-Pipeline', 'auto')
            length = int(self.headers.get('Content-Length', 0))
            upload_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'offline_uploads')
            os.makedirs(upload_dir, exist_ok=True)
            
            filepath = os.path.join(upload_dir, filename)
            with open(filepath, 'wb') as f:
                bytes_left = length
                while bytes_left > 0:
                    chunk = self.rfile.read(min(bytes_left, 8192 * 1024))
                    if not chunk:
                        break
                    f.write(chunk)
                    bytes_left -= len(chunk)
                
            print(f"[GATEWAY] Offline file received: {filepath}. Launching backend in OFFLINE mode...")
            
            # Spawn backend in offline mode
            script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'cogsoc_behav.py')
            p3 = subprocess.Popen(
                [sys.executable, script_path, '--engine-only', '--offline-file', filepath, '--pipeline', pipeline],
                cwd=os.path.dirname(os.path.abspath(__file__))
            )
            ACTIVE_PROCESSES.append(p3)
            
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
        es_path = urllib.parse.unquote(self.path[3:])  # strip /es and unquote
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
        except Exception as e:
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

    from http.server import ThreadingHTTPServer
    server = ThreadingHTTPServer(('0.0.0.0', PORT), DashboardHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[Dashboard] Stopped. Terminating background processes...")
        import sys
        for p in ACTIVE_PROCESSES:
            try:
                if sys.platform == 'win32':
                    subprocess.call(['taskkill', '/F', '/T', '/PID', str(p.pid)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                else:
                    p.terminate()
            except Exception:
                pass
        server.server_close()
        os._exit(0)
"""
CogSOC Test Target — Web Application
A simple web app with login, search, and comments pages.
Host this locally so CogSOC AI can detect attack traffic patterns
(brute force, scanning, flood, etc.) at the network flow level.

Run:   python server.py
Open:  http://localhost:8080
"""

import http.server
import json
import os
import sys
import time
import urllib.parse
import html
from http.server import ThreadingHTTPServer
from datetime import datetime

PORT = 8080
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))

# Simple in-memory store
USERS = {"admin": "SuperSecure123!", "analyst": "CogSOC2024"}
COMMENTS = []
SEARCH_LOG = []
LOGIN_ATTEMPTS = []


class TargetHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=ROOT_DIR, **kwargs)

    # ── GET ──
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == "/" or path == "/index.html":
            self._serve_file("index.html")
        elif path == "/login":
            self._serve_file("login.html")
        elif path == "/search":
            self._serve_file("search.html")
        elif path == "/comments":
            self._serve_file("comments.html")
        elif path == "/admin":
            self._serve_file("admin.html")
        elif path == "/api/comments":
            self._json(200, {"comments": COMMENTS[-50:]})
        elif path == "/api/stats":
            self._json(200, {
                "total_logins": len(LOGIN_ATTEMPTS),
                "total_searches": len(SEARCH_LOG),
                "total_comments": len(COMMENTS),
                "uptime": "running",
            })
        elif path.startswith("/api/search"):
            q = urllib.parse.parse_qs(parsed.query).get("q", [""])[0]
            SEARCH_LOG.append({"query": q, "time": datetime.now().isoformat()})
            # Return safe mock results
            self._json(200, {
                "query": html.escape(q),
                "results": [
                    {"title": "Network Security Basics", "snippet": "Introduction to firewalls and IDS..."},
                    {"title": "CogSOC Documentation", "snippet": "AI-driven autonomous defense platform..."},
                    {"title": "MITRE ATT&CK Framework", "snippet": "Knowledge base of adversary tactics..."},
                ],
                "count": 3,
            })
        else:
            # Try to serve static file
            return super().do_GET()

    # ── POST ──
    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        try:
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8", errors="ignore") if length else ""
        except Exception:
            body = ""

        # Try JSON first, then form-encoded
        data = {}
        content_type = self.headers.get("Content-Type", "")
        if "json" in content_type:
            try:
                data = json.loads(body)
            except json.JSONDecodeError:
                data = {}
        else:
            data = dict(urllib.parse.parse_qsl(body))

        if path == "/api/login":
            username = data.get("username", "")
            password = data.get("password", "")
            LOGIN_ATTEMPTS.append({
                "username": username,
                "time": datetime.now().isoformat(),
                "ip": self.client_address[0],
            })
            # Artificial delay to make brute force patterns visible in flows
            time.sleep(0.3)
            if username in USERS and USERS[username] == password:
                self._json(200, {"success": True, "message": "Login successful", "token": "session_abc123"})
            else:
                self._json(401, {"success": False, "message": "Invalid credentials"})

        elif path == "/api/comment":
            name = html.escape(data.get("name", "Anonymous"))
            text = html.escape(data.get("comment", ""))
            if text:
                COMMENTS.append({
                    "name": name,
                    "comment": text,
                    "time": datetime.now().isoformat(),
                })
                self._json(200, {"success": True, "message": "Comment posted"})
            else:
                self._json(400, {"success": False, "message": "Empty comment"})

        elif path == "/api/search":
            q = data.get("q", "")
            SEARCH_LOG.append({"query": q, "time": datetime.now().isoformat()})
            self._json(200, {
                "query": html.escape(q),
                "results": [
                    {"title": "Network Security Basics", "snippet": "Introduction to firewalls and IDS..."},
                    {"title": "CogSOC Documentation", "snippet": "AI-driven autonomous defense platform..."},
                ],
                "count": 2,
            })
        else:
            self._json(404, {"error": "Not found"})

    # ── Helpers ──
    def _serve_file(self, filename):
        filepath = os.path.join(ROOT_DIR, filename)
        if not os.path.exists(filepath):
            self.send_error(404)
            return
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(content.encode("utf-8"))))
        self.end_headers()
        self.wfile.write(content.encode("utf-8"))

    def _json(self, code, data):
        body = json.dumps(data).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        ts = datetime.now().strftime("%H:%M:%S")
        print(f"  [{ts}] {self.client_address[0]} — {format % args}")


if __name__ == "__main__":
    print(f"\n{'='*60}")
    print(f"  CogSOC Test Target — Web Application")
    print(f"  URL     : http://localhost:{PORT}")
    print(f"  Login   : http://localhost:{PORT}/login")
    print(f"  Search  : http://localhost:{PORT}/search")
    print(f"  Comments: http://localhost:{PORT}/comments")
    print(f"  Admin   : http://localhost:{PORT}/admin")
    print(f"{'='*60}")
    print(f"  This app is a TEST TARGET for CogSOC AI detection.")
    print(f"  Run CogSOC with live capture to monitor traffic.\n")

    server = ThreadingHTTPServer(("0.0.0.0", PORT), TargetHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[Server] Stopped.")
        server.server_close()

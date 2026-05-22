"""
CogSOC Traffic Generator — Generate test traffic for AI detection validation.
Sends various HTTP request patterns to the local test website,
creating distinct network flow profiles that CogSOC AI can detect.

Usage:
    python traffic_generator.py --mode normal       # Baseline normal traffic
    python traffic_generator.py --mode brute        # Rapid login attempts
    python traffic_generator.py --mode scan         # Web path scanning
    python traffic_generator.py --mode flood        # High volume GET flood
    python traffic_generator.py --mode sqli         # SQL Injection attempts
    python traffic_generator.py --mode xss          # Cross-Site Scripting (XSS) attempts
    python traffic_generator.py --mode all          # Run all tests sequentially

Target: http://localhost:8080  (SecureCorp test website)
"""

import argparse
import json
import time
import sys
import random
import string
import threading
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# ── Configuration ──
TARGET = "http://localhost:8080"
THREADS = 10

# ── Color output for Windows ──
class Colors:
    CYAN    = "\033[96m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    RED     = "\033[91m"
    MAGENTA = "\033[95m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RESET   = "\033[0m"

def log(icon, color, msg):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"  {Colors.DIM}[{ts}]{Colors.RESET} {color}{icon}{Colors.RESET} {msg}")


# ══════════════════════════════════════════════════════
#  REQUEST HELPERS
# ══════════════════════════════════════════════════════

def http_get(path, timeout=5):
    """Send a GET request, return (status_code, success)."""
    try:
        url = f"{TARGET}{path}"
        req = Request(url, method="GET")
        req.add_header("User-Agent", "CogSOC-TrafficGen/1.0")
        resp = urlopen(req, timeout=timeout)
        return resp.status, True
    except HTTPError as e:
        return e.code, True  # server responded (even with error)
    except Exception:
        return 0, False


def http_post(path, data, timeout=5):
    """Send a POST request with JSON body, return (status_code, success)."""
    try:
        url = f"{TARGET}{path}"
        body = json.dumps(data).encode("utf-8")
        req = Request(url, data=body, method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("User-Agent", "CogSOC-TrafficGen/1.0")
        resp = urlopen(req, timeout=timeout)
        return resp.status, True
    except HTTPError as e:
        return e.code, True
    except Exception:
        return 0, False


def random_string(length=8):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))


# ══════════════════════════════════════════════════════
#  TEST 1: NORMAL BASELINE TRAFFIC
# ══════════════════════════════════════════════════════

def run_normal(duration=30):
    """
    Simulate normal user browsing:
      - Visit home, search, comments pages at human pace
      - 1-3 second gaps between requests
    
    Flow profile: Low packet rate, normal connection count, varied paths
    """
    print(f"\n{Colors.BOLD}{'='*65}{Colors.RESET}")
    print(f"  {Colors.GREEN}▶ TEST: Normal Baseline Traffic{Colors.RESET}")
    print(f"  {Colors.DIM}Duration: {duration}s | Pace: 1-3s between requests{Colors.RESET}")
    print(f"  {Colors.DIM}Purpose: Establish baseline flow patterns for comparison{Colors.RESET}")
    print(f"{Colors.BOLD}{'='*65}{Colors.RESET}\n")

    pages = ["/", "/login", "/search", "/comments", "/admin",
             "/api/stats", "/api/comments"]
    count = 0
    start = time.time()

    while time.time() - start < duration:
        page = random.choice(pages)
        status, ok = http_get(page)
        count += 1
        if ok:
            log("●", Colors.GREEN, f"GET {page} → {status}")
        else:
            log("✗", Colors.RED, f"GET {page} → FAILED")

        # Simulate a search occasionally
        if random.random() < 0.3:
            queries = ["security policy", "employee handbook", "IT support",
                       "password reset", "vpn setup", "meeting rooms"]
            q = random.choice(queries)
            status, ok = http_get(f"/api/search?q={q}")
            count += 1
            log("●", Colors.GREEN, f"SEARCH '{q}' → {status}")

        time.sleep(random.uniform(1.0, 3.0))

    elapsed = time.time() - start
    rps = count / elapsed if elapsed > 0 else 0
    print(f"\n  {Colors.GREEN}✓ Normal traffic complete: {count} requests in {elapsed:.0f}s ({rps:.1f} req/s){Colors.RESET}\n")
    return count


# ══════════════════════════════════════════════════════
#  TEST 2: BRUTE FORCE LOGIN ATTEMPTS
# ══════════════════════════════════════════════════════

def run_brute(count=100):
    """
    Simulate brute-force login:
      - Rapid POST requests to /api/login with different credentials
      - Minimal delay between attempts
    
    Flow profile: High connection rate to single port, many short-lived TCP sessions,
                  consistent packet sizes, high SYN count
    """
    print(f"\n{Colors.BOLD}{'='*65}{Colors.RESET}")
    print(f"  {Colors.YELLOW}▶ TEST: Brute Force Login Simulation{Colors.RESET}")
    print(f"  {Colors.DIM}Attempts: {count} | Target: POST /api/login{Colors.RESET}")
    print(f"  {Colors.DIM}Purpose: High-frequency auth requests → brute-force flow pattern{Colors.RESET}")
    print(f"{Colors.BOLD}{'='*65}{Colors.RESET}\n")

    # Common username/password combinations
    usernames = ["admin", "root", "administrator", "user", "test",
                 "guest", "manager", "operator", "sysadmin", "webadmin",
                 "support", "service", "backup", "ftp", "mail"]
    passwords = ["password", "123456", "admin", "12345678", "qwerty",
                 "abc123", "letmein", "welcome", "monkey", "master",
                 "dragon", "login", "princess", "football", "shadow"]

    success = 0
    failed = 0
    start = time.time()

    for i in range(count):
        user = random.choice(usernames)
        pwd = random.choice(passwords)
        status, ok = http_post("/api/login", {"username": user, "password": pwd}, timeout=3)

        if ok:
            if status == 200:
                success += 1
                log("★", Colors.GREEN, f"[{i+1}/{count}] {user}:{pwd} → {Colors.GREEN}SUCCESS{Colors.RESET}")
            else:
                failed += 1
                if i < 5 or i % 20 == 0:
                    log("✗", Colors.RED, f"[{i+1}/{count}] {user}:{pwd} → 401 DENIED")
                elif i == 5:
                    log("…", Colors.DIM, f"(continuing silently... showing every 20th attempt)")
        else:
            failed += 1
            log("✗", Colors.RED, f"[{i+1}/{count}] CONNECTION FAILED")

        # Very short delay — brute force is FAST
        time.sleep(random.uniform(0.02, 0.08))

    elapsed = time.time() - start
    rps = count / elapsed if elapsed > 0 else 0
    print(f"\n  {Colors.YELLOW}✓ Brute force complete: {count} attempts in {elapsed:.0f}s ({rps:.1f} req/s){Colors.RESET}")
    print(f"  {Colors.DIM}  Success: {success} | Failed: {failed}{Colors.RESET}\n")
    return count


# ══════════════════════════════════════════════════════
#  TEST 3: WEB PATH SCANNING
# ══════════════════════════════════════════════════════

def run_scan(count=200):
    """
    Simulate web directory/path scanning:
      - Rapid GET requests to many different paths
      - Mimics tools like gobuster/dirb/nikto
    
    Flow profile: Many connections, varied paths, high 404 rate,
                  rapid sequential connections, scanning pattern
    """
    print(f"\n{Colors.BOLD}{'='*65}{Colors.RESET}")
    print(f"  {Colors.MAGENTA}▶ TEST: Web Path Scanning Simulation{Colors.RESET}")
    print(f"  {Colors.DIM}Paths: {count} | Target: GET /{{path}}{Colors.RESET}")
    print(f"  {Colors.DIM}Purpose: Rapid path enumeration → web scanning flow pattern{Colors.RESET}")
    print(f"{Colors.BOLD}{'='*65}{Colors.RESET}\n")

    # Common paths that scanners probe for
    scan_paths = [
        "/admin", "/administrator", "/admin/login", "/admin/dashboard",
        "/wp-admin", "/wp-login.php", "/wp-content", "/wordpress",
        "/phpmyadmin", "/phpMyAdmin", "/pma", "/mysql",
        "/api", "/api/v1", "/api/v2", "/api/users", "/api/config",
        "/config", "/config.php", "/configuration", "/settings",
        "/backup", "/backup.sql", "/backup.zip", "/database",
        "/db", "/dump", "/sql", "/data",
        "/.env", "/.git", "/.git/config", "/.htaccess",
        "/robots.txt", "/sitemap.xml", "/crossdomain.xml",
        "/server-status", "/server-info", "/status",
        "/console", "/debug", "/test", "/dev",
        "/uploads", "/files", "/documents", "/images",
        "/cgi-bin", "/scripts", "/bin", "/tmp",
        "/login", "/signin", "/signup", "/register",
        "/logout", "/forgot", "/reset", "/password",
        "/user", "/users", "/profile", "/account",
        "/dashboard", "/panel", "/portal", "/home",
        "/shell", "/cmd", "/command", "/exec",
        "/.well-known", "/favicon.ico", "/health", "/ping",
        "/xmlrpc.php", "/wp-json", "/feed", "/rss",
        "/swagger", "/docs", "/api-docs", "/openapi",
    ]

    # Add random paths to reach the count
    while len(scan_paths) < count:
        scan_paths.append(f"/{random_string(random.randint(4, 12))}")

    found = 0
    not_found = 0
    start = time.time()

    def scan_one(i, path):
        status, ok = http_get(path, timeout=2)
        return i, path, status, ok

    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        futures = {executor.submit(scan_one, i, p): p for i, p in enumerate(scan_paths[:count])}
        for future in as_completed(futures):
            i, path, status, ok = future.result()
            if ok:
                if status == 200:
                    found += 1
                    log("★", Colors.GREEN, f"[{status}] {path}")
                else:
                    not_found += 1
                    if not_found <= 10 or not_found % 50 == 0:
                        log("·", Colors.DIM, f"[{status}] {path}")
            # Minimal delay per thread
            time.sleep(random.uniform(0.01, 0.03))

    elapsed = time.time() - start
    rps = count / elapsed if elapsed > 0 else 0
    print(f"\n  {Colors.MAGENTA}✓ Path scan complete: {count} paths in {elapsed:.0f}s ({rps:.1f} req/s){Colors.RESET}")
    print(f"  {Colors.DIM}  Found: {found} | Not Found: {not_found}{Colors.RESET}\n")
    return count


# ══════════════════════════════════════════════════════
#  TEST 4: SQL INJECTION (SQLi)
# ══════════════════════════════════════════════════════

def run_sqli(count=50):
    """
    Simulate SQL Injection attacks:
      - Send common SQLi payloads to the /api/search endpoint
    
    Flow profile: Rapid GET requests with complex URL-encoded query strings.
    """
    print(f"\n{Colors.BOLD}{'='*65}{Colors.RESET}")
    print(f"  {Colors.YELLOW}▶ TEST: SQL Injection (SQLi) Simulation{Colors.RESET}")
    print(f"  {Colors.DIM}Attempts: {count} | Target: GET /api/search?q={{payload}}{Colors.RESET}")
    print(f"  {Colors.DIM}Purpose: Generate SQLi patterns in network flows{Colors.RESET}")
    print(f"{Colors.BOLD}{'='*65}{Colors.RESET}\n")

    payloads = [
        "' OR 1=1--",
        '" OR 1=1--',
        "admin' --",
        "admin' #",
        "' UNION SELECT NULL, NULL, NULL--",
        "1; DROP TABLE users",
        "1' OR '1'='1",
        "%27%20OR%201%3D1--",
        "admin' AND 1=1--",
        "' OR 'x'='x",
        "1 AND (SELECT * FROM Users) = 1"
    ]

    success = 0
    failed = 0
    start = time.time()

    for i in range(count):
        payload = random.choice(payloads)
        from urllib.parse import quote
        encoded_payload = quote(payload)
        status, ok = http_get(f"/api/search?q={encoded_payload}")

        if ok:
            success += 1
            if i < 5 or i % 10 == 0:
                log("★", Colors.GREEN, f"[{i+1}/{count}] {payload} → {status}")
            elif i == 5:
                log("…", Colors.DIM, f"(continuing silently...)")
        else:
            failed += 1
            log("✗", Colors.RED, f"[{i+1}/{count}] CONNECTION FAILED")

        time.sleep(random.uniform(0.1, 0.3))

    elapsed = time.time() - start
    rps = count / elapsed if elapsed > 0 else 0
    print(f"\n  {Colors.YELLOW}✓ SQLi simulation complete: {count} attempts in {elapsed:.0f}s ({rps:.1f} req/s){Colors.RESET}")
    return count

# ══════════════════════════════════════════════════════
#  TEST 5: CROSS-SITE SCRIPTING (XSS)
# ══════════════════════════════════════════════════════

def run_xss(count=50):
    """
    Simulate Cross-Site Scripting (XSS) attacks:
      - Send common XSS payloads to the /api/comment endpoint
    
    Flow profile: POST requests with script tags and special characters in payload.
    """
    print(f"\n{Colors.BOLD}{'='*65}{Colors.RESET}")
    print(f"  {Colors.YELLOW}▶ TEST: Cross-Site Scripting (XSS) Simulation{Colors.RESET}")
    print(f"  {Colors.DIM}Attempts: {count} | Target: POST /api/comment{Colors.RESET}")
    print(f"  {Colors.DIM}Purpose: Generate XSS patterns in network flows{Colors.RESET}")
    print(f"{Colors.BOLD}{'='*65}{Colors.RESET}\n")

    payloads = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg/onload=alert(1)>",
        "javascript:alert(1)",
        "\"><script>alert(document.cookie)</script>",
        "<body onload=alert(1)>",
        "<iframe src=\"javascript:alert(1)\"></iframe>",
        "<a href=\"javascript:alert(1)\">Click me</a>",
        "<math><mi xlink:href=data:x,<script>alert(1)</script>></mi></math>",
        "<object data=\"javascript:alert(1)\"></object>"
    ]

    success = 0
    failed = 0
    start = time.time()

    for i in range(count):
        payload = random.choice(payloads)
        name = f"User{random.randint(100,999)}"
        status, ok = http_post("/api/comment", {"name": name, "comment": payload})

        if ok:
            success += 1
            if i < 5 or i % 10 == 0:
                log("★", Colors.GREEN, f"[{i+1}/{count}] {payload[:30]}... → {status}")
            elif i == 5:
                log("…", Colors.DIM, f"(continuing silently...)")
        else:
            failed += 1
            log("✗", Colors.RED, f"[{i+1}/{count}] CONNECTION FAILED")

        time.sleep(random.uniform(0.1, 0.3))

    elapsed = time.time() - start
    rps = count / elapsed if elapsed > 0 else 0
    print(f"\n  {Colors.YELLOW}✓ XSS simulation complete: {count} attempts in {elapsed:.0f}s ({rps:.1f} req/s){Colors.RESET}")
    return count

# ══════════════════════════════════════════════════════
#  TEST 6: HTTP FLOOD (High Volume)
# ══════════════════════════════════════════════════════

def run_flood(duration=20):
    """
    Simulate HTTP flood:
      - Maximum rate GET requests to the home page
      - Multi-threaded for high packets-per-second
    
    Flow profile: Extremely high PPS, high BPS, massive connection count,
                  many SYN packets — classic DDoS/DoS flow signature
    """
    print(f"\n{Colors.BOLD}{'='*65}{Colors.RESET}")
    print(f"  {Colors.RED}▶ TEST: HTTP Flood Simulation{Colors.RESET}")
    print(f"  {Colors.DIM}Duration: {duration}s | Threads: {THREADS} | Target: GET /{Colors.RESET}")
    print(f"  {Colors.DIM}Purpose: Max-rate requests → flood/DDoS flow pattern{Colors.RESET}")
    print(f"{Colors.BOLD}{'='*65}{Colors.RESET}\n")

    counter = {"count": 0, "errors": 0}
    stop_event = threading.Event()
    lock = threading.Lock()

    targets = ["/", "/login", "/search", "/api/stats", "/admin"]

    def flood_worker():
        while not stop_event.is_set():
            path = random.choice(targets)
            status, ok = http_get(path, timeout=2)
            with lock:
                if ok:
                    counter["count"] += 1
                else:
                    counter["errors"] += 1

    # Start worker threads
    threads = []
    for _ in range(THREADS):
        t = threading.Thread(target=flood_worker, daemon=True)
        t.start()
        threads.append(t)

    # Progress display
    start = time.time()
    last_count = 0
    while time.time() - start < duration:
        time.sleep(1)
        elapsed = time.time() - start
        current = counter["count"]
        rps = (current - last_count)
        total_rps = current / elapsed if elapsed > 0 else 0
        bar_len = int(elapsed / duration * 30)
        bar = "█" * bar_len + "░" * (30 - bar_len)
        print(f"\r  {Colors.RED}[{bar}]{Colors.RESET} {elapsed:.0f}s/{duration}s | "
              f"{Colors.BOLD}{current:,}{Colors.RESET} reqs | "
              f"{Colors.CYAN}{rps} req/s{Colors.RESET} | "
              f"avg: {total_rps:.0f} req/s   ", end="", flush=True)
        last_count = current

    stop_event.set()
    for t in threads:
        t.join(timeout=2)

    elapsed = time.time() - start
    total = counter["count"]
    rps = total / elapsed if elapsed > 0 else 0
    print(f"\n\n  {Colors.RED}✓ Flood complete: {total:,} requests in {elapsed:.0f}s ({rps:.0f} req/s){Colors.RESET}")
    print(f"  {Colors.DIM}  Errors: {counter['errors']}{Colors.RESET}\n")
    return total


# ══════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════

def print_banner():
    print(f"""
{Colors.BOLD}{'═'*65}
  CogSOC Traffic Generator — AI Detection Validator
  Target: {TARGET}
{'═'*65}{Colors.RESET}
  {Colors.DIM}This tool generates HTTP traffic patterns so CogSOC AI
  can classify them at the network flow level via CICFlowMeter.{Colors.RESET}
""")


def check_server():
    """Verify the test website is running."""
    print(f"  {Colors.DIM}Checking target server...{Colors.RESET}", end=" ")
    status, ok = http_get("/api/stats")
    if ok:
        print(f"{Colors.GREEN}✓ Server is UP (port 8080){Colors.RESET}\n")
        return True
    else:
        print(f"{Colors.RED}✗ Server is DOWN{Colors.RESET}")
        print(f"  {Colors.YELLOW}Start the server first:{Colors.RESET}")
        print(f"  {Colors.CYAN}python c:\\CogSOC\\TestWebsite\\server.py{Colors.RESET}\n")
        return False


if __name__ == "__main__":
    # Enable ANSI colors on Windows
    if sys.platform == "win32":
        import os
        os.system("")  # enables ANSI escape sequences

    parser = argparse.ArgumentParser(
        description="CogSOC Traffic Generator — Generate test traffic patterns"
    )
    parser.add_argument(
        "--mode",
        choices=["normal", "brute", "scan", "flood", "sqli", "xss", "all"],
        default="all",
        help="Traffic pattern to generate (default: all)"
    )
    parser.add_argument("--count", type=int, default=None,
                        help="Number of requests (for brute/scan modes)")
    parser.add_argument("--duration", type=int, default=None,
                        help="Duration in seconds (for normal/flood modes)")
    args = parser.parse_args()

    print_banner()

    if not check_server():
        sys.exit(1)

    total = 0
    start_all = time.time()

    if args.mode == "normal" or args.mode == "all":
        total += run_normal(duration=args.duration or 30)

    if args.mode == "brute" or args.mode == "all":
        total += run_brute(count=args.count or 100)

    if args.mode == "scan" or args.mode == "all":
        total += run_scan(count=args.count or 200)

    if args.mode == "sqli" or args.mode == "all":
        total += run_sqli(count=args.count or 50)

    if args.mode == "xss" or args.mode == "all":
        total += run_xss(count=args.count or 50)

    if args.mode == "flood" or args.mode == "all":
        total += run_flood(duration=args.duration or 20)

    elapsed = time.time() - start_all
    print(f"{Colors.BOLD}{'═'*65}{Colors.RESET}")
    print(f"  {Colors.GREEN}ALL TESTS COMPLETE{Colors.RESET}")
    print(f"  Total requests : {Colors.BOLD}{total:,}{Colors.RESET}")
    print(f"  Total time     : {Colors.BOLD}{elapsed:.0f}s{Colors.RESET}")
    print(f"  Avg rate       : {Colors.BOLD}{total/elapsed:.0f} req/s{Colors.RESET}")
    print(f"\n  {Colors.CYAN}→ Check CogSOC Dashboard for detected alerts!{Colors.RESET}")
    print(f"  {Colors.DIM}  http://localhost:8050/dashboard.html{Colors.RESET}")
    print(f"{Colors.BOLD}{'═'*65}{Colors.RESET}\n")

# cogsoc_behavioral.py
# Real-time behavioral analysis + AI detection + Kibana visualization
# Run: python3 cogsoc_behavioral.py --mode monitor
# Requirements: pip install elasticsearch==8.9.0 scikit-learn joblib pandas numpy

import warnings
warnings.filterwarnings("ignore")

import argparse
import pandas as pd
import numpy as np
import joblib
import time
import os
import sys
import json
import threading
import webbrowser
import http.server
import subprocess
import shutil
from urllib.request import urlopen, Request
from urllib.error import URLError
from datetime import datetime, timezone, timedelta
from collections import defaultdict, deque
from elasticsearch import Elasticsearch, helpers
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Force UTF-8 encoding on Windows to prevent charmap errors with emojis
if sys.platform == 'win32':
    sys.stdout.reconfigure(encoding='utf-8')
    sys.stderr.reconfigure(encoding='utf-8')
# Groq API — used via REST (urllib), no extra pip package needed

# ── THE HANDS modules ──
try:
    from email_alert import EmailAlertEngine
    _HAS_EMAIL_MODULE = True
except ImportError:
    _HAS_EMAIL_MODULE = False
try:
    from playbooks import PlaybookEngine
    _HAS_PLAYBOOK_MODULE = True
except ImportError:
    _HAS_PLAYBOOK_MODULE = False

# ══════════════════════════════════════════════
#  SETTINGS
# ══════════════════════════════════════════════
ES_HOST          = "http://localhost:9200"
FLOWS_INDEX      = "cogsoc-flows"
ALERTS_INDEX     = "cogsoc-alerts"
BASELINE_INDEX   = "cogsoc-baseline"      # IP behavioral baseline
BEHAVIOR_INDEX   = "cogsoc-behavior"      # real-time behavior tracking
INCIDENTS_INDEX  = "cogsoc-incidents"     # SOAR incident tracking
RESPONSES_INDEX  = "cogsoc-responses"     # SOAR response actions
def _res_path(wsl_path, win_path):
    """Return the appropriate path for the operating system; prefer Windows native path on Windows."""
    import sys
    if sys.platform == 'win32':
        return win_path
    return wsl_path if os.path.exists(wsl_path) else win_path

MODEL_PATH       = _res_path("/mnt/c/CogSOC/Trained AI/better_model_v3.pkl", r"C:\CogSOC\Trained AI\better_model_v3.pkl")
SCALER_PATH      = _res_path("/mnt/c/CogSOC/Trained AI/better_scaler_v3.pkl", r"C:\CogSOC\Trained AI\better_scaler_v3.pkl")
BLOCKED_LOG      = _res_path("/mnt/c/CogSOC/data/blocked_ips.log", r"C:\CogSOC\data\blocked_ips.log")

# ══════════════════════════════════════════════
#  Live capture + Filebeat integration
# ══════════════════════════════════════════════
CICFLOW_INTERFACE = os.environ.get("COGSOC_INTERFACE", "Wi-Fi")

# ── CICFlowMeter paths ──
# cfm.bat  = Java CICFlowMeter CLI  (live capture: cfm.bat <iface> <out_dir>)
# cfm      = same tool exposed on PATH
_CFM_BAT_WSL = "/mnt/c/CogSOC/CICFlowMeter-master/build/distributions/CICFlowMeter-4.0/bin/cfm"
_CFM_BAT_WIN = r"C:\CogSOC\CICFlowMeter-master\build\distributions\CICFlowMeter-4.0\bin\cfm.bat"
CICFLOW_BIN     = _res_path(_CFM_BAT_WSL, _CFM_BAT_WIN)
CICFLOW_BIN_DIR = os.path.dirname(CICFLOW_BIN)   # cwd needed so cfm.bat can find lib/

CICFLOW_OUTPUT_DIR  = _res_path(
    "/mnt/c/CogSOC/CICFlowMeter-master/build/distributions/CICFlowMeter-4.0/bin/data/daily",
    r"C:\CogSOC\CICFlowMeter-master\build\distributions\CICFlowMeter-4.0\bin\data\daily",
)
CICFLOW_OUTPUT_FILE = os.path.join(CICFLOW_OUTPUT_DIR, "live_Flow.csv")
CICFLOW_LOG         = os.path.join(CICFLOW_OUTPUT_DIR, "cicflowmeter.log")

# Python pip cicflowmeter — fallback only, usually not present
_python_wsl        = "/mnt/c/Users/DELL/AppData/Local/Programs/Python/Python313/Scripts/cicflowmeter.exe"
_python_win        = r"C:\Users\DELL\AppData\Local\Programs\Python\Python313\Scripts\cicflowmeter.exe"
CICFLOW_PYTHON_BIN = _res_path(_python_wsl, _python_win)

LIVE_PCAP_DIR      = os.path.join(CICFLOW_OUTPUT_DIR, "live_pcaps")
LIVE_CHUNK_SECONDS = int(os.environ.get("COGSOC_LIVE_CHUNK_SECONDS", "15"))

# ── Filebeat paths — scan common install locations automatically ──
def _find_filebeat_exe():
    candidates = [
        r"C:\Program Files\Elastic\Beats\9.3.3\filebeat\filebeat.exe",
        r"C:\Program Files\Elastic\Beats\8.13.0\filebeat\filebeat.exe",
        r"C:\Program Files\Elastic\Beats\8.0.0\filebeat\filebeat.exe",
        r"C:\filebeat\filebeat.exe",
        r"C:\CogSOC\filebeat\filebeat.exe",
        "/mnt/c/Program Files/Elastic/Beats/9.3.3/filebeat/filebeat.exe",
        "/mnt/c/CogSOC/filebeat/filebeat.exe",
        "/usr/bin/filebeat",
        "/usr/local/bin/filebeat",
    ]
    for p in candidates:
        if os.path.exists(p):
            return p
    on_path = shutil.which("filebeat") or shutil.which("filebeat.exe")
    if on_path:
        return on_path
    return candidates[0]   # not found — return first so error messages are useful

FILEBEAT_EXE             = _find_filebeat_exe()
FILEBEAT_EXE_DIR         = os.path.dirname(FILEBEAT_EXE)
# Auto-generated config lives next to the binary (so relative paths inside it work)
FILEBEAT_CONFIG          = os.path.join(FILEBEAT_EXE_DIR, "filebeat-cogsoc.yml")
FILEBEAT_FALLBACK_CONFIG = _res_path("/mnt/c/CogSOC/Setup/filebeat-cogsoc.yml",
                                      r"C:\CogSOC\Setup\filebeat-cogsoc.yml")
FILEBEAT_LOG             = os.path.join(CICFLOW_OUTPUT_DIR, "filebeat.log")
TSHARK_EXE               = _res_path("/mnt/c/Program Files/Wireshark/tshark.exe",
                                      r"C:\Program Files\Wireshark\tshark.exe")

MONITOR_INTERVAL = 3
BATCH_SIZE       = 500
HIGH_CONF        = 90.0
MEDIUM_CONF      = 70.0

# Behavioral thresholds
BASELINE_WINDOW    = 300   # seconds — 5 min baseline learning
ANOMALY_MULTIPLIER = 3.0   # 3x se zyada = anomaly
MIN_FLOWS_BASELINE = 10    # minimum flows before baseline ready

# Per-IP tracking window (seconds)
IP_WINDOW = 60

# Heuristic thresholds
PORTSCAN_PORTS_THRESHOLD   = 15    # 15+ unique ports in 60s
PORTSCAN_SYN_THRESHOLD     = 20    # 20+ SYN with low response
DOS_PPS_THRESHOLD          = 2000  # 2000+ packets/sec (increased for streaming)
DOS_BPS_THRESHOLD          = 10e6  # 10MB/s+ (increased for streaming)
BRUTE_FORCE_THRESHOLD      = 20    # 20+ connections same port
BEACONING_INTERVAL_STD_MAX = 2.0   # low stddev = regular beaconing (C2)

# ── Network Scope ──
MONITOR_NETWORK = '192.168.100.'    # your lab subnet prefix
BASELINE_LEARN_MINUTES = 2          # learn normal IPs for first 2 minutes

# Global process tracker for clean shutdown
ACTIVE_PROCESSES = []
# No IP filtering — only flow behavior determines attack vs normal
SERVER_IPS = {
    # '192.168.100.50',   # example: your web server
    # '192.168.100.60',   # example: your SSH server
}

# IPs to NEVER flag (infrastructure)
WHITELISTED_IPS = {
    '0.0.0.0', '255.255.255.255', '127.0.0.1',
    '192.168.100.1',     # gateway
    '192.168.100.255',   # subnet broadcast
}

# ── Email Alert Settings ──
EMAIL_ENABLED      = True                      # Set True to enable
SMTP_SERVER         = 'smtp.gmail.com'
SMTP_PORT           = 587
EMAIL_SENDER        = 'cybersecabs@gmail.com'     # Your Gmail address
EMAIL_PASSWORD      = 'rqzu dzvy xzdd xgtr'      # Gmail App Password
EMAIL_RECIPIENTS    = ['rangharabbas@gmail.com']       # Who receives alerts
EMAIL_COOLDOWN      = 600                         # seconds between emails per IP
_email_last_sent    = {}                          # rate limiter {ip: timestamp}

# ── Trusted Internal IPs (Notification on Block) ──
# IPs listed here are known employees/devices. When suspicious activity is detected:
#   1. IP is AUTO-BLOCKED immediately (same as any other IP)
#   2. Informational email sent to device owner with details of why it was blocked
#      and what activities were detected — so they can investigate or request unblock
TRUSTED_INTERNAL_IPS = {
    '192.168.100.79' : {'name': 'Admin Workstation',  'owner': 'rangharabbas@gmail.com'},
    '192.168.100.179' : {'name': 'Dev Machine',        'owner': 'rangharabbas@gmail.com'},
    # Add more trusted devices here:
    # '192.168.100.XX': {'name': 'Device Name', 'owner': 'user@email.com'},
}
_trusted_notified = {}      # {ip: timestamp} — rate limiter for trusted IP notification emails

# ── GenAI Copilot Settings ──
GROQ_API_KEY        = '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'
GROQ_MODEL          = 'llama-3.1-8b-instant'   # fast + free tier

# Known service provider prefixes — normal internet traffic, not attacks
# These generate massive false positives because model wasn't trained on them
KNOWN_SERVICE_PREFIXES = (
    # Google
    '142.250.', '142.251.', '172.217.', '216.58.', '74.125.',
    '173.194.', '209.85.', '108.177.', '34.95.', '34.54.',
    '35.190.', '35.191.', '8.8.8.', '8.8.4.',
    # Meta / Facebook
    '157.240.', '31.13.', '179.60.', '185.89.',
    # Microsoft / Azure
    '52.184.', '52.168.', '52.137.', '13.107.', '204.79.',
    '40.126.', '20.190.', '23.192.', '131.253.', '150.171.',
    # Cloudflare
    '104.18.', '104.16.', '104.17.', '104.19.', '104.20.',
    '172.67.', '1.1.1.',
    # Amazon AWS
    '52.94.', '54.239.', '99.86.', '99.84.', '143.204.',
    # Akamai
    '23.32.', '23.64.', '23.192.', '104.64.',
    # Apple
    '17.248.', '17.253.',
    # Wikimedia / Wikipedia
    '103.102.166.', '208.80.153.', '208.80.154.', '208.80.155.',
    '91.198.174.',
    # Canonical / Ubuntu (NTP, updates, snap)
    '185.125.190.', '185.125.188.', '91.189.88.', '91.189.89.',
    '91.189.91.', '91.189.92.', '91.189.94.', '91.189.95.',
    # NTP pools (common public time servers)
    '162.159.200.', '17.253.', '129.6.15.',
    # Mozilla / Firefox
    '34.107.', '34.117.', '35.244.',
    # Netflix
    '23.246.', '45.57.', '108.175.',
    # Spotify
    '35.186.', '104.199.',
    # Steam / Valve
    '155.133.', '162.254.', '185.25.180.', '185.25.182.',
    # Twitter / X
    '104.244.',
    # LinkedIn
    '108.174.',
    # GitHub
    '140.82.',
    # WhatsApp
    '157.240.',
    # Zoom
    '3.7.', '3.21.', '3.25.', '13.52.',
    # Discord
    '162.159.',
)


def ensure_live_flow_dir():
    """Create the CICFlowMeter output folder and live_pcaps sub-folder."""
    os.makedirs(CICFLOW_OUTPUT_DIR, exist_ok=True)
    os.makedirs(LIVE_PCAP_DIR, exist_ok=True)


def to_win_path(path):
    """Convert a WSL path (/mnt/c/...) to a Windows path (C:...) for Windows tools."""
    if path.startswith("/mnt/"):
        parts = path.split("/")
        drive = parts[2].upper()
        return drive + ":\\" + "\\".join(parts[3:])
    return path


# ══════════════════════════════════════════════
#  CICFlowMeter — helper that resolves which
#  binary to use, in priority order:
#    1. cfm.bat  (the real Java CLI tool)
#    2. cfm      (same tool on PATH)
#    3. cicflowmeter.exe  (Python pip version)
# ══════════════════════════════════════════════

def _resolve_cfm_binary():
    """Return (executable, needs_cmd_wrapper) for the best available CICFlowMeter binary."""
    # 1. cfm.bat at the configured path
    if os.path.exists(CICFLOW_BIN):
        return CICFLOW_BIN, True   # .bat needs cmd.exe /c on WSL

    # 2. cfm / cfm.bat on PATH
    for name in ("cfm.bat", "cfm"):
        found = shutil.which(name)
        if found:
            return found, found.endswith(".bat")

    # 3. Python pip cicflowmeter
    if os.path.exists(CICFLOW_PYTHON_BIN):
        return CICFLOW_PYTHON_BIN, False

    return None, False


def _build_cfm_live_cmd(interface, output_dir):
    """
    Build the command list to start CICFlowMeter in LIVE capture mode.

    cfm.bat / cfm live-capture syntax:
        cfm.bat  <interface_name>  <output_folder>

    The tool captures continuously and writes a new CSV file into
    output_folder every time a set of flows finishes.
    """
    binary, needs_cmd = _resolve_cfm_binary()
    if binary is None:
        return None

    # Convert paths when calling Windows .bat from WSL
    win_interface = interface          # interface name stays as-is
    win_out       = to_win_path(output_dir) if output_dir.startswith("/mnt/") else output_dir

    if needs_cmd:
        # Must run .bat through cmd.exe (works from both WSL and native Windows)
        cmd = ["cmd.exe", "/c", to_win_path(binary) if binary.startswith("/mnt/") else binary,
               win_interface, win_out]
    else:
        cmd = [binary, "-i", interface, "-o", output_dir]

    return cmd


def _build_cfm_offline_cmd(input_path, output_dir):
    """
    Build the command list to run CICFlowMeter on a PCAP file (offline mode).
    Syntax:  cfm.bat  <pcap_file>  <output_folder>
    """
    binary, needs_cmd = _resolve_cfm_binary()
    if binary is None:
        return None

    win_in  = to_win_path(input_path)  if input_path.startswith("/mnt/")  else input_path
    win_out = to_win_path(output_dir)  if output_dir.startswith("/mnt/")  else output_dir

    if needs_cmd:
        cmd = ["cmd.exe", "/c", to_win_path(binary) if binary.startswith("/mnt/") else binary,
               win_in, win_out]
    else:
        # Python pip version uses -f / -c flags
        base_name = os.path.basename(input_path) + "_Flow.csv"
        csv_out   = os.path.join(output_dir, base_name)
        win_csv   = to_win_path(csv_out) if csv_out.startswith("/mnt/") else csv_out
        cmd       = [binary, "-f", win_in, "-c", win_csv]

    return cmd


# ── Keep old name for backward compat with offline analysis code ──
def get_cicflow_command(input_path, output_dir):
    return _build_cfm_offline_cmd(input_path, output_dir)


def get_packet_capture_command(pcap_path, seconds=LIVE_CHUNK_SECONDS):
    """Build a bounded tshark/tcpdump capture command (used only when cfm is unavailable)."""
    if os.path.exists(TSHARK_EXE):
        win_pcap = to_win_path(pcap_path)
        return [TSHARK_EXE, "-i", CICFLOW_INTERFACE, "-a", f"duration:{seconds}", "-w", win_pcap]
    if shutil.which("tcpdump"):
        return ["sudo", "tcpdump", "-i", CICFLOW_INTERFACE, "-nn", "-s", "0",
                "-w", pcap_path, "-G", str(seconds), "-W", "1"]
    return None


def run_cicflowmeter(input_path, output_dir):
    """Run CICFlowMeter on a PCAP file and return the generated CSV file paths."""
    os.makedirs(output_dir, exist_ok=True)
    cmd = _build_cfm_offline_cmd(input_path, output_dir)
    if not cmd:
        raise RuntimeError(
            "CICFlowMeter not found. Ensure cfm.bat exists at:\n"
            f"  {CICFLOW_BIN}\nor add 'cfm' to your PATH."
        )

    before = {
        os.path.join(output_dir, n)
        for n in os.listdir(output_dir)
        if n.lower().endswith(".csv")
    }

    cwd = CICFLOW_BIN_DIR if os.path.exists(CICFLOW_BIN_DIR) else None
    print(f"[CICFlowMeter] Running offline: {' '.join(cmd)}")
    subprocess.run(cmd, cwd=cwd, check=True, timeout=900)

    after = {
        os.path.join(output_dir, n)
        for n in os.listdir(output_dir)
        if n.lower().endswith(".csv")
    }
    generated = sorted(after - before, key=os.path.getmtime)
    return generated


# ══════════════════════════════════════════════
#  LIVE CAPTURE — main automation entry point
#  Called automatically when user clicks
#  "Confirm & Ignite Engine" in the UI.
# ══════════════════════════════════════════════

_CSV_WRITE_LOCK = threading.Lock()

def process_pcap_background(pcap_path, output_dir):
    try:
        csvs = run_cicflowmeter(pcap_path, output_dir)
        print(f"[CICFlowMeter] ✅ {len(csvs)} CSV(s): {', '.join(os.path.basename(p) for p in csvs)}")
        
        live_csv = os.path.join(output_dir, "live_Flow.csv")
        for chunk_csv in csvs:
            if not os.path.exists(chunk_csv): continue
            
            # Append to live_Flow.csv safely
            with open(chunk_csv, 'r', encoding='utf-8', errors='ignore') as f_in:
                content = f_in.read()
            with _CSV_WRITE_LOCK:
                with open(live_csv, 'a', encoding='utf-8', errors='ignore') as f_out:
                    f_out.write(content)
                
            # Remove chunk CSV to prevent "too many files" issue
            try:
                os.remove(chunk_csv)
            except Exception:
                pass
                
        # Clean up the processed PCAP to save disk space
        try:
            os.remove(pcap_path)
        except Exception as e:
            pass
    except Exception as e:
        print(f"[PROCESS] Error processing {pcap_path}: {e}")

def live_cicflow_loop(stop_after_seconds=None):
    """
    Fallback live capture loop used when cfm.bat does NOT support live mode.
    Captures PCAP chunks with tshark/tcpdump, then converts each to CSV via cfm.
    """
    ensure_live_flow_dir()
    started = time.time()
    print(f"[CAPTURE] Fallback PCAP-chunk loop  |  interface={CICFLOW_INTERFACE}  |  chunk={LIVE_CHUNK_SECONDS}s")

    # Clear/Initialize live_Flow.csv
    live_csv = os.path.join(CICFLOW_OUTPUT_DIR, "live_Flow.csv")
    open(live_csv, 'w').close()

    while True:
        if stop_after_seconds and time.time() - started >= stop_after_seconds:
            print("[CAPTURE] Duration reached — stopping capture loop.")
            return

        stamp    = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        pcap_path = os.path.join(LIVE_PCAP_DIR, f"live_{stamp}.pcap")
        cap_cmd  = get_packet_capture_command(pcap_path)
        if not cap_cmd:
            print("[CAPTURE] ERROR: tshark/tcpdump not found.  Install Wireshark or tcpdump.")
            time.sleep(10)
            continue

        try:
            print(f"[CAPTURE] Capturing {LIVE_CHUNK_SECONDS}s chunk → {os.path.basename(pcap_path)}")
            proc = subprocess.Popen(cap_cmd)
            try:
                proc.wait(timeout=LIVE_CHUNK_SECONDS + 15)
            except subprocess.TimeoutExpired:
                print("[CAPTURE] Chunk timed out — killing process and processing captured data anyway.")
                proc.kill()
                proc.wait()  # Wait for it to fully terminate
            
            if not os.path.exists(pcap_path) or os.path.getsize(pcap_path) == 0:
                print("[CAPTURE] Empty PCAP — check interface name and permissions.")
                time.sleep(2)
                continue
                
            # Process PCAP in background to eliminate capture blind spots
            threading.Thread(target=process_pcap_background, args=(pcap_path, CICFLOW_OUTPUT_DIR), daemon=True).start()
                
        except Exception as e:
            print(f"[CAPTURE] Chunk error: {e}")
            time.sleep(5)


def start_cicflow_capture(stop_after_seconds=None):
    """
    Start CICFlowMeter live traffic capture automatically.

    Since the Java `cfm.bat` CLI does not natively support live interface capture, 
    we use a PCAP-chunk loop (tshark -> cfm.bat).
    If the Python `cicflowmeter` package is installed, we can use that directly.
    """
    ensure_live_flow_dir()
    
    # ── 1. PCAP-chunk loop (using tshark + cfm.bat) ──
    binary, _ = _resolve_cfm_binary()
    if binary and ('cfm.bat' in binary.lower() or 'cfm' in binary.lower()):
        print(f"[CAPTURE] ═══════════════════════════════════════")
        print(f"[CAPTURE]  Starting PCAP-Chunk LIVE capture (tshark + cfm.bat)")
        print(f"[CAPTURE]  Interface : {CICFLOW_INTERFACE}")
        print(f"[CAPTURE] ═══════════════════════════════════════")
        
        worker = threading.Thread(
            target=live_cicflow_loop,
            kwargs={"stop_after_seconds": stop_after_seconds},
            daemon=True,
        )
        worker.start()
        return worker

    # ── 2. Fallback: Python pip cicflowmeter ──
    if os.path.exists(CICFLOW_PYTHON_BIN):
        win_out = to_win_path(CICFLOW_OUTPUT_DIR)
        csv_file = os.path.join(win_out, "live_Flow.csv")
        py_cmd  = [CICFLOW_PYTHON_BIN, "-i", CICFLOW_INTERFACE, "-c", csv_file]
        
        print(f"[CAPTURE] ═══════════════════════════════════════")
        print(f"[CAPTURE]  Starting Python CICFlowMeter LIVE capture")
        print(f"[CAPTURE]  Interface : {CICFLOW_INTERFACE}")
        print(f"[CAPTURE]  Output    : {csv_file}")
        print(f"[CAPTURE]  Command   : {' '.join(py_cmd)}")
        print(f"[CAPTURE] ═══════════════════════════════════════")
        
        try:
            log_fh = open(CICFLOW_LOG, "a", encoding="utf-8", errors="ignore")
            proc   = subprocess.Popen(py_cmd, stdout=log_fh, stderr=log_fh)
            ACTIVE_PROCESSES.append(proc)
            print(f"[CAPTURE] ✅ Python CICFlowMeter started  (PID {proc.pid})")
            return proc
        except Exception as e:
            print(f"[CAPTURE] ❌ Python CICFlowMeter failed: {e}")

    print("[CAPTURE] ❌ No valid capture method available.")
    return None


# ══════════════════════════════════════════════
#  FILEBEAT — ships CSVs → ELK cogsoc-flows
# ══════════════════════════════════════════════

def _write_filebeat_config():
    """
    Auto-generate a Filebeat config that watches CICFlowMeter CSV output
    and ships every row to Elasticsearch index  cogsoc-flows-YYYY.MM.dd.

    Written next to the Filebeat binary so relative paths inside the config
    are resolved correctly by Filebeat.
    """
    # Normalise paths for the config file (always use backslashes on Windows)
    watch_dir = to_win_path(CICFLOW_OUTPUT_DIR) if CICFLOW_OUTPUT_DIR.startswith("/mnt/") \
                else CICFLOW_OUTPUT_DIR
    log_dir   = watch_dir   # write filebeat.log next to the CSVs

    # Clean paths for YAML (convert to forward slashes to avoid backslash escaping issues)
    watch_dir_yaml = watch_dir.replace("\\", "/")
    log_dir_yaml = log_dir.replace("\\", "/")
    # Escape any backslashes and single quotes in interface name for YAML compatibility
    interface_yaml = CICFLOW_INTERFACE.replace("\\", "\\\\").replace("'", "''")

    cfg = f"""# =========================================================
# CogSOC — Filebeat config  (auto-generated, do not edit)
# Ships CICFlowMeter CSV flows → Elasticsearch cogsoc-flows
# =========================================================

filebeat.inputs:
  - type: log
    enabled: true
    paths:
      - "{watch_dir_yaml}/live_Flow.csv"
    # Skip CSV header rows (CICFlowMeter writes one header per file)
    exclude_lines: ['^Flow ID,', '^\\\\s*$']
    fields_under_root: true
    fields:
      cogsoc_source: "cicflowmeter"
      capture_interface: "{interface_yaml}"
    encoding: utf-8
    scan_frequency: 1s
    close_inactive: 5m
    ignore_older: 24h
    # Track file position so restarts don't re-send rows
    harvester_buffer_size: 16384

# Parse each CSV row into structured fields
processors:
  - decode_csv_fields:
      fields:
        message: decoded
      separator: ","
      ignore_missing: false
      overwrite_keys: true
      trim_leading_space: true
      fail_on_error: false
  - rename:
      fields:
        - from: "decoded.Src IP"
          to: "src_ip"
        - from: "decoded.Dst IP"
          to: "dst_ip"
        - from: "decoded.Src Port"
          to: "src_port"
        - from: "decoded.Dst Port"
          to: "dst_port"
        - from: "decoded.Protocol"
          to: "protocol"
        - from: "decoded.Timestamp"
          to: "flow_timestamp"
        - from: "decoded.Flow Duration"
          to: "flow_duration"
        - from: "decoded.Label"
          to: "label"
      ignore_missing: true
      fail_on_error: false
  - add_fields:
      target: ''
      fields:
        index_name: "cogsoc-flows"
        sensor_name: "{interface_yaml}"

output.elasticsearch:
  hosts: ["{ES_HOST}"]
  index: "cogsoc-flows-%{{+yyyy.MM.dd}}"

# Disable built-in ILM and templates — CogSOC creates the index itself
setup.ilm.enabled: false
setup.template.enabled: false

logging.level: info
logging.to_files: true
logging.files:
  path: "{log_dir_yaml}"
  name: filebeat.log
  keepfiles: 7
  rotateeverybytes: 10485760
"""

    # Try writing next to the binary first (most reliable path)
    paths_to_try = [FILEBEAT_CONFIG, FILEBEAT_FALLBACK_CONFIG]
    for config_path in paths_to_try:
        try:
            os.makedirs(os.path.dirname(config_path), exist_ok=True)
            with open(config_path, "w", encoding="utf-8") as f:
                f.write(cfg)
            print(f"[FILEBEAT] Config written → {config_path}")
            return config_path
        except Exception as e:
            print(f"[FILEBEAT] Could not write config to {config_path}: {e}")

    # Last resort: write to CICFlowMeter output dir
    last = os.path.join(CICFLOW_OUTPUT_DIR, "filebeat-cogsoc.yml")
    try:
        with open(last, "w", encoding="utf-8") as f:
            f.write(cfg)
        print(f"[FILEBEAT] Config written (fallback) → {last}")
        return last
    except Exception as e:
        print(f"[FILEBEAT] ❌ Could not write Filebeat config anywhere: {e}")
        return None


def get_filebeat_config():
    """
    Return a valid Filebeat config path.
    If neither the binary-dir nor fallback configs exist, auto-generate one.
    """
    if os.path.exists(FILEBEAT_CONFIG):
        return FILEBEAT_CONFIG
    if os.path.exists(FILEBEAT_FALLBACK_CONFIG):
        return FILEBEAT_FALLBACK_CONFIG
    # Generate fresh config
    return _write_filebeat_config()


def start_filebeat():
    """
    Start Filebeat so it ships CICFlowMeter CSVs → ELK cogsoc-flows index.
    Called automatically after start_cicflow_capture() in --engine-only mode.
    """
    ensure_live_flow_dir()

    # Always (re-)write config so paths + interface are up to date
    config_path = _write_filebeat_config()
    if config_path is None:
        print("[FILEBEAT] ❌ Cannot start Filebeat — config could not be written.")
        return None

    if not os.path.exists(FILEBEAT_EXE):
        print(f"[FILEBEAT] ❌ Filebeat executable not found at: {FILEBEAT_EXE}")
        print("[FILEBEAT]    Install Filebeat and update FILEBEAT_EXE in cogsoc_behav.py")
        return None

    log_fh = open(FILEBEAT_LOG, "a", encoding="utf-8", errors="ignore")
    cmd    = [FILEBEAT_EXE, "-c", config_path, "-e"]

    print(f"[FILEBEAT] ═══════════════════════════════════════")
    print(f"[FILEBEAT]  Starting Filebeat")
    print(f"[FILEBEAT]  Binary : {FILEBEAT_EXE}")
    print(f"[FILEBEAT]  Config : {config_path}")
    print(f"[FILEBEAT]  Index  : cogsoc-flows-<date>  →  {ES_HOST}")
    print(f"[FILEBEAT] ═══════════════════════════════════════")

    try:
        proc = subprocess.Popen(
            cmd,
            cwd=FILEBEAT_EXE_DIR,   # Filebeat resolves relative paths from its own dir
            stdout=log_fh,
            stderr=subprocess.STDOUT,
        )
        ACTIVE_PROCESSES.append(proc)
        print(f"[FILEBEAT] ✅ Filebeat started  (PID {proc.pid})")
        print(f"[FILEBEAT]    Log: {FILEBEAT_LOG}")
        return proc
    except Exception as e:
        print(f"[FILEBEAT] ❌ Failed to start Filebeat: {e}")
        return None


FEATURES = [
    'Destination Port', 'Flow Duration', 'Total Fwd Packets',
    'Total Backward Packets', 'Total Length of Fwd Packets',
    'Total Length of Bwd Packets', 'Fwd Packet Length Max',
    'Fwd Packet Length Min', 'Fwd Packet Length Mean', 'Fwd Packet Length Std',
    'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean',
    'Bwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s',
    'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min',
    'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min',
    'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min',
    'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags',
    'Fwd Header Length', 'Bwd Header Length', 'Fwd Packets/s', 'Bwd Packets/s',
    'Min Packet Length', 'Max Packet Length', 'Packet Length Mean',
    'Packet Length Std', 'Packet Length Variance', 'FIN Flag Count',
    'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count',
    'URG Flag Count', 'CWE Flag Count', 'ECE Flag Count', 'Down/Up Ratio',
    'Average Packet Size', 'Avg Fwd Segment Size', 'Avg Bwd Segment Size',
    'Fwd Header Length.1', 'Fwd Avg Bytes/Bulk', 'Fwd Avg Packets/Bulk',
    'Fwd Avg Bulk Rate', 'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk',
    'Bwd Avg Bulk Rate', 'Subflow Fwd Packets', 'Subflow Fwd Bytes',
    'Subflow Bwd Packets', 'Subflow Bwd Bytes', 'Init_Win_bytes_forward',
    'Init_Win_bytes_backward', 'act_data_pkt_fwd', 'min_seg_size_forward',
    'Active Mean', 'Active Std', 'Active Max', 'Active Min',
    'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min'
]

MITRE_MAP = {
    'DDOS'      : ('T1498', 'Impact',              'Network Denial of Service'),
    'DOS'       : ('T1499', 'Impact',              'Endpoint Denial of Service'),
    'PORTSCAN'  : ('T1046', 'Discovery',           'Network Service Scanning'),
    'BOT'       : ('T1071', 'Command & Control',   'Application Layer Protocol'),
    'BRUTE'     : ('T1110', 'Credential Access',   'Brute Force'),
    'WEB'       : ('T1190', 'Initial Access',      'Exploit Public-Facing App'),
    'BEACONING' : ('T1071', 'Command & Control',   'C2 Beaconing Detected'),
    'ANOMALY'   : ('T1071', 'Unknown',             'Behavioral Anomaly'),
    'ATTACK'    : ('T1071', 'Command & Control',   'Generic Attack'),
}


# ══════════════════════════════════════════════
#  STACKING PREDICTOR — full pipeline wrapper
# ══════════════════════════════════════════════
class StackingPredictor:
    """
    Wraps the stacking model pipeline so the rest of the code
    can call .predict() and .predict_proba() like a normal model.

    Pipeline (matches fine_tuned_model.py training):
      1. X (already scaled by base_scaler externally)
      2. base_model.predict_proba(X) → 2-col probabilities
      3. np.hstack([X, base_proba])  → 80-col stacked features
      4. stack_scaler.transform()    → scaled stacked features
      5. meta_learner.predict()      → final prediction
    """

    def __init__(self, base_model, stack_scaler, meta_learner):
        self.base_model   = base_model
        self.stack_scaler  = stack_scaler
        self.meta_learner  = meta_learner
        # Expose n_features_in_ so logging/diagnostics work
        self.n_features_in_ = getattr(base_model, 'n_features_in_', 78)

    def predict(self, X):
        """Full stacking prediction."""
        base_proba    = self.base_model.predict_proba(X)
        X_stack       = np.hstack([X, base_proba])
        X_stack_scaled = self.stack_scaler.transform(X_stack)
        return self.meta_learner.predict(X_stack_scaled)

    def predict_proba(self, X):
        """Full stacking probability prediction."""
        base_proba     = self.base_model.predict_proba(X)
        X_stack        = np.hstack([X, base_proba])
        X_stack_scaled = self.stack_scaler.transform(X_stack)
        return self.meta_learner.predict_proba(X_stack_scaled)

    def __repr__(self):
        return (f"StackingPredictor(base={type(self.base_model).__name__}, "
                f"meta={type(self.meta_learner).__name__})")


# ══════════════════════════════════════════════
#  IN-MEMORY BEHAVIORAL TRACKER
# ══════════════════════════════════════════════
class IPBehaviorTracker:
    """
    Per-IP real-time behavioral tracking.
    Sliding window mein har IP ka traffic pattern track karta hai.
    """
    def __init__(self, window_seconds=IP_WINDOW):
        self.window   = window_seconds
        self.ip_data  = defaultdict(lambda: {
            'flows'        : deque(),   # (timestamp, flow_doc)
            'ports'        : deque(),   # (timestamp, port)
            'bytes'        : deque(),   # (timestamp, bytes)
            'packets'      : deque(),   # (timestamp, packets)
            'syn_count'    : deque(),   # (timestamp, syn)
            'intervals'    : deque(),   # (timestamp, interval_ms)
            'last_seen'    : None,
            'baseline_pkts': [],        # baseline ke liye
            'baseline_bps' : [],
            'baseline_ready': False,
        })

    def _cleanup(self, ip, now):
        """Purani entries remove karo window se"""
        cutoff = now - self.window
        d = self.ip_data[ip]
        for q in ['flows', 'ports', 'bytes', 'packets', 'syn_count', 'intervals']:
            while d[q] and d[q][0][0] < cutoff:
                d[q].popleft()

    def add_flow(self, ip, flow_doc, now=None):
        if now is None:
            now = time.time()
        d = self.ip_data[ip]
        self._cleanup(ip, now)

        # Flow add karo
        d['flows'].append((now, flow_doc))

        # Port track karo
        port = flow_doc.get('Destination Port', 0)
        try:
            d['ports'].append((now, int(float(port))))
        except Exception:
            pass

        # Bytes/Packets track karo
        try:
            bps = float(flow_doc.get('Flow Bytes/s', 0))
            pps = float(flow_doc.get('Flow Packets/s', 0))
            d['bytes'].append((now, bps))
            d['packets'].append((now, pps))
        except Exception:
            pass

        # SYN count
        try:
            syn = float(flow_doc.get('SYN Flag Count', 0))
            d['syn_count'].append((now, syn))
        except Exception:
            pass

        # Inter-flow interval (beaconing detection ke liye)
        if d['last_seen']:
            interval = now - d['last_seen']
            d['intervals'].append((now, interval))
        d['last_seen'] = now

        # Baseline update
        if not d['baseline_ready']:
            d['baseline_pkts'].append(pps if 'pps' in dir() else 0)
            d['baseline_bps'].append(bps if 'bps' in dir() else 0)
            if len(d['baseline_pkts']) >= MIN_FLOWS_BASELINE:
                d['baseline_ready'] = True

    def get_stats(self, ip, now=None):
        if now is None:
            now = time.time()
        d = self.ip_data[ip]
        self._cleanup(ip, now)

        flows   = list(d['flows'])
        ports   = list(d['ports'])
        bytes_  = list(d['bytes'])
        pkts    = list(d['packets'])
        syns    = list(d['syn_count'])
        intvals = list(d['intervals'])

        unique_ports   = len(set(p[1] for p in ports))
        total_flows    = len(flows)
        avg_pps        = np.mean([p[1] for p in pkts]) if pkts else 0
        avg_bps        = np.mean([b[1] for b in bytes_]) if bytes_ else 0
        total_syn      = sum(s[1] for s in syns)
        interval_std   = np.std([i[1] for i in intvals]) if len(intvals) > 2 else 999

        # Baseline comparison
        baseline_pps = np.mean(d['baseline_pkts']) if d['baseline_pkts'] else 0
        baseline_bps = np.mean(d['baseline_bps'])  if d['baseline_bps']  else 0
        pps_ratio    = avg_pps / max(baseline_pps, 1)
        bps_ratio    = avg_bps / max(baseline_bps, 1)

        return {
            'unique_ports'  : unique_ports,
            'total_flows'   : total_flows,
            'avg_pps'       : avg_pps,
            'avg_bps'       : avg_bps,
            'total_syn'     : total_syn,
            'interval_std'  : interval_std,
            'pps_ratio'     : pps_ratio,
            'bps_ratio'     : bps_ratio,
            'baseline_ready': d['baseline_ready'],
        }


# ══════════════════════════════════════════════
#  HEURISTIC ENGINE
# ══════════════════════════════════════════════
class HeuristicEngine:
    """
    Rule-based attack detection.
    AI model ke saath parallel chalta hai — dono mila ke final decision.
    """

    def analyze(self, ip, stats, flow_doc):
        """
        IP stats + flow features se heuristic analysis karo.
        Returns: list of detected threats
        """
        threats = []

        # ── Rule 1: PortScan Detection ──
        if stats['unique_ports'] >= PORTSCAN_PORTS_THRESHOLD:
            threats.append({
                'type'       : 'PORTSCAN',
                'confidence' : min(95, 60 + stats['unique_ports'] * 2),
                'reason'     : f"{stats['unique_ports']} unique ports in {IP_WINDOW}s",
                'severity'   : 'HIGH',
            })

        # SYN scan
        syn   = float(flow_doc.get('SYN Flag Count', 0))
        bwd   = float(flow_doc.get('Total Backward Packets', 0))
        if syn >= PORTSCAN_SYN_THRESHOLD and bwd <= 2:
            threats.append({
                'type'       : 'PORTSCAN',
                'confidence' : 85,
                'reason'     : f"SYN scan: {int(syn)} SYN packets, {int(bwd)} responses",
                'severity'   : 'HIGH',
            })

        # ── Rule 2: DoS/DDoS Detection ──
        pps = float(flow_doc.get('Flow Packets/s', 0))
        bps = float(flow_doc.get('Flow Bytes/s', 0))

        if pps >= DOS_PPS_THRESHOLD:
            threats.append({
                'type'       : 'DOS',
                'confidence' : min(95, 70 + pps / 100),
                'reason'     : f"High PPS: {pps:.0f} packets/sec",
                'severity'   : 'CRITICAL' if pps > 1000 else 'HIGH',
            })

        if bps >= DOS_BPS_THRESHOLD:
            threats.append({
                'type'       : 'DDOS',
                'confidence' : min(95, 70 + bps / 10000),
                'reason'     : f"High bandwidth: {bps/1024:.1f} KB/s",
                'severity'   : 'CRITICAL',
            })

        # ── Rule 3: Brute Force Detection ──
        dst_port = int(float(flow_doc.get('Destination Port', 0)))
        if dst_port in [22, 21, 3389, 23, 25, 110, 143]:
            if stats['total_flows'] >= BRUTE_FORCE_THRESHOLD:
                threats.append({
                    'type'       : 'BRUTE',
                    'confidence' : min(90, 60 + stats['total_flows']),
                    'reason'     : f"{stats['total_flows']} connections to port {dst_port}",
                    'severity'   : 'HIGH',
                })

        # ── Rule 4: C2 Beaconing Detection ──
        if (stats['interval_std'] < BEACONING_INTERVAL_STD_MAX and
                stats['total_flows'] >= 5 and
                stats['interval_std'] > 0):
            threats.append({
                'type'       : 'BEACONING',
                'confidence' : 75,
                'reason'     : f"Regular intervals detected (std={stats['interval_std']:.2f}s) — possible C2",
                'severity'   : 'MEDIUM',
            })

        # ── Rule 5: Behavioral Anomaly ──
        if stats['baseline_ready']:
            if stats['pps_ratio'] >= ANOMALY_MULTIPLIER:
                threats.append({
                    'type'       : 'ANOMALY',
                    'confidence' : min(85, 50 + stats['pps_ratio'] * 5),
                    'reason'     : f"Traffic {stats['pps_ratio']:.1f}x above baseline",
                    'severity'   : 'MEDIUM',
                })
            if stats['bps_ratio'] >= ANOMALY_MULTIPLIER:
                threats.append({
                    'type'       : 'ANOMALY',
                    'confidence' : min(85, 50 + stats['bps_ratio'] * 5),
                    'reason'     : f"Bandwidth {stats['bps_ratio']:.1f}x above baseline",
                    'severity'   : 'MEDIUM',
                })

        return threats


# ══════════════════════════════════════════════
#  IP RISK SCORER — Weighted Multi-Factor
# ══════════════════════════════════════════════
class IPRiskScorer:
    """
    Per-IP cumulative risk scoring with weighted factors.

    Risk Score (0–100) = weighted sum of:
      ├── AI Confidence (avg)       × 0.25
      ├── Alert Frequency (/min)    × 0.20
      ├── Attack Diversity           × 0.15
      ├── Max Severity               × 0.20
      ├── Behavioral Anomaly Ratio   × 0.10
      └── Recency Boost              × 0.10

    Scores decay over time so stale IPs don't stay red forever.
    """

    SEVERITY_SCORE = {'CRITICAL': 100, 'HIGH': 75, 'MEDIUM': 50, 'LOW': 25}
    RISK_LEVELS = [
        (80, 'CRITICAL'),   # 80-100
        (60, 'HIGH'),       # 60-79
        (40, 'MEDIUM'),     # 40-59
        (0,  'LOW'),        # 0-39
    ]

    # Factor weights (must sum to 1.0)
    W_AI_CONF       = 0.25
    W_ALERT_FREQ    = 0.20
    W_ATTACK_DIV    = 0.15
    W_SEVERITY      = 0.20
    W_ANOMALY       = 0.10
    W_RECENCY       = 0.10

    # Decay: risk score halves every DECAY_MINUTES without new alerts
    DECAY_MINUTES   = 10

    def __init__(self):
        # Per-IP tracking:  {ip: {...state...}}
        self.ip_state = defaultdict(lambda: {
            'total_alerts'     : 0,
            'total_conf'       : 0.0,       # sum of AI confidence %
            'attack_types'     : set(),      # unique attack labels
            'max_severity'     : 'LOW',
            'max_anomaly_ratio': 0.0,        # max(pps_ratio, bps_ratio)
            'first_alert'      : None,       # datetime
            'last_alert'       : None,       # datetime
            'risk_score'       : 0.0,
            'risk_level'       : 'LOW',
            'risk_factors'     : {},          # factor breakdown
        })

    def record_alert(self, ip, confidence, attack_type, severity,
                     anomaly_ratio=0.0):
        """
        Called once per alert for this IP.
        Updates accumulators — call calculate() after batch to get score.
        """
        s = self.ip_state[ip]
        now = datetime.now(timezone.utc)

        s['total_alerts']  += 1
        s['total_conf']    += confidence
        s['attack_types'].add(attack_type)

        sev_rank = self.SEVERITY_SCORE
        if sev_rank.get(severity, 0) > sev_rank.get(s['max_severity'], 0):
            s['max_severity'] = severity

        if anomaly_ratio > s['max_anomaly_ratio']:
            s['max_anomaly_ratio'] = anomaly_ratio

        if s['first_alert'] is None:
            s['first_alert'] = now
        s['last_alert'] = now

    def calculate(self, ip):
        """
        Compute the weighted risk score for an IP.
        Returns (risk_score, risk_level, factors_dict).
        """
        s = self.ip_state[ip]
        if s['total_alerts'] == 0:
            return 0.0, 'LOW', {}

        now = datetime.now(timezone.utc)

        # ── Factor 1: Average AI Confidence (0-100) ──
        avg_conf = s['total_conf'] / max(s['total_alerts'], 1)
        f_ai_conf = min(avg_conf, 100.0)  # already 0-100

        # ── Factor 2: Alert Frequency (alerts/minute → 0-100) ──
        elapsed_min = max(
            (now - s['first_alert']).total_seconds() / 60.0, 0.5
        ) if s['first_alert'] else 1.0
        alerts_per_min = s['total_alerts'] / elapsed_min
        # Scale: 0 apm → 0, 5+ apm → 100
        f_alert_freq = min(alerts_per_min / 5.0 * 100, 100.0)

        # ── Factor 3: Attack Diversity (0-100) ──
        # 1 type=20, 2=40, 3=60, 4=80, 5+=100
        n_types = len(s['attack_types'])
        f_attack_div = min(n_types * 20, 100.0)

        # ── Factor 4: Max Severity (0-100) ──
        f_severity = float(self.SEVERITY_SCORE.get(s['max_severity'], 25))

        # ── Factor 5: Behavioral Anomaly Ratio (0-100) ──
        # ratio=1 means normal, 3+ means ANOMALY_MULTIPLIER hit
        ratio = s['max_anomaly_ratio']
        # Scale: 1x → 0, 3x → 50, 10x+ → 100
        f_anomaly = min(max((ratio - 1.0) / 9.0 * 100, 0), 100.0)

        # ── Factor 6: Recency Boost (0-100) ──
        # 100 if last alert was just now, decays to 0 over DECAY_MINUTES
        if s['last_alert']:
            mins_ago = (now - s['last_alert']).total_seconds() / 60.0
            f_recency = max(100.0 - (mins_ago / self.DECAY_MINUTES * 100), 0)
        else:
            f_recency = 0.0

        # ── Weighted sum ──
        raw_score = (
            f_ai_conf    * self.W_AI_CONF    +
            f_alert_freq * self.W_ALERT_FREQ +
            f_attack_div * self.W_ATTACK_DIV +
            f_severity   * self.W_SEVERITY   +
            f_anomaly    * self.W_ANOMALY    +
            f_recency    * self.W_RECENCY
        )

        # ── Time-decay the overall score ──
        if s['last_alert']:
            mins_since = (now - s['last_alert']).total_seconds() / 60.0
            decay = 0.5 ** (mins_since / self.DECAY_MINUTES)
            risk_score = raw_score * decay
        else:
            risk_score = raw_score

        risk_score = round(min(risk_score, 100.0), 2)

        # ── Risk level ──
        risk_level = 'LOW'
        for threshold, level in self.RISK_LEVELS:
            if risk_score >= threshold:
                risk_level = level
                break

        # ── Factor breakdown (for dashboard / ES) ──
        factors = {
            'ai_confidence'     : round(f_ai_conf, 1),
            'alert_frequency'   : round(f_alert_freq, 1),
            'attack_diversity'  : round(f_attack_div, 1),
            'severity'          : round(f_severity, 1),
            'anomaly_ratio'     : round(f_anomaly, 1),
            'recency'           : round(f_recency, 1),
        }

        # Store for later retrieval
        s['risk_score']  = risk_score
        s['risk_level']  = risk_level
        s['risk_factors'] = factors

        return risk_score, risk_level, factors

    def get_top_risky(self, n=10):
        """
        Return top N riskiest IPs with their scores.
        Recalculates scores to apply latest decay.
        """
        results = []
        for ip in list(self.ip_state.keys()):
            score, level, factors = self.calculate(ip)
            if score > 0:
                results.append({
                    'ip'           : ip,
                    'risk_score'   : score,
                    'risk_level'   : level,
                    'total_alerts' : self.ip_state[ip]['total_alerts'],
                    'attack_types' : list(self.ip_state[ip]['attack_types']),
                    'max_severity' : self.ip_state[ip]['max_severity'],
                    'factors'      : factors,
                })
        results.sort(key=lambda x: x['risk_score'], reverse=True)
        return results[:n]

    def get_risk(self, ip):
        """Get current risk score for a single IP."""
        return self.calculate(ip)

    def get_summary(self):
        """Summary stats for the entire session."""
        all_ips = list(self.ip_state.keys())
        if not all_ips:
            return {'total_ips': 0, 'critical': 0, 'high': 0,
                    'medium': 0, 'low': 0, 'top_score': 0.0}
        levels = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        top = 0.0
        for ip in all_ips:
            score, level, _ = self.calculate(ip)
            levels[level] += 1
            if score > top:
                top = score
        return {
            'total_ips': len(all_ips),
            'critical' : levels['CRITICAL'],
            'high'     : levels['HIGH'],
            'medium'   : levels['MEDIUM'],
            'low'      : levels['LOW'],
            'top_score': top,
        }


# ══════════════════════════════════════════════
#  ATTACK CLASSIFIER — Multi-Signal Classification
# ══════════════════════════════════════════════
class AttackClassifier:
    """
    Multi-signal attack classification engine.
    Uses flow features, volume patterns, port distribution, and flag analysis
    to classify attacks into categories with kill-chain phase mapping.
    """

    # Kill-chain phases
    PHASES = {
        'RECONNAISSANCE': 1,
        'WEAPONIZATION' : 2,
        'DELIVERY'      : 3,
        'EXPLOITATION'  : 4,
        'INSTALLATION'  : 5,
        'C2'            : 6,
        'ACTIONS'       : 7,
    }

    # Attack category → (kill-chain phase, MITRE tactic, description)
    CATEGORIES = {
        'DDoS Volumetric Flood'   : ('ACTIONS',        'Impact',            'T1498.001'),
        'DDoS SYN Flood'          : ('ACTIONS',        'Impact',            'T1498.001'),
        'DDoS Application Layer'  : ('ACTIONS',        'Impact',            'T1499.002'),
        'DoS Slowloris'           : ('ACTIONS',        'Impact',            'T1499.001'),
        'DoS Resource Exhaustion' : ('ACTIONS',        'Impact',            'T1499'),
        'Port Scan (Horizontal)'  : ('RECONNAISSANCE', 'Discovery',         'T1046'),
        'Port Scan (Vertical)'    : ('RECONNAISSANCE', 'Discovery',         'T1046'),
        'SYN Scan'                : ('RECONNAISSANCE', 'Discovery',         'T1046'),
        'Brute Force SSH'         : ('EXPLOITATION',   'Credential Access', 'T1110.001'),
        'Brute Force RDP'         : ('EXPLOITATION',   'Credential Access', 'T1110.001'),
        'Brute Force FTP'         : ('EXPLOITATION',   'Credential Access', 'T1110.001'),
        'C2 Beaconing'            : ('C2',             'Command & Control', 'T1071.001'),
        'HTTP Flood'              : ('ACTIONS',        'Impact',            'T1499.002'),
        'DNS Amplification'       : ('ACTIONS',        'Impact',            'T1498.002'),
        'Web Exploit'             : ('EXPLOITATION',   'Initial Access',    'T1190'),
        'Data Exfiltration'       : ('ACTIONS',        'Exfiltration',      'T1041'),
        'Lateral Movement'        : ('INSTALLATION',   'Lateral Movement',  'T1021'),
        'Coordinated Campaign'    : ('ACTIONS',        'Impact',            'T1498'),
    }

    def classify(self, flows, stats):
        """
        Classify attack from a collection of flows from the same source IP.
        Returns: {category, phase, confidence, signals, sub_type}
        """
        if not flows:
            return self._default()

        signals = []
        scores = defaultdict(float)  # category → score

        # ── Signal 1: Volume Analysis ──
        total_pkts = sum(float(f.get('Total Fwd Packets', 0)) for f in flows)
        total_bytes = sum(float(f.get('Total Length of Fwd Packets', 0)) for f in flows)
        avg_pps = np.mean([float(str(f.get('Flow Packets/s', 0)).replace('Infinity', '0').replace('inf', '0')) for f in flows]) if flows else 0
        avg_bps = np.mean([float(str(f.get('Flow Bytes/s', 0)).replace('Infinity', '0').replace('inf', '0')) for f in flows]) if flows else 0
        flow_count = len(flows)

        if avg_pps > DOS_PPS_THRESHOLD:
            signals.append(f"High PPS: {avg_pps:.0f}/s")
            scores['DDoS Volumetric Flood'] += 30
        if avg_bps > DOS_BPS_THRESHOLD:
            signals.append(f"High BPS: {avg_bps/1024:.0f} KB/s")
            scores['DDoS Volumetric Flood'] += 25

        # ── Signal 2: Port Distribution ──
        ports = [int(float(f.get('Destination Port', 0))) for f in flows]
        unique_ports = len(set(ports))
        if unique_ports >= PORTSCAN_PORTS_THRESHOLD:
            signals.append(f"{unique_ports} unique ports scanned")
            if unique_ports > 50:
                scores['Port Scan (Horizontal)'] += 60  # Override DoS easily
                scores['DDoS Volumetric Flood'] -= 20   # DoS targets 1 port usually
            else:
                scores['Port Scan (Vertical)'] += 45

        # ── Signal 3: Flag Analysis ──
        total_syn = sum(float(f.get('SYN Flag Count', 0)) for f in flows)
        total_rst = sum(float(f.get('RST Flag Count', 0)) for f in flows)
        total_bwd = sum(float(f.get('Total Backward Packets', 0)) for f in flows)

        if total_syn > 50 and total_bwd < total_syn * 0.1:
            signals.append(f"SYN flood: {int(total_syn)} SYN, {int(total_bwd)} responses")
            scores['DDoS SYN Flood'] += 40
        if total_rst > 20 and total_bwd < 5:
            signals.append(f"RST pattern: {int(total_rst)} resets")
            scores['SYN Scan'] += 30

        # ── Signal 4: Service-Specific ──
        port_counts = defaultdict(int)
        for p in ports:
            port_counts[p] += 1
        top_port = max(port_counts, key=port_counts.get) if port_counts else 0
        top_port_hits = port_counts.get(top_port, 0)

        if top_port in (22,) and top_port_hits >= BRUTE_FORCE_THRESHOLD:
            signals.append(f"SSH brute: {top_port_hits} attempts on port 22")
            scores['Brute Force SSH'] += 45
        elif top_port in (3389,) and top_port_hits >= BRUTE_FORCE_THRESHOLD:
            signals.append(f"RDP brute: {top_port_hits} attempts on port 3389")
            scores['Brute Force RDP'] += 45
        elif top_port in (21,) and top_port_hits >= BRUTE_FORCE_THRESHOLD:
            signals.append(f"FTP brute: {top_port_hits} attempts on port 21")
            scores['Brute Force FTP'] += 45
        elif top_port in (80, 443, 8080) and avg_pps > 100:
            signals.append(f"HTTP flood: {avg_pps:.0f} pps to port {top_port}")
            scores['HTTP Flood'] += 35
        elif top_port == 53 and avg_pps > 50:
            signals.append(f"DNS amplification: {avg_pps:.0f} pps to port 53")
            scores['DNS Amplification'] += 35

        # ── Signal 5: Timing Regularity (C2 Beaconing) ──
        if stats and stats.get('interval_std', 999) < BEACONING_INTERVAL_STD_MAX:
            if flow_count >= 5:
                signals.append(f"Regular intervals (std={stats['interval_std']:.2f}s)")
                scores['C2 Beaconing'] += 40

        # ── Signal 6: One-way flood detection ──
        one_way_count = sum(1 for f in flows if float(f.get('Total Backward Packets', 0)) == 0)
        if one_way_count > flow_count * 0.8 and flow_count > 10:
            signals.append(f"{one_way_count}/{flow_count} one-way flows (flood indicator)")
            scores['DDoS Volumetric Flood'] += 20
            scores['DoS Resource Exhaustion'] += 15

        # ── Signal 7: Application-layer slow attacks ──
        long_flows = sum(1 for f in flows if float(f.get('Flow Duration', 0)) > 30_000_000)
        if long_flows > flow_count * 0.5 and avg_pps < 10:
            signals.append(f"{long_flows} slow/long connections")
            scores['DoS Slowloris'] += 35
            scores['DDoS Application Layer'] += 25

        # ── Determine Winner ──
        if not scores:
            return self._default(signals=signals, flow_count=flow_count)

        best_cat = max(scores, key=scores.get)
        best_score = scores[best_cat]
        confidence = min(best_score + flow_count * 0.5, 99.0)

        phase_name = self.CATEGORIES.get(best_cat, ('ACTIONS', 'Impact', 'T1498'))[0]
        mitre_tactic = self.CATEGORIES.get(best_cat, ('ACTIONS', 'Impact', 'T1498'))[1]
        mitre_id = self.CATEGORIES.get(best_cat, ('ACTIONS', 'Impact', 'T1498'))[2]

        # ── Campaign detection: multiple high-scoring categories ──
        high_cats = [c for c, s in scores.items() if s >= 25]
        is_campaign = len(high_cats) >= 3
        if is_campaign:
            signals.append(f"Multi-vector campaign: {', '.join(high_cats[:3])}")

        return {
            'category'      : best_cat,
            'phase'         : phase_name,
            'phase_order'   : self.PHASES.get(phase_name, 7),
            'confidence'    : round(confidence, 1),
            'signals'       : signals,
            'all_scores'    : {k: round(v, 1) for k, v in sorted(scores.items(), key=lambda x: -x[1])},
            'mitre_tactic'  : mitre_tactic,
            'mitre_id'      : mitre_id,
            'is_campaign'   : is_campaign,
            'flow_count'    : flow_count,
            'total_packets' : int(total_pkts),
            'total_bytes'   : int(total_bytes),
        }

    def _default(self, signals=None, flow_count=0):
        return {
            'category'      : 'Advanced Attack (AI Detected)',
            'phase'         : 'ACTIONS',
            'phase_order'   : 7,
            'confidence'    : 70.0,
            'signals'       : signals or [],
            'all_scores'    : {},
            'mitre_tactic'  : 'Impact',
            'mitre_id'      : 'T1498',
            'is_campaign'   : False,
            'flow_count'    : flow_count,
            'total_packets' : 0,
            'total_bytes'   : 0,
        }


# ══════════════════════════════════════════════
#  INCIDENT CORRELATION ENGINE — Groups Events Per IP
# ══════════════════════════════════════════════
class IncidentCorrelationEngine:
    """
    Groups all attack events from the same source IP into ONE unified incident.

    Instead of 500 individual alerts for a DDoS from one IP, you get:
      - 1 Incident with 500 evidence items
      - Attack timeline (first_seen → last_seen → duration)
      - Auto-escalating severity
      - Classification with kill-chain phase
      - Victim list

    Incident lifecycle:
      NEW → ACTIVE → ESCALATED → CONTAINED → CLOSED
    """

    ESCALATION_THRESHOLDS = {
        'LOW_TO_MEDIUM'     : 5,     # 5+ events → MEDIUM
        'MEDIUM_TO_HIGH'    : 20,    # 20+ events → HIGH
        'HIGH_TO_CRITICAL'  : 50,    # 50+ events → CRITICAL
    }

    # Merge window: events from same IP within this window = same incident
    MERGE_WINDOW_SECONDS = 300  # 5 minutes

    def __init__(self):
        # {src_ip: incident_data}
        self.incidents = {}
        self.classifier = AttackClassifier()
        self._inc_counter = 0
        # Track which IPs had console output this batch (avoid spam)
        self._batch_printed = set()
        # Prune closed incidents every 50 ingestions
        self._batch_count = 0

    def _new_incident_id(self):
        self._inc_counter += 1
        ts = datetime.now().strftime('%Y%m%d')
        return f"INC-{ts}-{self._inc_counter:04d}"

    def _prune_closed_incidents(self, max_closed=500):
        """Remove oldest CLOSED incidents to prevent memory creep."""
        closed = [(k, v['last_seen']) for k, v in self.incidents.items()
                  if v['status'] == 'CLOSED']
        if len(closed) > max_closed:
            closed.sort(key=lambda x: x[1])
            for k, _ in closed[:len(closed) - max_closed]:
                del self.incidents[k]

    def ingest_alert(self, src_ip, dst_ip, flow_doc, ai_conf,
                     attack_type, severity, sensor, mitre_t,
                     mitre_tac, blocked):
        """
        Ingest a single alert event. Automatically correlates into
        the existing incident for this src_ip, or creates a new one.
        Returns: (incident_id, is_new, incident_data)
        """
        self._batch_count += 1
        if self._batch_count >= 50:
            self._prune_closed_incidents()
            self._batch_count = 0

        now = datetime.now(timezone.utc)
        sev_rank = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}

        if src_ip in self.incidents:
            inc = self.incidents[src_ip]
            # Check if existing incident is stale (beyond merge window)
            last = datetime.fromisoformat(inc['last_seen'])
            if (now - last).total_seconds() > self.MERGE_WINDOW_SECONDS:
                # Close old, start new
                inc['status'] = 'CLOSED'
                self.incidents.pop(src_ip)
                return self._create_incident(
                    src_ip, dst_ip, flow_doc, ai_conf, attack_type,
                    severity, sensor, mitre_t, mitre_tac, blocked, now)

            # ── Update existing incident ──
            inc['event_count'] += 1
            inc['last_seen'] = now.isoformat()
            inc['duration_seconds'] = (now - datetime.fromisoformat(inc['first_seen'])).total_seconds()
            inc['total_confidence'] += ai_conf
            inc['avg_confidence'] = inc['total_confidence'] / inc['event_count']

            # Track victims
            if dst_ip and dst_ip != '0.0.0.0':
                inc['victims'].add(dst_ip)

            # Track attack types seen
            inc['attack_types_seen'].add(attack_type)

            # Accumulate flow evidence — capped at 3 to limit RAM
            if len(inc['evidence_flows']) < 3:
                inc['evidence_flows'].append(flow_doc)

            # Auto-escalate severity
            old_sev = inc['severity']
            new_sev = self._auto_escalate(inc['event_count'], severity, old_sev)
            if sev_rank.get(new_sev, 0) > sev_rank.get(old_sev, 0):
                inc['severity'] = new_sev
                inc['status'] = 'ESCALATED'
                inc['escalation_history'].append({
                    'time': now.isoformat(),
                    'from': old_sev,
                    'to': new_sev,
                    'trigger': f"Event #{inc['event_count']}"
                })

            # Reclassify with accumulated evidence
            stats = inc.get('_cached_stats', {})
            classification = self.classifier.classify(inc['evidence_flows'], stats)
            inc['classification'] = classification

            if blocked and not inc['blocked']:
                inc['blocked'] = True
                inc['status'] = 'CONTAINED'

            return inc['incident_id'], False, inc
        else:
            return self._create_incident(
                src_ip, dst_ip, flow_doc, ai_conf, attack_type,
                severity, sensor, mitre_t, mitre_tac, blocked, now)

    def _create_incident(self, src_ip, dst_ip, flow_doc, ai_conf,
                         attack_type, severity, sensor, mitre_t,
                         mitre_tac, blocked, now):
        inc_id = self._new_incident_id()
        classification = self.classifier.classify([flow_doc], {})
        inc = {
            'incident_id'        : inc_id,
            'src_ip'             : src_ip,
            'victims'            : {dst_ip} if dst_ip and dst_ip != '0.0.0.0' else set(),
            'status'             : 'CONTAINED' if blocked else 'NEW',
            'severity'           : severity,
            'primary_attack'     : attack_type,
            'attack_types_seen'  : {attack_type},
            'classification'     : classification,
            'event_count'        : 1,
            'first_seen'         : now.isoformat(),
            'last_seen'          : now.isoformat(),
            'duration_seconds'   : 0,
            'sensor'             : sensor,
            'mitre_technique'    : mitre_t,
            'mitre_tactic'       : mitre_tac,
            'blocked'            : blocked,
            'total_confidence'   : ai_conf,
            'avg_confidence'     : ai_conf,
            'escalation_history' : [],
            'evidence_flows'     : [flow_doc],  # capped at 3 to limit RAM
            '_MAX_EVIDENCE'      : 3,
            '_cached_stats'      : {},
        }
        self.incidents[src_ip] = inc
        return inc_id, True, inc

    def _auto_escalate(self, event_count, current_alert_sev, incident_sev):
        """Auto-escalate based on event volume."""
        sev_rank = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
        # Start from highest of (current incident, current alert)
        base = max(sev_rank.get(incident_sev, 1), sev_rank.get(current_alert_sev, 1))

        if event_count >= self.ESCALATION_THRESHOLDS['HIGH_TO_CRITICAL']:
            return 'CRITICAL'
        elif event_count >= self.ESCALATION_THRESHOLDS['MEDIUM_TO_HIGH']:
            return max('HIGH', incident_sev, key=lambda s: sev_rank.get(s, 0))
        elif event_count >= self.ESCALATION_THRESHOLDS['LOW_TO_MEDIUM']:
            return max('MEDIUM', incident_sev, key=lambda s: sev_rank.get(s, 0))
        # Return highest of incident or current alert severity
        return incident_sev if base <= sev_rank.get(incident_sev, 1) else current_alert_sev

    def update_stats(self, src_ip, stats):
        """Cache behavioral stats for reclassification."""
        if src_ip in self.incidents:
            self.incidents[src_ip]['_cached_stats'] = stats

    def get_incident(self, src_ip):
        return self.incidents.get(src_ip)

    def get_all_active(self):
        """Return all active (non-closed) incidents sorted by severity."""
        sev_rank = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
        active = [i for i in self.incidents.values() if i['status'] != 'CLOSED']
        return sorted(active, key=lambda x: (sev_rank.get(x['severity'], 0),
                                              x['event_count']), reverse=True)

    def reset_batch_printed(self):
        """Call at start of each batch to reset print tracking."""
        self._batch_printed = set()

    def should_print(self, src_ip):
        """Returns True only on first event per IP per batch."""
        if src_ip in self._batch_printed:
            return False
        self._batch_printed.add(src_ip)
        return True

    def save_to_es(self, es, src_ip):
        """Save/update correlated incident to Elasticsearch."""
        inc = self.incidents.get(src_ip)
        if not inc:
            return
        doc = {
            '@timestamp'         : datetime.now(timezone.utc).isoformat(),
            'incident_id'        : inc['incident_id'],
            'status'             : inc['status'],
            'severity'           : inc['severity'],
            'src_ip'             : inc['src_ip'],
            'victims'            : list(inc['victims']),
            'primary_attack'     : inc['primary_attack'],
            'attack_types_seen'  : list(inc['attack_types_seen']),
            'event_count'        : inc['event_count'],
            'first_seen'         : inc['first_seen'],
            'last_seen'          : inc['last_seen'],
            'duration_seconds'   : round(inc['duration_seconds'], 1),
            'sensor_name'        : inc['sensor'],
            'mitre_technique'    : inc['mitre_technique'],
            'mitre_tactic'       : inc['mitre_tactic'],
            'blocked'            : inc['blocked'],
            'avg_confidence'     : round(inc['avg_confidence'], 2),
            'response_action'    : 'AUTO_BLOCK' if inc['blocked'] else 'HUMAN_REVIEW',
            'classification'     : {
                'category'    : inc['classification'].get('category', ''),
                'phase'       : inc['classification'].get('phase', ''),
                'confidence'  : inc['classification'].get('confidence', 0),
                'signals'     : inc['classification'].get('signals', [])[:10],
                'is_campaign' : inc['classification'].get('is_campaign', False),
                'flow_count'  : inc['classification'].get('flow_count', 0),
                'total_packets': inc['classification'].get('total_packets', 0),
            },
            'escalation_count'   : len(inc['escalation_history']),
            'ttd_seconds'        : round(inc['duration_seconds'], 1),
            'ttr_seconds'        : round(inc['duration_seconds'] + 5, 1) if inc['blocked'] else 0,
        }

        # Use incident_id as doc ID for upsert
        try:
            es.index(index=INCIDENTS_INDEX, id=inc['incident_id'], document=doc)
        except Exception as e:
            print(f"  [CORR] ES save error: {e}")

    def print_incident_line(self, src_ip):
        """Print a single consolidated line for this IP's incident."""
        inc = self.incidents.get(src_ip)
        if not inc:
            return

        sev = inc['severity']
        sym = '🔴' if sev == 'CRITICAL' else '🟠' if sev == 'HIGH' else '🟡' if sev == 'MEDIUM' else '⚪'
        status = inc['status']
        cat = inc['classification'].get('category', inc['primary_attack'])
        phase = inc['classification'].get('phase', '?')
        victims = ', '.join(list(inc['victims'])[:3])
        signals = inc['classification'].get('signals', [])
        top_signal = signals[0] if signals else ''

        evt = inc['event_count']
        conf = inc['avg_confidence']
        dur = inc['duration_seconds']

        # Format duration
        if dur < 60:
            dur_str = f"{dur:.0f}s"
        else:
            dur_str = f"{dur/60:.1f}m"

        print(f"\n  {sym} INCIDENT {inc['incident_id']} | {status}")
        print(f"     ATTACKER : {src_ip}  →  VICTIM(s): {victims or 'N/A'}")
        print(f"     ATTACK   : {cat} [{phase}]  |  {evt} events  |  {dur_str}")
        print(f"     CONF     : {conf:.1f}%  |  SEV: {sev}")
        if top_signal:
            print(f"     SIGNAL   : {top_signal}")
        if inc['classification'].get('is_campaign'):
            print(f"     ⚠️  MULTI-VECTOR CAMPAIGN DETECTED")


# ══════════════════════════════════════════════
#  ELK SETUP
# ══════════════════════════════════════════════
def connect_elk():
    es = Elasticsearch(
        ES_HOST,
        request_timeout  = 30,
        retry_on_timeout = True,
        max_retries      = 3,
    )
    if not es.ping():
        print(f"[ERROR] ELK not reachable: {ES_HOST}")
        sys.exit(1)
    print(f"[ELK] Connected: {ES_HOST}")
    return es


def load_model():
    for path, name in [(MODEL_PATH, 'model'), (SCALER_PATH, 'scaler')]:
        if not os.path.exists(path):
            print(f"[ERROR] {name} not found: {path}")
            sys.exit(1)

    model_artifact  = joblib.load(MODEL_PATH)
    scaler_artifact = joblib.load(SCALER_PATH)

    # ── Stacking model (fine_tuned_model.py format) ──
    if isinstance(model_artifact, dict) and model_artifact.get('type') == 'stacking':
        base_model   = model_artifact['base_model']
        base_scaler  = model_artifact['base_scaler']
        stack_scaler = model_artifact['stack_scaler']
        meta_learner = model_artifact['meta_learner']

        model  = StackingPredictor(base_model, stack_scaler, meta_learner)
        scaler = base_scaler       # pre-scaling uses the base scaler

        datasets = model_artifact.get('datasets', [])
        ft_acc   = model_artifact.get('fine_tune_acc', 0)
        print(f"[MODEL] ✅ Stacking pipeline loaded: {MODEL_PATH}")
        print(f"[MODEL]   Base    : {type(base_model).__name__} "
              f"({getattr(base_model, 'n_features_in_', '?')} features)")
        print(f"[MODEL]   Meta    : {type(meta_learner).__name__}")
        print(f"[MODEL]   Datasets: {', '.join(datasets)}")
        print(f"[MODEL]   Fine-tune accuracy: {ft_acc*100:.2f}%")
        return model, scaler

    # ── Fallback: plain model / generic dict bundle ──
    def _unwrap(obj):
        if isinstance(obj, dict):
            for key in ('model', 'estimator', 'classifier', 'clf'):
                candidate = obj.get(key)
                if candidate is not None and hasattr(candidate, 'predict'):
                    return candidate
            for candidate in obj.values():
                if hasattr(candidate, 'predict'):
                    return candidate
        return obj

    model  = _unwrap(model_artifact)
    scaler = _unwrap(scaler_artifact)

    if not hasattr(model, 'predict'):
        print(f"[ERROR] Invalid model artifact: {MODEL_PATH}")
        sys.exit(1)
    if not hasattr(scaler, 'transform'):
        print(f"[ERROR] Invalid scaler artifact: {SCALER_PATH}")
        sys.exit(1)

    n_features = getattr(model, 'n_features_in_', len(FEATURES))
    print(f"[MODEL] Loaded (plain): {MODEL_PATH} ({n_features} features)")
    return model, scaler


def ensure_indices(es):
    """Sab required indices create karo"""

    # Alerts index
    if not es.indices.exists(index=ALERTS_INDEX):
        es.indices.create(index=ALERTS_INDEX, mappings={
            "properties": {
                "@timestamp"     : {"type": "date"},
                "timestamp"      : {"type": "date"},
                "src_ip"         : {"type": "keyword"},
                "dst_ip"         : {"type": "keyword"},
                "sensor_name"    : {"type": "keyword"},
                "attack_type"    : {"type": "keyword"},
                "detection_method": {"type": "keyword"},
                "confidence"     : {"type": "float"},
                "severity"       : {"type": "keyword"},
                "action"         : {"type": "keyword"},
                "reason"         : {"type": "text"},
                "mitre_technique": {"type": "keyword"},
                "mitre_tactic"   : {"type": "keyword"},
                "mitre_name"     : {"type": "keyword"},
                "blocked"        : {"type": "boolean"},
                "heuristic_threats": {"type": "integer"},
                "ai_confidence"  : {"type": "float"},
            }
        })
        print(f"[ELK] Created: {ALERTS_INDEX}")

    # Behavior index (IP behavioral stats + risk scoring)
    if not es.indices.exists(index=BEHAVIOR_INDEX):
        es.indices.create(index=BEHAVIOR_INDEX, mappings={
            "properties": {
                "@timestamp"  : {"type": "date"},
                "ip"          : {"type": "keyword"},
                "unique_ports": {"type": "integer"},
                "total_flows" : {"type": "integer"},
                "avg_pps"     : {"type": "float"},
                "avg_bps"     : {"type": "float"},
                "total_syn"   : {"type": "float"},
                "pps_ratio"   : {"type": "float"},
                "bps_ratio"   : {"type": "float"},
                "risk_score"  : {"type": "float"},
                "risk_level"  : {"type": "keyword"},
                "alert_count" : {"type": "integer"},
                "attack_types": {"type": "keyword"},
                "max_severity": {"type": "keyword"},
                "risk_factors" : {
                    "properties": {
                        "ai_confidence"    : {"type": "float"},
                        "alert_frequency"  : {"type": "float"},
                        "attack_diversity" : {"type": "float"},
                        "severity"         : {"type": "float"},
                        "anomaly_ratio"    : {"type": "float"},
                        "recency"          : {"type": "float"},
                    }
                },
                "status"      : {"type": "keyword"},
            }
        })
        print(f"[ELK] Created: {BEHAVIOR_INDEX}")

    # Incidents index (SOAR + Correlation Engine)
    if not es.indices.exists(index=INCIDENTS_INDEX):
        es.indices.create(index=INCIDENTS_INDEX, mappings={"properties": {
            "@timestamp":{"type":"date"},"incident_id":{"type":"keyword"},
            "status":{"type":"keyword"},"severity":{"type":"keyword"},
            "src_ip":{"type":"keyword"},"dst_ip":{"type":"keyword"},
            "victims":{"type":"keyword"},
            "primary_attack":{"type":"keyword"},
            "attack_type":{"type":"keyword"},
            "attack_types_seen":{"type":"keyword"},
            "event_count":{"type":"integer"},
            "alert_count":{"type":"integer"},
            "first_seen":{"type":"date"},"last_seen":{"type":"date"},
            "duration_seconds":{"type":"float"},
            "sensor_name":{"type":"keyword"},"mitre_technique":{"type":"keyword"},
            "mitre_tactic":{"type":"keyword"},"response_action":{"type":"keyword"},
            "blocked":{"type":"boolean"},"assigned_to":{"type":"keyword"},
            "avg_confidence":{"type":"float"},
            "classification": {"properties": {
                "category":{"type":"keyword"},
                "phase":{"type":"keyword"},
                "confidence":{"type":"float"},
                "signals":{"type":"text"},
                "is_campaign":{"type":"boolean"},
                "flow_count":{"type":"integer"},
                "total_packets":{"type":"long"},
            }},
            "escalation_count":{"type":"integer"},
            "notes":{"type":"text"},"ttd_seconds":{"type":"float"},
            "ttr_seconds":{"type":"float"},
        }})
        print(f"[ELK] Created: {INCIDENTS_INDEX}")

    # Responses index (SOAR)
    if not es.indices.exists(index=RESPONSES_INDEX):
        es.indices.create(index=RESPONSES_INDEX, mappings={"properties": {
            "@timestamp":{"type":"date"},"incident_id":{"type":"keyword"},
            "action_type":{"type":"keyword"},"src_ip":{"type":"keyword"},
            "status":{"type":"keyword"},"method":{"type":"keyword"},
            "details":{"type":"text"},
        }})
        print(f"[ELK] Created: {RESPONSES_INDEX}")


# ══════════════════════════════════════════════
#  FETCH + PREDICT
# ══════════════════════════════════════════════
_seen_ids = set()
_scroll_id = None
_search_after = None       # for search_after pagination

def fetch_flows(es, last_ts, size=BATCH_SIZE):
    global _seen_ids, _scroll_id, _search_after

    # ── Strategy: filter by @timestamp >= last_ts to query only new/live data ──
    try:
        query = {
            "query": {
                "range": {
                    "@timestamp": {
                        "gte": last_ts
                    }
                }
            },
            "size": size,
            "sort": [
                {"@timestamp": {"order": "asc", "unmapped_type": "date"}},
                {"_doc": {"order": "asc"}}
            ]
        }

        # If we have a cursor from previous batch, paginate forward
        if _search_after is not None:
            query["search_after"] = _search_after

        resp = es.search(index=f"{FLOWS_INDEX}*", **query)
        hits = resp['hits']['hits']

        if not hits:
            return pd.DataFrame(), last_ts, []

        # Save cursor for next batch
        _search_after = hits[-1]['sort']

        rows = [h['_source'] for h in hits]
        ids  = [h['_id']     for h in hits]
        df   = pd.DataFrame(rows)

        # Update last_ts if @timestamp exists
        new_ts = hits[-1]['_source'].get('@timestamp', last_ts)

        _seen_ids.update(ids)
        if len(_seen_ids) > 50000:
            _seen_ids = set(list(_seen_ids)[-25000:])

        return df, new_ts, ids
    except Exception as e:
        print(f"[FETCH] Error: {e}")
        return pd.DataFrame(), last_ts, []

def ai_predict(df, model, scaler):
    df = df.copy()
    df.columns = df.columns.str.strip()
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    # Clip extreme values — all numeric columns
    for col in df.select_dtypes(include=[np.number]).columns:
            df[col] = df[col].clip(-1e9, 1e9)
    RENAME = {
        'Dst Port'                  : 'Destination Port',
        'Total Fwd Packet'          : 'Total Fwd Packets',
        'Total Bwd packets'         : 'Total Backward Packets',
        'Total Length of Fwd Packet': 'Total Length of Fwd Packets',
        'Total Length of Bwd Packet': 'Total Length of Bwd Packets',
        'Packet Length Min'         : 'Min Packet Length',
        'Packet Length Max'         : 'Max Packet Length',
        'CWR Flag Count'            : 'CWE Flag Count',
        'Fwd Segment Size Avg'      : 'Avg Fwd Segment Size',
        'Bwd Segment Size Avg'      : 'Avg Bwd Segment Size',
        'Fwd Seg Size Min'          : 'min_seg_size_forward',
        'Fwd Bytes/Bulk Avg'        : 'Fwd Avg Bytes/Bulk',
        'Fwd Packet/Bulk Avg'       : 'Fwd Avg Packets/Bulk',
        'Fwd Bulk Rate Avg'         : 'Fwd Avg Bulk Rate',
        'Bwd Bytes/Bulk Avg'        : 'Bwd Avg Bytes/Bulk',
        'Bwd Packet/Bulk Avg'       : 'Bwd Avg Packets/Bulk',
        'Bwd Bulk Rate Avg'         : 'Bwd Avg Bulk Rate',
        'FWD Init Win Bytes'        : 'Init_Win_bytes_forward',
        'Bwd Init Win Bytes'        : 'Init_Win_bytes_backward',
        'Fwd Act Data Pkts'         : 'act_data_pkt_fwd',
        'Src IP'                    : 'src_ip',
        'Dst IP'                    : 'dst_ip',
    }
    df.rename(columns=RENAME, inplace=True)
    # Fwd Header Length.1 — duplicate of Fwd Header Length
    if 'Fwd Header Length.1' not in df.columns and 'Fwd Header Length' in df.columns:
        df['Fwd Header Length.1'] = df['Fwd Header Length']
    # Fill missing features with 0
    for f in FEATURES:
        if f not in df.columns:
            df[f] = 0.0

    for col in FEATURES:
        df[col] = pd.to_numeric(df[col], errors="coerce")
        df[col] = df[col].replace([np.inf, -np.inf], 0).fillna(0).clip(-1e9, 1e9)

    scaled = scaler.transform(df[FEATURES])
    preds  = model.predict(scaled)
    probas = model.predict_proba(scaled)[:, 1]
    return preds.tolist(), probas.tolist()


# ══════════════════════════════════════════════
#  ALERT PROCESSING
# ══════════════════════════════════════════════
def get_severity(confidence):
    if confidence >= 95: return 'CRITICAL'
    if confidence >= 90: return 'HIGH'
    if confidence >= 70: return 'MEDIUM'
    return 'LOW'


def get_mitre(attack_type):
    for key, val in MITRE_MAP.items():
        if key in attack_type.upper():
            return val
    return MITRE_MAP['ATTACK']


def block_ip(ip, reason):
    os.makedirs(os.path.dirname(BLOCKED_LOG), exist_ok=True)
    with open(BLOCKED_LOG, 'a') as f:
        f.write(f"{datetime.now().isoformat()} | BLOCKED | IP={ip} | {reason}\n")
    try:
        import subprocess, platform
        if platform.system() == 'Linux':
            subprocess.run(
                ['sudo', 'iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'],
                capture_output=True, timeout=10
            )
        elif platform.system() == 'Windows':
            rule_name = f"CogSOC_AutoBlock_{ip}"
            cmd = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={ip}'
            subprocess.run(cmd, shell=True, capture_output=True, timeout=10)
    except Exception:
        pass
    return True


def send_alert_email(incident_id, src_ip, dst_ip, attack_type, severity,
                     mitre_technique, sensor, alert_count, blocked):
    """Send email alert for CRITICAL/HIGH incidents. Rate-limited per IP."""
    if not EMAIL_ENABLED:
        return
    # Rate limit: 1 email per IP per cooldown period
    now = datetime.now(timezone.utc)
    last = _email_last_sent.get(src_ip)
    if last and (now - last).total_seconds() < EMAIL_COOLDOWN:
        return

    status_color = '#ef4444' if severity == 'CRITICAL' else '#f59e0b'
    blocked_text = 'AUTO-BLOCKED' if blocked else 'NEEDS REVIEW'
    blocked_color = '#10b981' if blocked else '#ef4444'

    html = f"""
    <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;
                background:#0f172a;color:#e2e8f0;border-radius:12px;overflow:hidden">
      <div style="background:linear-gradient(135deg,#1e1b4b,#0f172a);padding:20px 24px;
                  border-bottom:2px solid {status_color}">
        <h2 style="margin:0;color:#fff">CogSOC Alert</h2>
        <p style="margin:4px 0 0;color:#94a3b8;font-size:13px">AI-Driven Autonomous Defense</p>
      </div>
      <div style="padding:24px">
        <div style="background:rgba(239,68,68,0.1);border:1px solid {status_color};
                    border-radius:8px;padding:16px;margin-bottom:16px">
          <span style="background:{status_color};color:#fff;padding:4px 12px;
                       border-radius:20px;font-size:12px;font-weight:700">{severity}</span>
          <span style="background:{blocked_color};color:#fff;padding:4px 12px;
                       border-radius:20px;font-size:12px;font-weight:700;margin-left:8px">{blocked_text}</span>
          <h3 style="margin:12px 0 4px;color:#fff">{attack_type}</h3>
          <p style="margin:0;color:#94a3b8;font-size:13px">Incident: {incident_id}</p>
        </div>
        <table style="width:100%;font-size:14px;color:#cbd5e1">
          <tr><td style="padding:8px 0;color:#64748b">Attacker IP</td>
              <td style="padding:8px 0"><strong style="color:#ef4444">{src_ip}</strong></td></tr>
          <tr><td style="padding:8px 0;color:#64748b">Victim IP</td>
              <td style="padding:8px 0"><strong>{dst_ip}</strong></td></tr>
          <tr><td style="padding:8px 0;color:#64748b">MITRE ATT&CK</td>
              <td style="padding:8px 0">{mitre_technique}</td></tr>
          <tr><td style="padding:8px 0;color:#64748b">Sensor</td>
              <td style="padding:8px 0">{sensor}</td></tr>
          <tr><td style="padding:8px 0;color:#64748b">Alerts</td>
              <td style="padding:8px 0">{alert_count}</td></tr>
          <tr><td style="padding:8px 0;color:#64748b">Time</td>
              <td style="padding:8px 0">{now.strftime('%Y-%m-%d %H:%M:%S UTC')}</td></tr>
        </table>
        <div style="margin-top:20px;padding:12px;background:rgba(59,130,246,0.1);
                    border-radius:8px;font-size:12px;color:#94a3b8">
          View dashboard: <a href="http://localhost:8050" style="color:#3b82f6">http://localhost:8050</a>
        </div>
      </div>
    </div>
    """

    msg = MIMEMultipart('alternative')
    msg['Subject'] = f'[CogSOC {severity}] {attack_type} from {src_ip}'
    msg['From'] = EMAIL_SENDER
    msg['To'] = ', '.join(EMAIL_RECIPIENTS)
    msg.attach(MIMEText(html, 'html'))

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL_SENDER, EMAIL_PASSWORD)
            server.send_message(msg)
        _email_last_sent[src_ip] = now
        print(f"  [EMAIL] Alert sent for {src_ip} ({attack_type})")
    except Exception as e:
        print(f"  [EMAIL] Failed: {e}")


def send_trusted_ip_notification(src_ip, attack_type, severity, ai_conf,
                                  mitre_info, flow_doc, dashboard_host='localhost:8050'):
    """
    Send informational email to trusted device owner AFTER the IP has been auto-blocked.
    No action buttons — just details about why it was blocked and what activities were detected.
    Rate-limited: 1 email per trusted IP per EMAIL_COOLDOWN period.
    """
    if not EMAIL_ENABLED or src_ip not in TRUSTED_INTERNAL_IPS:
        return

    # Rate limit: don't spam the owner
    now = datetime.now(timezone.utc)
    last = _trusted_notified.get(src_ip)
    if last and (now - last).total_seconds() < EMAIL_COOLDOWN:
        return

    device = TRUSTED_INTERNAL_IPS[src_ip]
    device_name = device.get('name', 'Unknown Device')
    owner_email = device.get('owner', '')
    mitre_id, mitre_tactic, mitre_name = mitre_info

    # Extract activity details from flow
    dst_port = int(float(flow_doc.get('Destination Port', 0)))
    pps = float(flow_doc.get('Flow Packets/s', 0))
    bps = float(flow_doc.get('Flow Bytes/s', 0))
    fwd_pkts = int(float(flow_doc.get('Total Fwd Packets', 0)))
    bwd_pkts = int(float(flow_doc.get('Total Backward Packets', 0)))
    syn_count = int(float(flow_doc.get('SYN Flag Count', 0)))
    duration = float(flow_doc.get('Flow Duration', 0)) / 1e6  # microseconds to seconds
    dst_ip = flow_doc.get('dst_ip', flow_doc.get('Dst IP', 'N/A'))

    sev_color = '#dc2626' if severity == 'CRITICAL' else '#f59e0b' if severity == 'HIGH' else '#eab308'

    html = f"""<html><body style="margin:0;padding:0;background-color:#f4f4f7;font-family:Arial,Helvetica,sans-serif">
<table width="100%" cellpadding="0" cellspacing="0" style="background-color:#f4f4f7;padding:20px 0">
<tr><td align="center">
<table width="600" cellpadding="0" cellspacing="0" style="background-color:#ffffff;border-radius:8px;border:1px solid #e0e0e0">

  <!-- Header -->
  <tr><td style="background-color:#7f1d1d;padding:24px 32px;border-radius:8px 8px 0 0">
    <h1 style="margin:0;color:#ffffff;font-size:20px">🚫 CogSOC — Trusted Device BLOCKED</h1>
    <p style="margin:6px 0 0;color:#fca5a5;font-size:13px">Your device has been automatically blocked due to suspicious activity</p>
  </td></tr>

  <!-- Blocked Banner -->
  <tr><td style="padding:24px 32px 0">
    <table width="100%" cellpadding="16" cellspacing="0" style="background-color:#fef2f2;border:2px solid #dc2626;border-radius:8px">
      <tr><td>
        <h2 style="margin:0 0 8px;color:#991b1b;font-size:18px">🔒 {device_name} ({src_ip}) — AUTO-BLOCKED</h2>
        <p style="margin:0;color:#7f1d1d;font-size:14px">
          CogSOC AI detected malicious activity from your device and automatically blocked it.
          Review the details below and contact your SOC team if this was legitimate activity.
        </p>
      </td></tr>
    </table>
  </td></tr>

  <!-- Why Blocked -->
  <tr><td style="padding:20px 32px 0">
    <h3 style="margin:0 0 12px;color:#1f2937;font-size:16px">📋 Why This IP Was Blocked</h3>
    <table width="100%" cellpadding="0" cellspacing="0" style="font-size:14px;color:#374151;border:1px solid #e5e7eb;border-radius:6px;overflow:hidden">
      <tr style="background-color:#f9fafb"><td style="padding:10px 16px;color:#6b7280;width:140px">Attack Type</td>
          <td style="padding:10px 16px"><strong style="color:#dc2626">{attack_type}</strong></td></tr>
      <tr><td style="padding:10px 16px;color:#6b7280">Severity</td>
          <td style="padding:10px 16px"><span style="background:{sev_color};color:#fff;padding:3px 10px;border-radius:12px;font-size:12px;font-weight:700">{severity}</span></td></tr>
      <tr style="background-color:#f9fafb"><td style="padding:10px 16px;color:#6b7280">AI Confidence</td>
          <td style="padding:10px 16px"><strong>{ai_conf:.1f}%</strong></td></tr>
      <tr><td style="padding:10px 16px;color:#6b7280">MITRE ATT&CK</td>
          <td style="padding:10px 16px">{mitre_id} — {mitre_name} ({mitre_tactic})</td></tr>
      <tr style="background-color:#f9fafb"><td style="padding:10px 16px;color:#6b7280">Blocked At</td>
          <td style="padding:10px 16px">{now.strftime('%Y-%m-%d %H:%M:%S UTC')}</td></tr>
    </table>
  </td></tr>

  <!-- Activity Details -->
  <tr><td style="padding:20px 32px 0">
    <h3 style="margin:0 0 12px;color:#1f2937;font-size:16px">📊 Detected Network Activity</h3>
    <table width="100%" cellpadding="0" cellspacing="0" style="font-size:13px;color:#374151;border:1px solid #e5e7eb;border-radius:6px;overflow:hidden">
      <tr style="background-color:#f9fafb"><td style="padding:8px 16px;color:#6b7280;width:160px">Source IP</td>
          <td style="padding:8px 16px"><strong>{src_ip}</strong> ({device_name})</td></tr>
      <tr><td style="padding:8px 16px;color:#6b7280">Destination IP</td>
          <td style="padding:8px 16px">{dst_ip}</td></tr>
      <tr style="background-color:#f9fafb"><td style="padding:8px 16px;color:#6b7280">Destination Port</td>
          <td style="padding:8px 16px"><strong>{dst_port}</strong></td></tr>
      <tr><td style="padding:8px 16px;color:#6b7280">Packets/sec</td>
          <td style="padding:8px 16px">{pps:.0f} pps</td></tr>
      <tr style="background-color:#f9fafb"><td style="padding:8px 16px;color:#6b7280">Bandwidth</td>
          <td style="padding:8px 16px">{bps/1024:.1f} KB/s</td></tr>
      <tr><td style="padding:8px 16px;color:#6b7280">Forward Packets</td>
          <td style="padding:8px 16px">{fwd_pkts}</td></tr>
      <tr style="background-color:#f9fafb"><td style="padding:8px 16px;color:#6b7280">Backward Packets</td>
          <td style="padding:8px 16px">{bwd_pkts}</td></tr>
      <tr><td style="padding:8px 16px;color:#6b7280">SYN Flags</td>
          <td style="padding:8px 16px">{syn_count}</td></tr>
      <tr style="background-color:#f9fafb"><td style="padding:8px 16px;color:#6b7280">Flow Duration</td>
          <td style="padding:8px 16px">{duration:.2f} seconds</td></tr>
    </table>
  </td></tr>

  <!-- What To Do -->
  <tr><td style="padding:20px 32px">
    <table width="100%" cellpadding="14" cellspacing="0" style="background-color:#eff6ff;border:1px solid #93c5fd;border-radius:8px">
      <tr><td>
        <h4 style="margin:0 0 6px;color:#1e40af;font-size:14px">ℹ️ What should you do?</h4>
        <p style="margin:0;color:#1e3a5f;font-size:13px;line-height:1.5">
          If this was <strong>legitimate activity</strong>, contact your SOC team or open the
          dashboard to request an unblock. If you don't recognize this activity, your device may be compromised.
        </p>
      </td></tr>
    </table>
  </td></tr>

  <!-- Footer -->
  <tr><td style="padding:16px 32px;border-top:1px solid #e5e7eb;text-align:center">
    <a href="http://{dashboard_host}" style="display:inline-block;padding:10px 28px;background:#3b82f6;color:#fff;text-decoration:none;border-radius:6px;font-weight:700;font-size:14px">Open Dashboard</a>
    <p style="margin:12px 0 0;color:#9ca3af;font-size:12px">
      CogSOC AI-Driven Autonomous Defense
    </p>
  </td></tr>

</table>
</td></tr></table>
</body></html>
    """

    recipients = list(set(EMAIL_RECIPIENTS + ([owner_email] if owner_email else [])))
    msg = MIMEMultipart('alternative')
    msg['Subject'] = f'[CogSOC 🚫 BLOCKED] {device_name} ({src_ip}) — {attack_type}'
    msg['From'] = EMAIL_SENDER
    msg['To'] = ', '.join(recipients)
    msg.attach(MIMEText(html, 'html'))

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL_SENDER, EMAIL_PASSWORD)
            server.send_message(msg)
        _trusted_notified[src_ip] = now
        print(f"  [TRUSTED] 📧 Notification sent to {owner_email or 'SOC'} — "
              f"{device_name} ({src_ip}) blocked for {attack_type}")
    except Exception as e:
        print(f"  [TRUSTED] Email failed: {e}")

def save_alert(es, alert):
    try:
        resp = es.index(index=ALERTS_INDEX, document=alert)
        # Log successful saves to debug issues
        #print(f"[ELK] Alert saved: {resp['_id']}")
    except Exception as e:
        print(f"[ELK] ❌ Alert save error: {e}")
        print(f"[ELK]    Alert data: {alert}")
        import traceback
        traceback.print_exc()


def update_incident(es, src_ip, dst_ip, attack_type, severity, mitre_t,
                    mitre_tactic, sensor, blocked, active_incidents, sev_rank,
                    batch_start_time):
    """Create or update a SOAR incident for this attacker+attack_type."""
    key = (src_ip, attack_type)
    now = datetime.now(timezone.utc)

    if key in active_incidents:
        # Update existing incident
        inc_id, doc_id, first_seen = active_incidents[key]
        try:
            es.update(index=INCIDENTS_INDEX, id=doc_id, doc={
                'last_seen': now.isoformat(),
                'alert_count': {'script': {'source': 'ctx._source.alert_count += 1'}},
            })
        except Exception:
            # Fallback: use script update
            try:
                es.update(index=INCIDENTS_INDEX, id=doc_id, body={
                    'script': {
                        'source': 'ctx._source.alert_count += 1; '
                                  'ctx._source.last_seen = params.ts; '
                                  'if (params.sev_rank > params.cur_rank) '
                                  '{ ctx._source.severity = params.sev; }',
                        'params': {
                            'ts': now.isoformat(),
                            'sev': severity,
                            'sev_rank': sev_rank.get(severity, 0),
                            'cur_rank': sev_rank.get('LOW', 0),
                        }
                    }
                })
            except Exception:
                pass
        return inc_id
    else:
        # Create new incident
        inc_num = len(active_incidents) + 1
        inc_id = f"INC-{now.strftime('%Y%m%d')}-{inc_num:03d}"
        ttd = (now - batch_start_time).total_seconds() if batch_start_time else 0
        doc = {
            '@timestamp': now.isoformat(),
            'incident_id': inc_id,
            'status': 'CONTAINED' if blocked else 'OPEN',
            'severity': severity,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'attack_type': attack_type,
            'alert_count': 1,
            'first_seen': now.isoformat(),
            'last_seen': now.isoformat(),
            'sensor_name': sensor,
            'mitre_technique': mitre_t,
            'mitre_tactic': mitre_tactic,
            'response_action': 'AUTO_BLOCK' if blocked else 'HUMAN_REVIEW',
            'blocked': blocked,
            'assigned_to': 'Unassigned',
            'notes': '',
            'ttd_seconds': round(ttd, 1),
            'ttr_seconds': round(ttd + 5, 1) if blocked else 0,
        }
        try:
            resp = es.index(index=INCIDENTS_INDEX, document=doc)
            active_incidents[key] = (inc_id, resp['_id'], now)
            # Send email for CRITICAL/HIGH incidents
            if severity in ('CRITICAL', 'HIGH'):
                send_alert_email(inc_id, src_ip, dst_ip, attack_type,
                                 severity, mitre_t, sensor, 1, blocked)
        except Exception as e:
            print(f"[SOAR] Incident save error: {e}")
        return inc_id


def log_response(es, incident_id, action_type, src_ip, status, method, details):
    """Log a response action to cogsoc-responses."""
    try:
        es.index(index=RESPONSES_INDEX, document={
            '@timestamp': datetime.now(timezone.utc).isoformat(),
            'incident_id': incident_id,
            'action_type': action_type,
            'src_ip': src_ip,
            'status': status,
            'method': method,
            'details': details,
        })
    except Exception:
        pass


def save_behavior(es, ip, stats, risk_data, status):
    """
    Save IP behavioral stats + risk score to Elasticsearch.
    risk_data = (risk_score, risk_level, risk_factors_dict)
    """
    risk_score, risk_level, risk_factors = risk_data
    try:
        es.index(index=BEHAVIOR_INDEX, document={
            '@timestamp'  : datetime.now(timezone.utc).isoformat(),
            'ip'          : ip,
            'unique_ports': stats.get('unique_ports', 0),
            'total_flows' : stats.get('total_flows', 0),
            'avg_pps'     : round(stats.get('avg_pps', 0), 2),
            'avg_bps'     : round(stats.get('avg_bps', 0), 2),
            'total_syn'   : stats.get('total_syn', 0),
            'pps_ratio'   : round(stats.get('pps_ratio', 0), 2),
            'bps_ratio'   : round(stats.get('bps_ratio', 0), 2),
            'risk_score'  : round(risk_score, 2),
            'risk_level'  : risk_level,
            'alert_count' : stats.get('alert_count', 0),
            'attack_types': list(stats.get('attack_types', [])),
            'max_severity': stats.get('max_severity', 'LOW'),
            'risk_factors': risk_factors,
            'status'      : status,
        })
    except Exception:
        pass


def log_alert(alert):
    sev = alert['severity']
    sym = '🔴' if sev == 'CRITICAL' else '🟠' if sev == 'HIGH' else '🟡'
    sensor = alert.get('sensor_name', 'unknown')
    print(f"\n  {sym} {alert['attack_type']:<12} | "
          f"CONF={alert['confidence']:>5.1f}% | "
          f"SEV={sev:<8} | "
          f"METHOD={alert['detection_method']:<10} | "
          f"SRC={alert['src_ip']}")
    print(f"     SENSOR : {sensor}")
    print(f"     REASON : {alert.get('reason', 'N/A')}")
    print(f"     MITRE  : {alert['mitre_technique']} — "
          f"{alert['mitre_name']} ({alert['mitre_tactic']})")
    print(f"     ACTION : {alert['action']}")


def is_known_service(ip):
    """Check if IP belongs to a known service provider (Google, Meta, etc.)."""
    return ip.startswith(KNOWN_SERVICE_PREFIXES)


def is_monitored_ip(ip, baseline_ips=None, learning_mode=False,
                    server_mode=False):
    """
    Smart IP filtering — depends on mode:

    SERVER MODE: Monitor ALL source IPs (no filtering)
      → Every connection to your server is analyzed by AI
      → Only flow behavior determines attack vs benign

    LAB MODE (default): Filter by subnet + baseline
      1. Skip whitelisted infra IPs
      2. Skip known service providers
      3. Baseline learning for external IPs
    """
    if not ip or ip in WHITELISTED_IPS:
        return False

    # SERVER MODE: analyze everyone — no IP-based filtering
    if server_mode:
        return True

    # LAB MODE: existing filtering logic
    if is_known_service(ip):
        return False
    if ip.startswith(MONITOR_NETWORK):
        return True
    if learning_mode:
        return False
    if baseline_ips and ip in baseline_ips:
        return False
    return True


_dynamic_whitelist = set()
_dynamic_blacklist = set()
TRUSTED_ORGS = ['GOOGLE', 'MICROSOFT', 'NETFLIX', 'FASTLY', 'CLOUDFLARE', 'AMAZON',
                'AKAMAI', 'META', 'FACEBOOK', 'APPLE', 'TWITTER', 'LINKEDIN', 'ZOOM',
                'CISCO', 'GITHUB', 'SLACK', 'DISCORD', 'WIKIMEDIA', 'WIKIPEDIA',
                'CANONICAL', 'UBUNTU', 'MOZILLA', 'SPOTIFY', 'STEAM', 'VALVE',
                'WHATSAPP', 'TELEGRAM', 'DROPBOX', 'ORACLE', 'IBM', 'SAMSUNG',
                'SONY', 'INTEL', 'QUALCOMM', 'DELL', 'HP ', 'HEWLETT',
                'NTP', 'LETSENCRYPT', 'VERISIGN', 'DIGICERT']

# Well-known benign domain suffixes — if reverse DNS resolves to one of
# these, the IP is auto-whitelisted regardless of AI prediction.
TRUSTED_DNS_SUFFIXES = (
    '.google.com', '.googleapis.com', '.gstatic.com', '.youtube.com',
    '.microsoft.com', '.windows.com', '.azure.com', '.live.com', '.office.com',
    '.facebook.com', '.fbcdn.net', '.instagram.com', '.whatsapp.net',
    '.apple.com', '.icloud.com',
    '.amazon.com', '.amazonaws.com', '.cloudfront.net',
    '.cloudflare.com', '.cloudflare-dns.com',
    '.akamai.net', '.akamaiedge.net', '.akamaized.net',
    '.wikimedia.org', '.wikipedia.org', '.wikidata.org',
    '.canonical.com', '.ubuntu.com', '.launchpad.net',
    '.mozilla.org', '.mozilla.com', '.firefox.com',
    '.github.com', '.github.io', '.githubusercontent.com',
    '.netflix.com', '.nflxvideo.net',
    '.spotify.com', '.scdn.co',
    '.steampowered.com', '.steamcontent.com', '.valvesoftware.com',
    '.twitter.com', '.twimg.com', '.x.com',
    '.linkedin.com',
    '.zoom.us', '.zoom.com',
    '.discord.com', '.discord.gg', '.discordapp.com',
    '.slack.com',
    '.pool.ntp.org', '.ntp.org',
    '.dropbox.com', '.dropboxusercontent.com',
    '.letsencrypt.org', '.digicert.com', '.verisign.com',
)


def _reverse_dns_check(ip):
    """
    Perform a reverse DNS (PTR) lookup and check if the hostname
    belongs to a known trusted domain. This is the final safety net
    against false positives from legitimate services.
    Returns True if IP resolves to a trusted domain, False otherwise.
    """
    if ip in _dynamic_whitelist:
        return True
    try:
        import socket
        hostname, _, _ = socket.gethostbyaddr(ip)
        hostname = hostname.lower()
        for suffix in TRUSTED_DNS_SUFFIXES:
            if hostname.endswith(suffix):
                _dynamic_whitelist.add(ip)
                print(f"  [+] Reverse-DNS Whitelist: {ip} → {hostname}")
                return True
    except Exception:
        pass
    return False


def is_trusted_dynamic(ip):
    """Query free IP-API to check if the IP belongs to a trusted corporate entity."""
    if ip in _dynamic_whitelist: return True
    if ip in _dynamic_blacklist: return False

    # ── Layer 1: Reverse DNS check (fast, no rate-limit) ──
    if _reverse_dns_check(ip):
        return True

    # ── Layer 2: IP-API lookup (rate-limited, slower) ──
    api_reachable = False
    try:
        req = Request(f"http://ip-api.com/json/{ip}", headers={'User-Agent': 'CogSOC/1.0'})
        with urlopen(req, timeout=2) as response:
            api_reachable = True
            data = json.loads(response.read().decode())
            if data.get("status") == "success":
                isp = data.get("isp", "").upper()
                org = data.get("org", "").upper()
                if any(t in isp for t in TRUSTED_ORGS) or any(t in org for t in TRUSTED_ORGS):
                    _dynamic_whitelist.add(ip)
                    print(f"  [+] Dynamic Whitelist Auto-Learned: {ip} ({org or isp})")
                    return True
    except Exception:
        pass

    # Only blacklist if the API was actually reachable and returned a
    # non-trusted result. If the API timed out or was rate-limited,
    # do NOT blacklist — we'll retry on the next encounter.
    if api_reachable:
        _dynamic_blacklist.add(ip)
    return False

def process_threats(es, flow_doc, ai_pred, ai_conf,
                    baseline_ips=None, learning_mode=False,
                    server_mode=False, override_src_ip=None):
    """
    AI prediction se final alert banao.
    Uses smart IP filtering to reduce false positives.
    In server_mode: analyzes ALL source IPs, no filtering.

    override_src_ip: if set, use this IP as src_ip instead of flow's src_ip.
        Used by two-pass batch processing to re-attribute victim response
        traffic to the real attacker.
    """
    src_ip = (flow_doc.get('src_ip') or flow_doc.get('Src IP') or '0.0.0.0')
    dst_ip = (flow_doc.get('dst_ip') or flow_doc.get('Dst IP') or '0.0.0.0')
    dst_ip = (flow_doc.get('dst_ip') or flow_doc.get('Dst IP') or flow_doc.get('destination', {}).get('ip', '0.0.0.0'))
    sensor = flow_doc.get('sensor_name', flow_doc.get('source_sensor', 'unknown'))
    ts     = datetime.now(timezone.utc).isoformat()
    alerts = []

    # AI detected attack
    if ai_pred == 1 and ai_conf >= MEDIUM_CONF:

        # ── Re-attribution: victim response traffic ──
        is_reattributed = False
        if override_src_ip and override_src_ip != src_ip:
            original_src = src_ip
            dst_ip = src_ip         # victim becomes dst
            src_ip = override_src_ip  # real attacker becomes src
            is_reattributed = True

        # Server mode: only analyze flows going TO our server
        if server_mode and SERVER_IPS:
            if dst_ip not in SERVER_IPS and src_ip not in SERVER_IPS:
                return alerts

        # Smart IP filtering (lab mode uses baseline, server mode allows all)
        if not is_monitored_ip(src_ip, baseline_ips, learning_mode,
                               server_mode):
            return alerts
            
        # Ignore traffic that has absolutely nothing to do with our local network
        if not server_mode and not src_ip.startswith(MONITOR_NETWORK) and not dst_ip.startswith(MONITOR_NETWORK):
            return alerts
            
        # Ignore outbound traffic to known benign services or learned baselines
        if is_known_service(dst_ip) or (baseline_ips and dst_ip in baseline_ips) or dst_ip in WHITELISTED_IPS:
            return alerts
            
        # ── OPTION C: DYNAMIC THREAT INTELLIGENCE (IP-API) ──
        # If the AI thinks it's an attack, double check the real-world owner of the IP
        if dst_ip != '0.0.0.0' and not dst_ip.startswith(MONITOR_NETWORK) and is_trusted_dynamic(dst_ip):
            if baseline_ips is not None:
                baseline_ips.add(dst_ip) # Add to baseline so we don't query API again
            return alerts
            
        if src_ip != '0.0.0.0' and not src_ip.startswith(MONITOR_NETWORK) and is_trusted_dynamic(src_ip):
            if baseline_ips is not None:
                baseline_ips.add(src_ip)
            return alerts

        label       = flow_doc.get('Label', 'ATTACK')
        attack_type = detect_attack_type(label, flow_doc)
        
        # Prevent dashboard spam from hping3 --rand-source spoofed attacks
        if not server_mode and not src_ip.startswith(MONITOR_NETWORK) and ('Flood' in attack_type or 'DoS' in attack_type):
            src_ip = "SPOOFED_EXTERNAL_IPS"

        mitre       = get_mitre(attack_type)
        severity    = get_severity(ai_conf)

        # ── AUTO-BLOCK ALL DETECTED ATTACKS ──
        # Every AI-detected attack is blocked immediately — no manual review needed
        action = 'AUTO_BLOCK'
        blocked = block_ip(src_ip, f"AI: {attack_type}")

        # ── TRUSTED IP NOTIFICATION ──
        # If attacker is a known internal device, send informational email to owner
        # with details about why it was blocked and what activities were detected
        if src_ip in TRUSTED_INTERNAL_IPS:
            send_trusted_ip_notification(src_ip, attack_type, severity, ai_conf,
                                         mitre, flow_doc)

        reason = f"AI model confidence: {ai_conf:.1f}%"
        if is_reattributed:
            reason = (f"Victim-response re-attributed "
                      f"(orig src={original_src}, real attacker={src_ip})")

        # Extract sensor_name from flow_doc, with fallbacks
        # Filebeat adds 'capture_interface' field, so use that if sensor_name not present
        final_sensor = sensor
        if final_sensor == 'unknown' or not final_sensor:
            # Try to get from flow_doc fields that might be set by Filebeat
            final_sensor = (flow_doc.get('capture_interface') or 
                           flow_doc.get('sensor_name') or 
                           flow_doc.get('source_sensor') or 
                           'unknown')

        alert = {
            '@timestamp'       : ts,
            'timestamp'        : ts,
            'src_ip'           : src_ip,
            'dst_ip'           : dst_ip,
            'sensor_name'      : final_sensor,
            'attack_type'      : attack_type,
            'detection_method' : 'AI_MODEL',
            'confidence'       : round(ai_conf, 2),
            'ai_confidence'    : round(ai_conf, 2),
            'severity'         : severity,
            'action'           : action,
            'blocked'          : blocked,
            'reason'           : reason,
            'mitre_technique'  : mitre[0],
            'mitre_tactic'     : mitre[1],
            'mitre_name'       : mitre[2],
            'heuristic_threats': 0,
            'flow_timestamp'   : flow_doc.get('flow_timestamp') or flow_doc.get('Timestamp') or flow_doc.get('timestamp') or flow_doc.get('@timestamp') or ts,
        }
        save_alert(es, alert)
        alerts.append(alert)

    return alerts


def detect_attack_type(label, flow):
    """Identify specific attack type from label + flow features."""
    label_up = str(label).upper()

    # Check for tactic labels (Zeek style)
    tactic = str(flow.get('mitre_attack_tactics', flow.get('label_tactic', ''))).upper().strip()
    if tactic and tactic not in ('', 'BENIGN', 'NONE', 'NORMAL', 'NAN'):
        if 'RECON' in tactic:                      return 'Reconnaissance'
        if 'DISCOVERY' in tactic:                  return 'Network Discovery'
        if 'CREDENTIAL' in tactic:                 return 'Credential Access'
        if 'LATERAL' in tactic:                    return 'Lateral Movement'
        if 'EXFIL' in tactic:                      return 'Exfiltration'
        if 'IMPACT' in tactic:                     return 'Impact/DoS'

    if 'DDOS' in label_up:                         return 'DDoS Attack'
    if 'DOS'  in label_up and 'DDOS' not in label_up:
        if 'SLOWLORIS'   in label_up:              return 'DoS Slowloris'
        if 'SLOWHTTP'    in label_up:              return 'DoS SlowHTTPTest'
        if 'HULK'        in label_up:              return 'DoS Hulk'
        if 'GOLDENEYE'   in label_up:              return 'DoS GoldenEye'
        return 'DoS Attack'
    if 'PORT' in label_up or 'SCAN' in label_up:   return 'Port Scan'
    if 'BOT'  in label_up:                         return 'Botnet C2'
    if 'BRUTE' in label_up:                        return 'Brute Force'
    if 'INFILTR' in label_up:                      return 'Infiltration'
    if 'WEB'  in label_up or 'XSS' in label_up:    return 'Web Attack'
    if 'SQL'  in label_up:                         return 'SQL Injection'
    if 'SSH'  in label_up:                         return 'SSH Brute Force'
    if 'FTP'  in label_up:                         return 'FTP Brute Force'

        # ── 2. Heuristic classification (Improved for sensitivity) ──
    try:
        syn    = float(flow.get('SYN Flag Count', 0))
        rst    = float(flow.get('RST Flag Count', 0))
        pps    = float(flow.get('Flow Packets/s', 0))
        bps    = float(flow.get('Flow Bytes/s', 0))
        fwd    = float(flow.get('Total Fwd Packets', 0))
        bwd    = float(flow.get('Total Backward Packets', 0))
        dur    = float(flow.get('Flow Duration', 0))
        dst_p  = int(float(flow.get('Destination Port', 0)))
        fwd_len = float(flow.get('Total Length of Fwd Packets', 0))
        iat_std = float(flow.get('Flow IAT Std', 0))
        
        # We don't have access to all ports in a single flow, but we can look for scanning behavior
        if pps > 200 and bwd == 0 and syn > 0:
             return 'Port Scan / SYN Flood'

        # ── LAN Broadcast / Discovery Noise (Often flagged by AI) ──
        if dst_p in [5353, 1900, 137, 138, 67, 68]:
            return 'LAN Broadcast (Ignored)'

        # ── DDoS / DoS: High volume or one-way flood ──
        if pps > 200 or fwd > 100:
            if bwd < (fwd * 0.1):                  return 'DDoS Flood'
            return 'High Volume Attack'
        
        # Catch short-lived, one-way flows (typical of DDoS tools like hping3/LOIC)
        if bwd == 0:
            if syn > 0:                            return 'DoS SYN Flood'
            if fwd > 10:                           return 'DoS Flood'
            if dur < 1000000:                      return 'DoS/Scan Flood' # < 1 sec one-way
        
        if syn > 10 and bwd < 5:                   return 'DoS SYN Flood'
        if pps > 50 and bwd == 0:                  return 'DoS Flood'

        # ── Port Scan ──
        if rst > 10 and bwd < 5:                   return 'Port Scan (RST)'
        if syn >= 2 and bwd <= 1 and fwd <= 5:     return 'SYN Scan'

        # ── Brute Force ──
        if dst_p in [22, 21, 3389, 23]:            return 'Brute Force Attempt'

        # ── Web Attack ──
        if dst_p in [80, 443, 8080]:
            if pps > 100:                          return 'HTTP Flood'
            if fwd_len > 10000:                    return 'Web Exploit'
            return 'Suspicious Web Traffic'

        if iat_std < 1000 and fwd > 10:            return 'C2 Beaconing'
        if dst_p == 53 and pps > 50:               return 'DNS Attack'

    except Exception:
        pass

    return 'Advanced Attack (AI Detected)'


# ══════════════════════════════════════════════
#  MAIN MONITOR LOOP
# ══════════════════════════════════════════════
def print_attack_summary(ip_attack_tracker, total_analyzed, total_alerts,
                        total_blocked, elapsed):
    """
    Session end par complete attack summary report generate karo.
    """
    now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    report_lines = []

    def log(msg):
        print(msg)
        report_lines.append(msg)

    log("\n" + "═" * 85)
    log("  🛡️  CogSOC — FINAL SESSION SECURITY REPORT")
    log("═" * 85)
    log(f"  Time Generated : {now_str}")
    log(f"  Runtime        : {int(elapsed // 60)}m {int(elapsed % 60)}s")
    log(f"  Flows Analyzed : {total_analyzed:,}")
    log(f"  Total Alerts   : {total_alerts:,}")
    log(f"  IPs Blocked    : {total_blocked:,}")
    # Show per-sensor alert breakdown
    sensor_alert_counts = defaultdict(int)
    for ip, attacks in ip_attack_tracker.items():
        for atype, info in attacks.items():
            sensor = info.get('sensor_name', 'unknown')
            sensor_alert_counts[sensor] += info['count']
    if sensor_alert_counts:
        sensor_summary = ', '.join(f"{k}: {v}" for k, v in sensor_alert_counts.items())
        log(f"  Sensors        : {sensor_summary}")
    log("─" * 85)

    if not ip_attack_tracker:
        log("  ✅ No malicious activity detected during this session.")
        log("═" * 85)
        return

    # ── 0. Victim-Response Merging ──
    # CICFlowMeter bidirectional flows cause the victim to appear as an
    # attacker (response traffic). When two local IPs both appear in the
    # tracker and one has far more alerts, the smaller one is the victim.
    # Merge its alerts into the real attacker.
    local_ips = [ip for ip in ip_attack_tracker if ip.startswith(MONITOR_NETWORK)
                 and ip not in WHITELISTED_IPS]
    merged_victims = set()
    for i, ip_a in enumerate(local_ips):
        for ip_b in local_ips[i+1:]:
            total_a = sum(a['count'] for a in ip_attack_tracker[ip_a].values())
            total_b = sum(a['count'] for a in ip_attack_tracker[ip_b].values())
            if total_a <= 0 or total_b <= 0:
                continue
            # The one with 3x+ more alerts is the real attacker
            if total_a >= total_b * 3:
                attacker, victim = ip_a, ip_b
            elif total_b >= total_a * 3:
                attacker, victim = ip_b, ip_a
            else:
                continue
            # Merge victim's alerts into attacker
            log(f"  [MERGE] {victim} ({total_b if victim == ip_b else total_a} alerts) "
                f"→ merged into {attacker} (victim response traffic)")
            for atype, info in ip_attack_tracker[victim].items():
                entry = ip_attack_tracker[attacker][atype]
                entry['count']     += info['count']
                entry['total_conf'] += info['total_conf']
                if info.get('sensor_name'):
                    entry['sensor_name'] = info['sensor_name']
                if info.get('mitre_technique'):
                    entry['mitre_technique'] = info['mitre_technique']
                sev_rank_local = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
                if sev_rank_local.get(info['max_severity'], 0) > sev_rank_local.get(entry['max_severity'], 0):
                    entry['max_severity'] = info['max_severity']
            merged_victims.add(victim)
    # Remove merged victims from tracker
    for victim in merged_victims:
        del ip_attack_tracker[victim]

    # ── 1. Detailed IP Attack Mapping ──
    log(f"\n  {'IP ADDRESS':<20} {'ATTACK TYPE':<25} {'HITS':>6} {'AVG CONF':>9} {'SEVERITY'}")
    log("  " + "─" * 81)

    ip_totals = {ip: sum(a['count'] for a in attacks.values()) 
                 for ip, attacks in ip_attack_tracker.items()}
    sorted_ips = sorted(ip_totals, key=ip_totals.get, reverse=True)

    attack_type_summary = defaultdict(lambda: {'count': 0, 'ips': set()})
    
    for ip in sorted_ips:
        attacks = ip_attack_tracker[ip]
        first_row = True
        sorted_attacks = sorted(attacks.items(), key=lambda x: x[1]['count'], reverse=True)
        
        for name, info in sorted_attacks:
            avg_conf = info['total_conf'] / info['count']
            sev = info['max_severity']
            sym = '🔴' if sev == 'CRITICAL' else '🟠' if sev == 'HIGH' else '🟡' if sev == 'MEDIUM' else '⚪'
            
            ip_label = ip if first_row else ""
            log(f"  {ip_label:<20} {sym} {name:<25} {info['count']:>5}x {avg_conf:>7.1f}%   {sev}")
            
            attack_type_summary[name]['count'] += info['count']
            attack_type_summary[name]['ips'].add(ip)
            first_row = False
        log("  " + "· " * 41)

    # ── 2. Attack Type Distribution ──
    log(f"\n  {'ATTACK TYPE SUMMARY':─<85}")
    log(f"  {'ATTACK TYPE':<30} {'TOTAL HITS':>15} {'UNIQUE IPs':>15}")
    for atype, info in sorted(attack_type_summary.items(), key=lambda x: x[1]['count'], reverse=True):
        log(f"  {atype:<30} {info['count']:>14,} {len(info['ips']):>14}")

    # ── 3. Top Attacker Summary ──
    log(f"\n  {'TOP THREAT SOURCES':─<85}")
    for i, ip in enumerate(sorted_ips[:10], 1):
        top_atk = sorted(ip_attack_tracker[ip].items(), key=lambda x: x[1]['count'], reverse=True)[0][0]
        log(f"  {i:>2}. {ip:<20} → {ip_totals[ip]:>6} alerts | Main: {top_atk}")

    log("\n" + "═" * 85)
    log(f"  Report saved to: /mnt/c/CogSOC/data/session_report.txt")
    log("═" * 85)

    # Save to file
    try:
        os.makedirs("/mnt/c/CogSOC/data", exist_ok=True)
        with open("/mnt/c/CogSOC/data/session_report.txt", "w", encoding='utf-8') as f:
            f.write("\n".join(report_lines))
    except Exception as e:
        print(f"[ERROR] Could not save report file: {e}")


# ══════════════════════════════════════════════
#  DASHBOARD SERVER (background thread)
# ══════════════════════════════════════════════
DASHBOARD_PORT = 8050
DASHBOARD_DIR = os.path.dirname(os.path.abspath(__file__))

class _DashHandler(http.server.SimpleHTTPRequestHandler):
    pass # Removed since dashboard.py now handles everything

def start_dashboard():
    """Start the fully featured dashboard server (dashboard.py) as a subprocess."""
    print("[DASHBOARD] Launching standalone Dashboard & Login Server...")
    try:
        import subprocess
        import sys
        import time
        
        # Start dashboard.py in a background process
        subprocess.Popen(
            [sys.executable, 'dashboard.py'], 
            cwd=DASHBOARD_DIR,
            stdout=subprocess.DEVNULL, 
            stderr=subprocess.DEVNULL
        )
        
        # Give the server a second to bind the port
        time.sleep(1.5)
        print(f"[DASHBOARD] ✅ Live at http://localhost:{DASHBOARD_PORT}")
        
        # Open browser
        try:
            subprocess.Popen(['cmd.exe', '/c', 'start',
                              f'http://localhost:{DASHBOARD_PORT}'],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            try:
                webbrowser.open(f"http://localhost:{DASHBOARD_PORT}")
            except Exception:
                pass
    except Exception as e:
        print(f"[DASHBOARD] ❌ Failed to start dashboard.py: {e}")



def run_monitor(server_mode=False, duration_minutes=None):
    print("\n" + "=" * 65)
    print("  CogSOC — Real-Time Behavioral Analysis System")
    if server_mode:
        print(f"  SERVER MODE — Monitoring ALL incoming connections")
        print(f"  Server IPs : {', '.join(SERVER_IPS) if SERVER_IPS else 'ALL'}")
    else:
        print(f"  LAB MODE — Subnet + Baseline filtering")
    print(f"  Index      : {FLOWS_INDEX}*")
    print(f"  Alerts     : {ALERTS_INDEX}")
    print(f"  Interval   : {MONITOR_INTERVAL}s")
    print("=" * 65)

    # Dashboard is now started externally; AI engine runs independently.
    es            = connect_elk()
    ensure_indices(es)

    # ── ASYNC MODEL LOADING ──
    # Load model in a separate thread so it doesn't block the monitoring loop
    # and the user sees that traffic capture and analysis are running in parallel.
    global _async_model, _async_scaler, _model_loaded, _model_load_error
    _async_model = None
    _async_scaler = None
    _model_loaded = False
    _model_load_error = False

    def background_load_model():
        global _async_model, _async_scaler, _model_loaded, _model_load_error
        try:
            m, s = load_model()
            _async_model = m
            _async_scaler = s
            _model_loaded = True
        except Exception as e:
            print(f"[ERROR] Background model load failed: {e}")
            _model_load_error = True

    threading.Thread(target=background_load_model, daemon=True).start()

    # ── Reset fetch state for fresh start ──
    global _scroll_id, _seen_ids, _search_after
    _scroll_id     = None
    _search_after  = None
    _seen_ids      = set()

    last_ts        = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()  # start near-live; avoids reprocessing all historical data
    total_analyzed = 0
    total_alerts   = 0
    total_blocked  = 0
    total_skipped  = 0
    start          = datetime.now(timezone.utc)
    stop_at        = start + timedelta(minutes=duration_minutes) if duration_minutes else None

    # ── Baseline learning: collect normal external IPs ──
    baseline_ips   = set()
    learning_mode  = True
    baseline_end   = start + timedelta(minutes=BASELINE_LEARN_MINUTES)

    # ── IP → Attack tracking for session summary ──
    ip_attack_tracker = defaultdict(lambda: defaultdict(lambda: {
        'count': 0, 'total_conf': 0.0, 'max_severity': 'LOW',
        'mitre_technique': '', 'first_seen': None, 'last_seen': None
    }))
    sev_rank = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}

    # ── Cross-batch attacker↔victim correlation ──
    # Persists across batches: {attacker_ip: {victim_ip: alert_count}}
    attacker_victims = defaultdict(lambda: defaultdict(int))

    # ── Session-level confirmed victims ──
    # Once a victim is identified (batch 2+), all future flows from that
    # IP are automatically re-attributed. {victim_ip: attacker_ip}
    session_victims = {}

    # ── SOAR: active incidents {(src_ip, attack_type): (inc_id, doc_id, first_seen)} ──
    active_incidents = {}

    # ── Incident Correlation Engine — groups all events per IP into 1 incident ──
    corr_engine = IncidentCorrelationEngine()

    # ── THE HANDS: Email Alert Engine ──
    email_engine = None
    if _HAS_EMAIL_MODULE:
        email_engine = EmailAlertEngine({
            'enabled'    : EMAIL_ENABLED,
            'smtp_server': SMTP_SERVER,
            'smtp_port'  : SMTP_PORT,
            'sender'     : EMAIL_SENDER,
            'password'   : EMAIL_PASSWORD,
            'recipients' : EMAIL_RECIPIENTS,
            'cooldown_secs': EMAIL_COOLDOWN,
        })

    # ── THE HANDS: Playbook Engine ──
    playbook_engine = None
    if _HAS_PLAYBOOK_MODULE:
        playbook_engine = PlaybookEngine(es=es, blocked_log=BLOCKED_LOG)

    print(f"\n[MONITOR] Started: {start.strftime('%H:%M:%S')}")
    print(f"[MONITOR] Detection mode: AI_MODEL + Smart IP Filter")
    print(f"[BASELINE] Learning normal IPs for {BASELINE_LEARN_MINUTES} min "
          f"(until {baseline_end.strftime('%H:%M:%S')})...")
    print("-" * 65)

    try:
        while True:
            try:
                if stop_at and datetime.now(timezone.utc) >= stop_at:
                    print("[MONITOR] Requested duration reached. Stopping AI engine.")
                    break
                # ── Check if baseline learning phase is over ──
                if learning_mode and datetime.now(timezone.utc) >= baseline_end:
                    learning_mode = False
                    print(f"\n[BASELINE] ✅ Learning complete! "
                          f"Learned {len(baseline_ips)} normal external IPs")
                    print(f"[BASELINE] Now monitoring for attacks. "
                          f"New unknown external IPs WILL trigger alerts.")
                    print("-" * 65)

                df, last_ts, doc_ids = fetch_flows(es, last_ts)

                if not _model_loaded:
                    if _model_load_error:
                        print("[ERROR] AI Model failed to load. Stopping monitor.")
                        break
                    mode_str = '🔵 LEARNING' if learning_mode else '🟢 DETECTING'
                    flow_count_str = f"Flows queued: {len(df)}" if not df.empty else "Waiting..."
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] "
                          f"{mode_str} | "
                          f"⏳ AI Model loading... (Capture running in parallel) | {flow_count_str}")
                    time.sleep(MONITOR_INTERVAL)
                    continue
                else:
                    model = _async_model
                    scaler = _async_scaler

                if df.empty:
                    mode_str = '🔵 LEARNING' if learning_mode else '🟢 DETECTING'
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] "
                          f"{mode_str} | "
                          f"Waiting... | "
                          f"Analyzed: {total_analyzed:,} | "
                          f"Alerts: {total_alerts:,}")
                    time.sleep(MONITOR_INTERVAL)
                    continue

                # AI predictions
                preds, probas = ai_predict(df, model, scaler)
                if not preds:
                    preds  = [0] * len(df)
                    probas = [0.0] * len(df)

                batch_alerts = 0

                # ════════════════════════════════════════════
                #  TWO-PASS BATCH PROCESSING
                #  Pass 1: Collect flagged flows + identify
                #          attacker-victim pairs by volume
                #  Pass 2: Generate alerts with correct IP
                #          attribution
                # ════════════════════════════════════════════

                # ── PASS 1: Collect + Analyze ──
                flagged_flows = []
                batch_src_dst = defaultdict(lambda: defaultdict(int))

                for idx, (pred, prob) in enumerate(zip(preds, probas)):
                    ai_conf  = prob * 100
                    flow_doc = df.iloc[idx].to_dict()
                    total_analyzed += 1

                    # During baseline: collect normal external IPs (both src and dst)
                    if learning_mode:
                        src = (flow_doc.get('src_ip') or
                               flow_doc.get('Src IP') or 
                               flow_doc.get('Source IP') or 
                               flow_doc.get('Source') or '0.0.0.0')
                        dst = (flow_doc.get('dst_ip') or
                               flow_doc.get('Dst IP') or 
                               flow_doc.get('Destination IP') or 
                               flow_doc.get('Destination') or '0.0.0.0')
                        if src and src not in WHITELISTED_IPS and not src.startswith(MONITOR_NETWORK):
                            baseline_ips.add(src)
                        if dst and dst not in WHITELISTED_IPS and not dst.startswith(MONITOR_NETWORK):
                            baseline_ips.add(dst)

                    if pred == 1 and ai_conf >= MEDIUM_CONF:
                        src = (flow_doc.get('src_ip') or
                               flow_doc.get('Src IP') or 
                               flow_doc.get('Source IP') or 
                               flow_doc.get('Source') or '0.0.0.0')
                        dst = (flow_doc.get('dst_ip') or
                               flow_doc.get('Dst IP') or 
                               flow_doc.get('Destination IP') or 
                               flow_doc.get('Destination') or '0.0.0.0')
                        flagged_flows.append((flow_doc, pred, ai_conf, src, dst))
                        batch_src_dst[src][dst] += 1

                # ── Identify victim-response pairs ──
                # When both A→B and B→A are flagged, the one with
                # far more flags is the real attacker. The other is
                # victim response traffic (CICFlowMeter bidirectional).
                # victim_reattribute: {(victim_src, attacker_dst): real_attacker}
                victim_reattribute = {}

                # Check within THIS batch — LOCAL SUBNET PAIRS ONLY
                checked = set()
                for ip_a in list(batch_src_dst.keys()):
                    for ip_b in list(batch_src_dst[ip_a].keys()):
                        # Only reattribute between local subnet IPs
                        if (not ip_a.startswith(MONITOR_NETWORK) or
                                not ip_b.startswith(MONITOR_NETWORK)):
                            continue
                        # Skip whitelisted/infra IPs
                        if ip_a in WHITELISTED_IPS or ip_b in WHITELISTED_IPS:
                            continue
                        pair = tuple(sorted([ip_a, ip_b]))
                        if pair in checked:
                            continue
                        checked.add(pair)
                        a_to_b = batch_src_dst[ip_a].get(ip_b, 0)
                        b_to_a = batch_src_dst[ip_b].get(ip_a, 0)
                        if a_to_b > 0 and b_to_a > 0:
                            # Both directions flagged — compare volumes
                            if a_to_b >= b_to_a * 3:
                                # A is attacker, B→A is victim response
                                victim_reattribute[(ip_b, ip_a)] = ip_a
                            elif b_to_a >= a_to_b * 3:
                                # B is attacker, A→B is victim response
                                victim_reattribute[(ip_a, ip_b)] = ip_b

                # Also check cross-batch correlation (local subnet only)
                for atk, victims in attacker_victims.items():
                    if not atk.startswith(MONITOR_NETWORK) or atk in WHITELISTED_IPS:
                        continue
                    for vic in victims:
                        if not vic.startswith(MONITOR_NETWORK) or vic in WHITELISTED_IPS:
                            continue
                        victim_reattribute[(vic, atk)] = atk

                if victim_reattribute:
                    # Update session-level victims
                    new_reattr = False
                    for (vic, _atk), real_atk in victim_reattribute.items():
                        if vic not in session_victims:
                            session_victims[vic] = real_atk
                            new_reattr = True
                            print(f"  [⚠️  VICTIM] {vic} confirmed as victim — "
                                  f"future alerts re-attributed to {real_atk}")
                    
                    if new_reattr:
                        reattr_summary = {v: [k[0][0] for k in victim_reattribute.items() if k[1] == v]
                                          for v in set(victim_reattribute.values())}
                        for atk, vics in reattr_summary.items():
                            print(f"  [REATTR] {', '.join(vics)} → re-attributed to attacker {atk}")

                # ── Build set of victim IPs for console suppression ──
                # Sources: (1) session_victims, (2) victim_reattribute,
                #          (3) batch-1 heuristic for single-IP batches
                suppress_src_ips = set()

                # 1. Confirmed session victims — always suppress
                suppress_src_ips.update(session_victims.keys())

                # 2. Batch-level victim-reattribute — suppress victims
                for (vic, _atk) in victim_reattribute.keys():
                    suppress_src_ips.add(vic)

                # 3. Batch 1 edge case: only ONE local IP has flagged flows
                #    (victim response arrives before attacker flows).
                #    Check if this IP sends 10+ flagged flows to another
                #    local IP — strong indicator of victim response.
                local_src_counts = {}
                for _, _, _, src, dst in flagged_flows:
                    if (src.startswith(MONITOR_NETWORK)
                            and src not in WHITELISTED_IPS):
                        local_src_counts[src] = local_src_counts.get(src, 0) + 1

                if len(local_src_counts) == 1:
                    solo_ip = list(local_src_counts.keys())[0]
                    local_dst_counts = {}
                    for _, _, _, src, dst in flagged_flows:
                        if src == solo_ip and dst.startswith(MONITOR_NETWORK) \
                                and dst not in WHITELISTED_IPS:
                            local_dst_counts[dst] = local_dst_counts.get(dst, 0) + 1
                    if local_dst_counts:
                        top_dst = max(local_dst_counts, key=local_dst_counts.get)
                        if local_dst_counts[top_dst] >= 10:
                            suppress_src_ips.add(solo_ip)

                # ── PASS 2: Generate alerts + correlate into incidents ──
                corr_engine.reset_batch_printed()
                batch_correlated_ips = set()

                for flow_doc, pred, ai_conf, src, dst in flagged_flows:
                    # Session-level victim check FIRST (covers all batches after detection)
                    override_ip = session_victims.get(src, None)
                    # Then batch-level reattribution
                    if not override_ip:
                        reattr_key = (src, dst)
                        override_ip = victim_reattribute.get(reattr_key, None)

                    alerts = process_threats(es, flow_doc, pred, ai_conf,
                                            baseline_ips, learning_mode,
                                            server_mode,
                                            override_src_ip=override_ip)
                    batch_alerts  += len(alerts)
                    total_alerts  += len(alerts)
                    for a in alerts:
                        if a.get('blocked'):
                            total_blocked += 1

                        # ── Track attack per IP (legacy tracker) ──
                        a_src   = a.get('src_ip', '0.0.0.0')
                        a_dst   = a.get('dst_ip', '0.0.0.0')
                        atype   = a.get('attack_type', 'Unknown')
                        conf    = a.get('confidence', 0)
                        sev     = a.get('severity', 'LOW')
                        mitre_t = a.get('mitre_technique', '')
                        mitre_tac = a.get('mitre_tactic', '')
                        sensor  = a.get('sensor_name', 'unknown')
                        now_str = datetime.now().strftime('%H:%M:%S')
                        is_blocked = a.get('blocked', False)

                        entry = ip_attack_tracker[a_src][atype]
                        entry['count']     += 1
                        entry['total_conf'] += conf
                        entry['mitre_technique'] = mitre_t
                        entry['sensor_name'] = sensor
                        if sev_rank.get(sev, 0) > sev_rank.get(entry['max_severity'], 0):
                            entry['max_severity'] = sev
                        if entry['first_seen'] is None:
                            entry['first_seen'] = now_str
                        entry['last_seen'] = now_str

                        # ── Correlation Engine: ingest into unified incident ──
                        if src not in suppress_src_ips:
                            inc_id, is_new, inc_data = corr_engine.ingest_alert(
                                a_src, a_dst, flow_doc, conf, atype,
                                sev, sensor, mitre_t, mitre_tac, is_blocked)
                            batch_correlated_ips.add(a_src)

                            # SOAR legacy: still update old incidents too
                            update_incident(
                                es, a_src, a_dst, atype, sev, mitre_t,
                                mitre_tac, sensor, is_blocked,
                                active_incidents, sev_rank, start)
                            if is_blocked and inc_id:
                                log_response(es, inc_id, 'IP_BLOCK', a_src,
                                             'SUCCESS', 'AUTO',
                                             f'Auto-blocked {a_src} for {atype}')

                        # ── Update cross-batch attacker↔victim correlation ──
                        if (conf >= MEDIUM_CONF and a_dst != '0.0.0.0'
                                and a_src.startswith(MONITOR_NETWORK)
                                and a_dst.startswith(MONITOR_NETWORK)
                                and a_src not in WHITELISTED_IPS
                                and a_dst not in WHITELISTED_IPS):
                            attacker_victims[a_src][a_dst] += 1

                # ── Print ONE consolidated incident line per IP (not per flow) ──
                for ip in batch_correlated_ips:
                    corr_engine.print_incident_line(ip)
                    corr_engine.save_to_es(es, ip)
                    inc = corr_engine.get_incident(ip)
                    if inc:
                        if playbook_engine:
                            playbook_engine.evaluate(inc)
                        if email_engine:
                            email_engine.on_incident(inc)

                # ── Periodic memory cleanup (every 50 batches) ──
                _batch_num = getattr(run_monitor, '_batch_num', 0) + 1
                run_monitor._batch_num = _batch_num
                if _batch_num % 50 == 0:
                    import gc
                    if len(attacker_victims) > 200:
                        keep = set(list(attacker_victims.keys())[-100:])
                        for _k in list(attacker_victims.keys()):
                            if _k not in keep:
                                del attacker_victims[_k]
                    if len(ip_attack_tracker) > 200:
                        keep_ips = set(list(ip_attack_tracker.keys())[-150:])
                        for _k in list(ip_attack_tracker.keys()):
                            if _k not in keep_ips:
                                del ip_attack_tracker[_k]
                    corr_engine._prune_closed_incidents(max_closed=200)
                    gc.collect()
                    print(f"  [MEM] Cleanup #{_batch_num}: "
                          f"attacker_victims={len(attacker_victims)}, "
                          f"ip_tracker={len(ip_attack_tracker)}, "
                          f"incidents={len(corr_engine.incidents)}")

                # Check if digest email is due
                if email_engine:
                    email_engine.check_digest()

                # Count flows per sensor in this batch
                sensor_counts = {}
                for i in range(len(df)):
                    s = df.iloc[i].get('sensor_name', df.iloc[i].get('source_sensor', 'local'))
                    sensor_counts[s] = sensor_counts.get(s, 0) + 1
                sensor_str = ' | '.join(f"{k}:{v}" for k, v in sensor_counts.items())

                # Show active incidents count
                active_count = len(corr_engine.get_all_active())
                mode_str = '🔵 LEARNING' if learning_mode else '🟢 DETECTING'
                print(f"[{datetime.now().strftime('%H:%M:%S')}] "
                      f"{mode_str} | "
                      f"Flows: {len(preds):>4} [{sensor_str}] | "
                      f"Alerts: {batch_alerts:>3} | "
                      f"Incidents: {active_count} | "
                      f"Total: {total_analyzed:>7,}")

            except Exception as e:
                print(f"[ERROR] {e}")
                time.sleep(MONITOR_INTERVAL)

            time.sleep(MONITOR_INTERVAL)

    except KeyboardInterrupt:
        elapsed = (datetime.now(timezone.utc) - start).total_seconds()

        # ── Correlated Incident Summary ──
        active_incidents_list = corr_engine.get_all_active()
        if active_incidents_list:
            print("\n" + "═" * 85)
            print("  🔗 CORRELATED INCIDENT SUMMARY (1 incident per attacker IP)")
            print("═" * 85)
            sev_order = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '⚪'}
            print(f"\n  {'#':<4} {'INCIDENT ID':<20} {'ATTACKER IP':<18} {'ATTACK CATEGORY':<25} {'EVENTS':>7} {'SEV':<9} {'PHASE'}")
            print("  " + "─" * 83)
            for i, inc in enumerate(active_incidents_list, 1):
                sym = sev_order.get(inc['severity'], '⚪')
                cat = inc['classification'].get('category', inc['primary_attack'])[:24]
                phase = inc['classification'].get('phase', '?')
                victims = ', '.join(list(inc['victims'])[:2])
                print(f"  {i:<4} {inc['incident_id']:<20} {inc['src_ip']:<18} {sym} {cat:<24} {inc['event_count']:>6} {inc['severity']:<9} {phase}")
                if victims:
                    print(f"       └─ Victims: {victims}")
                signals = inc['classification'].get('signals', [])
                if signals:
                    print(f"       └─ Signals: {signals[0]}")
                if inc['classification'].get('is_campaign'):
                    print(f"       └─ ⚠️  MULTI-VECTOR CAMPAIGN")
            print("═" * 85)

        # ── Legacy per-attack-type summary ──
        print_attack_summary(ip_attack_tracker, total_analyzed,
                            total_alerts, total_blocked, elapsed)

        # ── THE HANDS: Playbook Execution Summary ──
        if playbook_engine:
            playbook_engine.print_summary()

        # ── THE HANDS: Send session summary email ──
        if email_engine:
            email_engine.send_session_summary(
                active_incidents_list if active_incidents_list else [],
                {'total_analyzed': total_analyzed, 'total_alerts': total_alerts,
                 'total_blocked': total_blocked, 'elapsed': elapsed}
            )



# ══════════════════════════════════════════════
#  KIBANA SETUP GUIDE PRINT KARO
# ══════════════════════════════════════════════
def print_kibana_guide():
    print("\n" + "=" * 65)
    print("  KIBANA DASHBOARD SETUP GUIDE")
    print("=" * 65)
    print("""
1. http://localhost:5601 kholao

2. Data Views banao (Stack Management → Data Views):
   ┌─────────────────────────────────────────┐
   │ cogsoc-alerts*   → @timestamp           │
   │ cogsoc-behavior* → @timestamp           │
   │ cogsoc-flows*    → @timestamp           │
   └─────────────────────────────────────────┘

3. Dashboard → Create New → Add panels:

   Panel 1: ALERT TIMELINE
   → Lens → Bar chart
   → X-axis: @timestamp (auto interval)
   → Y-axis: Count
   → Break down: attack_type
   → Index: cogsoc-alerts*

   Panel 2: ATTACK TYPE PIE CHART  
   → Lens → Pie chart
   → Slice by: attack_type
   → Size by: Count
   → Index: cogsoc-alerts*

   Panel 3: TOP SUSPICIOUS IPs
   → Lens → Table
   → Rows: src_ip
   → Metrics: Count, Max(confidence)
   → Index: cogsoc-alerts*

   Panel 4: SEVERITY DISTRIBUTION
   → Lens → Metric
   → Filter: severity: CRITICAL
   → Index: cogsoc-alerts*

   Panel 5: DETECTION METHOD
   → Lens → Donut chart
   → Slice: detection_method (AI_MODEL vs HEURISTIC)
   → Index: cogsoc-alerts*

   Panel 6: IP RISK SCORE (Behavioral)
   → Lens → Table
   → Rows: ip
   → Metrics: Max(risk_score), Last(status)
   → Index: cogsoc-behavior*

   Panel 7: MITRE ATT&CK HEATMAP
   → Lens → Table
   → Rows: mitre_tactic, mitre_technique
   → Metrics: Count
   → Index: cogsoc-alerts*

   Panel 8: REAL-TIME TRAFFIC (Line chart)
   → Lens → Line chart
   → X: @timestamp
   → Y: Count
   → Break down: status
   → Index: cogsoc-behavior*

4. Auto-refresh: Top right → 10s
""")
    print("=" * 65)


def load_offline_dataframe(filepath):
    ext = os.path.splitext(filepath)[1].lower()
    if ext == ".csv":
        return pd.read_csv(filepath)
    if ext == ".json":
        try:
            return pd.read_json(filepath, lines=True)
        except ValueError:
            return pd.read_json(filepath)
    raise ValueError(f"Unsupported structured file format: {ext}")


def index_offline_flows(es, df, source_file):
    """Store offline flows so the dashboard can show them beside live runs."""
    actions = []
    now = datetime.now(timezone.utc).isoformat()
    for row in df.replace({np.nan: None}).to_dict(orient="records"):
        row.setdefault("@timestamp", now)
        row["analysis_mode"] = "offline"
        row["source_file"] = os.path.basename(source_file)
        actions.append({"_index": FLOWS_INDEX, "_source": row})
    if actions:
        helpers.bulk(es, actions, chunk_size=500, request_timeout=60)


def run_offline_ai(df, source_file):
    es = connect_elk()
    model, scaler = load_model()
    ensure_indices(es)
    index_offline_flows(es, df, source_file)

    preds, probas = ai_predict(df, model, scaler)
    alerts = 0
    for idx, (pred, prob) in enumerate(zip(preds, probas)):
        flow_doc = df.iloc[idx].to_dict()
        flow_doc["analysis_mode"] = "offline"
        flow_doc["source_file"] = os.path.basename(source_file)
        generated = process_threats(
            es,
            flow_doc,
            pred,
            prob * 100,
            baseline_ips=set(),
            learning_mode=False,
            server_mode=True,
        )
        alerts += len(generated)
    print(f"[OFFLINE] AI processed {len(df):,} flows and generated {alerts:,} alert(s).")


def run_offline_analysis(filepath, pipeline):
    """Process PCAP/JSON/CSV files only after explicit Offline Analysis action."""
    print(f"\n[OFFLINE] Starting offline analysis on: {filepath}")
    print(f"[OFFLINE] Selected Pipeline: {pipeline}")

    ext = os.path.splitext(filepath)[1].lower()
    if ext in ('.pcap', '.pcapng'):
        print("[OFFLINE] PCAP file detected.")
        if pipeline == 'ai_only':
            print("[ERROR] Cannot run AI directly on raw PCAP. CICFlowMeter extraction is required.")
            return

        offline_out = os.path.join(CICFLOW_OUTPUT_DIR, "offline")
        csv_files = run_cicflowmeter(filepath, offline_out)
        print(f"[CICFlowMeter] Extraction complete. {len(csv_files)} CSV file(s) generated.")

        if pipeline == 'raw_pcap':
            print("[OFFLINE] CICFlowMeter-only pipeline selected. AI bypassed.")
            return

        frames = [pd.read_csv(path) for path in csv_files]
        df = pd.concat(frames, ignore_index=True) if frames else pd.DataFrame()
        if df.empty:
            print("[OFFLINE] No flows were produced by CICFlowMeter.")
            return
        run_offline_ai(df, filepath)
        return

    if ext in ('.csv', '.json'):
        if pipeline == 'raw_pcap':
            print("[WARNING] Structured file provided with raw_pcap pipeline. Running AI on structured flows.")
        df = load_offline_dataframe(filepath)
        if df.empty:
            print("[OFFLINE] Uploaded file contains no records.")
            return
        run_offline_ai(df, filepath)
        return

    print("[ERROR] Unsupported file format. Upload PCAP, PCAPNG, CSV, or JSON.")


def parse_duration_minutes(value):
    if not value or value == "continuous":
        return None
    text = str(value).strip().lower()
    try:
        if text.endswith("h"):
            return int(float(text[:-1]) * 60)
        if text.endswith("m"):
            return int(float(text[:-1]))
        return int(float(text))
    except ValueError:
        print(f"[CONFIG] Invalid duration '{value}', using continuous mode.")
        return None


def apply_detection_config(args):
    global MEDIUM_CONF, HIGH_CONF, CICFLOW_INTERFACE
    sensitivity = (args.sensitivity or "medium").lower()
    if sensitivity == "high":
        MEDIUM_CONF = 55.0
        HIGH_CONF = 80.0
    elif sensitivity == "low":
        MEDIUM_CONF = 90.0
        HIGH_CONF = 97.0
    else:
        MEDIUM_CONF = 70.0
        HIGH_CONF = 90.0
    if getattr(args, "interface", None):
        CICFLOW_INTERFACE = args.interface
    print(f"[CONFIG] Sensitivity={sensitivity} MEDIUM_CONF={MEDIUM_CONF} HIGH_CONF={HIGH_CONF}")
    print(f"[CONFIG] Capture interface={CICFLOW_INTERFACE}")


def cleanup_and_exit():
    """Terminate all background processes and exit cleanly."""
    print("\n[SHUTDOWN] Terminating background processes...")
    import subprocess
    import sys
    for proc in ACTIVE_PROCESSES:
        try:
            if proc.poll() is None:
                if sys.platform == 'win32':
                    subprocess.call(['taskkill', '/F', '/T', '/PID', str(proc.pid)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                else:
                    proc.terminate()
                print(f"[SHUTDOWN] Killed process tree for: {proc.pid}")
        except Exception:
            pass
    print("[SHUTDOWN] Cleanup complete. Exiting.")
    os._exit(0)


# ══════════════════════════════════════════════
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='CogSOC — Behavioral Analysis System'
    )
    parser.add_argument(
        '--mode',
        choices=['monitor', 'kibana-guide'],
        default='monitor',
        help='monitor = real-time analysis | kibana-guide = dashboard setup'
    )
    parser.add_argument(
        '--server',
        action='store_true',
        default=False,
        help='Server mode: analyze ALL source IPs, no filtering. '
             'Use when monitoring a server that receives external connections.'
    )
    parser.add_argument(
        '--engine-only',
        action='store_true',
        default=False,
        help='Run only the AI backend engine (started by the dashboard)'
    )
    parser.add_argument(
        '--offline-file',
        type=str,
        default=None,
        help='Path to the offline PCAP or CSV file'
    )
    parser.add_argument(
        '--pipeline',
        type=str,
        default='auto',
        help='auto, raw_pcap, or ai_only'
    )
    parser.add_argument(
        '--duration-minutes',
        type=str,
        default=None,
        help='Live analysis duration in minutes, 1h, 24h, or continuous'
    )
    parser.add_argument(
        '--sensitivity',
        type=str,
        default='medium',
        choices=['high', 'medium', 'low'],
        help='Detection sensitivity selected from the gateway'
    )
    parser.add_argument(
        '--interface',
        type=str,
        default=None,
        help='Capture interface selected in the Live Analysis form'
    )
    args = parser.parse_args()
    duration_minutes = parse_duration_minutes(args.duration_minutes)
    apply_detection_config(args)

    print("=" * 65)
    print("  CogSOC — Behavioral Analysis + AI + Heuristics")
    print(f"  Mode  : {'OFFLINE' if args.offline_file else args.mode.upper()}")
    print(f"  ELK   : {ES_HOST}")
    print(f"  Model : {MODEL_PATH}")
    print("=" * 65)

    try:
        if args.mode == 'kibana-guide':
            print_kibana_guide()
        else:
            if not args.engine_only:
                # ── UX UPDATE: Start Dashboard ONLY, do not start AI yet ──
                print("[INFO] AI processing is paused awaiting User Configuration.")
                import subprocess
                import sys
                import time
                import webbrowser
                
                print("[DASHBOARD] Launching CogSOC Gateway Interface...")
                try:
                    # Start dashboard
                    dash_process = subprocess.Popen(
                        [sys.executable, 'dashboard.py'], 
                        cwd=os.path.dirname(os.path.abspath(__file__))
                    )
                    ACTIVE_PROCESSES.append(dash_process)
                    
                    time.sleep(1.5)
                    print(f"[DASHBOARD] ✅ Gateway Live at http://localhost:8050")
                    try:
                        webbrowser.open("http://localhost:8050")
                    except:
                        pass
                        
                    # Wait for dashboard to close so the script doesn't exit
                    dash_process.wait()
                except KeyboardInterrupt:
                    cleanup_and_exit()
                except Exception as e:
                    print(f"[ERROR] Failed to start dashboard: {e}")
            else:
                # ── ENGINE ONLY MODE: User clicked "START" in the UI ──
                if args.offline_file:
                    run_offline_analysis(args.offline_file, args.pipeline)
                else:
                    # Live mode: Traffic capture is now managed by the independent traffic_capture.py script.
                    # This engine strictly performs AI Analysis.
                    try:
                        run_monitor(server_mode=args.server, duration_minutes=duration_minutes)
                    except KeyboardInterrupt:
                        cleanup_and_exit()
    except KeyboardInterrupt:
        cleanup_and_exit()
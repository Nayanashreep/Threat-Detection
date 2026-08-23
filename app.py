# --- app.py (fixed & aligned) ---

from flask import Flask, render_template, request, jsonify, redirect, send_file
import json, csv, io, os, sys, threading, subprocess
from datetime import datetime
from collections import defaultdict
from scapy.all import sniff, IP

app = Flask(__name__)

# === Directory Base & File Paths ===
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "dataset", "model.joblib")
RULES_FILE = os.path.join(BASE_DIR, "rules.json")
LOG_FILE = os.path.join(BASE_DIR, "logs.json")
HONEYPOT_LOG = os.path.join(BASE_DIR, "logs", "honeypot_log.json")
BLACKLIST_FILE = os.path.join(BASE_DIR, "blacklist.json")

os.makedirs(os.path.dirname(HONEYPOT_LOG), exist_ok=True)

# === Global Variables ===
PACKET_LOG = []                          # in-memory rolling buffer for quick UI
ML_ENABLED = True                        # toggled via /toggle-ml
HONEYPOT_PROCESS = None
HONEYPOT_STATUS = {"running": False, "port": 8000}

# === Load ML Detector ===
try:
    from ml_detector import is_malicious
except Exception as e:
    print(f"[!] Warning: ml_detector import failed ({e}). Fallback to dummy ML.")
    def is_malicious(pkt):
        return False

# === Utility Functions ===
def load_rules():
    """Load rule list from file. Returns a list of dicts."""
    if not os.path.exists(RULES_FILE):
        return []
    try:
        with open(RULES_FILE, "r") as f:
            data = json.load(f)
            return data if isinstance(data, list) else []
    except json.JSONDecodeError:
        return []

def ensure_logs_file():
    """Ensure logs.json exists and is valid JSON array."""
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, "w") as f:
            f.write("[]")
        return
    try:
        with open(LOG_FILE, "r") as f:
            content = f.read().strip()
            if not content:
                raise json.JSONDecodeError("Empty file", "", 0)
            _ = json.loads(content)
    except json.JSONDecodeError:
        print("[!] Detected malformed logs.json on startup. Resetting...")
        with open(LOG_FILE, "w") as f:
            f.write("[]")

_PROTO_MAP = {"1": "ICMP", "6": "TCP", "17": "UDP", "2": "IGMP", "47": "GRE", "89": "OSPF"}

def normalize_log(log):
    """Normalize a single log dict – fix numeric protocol strings, ensure both src/src_ip exist."""
    entry = dict(log)
    proto = str(entry.get("protocol", ""))
    if proto in _PROTO_MAP:
        entry["protocol"] = _PROTO_MAP[proto]
    # ensure both src_ip / dst_ip aliases exist
    entry.setdefault("src_ip", entry.get("src", "-"))
    entry.setdefault("dst_ip", entry.get("dst", "-"))
    entry.setdefault("src",    entry.get("src_ip", "-"))
    entry.setdefault("dst",    entry.get("dst_ip", "-"))
    entry.setdefault("severity",    "Low")
    entry.setdefault("description", "Normal traffic")
    return entry

def load_logs():
    """Load persisted detection logs (not honeypot), normalizing each entry."""
    try:
        if not os.path.exists(LOG_FILE) or os.stat(LOG_FILE).st_size == 0:
            raise json.JSONDecodeError("Empty file", "", 0)
        with open(LOG_FILE, "r") as f:
            raw = json.load(f)
            return [normalize_log(e) for e in raw]
    except json.JSONDecodeError as e:
        print(f"[!] Malformed {LOG_FILE} detected. Resetting... ({e})")
        with open(LOG_FILE, "w") as f:
            f.write("[]")
        return []

def save_log(entry):
    """Append a single detection entry and keep last 1000."""
    logs = load_logs()
    logs.append(entry)
    with open(LOG_FILE, "w") as f:
        json.dump(logs[-1000:], f, indent=2)

def load_blacklist():
    if not os.path.exists(BLACKLIST_FILE):
        return set()
    try:
        with open(BLACKLIST_FILE) as f:
            return set(json.load(f))
    except json.JSONDecodeError:
        return set()

def save_blacklist(blacklist):
    with open(BLACKLIST_FILE, "w") as f:
        json.dump(list(blacklist), f, indent=2)


# === Detection Logic (ML + Rule-Based Together) ===
def detect(packet):
    """
    Called by scapy for each packet.
    Evaluates BOTH rule-based static rules AND ML anomaly detection concurrently.
    """
    global ML_ENABLED
    try:
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            proto_num = int(packet[IP].proto)
            proto_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
            proto_str = proto_map.get(proto_num, str(proto_num))
            length = int(len(packet))

            rule_alert = False
            rule_severity = "Low"
            rule_desc = ""

            # 1. Rule-Based Evaluation
            rules = load_rules()
            for rule in rules:
                r_src = (rule.get("src") or rule.get("pattern") or "").strip()
                r_dst = (rule.get("dst") or "").strip()
                r_proto = str(rule.get("protocol") or "").strip().upper()

                src_match = (not r_src) or (r_src in src_ip)
                dst_match = (not r_dst) or (r_dst in dst_ip)

                proto_match = True
                if r_proto != "":
                    if r_proto in ("1", "ICMP"):
                        proto_match = (proto_num == 1)
                    elif r_proto in ("6", "TCP"):
                        proto_match = (proto_num == 6)
                    elif r_proto in ("17", "UDP"):
                        proto_match = (proto_num == 17)
                    else:
                        proto_match = (r_proto == str(proto_num))

                if src_match and dst_match and proto_match:
                    rule_alert = True
                    rule_severity = rule.get("severity") or "High"
                    rule_desc = rule.get("description") or f"Matched rule for {r_src or 'any'}"
                    break

            # 2. ML Anomaly Detection Evaluation
            ml_alert = False
            if ML_ENABLED:
                try:
                    ml_alert = is_malicious(packet)
                except Exception as ml_err:
                    print(f"[ML] Error evaluating packet: {ml_err}")

            # 3. Determine Consolidated Type and Alert Status
            if rule_alert and ml_alert:
                entry_type = "both"
                alert = True
                severity = rule_severity
                description = f"Rule: {rule_desc} | ML: Anomaly Detected"
            elif rule_alert:
                entry_type = "rule"
                alert = True
                severity = rule_severity
                description = f"Rule: {rule_desc}"
            elif ml_alert:
                entry_type = "ml"
                alert = True
                severity = "High"
                description = "ML Anomaly Detected"
            else:
                entry_type = "safe"
                alert = False
                severity = "Low"
                description = "Normal traffic"

            entry = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "src": src_ip,
                "src_ip": src_ip,
                "dst": dst_ip,
                "dst_ip": dst_ip,
                "protocol": proto_str,
                "payload_len": length,
                "type": entry_type,
                "alert": alert,
                "severity": severity,
                "description": description
            }

            PACKET_LOG.append(entry)
            if len(PACKET_LOG) > 2000:
                del PACKET_LOG[:len(PACKET_LOG)-2000]

            save_log(entry)

    except Exception as e:
        print(f"[ERROR] detect(): {e}")


# === Filter Helper ===
def filter_logs_list(logs, start_date=None, end_date=None, severity=None):
    filtered = []
    for log in logs:
        ts_str = log.get("timestamp", "")
        # Date filter
        if start_date or end_date:
            try:
                log_dt = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S").date()
                if start_date:
                    s_dt = datetime.strptime(start_date, "%Y-%m-%d").date()
                    if log_dt < s_dt:
                        continue
                if end_date:
                    e_dt = datetime.strptime(end_date, "%Y-%m-%d").date()
                    if log_dt > e_dt:
                        continue
            except Exception:
                pass

        # Severity filter
        if severity and severity.strip() != "":
            log_sev = (log.get("severity") or "").lower()
            if log_sev != severity.strip().lower():
                continue

        filtered.append(log)
    return filtered


# === Routes ===
@app.route("/")
def index():
    return render_template("index.html", ml_enabled=ML_ENABLED)

@app.route("/logs")
def logs_page():
    start = request.args.get("start", "")
    end = request.args.get("end", "")
    severity = request.args.get("severity", "")
    logs = load_logs()
    filtered = filter_logs_list(logs, start, end, severity)
    return render_template("logs.html", logs=filtered, start=start, end=end, severity=severity)

@app.route("/rules")
def rules_page():
    return render_template("rules.html", rules=load_rules())

@app.route("/add-rule", methods=["POST"])
def add_rule():
    rules = load_rules()
    existing_ids = [r.get("id", 0) for r in rules if isinstance(r.get("id"), int)]
    new_id = max(existing_ids, default=0) + 1

    new_rule = {
        "id": new_id,
        "src": (request.form.get("src") or "").strip(),
        "dst": (request.form.get("dst") or "").strip(),
        "protocol": (request.form.get("protocol") or "").strip(),
        "severity": (request.form.get("severity") or "Medium").strip(),
        "description": (request.form.get("description") or "").strip()
    }

    rules.append(new_rule)
    with open(RULES_FILE, "w") as f:
        json.dump(rules, f, indent=2)

    return redirect("/rules")

@app.route("/delete-rule/<int:rule_id>", methods=["POST"])
def delete_rule(rule_id):
    rules = load_rules()
    rules = [r for r in rules if r.get("id") != rule_id]
    with open(RULES_FILE, "w") as f:
        json.dump(rules, f, indent=2)
    return redirect("/rules")

@app.route("/honeypot")
def honeypot_page():
    logs = []
    if os.path.exists(HONEYPOT_LOG):
        try:
            with open(HONEYPOT_LOG) as f:
                logs = json.load(f)
                if not isinstance(logs, list):
                    logs = []
        except json.JSONDecodeError:
            logs = []
    
    status_str = f"Running on port {HONEYPOT_STATUS['port']}" if HONEYPOT_STATUS["running"] else "Stopped"
    return render_template("fullhoneypot.html", logs=logs, honeypot_logs=logs, honeypot_status=status_str, honeypot_running=HONEYPOT_STATUS["running"])

@app.route("/honeypot/control", methods=["POST"])
def honeypot_control():
    global HONEYPOT_PROCESS, HONEYPOT_STATUS
    action = request.form.get("action")
    port = request.form.get("port", 8000)
    try:
        port = int(port)
    except Exception:
        port = 8000

    if action == "start":
        if HONEYPOT_PROCESS is None or HONEYPOT_PROCESS.poll() is not None:
            HONEYPOT_STATUS["port"] = port
            script_path = os.path.join(BASE_DIR, "honeypot.py")
            HONEYPOT_PROCESS = subprocess.Popen([sys.executable, script_path, str(port)])
            HONEYPOT_STATUS["running"] = True
    elif action == "stop":
        if HONEYPOT_PROCESS and HONEYPOT_PROCESS.poll() is None:
            HONEYPOT_PROCESS.terminate()
            HONEYPOT_PROCESS = None
            HONEYPOT_STATUS["running"] = False

    return redirect("/honeypot")

@app.route("/toggle-ml", methods=["POST"])
def toggle_ml():
    global ML_ENABLED
    ML_ENABLED = not ML_ENABLED
    return jsonify({"ml_enabled": ML_ENABLED})

@app.route("/api/stats")
def stats():
    logs = load_logs()
    total = len(logs)
    rule = sum(1 for log in logs if log.get("type") in ("rule", "both"))
    ml = sum(1 for log in logs if log.get("type") in ("ml", "both"))
    safe = sum(1 for log in logs if log.get("type") == "safe")
    return jsonify({"total": total, "rule": rule, "ml": ml, "safe": safe})

@app.route("/api/alerts-per-hour")
def alerts_per_hour():
    logs = load_logs()
    hourly = defaultdict(int)
    for log in logs:
        if log.get("alert"):
            try:
                ts = datetime.strptime(log["timestamp"], "%Y-%m-%d %H:%M:%S")
                hour = ts.strftime("%Y-%m-%d %H:00")
                hourly[hour] += 1
            except Exception:
                continue
    sorted_keys = sorted(hourly.keys())
    return jsonify({"labels": sorted_keys, "counts": [hourly[k] for k in sorted_keys]})

@app.route("/api/honeypot-live")
def honeypot_live():
    if not os.path.exists(HONEYPOT_LOG):
        return jsonify([])
    try:
        with open(HONEYPOT_LOG) as f:
            logs = json.load(f)
            if not isinstance(logs, list):
                return jsonify([])
            return jsonify(logs[-20:])
    except Exception:
        return jsonify([])

@app.route("/api/honeypot")
def api_honeypot():
    return honeypot_live()

@app.route("/honeypot/start", methods=["POST"])
def honeypot_start():
    global HONEYPOT_PROCESS, HONEYPOT_STATUS
    if HONEYPOT_PROCESS is None or HONEYPOT_PROCESS.poll() is not None:
        port = (request.json or {}).get("port", 8000)
        try:
            port = int(port)
        except Exception:
            port = 8000
        HONEYPOT_STATUS["port"] = port
        script_path = os.path.join(BASE_DIR, "honeypot.py")
        HONEYPOT_PROCESS = subprocess.Popen([sys.executable, script_path, str(port)])
        HONEYPOT_STATUS["running"] = True
        return jsonify({"status": "started", "port": port})
    return jsonify({"status": "already running"})

@app.route("/honeypot/stop", methods=["POST"])
def honeypot_stop():
    global HONEYPOT_PROCESS, HONEYPOT_STATUS
    if HONEYPOT_PROCESS and HONEYPOT_PROCESS.poll() is None:
        HONEYPOT_PROCESS.terminate()
        HONEYPOT_PROCESS = None
        HONEYPOT_STATUS["running"] = False
        return jsonify({"status": "stopped"})
    return jsonify({"status": "not running"})

@app.route("/honeypot/status")
def honeypot_status():
    return jsonify(HONEYPOT_STATUS)

# === Export Routes ===
@app.route("/export-logs")
@app.route("/export/logs.csv")
def export_logs_csv():
    start = request.args.get("start", "")
    end = request.args.get("end", "")
    severity = request.args.get("severity", "")
    logs = filter_logs_list(load_logs(), start, end, severity)
    default_fields = ["timestamp", "src_ip", "dst_ip", "protocol", "severity", "description", "payload_len", "alert", "type"]
    fieldnames = list(logs[0].keys()) if logs else default_fields
    si = io.StringIO()
    cw = csv.DictWriter(si, fieldnames=fieldnames)
    cw.writeheader()
    if logs:
        cw.writerows(logs)
    output = io.BytesIO()
    output.write(si.getvalue().encode())
    output.seek(0)
    return send_file(output, mimetype="text/csv", as_attachment=True, download_name="logs.csv")

@app.route("/export/logs.json")
def export_logs_json():
    start = request.args.get("start", "")
    end = request.args.get("end", "")
    severity = request.args.get("severity", "")
    logs = filter_logs_list(load_logs(), start, end, severity)
    output = io.BytesIO()
    output.write(json.dumps(logs, indent=2).encode())
    output.seek(0)
    return send_file(output, mimetype="application/json", as_attachment=True, download_name="logs.json")

@app.route("/export-honeypot")
@app.route("/export/honeypot.csv")
def export_honeypot_csv():
    logs = []
    if os.path.exists(HONEYPOT_LOG):
        try:
            with open(HONEYPOT_LOG) as f:
                logs = json.load(f)
        except json.JSONDecodeError:
            logs = []
    fields = list(logs[0].keys()) if logs else ["timestamp", "ip", "port", "request"]
    si = io.StringIO()
    cw = csv.DictWriter(si, fieldnames=fields)
    cw.writeheader()
    if logs:
        cw.writerows(logs)
    output = io.BytesIO()
    output.write(si.getvalue().encode())
    output.seek(0)
    return send_file(output, mimetype="text/csv", as_attachment=True, download_name="honeypot_logs.csv")

@app.route("/export/honeypot.json")
def export_honeypot_json():
    logs = []
    if os.path.exists(HONEYPOT_LOG):
        try:
            with open(HONEYPOT_LOG) as f:
                logs = json.load(f)
        except json.JSONDecodeError:
            logs = []
    output = io.BytesIO()
    output.write(json.dumps(logs, indent=2).encode())
    output.seek(0)
    return send_file(output, mimetype="application/json", as_attachment=True, download_name="honeypot_logs.json")

@app.route("/api/recent-packets")
@app.route("/api/live-packets")
def live_packets():
    # If the sniffer is running, serve from in-memory buffer
    if PACKET_LOG:
        return jsonify(PACKET_LOG[-50:])
    # Fallback: serve last 50 entries from the persisted log file
    logs = load_logs()
    return jsonify(logs[-50:])

# === Sniffer Thread ===
def start_sniffer():
    print("[*] Starting packet sniffer...")
    try:
        sniff(filter="ip", prn=detect, store=0)
    except Exception as e:
        print(f"[!] Sniffer failed (requires elevated privileges/Scapy): {e}")

if __name__ == "__main__":
    ensure_logs_file()
    if not app.debug or os.environ.get("WERKZEUG_RUN_MAIN") == "true":
        sniffer_thread = threading.Thread(target=start_sniffer, daemon=True)
        sniffer_thread.start()
    app.run(debug=True, port=8855)

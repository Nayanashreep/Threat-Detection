# --- app.py (SDN-Based Honeypot Threat Detection) ---

from flask import Flask, render_template, request, jsonify, redirect, send_file
import json, csv, io, os, sys, threading, subprocess
from datetime import datetime, timedelta
from collections import defaultdict
try:
    from scapy.all import sniff, IP
except Exception as _scapy_err:
    sniff = None
    IP = None


# Import the new SDN Controller logic
from controller.controller import controller_instance
from controller.flow_manager import get_recent_flows, get_routing_events, log_flow

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
THREAT_EVENT_COUNTER = 0
LATEST_THREAT_EVENT = {}

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
    """Normalize a single log dict"""
    entry = dict(log)
    proto = str(entry.get("protocol", ""))
    if proto in _PROTO_MAP:
        entry["protocol"] = _PROTO_MAP[proto]
    entry.setdefault("source_ip", entry.get("src_ip", entry.get("src", "-")))
    entry.setdefault("destination_ip", entry.get("dst_ip", entry.get("dst", "-")))
    entry.setdefault("severity", "Low")
    entry.setdefault("event_type", "Normal Traffic")
    entry.setdefault("status", "SAFE")
    entry.setdefault("action", "ALLOW")
    return entry

def load_logs():
    """Load persisted detection logs, normalizing each entry."""
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

# === Detection Logic (ML + Rule-Based) ===
def detect(packet):
    global ML_ENABLED
    try:
        if IP is not None and IP in packet:
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
                pattern = (rule.get("pattern") or "").strip()
                if pattern and pattern in src_ip:
                    rule_alert = True
                    rule_severity = rule.get("severity") or "High"
                    rule_desc = rule.get("description") or f"Matched rule pattern {pattern}"
                    break

            # 2. ML Anomaly Detection Evaluation
            ml_alert = False
            if ML_ENABLED:
                try:
                    ml_alert = is_malicious(packet)
                except Exception as ml_err:
                    print(f"[ML] Error: {ml_err}")

            if rule_alert or ml_alert:
                entry_type = "Threat Detected"
                severity = rule_severity if rule_alert else "High"
                desc = f"Rule: {rule_desc}" if rule_alert else "ML Anomaly Detected"
                
                # Notify SDN Controller
                controller_instance.handle_threat(desc, src_ip, dst_ip, proto_str, severity)
                
                entry = {
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "source_ip": src_ip,
                    "destination_ip": dst_ip,
                    "protocol": proto_str,
                    "payload_len": length,
                    "event_type": entry_type,
                    "severity": severity,
                    "description": desc,
                    "action": "ISOLATED" if severity.lower() == "high" else "BLOCKED",
                    "status": "THREAT DETECTED"
                }
            else:
                controller_instance.handle_new_flow(src_ip, dst_ip, proto_str, "N/A")
                entry = {
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "source_ip": src_ip,
                    "destination_ip": dst_ip,
                    "protocol": proto_str,
                    "payload_len": length,
                    "event_type": "Normal Traffic",
                    "severity": "Low",
                    "description": "Normal traffic",
                    "action": "ALLOW",
                    "status": "SAFE"
                }

            PACKET_LOG.append(entry)
            if len(PACKET_LOG) > 2000:
                del PACKET_LOG[:len(PACKET_LOG)-2000]

            save_log(entry)

    except Exception as e:
        print(f"[ERROR] detect(): {e}")


def filter_logs_list(logs, start_date=None, end_date=None, severity=None):
    filtered = []
    for log in logs:
        ts_str = log.get("timestamp", "")
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

        if severity and severity.strip() != "":
            log_sev = (log.get("severity") or "").lower()
            if log_sev != severity.strip().lower():
                continue

        filtered.append(log)
    return filtered


# === Routes ===
@app.route("/")
@app.route("/dashboard")
def index():
    return render_template("index.html", active_tab="dashboard", ml_enabled=ML_ENABLED)

@app.route("/routing")
def routing_page():
    return render_template("index.html", active_tab="routing", ml_enabled=ML_ENABLED)

@app.route("/topology")
def topology_page():
    return render_template("index.html", active_tab="topology", ml_enabled=ML_ENABLED)

@app.route("/traffic")
def traffic_page():
    return render_template("index.html", active_tab="traffic", ml_enabled=ML_ENABLED)

@app.route("/threats")
def threats_page():
    all_logs = load_logs()
    threats = [log for log in all_logs if log.get("status") == "THREAT DETECTED" or log.get("severity", "").lower() in ["high", "critical", "medium"]]
    return render_template("index.html", active_tab="threats", threats=threats, ml_enabled=ML_ENABLED)

@app.route("/rules")
def rules_page():
    return render_template("index.html", active_tab="rules", rules=load_rules(), ml_enabled=ML_ENABLED)

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
    status_str = f"RUNNING on port {HONEYPOT_STATUS['port']}" if HONEYPOT_STATUS["running"] else "STOPPED"
    return render_template("index.html", active_tab="honeypot", logs=logs, honeypot_logs=logs, honeypot_status=status_str, honeypot_running=HONEYPOT_STATUS["running"], listening_ip="0.0.0.0", port=HONEYPOT_STATUS["port"], ml_enabled=ML_ENABLED)

@app.route("/logs")
def logs_page():
    start = request.args.get("start", "")
    end = request.args.get("end", "")
    severity = request.args.get("severity", "")
    logs = load_logs()
    filtered = filter_logs_list(logs, start, end, severity)
    return render_template("index.html", active_tab="logs", logs=filtered, start=start, end=end, severity=severity, ml_enabled=ML_ENABLED)

@app.route("/api/rules", methods=["GET", "POST"])
def api_rules():
    if request.method == "POST":
        data = request.json or request.form
        rules = load_rules()
        existing_ids = [r.get("id", 0) for r in rules if isinstance(r.get("id"), int)]
        new_id = max(existing_ids, default=0) + 1
        new_rule = {
            "id": new_id,
            "pattern": (data.get("pattern") or "").strip(),
            "severity": (data.get("severity") or "Medium").strip(),
            "description": (data.get("description") or "").strip()
        }
        rules.append(new_rule)
        with open(RULES_FILE, "w") as f:
            json.dump(rules, f, indent=2)
        return jsonify({"success": True, "rules": rules})
    return jsonify(load_rules())

@app.route("/api/delete-rule/<int:rule_id>", methods=["POST", "DELETE"])
def api_delete_rule(rule_id):
    rules = load_rules()
    rules = [r for r in rules if r.get("id") != rule_id]
    with open(RULES_FILE, "w") as f:
        json.dump(rules, f, indent=2)
    return jsonify({"success": True, "rules": rules})

@app.route("/api/logs", methods=["GET"])
def api_logs():
    start = request.args.get("start", "")
    end = request.args.get("end", "")
    severity = request.args.get("severity", "")
    logs = load_logs()
    filtered = filter_logs_list(logs, start, end, severity)
    return jsonify(filtered)

@app.route("/api/threats", methods=["GET"])
def api_threats():
    all_logs = load_logs()
    threats = [log for log in all_logs if log.get("status") == "THREAT DETECTED" or log.get("severity", "").lower() in ["high", "critical", "medium"]]
    return jsonify(threats)



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

@app.route("/honeypot/status")
def honeypot_status():
    return jsonify(HONEYPOT_STATUS)

@app.route("/api/honeypot")
def api_honeypot():
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

@app.route("/api/report-threat", methods=["POST"])
def report_threat():
    global THREAT_EVENT_COUNTER, LATEST_THREAT_EVENT
    data = request.json or {}
    src_ip = data.get("source_ip", "Unknown")
    dst_ip = data.get("destination_ip", "Unknown")
    port = data.get("port", "Unknown")
    threat_type = data.get("threat_type", "Unknown Threat")
    severity = data.get("severity", "High")
    payload = data.get("payload", "DDoS signature pattern")
    
    # Send to controller logic
    controller_instance.handle_threat(threat_type, src_ip, dst_ip, port, severity)
    
    # Also log to logs.json so /threats and /logs display the alert
    action = "BLOCKED" if severity.lower() == "critical" else "ISOLATED"
    entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "source_ip": src_ip,
        "destination_ip": dst_ip,
        "protocol": "TCP",
        "payload_len": 64,
        "event_type": threat_type,
        "severity": severity,
        "description": f"{threat_type} on port {port}",
        "action": action,
        "status": "THREAT DETECTED"
    }
    save_log(entry)

    # Save to honeypot_log.json so Honeypot tab displays trapped payloads
    try:
        hp_logs = []
        if os.path.exists(HONEYPOT_LOG):
            with open(HONEYPOT_LOG, "r") as f:
                hp_logs = json.load(f)
                if not isinstance(hp_logs, list):
                    hp_logs = []
        hp_entry = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "attacker_ip": src_ip,
            "service": f"SDN-Decoy-Port-{port}",
            "request": f"{threat_type} trapped in Honeypot VLAN. Destination was {dst_ip}:{port} [Payload: {payload}]"
        }
        hp_logs.append(hp_entry)
        with open(HONEYPOT_LOG, "w") as f:
            json.dump(hp_logs[-200:], f, indent=2)
    except Exception as hp_err:
        print(f"[!] Error updating honeypot log: {hp_err}")

    # Track latest event for real-time frontend detection
    THREAT_EVENT_COUNTER += 1
    LATEST_THREAT_EVENT = {
        "counter": THREAT_EVENT_COUNTER,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "source_ip": src_ip,
        "destination_ip": dst_ip,
        "threat_type": threat_type,
        "severity": severity,
        "action": action
    }
    return jsonify({"status": "received", "counter": THREAT_EVENT_COUNTER})

@app.route("/api/report-flow", methods=["POST"])
def report_flow():
    data = request.json or {}
    src_ip = data.get("source_ip", "10.0.0.1")
    dst_ip = data.get("destination_ip", "10.0.0.3")
    port = data.get("port", 443)
    proto = data.get("protocol", "TCP")
    status = data.get("status", "SAFE")
    
    controller_instance.handle_new_flow(src_ip, dst_ip, proto, port)
    entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "source_ip": src_ip,
        "destination_ip": dst_ip,
        "protocol": proto,
        "payload_len": 128,
        "event_type": "Legitimate Financial Transaction",
        "severity": "Low",
        "description": f"Customer payment transaction on port {port}",
        "action": "ALLOW",
        "status": "SAFE"
    }
    save_log(entry)
    return jsonify({"status": "received"})

@app.route("/toggle-ml", methods=["POST"])
def toggle_ml():
    global ML_ENABLED
    ML_ENABLED = not ML_ENABLED
    return jsonify({"ml_enabled": ML_ENABLED})

@app.route("/api/stats")
@app.route("/api/live-status")
def stats():
    flows = get_recent_flows()
    routing_events = get_routing_events()
    logs = load_logs()
    
    threat_count = sum(1 for f in flows if f.get("status") == "THREAT DETECTED")
    safe_count = sum(1 for f in flows if f.get("status") == "SAFE")
    
    if safe_count == 0 and len(logs) > 0:
        safe_count = sum(1 for l in logs if l.get("status") == "SAFE")
    if threat_count == 0 and len(logs) > 0:
        threat_count = sum(1 for l in logs if l.get("status") == "THREAT DETECTED")
        
    total = len(flows) if len(flows) > 0 else (threat_count + safe_count)
    if safe_count + threat_count > total:
        total = safe_count + threat_count
        
    rerouted = len(routing_events)
    
    return jsonify({
        "total": max(1, total),
        "threats": threat_count,
        "safe": safe_count,
        "rerouted": rerouted,
        "threat_counter": THREAT_EVENT_COUNTER,
        "latest_threat": LATEST_THREAT_EVENT,
        "routing_events_count": len(routing_events)
    })

@app.route("/api/alerts-per-hour")
def alerts_per_hour():
    threat_timestamps = []
    
    # 1. From logs.json
    logs = load_logs()
    for log in logs:
        if log.get("status") == "THREAT DETECTED":
            ts_str = log.get("timestamp")
            if ts_str:
                for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M"):
                    try:
                        threat_timestamps.append(datetime.strptime(ts_str.split(".")[0], fmt))
                        break
                    except Exception:
                        pass

    # 2. From flows_log.json
    flows = get_recent_flows()
    for flow in flows:
        if flow.get("status") == "THREAT DETECTED" or (flow.get("threat_type") and flow.get("threat_type") not in ("None", "")):
            ts_str = flow.get("timestamp")
            if ts_str:
                for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M"):
                    try:
                        threat_timestamps.append(datetime.strptime(ts_str.split(".")[0], fmt))
                        break
                    except Exception:
                        pass

    # 3. From honeypot_log.json
    if os.path.exists(HONEYPOT_LOG):
        try:
            with open(HONEYPOT_LOG, "r", encoding="utf-8") as f:
                h_logs = json.load(f)
                if isinstance(h_logs, list):
                    for h in h_logs:
                        if h.get("alert") or h.get("status") == "THREAT DETECTED":
                            ts_str = h.get("timestamp")
                            if ts_str:
                                for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M"):
                                    try:
                                        threat_timestamps.append(datetime.strptime(ts_str.split(".")[0], fmt))
                                        break
                                    except Exception:
                                        pass
        except Exception:
            pass

    # Aggregate counts per hourly bucket (YYYY-MM-DD HH:00)
    hourly = defaultdict(int)
    for dt in threat_timestamps:
        hourly[dt.strftime("%Y-%m-%d %H:00")] += 1

    # Focus on active operational day (or current day) for a standard 24-hour telemetry matrix
    active_date = max(threat_timestamps).date() if threat_timestamps else datetime.now().date()
    labels = [f"{h:02d}:00" for h in range(24)]
    counts = [hourly.get(f"{active_date} {h:02d}:00", 0) for h in range(24)]

    return jsonify({"labels": labels, "counts": counts})

@app.route("/api/routing")
def api_routing():
    return jsonify(get_routing_events()[-50:])

@app.route("/api/recent-packets")
@app.route("/api/live-packets")
def live_packets():
    flows = get_recent_flows()
    return jsonify(flows[-50:])


# === Export Routes ===
@app.route("/export-logs")
@app.route("/export/logs.csv")
def export_logs_csv():
    start = request.args.get("start", "")
    end = request.args.get("end", "")
    severity = request.args.get("severity", "")
    logs = filter_logs_list(load_logs(), start, end, severity)
    fieldnames = ["timestamp", "source_ip", "destination_ip", "protocol", "severity", "description", "payload_len", "status", "action", "event_type"]
    si = io.StringIO()
    cw = csv.DictWriter(si, fieldnames=fieldnames, quoting=csv.QUOTE_ALL, escapechar='\\', extrasaction='ignore')
    cw.writeheader()
    for row in logs:
        if isinstance(row, dict):
            cw.writerow({k: str(row.get(k, "-")).replace("\r", " ").replace("\n", " ") for k in fieldnames})
    output = io.BytesIO()
    output.write(si.getvalue().encode("utf-8"))
    output.seek(0)
    return send_file(output, mimetype="text/csv", as_attachment=True, download_name="network_security_logs.csv")

@app.route("/export/honeypot.csv")
@app.route("/export-honeypot-csv")
def export_honeypot_csv():
    logs = []
    if os.path.exists(HONEYPOT_LOG):
        try:
            with open(HONEYPOT_LOG, "r", encoding="utf-8") as f:
                logs = json.load(f)
                if not isinstance(logs, list):
                    logs = []
        except Exception:
            logs = []
    fieldnames = ["timestamp", "attacker_ip", "service", "request"]
    si = io.StringIO()
    cw = csv.DictWriter(si, fieldnames=fieldnames, quoting=csv.QUOTE_ALL, escapechar='\\', extrasaction='ignore')
    cw.writeheader()
    for entry in logs:
        if isinstance(entry, dict):
            cw.writerow({
                "timestamp": str(entry.get("timestamp", "-")),
                "attacker_ip": str(entry.get("attacker_ip", entry.get("src", entry.get("src_ip", "-")))),
                "service": str(entry.get("service", "-")),
                "request": str(entry.get("request", entry.get("payload", "-"))).replace("\r", " ").replace("\n", " ")
            })
    output = io.BytesIO()
    output.write(si.getvalue().encode("utf-8"))
    output.seek(0)
    return send_file(output, mimetype="text/csv", as_attachment=True, download_name="honeypot_logs.csv")

@app.route("/export/honeypot.json")
@app.route("/export-honeypot-json")
def export_honeypot_json():
    logs = []
    if os.path.exists(HONEYPOT_LOG):
        try:
            with open(HONEYPOT_LOG, "r", encoding="utf-8") as f:
                logs = json.load(f)
                if not isinstance(logs, list):
                    logs = []
        except Exception:
            logs = []
    output = io.BytesIO()
    output.write(json.dumps(logs, indent=2).encode("utf-8"))
    output.seek(0)
    return send_file(output, mimetype="application/json", as_attachment=True, download_name="honeypot_logs.json")




# === Sniffer Thread ===
def start_sniffer():
    print("[*] Starting packet sniffer...")
    try:
        sniff(filter="ip", prn=detect, store=0)
    except Exception as e:
        print(f"[!] Sniffer failed (requires elevated privileges/Scapy): {e}")

if __name__ == "__main__":
    ensure_logs_file()
    sniffer_thread = threading.Thread(target=start_sniffer, daemon=True)
    sniffer_thread.start()
    app.run(host="0.0.0.0", port=8855, debug=False)


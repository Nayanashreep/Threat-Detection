import json
import os
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROUTING_LOG = os.path.join(BASE_DIR, "logs", "routing_log.json")
FLOWS_LOG = os.path.join(BASE_DIR, "logs", "flows_log.json")

def _load_json(filepath):
    if not os.path.exists(filepath):
        return []
    try:
        with open(filepath, "r") as f:
            return json.load(f)
    except json.JSONDecodeError:
        return []

def _save_json(filepath, data):
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, "w") as f:
        json.dump(data, f, indent=2)

def log_routing_event(threat_src, threat_dst, original_route, new_route, action, status):
    events = _load_json(ROUTING_LOG)
    event = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "threat_src": threat_src,
        "threat_dst": threat_dst,
        "original_route": original_route,
        "new_route": new_route,
        "action": action,
        "status": status
    }
    events.append(event)
    _save_json(ROUTING_LOG, events[-100:])

def log_flow(src, dst, proto, port, status, threat_type="None"):
    flows = _load_json(FLOWS_LOG)
    flow = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "src": src,
        "dst": dst,
        "protocol": proto,
        "port": port,
        "status": status,
        "threat_type": threat_type
    }
    flows.append(flow)
    _save_json(FLOWS_LOG, flows[-500:])

def get_recent_flows():
    return _load_json(FLOWS_LOG)

def get_routing_events():
    return _load_json(ROUTING_LOG)

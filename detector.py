from scapy.all import IP, TCP, UDP, ICMP
import json
import os
from datetime import datetime
from ml_detector import is_malicious  # ML anomaly detection

# Load rules from JSON file
RULES_PATH = os.path.join("rules", "signatures.json")
with open(RULES_PATH, "r") as f:
    RULES = json.load(f)

# In-memory trackers
SYN_TRACKER = {}
ICMP_TRACKER = {}
UDP_TRACKER = {}


def detect_intrusion(pkt):
    """Apply static rules and ML to detect malicious activity."""
    if IP not in pkt:
        return False, ""

    src_ip = pkt[IP].src
    now = datetime.now()

    for rule in RULES:
        field = rule["field"].upper()
        rule_type = rule["type"]

        # SYN flood detection
        if rule_type == "threshold" and field == "SYN":
            if TCP in pkt and pkt[TCP].flags == "S":
                SYN_TRACKER.setdefault(src_ip, []).append(now)
                SYN_TRACKER[src_ip] = [t for t in SYN_TRACKER[src_ip] if (now - t).seconds < rule["timeframe"]]
                if len(SYN_TRACKER[src_ip]) >= rule["threshold"]:
                    return True, f"{rule['name']} from {src_ip}"

        # ICMP flood detection
        elif rule_type == "threshold" and field == "ICMP":
            if ICMP in pkt:
                ICMP_TRACKER.setdefault(src_ip, []).append(now)
                ICMP_TRACKER[src_ip] = [t for t in ICMP_TRACKER[src_ip] if (now - t).seconds < rule["timeframe"]]
                if len(ICMP_TRACKER[src_ip]) >= rule["threshold"]:
                    return True, f"{rule['name']} from {src_ip}"

        # UDP flood detection
        elif rule_type == "threshold" and field == "UDP":
            if UDP in pkt:
                UDP_TRACKER.setdefault(src_ip, []).append(now)
                UDP_TRACKER[src_ip] = [t for t in UDP_TRACKER[src_ip] if (now - t).seconds < rule["timeframe"]]
                if len(UDP_TRACKER[src_ip]) >= rule["threshold"]:
                    return True, f"{rule['name']} from {src_ip}"

        # Null scan detection (no TCP flags)
        elif rule_type == "signature" and field == "TCP_NULL":
            if TCP in pkt and pkt[TCP].flags == 0:
                return True, f"{rule['name']} from {src_ip}"

    # Machine Learning detection (last fallback)
    if is_malicious(pkt):
        return True, f"ML Anomaly Detected from {src_ip}"

    return False, ""

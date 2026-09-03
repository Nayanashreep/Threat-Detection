import requests
import json
import os
from datetime import datetime
from detector import detect_intrusion

LOG_PATH = os.path.join("logs", "traffic_log.json")

# In-memory log to reduce file I/O
packet_log = []

def log_packet(pkt, alert=False, reason=""):
    """Log each packet to the JSON log file."""
    entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "src_ip": pkt[IP].src if IP in pkt else "N/A",
        "dst_ip": pkt[IP].dst if IP in pkt else "N/A",
        "protocol": pkt.proto if IP in pkt else "N/A",
        "dst_port": pkt[TCP].dport if TCP in pkt else None,
        "alert": alert,
        "reason": reason
    }

    packet_log.append(entry)

    # Load existing logs
    try:
        with open(LOG_PATH, "r") as f:
            existing_logs = json.load(f)
    except:
        existing_logs = []

    existing_logs.append(entry)

    # Keep only the latest 500 entries
    with open(LOG_PATH, "w") as f:
        json.dump(existing_logs[-500:], f, indent=2)

def process_packet(pkt):
    """Analyze and log packets."""
    if IP not in pkt:
        return

    alert, reason = detect_intrusion(pkt)
    log_packet(pkt, alert, reason)

    if alert:
        src_ip = pkt[IP].src
        print(f"[!] Threat detected from {src_ip}. Triggering SDN Controller BLOCK action.")
        try:
            # Call the Ryu REST API to block the IP on OpenFlow switches
            requests.post("http://127.0.0.1:8080/block", json={"ip": src_ip}, timeout=2)
            # Also notify the dashboard
            requests.post("http://127.0.0.1:8855/api/report-threat", json={
                "source_ip": src_ip,
                "destination_ip": pkt[IP].dst,
                "port": pkt[TCP].dport if TCP in pkt else 80,
                "threat_type": reason,
                "severity": "Critical"
            }, timeout=2)
        except Exception as e:
            pass

def start_sniffing():
    print("[🔍] Packet sniffing started. Press Ctrl+C to stop.")
    from scapy.all import sniff
    sniff(filter="ip", prn=process_packet, store=0)

if __name__ == "__main__":
    from scapy.all import IP, TCP, ICMP
    start_sniffing()


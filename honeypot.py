import socket
import threading
import json
from datetime import datetime
import os
import sys
import urllib.request
import urllib.parse

# Default port
HONEYPOT_PORT = 9999
if len(sys.argv) > 1:
    try:
        HONEYPOT_PORT = int(sys.argv[1])
    except ValueError:
        pass

# Log file path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(BASE_DIR, "logs")
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "honeypot_log.json")

def notify_controller(ip, port, payload):
    """Notify the Flask app / SDN controller of the threat."""
    url = "http://127.0.0.1:8855/api/report-threat"
    data = {
        "source_ip": ip,
        "destination_ip": "Honeypot",
        "port": port,
        "payload": payload,
        "threat_type": "Honeypot Connection",
        "severity": "High"
    }
    try:
        req = urllib.request.Request(url, method="POST")
        req.add_header("Content-Type", "application/json")
        jsondata = json.dumps(data).encode("utf-8")
        urllib.request.urlopen(req, data=jsondata, timeout=2)
    except Exception as e:
        print(f"[HONEYPOT] Failed to notify controller: {e}")

def log_connection(ip, src_port, data):
    payload_str = data.strip()
    entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "source_ip": ip,
        "destination_ip": "0.0.0.0",
        "source_port": src_port,
        "destination_port": HONEYPOT_PORT,
        "protocol": "TCP",
        "event_type": "Honeypot Access",
        "severity": "High",
        "action": "BLOCKED",
        "status": "THREAT DETECTED",
        # Keep old fields for backward compatibility if needed
        "ip": ip,
        "attacker_ip": ip,
        "port": HONEYPOT_PORT,
        "service": f"TCP/{HONEYPOT_PORT}",
        "payload": payload_str,
        "request": payload_str,
    }

    try:
        with open(LOG_FILE, "r") as f:
            logs = json.load(f)
    except:
        logs = []

    logs.append(entry)
    with open(LOG_FILE, "w") as f:
        json.dump(logs[-500:], f, indent=2)

    print(f"[HONEYPOT] Connection from {ip}:{src_port} | Data: {data.strip()}")
    
    # Notify SDN Controller
    notify_controller(ip, HONEYPOT_PORT, payload_str)


def handle_client(client_socket, address):
    try:
        data = client_socket.recv(1024).decode(errors="ignore")
        log_connection(address[0], address[1], data)
        client_socket.send(b"Access Denied\r\n")
    except Exception as e:
        print(f"[!] Error handling client {address}: {e}")
    finally:
        client_socket.close()


def start_honeypot():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", HONEYPOT_PORT))
    server.listen(5)
    print(f"[HONEYPOT] Listening on port {HONEYPOT_PORT}...")

    while True:
        client, addr = server.accept()
        threading.Thread(target=handle_client, args=(client, addr)).start()


if __name__ == "__main__":
    start_honeypot()

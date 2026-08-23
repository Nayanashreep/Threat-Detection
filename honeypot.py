import socket
import threading
import json
from datetime import datetime
import os
import sys

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

def log_connection(ip, data):
    payload_str = data.strip()
    entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "src": ip,
        "src_ip": ip,
        "ip": ip,
        "attacker_ip": ip,
        "port": HONEYPOT_PORT,
        "service": f"TCP/{HONEYPOT_PORT}",
        "payload": payload_str,
        "request": payload_str,
        "alert": True,
        "source": "honeypot"
    }

    try:
        with open(LOG_FILE, "r") as f:
            logs = json.load(f)
    except:
        logs = []

    logs.append(entry)
    with open(LOG_FILE, "w") as f:
        json.dump(logs[-500:], f, indent=2)

    print(f"[HONEYPOT] Connection from {ip} | Data: {data.strip()}")


def handle_client(client_socket, address):
    try:
        data = client_socket.recv(1024).decode(errors="ignore")
        log_connection(address[0], data)
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

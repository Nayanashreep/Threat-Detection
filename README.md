# 🛡️ NIDPS — Network Intrusion Detection & Prevention System

A real-time network security tool that monitors traffic, detects intrusions using both rule-based and ML-based methods, and traps attackers with a honeypot — all through a clean web dashboard.

---

## Features

- **📡 Live Packet Sniffing** — Captures IP traffic in real-time using Scapy
- **🔍 Rule-Based Detection** — Flag traffic matching custom IP/protocol rules
- **🧠 ML-Based Detection** — Isolation Forest model (trained on KDD Cup dataset) detects anomalous traffic
- **🐝 Honeypot** — Fake service that traps and logs attacker connections
- **🌐 Web Dashboard** — Flask-powered UI with charts, logs, rule management, and exports

---

## Project Structure

```
NIDPS/
├── app.py              # Main Flask application (all routes & detection logic)
├── ml_detector.py      # ML anomaly detection (Isolation Forest)
├── honeypot.py         # TCP honeypot server
├── detector.py         # Signature-based intrusion detector
├── sniffer.py          # Packet sniffer (standalone)
├── preventer.py        # IP blocking via iptables (Linux)
├── rules.json          # User-defined detection rules
├── dataset/
│   └── KDDTrain+.csv   # KDD Cup training dataset (not committed — download separately)
├── logs/               # Runtime log directory
├── static/
│   └── style.css       # Dashboard styles
└── templates/
    ├── index.html      # Dashboard
    ├── logs.html       # Log viewer
    ├── rules.html      # Rule management
    └── fullhoneypot.html  # Honeypot control & log viewer
```

---

## Setup

### Requirements
- Python 3.10+
- Linux/WSL (Scapy requires raw socket access)

### Install dependencies

```bash
python3 -m venv venv
source venv/bin/activate
pip install flask scapy scikit-learn pandas joblib numpy
```

### Download Dataset (for ML training)

Download **KDDTrain+.csv** from the [NSL-KDD dataset](https://www.unb.ca/cic/datasets/nsl.html) and place it in the `dataset/` folder. The model trains automatically on first run if `model.joblib` is not found.

### Run the application

```bash
# Standard (no packet sniffing)
python app.py

# With live packet capture (requires root)
sudo python app.py
```

Open **http://127.0.0.1:8855** in your browser.

---

## Usage

### Dashboard
- View total packets, rule alerts, ML alerts, and safe packets
- See the hourly alert trend chart
- Monitor live packet stream

### Rules
- Add rules specifying Source IP, Destination IP, Protocol, Severity, Description
- Delete rules with one click

### Logs
- Filter captured events by date range and severity
- Export to CSV

### Honeypot
- Enter port and click **Start** to launch the honeypot
- Attacker connections are logged with IP, payload, and timestamp
- Export honeypot logs to CSV

---

## Detection Methods

| Method | Description |
|--------|-------------|
| **Rule-Based** | Matches packets against user-defined IP/protocol rules stored in `rules.json` |
| **ML (Isolation Forest)** | Trained on KDD Cup network dataset. Detects statistically anomalous packets |
| **Both** | Both methods run on every packet simultaneously |

---

## Honeypot Attacks Captured (Example)

```
GET /admin HTTP/1.1           → HTTP admin probe
GET /wp-login.php HTTP/1.1    → WordPress scan
USER root / PASS toor         → FTP brute-force
SSH-2.0-OpenSSH_7.4           → SSH version fingerprint
() { :; }; /bin/bash -c 'id' → Shellshock exploit attempt
EHLO attacker.com             → SMTP relay probe
```

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Backend | Python / Flask |
| Packet Capture | Scapy |
| ML Model | scikit-learn (Isolation Forest) |
| Training Data | NSL-KDD (KDDTrain+) |
| Frontend | HTML / Vanilla CSS / Chart.js |
| Storage | JSON files |

---

## Author

**NAYANASHREE P** — nayanashreep.23ise@cambridge.edu.in

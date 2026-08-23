# 🛡️ SDN-Based Honeypot Threat Detection and Secure Routing for Financial Networks

A real-time financial network security system that simulates a Mininet SDN network, uses a TCP Honeypot as its primary threat detection mechanism, detects DDoS & intrusion anomalies using Machine Learning trained on financial network traffic, and dynamically blocks/isolates threats via an SDN controller.

---

## 🌟 Key Features

- **🌐 Simulated Financial Network Topology (Mininet):** Models Customer, Payment Gateway, Bank Server, Attacker, and Honeypot.
- **🐝 Honeypot Primary Threat Detection:** Traps attackers targeting financial services and immediately alerts the SDN controller.
- **🧠 Financial Traffic Anomaly Detection:** Machine Learning model trained on `Financial_Network_Traffic.csv` to detect DDoS floods and malicious traffic anomalies.
- **🛣️ SDN Controller Dynamic Rerouting:** Automatically reroutes suspicious traffic away from the Bank Server / Payment Gateway into isolated VLANs or drops malicious packets.
- **📊 Real-time Dashboard:** Displays Live Network Flows, Threat Alerts, SDN Topology, Secure Routing paths, Rules Management, and CSV log exports.

---

## 📁 Project Structure

```
NIDPS/
├── app.py                      # Flask Application (Dashboard, Routes, API & Sniffer)
├── honeypot.py                 # TCP Honeypot (Primary Threat Detection)
├── mininet_topology.py         # Mininet Financial Network Topology Script
├── ml_detector.py              # ML Anomaly Detector (Financial Network Traffic)
├── controller/
│   ├── controller.py           # SDN Controller main module
│   ├── flow_manager.py         # Tracks active network flows & routing logs
│   └── routing.py              # Dynamic route calculation logic
├── dataset/
│   ├── Financial_Network_Traffic.csv # Financial Network Traffic dataset
│   ├── generate_dataset.py     # Script to generate financial network samples
│   └── model.joblib            # Saved Machine Learning model
├── templates/                  # HTML Dashboard views (Topology, Routing, Threats, etc.)
└── static/style.css            # Custom CSS styling
```

---

## 🚀 Quick Setup

### Requirements
- Python 3.10+
- WSL / Ubuntu Linux

### Install Dependencies

```bash
source venv/bin/activate
pip install flask scapy scikit-learn pandas joblib numpy
```

### Run the Application

```bash
# 1. Start the Flask Security Dashboard
python3 app.py

# 2. (Optional) Run Mininet Topology (requires root on Linux)
sudo python3 mininet_topology.py
```

Access the dashboard at **http://127.0.0.1:8855**.

---

## 📊 Dataset & Algorithm

| Component | Specification |
|---|---|
| **Dataset** | `Financial_Network_Traffic.csv` (Simulated Financial Services Traffic: Bank API, Payment Gateway, ATM Switch, Web Portal) |
| **ML Algorithm** | **Isolation Forest** (Unsupervised Anomaly Detection for DDoS & Intrusion Floods) |
| **Primary Detection** | **Honeypot Service** (Captures unauthorized scans & exploit probes) |
| **Prevention Engine** | **SDN Controller** (Automated dynamic flow rerouting & threat isolation) |

---

## ✍️ Author

**NAYANASHREE P** — nayanashreep.23ise@cambridge.edu.in

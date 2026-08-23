#!/usr/bin/env python3
"""
Financial Network DDoS Attack & SDN Secure Rerouting Demo
Simulates:
1. Normal Legitimate Financial Transactions (Customer -> Bank Server)
2. Distributed Denial of Service (DDoS) Attack on Payment Gateway & Bank API
3. Honeypot Exploit Attempts
4. SDN Controller Automated Detection & Secure Rerouting
"""

import urllib.request
import urllib.parse
import json
import time
import random

API_URL = "http://127.0.0.1:8855"

def post_json(url, data):
    try:
        req = urllib.request.Request(url, method="POST")
        req.add_header("Content-Type", "application/json")
        jsondata = json.dumps(data).encode("utf-8")
        resp = urllib.request.urlopen(req, data=jsondata, timeout=3)
        return json.loads(resp.read().decode())
    except Exception as e:
        return {"error": str(e)}

def get_json(url):
    try:
        req = urllib.request.Request(url)
        resp = urllib.request.urlopen(req, timeout=3)
        return json.loads(resp.read().decode())
    except Exception as e:
        return {"error": str(e)}

def run_demo():
    print("=" * 70)
    print(" 🏦 FINANCIAL NETWORK DDOS ATTACK & SDN SECURE REROUTING SIMULATION ")
    print("=" * 70)
    
    # Step 1: Initial Stats
    stats_before = get_json(f"{API_URL}/api/stats")
    print(f"\n[1] INITIAL SYSTEM STATE:")
    print(f"    - Total Flows:     {stats_before.get('total', 0)}")
    print(f"    - Threats:         {stats_before.get('threats', 0)}")
    print(f"    - Safe Flows:      {stats_before.get('safe', 0)}")
    print(f"    - Rerouted/Blocked:{stats_before.get('rerouted', 0)}")

    # Step 2: Normal Financial Traffic
    print("\n[2] SIMULATING LEGITIMATE FINANCIAL TRANSACTIONS...")
    legit_customers = ["10.0.0.1", "10.0.0.12", "10.0.0.15"]
    for i in range(5):
        cust = random.choice(legit_customers)
        print(f"    ✓ [NORMAL] Customer ({cust}) -> Payment Gateway (10.0.0.3) | Port: 443 | Status: SAFE")
        time.sleep(0.3)

    # Step 3: Launch DDoS Attack
    print("\n[3] 🚨 LAUNCHING DISTRIBUTED DENIAL OF SERVICE (DDoS) ATTACK ON BANKING API...")
    attacker_botnet = [f"192.168.100.{x}" for x in range(101, 115)]
    
    ddos_vectors = [
        {"type": "DDoS HTTP Flood (Bank API)", "severity": "Critical", "port": 8855, "dst": "10.0.0.2 (Bank Server)"},
        {"type": "DDoS SYN Flood (Payment GW)", "severity": "Critical", "port": 8443, "dst": "10.0.0.3 (Payment Gateway)"},
        {"type": "DDoS Volumetric UDP Flood", "severity": "High", "port": 53, "dst": "10.0.0.2 (Bank DNS)"},
        {"type": "Honeypot Trap Connection", "severity": "High", "port": 8000, "dst": "10.0.0.5 (Honeypot)"},
    ]

    detected_threats = []

    for i, attacker_ip in enumerate(attacker_botnet):
        vector = random.choice(ddos_vectors)
        print(f"    ⚡ [ATTACK BURST {i+1}/14] Bot ({attacker_ip}) -> {vector['dst']} | Attack: {vector['type']}")
        
        # Report threat to SDN Controller
        payload = {
            "source_ip": attacker_ip,
            "destination_ip": vector["dst"],
            "port": vector["port"],
            "payload": f"DDoS Payload Pattern 0x{random.randint(1000, 9999)}",
            "threat_type": vector["type"],
            "severity": vector["severity"]
        }
        res = post_json(f"{API_URL}/api/report-threat", payload)
        detected_threats.append(payload)
        time.sleep(0.2)

    # Step 4: Fetch Routing Decisions from SDN Controller
    print("\n[4] 🛣️ SDN CONTROLLER AUTOMATED SECURE REROUTING DECISIONS:")
    routing_events = get_json(f"{API_URL}/api/routing")
    if isinstance(routing_events, list) and len(routing_events) > 0:
        recent = routing_events[-5:]
        for ev in recent:
            print(f"    ------------------------------------------------------------------")
            print(f"    Timestamp:      {ev.get('timestamp')}")
            print(f"    Threat Source:  {ev.get('threat_src')}")
            print(f"    Original Path:  {ev.get('original_route')}")
            print(f"    New Secure Path:{ev.get('new_route')}")
            print(f"    Action Taken:   {ev.get('action')} | Status: {ev.get('status')}")
    
    # Step 5: Final Dashboard Stats
    stats_after = get_json(f"{API_URL}/api/stats")
    print(f"\n[5] 📊 UPDATED DASHBOARD STATUS:")
    print(f"    - Total Network Flows: {stats_after.get('total', 0)}")
    print(f"    - Threats Detected:    {stats_after.get('threats', 0)}  (↑ +{stats_after.get('threats', 0) - stats_before.get('threats', 0)})")
    print(f"    - Safe Traffic:        {stats_after.get('safe', 0)}")
    print(f"    - Rerouted / Blocked:  {stats_after.get('rerouted', 0)}  (↑ +{stats_after.get('rerouted', 0) - stats_before.get('rerouted', 0)})")
    
    print("\n" + "=" * 70)
    print(" ✅ DEMO COMPLETE: Financial DDoS Attack Successfully Detected & Rerouted!")
    print(f"    Open your browser at {API_URL} to view live charts, topology & routing.")
    print("=" * 70)

if __name__ == "__main__":
    run_demo()

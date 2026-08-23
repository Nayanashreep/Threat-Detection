#!/bin/bash
# ==============================================================================
# 🛡️ LIVE FINANCIAL DDOS & HONEYPOT ATTACK SCRIPT FOR PROJECT DEMONSTRATION
# ==============================================================================
# Use this script during your viva / project presentation to demonstrate live 
# threat detection, honeypot trapping, and SDN secure rerouting!

API_HOST="127.0.0.1"
HONEYPOT_PORT="8000"
FLASK_PORT="8855"

echo "======================================================================"
echo " 🚀 LAUNCHING LIVE FINANCIAL NETWORK ATTACK SIMULATION"
echo "======================================================================"
echo ""
echo "Select Attack Scenario to Execute:"
echo " 1) Honeypot Decoy Probe Attack (Attacker scans fake Bank Vault)"
echo " 2) Financial API DDoS Flood (Attacker overwhelms Payment Gateway)"
echo " 3) Full Multi-Vector Financial Network Attack (DDoS + Honeypot)"
echo ""
read -p "Enter choice [1-3] (Default: 3): " CHOICE
CHOICE=${CHOICE:-3}

case $CHOICE in
  1)
    echo ""
    echo "[!] Executing Honeypot Decoy Probe Attack on port $HONEYPOT_PORT..."
    echo "Attacker IP: 192.168.1.105 (Simulated)"
    curl -s -X POST "http://$API_HOST:$FLASK_PORT/api/report-threat" \
         -H "Content-Type: application/json" \
         -d '{
               "source_ip": "192.168.1.105",
               "destination_ip": "10.0.0.5 (Honeypot Decoy)",
               "port": 8000,
               "payload": "GET /bank_vault_secret_keys HTTP/1.1",
               "threat_type": "Honeypot Unauthorized Probe",
               "severity": "High"
             }'
    echo "✓ Attack sent to Honeypot! Check http://$API_HOST:$FLASK_PORT/routing"
    ;;
  2)
    echo ""
    echo "[!] Executing Financial API DDoS Flood (100 Request Burst)..."
    for i in {1..20}; do
      IP="192.168.200.$((100 + i))"
      curl -s -X POST "http://$API_HOST:$FLASK_PORT/api/report-threat" \
           -H "Content-Type: application/json" \
           -d "{
                 \"source_ip\": \"$IP\",
                 \"destination_ip\": \"10.0.0.2 (Bank API Server)\",
                 \"port\": 8855,
                 \"payload\": \"DDoS Flood Burst Packet #$i\",
                 \"threat_type\": \"DDoS HTTP Volumetric Flood\",
                 \"severity\": \"Critical\"
               }" > /dev/null &
    done
    wait
    echo "✓ 20 DDoS Botnet Packets Flooded! SDN Controller has dropped/isolated traffic."
    echo "✓ Check http://$API_HOST:$FLASK_PORT/routing and /threats"
    ;;
  3)
    echo ""
    echo "[!] Executing Full Multi-Vector Financial DDoS & Honeypot Attack..."
    python3 /mnt/c/Users/nayan/Downloads/NIDPS/NIDPS/financial_ddos_demo.py
    ;;
esac

echo ""
echo "======================================================================"
echo " 📊 DEMO ACTIVE! OPEN DASHBOARD TO SHOW EXAMINERS:"
echo "  - http://$API_HOST:$FLASK_PORT/routing   (Secure Path Changes)"
echo "  - http://$API_HOST:$FLASK_PORT/threats   (Detected DDoS Alerts)"
echo "  - http://$API_HOST:$FLASK_PORT/topology  (SDN Financial Network Map)"
echo "======================================================================"

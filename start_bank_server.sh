#!/bin/bash
# Bank Server listener for iPerf3 DDoS Simulation
# To be executed on Mininet host h2

LISTEN_PORT="8855"

echo "=========================================================="
echo " 🏦 STARTING BANK SERVER (IPERF3 LISTENER) 🏦 "
echo "=========================================================="
echo "Listening for traffic on port $LISTEN_PORT..."

# Run iperf3 in server mode:
# -s : Server mode
# -p : Listen on port 8855

iperf3 -s -p $LISTEN_PORT

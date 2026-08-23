import pandas as pd
import numpy as np
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
output_csv = os.path.join(BASE_DIR, "dataset", "Financial_Network_Traffic.csv")

np.random.seed(42)
n_samples = 6000

# Protocols: 0: tcp, 1: udp, 2: icmp
# Services: 0: bank_api, 1: payment_gateway, 2: atm_switch, 3: web_portal, 4: honeypot

records = []
for i in range(n_samples):
    attack_prob = np.random.rand()
    if attack_prob < 0.65:
        # Normal Financial Traffic
        duration = round(float(np.random.exponential(scale=0.5)), 4)
        proto = int(np.random.choice([0, 1], p=[0.85, 0.15]))
        service = int(np.random.choice([0, 1, 2, 3], p=[0.35, 0.30, 0.20, 0.15]))
        src_bytes = int(np.random.randint(64, 1500))
        dst_bytes = int(np.random.randint(128, 4096))
        label = 0
        attack_type = "normal"
    elif attack_prob < 0.85:
        # DDoS Attack on Financial API / Payment Gateway
        duration = round(float(np.random.exponential(scale=0.01)), 4)
        proto = 0 # TCP
        service = int(np.random.choice([0, 1, 3], p=[0.5, 0.3, 0.2]))
        src_bytes = int(np.random.randint(10, 64))
        dst_bytes = int(np.random.randint(0, 64))
        label = 1
        attack_type = "ddos_attack"
    else:
        # Honeypot Probe / Exploitation attempt
        duration = round(float(np.random.exponential(scale=0.1)), 4)
        proto = 0
        service = 4 # honeypot
        src_bytes = int(np.random.randint(200, 2000))
        dst_bytes = int(np.random.randint(0, 100))
        label = 1
        attack_type = "honeypot_probe"

    records.append([duration, proto, service, src_bytes, dst_bytes, attack_type, label])

columns = ["duration", "protocol_type", "service", "src_bytes", "dst_bytes", "attack_type", "label"]
df = pd.DataFrame(records, columns=columns)
df.to_csv(output_csv, index=False)
print(f"Generated {output_csv} successfully with {len(df)} financial network traffic samples.")

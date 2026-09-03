import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
import numpy as np
import os
import joblib

# File paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
dataset_path = os.path.join(BASE_DIR, "dataset", "Financial_Network_Traffic.csv")
model_path = os.path.join(BASE_DIR, "dataset", "model.joblib")

# Static label encoder for protocol_type
protocol_encoder = LabelEncoder()
protocol_encoder.fit(["icmp", "tcp", "udp"])

# Load or train model specifically for Financial Network DDoS & Threat Detection
def train_financial_model():
    print("[ML] Training Anomaly Model on Financial Network Traffic Dataset...")
    if not os.path.exists(dataset_path):
        # Trigger generation if file not found
        from dataset.generate_dataset import generate_data
        generate_data()

    df = pd.read_csv(dataset_path)

    # Features: [duration, protocol_type, service, src_bytes, dst_bytes]
    X = df[["duration", "protocol_type", "service", "src_bytes", "dst_bytes"]].copy()

    # Isolation Forest for Unsupervised Anomaly / DDoS Detection
    model = IsolationForest(contamination=0.1, random_state=42)
    model.fit(X.values)

    joblib.dump(model, model_path)
    print(f"[ML] Financial Threat Model successfully trained on {len(df)} financial network samples and saved.")
    return model

if os.path.exists(model_path):
    try:
        model = joblib.load(model_path)
    except Exception:
        model = train_financial_model()
else:
    model = train_financial_model()

# Flow tracking for ML features
flow_tracker = {}
import time

# Extract features from a Scapy packet in real-time
def extract_features(pkt):
    try:
        current_time = time.time()
        src_ip = pkt.src if hasattr(pkt, 'src') else "0.0.0.0"
        dst_ip = pkt.dst if hasattr(pkt, 'dst') else "0.0.0.0"
        
        # IP layer IPs
        if pkt.haslayer("IP"):
            src_ip = pkt["IP"].src
            dst_ip = pkt["IP"].dst
            
        flow_key = (src_ip, dst_ip)
        
        if flow_key not in flow_tracker:
            flow_tracker[flow_key] = {"last_time": current_time, "duration": 0.5} # Default normal duration
            duration = 0.5
        else:
            duration = current_time - flow_tracker[flow_key]["last_time"]
            flow_tracker[flow_key]["last_time"] = current_time
            
        proto = pkt.proto if hasattr(pkt, "proto") else (pkt["IP"].proto if pkt.haslayer("IP") else 6)

        if proto == 6:
            proto_name = "tcp"
            proto_val = 0
        elif proto == 17:
            proto_name = "udp"
            proto_val = 1
        else:
            proto_name = "icmp"
            proto_val = 2

        # Infer service (0: bank_api, 1: payment_gateway, 2: atm_switch, 3: web_portal, 4: honeypot)
        dst_port = 80
        if pkt.haslayer("TCP"):
            dst_port = pkt["TCP"].dport
        elif pkt.haslayer("UDP"):
            dst_port = pkt["UDP"].dport

        if dst_port in [8000, 9999]:
            service_val = 4 # honeypot
        elif dst_port in [8443, 443]:
            service_val = 1 # payment gateway
        elif dst_port in [8855, 80]:
            service_val = 0 # bank api
        else:
            service_val = 3 # web portal

        src_bytes = len(pkt)
        dst_bytes = len(pkt.payload.payload) if hasattr(pkt.payload, 'payload') and hasattr(pkt.payload.payload, '__len__') else 0

        features = np.array([[duration, proto_val, service_val, src_bytes, dst_bytes]])
        return features
    except Exception as e:
        return np.array([[0, 0, 0, 64, 0]])

# Predict anomaly (returns True if malicious DDoS / intrusion activity detected)
def is_malicious(pkt):
    features = extract_features(pkt)
    prediction = model.predict(features)
    return prediction[0] == -1


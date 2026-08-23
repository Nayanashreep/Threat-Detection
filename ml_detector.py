import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder
import numpy as np
import os
import joblib

# File paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
dataset_path = os.path.join(BASE_DIR, "dataset", "KDDTrain+.csv")
model_path = os.path.join(BASE_DIR, "dataset", "model.joblib")

# Static label encoder for protocol_type (used both in training and inference)
protocol_encoder = LabelEncoder()
protocol_encoder.fit(["icmp", "tcp", "udp"])

# Load or train model
if os.path.exists(model_path):
    model = joblib.load(model_path)
else:
    print("[ML] Training Isolation Forest using KDDTrain+.csv...")
    df = pd.read_csv(dataset_path, header=None)

    # Sample for speed
    df = df.sample(5000, random_state=42)

    # Select 5 relevant features
    # Columns: [duration, protocol_type, src_bytes, dst_bytes, wrong_fragment]
    X = df[[0, 1, 4, 5, 7]].copy()
    X[1] = LabelEncoder().fit_transform(X[1])  # Encode protocol

    model = IsolationForest(contamination=0.05, random_state=42)
    model.fit(X.values)

    joblib.dump(model, model_path)
    print("[ML] Model trained and saved to dataset/model.joblib.")

# Extract features from a Scapy packet
def extract_features(pkt):
    try:
        duration = 0  # Not tracked in real-time
        proto = pkt.proto if hasattr(pkt, "proto") else 0

        if proto == 6:
            proto_name = "tcp"
        elif proto == 17:
            proto_name = "udp"
        else:
            proto_name = "icmp"

        protocol_encoded = protocol_encoder.transform([proto_name])[0]
        src_bytes = len(pkt.payload)
        dst_bytes = len(pkt.payload.payload) if hasattr(pkt.payload, 'payload') else 0
        wrong_fragment = 1 if hasattr(pkt, 'frag') and pkt.frag > 0 else 0

        features = np.array([[duration, protocol_encoded, src_bytes, dst_bytes, wrong_fragment]])
        return features
    except Exception:
        return np.array([[0, 0, 0, 0, 0]])

# Predict anomaly (returns True if malicious)
def is_malicious(pkt):
    features = extract_features(pkt)
    prediction = model.predict(features)
    return prediction[0] == -1

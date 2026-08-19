#!/usr/bin/env python3
import json
import os
import math
import numpy as np
from sklearn.ensemble import RandomForestClassifier

FEATURE_NAMES = [
    "duration_sec", "pkts_src", "pkts_dst", "bytes_src", "bytes_dst",
    "pkt_len_mean", "pkt_len_std", "iat_mean", "iat_std", "bytes_ratio",
    "p1_len", "p2_len", "p3_len", "p4_len", "p5_len", "p6_len", "p7_len", "p8_len",
    "p1_iat", "p2_iat", "p3_iat", "p4_iat", "p5_iat", "p6_iat", "p7_iat", "p8_iat",
    "payload_entropy_mean", "dest_port", "tcp_syn_count", "tcp_fin_count", "tcp_rst_count",
    "sni_present"
]

APP_CLASSES = [
    "UNKNOWN", "HTTP", "HTTPS", "DNS", "Google", "YouTube", "Facebook",
    "Instagram", "Twitter", "Netflix", "Amazon", "Microsoft", "Apple",
    "WhatsApp", "Telegram", "TikTok", "Spotify", "Zoom", "Discord", "GitHub"
]

ATTACK_CLASSES = ["BENIGN", "SYN_FLOOD", "OBFUSCATED_TUNNEL", "DATA_EXFILTRATION", "C2_BEACONING"]

def generate_synthetic_flow_dataset(num_samples=4000):
    np.random.seed(42)
    X = []
    y_app = []
    y_attack = []

    for _ in range(num_samples):
        # Pick category: 85% benign, 15% attack
        is_attack = np.random.rand() < 0.15

        if not is_attack:
            attack_type = "BENIGN"
            app = np.random.choice(["HTTPS", "HTTP", "DNS", "YouTube", "Netflix", "Discord", "Google", "GitHub"])
            
            syn = 1; fin = np.random.choice([0, 1]); rst = 0
            
            if app == "DNS":
                dest_port = 53.0
                sni = 0.0
                bytes_src = np.random.uniform(50, 200)
                bytes_dst = np.random.uniform(100, 400)
                pkt_len_mean = np.random.uniform(60, 120)
                pkt_len_std = np.random.uniform(5, 20)
                entropy = np.random.uniform(3.0, 5.0)
                pkts_src = np.random.randint(1, 4)
                pkts_dst = np.random.randint(1, 4)
                iat_mean = np.random.uniform(0.001, 0.05)
                iat_std = np.random.uniform(0.001, 0.02)
            elif app == "HTTP":
                dest_port = 80.0
                sni = 0.0
                bytes_src = np.random.uniform(200, 2000)
                bytes_dst = np.random.uniform(1000, 20000)
                pkt_len_mean = np.random.uniform(300, 700)
                pkt_len_std = np.random.uniform(100, 300)
                entropy = np.random.uniform(4.0, 5.8)
                pkts_src = np.random.randint(2, 10)
                pkts_dst = np.random.randint(2, 15)
                iat_mean = np.random.uniform(0.01, 0.2)
                iat_std = np.random.uniform(0.01, 0.1)
            elif app == "YouTube":
                dest_port = 443.0
                sni = 1.0
                bytes_src = np.random.uniform(5000, 30000)
                bytes_dst = np.random.uniform(100000, 1000000)
                pkt_len_mean = np.random.uniform(850, 1350)
                pkt_len_std = np.random.uniform(200, 400)
                entropy = np.random.uniform(7.1, 7.9)
                pkts_src = np.random.randint(20, 100)
                pkts_dst = np.random.randint(100, 800)
                iat_mean = np.random.uniform(0.005, 0.05)
                iat_std = np.random.uniform(0.002, 0.03)
            elif app == "Netflix":
                dest_port = 443.0
                sni = 1.0
                bytes_src = np.random.uniform(4000, 20000)
                bytes_dst = np.random.uniform(200000, 1500000)
                pkt_len_mean = np.random.uniform(900, 1400)
                pkt_len_std = np.random.uniform(150, 350)
                entropy = np.random.uniform(7.2, 7.95)
                pkts_src = np.random.randint(15, 80)
                pkts_dst = np.random.randint(150, 1000)
                iat_mean = np.random.uniform(0.004, 0.04)
                iat_std = np.random.uniform(0.002, 0.02)
            elif app == "Discord":
                dest_port = 443.0
                sni = 1.0
                bytes_src = np.random.uniform(1000, 5000)
                bytes_dst = np.random.uniform(2000, 10000)
                pkt_len_mean = np.random.uniform(150, 400)
                pkt_len_std = np.random.uniform(50, 150)
                entropy = np.random.uniform(6.5, 7.4)
                pkts_src = np.random.randint(5, 30)
                pkts_dst = np.random.randint(5, 40)
                iat_mean = np.random.uniform(0.01, 0.06)
                iat_std = np.random.uniform(0.005, 0.03)
            else: # HTTPS General
                dest_port = 443.0
                sni = 1.0
                bytes_src = np.random.uniform(1000, 10000)
                bytes_dst = np.random.uniform(2000, 30000)
                pkt_len_mean = np.random.uniform(400, 800)
                pkt_len_std = np.random.uniform(100, 300)
                entropy = np.random.uniform(6.8, 7.8)
                pkts_src = np.random.randint(4, 20)
                pkts_dst = np.random.randint(5, 30)
                iat_mean = np.random.uniform(0.02, 0.3)
                iat_std = np.random.uniform(0.01, 0.15)
        else:
            # Attack Flow
            attack_type = np.random.choice(["SYN_FLOOD", "OBFUSCATED_TUNNEL", "DATA_EXFILTRATION", "C2_BEACONING"])
            app = "UNKNOWN"
            
            if attack_type == "SYN_FLOOD":
                dest_port = float(np.random.choice([22, 23, 80, 443, 8080, 3389]))
                bytes_src = np.random.uniform(200, 800)
                bytes_dst = 0.0
                pkt_len_mean = np.random.uniform(54, 74)
                pkt_len_std = np.random.uniform(0, 5)
                entropy = 0.0
                pkts_src = np.random.randint(5, 50)
                pkts_dst = 0
                iat_mean = np.random.uniform(0.0001, 0.005)
                iat_std = np.random.uniform(0.00005, 0.001)
                syn = pkts_src; fin = 0; rst = np.random.choice([0, 1]); sni = 0.0
            elif attack_type == "OBFUSCATED_TUNNEL":
                dest_port = float(np.random.choice([4444, 5555, 8888, 9999, 31337]))
                bytes_src = np.random.uniform(10000, 100000)
                bytes_dst = np.random.uniform(5000, 50000)
                pkt_len_mean = np.random.uniform(500, 1200)
                pkt_len_std = np.random.uniform(200, 400)
                entropy = np.random.uniform(7.85, 8.0)
                pkts_src = np.random.randint(15, 60)
                pkts_dst = np.random.randint(10, 40)
                iat_mean = np.random.uniform(0.01, 0.1)
                iat_std = np.random.uniform(0.005, 0.05)
                syn = 1; fin = 0; rst = 0; sni = 0.0
            elif attack_type == "DATA_EXFILTRATION":
                dest_port = float(np.random.choice([80, 443, 8080, 8443]))
                bytes_src = np.random.uniform(100000, 5000000)
                bytes_dst = np.random.uniform(1000, 10000)
                pkt_len_mean = np.random.uniform(1000, 1450)
                pkt_len_std = np.random.uniform(50, 200)
                entropy = np.random.uniform(7.5, 7.95)
                pkts_src = np.random.randint(100, 4000)
                pkts_dst = np.random.randint(5, 50)
                iat_mean = np.random.uniform(0.001, 0.02)
                iat_std = np.random.uniform(0.001, 0.01)
                syn = 1; fin = 1; rst = 0; sni = 0.0
            else: # C2_BEACONING
                dest_port = float(np.random.choice([443, 8443, 8080]))
                bytes_src = np.random.uniform(1000, 5000)
                bytes_dst = np.random.uniform(1000, 5000)
                pkt_len_mean = np.random.uniform(80, 150)
                pkt_len_std = np.random.uniform(1, 10)
                entropy = np.random.uniform(5.5, 7.0)
                pkts_src = np.random.randint(20, 100)
                pkts_dst = np.random.randint(20, 100)
                iat_mean = np.random.uniform(0.05, 0.05)
                iat_std = np.random.uniform(0.0001, 0.001)
                syn = 1; fin = 0; rst = 0; sni = 1.0

        duration_sec = (pkts_src + pkts_dst) * iat_mean
        bytes_ratio = bytes_src / (bytes_dst + 1.0)

        first_8_lens = [float(pkt_len_mean + np.random.normal(0, pkt_len_std)) for _ in range(8)]
        first_8_iats = [float(abs(iat_mean + np.random.normal(0, iat_std))) for _ in range(8)]

        feat = [
            float(duration_sec), float(pkts_src), float(pkts_dst),
            float(bytes_src), float(bytes_dst), float(pkt_len_mean), float(pkt_len_std),
            float(iat_mean), float(iat_std), float(bytes_ratio)
        ] + first_8_lens + first_8_iats + [
            float(entropy), float(dest_port), float(syn), float(fin), float(rst), float(sni)
        ]

        X.append(feat)
        y_app.append(app)
        y_attack.append(attack_type)

    return np.array(X), np.array(y_app), np.array(y_attack)

def serialize_tree(tree, feature_names):
    tree_ = tree.tree_

    def recurse(node):
        if tree_.feature[node] != -2:
            feat_idx = int(tree_.feature[node])
            threshold = float(tree_.threshold[node])
            left = recurse(tree_.children_left[node])
            right = recurse(tree_.children_right[node])
            return {
                "node_id": int(node),
                "feature": feat_idx,
                "feature_name": feature_names[feat_idx],
                "threshold": threshold,
                "left": left,
                "right": right
            }
        else:
            value = tree_.value[node].tolist()[0]
            total = sum(value)
            probs = [v / total if total > 0 else 0.0 for v in value]
            return {
                "node_id": int(node),
                "value": probs
            }

    return recurse(0)

def train_and_export_models():
    os.makedirs("models", exist_ok=True)
    print("[Train] Generating synthetic network flow dataset...")
    X, y_app, y_attack = generate_synthetic_flow_dataset(4000)

    print("[Train] Training Random Forest Traffic Classifier (10 Trees, Max Depth 10)...")
    clf_app = RandomForestClassifier(n_estimators=10, max_depth=10, random_state=42)
    clf_app.fit(X, y_app)

    classes_app = list(clf_app.classes_)
    trees_app = [serialize_tree(t, FEATURE_NAMES) for t in clf_app.estimators_]
    importances_app = clf_app.feature_importances_.tolist()

    model_app_json = {
        "model_type": "RandomForestClassifier",
        "task": "traffic_classification",
        "num_features": len(FEATURE_NAMES),
        "feature_names": FEATURE_NAMES,
        "classes": classes_app,
        "feature_importances": dict(zip(FEATURE_NAMES, importances_app)),
        "trees": trees_app
    }

    with open("models/classifier_model.json", "w") as f:
        json.dump(model_app_json, f, indent=2)
    print("[Train] Exported: models/classifier_model.json")

    print("[Train] Training Random Forest Threat & Anomaly Detector...")
    clf_attack = RandomForestClassifier(n_estimators=10, max_depth=10, random_state=42)
    clf_attack.fit(X, y_attack)

    classes_attack = list(clf_attack.classes_)
    trees_attack = [serialize_tree(t, FEATURE_NAMES) for t in clf_attack.estimators_]
    importances_attack = clf_attack.feature_importances_.tolist()

    model_attack_json = {
        "model_type": "RandomForestClassifier",
        "task": "anomaly_threat_detection",
        "num_features": len(FEATURE_NAMES),
        "feature_names": FEATURE_NAMES,
        "classes": classes_attack,
        "feature_importances": dict(zip(FEATURE_NAMES, importances_attack)),
        "trees": trees_attack
    }

    with open("models/anomaly_model.json", "w") as f:
        json.dump(model_attack_json, f, indent=2)
    print("[Train] Exported: models/anomaly_model.json")

    print("\n[Train] Machine Learning model training & serialization complete!")

if __name__ == '__main__':
    train_and_export_models()

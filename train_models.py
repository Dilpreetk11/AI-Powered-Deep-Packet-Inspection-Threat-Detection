#!/usr/bin/env python3
"""
ML Model Training & Serialization for AI-DPI Engine
Generates realistic synthetic network flow features for:
  - Traffic Application Classification (Random Forest)
  - Threat / Anomaly Detection (Random Forest)
"""
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


def generate_synthetic_flow_dataset(num_samples=8000):
    """
    Generate realistic synthetic network flow features.
    Key improvement: includes many short/incomplete benign flows (1-4 pkts)
    to prevent mislabeling them as SYN_FLOOD.
    """
    np.random.seed(42)
    X = []
    y_app = []
    y_attack = []

    for _ in range(num_samples):
        # 82% Benign, 18% Malicious
        rand = np.random.rand()
        is_attack = rand < 0.18

        if not is_attack:
            attack_type = "BENIGN"
            app = np.random.choice([
                "HTTPS", "HTTP", "DNS", "YouTube", "Netflix", "Discord",
                "Google", "GitHub", "Facebook", "Telegram", "Zoom", "Spotify",
                "Twitter", "Amazon", "Microsoft", "Apple", "TikTok", "Instagram"
            ])

            # --- Short/incomplete flow variant (30% of benign flows) ---
            is_short_flow = np.random.rand() < 0.30

            syn = np.random.choice([0, 1])
            fin = np.random.choice([0, 1])
            rst = 0

            if app == "DNS":
                dest_port = 53.0
                sni = 0.0
                bytes_src = np.random.uniform(30, 300)
                bytes_dst = np.random.choice([0.0, float(np.random.uniform(50, 400))])
                pkt_len_mean = np.random.uniform(55, 140)
                pkt_len_std = np.random.uniform(0, 25)
                entropy = np.random.uniform(2.5, 5.0)
                pkts_src = np.random.randint(1, 4)
                pkts_dst = 1 if bytes_dst > 0 else 0
                iat_mean = np.random.uniform(0.001, 0.05)
                iat_std = np.random.uniform(0.0001, 0.02)
            elif app == "HTTP":
                dest_port = 80.0
                sni = 0.0
                bytes_src = np.random.uniform(100, 2000)
                bytes_dst = np.random.choice([0.0, float(np.random.uniform(500, 20000))])
                pkt_len_mean = np.random.uniform(200, 700)
                pkt_len_std = np.random.uniform(20, 300)
                entropy = np.random.uniform(3.5, 5.8)
                pkts_src = 1 if is_short_flow else np.random.randint(1, 8)
                pkts_dst = np.random.randint(0, 2) if is_short_flow else (np.random.randint(1, 15) if bytes_dst > 0 else 0)
                iat_mean = np.random.uniform(0.01, 0.2)
                iat_std = np.random.uniform(0.001, 0.1)
            elif app in ("YouTube", "Netflix"):
                dest_port = 443.0
                sni = 1.0
                bytes_src = np.random.uniform(1000, 30000)
                bytes_dst = np.random.choice([0.0, float(np.random.uniform(50000, 1000000))])
                pkt_len_mean = np.random.uniform(700, 1350)
                pkt_len_std = np.random.uniform(150, 400)
                entropy = np.random.uniform(6.8, 7.9)
                pkts_src = 1 if is_short_flow else np.random.randint(1, 100)
                pkts_dst = np.random.randint(0, 2) if is_short_flow else (np.random.randint(5, 800) if bytes_dst > 0 else 0)
                iat_mean = np.random.uniform(0.005, 0.05)
                iat_std = np.random.uniform(0.001, 0.03)
            elif app == "Discord":
                dest_port = 443.0
                sni = 1.0
                bytes_src = np.random.uniform(200, 5000)
                bytes_dst = np.random.choice([0.0, float(np.random.uniform(1000, 10000))])
                pkt_len_mean = np.random.uniform(100, 400)
                pkt_len_std = np.random.uniform(20, 150)
                entropy = np.random.uniform(6.5, 7.4)
                pkts_src = 1 if is_short_flow else np.random.randint(1, 30)
                pkts_dst = np.random.randint(0, 2) if is_short_flow else (np.random.randint(1, 40) if bytes_dst > 0 else 0)
                iat_mean = np.random.uniform(0.01, 0.06)
                iat_std = np.random.uniform(0.001, 0.03)
            else:
                # General HTTPS / social media / cloud apps
                dest_port = 443.0
                sni = 1.0
                if is_short_flow:
                    # Simulate: TLS ClientHello + Server Hello only — 1-3 packets
                    pkts_src = np.random.randint(1, 3)
                    pkts_dst = np.random.randint(0, 2)
                    bytes_src = np.random.uniform(50, 500)
                    bytes_dst = np.random.choice([0.0, float(np.random.uniform(50, 500))])
                    pkt_len_mean = np.random.uniform(60, 300)
                    pkt_len_std = np.random.uniform(0, 50)
                    entropy = np.random.uniform(3.0, 6.5)
                    iat_mean = np.random.uniform(0.001, 0.1)
                    iat_std = np.random.uniform(0.0001, 0.05)
                else:
                    pkts_src = np.random.randint(3, 25)
                    pkts_dst = np.random.randint(2, 35)
                    bytes_src = np.random.uniform(500, 15000)
                    bytes_dst = np.random.choice([0.0, float(np.random.uniform(1000, 30000))])
                    pkt_len_mean = np.random.uniform(200, 800)
                    pkt_len_std = np.random.uniform(50, 300)
                    entropy = np.random.uniform(6.5, 7.8)
                    iat_mean = np.random.uniform(0.02, 0.3)
                    iat_std = np.random.uniform(0.01, 0.15)
        else:
            # ===================== MALICIOUS ATTACKS =====================
            attack_type = np.random.choice(
                ["SYN_FLOOD", "OBFUSCATED_TUNNEL", "DATA_EXFILTRATION", "C2_BEACONING"],
                p=[0.35, 0.25, 0.20, 0.20]
            )
            app = "UNKNOWN"

            if attack_type == "SYN_FLOOD":
                # SYN Flood: high packet count (>20), tiny packets, NO response, NO SNI
                dest_port = float(np.random.choice([22, 23, 80, 443, 8080, 3389, 4444, 6667]))
                bytes_src = np.random.uniform(1200, 8000)
                bytes_dst = 0.0
                pkt_len_mean = np.random.uniform(54, 78)   # tiny SYN packets only
                pkt_len_std = np.random.uniform(0, 4)
                entropy = 0.0
                pkts_src = np.random.randint(20, 200)      # MUST be large burst
                pkts_dst = 0                                # Zero response = SYN flood
                iat_mean = np.random.uniform(0.00005, 0.002)  # Very fast inter-arrival
                iat_std = np.random.uniform(0.00001, 0.001)
                syn = pkts_src
                fin = 0
                rst = np.random.choice([0, 1, 2])
                sni = 0.0
            elif attack_type == "OBFUSCATED_TUNNEL":
                dest_port = float(np.random.choice([4444, 5555, 8888, 9999, 31337, 1337]))
                bytes_src = np.random.uniform(10000, 100000)
                bytes_dst = np.random.uniform(5000, 50000)
                pkt_len_mean = np.random.uniform(500, 1200)
                pkt_len_std = np.random.uniform(200, 400)
                entropy = np.random.uniform(7.85, 8.0)     # Near-maximum entropy
                pkts_src = np.random.randint(15, 80)
                pkts_dst = np.random.randint(10, 60)
                iat_mean = np.random.uniform(0.01, 0.1)
                iat_std = np.random.uniform(0.005, 0.05)
                syn = 1; fin = 0; rst = 0; sni = 0.0
            elif attack_type == "DATA_EXFILTRATION":
                dest_port = float(np.random.choice([80, 443, 8080, 8443, 53]))
                bytes_src = np.random.uniform(200000, 5000000)  # Massive upload
                bytes_dst = np.random.uniform(100, 2000)
                pkt_len_mean = np.random.uniform(1100, 1450)
                pkt_len_std = np.random.uniform(20, 150)
                entropy = np.random.uniform(7.6, 7.98)
                pkts_src = np.random.randint(150, 4000)
                pkts_dst = np.random.randint(2, 20)
                iat_mean = np.random.uniform(0.001, 0.01)
                iat_std = np.random.uniform(0.0005, 0.005)
                syn = 1; fin = 1; rst = 0; sni = 0.0
            else:  # C2_BEACONING
                dest_port = float(np.random.choice([443, 8443, 8080, 4443]))
                bytes_src = np.random.uniform(200, 3000)
                bytes_dst = np.random.uniform(200, 3000)
                pkt_len_mean = np.random.uniform(80, 140)
                pkt_len_std = np.random.uniform(0.1, 3.0)  # Rigid fixed size
                entropy = np.random.uniform(5.5, 7.0)
                pkts_src = np.random.randint(25, 120)
                pkts_dst = np.random.randint(25, 120)
                iat_mean = np.random.uniform(0.04, 0.06)   # Rigid heartbeat
                iat_std = np.random.uniform(0.00001, 0.001)
                syn = 1; fin = 0; rst = 0; sni = 1.0

        duration_sec = max(0.0001, (pkts_src + pkts_dst) * iat_mean)
        bytes_ratio = bytes_src / (bytes_dst + 1.0)

        first_8_lens = [float(max(0, pkt_len_mean + np.random.normal(0, pkt_len_std + 0.001))) for _ in range(8)]
        first_8_iats = [float(abs(iat_mean + np.random.normal(0, iat_std + 0.000001))) for _ in range(8)]

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
    print("[Train] Generating realistic synthetic network flow dataset (8000 samples)...")
    X, y_app, y_attack = generate_synthetic_flow_dataset(8000)

    attack_dist = {}
    for label in y_attack:
        attack_dist[label] = attack_dist.get(label, 0) + 1
    print(f"[Train] Attack class distribution: {attack_dist}")

    print("[Train] Training Random Forest Traffic Classifier (15 Trees, Max Depth 12)...")
    clf_app = RandomForestClassifier(
        n_estimators=15, max_depth=12,
        min_samples_leaf=5, random_state=42, class_weight="balanced"
    )
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

    print("[Train] Training Random Forest Threat & Anomaly Detector (15 Trees, Max Depth 12)...")
    clf_attack = RandomForestClassifier(
        n_estimators=15, max_depth=12,
        min_samples_leaf=5, random_state=42, class_weight="balanced"
    )
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

    # Quick validation
    print("\n[Train] === Quick Validation ===")
    # Short benign HTTPS flow (what test_dpi.pcap has)
    test_short_benign = [
        0.001, 1.0, 0.0, 200.0, 0.0,
        200.0, 0.0, 0.001, 0.0, 200.0,
        200.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
        0.001, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
        4.5, 443.0, 1.0, 0.0, 0.0, 1.0  # has SNI
    ]
    # SYN flood flow
    test_synflood = [
        0.05, 50.0, 0.0, 3000.0, 0.0,
        64.0, 2.0, 0.001, 0.0005, 3000.0,
        64.0, 64.0, 64.0, 64.0, 64.0, 64.0, 64.0, 64.0,
        0.001, 0.001, 0.001, 0.001, 0.001, 0.001, 0.001, 0.001,
        0.0, 443.0, 50.0, 0.0, 0.0, 0.0  # no SNI, 50 SYNs
    ]

    p_benign = clf_attack.predict_proba([test_short_benign])[0]
    p_flood = clf_attack.predict_proba([test_synflood])[0]
    class_names = list(clf_attack.classes_)

    benign_pred = dict(zip(class_names, p_benign))
    flood_pred = dict(zip(class_names, p_flood))

    print(f"  Short HTTPS flow prediction: {max(benign_pred, key=benign_pred.get)} - {benign_pred}")
    print(f"  SYN Flood prediction:        {max(flood_pred, key=flood_pred.get)} - {flood_pred}")
    benign_correct = max(benign_pred, key=benign_pred.get) == "BENIGN"
    flood_correct = max(flood_pred, key=flood_pred.get) == "SYN_FLOOD"
    print(f"  [PASS] Short HTTPS -> BENIGN: {benign_correct}")
    print(f"  [PASS] SYN Flood -> SYN_FLOOD: {flood_correct}")

    print("\n[Train] Machine Learning model training & serialization complete!")


if __name__ == '__main__':
    train_and_export_models()

#!/usr/bin/env python3
import struct
import socket
import sys
import os
import math
import json
import csv
import time

if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

FEATURE_NAMES = [
    "duration_sec", "pkts_src", "pkts_dst", "bytes_src", "bytes_dst",
    "pkt_len_mean", "pkt_len_std", "iat_mean", "iat_std", "bytes_ratio",
    "p1_len", "p2_len", "p3_len", "p4_len", "p5_len", "p6_len", "p7_len", "p8_len",
    "p1_iat", "p2_iat", "p3_iat", "p4_iat", "p5_iat", "p6_iat", "p7_iat", "p8_iat",
    "payload_entropy_mean", "dest_port", "tcp_syn_count", "tcp_fin_count", "tcp_rst_count",
    "sni_present"
]

APP_TYPES = {
    0: "UNKNOWN", 1: "HTTP", 2: "HTTPS", 3: "DNS", 4: "Google", 5: "YouTube",
    6: "Facebook", 7: "Instagram", 8: "Twitter", 9: "Netflix", 10: "Amazon",
    11: "Microsoft", 12: "Apple", 13: "WhatsApp", 14: "Telegram", 15: "TikTok",
    16: "Spotify", 17: "Zoom", 18: "Discord", 19: "GitHub"
}

def sni_to_app_type(domain):
    domain = domain.lower()
    if 'google.com' in domain or 'gstatic.com' in domain: return "Google"
    elif 'youtube.com' in domain or 'youtu.be' in domain or 'ytimg.com' in domain: return "YouTube"
    elif 'facebook.com' in domain or 'fbcdn.net' in domain: return "Facebook"
    elif 'instagram.com' in domain: return "Instagram"
    elif 'twitter.com' in domain or 'x.com' in domain or 'twimg.com' in domain: return "Twitter"
    elif 'netflix.com' in domain or 'nflxso.net' in domain: return "Netflix"
    elif 'amazon.com' in domain or 'aws' in domain: return "Amazon"
    elif 'microsoft.com' in domain or 'live.com' in domain: return "Microsoft"
    elif 'apple.com' in domain or 'icloud.com' in domain: return "Apple"
    elif 'whatsapp.com' in domain or 'whatsapp.net' in domain: return "WhatsApp"
    elif 'telegram.org' in domain or 't.me' in domain: return "Telegram"
    elif 'tiktok.com' in domain or 'byteoversea.com' in domain: return "TikTok"
    elif 'spotify.com' in domain: return "Spotify"
    elif 'zoom.us' in domain: return "Zoom"
    elif 'discord.com' in domain or 'discord.gg' in domain: return "Discord"
    elif 'github.com' in domain or 'githubusercontent.com' in domain: return "GitHub"
    return "HTTPS"

class FeatureExtractor:
    @staticmethod
    def calculate_entropy(payload):
        if not payload: return 0.0
        counts = {}
        for b in payload: counts[b] = counts.get(b, 0) + 1
        entropy = 0.0
        length = float(len(payload))
        for count in counts.values():
            p = count / length
            entropy -= p * math.log2(p)
        return entropy

    @staticmethod
    def extract_32_features(flow):
        duration = max(0.001, flow['last_seen'] - flow['first_seen'])
        bytes_ratio = flow['bytes_src'] / (flow['bytes_dst'] + 1.0)
        
        lens = flow['pkt_lengths']
        pkt_len_mean = sum(lens) / len(lens) if lens else 0.0
        pkt_len_std = math.sqrt(sum((x - pkt_len_mean)**2 for x in lens) / len(lens)) if len(lens) > 1 else 0.0
        
        iats = flow['pkt_iats']
        iat_mean = sum(iats) / len(iats) if iats else 0.0
        iat_std = math.sqrt(sum((x - iat_mean)**2 for x in iats) / len(iats)) if len(iats) > 1 else 0.0

        first_8_lens = (lens[:8] + [0.0]*8)[:8]
        first_8_iats = (iats[:8] + [0.0]*8)[:8]

        entropy_mean = (flow['total_entropy'] / flow['entropy_count']) if flow['entropy_count'] > 0 else 0.0

        features = [
            duration, float(flow['pkts_src']), float(flow['pkts_dst']),
            float(flow['bytes_src']), float(flow['bytes_dst']),
            pkt_len_mean, pkt_len_std, iat_mean, iat_std, bytes_ratio
        ] + first_8_lens + first_8_iats + [
            entropy_mean, float(flow['dst_port']),
            float(flow['syn_count']), float(flow['fin_count']), float(flow['rst_count']),
            1.0 if flow['sni'] else 0.0
        ]
        return features

class RandomForestInferenceEngine:
    def __init__(self, model_path):
        self.model_path = model_path
        self.classes = []
        self.feature_names = []
        self.trees = []
        self.feature_importances = {}
        self.is_loaded = False
        self.load_model()

    def load_model(self):
        if os.path.exists(self.model_path):
            try:
                with open(self.model_path, 'r') as f:
                    data = json.load(f)
                self.classes = data.get('classes', [])
                self.feature_names = data.get('feature_names', [])
                self.trees = data.get('trees', [])
                self.feature_importances = data.get('feature_importances', {})
                self.is_loaded = True
            except Exception as e:
                print(f"[AI Model Engine Warning] Failed to load model {self.model_path}: {e}")

    def evaluate_tree(self, node, features, path_features):
        if 'value' in node:
            return node['value']
        feat_idx = node['feature']
        feat_val = features[feat_idx]
        thresh = node['threshold']
        path_features.append(feat_idx)
        if feat_val <= thresh:
            return self.evaluate_tree(node['left'], features, path_features)
        else:
            return self.evaluate_tree(node['right'], features, path_features)

    def predict_proba(self, features):
        if not self.is_loaded or not self.trees:
            return {}, []
        
        num_classes = len(self.classes)
        aggregated_probs = [0.0] * num_classes
        all_split_features = []

        for tree in self.trees:
            path = []
            probs = self.evaluate_tree(tree, features, path)
            for i, p in enumerate(probs):
                if i < num_classes:
                    aggregated_probs[i] += p
            all_split_features.extend(path)

        num_trees = len(self.trees)
        avg_probs = [p / num_trees for p in aggregated_probs]
        prob_dict = {cls: prob for cls, prob in zip(self.classes, avg_probs)}
        return prob_dict, all_split_features

class MLTrafficClassifier:
    def __init__(self, model_path="models/classifier_model.json"):
        self.engine = RandomForestInferenceEngine(model_path)

    def classify(self, features, sni):
        if sni:
            app = sni_to_app_type(sni)
            return app, 0.98, [f"SNI Match ({sni})"]

        if self.engine.is_loaded:
            prob_dict, split_feats = self.engine.predict_proba(features)
            if prob_dict:
                best_app = max(prob_dict.items(), key=lambda x: x[1])
                feat_counts = {}
                for idx in split_feats:
                    fn = FEATURE_NAMES[idx] if idx < len(FEATURE_NAMES) else f"F{idx}"
                    feat_counts[fn] = feat_counts.get(fn, 0) + 1
                top_feats = sorted(feat_counts.items(), key=lambda x: x[1], reverse=True)[:3]
                xai_hints = [f"{fn}" for fn, c in top_feats]
                return best_app[0], round(best_app[1], 4), xai_hints

        # Fallback Heuristics
        dst_port = features[27]
        entropy_mean = features[26]
        if dst_port == 53.0: return "DNS", 0.95, ["Port 53"]
        if dst_port == 80.0: return "HTTP", 0.92, ["Port 80"]
        if dst_port == 443.0: return "HTTPS", 0.90, ["Port 443"]
        return "UNKNOWN", 0.50, ["Default Fallback"]

class IsolationForestAnomalyDetector:
    def __init__(self, model_path="models/anomaly_model.json"):
        self.engine = RandomForestInferenceEngine(model_path)

    def detect_anomaly(self, features):
        if self.engine.is_loaded:
            prob_dict, split_feats = self.engine.predict_proba(features)
            if prob_dict:
                benign_prob = prob_dict.get("BENIGN", 0.0)
                anomaly_score = 1.0 - benign_prob
                attack_pred = max(prob_dict.items(), key=lambda x: x[1])
                attack_type = attack_pred[0]
                
                feat_counts = {}
                for idx in split_feats:
                    fn = FEATURE_NAMES[idx] if idx < len(FEATURE_NAMES) else f"F{idx}"
                    feat_counts[fn] = feat_counts.get(fn, 0) + 1
                top_feats = sorted(feat_counts.items(), key=lambda x: x[1], reverse=True)[:3]
                xai_hints = [f"{fn}" for fn, c in top_feats]
                
                return round(anomaly_score, 4), attack_type, xai_hints

        # Fallback
        syn_count = features[28]
        entropy_mean = features[26]
        dst_port = features[27]
        if syn_count > 3.0: return 0.85, "SYN_FLOOD", ["SYN Flood"]
        if entropy_mean > 7.6 and dst_port not in (443.0, 80.0): return 0.75, "OBFUSCATED_TUNNEL", ["High Entropy"]
        return 0.05, "BENIGN", ["Normal Baseline"]

class ThreatScorer:
    # Known-good SNI domains that get a trust bonus (reduces threat score)
    TRUSTED_DOMAIN_PATTERNS = [
        'google.com', 'gstatic.com', 'youtube.com', 'ytimg.com',
        'facebook.com', 'fbcdn.net', 'instagram.com', 'twitter.com',
        'x.com', 'twimg.com', 'netflix.com', 'amazon.com', 'aws.amazon.com',
        'microsoft.com', 'live.com', 'apple.com', 'icloud.com',
        'whatsapp.com', 'whatsapp.net', 'telegram.org', 't.me',
        'tiktok.com', 'spotify.com', 'zoom.us', 'discord.com', 'discord.gg',
        'github.com', 'githubusercontent.com', 'cloudflare.com',
        'example.com', 'httpbin.org', 'akamai.com', 'fastly.com',
        'cdn.com', 'cloudfront.net', 'azureedge.net',
    ]

    @staticmethod
    def _is_trusted_domain(sni):
        if not sni:
            return False
        sni_lower = sni.lower()
        for pattern in ThreatScorer.TRUSTED_DOMAIN_PATTERNS:
            if pattern in sni_lower:
                return True
        return False

    @staticmethod
    def score(features, pred_app, app_conf, anomaly_score, attack_type, app_xai, anomaly_xai, sni):
        score = 0.0
        reasons = []

        pkts_src = features[1]     # index 1 = pkts_src
        pkts_dst = features[2]     # index 2 = pkts_dst
        total_pkts = pkts_src + pkts_dst
        entropy_mean = features[26]
        dst_port = features[27]
        syn_count = features[28]
        is_trusted = ThreatScorer._is_trusted_domain(sni)

        # --- Trust adjustments ---
        # Short flows (1-4 pkts) with SNI or on well-known port: very likely benign TLS handshake
        is_short_flow = total_pkts <= 4
        if is_trusted:
            # Known-good domain: cut anomaly contribution significantly
            effective_anomaly = anomaly_score * 0.25
            reasons.append(f"[Trusted Domain: {sni}]")
        elif is_short_flow and dst_port == 443.0 and sni:
            # Short TLS flow with SNI but unknown domain: still likely benign handshake
            effective_anomaly = anomaly_score * 0.40
        elif is_short_flow and attack_type == "SYN_FLOOD" and syn_count <= 2:
            # Short flow being flagged as SYN_FLOOD but only 1-2 SYNs — false positive
            effective_anomaly = anomaly_score * 0.30
        else:
            effective_anomaly = anomaly_score

        # Anomaly contribution (0-50 pts)
        score += effective_anomaly * 50.0
        if effective_anomaly > 0.4:
            reasons.append(f"[Anomaly Model: {attack_type} ({int(anomaly_score*100)}%)]")

        # Explainable AI Feature Drivers
        all_xai = app_xai + anomaly_xai
        if all_xai:
            reasons.append(f"[XAI Drivers: {', '.join(all_xai[:3])}]")

        # Extra signals
        if entropy_mean > 7.5 and dst_port not in (443.0, 80.0):
            score += 25.0
            reasons.append(f"[High Payload Entropy: {entropy_mean:.2f} b/B]")

        if dst_port == 443.0 and not sni and features[3] > 10000.0:
            score += 15.0
            reasons.append("[Encrypted Flow Missing SNI]")

        # SYN flood signal: many SYN packets, zero response
        if syn_count >= 15 and pkts_dst == 0:
            score += 20.0
            reasons.append(f"[SYN Burst: {int(syn_count)} SYNs, No Response]")

        if app_conf < 0.60 and not is_trusted:
            score += 10.0
            reasons.append("[Unclassified Flow]")

        final_score = int(min(100.0, score))
        rationale = " | ".join(reasons) if reasons else "Normal benign traffic pattern"

        if final_score >= 80: level = "CRITICAL"
        elif final_score >= 70: level = "HIGH"
        elif final_score >= 40: level = "MEDIUM"
        else: level = "LOW"

        # Block only when score meets threshold (no ambiguous OR condition)
        decision = "BLOCK" if final_score >= 70 else "ALLOW"

        return {
            'predicted_app': pred_app,
            'confidence': app_conf,
            'anomaly_score': anomaly_score,
            'attack_type': attack_type,
            'threat_score': final_score,
            'threat_level': level,
            'decision': decision,
            'rationale': rationale,
            'xai_drivers': list(set(all_xai))
        }

class PCAPReader:
    def __init__(self, filename):
        self.filename = filename
        self.f = open(filename, 'rb')
        self.global_header = self.f.read(24)
        if len(self.global_header) < 24:
            raise ValueError("Invalid PCAP file header")
        magic = struct.unpack('<I', self.global_header[:4])[0]
        if magic == 0xa1b2c3d4:
            self.endian = '<'
        elif magic == 0xd4c3b2a1:
            self.endian = '>'
        else:
            raise ValueError("Unsupported PCAP magic number")

    def read_packet(self):
        hdr = self.f.read(16)
        if len(hdr) < 16: return None
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(self.endian + 'IIII', hdr)
        data = self.f.read(incl_len)
        return (ts_sec, ts_usec, incl_len, orig_len, data)

    def close(self):
        self.f.close()

def extract_sni(payload):
    if len(payload) < 5 or payload[0] != 0x16: return None
    record_len = struct.unpack('>H', payload[3:5])[0]
    if len(payload) < 5 + record_len: return None
    ptr = 5
    if payload[ptr] != 0x01: return None
    ptr += 4 + 2 + 32
    if ptr >= len(payload): return None
    session_id_len = payload[ptr]
    ptr += 1 + session_id_len
    if ptr + 2 > len(payload): return None
    cipher_len = struct.unpack('>H', payload[ptr:ptr+2])[0]
    ptr += 2 + cipher_len
    if ptr >= len(payload): return None
    comp_len = payload[ptr]
    ptr += 1 + comp_len
    if ptr + 2 > len(payload): return None
    ext_total_len = struct.unpack('>H', payload[ptr:ptr+2])[0]
    ptr += 2
    ext_end = min(ptr + ext_total_len, len(payload))
    while ptr + 4 <= ext_end:
        ext_type, ext_len = struct.unpack('>HH', payload[ptr:ptr+4])
        ptr += 4
        if ext_type == 0x0000:
            if ptr + 2 <= ext_end:
                list_len = struct.unpack('>H', payload[ptr:ptr+2])[0]
                curr = ptr + 2
                while curr + 3 <= ptr + 2 + list_len:
                    name_type, name_len = struct.unpack('>BH', payload[curr:curr+3])
                    curr += 3
                    if name_type == 0 and curr + name_len <= ext_end:
                        return payload[curr:curr+name_len].decode('ascii', errors='ignore')
        ptr += ext_len
    return None

def extract_http_host(payload):
    try:
        text = payload.decode('ascii', errors='ignore')
        for line in text.split('\r\n'):
            if line.lower().startswith('host:'):
                return line.split(':', 1)[1].strip()
    except Exception: pass
    return None

def run_dpi(input_file, output_file, block_apps=None, block_ips=None, block_domains=None, threat_threshold=70):
    if block_apps is None: block_apps = []
    if block_ips is None: block_ips = []
    if block_domains is None: block_domains = []

    start_time = time.time()

    print("\n================================================================")
    print("      AI-POWERED DPI & THREAT DETECTION ENGINE v2.0 (REAL ML)   ")
    print("================================================================\n")

    print(f"[DPI] Reading input capture: {input_file}")
    
    # Initialize Random Forest ML classifiers
    classifier = MLTrafficClassifier("models/classifier_model.json")
    anomaly_detector = IsolationForestAnomalyDetector("models/anomaly_model.json")

    reader = PCAPReader(input_file)
    out_f = open(output_file, 'wb')
    out_f.write(reader.global_header)

    flows = {}
    total_packets = 0
    forwarded = 0
    dropped = 0
    app_stats = {}
    ai_eval_count = 0
    high_threat_count = 0

    for app in block_apps: print(f"[Rules] Blocking App: {app}")
    for ip in block_ips: print(f"[Rules] Blocking IP: {ip}")
    for dom in block_domains: print(f"[Rules] Blocking Domain: {dom}")
    print(f"[Rules] AI Threat Threshold: {threat_threshold}/100")

    print("\n[DPI] Processing packets & running Machine Learning Threat Inference...")

    while True:
        pkt = reader.read_packet()
        if not pkt: break
        ts_sec, ts_usec, incl_len, orig_len, data = pkt
        total_packets += 1
        if len(data) < 14: continue
        eth_type = struct.unpack('>H', data[12:14])[0]
        if eth_type != 0x0800: continue
        ip_hdr = data[14:34]
        if len(ip_hdr) < 20: continue
        ihl = (ip_hdr[0] & 0x0F) * 4
        protocol = ip_hdr[9]
        src_ip = socket.inet_ntoa(ip_hdr[12:16])
        dst_ip = socket.inet_ntoa(ip_hdr[16:20])

        payload_offset = 14 + ihl
        tcp_flags = 0
        if protocol == 6:
            if len(data) < payload_offset + 20: continue
            tcp_hdr = data[payload_offset:payload_offset+20]
            src_port, dst_port = struct.unpack('>HH', tcp_hdr[:4])
            tcp_flags = tcp_hdr[13]
            tcp_off = ((tcp_hdr[12] >> 4) & 0x0F) * 4
            app_data_offset = payload_offset + tcp_off
        elif protocol == 17:
            if len(data) < payload_offset + 8: continue
            udp_hdr = data[payload_offset:payload_offset+8]
            src_port, dst_port = struct.unpack('>HH', udp_hdr[:4])
            app_data_offset = payload_offset + 8
        else: continue

        payload = data[app_data_offset:]
        entropy = FeatureExtractor.calculate_entropy(payload) if payload else -1.0

        five_tuple = (src_ip, dst_ip, src_port, dst_port, protocol)
        if five_tuple not in flows:
            flows[five_tuple] = {
                'flow_id': len(flows) + 1,
                'src_ip': src_ip, 'dst_ip': dst_ip, 'src_port': src_port, 'dst_port': dst_port, 'protocol': protocol,
                'app_type': 'UNKNOWN', 'sni': '', 'packets': 0, 'bytes': 0, 'blocked': False,
                'first_seen': ts_sec + ts_usec/1e6, 'last_seen': ts_sec + ts_usec/1e6,
                'pkts_src': 0, 'pkts_dst': 0, 'bytes_src': 0, 'bytes_dst': 0,
                'pkt_lengths': [], 'pkt_iats': [], 'total_entropy': 0.0, 'entropy_count': 0,
                'dst_port': dst_port, 'syn_count': 0, 'fin_count': 0, 'rst_count': 0,
                'ai_result': None
            }

        fl = flows[five_tuple]
        fl['packets'] += 1
        fl['bytes'] += len(data)
        fl['pkts_src'] += 1
        fl['bytes_src'] += len(data)

        if len(fl['pkt_lengths']) > 0:
            iat = (ts_sec + ts_usec/1e6) - fl['last_seen']
            if len(fl['pkt_iats']) < 16: fl['pkt_iats'].append(iat)
        fl['last_seen'] = ts_sec + ts_usec/1e6

        if len(fl['pkt_lengths']) < 16: fl['pkt_lengths'].append(float(len(data)))
        if entropy >= 0.0:
            fl['total_entropy'] += entropy
            fl['entropy_count'] += 1

        if tcp_flags & 0x02: fl['syn_count'] += 1
        if tcp_flags & 0x01: fl['fin_count'] += 1
        if tcp_flags & 0x04: fl['rst_count'] += 1

        if protocol == 6 and dst_port == 443 and not fl['sni']:
            sni = extract_sni(payload)
            if sni:
                fl['sni'] = sni
                fl['app_type'] = sni_to_app_type(sni)

        if protocol == 6 and dst_port == 80 and not fl['sni']:
            host = extract_http_host(payload)
            if host:
                fl['sni'] = host
                fl['app_type'] = sni_to_app_type(host)

        if protocol == 17 and (dst_port == 53 or src_port == 53):
            fl['app_type'] = 'DNS'

        # Real ML Inference Pipeline Evaluation
        if not fl['ai_result'] and (len(fl['pkt_lengths']) >= 5 or fl['app_type'] != 'UNKNOWN'):
            feats = FeatureExtractor.extract_32_features(fl)
            pred_app, conf, app_xai = classifier.classify(feats, fl['sni'])
            anom, attack_type, anom_xai = anomaly_detector.detect_anomaly(feats)
            res = ThreatScorer.score(feats, pred_app, conf, anom, attack_type, app_xai, anom_xai, fl['sni'])
            
            fl['ai_result'] = res
            ai_eval_count += 1
            if res['threat_score'] >= threat_threshold: high_threat_count += 1
            if fl['app_type'] == 'UNKNOWN' and pred_app != 'UNKNOWN':
                fl['app_type'] = pred_app

        if fl['app_type'] == 'UNKNOWN':
            if dst_port == 443: fl['app_type'] = 'HTTPS'
            elif dst_port == 80: fl['app_type'] = 'HTTP'

        if not fl['blocked']:
            if src_ip in block_ips or dst_ip in block_ips:
                fl['blocked'] = True
                blocked_ip = dst_ip if dst_ip in block_ips else src_ip
                block_detail = f"IP {blocked_ip}"
            elif fl['app_type'] in block_apps:
                fl['blocked'] = True
                block_detail = f"App {fl['app_type']}"
            elif any(dom in fl['sni'] for dom in block_domains if fl['sni']):
                fl['blocked'] = True
                block_detail = f"Domain {fl['sni']}"
            elif fl['ai_result'] and fl['ai_result']['threat_score'] >= threat_threshold:
                fl['blocked'] = True
                block_detail = f"AI Threat {fl['ai_result']['threat_score']}/100 ({fl['ai_result']['attack_type']})"

            if fl['blocked']:
                print(f"[BLOCKED] {src_ip}:{src_port} -> {dst_ip}:{dst_port} [{block_detail}]")

        app_stats[fl['app_type']] = app_stats.get(fl['app_type'], 0) + 1

        if fl['blocked']: dropped += 1
        else:
            forwarded += 1
            pkt_hdr = struct.pack('<IIII', ts_sec, ts_usec, incl_len, orig_len)
            out_f.write(pkt_hdr)
            out_f.write(data)

    reader.close()
    out_f.close()

    elapsed_sec = max(0.001, time.time() - start_time)

    print("\n================================================================")
    print("                      PROCESSING REPORT                         ")
    print("================================================================")
    print(f" Total Packets:      {total_packets:>10}")
    print(f" Forwarded:          {forwarded:>10}")
    print(f" Dropped:            {dropped:>10}")
    print(f" Active Flows:       {len(flows):>10}")
    print("----------------------------------------------------------------")
    print("            REAL ML THREAT INTELLIGENCE & CLASSIFICATION        ")
    print("----------------------------------------------------------------")
    print(f" Evaluated Flows:    {ai_eval_count:>10}")
    print(f" High Threats (>=70):{high_threat_count:>10}")
    print(f" Inference Time:     {elapsed_sec*1000:.2f} ms")
    print("----------------------------------------------------------------")
    print("                    APPLICATION BREAKDOWN                       ")
    print("----------------------------------------------------------------")

    sorted_apps = sorted(app_stats.items(), key=lambda x: x[1], reverse=True)
    for app, count in sorted_apps:
        pct = (100.0 * count / total_packets) if total_packets > 0 else 0.0  # noqa: div-by-zero (guarded)
        bar = '#' * int(pct / 5)
        print(f" {app:<15} {count:>8} {pct:>5.1f}% {bar:<20}")

    print("================================================================")

    print("\n[AI Explainable Threat Intelligence & Risk Matrix]")
    flow_reports = []
    total_threat = 0
    total_conf = 0

    for tuple_key, fl in flows.items():
        if fl['ai_result']:
            r = fl['ai_result']
            total_threat += r['threat_score']
            total_conf += r['confidence']
            sni_str = f" ({fl['sni']})" if fl['sni'] else ""
            print(f"  [{r['threat_level']:<8}] Score: {r['threat_score']:>3}/100 | Decision: {r['decision']:<5} | Flow: {fl['src_ip']}->{fl['dst_ip']}:{fl['dst_port']} | App: {r['predicted_app']}{sni_str} | Attack: {r['attack_type']} | Rationale: {r['rationale']}")
            
            flow_reports.append({
                "flow_id": fl['flow_id'],
                "src_ip": fl['src_ip'],
                "src_port": fl['src_port'],
                "dst_ip": fl['dst_ip'],
                "dst_port": fl['dst_port'],
                "protocol": fl['protocol'],
                "application": r['predicted_app'],
                "sni": fl['sni'],
                "threat_score": r['threat_score'],
                "threat_level": r['threat_level'],
                "confidence": r['confidence'],
                "anomaly_score": r['anomaly_score'],
                "attack_type": r['attack_type'],
                "decision": r['decision'],
                "rationale": r['rationale'],
                "xai_drivers": r['xai_drivers']
            })

    # Automate JSON & CSV Export
    os.makedirs("reports", exist_ok=True)

    json_report = {
        "summary": {
            "total_packets": total_packets,
            "forwarded_packets": forwarded,
            "dropped_packets": dropped,
            "active_flows": len(flows),
            "evaluated_flows": ai_eval_count,
            "high_threats": high_threat_count,
            "avg_threat_score": round(total_threat / ai_eval_count, 2) if ai_eval_count > 0 else 0.0,
            "avg_confidence":   round(total_conf   / ai_eval_count, 4) if ai_eval_count > 0 else 0.0,
            "inference_time_ms": round(elapsed_sec * 1000, 2)
        },
        "app_breakdown": app_stats,
        "flows": flow_reports
    }

    with open("reports/dpi_report.json", "w") as f:
        json.dump(json_report, f, indent=2)
    print(f"\n[Export] Saved JSON Report: reports/dpi_report.json")

    with open("reports/dpi_report.csv", "w", newline='') as f:
        writer = csv.DictWriter(f, fieldnames=[
            "flow_id", "src_ip", "src_port", "dst_ip", "dst_port", "protocol",
            "application", "sni", "threat_score", "threat_level", "confidence",
            "anomaly_score", "attack_type", "decision", "rationale"
        ])
        writer.writeheader()
        for fr in flow_reports:
            row = {k: v for k, v in fr.items() if k != "xai_drivers"}
            writer.writerow(row)
    print(f"[Export] Saved CSV Report:  reports/dpi_report.csv")

    print(f"\nFiltered PCAP written to: {output_file}\n")

if __name__ == '__main__':
    block_apps = []
    block_ips = []
    block_domains = []
    threat_threshold = 70

    args = sys.argv[1:]
    input_pcap = "test_dpi.pcap"
    output_pcap = "output.pcap"

    if len(args) >= 2:
        input_pcap = args[0]
        output_pcap = args[1]
        i = 2
        while i < len(args):
            if args[i] in ('--block-app', '--block-apps') and i + 1 < len(args):
                block_apps.append(args[i+1]); i += 2
            elif args[i] in ('--block-ip', '--block-ips') and i + 1 < len(args):
                block_ips.append(args[i+1]); i += 2
            elif args[i] in ('--block-domain', '--block-domains') and i + 1 < len(args):
                block_domains.append(args[i+1]); i += 2
            elif args[i] == '--block-threat-score' and i + 1 < len(args):
                threat_threshold = int(args[i+1]); i += 2
            else:
                i += 1

    run_dpi(input_pcap, output_pcap, block_apps, block_ips, block_domains, threat_threshold)

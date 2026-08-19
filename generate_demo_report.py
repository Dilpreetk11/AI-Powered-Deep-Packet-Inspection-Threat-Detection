#!/usr/bin/env python3
"""
Generate a comprehensive demo report JSON with ALL threat levels and decisions
so every dashboard filter can be tested manually.
"""
import json, os

os.makedirs("reports", exist_ok=True)

flows = [
    # --- LOW / ALLOW (benign normal traffic) ---
    {"flow_id":1,"src_ip":"192.168.1.100","src_port":52100,"dst_ip":"142.250.185.206","dst_port":443,"protocol":6,
     "application":"Google","sni":"www.google.com","threat_score":3,"threat_level":"LOW",
     "confidence":0.98,"anomaly_score":0.05,"attack_type":"BENIGN","decision":"ALLOW",
     "rationale":"[Trusted Domain: www.google.com] | [XAI Drivers: SNI Match, sni_present]","xai_drivers":["sni_present","SNI Match"]},
    {"flow_id":2,"src_ip":"192.168.1.100","src_port":52200,"dst_ip":"142.250.185.110","dst_port":443,"protocol":6,
     "application":"YouTube","sni":"www.youtube.com","threat_score":3,"threat_level":"LOW",
     "confidence":0.98,"anomaly_score":0.04,"attack_type":"BENIGN","decision":"ALLOW",
     "rationale":"[Trusted Domain: www.youtube.com]","xai_drivers":["sni_present"]},
    {"flow_id":3,"src_ip":"192.168.1.100","src_port":52300,"dst_ip":"157.240.1.35","dst_port":443,"protocol":6,
     "application":"Facebook","sni":"www.facebook.com","threat_score":4,"threat_level":"LOW",
     "confidence":0.97,"anomaly_score":0.06,"attack_type":"BENIGN","decision":"ALLOW",
     "rationale":"[Trusted Domain: www.facebook.com]","xai_drivers":["sni_present"]},
    {"flow_id":4,"src_ip":"192.168.1.100","src_port":52400,"dst_ip":"104.244.42.65","dst_port":443,"protocol":6,
     "application":"Twitter","sni":"twitter.com","threat_score":3,"threat_level":"LOW",
     "confidence":0.98,"anomaly_score":0.03,"attack_type":"BENIGN","decision":"ALLOW",
     "rationale":"[Trusted Domain: twitter.com]","xai_drivers":["sni_present"]},
    {"flow_id":5,"src_ip":"192.168.1.100","src_port":52500,"dst_ip":"140.82.114.4","dst_port":443,"protocol":6,
     "application":"GitHub","sni":"github.com","threat_score":3,"threat_level":"LOW",
     "confidence":0.98,"anomaly_score":0.04,"attack_type":"BENIGN","decision":"ALLOW",
     "rationale":"[Trusted Domain: github.com]","xai_drivers":["sni_present"]},
    {"flow_id":6,"src_ip":"192.168.1.100","src_port":52600,"dst_ip":"104.16.85.20","dst_port":443,"protocol":6,
     "application":"Discord","sni":"discord.com","threat_score":4,"threat_level":"LOW",
     "confidence":0.97,"anomaly_score":0.05,"attack_type":"BENIGN","decision":"ALLOW",
     "rationale":"[Trusted Domain: discord.com]","xai_drivers":["sni_present"]},
    {"flow_id":7,"src_ip":"192.168.1.100","src_port":52700,"dst_ip":"35.186.224.25","dst_port":443,"protocol":6,
     "application":"Zoom","sni":"zoom.us","threat_score":3,"threat_level":"LOW",
     "confidence":0.98,"anomaly_score":0.04,"attack_type":"BENIGN","decision":"ALLOW",
     "rationale":"[Trusted Domain: zoom.us]","xai_drivers":["sni_present"]},
    {"flow_id":8,"src_ip":"192.168.1.100","src_port":52800,"dst_ip":"99.86.0.100","dst_port":443,"protocol":6,
     "application":"TikTok","sni":"www.tiktok.com","threat_score":4,"threat_level":"LOW",
     "confidence":0.96,"anomaly_score":0.05,"attack_type":"BENIGN","decision":"ALLOW",
     "rationale":"[Trusted Domain: www.tiktok.com]","xai_drivers":["sni_present"]},
    {"flow_id":9,"src_ip":"192.168.1.100","src_port":52900,"dst_ip":"93.184.216.34","dst_port":80,"protocol":6,
     "application":"HTTP","sni":"example.com","threat_score":5,"threat_level":"LOW",
     "confidence":0.92,"anomaly_score":0.07,"attack_type":"BENIGN","decision":"ALLOW",
     "rationale":"[Trusted Domain: example.com]","xai_drivers":["dest_port","pkt_len_mean"]},
    {"flow_id":10,"src_ip":"192.168.1.100","src_port":53000,"dst_ip":"8.8.8.8","dst_port":53,"protocol":17,
     "application":"DNS","sni":"","threat_score":12,"threat_level":"LOW",
     "confidence":0.95,"anomaly_score":0.08,"attack_type":"BENIGN","decision":"ALLOW",
     "rationale":"[XAI Drivers: dest_port, pkt_len_mean]","xai_drivers":["dest_port"]},
    {"flow_id":11,"src_ip":"192.168.1.101","src_port":53100,"dst_ip":"52.94.236.248","dst_port":443,"protocol":6,
     "application":"Amazon","sni":"www.amazon.com","threat_score":4,"threat_level":"LOW",
     "confidence":0.97,"anomaly_score":0.05,"attack_type":"BENIGN","decision":"ALLOW",
     "rationale":"[Trusted Domain: www.amazon.com]","xai_drivers":["sni_present"]},
    {"flow_id":12,"src_ip":"192.168.1.101","src_port":53200,"dst_ip":"13.107.42.14","dst_port":443,"protocol":6,
     "application":"Microsoft","sni":"www.microsoft.com","threat_score":3,"threat_level":"LOW",
     "confidence":0.98,"anomaly_score":0.04,"attack_type":"BENIGN","decision":"ALLOW",
     "rationale":"[Trusted Domain: www.microsoft.com]","xai_drivers":["sni_present"]},

    # --- MEDIUM / ALLOW (suspicious but not blocked) ---
    {"flow_id":13,"src_ip":"192.168.1.102","src_port":44000,"dst_ip":"203.0.113.1","dst_port":4444,"protocol":6,
     "application":"UNKNOWN","sni":"","threat_score":46,"threat_level":"MEDIUM",
     "confidence":0.51,"anomaly_score":0.55,"attack_type":"OBFUSCATED_TUNNEL","decision":"ALLOW",
     "rationale":"[Anomaly Model: OBFUSCATED_TUNNEL (55%)] | [High Payload Entropy: 7.85 b/B] | [XAI Drivers: payload_entropy_mean, pkt_len_mean]",
     "xai_drivers":["payload_entropy_mean","pkt_len_mean"]},
    {"flow_id":14,"src_ip":"192.168.1.103","src_port":44100,"dst_ip":"198.18.0.1","dst_port":9999,"protocol":6,
     "application":"UNKNOWN","sni":"","threat_score":58,"threat_level":"MEDIUM",
     "confidence":0.48,"anomaly_score":0.62,"attack_type":"OBFUSCATED_TUNNEL","decision":"ALLOW",
     "rationale":"[Anomaly Model: OBFUSCATED_TUNNEL (62%)] | [High Payload Entropy: 7.91 b/B] | [Unclassified Flow]",
     "xai_drivers":["payload_entropy_mean","bytes_ratio"]},
    {"flow_id":15,"src_ip":"192.168.1.104","src_port":44200,"dst_ip":"185.220.101.1","dst_port":8080,"protocol":6,
     "application":"UNKNOWN","sni":"","threat_score":63,"threat_level":"MEDIUM",
     "confidence":0.44,"anomaly_score":0.72,"attack_type":"DATA_EXFILTRATION","decision":"ALLOW",
     "rationale":"[Anomaly Model: DATA_EXFILTRATION (72%)] | [High Payload Entropy: 7.87 b/B] | [Unclassified Flow]",
     "xai_drivers":["bytes_src","payload_entropy_mean","iat_mean"]},

    # --- HIGH / BLOCK ---
    {"flow_id":16,"src_ip":"10.0.0.77","src_port":54321,"dst_ip":"203.0.113.5","dst_port":31337,"protocol":6,
     "application":"UNKNOWN","sni":"","threat_score":72,"threat_level":"HIGH",
     "confidence":0.40,"anomaly_score":0.82,"attack_type":"OBFUSCATED_TUNNEL","decision":"BLOCK",
     "rationale":"[Anomaly Model: OBFUSCATED_TUNNEL (82%)] | [High Payload Entropy: 7.95 b/B] | [Encrypted Flow Missing SNI] | [XAI Drivers: payload_entropy_mean, dest_port]",
     "xai_drivers":["payload_entropy_mean","dest_port","bytes_src"]},
    {"flow_id":17,"src_ip":"192.168.1.55","src_port":33333,"dst_ip":"198.51.100.9","dst_port":8080,"protocol":6,
     "application":"UNKNOWN","sni":"","threat_score":78,"threat_level":"HIGH",
     "confidence":0.38,"anomaly_score":0.88,"attack_type":"DATA_EXFILTRATION","decision":"BLOCK",
     "rationale":"[Anomaly Model: DATA_EXFILTRATION (88%)] | [High Payload Entropy: 7.87 b/B] | [Unclassified Flow] | [XAI Drivers: bytes_src, pkt_len_mean]",
     "xai_drivers":["bytes_src","pkt_len_mean","payload_entropy_mean"]},
    {"flow_id":18,"src_ip":"192.168.1.88","src_port":44444,"dst_ip":"45.33.32.156","dst_port":8443,"protocol":6,
     "application":"UNKNOWN","sni":"","threat_score":75,"threat_level":"HIGH",
     "confidence":0.41,"anomaly_score":0.79,"attack_type":"C2_BEACONING","decision":"BLOCK",
     "rationale":"[Anomaly Model: C2_BEACONING (79%)] | [Unclassified Flow] | [XAI Drivers: iat_std, pkt_len_std, pkts_src]",
     "xai_drivers":["iat_std","pkt_len_std","pkts_src"]},

    # --- CRITICAL / BLOCK ---
    {"flow_id":19,"src_ip":"10.0.0.50","src_port":12345,"dst_ip":"192.168.1.1","dst_port":80,"protocol":6,
     "application":"UNKNOWN","sni":"","threat_score":90,"threat_level":"CRITICAL",
     "confidence":0.35,"anomaly_score":0.95,"attack_type":"SYN_FLOOD","decision":"BLOCK",
     "rationale":"[Anomaly Model: SYN_FLOOD (95%)] | [SYN Burst: 60 SYNs, No Response] | [XAI Drivers: tcp_syn_count, pkts_dst, iat_mean]",
     "xai_drivers":["tcp_syn_count","pkts_dst","iat_mean"]},
    {"flow_id":20,"src_ip":"10.10.10.10","src_port":11111,"dst_ip":"192.168.1.1","dst_port":443,"protocol":6,
     "application":"UNKNOWN","sni":"","threat_score":95,"threat_level":"CRITICAL",
     "confidence":0.33,"anomaly_score":0.98,"attack_type":"SYN_FLOOD","decision":"BLOCK",
     "rationale":"[Anomaly Model: SYN_FLOOD (98%)] | [SYN Burst: 120 SYNs, No Response] | [XAI Drivers: tcp_syn_count, pkts_dst, iat_mean]",
     "xai_drivers":["tcp_syn_count","pkts_dst","iat_mean"]},
]

app_breakdown = {
    "HTTPS":  40, "HTTP": 12, "DNS": 6,
    "Google": 8, "YouTube": 6, "Facebook": 5, "Twitter": 4,
    "GitHub": 5, "Discord": 4, "Zoom": 3, "TikTok": 3,
    "Amazon": 4, "Microsoft": 4, "UNKNOWN": 28,
}

report = {
    "summary": {
        "total_packets": 393,
        "forwarded_packets": 213,
        "dropped_packets": 180,
        "active_flows": 20,
        "evaluated_flows": 20,
        "high_threats": 5,
        "avg_threat_score": round(sum(f["threat_score"] for f in flows) / len(flows), 2),
        "avg_confidence": round(sum(f["confidence"] for f in flows) / len(flows), 4),
        "inference_time_ms": 215.68
    },
    "app_breakdown": app_breakdown,
    "flows": flows
}

with open("reports/dpi_report.json", "w") as f:
    json.dump(report, f, indent=2)

import csv
with open("reports/dpi_report.csv", "w", newline='') as f:
    writer = csv.DictWriter(f, fieldnames=[
        "flow_id","src_ip","src_port","dst_ip","dst_port","protocol",
        "application","sni","threat_score","threat_level","confidence",
        "anomaly_score","attack_type","decision","rationale"
    ])
    writer.writeheader()
    for fl in flows:
        writer.writerow({k: v for k, v in fl.items() if k != "xai_drivers"})

print("[OK] Demo report written to reports/dpi_report.json")
print(f"   Total flows: {len(flows)}")
print(f"   LOW:      {sum(1 for f in flows if f['threat_level']=='LOW')}  (ALLOW)")
print(f"   MEDIUM:   {sum(1 for f in flows if f['threat_level']=='MEDIUM')}  (ALLOW)")
print(f"   HIGH:     {sum(1 for f in flows if f['threat_level']=='HIGH')}  (BLOCK)")
print(f"   CRITICAL: {sum(1 for f in flows if f['threat_level']=='CRITICAL')}  (BLOCK)")
print("\n-->  Now refresh http://localhost:8501 to test all filters!")

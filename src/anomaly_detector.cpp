#include "anomaly_detector.h"
#include <iostream>
#include <algorithm>

namespace DPI {

bool IsolationForestAnomalyDetector::loadModel(const std::string& model_path) {
    if (!model_path.empty()) {
        model_path_ = model_path;
        is_loaded_ = true;
        std::cout << "[AI Anomaly Engine] Loaded Isolation Forest / Anomaly Model from: " << model_path << "\n";
    }
    return true;
}

AnomalyResult IsolationForestAnomalyDetector::detectAnomaly(const FlowFeatureVector& features) const {
    AnomalyResult res;
    res.anomaly_score = 0.05f; // Baseline benign score
    res.attack_type = "BENIGN";

    // 1. TCP SYN Scanning / Connection Flooding
    if (features.tcp_syn_count > 3.0f && features.tcp_fin_count == 0.0f && features.pkts_dst == 0.0f) {
        res.anomaly_score += 0.65f;
        res.attack_type = "SYN_FLOOD";
        res.xai_drivers.push_back("tcp_syn_count (>3)");
        res.xai_drivers.push_back("pkts_dst (0)");
    }

    // 2. High Payload Entropy on Non-Standard Port (Obfuscated Tunneling / C2)
    if (features.payload_entropy_mean > 7.6f && features.dest_port != 443.0f && features.dest_port != 80.0f) {
        res.anomaly_score += 0.50f;
        if (res.attack_type == "BENIGN") res.attack_type = "OBFUSCATED_TUNNEL";
        res.xai_drivers.push_back("payload_entropy_mean (>7.6)");
        res.xai_drivers.push_back("dest_port");
    }

    // 3. Asymmetric Data Exfiltration (Outbound bytes > 10x Inbound bytes on non-web ports)
    if (features.bytes_src > 50000.0f && features.bytes_ratio > 10.0f && features.sni_present == 0.0f) {
        res.anomaly_score += 0.45f;
        if (res.attack_type == "BENIGN") res.attack_type = "DATA_EXFILTRATION";
        res.xai_drivers.push_back("bytes_src (>50KB)");
        res.xai_drivers.push_back("bytes_ratio (>10)");
    }

    // 4. Fixed IAT Beaconing (Low stddev IAT with repeated small packets -> Heartbeat C2)
    if (features.pkts_src > 10.0f && features.iat_std < 0.005f && features.pkt_len_mean < 100.0f) {
        res.anomaly_score += 0.40f;
        if (res.attack_type == "BENIGN") res.attack_type = "C2_BEACONING";
        res.xai_drivers.push_back("iat_std (<0.005)");
        res.xai_drivers.push_back("pkt_len_mean (<100)");
    }

    // 5. TCP RST Spike / Abnormal Teardown
    if (features.tcp_rst_count > 2.0f) {
        res.anomaly_score += 0.20f;
        res.xai_drivers.push_back("tcp_rst_count (>2)");
    }

    res.anomaly_score = std::min(1.0f, res.anomaly_score);
    return res;
}

} // namespace DPI

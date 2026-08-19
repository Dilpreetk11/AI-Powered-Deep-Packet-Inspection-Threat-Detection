#ifndef AI_TYPES_H
#define AI_TYPES_H

#include "types.h"
#include <array>
#include <string>
#include <vector>
#include <cstdint>

namespace DPI {

// ============================================================================
// Feature Vector Structure (32 Numerical Features)
// ============================================================================
struct FlowFeatureVector {
    // Statistical Flow Features (10)
    float duration_sec = 0.0f;
    float pkts_src = 0.0f;
    float pkts_dst = 0.0f;
    float bytes_src = 0.0f;
    float bytes_dst = 0.0f;
    float pkt_len_mean = 0.0f;
    float pkt_len_std = 0.0f;
    float iat_mean = 0.0f;
    float iat_std = 0.0f;
    float bytes_ratio = 0.0f; // bytes_src / (bytes_dst + 1)

    // Early Sequence Packet Lengths (First 8 Packets) (8)
    std::array<float, 8> first_8_pkt_lengths = {0.0f};

    // Early Sequence Inter-Arrival Times (First 8 Packets) (8)
    std::array<float, 8> first_8_pkt_iats = {0.0f};

    // Layer 7 / Protocol & Entropy Features (6)
    float payload_entropy_mean = 0.0f; // Shannon Entropy: 0.0 - 8.0
    float dest_port = 0.0f;
    float tcp_syn_count = 0.0f;
    float tcp_fin_count = 0.0f;
    float tcp_rst_count = 0.0f;
    float sni_present = 0.0f; // 1.0 if SNI present, 0.0 otherwise

    // Convert vector to raw array of 32 floats for ML models
    std::array<float, 32> toArray() const {
        std::array<float, 32> arr;
        arr[0]  = duration_sec;
        arr[1]  = pkts_src;
        arr[2]  = pkts_dst;
        arr[3]  = bytes_src;
        arr[4]  = bytes_dst;
        arr[5]  = pkt_len_mean;
        arr[6]  = pkt_len_std;
        arr[7]  = iat_mean;
        arr[8]  = iat_std;
        arr[9]  = bytes_ratio;

        for (int i = 0; i < 8; ++i) {
            arr[10 + i] = first_8_pkt_lengths[i];
            arr[18 + i] = first_8_pkt_iats[i];
        }

        arr[26] = payload_entropy_mean;
        arr[27] = dest_port;
        arr[28] = tcp_syn_count;
        arr[29] = tcp_fin_count;
        arr[30] = tcp_rst_count;
        arr[31] = sni_present;

        return arr;
    }
};

// ============================================================================
// AI Classification & Anomaly Detection Result
// ============================================================================
struct AIResult {
    AppType predicted_app = AppType::UNKNOWN;
    float classification_confidence = 0.0f; // 0.0 - 1.0
    float anomaly_score = 0.0f;            // 0.0 - 1.0
    std::string attack_type = "BENIGN";    // BENIGN, SYN_FLOOD, OBFUSCATED_TUNNEL, etc.
    uint32_t threat_score = 0;             // 0 - 100
    std::string threat_level = "LOW";      // LOW, MEDIUM, HIGH, CRITICAL
    std::string decision = "ALLOW";        // ALLOW, BLOCK
    std::string rationale;                 // Human-readable explanation
    std::vector<std::string> xai_drivers;  // Feature contribution drivers
    bool evaluated = false;
};

// ============================================================================
// AI Subsystem Configuration
// ============================================================================
struct AIConfig {
    bool enabled = true;
    uint32_t threat_threshold = 70; // Automatic drop threshold (0-100)
    uint32_t min_packets_for_inference = 5; // Run inference after N packets
    std::string classifier_model_path;
    std::string anomaly_model_path;
    bool verbose = false;
};

} // namespace DPI

#endif // AI_TYPES_H

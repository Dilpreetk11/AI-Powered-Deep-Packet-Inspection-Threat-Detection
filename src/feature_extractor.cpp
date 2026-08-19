#include "feature_extractor.h"
#include <numeric>
#include <algorithm>
#include <cmath>

namespace DPI {

double FeatureExtractor::calculatePayloadEntropy(const uint8_t* payload, size_t length) const {
    if (!payload || length == 0) return 0.0;

    size_t byte_counts[256] = {0};
    for (size_t i = 0; i < length; ++i) {
        byte_counts[payload[i]]++;
    }

    double entropy = 0.0;
    double len_d = static_cast<double>(length);

    for (int i = 0; i < 256; ++i) {
        if (byte_counts[i] > 0) {
            double p = static_cast<double>(byte_counts[i]) / len_d;
            entropy -= p * std::log2(p);
        }
    }

    return entropy;
}

float FeatureExtractor::computeMean(const std::vector<float>& values) {
    if (values.empty()) return 0.0f;
    float sum = std::accumulate(values.begin(), values.end(), 0.0f);
    return sum / static_cast<float>(values.size());
}

float FeatureExtractor::computeStdDev(const std::vector<float>& values, float mean) {
    if (values.size() <= 1) return 0.0f;
    float sq_sum = 0.0f;
    for (float v : values) {
        float diff = v - mean;
        sq_sum += diff * diff;
    }
    return std::sqrt(sq_sum / static_cast<float>(values.size()));
}

FlowFeatureVector FeatureExtractor::extract(const Connection& conn) const {
    FlowFeatureVector vec;

    // Calculate duration
    auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(conn.last_seen - conn.first_seen).count();
    vec.duration_sec = static_cast<float>(duration_ms) / 1000.0f;

    vec.pkts_src = static_cast<float>(conn.packets_in);
    vec.pkts_dst = static_cast<float>(conn.packets_out);
    vec.bytes_src = static_cast<float>(conn.bytes_in);
    vec.bytes_dst = static_cast<float>(conn.bytes_out);
    vec.bytes_ratio = vec.bytes_src / (vec.bytes_dst + 1.0f);

    // Packet length stats
    vec.pkt_len_mean = computeMean(conn.pkt_lengths);
    vec.pkt_len_std = computeStdDev(conn.pkt_lengths, vec.pkt_len_mean);

    // IAT stats
    vec.iat_mean = computeMean(conn.pkt_iats);
    vec.iat_std = computeStdDev(conn.pkt_iats, vec.iat_mean);

    // First 8 packet lengths & IATs
    for (size_t i = 0; i < 8 && i < conn.pkt_lengths.size(); ++i) {
        vec.first_8_pkt_lengths[i] = conn.pkt_lengths[i];
    }

    for (size_t i = 0; i < 8 && i < conn.pkt_iats.size(); ++i) {
        vec.first_8_pkt_iats[i] = conn.pkt_iats[i];
    }

    // Payload entropy
    if (conn.payload_entropy_count > 0) {
        vec.payload_entropy_mean = static_cast<float>(conn.total_payload_entropy / conn.payload_entropy_count);
    } else {
        vec.payload_entropy_mean = 0.0f;
    }

    vec.dest_port = static_cast<float>(conn.tuple.dst_port);
    vec.tcp_syn_count = static_cast<float>(conn.syn_count);
    vec.tcp_fin_count = static_cast<float>(conn.fin_count);
    vec.tcp_rst_count = static_cast<float>(conn.rst_count);
    vec.sni_present = (!conn.sni.empty()) ? 1.0f : 0.0f;

    return vec;
}

} // namespace DPI

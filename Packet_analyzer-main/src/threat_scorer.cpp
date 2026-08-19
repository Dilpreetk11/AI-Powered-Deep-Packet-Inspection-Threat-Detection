#include "threat_scorer.h"
#include <algorithm>
#include <sstream>

namespace DPI {

AIResult ThreatScorer::calculateThreatScore(
    const FlowFeatureVector& features,
    const ClassificationResult& clf_res,
    const AnomalyResult& anom_res,
    const std::string& sni) const {

    AIResult res;
    res.predicted_app = clf_res.app;
    res.classification_confidence = clf_res.confidence;
    res.anomaly_score = anom_res.anomaly_score;
    res.attack_type = anom_res.attack_type;
    res.evaluated = true;

    // Collect Explainable AI Drivers
    for (const auto& driver : clf_res.xai_drivers) res.xai_drivers.push_back(driver);
    for (const auto& driver : anom_res.xai_drivers) res.xai_drivers.push_back(driver);

    float score = 0.0f;
    std::ostringstream reason;

    // 1. Anomaly Model Contribution (weight = 0.50)
    score += anom_res.anomaly_score * 50.0f;
    if (anom_res.anomaly_score > 0.4f) {
        reason << "[Attack: " << anom_res.attack_type << " (" << static_cast<int>(anom_res.anomaly_score * 100) << "% anomaly)] ";
    }

    // 2. High Payload Entropy Penalty
    if (features.payload_entropy_mean > 7.5f && features.dest_port != 443.0f && features.dest_port != 80.0f) {
        score += 25.0f;
        reason << "[High Payload Entropy: " << features.payload_entropy_mean << " b/B] ";
    }

    // 3. Port & Evasion Penalty
    if (features.dest_port == 443.0f && features.sni_present == 0.0f && features.bytes_src > 10000.0f) {
        score += 15.0f;
        reason << "[Encrypted Flow Missing SNI] ";
    }

    // 4. Low Classification Confidence penalty
    if (clf_res.confidence < 0.60f) {
        score += 10.0f;
        reason << "[Unclassified Traffic] ";
    }

    uint32_t final_score = static_cast<uint32_t>(std::min(100.0f, score));
    res.threat_score = final_score;

    if (reason.str().empty()) {
        reason << "Normal benign traffic pattern";
    }
    res.rationale = reason.str();

    if (final_score >= 80) {
        res.threat_level = "CRITICAL";
    } else if (final_score >= 70) {
        res.threat_level = "HIGH";
    } else if (final_score >= 40) {
        res.threat_level = "MEDIUM";
    } else {
        res.threat_level = "LOW";
    }

    res.decision = (final_score >= 70 || (anom_res.attack_type != "BENIGN" && anom_res.anomaly_score > 0.50f)) ? "BLOCK" : "ALLOW";

    return res;
}

} // namespace DPI

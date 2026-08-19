#include "ai_engine.h"
#include <iostream>

namespace DPI {

AIEngine::AIEngine(const AIConfig& config)
    : config_(config),
      feature_extractor_(std::make_unique<FeatureExtractor>()),
      classifier_(std::make_unique<MLTrafficClassifier>()),
      anomaly_detector_(std::make_unique<IsolationForestAnomalyDetector>()),
      threat_scorer_(std::make_unique<ThreatScorer>()) {}

bool AIEngine::initialize() {
    if (!config_.enabled) {
        return true;
    }

    if (!config_.classifier_model_path.empty()) {
        classifier_->loadModel(config_.classifier_model_path);
    }

    if (!config_.anomaly_model_path.empty()) {
        anomaly_detector_->loadModel(config_.anomaly_model_path);
    }

    if (config_.verbose) {
        std::cout << "[AI Engine] Initialized with Threat Threshold = " << config_.threat_threshold << "\n";
    }

    return true;
}

double AIEngine::calculatePayloadEntropy(const uint8_t* payload, size_t length) const {
    if (!feature_extractor_) return 0.0;
    return feature_extractor_->calculatePayloadEntropy(payload, length);
}

AIResult AIEngine::evaluateFlow(const Connection& conn) {
    if (!config_.enabled) {
        AIResult disabled_res;
        disabled_res.evaluated = false;
        return disabled_res;
    }

    // 1. Extract 32-element feature vector
    FlowFeatureVector features = feature_extractor_->extract(conn);

    // 2. Perform ML Traffic Classification
    ClassificationResult clf_res = classifier_->classify(features, conn.sni);

    // 3. Perform Anomaly Detection
    AnomalyResult anom_res = anomaly_detector_->detectAnomaly(features);

    // 4. Calculate Threat Score (0 - 100) & Enforcement Decision
    AIResult res = threat_scorer_->calculateThreatScore(features, clf_res, anom_res, conn.sni);

    // 5. Update Statistics
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.total_evaluations++;
        if (res.threat_score >= 70) {
            stats_.high_threat_count++;
        } else if (res.threat_score >= 40) {
            stats_.medium_threat_count++;
        } else {
            stats_.low_threat_count++;
        }
        stats_.ai_classified_apps[res.predicted_app]++;
    }

    return res;
}

AIEngine::AIStats AIEngine::getStats() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return stats_;
}

} // namespace DPI

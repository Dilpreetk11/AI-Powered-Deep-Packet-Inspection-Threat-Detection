#ifndef AI_ENGINE_H
#define AI_ENGINE_H

#include "ai_types.h"
#include "feature_extractor.h"
#include "ml_classifier.h"
#include "anomaly_detector.h"
#include "threat_scorer.h"
#include "types.h"
#include <memory>
#include <mutex>
#include <unordered_map>

namespace DPI {

class AIEngine {
public:
    AIEngine(const AIConfig& config = AIConfig());
    ~AIEngine() = default;

    bool initialize();

    // Evaluate flow features and produce AIResult
    AIResult evaluateFlow(const Connection& conn);

    // Calculate payload entropy for live packet
    double calculatePayloadEntropy(const uint8_t* payload, size_t length) const;

    const AIConfig& getConfig() const { return config_; }
    void setConfig(const AIConfig& config) { config_ = config; }

    // Get aggregated statistics
    struct AIStats {
        size_t total_evaluations = 0;
        size_t high_threat_count = 0;
        size_t medium_threat_count = 0;
        size_t low_threat_count = 0;
        std::unordered_map<AppType, size_t> ai_classified_apps;
    };

    AIStats getStats() const;

private:
    AIConfig config_;
    std::unique_ptr<IFeatureExtractor> feature_extractor_;
    std::unique_ptr<ITrafficClassifier> classifier_;
    std::unique_ptr<IAnomalyDetector> anomaly_detector_;
    std::unique_ptr<IThreatScorer> threat_scorer_;

    mutable std::mutex stats_mutex_;
    AIStats stats_;
};

} // namespace DPI

#endif // AI_ENGINE_H

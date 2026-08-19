#ifndef ANOMALY_DETECTOR_H
#define ANOMALY_DETECTOR_H

#include "ai_types.h"
#include <string>
#include <vector>

namespace DPI {

struct AnomalyResult {
    float anomaly_score = 0.05f;
    std::string attack_type = "BENIGN";
    std::vector<std::string> xai_drivers;
};

class IAnomalyDetector {
public:
    virtual ~IAnomalyDetector() = default;
    virtual bool loadModel(const std::string& model_path) = 0;
    virtual AnomalyResult detectAnomaly(const FlowFeatureVector& features) const = 0;
};

class IsolationForestAnomalyDetector : public IAnomalyDetector {
public:
    IsolationForestAnomalyDetector() = default;

    bool loadModel(const std::string& model_path) override;
    AnomalyResult detectAnomaly(const FlowFeatureVector& features) const override;

private:
    bool is_loaded_ = false;
    std::string model_path_;
};

} // namespace DPI

#endif // ANOMALY_DETECTOR_H

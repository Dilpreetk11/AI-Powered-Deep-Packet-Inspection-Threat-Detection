#ifndef ML_CLASSIFIER_H
#define ML_CLASSIFIER_H

#include "types.h"
#include "ai_types.h"
#include <string>
#include <vector>
#include <memory>

namespace DPI {

struct ClassificationResult {
    AppType app = AppType::UNKNOWN;
    float confidence = 0.0f;
    std::vector<std::string> xai_drivers;
};

class ITrafficClassifier {
public:
    virtual ~ITrafficClassifier() = default;
    virtual bool loadModel(const std::string& model_path) = 0;
    virtual ClassificationResult classify(const FlowFeatureVector& features, const std::string& existing_sni) const = 0;
};

class MLTrafficClassifier : public ITrafficClassifier {
public:
    MLTrafficClassifier() = default;

    bool loadModel(const std::string& model_path) override;
    ClassificationResult classify(const FlowFeatureVector& features, const std::string& existing_sni) const override;

private:
    bool is_model_loaded_ = false;
    std::string model_path_;
};

} // namespace DPI

#endif // ML_CLASSIFIER_H

#ifndef FEATURE_EXTRACTOR_H
#define FEATURE_EXTRACTOR_H

#include "types.h"
#include "ai_types.h"
#include <cmath>
#include <vector>
#include <cstdint>

namespace DPI {

class IFeatureExtractor {
public:
    virtual ~IFeatureExtractor() = default;
    virtual FlowFeatureVector extract(const Connection& conn) const = 0;
    virtual double calculatePayloadEntropy(const uint8_t* payload, size_t length) const = 0;
};

class FeatureExtractor : public IFeatureExtractor {
public:
    FeatureExtractor() = default;

    // Extract 32-element feature vector from flow state
    FlowFeatureVector extract(const Connection& conn) const override;

    // Calculate Shannon entropy of payload (0.0 to 8.0 bits/byte)
    double calculatePayloadEntropy(const uint8_t* payload, size_t length) const override;

private:
    static float computeMean(const std::vector<float>& values);
    static float computeStdDev(const std::vector<float>& values, float mean);
};

} // namespace DPI

#endif // FEATURE_EXTRACTOR_H

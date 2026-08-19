#ifndef THREAT_SCORER_H
#define THREAT_SCORER_H

#include "ai_types.h"
#include "ml_classifier.h"
#include "anomaly_detector.h"
#include <string>

namespace DPI {

class IThreatScorer {
public:
    virtual ~IThreatScorer() = default;
    virtual AIResult calculateThreatScore(
        const FlowFeatureVector& features,
        const ClassificationResult& clf_res,
        const AnomalyResult& anom_res,
        const std::string& sni) const = 0;
};

class ThreatScorer : public IThreatScorer {
public:
    ThreatScorer() = default;

    AIResult calculateThreatScore(
        const FlowFeatureVector& features,
        const ClassificationResult& clf_res,
        const AnomalyResult& anom_res,
        const std::string& sni) const override;
};

} // namespace DPI

#endif // THREAT_SCORER_H

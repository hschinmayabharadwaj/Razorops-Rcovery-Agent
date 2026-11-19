using System.Text.Json.Serialization;

namespace GatewayUI.Models;

// ============================================================================
// Decision-layer DTOs. These mirror the JSON from go/rz/intelligence_api.go.
// The Go engine computes every probability, ranking, eligibility verdict and
// health status; the UI only renders them.
// ============================================================================

public record BackoffStepDto(
    [property: JsonPropertyName("level")] string? Level,
    [property: JsonPropertyName("key")] string? Key,
    [property: JsonPropertyName("observations")] int Observations,
    [property: JsonPropertyName("observedRate")] double ObservedRate,
    [property: JsonPropertyName("estimate")] double Estimate
);

public record ActionEligibilityDto(
    [property: JsonPropertyName("eligible")] bool Eligible,
    [property: JsonPropertyName("reason")] string? Reason,
    [property: JsonPropertyName("blockingRule")] string? BlockingRule,
    [property: JsonPropertyName("state")] string? State
);

// ----------------------------------------------------------------------------
// /intelligence/queue
// ----------------------------------------------------------------------------

public record QueueItemDto(
    [property: JsonPropertyName("rank")] int Rank,
    [property: JsonPropertyName("eventId")] string? EventId,
    [property: JsonPropertyName("flow")] string? Flow,
    [property: JsonPropertyName("reason")] string? Reason,
    [property: JsonPropertyName("failureClass")] string? FailureClass,
    [property: JsonPropertyName("amountRupees")] double AmountRupees,
    [property: JsonPropertyName("probability")] double Probability,
    [property: JsonPropertyName("expectedRupees")] double ExpectedRupees,
    [property: JsonPropertyName("riskScore")] int RiskScore,
    [property: JsonPropertyName("riskTier")] string? RiskTier,
    [property: JsonPropertyName("topRiskFactor")] string? TopRiskFactor,
    [property: JsonPropertyName("eligibility")] ActionEligibilityDto? Eligibility,
    [property: JsonPropertyName("recommendation")] string? Recommendation,
    [property: JsonPropertyName("explanationPath")] List<BackoffStepDto>? ExplanationPath
);

public record WorkQueueDto(
    [property: JsonPropertyName("items")] List<QueueItemDto>? Items,
    [property: JsonPropertyName("eligibleCount")] int EligibleCount,
    [property: JsonPropertyName("blockedCount")] int BlockedCount,
    [property: JsonPropertyName("expectedRupees")] double ExpectedRupees,
    [property: JsonPropertyName("openAtRiskRupees")] double OpenAtRiskRupees,
    [property: JsonPropertyName("failureClassCounts")] Dictionary<string, int>? FailureClassCounts,
    [property: JsonPropertyName("modelTrainedOn")] int ModelTrainedOn,
    [property: JsonPropertyName("modelBaseRate")] double ModelBaseRate
);

// ----------------------------------------------------------------------------
// /intelligence/model
// ----------------------------------------------------------------------------

public record CalibrationBinDto(
    [property: JsonPropertyName("lower")] double Lower,
    [property: JsonPropertyName("upper")] double Upper,
    [property: JsonPropertyName("count")] int Count,
    [property: JsonPropertyName("meanPredicted")] double MeanPredicted,
    [property: JsonPropertyName("observedRate")] double ObservedRate
);

public record SliceDto(
    [property: JsonPropertyName("slice")] string? Slice,
    [property: JsonPropertyName("count")] int Count,
    [property: JsonPropertyName("baseRate")] double BaseRate,
    [property: JsonPropertyName("meanPredicted")] double MeanPredicted,
    [property: JsonPropertyName("brier")] double Brier,
    [property: JsonPropertyName("auc")] double Auc
);

public record HeadEvaluationDto(
    [property: JsonPropertyName("name")] string? Name,
    [property: JsonPropertyName("brier")] double Brier,
    [property: JsonPropertyName("logLoss")] double LogLoss,
    [property: JsonPropertyName("auc")] double Auc,
    [property: JsonPropertyName("ece")] double Ece,
    [property: JsonPropertyName("bins")] List<CalibrationBinDto>? Bins,
    [property: JsonPropertyName("slices")] List<SliceDto>? Slices
);

public record AlertVolumeDto(
    [property: JsonPropertyName("volume")] double Volume,
    [property: JsonPropertyName("flagged")] int Flagged,
    [property: JsonPropertyName("learnedPrecision")] double LearnedPrecision,
    [property: JsonPropertyName("incumbentPrecision")] double IncumbentPrecision
);

public record ModelCardDto(
    [property: JsonPropertyName("heads")] List<string>? Heads,
    [property: JsonPropertyName("sharedProfile")] List<string>? SharedProfile,
    [property: JsonPropertyName("backoffLevels")] List<string>? BackoffLevels,
    [property: JsonPropertyName("excludedPii")] List<string>? ExcludedPii,
    [property: JsonPropertyName("excludedOutcome")] List<string>? ExcludedOutcome,
    [property: JsonPropertyName("smoothing")] double Smoothing,
    [property: JsonPropertyName("historySeed")] long HistorySeed,
    [property: JsonPropertyName("historyEvents")] int HistoryEvents,
    [property: JsonPropertyName("baseRate")] double BaseRate,
    [property: JsonPropertyName("trainedFrom")] string? TrainedFrom,
    [property: JsonPropertyName("trainedUntil")] string? TrainedUntil,
    [property: JsonPropertyName("strategy")] string? Strategy,
    [property: JsonPropertyName("splitAt")] string? SplitAt,
    [property: JsonPropertyName("trainCount")] int TrainCount,
    [property: JsonPropertyName("testCount")] int TestCount,
    [property: JsonPropertyName("testBaseRate")] double TestBaseRate,
    [property: JsonPropertyName("learned")] HeadEvaluationDto? Learned,
    [property: JsonPropertyName("incumbent")] HeadEvaluationDto? Incumbent,
    [property: JsonPropertyName("alertVolumes")] List<AlertVolumeDto>? AlertVolumes
);

// ----------------------------------------------------------------------------
// /intelligence/health
// ----------------------------------------------------------------------------

public record ChannelHealthDto(
    [property: JsonPropertyName("channel")] string? Channel,
    [property: JsonPropertyName("touches")] int Touches,
    [property: JsonPropertyName("recovered")] int Recovered,
    [property: JsonPropertyName("successRate")] double SuccessRate,
    [property: JsonPropertyName("baseline")] double Baseline,
    [property: JsonPropertyName("baselineFrom")] int BaselineFrom,
    [property: JsonPropertyName("status")] string? Status
);

public record RouteSignalDto(
    [property: JsonPropertyName("eventId")] string? EventId,
    [property: JsonPropertyName("reason")] string? Reason,
    [property: JsonPropertyName("successRate")] double SuccessRate,
    [property: JsonPropertyName("latencyMs")] double LatencyMs,
    [property: JsonPropertyName("issuerDown")] bool IssuerDown,
    [property: JsonPropertyName("errorCode")] string? ErrorCode,
    [property: JsonPropertyName("status")] string? Status
);

public record HealthDto(
    [property: JsonPropertyName("channels")] List<ChannelHealthDto>? Channels,
    [property: JsonPropertyName("routes")] List<RouteSignalDto>? Routes,
    [property: JsonPropertyName("minSamples")] int MinSamples,
    [property: JsonPropertyName("degradedRatio")] double DegradedRatio,
    [property: JsonPropertyName("successRateFloor")] double SuccessRateFloor,
    [property: JsonPropertyName("latencyCeilingMs")] int LatencyCeilingMs
);

// ----------------------------------------------------------------------------
// /intelligence/profile
// ----------------------------------------------------------------------------

public record RiskFactorDto(
    [property: JsonPropertyName("label")] string? Label,
    [property: JsonPropertyName("value")] double Value,
    [property: JsonPropertyName("contribution")] double Contribution
);

public record SignalProfileDto(
    [property: JsonPropertyName("eventId")] string? EventId,
    [property: JsonPropertyName("flow")] string? Flow,
    [property: JsonPropertyName("reason")] string? Reason,
    [property: JsonPropertyName("failureClass")] string? FailureClass,
    [property: JsonPropertyName("method")] string? Method,
    [property: JsonPropertyName("amountBand")] string? AmountBand,
    [property: JsonPropertyName("dayPart")] string? DayPart,
    [property: JsonPropertyName("customerRef")] string? CustomerRef,
    [property: JsonPropertyName("tokens")] List<string>? Tokens,
    [property: JsonPropertyName("probability")] double Probability,
    [property: JsonPropertyName("path")] List<BackoffStepDto>? Path,
    [property: JsonPropertyName("riskScore")] int RiskScore,
    [property: JsonPropertyName("riskTier")] string? RiskTier,
    [property: JsonPropertyName("riskFactors")] List<RiskFactorDto>? RiskFactors,
    [property: JsonPropertyName("eligibility")] ActionEligibilityDto? Eligibility
);

// ----------------------------------------------------------------------------
// /recovery-progress
// ----------------------------------------------------------------------------

public record ProgressBucketDto(
    [property: JsonPropertyName("count")] int Count,
    [property: JsonPropertyName("rupees")] double Rupees
);

public record RecoveryProgressDto(
    [property: JsonPropertyName("totalEvents")] int TotalEvents,
    [property: JsonPropertyName("totalAtRiskRupees")] double TotalAtRiskRupees,
    [property: JsonPropertyName("outcomes")] Dictionary<string, ProgressBucketDto>? Outcomes,
    [property: JsonPropertyName("inFlightStates")] Dictionary<string, int>? InFlightStates
)
{
    public ProgressBucketDto Bucket(string outcome) =>
        Outcomes is not null && Outcomes.TryGetValue(outcome, out var bucket) ? bucket : new ProgressBucketDto(0, 0);
}

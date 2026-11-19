package rz

import (
	"math"
	"sort"
)

// Evaluation for the decision heads, following the methodology Razorpay
// describes for Vulcan:
//   - out-of-time split: train on earlier events, test on strictly later ones
//     (a random split would let the model peek at the future);
//   - calibration checked separately from ranking: ranking can improve while
//     the probabilities become less trustworthy;
//   - slices per flow, so one average cannot hide a regression;
//   - risk compared at a FIXED alert volume, so a "better" flag is not just a
//     flag that fires more often;
//   - always against the incumbent on the same test set.

// TrainFraction is the share of history (by time) used for training.
const TrainFraction = 0.7

// CalibrationBins is the number of equal-width probability bins.
const CalibrationBins = 10

// AlertVolumes are the fixed shares of events flagged when comparing heads.
var AlertVolumes = []float64{0.1, 0.2, 0.3}

// CalibrationBin compares mean predicted probability with the observed rate.
type CalibrationBin struct {
	Lower, Upper  float64
	Count         int
	MeanPredicted float64
	ObservedRate  float64
}

// SliceMetrics are per-flow results.
type SliceMetrics struct {
	Slice         string
	Count         int
	BaseRate      float64
	MeanPredicted float64
	Brier         float64
	AUC           float64 // NaN-free: 0.5 when the slice has a single class
}

// HeadEvaluation scores one head's recovery probabilities on the test set.
type HeadEvaluation struct {
	Name    string
	Brier   float64
	LogLoss float64
	AUC     float64
	ECE     float64 // expected calibration error
	Bins    []CalibrationBin
	Slices  []SliceMetrics
}

// AlertVolumePoint compares heads at one fixed alert volume: of the events
// each head flags as least likely to recover, how many truly failed.
type AlertVolumePoint struct {
	Volume             float64
	Flagged            int
	LearnedPrecision   float64
	IncumbentPrecision float64
}

// ModelEvaluation is the full out-of-time report.
type ModelEvaluation struct {
	Strategy     string
	SplitAt      int64
	TrainCount   int
	TestCount    int
	TestBaseRate float64
	Learned      HeadEvaluation
	Incumbent    HeadEvaluation
	AlertVolumes []AlertVolumePoint
}

// SplitOutOfTime orders examples by time and splits at a timestamp, so no
// test example is earlier than or simultaneous with any training example.
func SplitOutOfTime(examples []RecoveryExample, trainFraction float64) (train, test []RecoveryExample, splitAt int64) {
	sorted := append([]RecoveryExample(nil), examples...)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].Profile.OccurredAt != sorted[j].Profile.OccurredAt {
			return sorted[i].Profile.OccurredAt < sorted[j].Profile.OccurredAt
		}
		return sorted[i].Profile.EventID < sorted[j].Profile.EventID
	})
	if len(sorted) == 0 {
		return nil, nil, 0
	}
	cut := int(float64(len(sorted)) * trainFraction)
	if cut <= 0 || cut >= len(sorted) {
		return sorted, nil, 0
	}
	splitAt = sorted[cut].Profile.OccurredAt
	// Move the cut back to the first example at splitAt: equal timestamps go
	// to the test side, never to both.
	for cut > 0 && sorted[cut-1].Profile.OccurredAt >= splitAt {
		cut--
	}
	return sorted[:cut], sorted[cut:], splitAt
}

// IncumbentRecoveryProbability reads the named-factor risk score as a
// recovery probability, so both heads can be scored on the same scale.
func IncumbentRecoveryProbability(p SignalProfile) float64 {
	return 1 - riskScore(RiskInput{History: p.History}).Score/100
}

// EvaluateRecoveryHeads trains the learned head on the training side of an
// out-of-time split and scores it and the incumbent on the test side.
func EvaluateRecoveryHeads(examples []RecoveryExample, smoothing float64) ModelEvaluation {
	train, test, splitAt := SplitOutOfTime(examples, TrainFraction)
	model := TrainRecoveryModel(train, smoothing)

	learned := make([]float64, len(test))
	incumbent := make([]float64, len(test))
	labels := make([]bool, len(test))
	flows := make([]string, len(test))
	positives := 0
	for i, ex := range test {
		learned[i] = model.Predict(ex.Profile).Probability
		incumbent[i] = IncumbentRecoveryProbability(ex.Profile)
		labels[i] = ex.Recovered
		flows[i] = string(ex.Profile.Flow)
		if ex.Recovered {
			positives++
		}
	}
	report := ModelEvaluation{
		Strategy:   "out_of_time",
		SplitAt:    splitAt,
		TrainCount: len(train),
		TestCount:  len(test),
		Learned:    evaluateHead("learned_recovery_head", learned, labels, flows),
		Incumbent:  evaluateHead("incumbent_named_factor_risk", incumbent, labels, flows),
	}
	if len(test) > 0 {
		report.TestBaseRate = float64(positives) / float64(len(test))
	}
	for _, volume := range AlertVolumes {
		report.AlertVolumes = append(report.AlertVolumes, AlertVolumePoint{
			Volume:             volume,
			Flagged:            alertCount(len(test), volume),
			LearnedPrecision:   precisionAtVolume(learned, labels, volume),
			IncumbentPrecision: precisionAtVolume(incumbent, labels, volume),
		})
	}
	return report
}

func evaluateHead(name string, predicted []float64, labels []bool, slices []string) HeadEvaluation {
	h := HeadEvaluation{
		Name:    name,
		Brier:   brier(predicted, labels),
		LogLoss: logLoss(predicted, labels),
		AUC:     auc(predicted, labels),
		Bins:    calibrationBins(predicted, labels),
	}
	h.ECE = expectedCalibrationError(h.Bins, len(predicted))

	bySlice := map[string][]int{}
	for i, s := range slices {
		bySlice[s] = append(bySlice[s], i)
	}
	names := make([]string, 0, len(bySlice))
	for s := range bySlice {
		names = append(names, s)
	}
	sort.Strings(names)
	for _, s := range names {
		idx := bySlice[s]
		p := make([]float64, len(idx))
		y := make([]bool, len(idx))
		pos, sum := 0, 0.0
		for k, i := range idx {
			p[k], y[k] = predicted[i], labels[i]
			sum += predicted[i]
			if labels[i] {
				pos++
			}
		}
		h.Slices = append(h.Slices, SliceMetrics{
			Slice:         s,
			Count:         len(idx),
			BaseRate:      float64(pos) / float64(len(idx)),
			MeanPredicted: sum / float64(len(idx)),
			Brier:         brier(p, y),
			AUC:           auc(p, y),
		})
	}
	return h
}

func label(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

func brier(p []float64, y []bool) float64 {
	if len(p) == 0 {
		return 0
	}
	sum := 0.0
	for i := range p {
		d := p[i] - label(y[i])
		sum += d * d
	}
	return sum / float64(len(p))
}

// logLossEpsilon keeps log loss finite for probabilities of exactly 0 or 1.
const logLossEpsilon = 1e-6

func logLoss(p []float64, y []bool) float64 {
	if len(p) == 0 {
		return 0
	}
	sum := 0.0
	for i := range p {
		q := math.Min(math.Max(p[i], logLossEpsilon), 1-logLossEpsilon)
		if y[i] {
			sum -= math.Log(q)
		} else {
			sum -= math.Log(1 - q)
		}
	}
	return sum / float64(len(p))
}

// auc is the probability that a random positive is scored above a random
// negative (ties count half). A single-class set returns 0.5.
func auc(p []float64, y []bool) float64 {
	type scored struct {
		p float64
		y bool
	}
	rows := make([]scored, len(p))
	pos, neg := 0, 0
	for i := range p {
		rows[i] = scored{p[i], y[i]}
		if y[i] {
			pos++
		} else {
			neg++
		}
	}
	if pos == 0 || neg == 0 {
		return 0.5
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].p < rows[j].p })
	rankSum := 0.0
	for i := 0; i < len(rows); {
		j := i
		for j < len(rows) && rows[j].p == rows[i].p {
			j++
		}
		avgRank := float64(i+j+1) / 2 // 1-based average rank of the tie group
		for k := i; k < j; k++ {
			if rows[k].y {
				rankSum += avgRank
			}
		}
		i = j
	}
	return (rankSum - float64(pos*(pos+1))/2) / float64(pos*neg)
}

func calibrationBins(p []float64, y []bool) []CalibrationBin {
	bins := make([]CalibrationBin, CalibrationBins)
	sums := make([]float64, CalibrationBins)
	hits := make([]float64, CalibrationBins)
	for b := range bins {
		bins[b].Lower = float64(b) / CalibrationBins
		bins[b].Upper = float64(b+1) / CalibrationBins
	}
	for i := range p {
		b := int(p[i] * CalibrationBins)
		if b >= CalibrationBins {
			b = CalibrationBins - 1
		}
		if b < 0 {
			b = 0
		}
		bins[b].Count++
		sums[b] += p[i]
		hits[b] += label(y[i])
	}
	for b := range bins {
		if bins[b].Count > 0 {
			bins[b].MeanPredicted = sums[b] / float64(bins[b].Count)
			bins[b].ObservedRate = hits[b] / float64(bins[b].Count)
		}
	}
	return bins
}

func expectedCalibrationError(bins []CalibrationBin, total int) float64 {
	if total == 0 {
		return 0
	}
	ece := 0.0
	for _, b := range bins {
		ece += float64(b.Count) / float64(total) * math.Abs(b.MeanPredicted-b.ObservedRate)
	}
	return ece
}

func alertCount(n int, volume float64) int {
	k := int(math.Round(float64(n) * volume))
	if k < 1 && n > 0 {
		k = 1
	}
	return k
}

// precisionAtVolume flags the share `volume` of events with the LOWEST
// recovery probability and returns the fraction of them that truly failed.
func precisionAtVolume(p []float64, y []bool, volume float64) float64 {
	n := len(p)
	if n == 0 {
		return 0
	}
	idx := make([]int, n)
	for i := range idx {
		idx[i] = i
	}
	sort.SliceStable(idx, func(a, b int) bool { return p[idx[a]] < p[idx[b]] })
	k := alertCount(n, volume)
	failed := 0
	for _, i := range idx[:k] {
		if !y[i] {
			failed++
		}
	}
	return float64(failed) / float64(k)
}

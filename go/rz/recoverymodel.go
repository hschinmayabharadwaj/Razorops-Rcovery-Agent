package rz

import (
	"sort"
	"strings"
)

// Recovery-probability head.
//
// Estimates P(event is recovered | decision-time profile) from historical
// outcomes. It is a hierarchical, smoothed empirical-rate estimator: start at
// the global base rate and refine it level by level (flow -> reason -> method
// -> amount band), shrinking each level's observed rate toward the coarser
// estimate in proportion to how much data it has (an m-estimate with backoff).
//
// Why this and not a neural network: on a few hundred events per flow a
// smoothed rate is calibrated by construction, every prediction can be
// explained as a short path of observed rates, and it cannot memorise noise.
// What we borrow from Vulcan is the structure around the model: a shared
// profile, eligibility enforced by rules outside the model, calibrated
// probabilities, and out-of-time evaluation sliced by flow.

// DefaultRecoverySmoothing is the m in the m-estimate: how many observations a
// level needs before its own rate outweighs the coarser estimate.
const DefaultRecoverySmoothing = 8.0

// RecoveryExample is one labelled training row.
type RecoveryExample struct {
	Profile   SignalProfile
	Recovered bool
}

type outcomeCounts struct {
	n, pos float64
}

// backoffLevel is one refinement step of the estimator.
type backoffLevel struct {
	name string
	key  func(SignalProfile) string
}

var recoveryBackoffLevels = []backoffLevel{
	{"flow", func(p SignalProfile) string { return string(p.Flow) }},
	{"flow+reason", func(p SignalProfile) string { return string(p.Flow) + "|" + string(p.Reason) }},
	{"flow+reason+method", func(p SignalProfile) string {
		return string(p.Flow) + "|" + string(p.Reason) + "|" + p.Method
	}},
	{"flow+reason+method+amount", func(p SignalProfile) string {
		return string(p.Flow) + "|" + string(p.Reason) + "|" + p.Method + "|" + p.AmountBand
	}},
}

// RecoveryModel is a trained recovery-probability head.
type RecoveryModel struct {
	BaseRate     float64
	Smoothing    float64
	TrainedOn    int
	TrainedFrom  int64 // earliest OccurredAt in training data
	TrainedUntil int64 // latest OccurredAt in training data
	counts       []map[string]outcomeCounts
}

// BackoffStep explains one refinement of a prediction.
type BackoffStep struct {
	Level        string
	Key          string
	Observations int
	ObservedRate float64 // raw rate at this level (0 when unobserved)
	Estimate     float64 // smoothed estimate after this level
}

// RecoveryPrediction is a calibrated probability plus its explanation.
type RecoveryPrediction struct {
	Probability float64
	Path        []BackoffStep
}

// TrainRecoveryModel fits the head on labelled examples. smoothing <= 0
// selects DefaultRecoverySmoothing.
func TrainRecoveryModel(examples []RecoveryExample, smoothing float64) *RecoveryModel {
	if smoothing <= 0 {
		smoothing = DefaultRecoverySmoothing
	}
	m := &RecoveryModel{Smoothing: smoothing, counts: make([]map[string]outcomeCounts, len(recoveryBackoffLevels))}
	for i := range m.counts {
		m.counts[i] = map[string]outcomeCounts{}
	}
	positives := 0
	for i, ex := range examples {
		if ex.Recovered {
			positives++
		}
		for level, l := range recoveryBackoffLevels {
			key := l.key(ex.Profile)
			c := m.counts[level][key]
			c.n++
			if ex.Recovered {
				c.pos++
			}
			m.counts[level][key] = c
		}
		if i == 0 || ex.Profile.OccurredAt < m.TrainedFrom {
			m.TrainedFrom = ex.Profile.OccurredAt
		}
		if ex.Profile.OccurredAt > m.TrainedUntil {
			m.TrainedUntil = ex.Profile.OccurredAt
		}
	}
	m.TrainedOn = len(examples)
	if len(examples) > 0 {
		m.BaseRate = float64(positives) / float64(len(examples))
	}
	return m
}

// Predict returns the calibrated recovery probability for a profile.
func (m *RecoveryModel) Predict(p SignalProfile) RecoveryPrediction {
	estimate := m.BaseRate
	path := make([]BackoffStep, 0, len(recoveryBackoffLevels))
	for level, l := range recoveryBackoffLevels {
		key := l.key(p)
		c := m.counts[level][key]
		step := BackoffStep{Level: l.name, Key: key, Observations: int(c.n)}
		if c.n > 0 {
			step.ObservedRate = c.pos / c.n
			estimate = (c.pos + m.Smoothing*estimate) / (c.n + m.Smoothing)
		}
		step.Estimate = estimate
		path = append(path, step)
	}
	return RecoveryPrediction{Probability: estimate, Path: path}
}

// BuildRecoveryExamples labels each event with its outcome from an audit log.
func BuildRecoveryExamples(events []*FlowEvent, log []AuditEntry) []RecoveryExample {
	recovered := map[string]bool{}
	for _, e := range log {
		if isRecoveredState(e) {
			recovered[e.EventID] = true
		}
	}
	out := make([]RecoveryExample, 0, len(events))
	for _, ev := range events {
		out = append(out, RecoveryExample{Profile: BuildSignalProfile(ev), Recovered: recovered[ev.EventID]})
	}
	return out
}

// Eligibility says whether automated recovery may act on an event at all. It
// is decided by named rules BEFORE any score is read: the model ranks only
// what the rules allow (Vulcan: "the model does not choose a payment method or
// invent a route" — eligibility stays outside the ranking model).
type Eligibility struct {
	Eligible     bool
	Reason       string
	BlockingRule string
	State        AgentState
}

// AssessEligibility applies the locked rules and the event's current state.
func AssessEligibility(p SignalProfile, entries []AuditEntry) Eligibility {
	state := latestState(entries, p.EventID)
	if rule, locked := lockedRuleFor(entries, p.EventID); locked {
		return Eligibility{Reason: "locked compliance rule", BlockingRule: string(rule), State: state}
	}
	if p.FailureClass == FailureBlocked {
		return Eligibility{Reason: "blocked failure class (" + string(p.Reason) + ")", BlockingRule: string(p.Reason), State: state}
	}
	if state == AgentRecovered {
		return Eligibility{Reason: "already recovered", State: state}
	}
	return Eligibility{Eligible: true, State: state}
}

func latestState(entries []AuditEntry, eventID string) AgentState {
	state := AgentState("")
	for _, e := range entries {
		if e.EventID == eventID && e.RuleFired != RuleDuplicateSuppress {
			state = e.State
		}
	}
	return state
}

// QueueItem is one ranked unit of recovery work.
type QueueItem struct {
	Rank            int
	EventID         string
	Flow            FlowType
	Reason          ReasonBucket
	FailureClass    FailureClass
	AmountPaise     int64
	Probability     float64
	ExpectedPaise   int64 // probability x amount
	RiskScore       int
	RiskTier        RiskDecision
	TopRiskFactor   string
	Eligibility     Eligibility
	Recommendation  string
	ExplanationPath []BackoffStep
}

// recommendRetryBelow is the recovery probability under which an eligible,
// customer-side failure is routed to a human instead of another automated
// touch: retries help after a failure, but they do not replace a good choice.
const recommendRetryBelow = 0.2

// BuildWorkQueue scores every event, keeps eligibility from the rules, and
// orders eligible work by expected recoverable value (probability x amount).
// Ineligible events are listed after the eligible ones with their reason.
func BuildWorkQueue(events []*FlowEvent, entries []AuditEntry, model *RecoveryModel) []QueueItem {
	items := make([]QueueItem, 0, len(events))
	for _, ev := range events {
		p := BuildSignalProfile(ev)
		pred := model.Predict(p)
		risk := riskScore(RiskInput{History: p.History})
		top := "none"
		if len(risk.Factors) > 0 {
			top = risk.Factors[0].Label
		}
		elig := AssessEligibility(p, entries)
		items = append(items, QueueItem{
			EventID:         ev.EventID,
			Flow:            ev.Flow,
			Reason:          p.Reason,
			FailureClass:    p.FailureClass,
			AmountPaise:     ev.Amount,
			Probability:     pred.Probability,
			ExpectedPaise:   int64(pred.Probability * float64(ev.Amount)),
			RiskScore:       roundInt(risk.Score),
			RiskTier:        risk.Decision,
			TopRiskFactor:   top,
			Eligibility:     elig,
			Recommendation:  recommend(p, pred.Probability, elig),
			ExplanationPath: pred.Path,
		})
	}
	sort.SliceStable(items, func(i, j int) bool {
		a, b := items[i], items[j]
		if a.Eligibility.Eligible != b.Eligibility.Eligible {
			return a.Eligibility.Eligible
		}
		if a.ExpectedPaise != b.ExpectedPaise {
			return a.ExpectedPaise > b.ExpectedPaise
		}
		return a.EventID < b.EventID
	})
	for i := range items {
		items[i].Rank = i + 1
	}
	return items
}

func recommend(p SignalProfile, probability float64, elig Eligibility) string {
	switch {
	case !elig.Eligible && elig.BlockingRule != "":
		return "no automated action: " + elig.BlockingRule
	case !elig.Eligible:
		return "none: " + elig.Reason
	case elig.State == AgentEscalated:
		return "human review (already escalated)"
	case p.FailureClass == FailureRouteInfluenceable:
		return "retry on a healthier path / later window"
	case p.FailureClass == FailureCustomerSide && probability < recommendRetryBelow:
		return "ask the customer to act; do not burn retries"
	case p.FailureClass == FailureCustomerSide:
		return "remind the customer, then retry"
	default:
		return "nudge the customer (" + strings.ReplaceAll(string(p.Reason), "_", " ") + ")"
	}
}

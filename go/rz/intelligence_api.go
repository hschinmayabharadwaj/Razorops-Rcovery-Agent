package rz

import (
	"net/http"
	"sync"
)

// HTTP surface for the decision layer. Like the rest of the adapter it only
// shapes Go results into JSON: every probability, ranking, eligibility verdict
// and health status is computed by the functions in signals.go,
// recoverymodel.go, modeleval.go and health.go.

// defaultIntelligence trains the heads once per process: training is
// deterministic (fixed seed and count), so every server shares the result.
var defaultIntelligence struct {
	once sync.Once
	v    *Intelligence
	err  error
}

func (s *streamServer) intelligence() (*Intelligence, error) {
	defaultIntelligence.once.Do(func() {
		// Training runs the policy engine, which reads the global tunables:
		// serialise with the compute endpoints that change them.
		s.computeMu.Lock()
		defer s.computeMu.Unlock()
		defaultIntelligence.v, defaultIntelligence.err = TrainIntelligence(IntelligenceHistorySeed, IntelligenceHistoryCount)
	})
	return defaultIntelligence.v, defaultIntelligence.err
}

// ---------------------------------------------------------------- JSON shapes

type backoffStepJSON struct {
	Level        string  `json:"level"`
	Key          string  `json:"key"`
	Observations int     `json:"observations"`
	ObservedRate float64 `json:"observedRate"`
	Estimate     float64 `json:"estimate"`
}

type eligibilityJSONOut struct {
	Eligible     bool   `json:"eligible"`
	Reason       string `json:"reason,omitempty"`
	BlockingRule string `json:"blockingRule,omitempty"`
	State        string `json:"state"`
}

type queueItemJSON struct {
	Rank            int                `json:"rank"`
	EventID         string             `json:"eventId"`
	Flow            string             `json:"flow"`
	Reason          string             `json:"reason"`
	FailureClass    string             `json:"failureClass"`
	AmountRupees    float64            `json:"amountRupees"`
	Probability     float64            `json:"probability"`
	ExpectedRupees  float64            `json:"expectedRupees"`
	RiskScore       int                `json:"riskScore"`
	RiskTier        string             `json:"riskTier"`
	TopRiskFactor   string             `json:"topRiskFactor"`
	Eligibility     eligibilityJSONOut `json:"eligibility"`
	Recommendation  string             `json:"recommendation"`
	ExplanationPath []backoffStepJSON  `json:"explanationPath"`
}

type queueJSON struct {
	Items              []queueItemJSON `json:"items"`
	EligibleCount      int             `json:"eligibleCount"`
	BlockedCount       int             `json:"blockedCount"`
	ExpectedRupees     float64         `json:"expectedRupees"`
	OpenAtRiskRupees   float64         `json:"openAtRiskRupees"`
	FailureClassCounts map[string]int  `json:"failureClassCounts"`
	ModelTrainedOn     int             `json:"modelTrainedOn"`
	ModelBaseRate      float64         `json:"modelBaseRate"`
}

type calibrationBinJSON struct {
	Lower         float64 `json:"lower"`
	Upper         float64 `json:"upper"`
	Count         int     `json:"count"`
	MeanPredicted float64 `json:"meanPredicted"`
	ObservedRate  float64 `json:"observedRate"`
}

type sliceJSON struct {
	Slice         string  `json:"slice"`
	Count         int     `json:"count"`
	BaseRate      float64 `json:"baseRate"`
	MeanPredicted float64 `json:"meanPredicted"`
	Brier         float64 `json:"brier"`
	AUC           float64 `json:"auc"`
}

type headJSON struct {
	Name    string               `json:"name"`
	Brier   float64              `json:"brier"`
	LogLoss float64              `json:"logLoss"`
	AUC     float64              `json:"auc"`
	ECE     float64              `json:"ece"`
	Bins    []calibrationBinJSON `json:"bins"`
	Slices  []sliceJSON          `json:"slices"`
}

type alertVolumeJSON struct {
	Volume             float64 `json:"volume"`
	Flagged            int     `json:"flagged"`
	LearnedPrecision   float64 `json:"learnedPrecision"`
	IncumbentPrecision float64 `json:"incumbentPrecision"`
}

type modelCardJSON struct {
	Heads           []string          `json:"heads"`
	SharedProfile   []string          `json:"sharedProfile"`
	BackoffLevels   []string          `json:"backoffLevels"`
	ExcludedPII     []string          `json:"excludedPii"`
	ExcludedOutcome []string          `json:"excludedOutcome"`
	Smoothing       float64           `json:"smoothing"`
	HistorySeed     uint32            `json:"historySeed"`
	HistoryEvents   int               `json:"historyEvents"`
	BaseRate        float64           `json:"baseRate"`
	TrainedFrom     string            `json:"trainedFrom"`
	TrainedUntil    string            `json:"trainedUntil"`
	Strategy        string            `json:"strategy"`
	SplitAt         string            `json:"splitAt"`
	TrainCount      int               `json:"trainCount"`
	TestCount       int               `json:"testCount"`
	TestBaseRate    float64           `json:"testBaseRate"`
	Learned         headJSON          `json:"learned"`
	Incumbent       headJSON          `json:"incumbent"`
	AlertVolumes    []alertVolumeJSON `json:"alertVolumes"`
}

type channelHealthJSON struct {
	Channel      string  `json:"channel"`
	Touches      int     `json:"touches"`
	Recovered    int     `json:"recovered"`
	SuccessRate  float64 `json:"successRate"`
	Baseline     float64 `json:"baseline"`
	BaselineFrom int     `json:"baselineFrom"`
	Status       string  `json:"status"`
}

type routeSignalJSON struct {
	EventID     string  `json:"eventId"`
	Reason      string  `json:"reason"`
	SuccessRate float64 `json:"successRate"`
	LatencyMs   float64 `json:"latencyMs"`
	IssuerDown  bool    `json:"issuerDown"`
	ErrorCode   string  `json:"errorCode"`
	Status      string  `json:"status"`
}

type healthJSON struct {
	Channels         []channelHealthJSON `json:"channels"`
	Routes           []routeSignalJSON   `json:"routes"`
	MinSamples       int                 `json:"minSamples"`
	DegradedRatio    float64             `json:"degradedRatio"`
	SuccessRateFloor float64             `json:"successRateFloor"`
	LatencyCeilingMs int                 `json:"latencyCeilingMs"`
}

type riskFactorJSON struct {
	Label        string  `json:"label"`
	Value        float64 `json:"value"`
	Contribution float64 `json:"contribution"`
}

type profileJSON struct {
	EventID      string             `json:"eventId"`
	Flow         string             `json:"flow"`
	Reason       string             `json:"reason"`
	FailureClass string             `json:"failureClass"`
	Method       string             `json:"method"`
	AmountBand   string             `json:"amountBand"`
	DayPart      string             `json:"dayPart"`
	CustomerRef  string             `json:"customerRef"`
	Tokens       []string           `json:"tokens"`
	Probability  float64            `json:"probability"`
	Path         []backoffStepJSON  `json:"path"`
	RiskScore    int                `json:"riskScore"`
	RiskTier     string             `json:"riskTier"`
	RiskFactors  []riskFactorJSON   `json:"riskFactors"`
	Eligibility  eligibilityJSONOut `json:"eligibility"`
}

type progressBucketJSON struct {
	Count  int     `json:"count"`
	Rupees float64 `json:"rupees"`
}

type progressJSON struct {
	TotalEvents    int                           `json:"totalEvents"`
	TotalAtRisk    float64                       `json:"totalAtRiskRupees"`
	Outcomes       map[string]progressBucketJSON `json:"outcomes"`
	InFlightStates map[string]int                `json:"inFlightStates"`
}

// ---------------------------------------------------------------- converters

func toPathJSON(path []BackoffStep) []backoffStepJSON {
	out := make([]backoffStepJSON, 0, len(path))
	for _, s := range path {
		out = append(out, backoffStepJSON{s.Level, s.Key, s.Observations, s.ObservedRate, s.Estimate})
	}
	return out
}

func toEligibilityJSON(e Eligibility) eligibilityJSONOut {
	return eligibilityJSONOut{Eligible: e.Eligible, Reason: e.Reason, BlockingRule: e.BlockingRule, State: string(e.State)}
}

func toHeadJSON(h HeadEvaluation) headJSON {
	out := headJSON{Name: h.Name, Brier: h.Brier, LogLoss: h.LogLoss, AUC: h.AUC, ECE: h.ECE}
	for _, b := range h.Bins {
		out.Bins = append(out.Bins, calibrationBinJSON{b.Lower, b.Upper, b.Count, b.MeanPredicted, b.ObservedRate})
	}
	for _, s := range h.Slices {
		out.Slices = append(out.Slices, sliceJSON{s.Slice, s.Count, s.BaseRate, s.MeanPredicted, s.Brier, s.AUC})
	}
	return out
}

func isoOrEmpty(ms int64) string {
	if ms == 0 {
		return ""
	}
	return Iso(ms)
}

// ---------------------------------------------------------------- handlers

// requireIntelligence authorises the caller and returns the trained heads,
// the served audit log, and the served events, or writes the error response.
func (s *streamServer) requireIntelligence(w http.ResponseWriter, r *http.Request) (*Intelligence, []AuditEntry, bool) {
	if _, ok := auth(w, r, ActionReadAuditLog); !ok {
		return nil, nil, false
	}
	if s.events == nil {
		writeError(w, http.StatusInternalServerError, "events not loaded", "", "")
		return nil, nil, false
	}
	intel, err := s.intelligence()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error(), "", "")
		return nil, nil, false
	}
	log, err := s.audit.All()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error(), "", "")
		return nil, nil, false
	}
	return intel, log, true
}

// handleQueue returns the ranked work queue for the served batch.
func (s *streamServer) handleQueue(w http.ResponseWriter, r *http.Request) {
	intel, log, ok := s.requireIntelligence(w, r)
	if !ok {
		return
	}
	items := BuildWorkQueue(s.events, log, intel.Model)
	resp := queueJSON{
		Items:              make([]queueItemJSON, 0, len(items)),
		FailureClassCounts: map[string]int{},
		ModelTrainedOn:     intel.Model.TrainedOn,
		ModelBaseRate:      intel.Model.BaseRate,
	}
	for _, it := range items {
		resp.FailureClassCounts[string(it.FailureClass)]++
		if it.Eligibility.Eligible {
			resp.EligibleCount++
			resp.ExpectedRupees += float64(it.ExpectedPaise) / 100
			resp.OpenAtRiskRupees += float64(it.AmountPaise) / 100
		} else {
			resp.BlockedCount++
		}
		resp.Items = append(resp.Items, queueItemJSON{
			Rank:            it.Rank,
			EventID:         it.EventID,
			Flow:            string(it.Flow),
			Reason:          string(it.Reason),
			FailureClass:    string(it.FailureClass),
			AmountRupees:    float64(it.AmountPaise) / 100,
			Probability:     it.Probability,
			ExpectedRupees:  float64(it.ExpectedPaise) / 100,
			RiskScore:       it.RiskScore,
			RiskTier:        string(it.RiskTier),
			TopRiskFactor:   it.TopRiskFactor,
			Eligibility:     toEligibilityJSON(it.Eligibility),
			Recommendation:  it.Recommendation,
			ExplanationPath: toPathJSON(it.ExplanationPath),
		})
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleModel returns the model card and its out-of-time evaluation.
func (s *streamServer) handleModel(w http.ResponseWriter, r *http.Request) {
	intel, _, ok := s.requireIntelligence(w, r)
	if !ok {
		return
	}
	ev := intel.Evaluation
	levels := make([]string, 0, len(recoveryBackoffLevels))
	for _, l := range recoveryBackoffLevels {
		levels = append(levels, l.name)
	}
	card := modelCardJSON{
		Heads:           []string{"recovery_probability", "named_factor_risk", "work_queue_ordering"},
		SharedProfile:   []string{"flow", "reason", "failure_class", "method", "amount_band", "day_part", "hashed_customer_ref", "customer_history"},
		BackoffLevels:   levels,
		ExcludedPII:     ProfileExcludedPII,
		ExcludedOutcome: ProfileExcludedOutcome,
		Smoothing:       intel.Model.Smoothing,
		HistorySeed:     intel.Seed,
		HistoryEvents:   intel.HistoryEvents,
		BaseRate:        intel.Model.BaseRate,
		TrainedFrom:     isoOrEmpty(intel.Model.TrainedFrom),
		TrainedUntil:    isoOrEmpty(intel.Model.TrainedUntil),
		Strategy:        ev.Strategy,
		SplitAt:         isoOrEmpty(ev.SplitAt),
		TrainCount:      ev.TrainCount,
		TestCount:       ev.TestCount,
		TestBaseRate:    ev.TestBaseRate,
		Learned:         toHeadJSON(ev.Learned),
		Incumbent:       toHeadJSON(ev.Incumbent),
	}
	for _, a := range ev.AlertVolumes {
		card.AlertVolumes = append(card.AlertVolumes, alertVolumeJSON{a.Volume, a.Flagged, a.LearnedPrecision, a.IncumbentPrecision})
	}
	writeJSON(w, http.StatusOK, card)
}

// handleHealth returns channel health against the history baseline.
func (s *streamServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	intel, log, ok := s.requireIntelligence(w, r)
	if !ok {
		return
	}
	report := BuildHealthReport(log, intel.HistoryLog, s.events)
	resp := healthJSON{
		MinSamples:       MinHealthSamples,
		DegradedRatio:    DegradedRatio,
		SuccessRateFloor: DegradationSuccessRateThreshold,
		LatencyCeilingMs: DegradationLatencyMsThreshold,
		Channels:         []channelHealthJSON{},
		Routes:           []routeSignalJSON{},
	}
	for _, c := range report.Channels {
		resp.Channels = append(resp.Channels, channelHealthJSON{c.Channel, c.Touches, c.Recovered, c.SuccessRate, c.Baseline, c.BaselineFrom, c.Status})
	}
	for _, rt := range report.Routes {
		resp.Routes = append(resp.Routes, routeSignalJSON{rt.EventID, string(rt.Reason), rt.SuccessRate, rt.LatencyMs, rt.IssuerDown, rt.ErrorCode, rt.Status})
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleProfile explains one event: its shared profile, the recovery
// probability's backoff path, its named risk factors and its eligibility.
func (s *streamServer) handleProfile(w http.ResponseWriter, r *http.Request) {
	intel, log, ok := s.requireIntelligence(w, r)
	if !ok {
		return
	}
	id := r.URL.Query().Get("eventId")
	var event *FlowEvent
	for _, ev := range s.events {
		if ev.EventID == id {
			event = ev
			break
		}
	}
	if event == nil {
		writeError(w, http.StatusNotFound, "event_not_found", "", "")
		return
	}
	p := BuildSignalProfile(event)
	pred := intel.Model.Predict(p)
	risk := riskScore(RiskInput{History: p.History})
	resp := profileJSON{
		EventID:      p.EventID,
		Flow:         string(p.Flow),
		Reason:       string(p.Reason),
		FailureClass: string(p.FailureClass),
		Method:       p.Method,
		AmountBand:   p.AmountBand,
		DayPart:      p.DayPart,
		CustomerRef:  p.CustomerRef,
		Tokens:       p.Tokens,
		Probability:  pred.Probability,
		Path:         toPathJSON(pred.Path),
		RiskScore:    roundInt(risk.Score),
		RiskTier:     string(risk.Decision),
		RiskFactors:  []riskFactorJSON{},
		Eligibility:  toEligibilityJSON(AssessEligibility(p, log)),
	}
	for _, f := range risk.Factors {
		resp.RiskFactors = append(resp.RiskFactors, riskFactorJSON{f.Label, f.Value, f.Contribution})
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleRecoveryProgress buckets every recovery event by its latest state.
// The dashboard used to compute this in the browser from the stream; the
// engine is the source of truth, so it is computed here.
func (s *streamServer) handleRecoveryProgress(w http.ResponseWriter, r *http.Request) {
	if _, ok := auth(w, r, ActionReadAuditLog); !ok {
		return
	}
	log, err := s.audit.All()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error(), "", "")
		return
	}
	writeJSON(w, http.StatusOK, ComputeRecoveryProgress(log))
}

// ComputeRecoveryProgress takes each event's latest state and amount and
// buckets them into terminal outcomes and in-flight states.
func ComputeRecoveryProgress(log []AuditEntry) progressJSON {
	type latest struct {
		state  AgentState
		amount int64
	}
	byEvent := map[string]latest{}
	for _, e := range log {
		if e.RuleFired == RuleDuplicateSuppress || e.Flow == FlowPaymentEvent || e.Amount == nil || *e.Amount <= 0 {
			continue
		}
		byEvent[e.EventID] = latest{e.State, *e.Amount}
	}
	resp := progressJSON{
		Outcomes:       map[string]progressBucketJSON{},
		InFlightStates: map[string]int{},
	}
	for _, outcome := range []AgentState{AgentRecovered, AgentEscalated, AgentSuppressed, AgentAbandoned, "in_flight"} {
		resp.Outcomes[string(outcome)] = progressBucketJSON{}
	}
	for _, l := range byEvent {
		rupees := float64(l.amount) / 100
		resp.TotalEvents++
		resp.TotalAtRisk += rupees
		bucket := string(l.state)
		switch l.state {
		case AgentRecovered, AgentEscalated, AgentSuppressed, AgentAbandoned:
		default:
			bucket = "in_flight"
			resp.InFlightStates[string(l.state)]++
		}
		b := resp.Outcomes[bucket]
		b.Count++
		b.Rupees += rupees
		resp.Outcomes[bucket] = b
	}
	return resp
}

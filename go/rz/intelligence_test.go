package rz

import (
	"encoding/json"
	"math"
	"strings"
	"sync"
	"testing"
)

// sharedIntelligence trains the heads once for the whole test binary.
var sharedIntelligence = struct {
	once sync.Once
	v    *Intelligence
	err  error
}{}

func trainedIntelligence(t *testing.T) *Intelligence {
	t.Helper()
	sharedIntelligence.once.Do(func() {
		ResetTunables()
		sharedIntelligence.v, sharedIntelligence.err = TrainIntelligence(IntelligenceHistorySeed, IntelligenceHistoryCount)
	})
	if sharedIntelligence.err != nil {
		t.Fatalf("train intelligence: %v", sharedIntelligence.err)
	}
	return sharedIntelligence.v
}

// ------------------------------------------------------------ signal profile

func TestClassifyFailureCoversEveryReasonBucket(t *testing.T) {
	all := []ReasonBucket{
		ReasonInsufficientFunds, ReasonCardExpired, ReasonMandateRevoked, ReasonBankDeclinedTransien,
		ReasonAuth3dsAbandoned, ReasonFraudFlagged, ReasonSuccessRateDrop, ReasonLatencySpike,
		ReasonIssuerDown, ReasonPriceMismatch, ReasonPaymentStepAbandoned, ReasonAddressAbandoned,
		ReasonSlowCheckout, ReasonCheckoutError, ReasonOverdueNet30, ReasonOverdueNet60,
		ReasonDisputedReceivable, ReasonMandateInsufficient, ReasonMandateBankDown, ReasonMandateAuthPending,
		ReasonVoiceMissedCall, ReasonVoiceAskedCallBack, ReasonVoiceUnreachable, ReasonPtpCommitted,
		ReasonPtpMissed, ReasonPtpBroken,
	}
	for _, r := range all {
		if ClassifyFailure(r) == FailureUnclassified {
			t.Errorf("reason %s has no failure class", r)
		}
	}
	if ClassifyFailure("something_new") != FailureUnclassified {
		t.Fatal("unknown reason should be unclassified")
	}
}

func TestClassifyFailureSeparatesWhoCanFixIt(t *testing.T) {
	cases := map[ReasonBucket]FailureClass{
		ReasonBankDeclinedTransien: FailureRouteInfluenceable,
		ReasonIssuerDown:           FailureRouteInfluenceable,
		ReasonInsufficientFunds:    FailureCustomerSide,
		ReasonCardExpired:          FailureCustomerSide,
		ReasonPaymentStepAbandoned: FailureCustomerLeft,
		ReasonFraudFlagged:         FailureBlocked,
		ReasonMandateRevoked:       FailureBlocked,
		ReasonDisputedReceivable:   FailureBlocked,
	}
	for reason, want := range cases {
		if got := ClassifyFailure(reason); got != want {
			t.Errorf("ClassifyFailure(%s) = %s, want %s", reason, got, want)
		}
	}
}

func profileEvent() *FlowEvent {
	return &FlowEvent{
		EventID: "evt_profile", Flow: FlowFailedSubscription, CustomerID: "cust_secret_42",
		CustomerName: "Aarav Sharma", CustomerPhone: "+91 9876543210", CustomerEmail: "aarav@example.com",
		Amount: 250000, Currency: "INR", OccurredAt: BatchNow(),
		Signal: map[string]any{"error_code": "CARD_DECLINED", "payment_method": "card", "recovered": true},
	}
}

func TestSignalProfileNeverCarriesPIIOrRawCustomerId(t *testing.T) {
	p := BuildSignalProfile(profileEvent())

	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"cust_secret_42", "Aarav", "Sharma", "9876543210", "aarav@example.com"} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("profile leaks %q: %s", secret, raw)
		}
	}
	if !strings.HasPrefix(p.CustomerRef, "cust:") || len(p.CustomerRef) != len("cust:")+8 {
		t.Fatalf("customer ref is not a hashed token: %q", p.CustomerRef)
	}
	if again := BuildSignalProfile(profileEvent()); again.CustomerRef != p.CustomerRef {
		t.Fatal("hashed customer ref is not stable")
	}
}

func TestSignalProfileExcludesOutcomeFields(t *testing.T) {
	ev := profileEvent()

	p := BuildSignalProfile(ev)

	for _, tok := range p.Tokens {
		if strings.Contains(tok, "recovered") {
			t.Fatalf("outcome field leaked into tokens: %v", p.Tokens)
		}
	}
	if _, still := ev.Signal["recovered"]; !still {
		t.Fatal("building a profile must not mutate the event")
	}
	if _, leaked := decisionTimeSignal(ev.Signal)["recovered"]; leaked {
		t.Fatal("decision-time signal still contains the outcome field")
	}
}

func TestSignalProfileBands(t *testing.T) {
	cases := []struct {
		paise int64
		band  string
	}{{50_000, "lt_1k"}, {500_000, "1k_10k"}, {5_000_000, "10k_1l"}, {50_000_000, "gte_1l"}}
	for _, c := range cases {
		if got := amountBand(c.paise); got != c.band {
			t.Errorf("amountBand(%d) = %s, want %s", c.paise, got, c.band)
		}
	}
	// 2026-09-01 14:30 UTC is 20:00 IST.
	if got := dayPart(BatchNow()); got != "evening" {
		t.Fatalf("dayPart(BatchNow) = %s, want evening", got)
	}
}

// ------------------------------------------------------------ recovery head

func example(flow FlowType, reason ReasonBucket, method string, at int64, recovered bool) RecoveryExample {
	return RecoveryExample{
		Profile:   SignalProfile{EventID: string(flow) + string(reason), Flow: flow, Reason: reason, Method: method, AmountBand: "1k_10k", OccurredAt: at},
		Recovered: recovered,
	}
}

func TestRecoveryModelUnseenProfileFallsBackToBaseRate(t *testing.T) {
	examples := []RecoveryExample{
		example(FlowFailedSubscription, ReasonInsufficientFunds, "upi", 1, true),
		example(FlowFailedSubscription, ReasonInsufficientFunds, "upi", 2, false),
		example(FlowCheckoutAbandonment, ReasonAddressAbandoned, "n/a", 3, false),
		example(FlowCheckoutAbandonment, ReasonAddressAbandoned, "n/a", 4, false),
	}
	m := TrainRecoveryModel(examples, 4)

	pred := m.Predict(SignalProfile{Flow: FlowPromiseToPay, Reason: ReasonPtpBroken, Method: "n/a", AmountBand: "lt_1k"})

	if pred.Probability != 0.25 || m.BaseRate != 0.25 {
		t.Fatalf("unseen profile = %.3f, base rate = %.3f; want both 0.25", pred.Probability, m.BaseRate)
	}
	for _, step := range pred.Path {
		if step.Observations != 0 {
			t.Fatalf("unseen profile reported observations: %+v", step)
		}
	}
}

func TestRecoveryModelShrinksSmallSamplesTowardCoarserLevels(t *testing.T) {
	var examples []RecoveryExample
	for i := 0; i < 50; i++ {
		examples = append(examples, example(FlowFailedSubscription, ReasonInsufficientFunds, "upi", int64(i), i%2 == 0))
	}
	// A single perfect observation for a rare method must not jump to 1.0.
	examples = append(examples, example(FlowFailedSubscription, ReasonInsufficientFunds, "netbanking", 99, true))
	m := TrainRecoveryModel(examples, DefaultRecoverySmoothing)

	rare := m.Predict(SignalProfile{Flow: FlowFailedSubscription, Reason: ReasonInsufficientFunds, Method: "netbanking", AmountBand: "1k_10k"}).Probability

	if rare >= 0.7 || rare <= 0.5 {
		t.Fatalf("one observation moved the estimate to %.3f; want shrinkage close to ~0.5", rare)
	}
}

func TestRecoveryModelPathEndsAtThePrediction(t *testing.T) {
	m := TrainRecoveryModel([]RecoveryExample{
		example(FlowMandateRetry, ReasonMandateBankDown, "upi", 1, true),
		example(FlowMandateRetry, ReasonMandateBankDown, "upi", 2, true),
		example(FlowMandateRetry, ReasonMandateInsufficient, "upi", 3, false),
	}, 2)

	pred := m.Predict(SignalProfile{Flow: FlowMandateRetry, Reason: ReasonMandateBankDown, Method: "upi", AmountBand: "1k_10k"})

	if len(pred.Path) != len(recoveryBackoffLevels) {
		t.Fatalf("path has %d steps, want %d", len(pred.Path), len(recoveryBackoffLevels))
	}
	if last := pred.Path[len(pred.Path)-1]; last.Estimate != pred.Probability {
		t.Fatalf("path ends at %.4f, prediction is %.4f", last.Estimate, pred.Probability)
	}
	if pred.Probability <= m.BaseRate {
		t.Fatalf("a reason that always recovered should score above the base rate: %.3f vs %.3f", pred.Probability, m.BaseRate)
	}
}

// ---------------------------------------------------------------- evaluation

func TestSplitOutOfTimeNeverPutsTheSameTimestampOnBothSides(t *testing.T) {
	var examples []RecoveryExample
	for day := int64(0); day < 10; day++ {
		for k := 0; k < 3; k++ {
			ex := example(FlowFailedSubscription, ReasonInsufficientFunds, "upi", day*86_400_000, k == 0)
			ex.Profile.EventID = string(rune('a'+day)) + string(rune('0'+k))
			examples = append(examples, ex)
		}
	}

	train, test, splitAt := SplitOutOfTime(examples, 0.7)

	if len(train)+len(test) != len(examples) || len(train) == 0 || len(test) == 0 {
		t.Fatalf("bad split sizes: train=%d test=%d", len(train), len(test))
	}
	for _, ex := range train {
		if ex.Profile.OccurredAt >= splitAt {
			t.Fatalf("training example at %d is not before the split %d", ex.Profile.OccurredAt, splitAt)
		}
	}
	for _, ex := range test {
		if ex.Profile.OccurredAt < splitAt {
			t.Fatalf("test example at %d is before the split %d", ex.Profile.OccurredAt, splitAt)
		}
	}
}

func TestMetricHelpers(t *testing.T) {
	perfect := []float64{0.9, 0.8, 0.2, 0.1}
	labels := []bool{true, true, false, false}
	if got := auc(perfect, labels); got != 1 {
		t.Fatalf("auc(perfect) = %v, want 1", got)
	}
	if got := auc([]float64{0.5, 0.5, 0.5, 0.5}, labels); got != 0.5 {
		t.Fatalf("auc(all ties) = %v, want 0.5", got)
	}
	if got := auc([]float64{0.1, 0.2}, []bool{true, true}); got != 0.5 {
		t.Fatalf("auc(single class) = %v, want 0.5", got)
	}
	if got := brier([]float64{1, 0}, []bool{true, false}); got != 0 {
		t.Fatalf("brier(perfect) = %v, want 0", got)
	}
	if got := logLoss([]float64{0, 1}, []bool{true, false}); math.IsInf(got, 0) || math.IsNaN(got) {
		t.Fatalf("log loss must stay finite on 0/1 predictions, got %v", got)
	}
	// Flag the lowest 50%: both are failures -> precision 1.
	if got := precisionAtVolume(perfect, labels, 0.5); got != 1 {
		t.Fatalf("precisionAtVolume = %v, want 1", got)
	}
	bins := calibrationBins([]float64{0.05, 0.95, 1.0}, []bool{false, true, true})
	if bins[0].Count != 1 || bins[CalibrationBins-1].Count != 2 {
		t.Fatalf("probability 1.0 must land in the last bin: %+v", bins)
	}
}

func TestOutOfTimeEvaluationBeatsTheIncumbentOnTheSameTestSet(t *testing.T) {
	intel := trainedIntelligence(t)
	ev := intel.Evaluation

	if ev.Strategy != "out_of_time" || ev.TrainCount == 0 || ev.TestCount == 0 {
		t.Fatalf("evaluation did not run out-of-time: %+v", ev)
	}
	if ev.TrainCount+ev.TestCount != intel.HistoryEvents {
		t.Fatalf("split lost events: %d + %d != %d", ev.TrainCount, ev.TestCount, intel.HistoryEvents)
	}
	if ev.Learned.Brier >= ev.Incumbent.Brier || ev.Learned.AUC <= ev.Incumbent.AUC {
		t.Fatalf("learned head does not beat the incumbent: learned %+v vs incumbent %+v",
			[]float64{ev.Learned.Brier, ev.Learned.AUC}, []float64{ev.Incumbent.Brier, ev.Incumbent.AUC})
	}
	if ev.Learned.ECE > 0.1 {
		t.Fatalf("learned head is poorly calibrated out-of-time: ECE %.3f", ev.Learned.ECE)
	}
	if len(ev.Learned.Slices) != len(FlowTypes) {
		t.Fatalf("evaluation has %d flow slices, want %d", len(ev.Learned.Slices), len(FlowTypes))
	}
	binTotal := 0
	for _, b := range ev.Learned.Bins {
		binTotal += b.Count
	}
	if binTotal != ev.TestCount {
		t.Fatalf("calibration bins hold %d examples, want %d", binTotal, ev.TestCount)
	}
	for _, point := range ev.AlertVolumes {
		if point.LearnedPrecision < point.IncumbentPrecision {
			t.Fatalf("at %.0f%% alert volume the learned head flags fewer real failures: %+v", point.Volume*100, point)
		}
	}
}

func TestTrainingIsDeterministic(t *testing.T) {
	first := trainedIntelligence(t)
	second, err := TrainIntelligence(IntelligenceHistorySeed, IntelligenceHistoryCount)
	if err != nil {
		t.Fatal(err)
	}

	if first.Model.BaseRate != second.Model.BaseRate || first.Evaluation.Learned.Brier != second.Evaluation.Learned.Brier {
		t.Fatalf("training is not reproducible: %.6f/%.6f vs %.6f/%.6f",
			first.Model.BaseRate, first.Evaluation.Learned.Brier, second.Model.BaseRate, second.Evaluation.Learned.Brier)
	}
}

// ---------------------------------------------------------------- work queue

func TestWorkQueueNeverRanksBlockedEventsAboveEligibleWork(t *testing.T) {
	intel := trainedIntelligence(t)
	events := GenerateEvents(BatchNow())

	queue := BuildWorkQueue(events, nil, intel.Model)

	if len(queue) != len(events) {
		t.Fatalf("queue has %d items, want %d", len(queue), len(events))
	}
	seenBlocked := false
	for i, it := range queue {
		if it.Rank != i+1 {
			t.Fatalf("item %d has rank %d", i, it.Rank)
		}
		if it.FailureClass == FailureBlocked && it.Eligibility.Eligible {
			t.Fatalf("blocked failure %s is eligible", it.EventID)
		}
		if !it.Eligibility.Eligible {
			seenBlocked = true
			if !strings.HasPrefix(it.Recommendation, "no automated action") && !strings.HasPrefix(it.Recommendation, "none") {
				t.Fatalf("blocked item %s recommends %q", it.EventID, it.Recommendation)
			}
			continue
		}
		if seenBlocked {
			t.Fatalf("eligible item %s ranked after a blocked one", it.EventID)
		}
		if i > 0 && queue[i-1].Eligibility.Eligible && queue[i-1].ExpectedPaise < it.ExpectedPaise {
			t.Fatalf("queue not ordered by expected value at rank %d", it.Rank)
		}
	}
}

func TestWorkQueueRespectsLockedRulesFromTheAuditLog(t *testing.T) {
	intel := trainedIntelligence(t)
	ev := &FlowEvent{EventID: "evt_locked", Flow: FlowHinglishVoice, CustomerID: "c1", Amount: 100000, Signal: map[string]any{"call_state": "missed"}}
	log := []AuditEntry{{EventID: "evt_locked", RuleFired: RuleVoiceDoNotCall, State: AgentAbandoned}}

	queue := BuildWorkQueue([]*FlowEvent{ev}, log, intel.Model)

	if queue[0].Eligibility.Eligible || queue[0].Eligibility.BlockingRule != string(RuleVoiceDoNotCall) {
		t.Fatalf("DNC-locked event is still eligible: %+v", queue[0].Eligibility)
	}
}

func TestWorkQueueExcludesAlreadyRecoveredEvents(t *testing.T) {
	intel := trainedIntelligence(t)
	ev := &FlowEvent{EventID: "evt_done", Flow: FlowFailedSubscription, CustomerID: "c2", Amount: 100000, Signal: map[string]any{"error_code": "CARD_DECLINED"}}
	log := []AuditEntry{{EventID: "evt_done", RuleFired: RuleRecovered, State: AgentRecovered}}

	queue := BuildWorkQueue([]*FlowEvent{ev}, log, intel.Model)

	if queue[0].Eligibility.Eligible || queue[0].Eligibility.Reason != "already recovered" {
		t.Fatalf("recovered event still queued: %+v", queue[0].Eligibility)
	}
}

// ---------------------------------------------------------------- health

func touchRow(event string, attempt int, channel string, state AgentState) AuditEntry {
	return AuditEntry{EventID: event, Actor: ActorPolicyEngine, Channel: channel, Attempt: intp(attempt), State: state}
}

func TestChannelOutcomesCountsEachTouchOnce(t *testing.T) {
	log := []AuditEntry{
		touchRow("e1", 0, "email", AgentRecovered), // action row
		touchRow("e1", 0, "email", AgentRecovered), // recovered row for the same touch
		touchRow("e2", 0, "email", AgentContacting),
		touchRow("e2", 1, "whatsapp", AgentContacting),
		{EventID: "e3", Actor: ActorLLMCopy, Channel: "email", Attempt: intp(0), State: AgentEscalated}, // not a touch
	}

	got := channelOutcomes(log)

	if got["email"].n != 2 || got["email"].pos != 1 || got["whatsapp"].n != 1 {
		t.Fatalf("channel outcomes = %+v", got)
	}
}

func TestHealthFlagsADegradedChannelAgainstItsBaseline(t *testing.T) {
	var history, recent []AuditEntry
	for i := 0; i < 10; i++ {
		history = append(history, touchRow("h"+itoa(i), 0, "sms", AgentRecovered))
		state := AgentContacting
		if i == 0 {
			state = AgentRecovered
		}
		recent = append(recent, touchRow("r"+itoa(i), 0, "sms", state))
	}
	recent = append(recent, touchRow("x", 0, "voice", AgentRecovered))

	report := BuildHealthReport(recent, history, nil)

	status := map[string]string{}
	for _, c := range report.Channels {
		status[c.Channel] = c.Status
	}
	if status["sms"] != HealthDegraded {
		t.Fatalf("sms at 10%% vs a 100%% baseline should be degraded: %+v", report.Channels)
	}
	if status["voice"] != HealthInsufficient {
		t.Fatalf("one voice touch is not enough data: %+v", report.Channels)
	}
}

func TestHealthReadsRouteSignalsFromDegradationEvents(t *testing.T) {
	events := []*FlowEvent{
		{EventID: "d1", Flow: FlowPaymentDegradation, Signal: map[string]any{"success_rate": 0.6, "latency_ms": 900.0}},
		{EventID: "d2", Flow: FlowPaymentDegradation, Signal: map[string]any{"success_rate": 0.97, "latency_ms": 300.0}},
		{EventID: "s1", Flow: FlowFailedSubscription, Signal: map[string]any{}},
	}

	report := BuildHealthReport(nil, nil, events)

	if len(report.Routes) != 2 || report.Routes[0].Status != HealthDegraded || report.Routes[1].Status != HealthHealthy {
		t.Fatalf("route signals = %+v", report.Routes)
	}
}

// ---------------------------------------------------------------- progress

func TestRecoveryProgressBucketsLatestStatePerEvent(t *testing.T) {
	log := []AuditEntry{
		{EventID: "a", Amount: i64p(10000), State: AgentRetryScheduled},
		{EventID: "a", Amount: i64p(10000), State: AgentRecovered},
		{EventID: "b", Amount: i64p(20000), State: AgentEscalated},
		{EventID: "c", Amount: i64p(30000), State: AgentWaitingOnPtp},
		{EventID: "c", Amount: i64p(30000), RuleFired: RuleDuplicateSuppress, State: AgentSuppressed},
		{EventID: "pay", Amount: i64p(99999), Flow: FlowPaymentEvent, State: AgentRecovered},
	}

	p := ComputeRecoveryProgress(log)

	if p.TotalEvents != 3 || p.TotalAtRisk != 600 {
		t.Fatalf("totals = %d events / ₹%.2f, want 3 / ₹600", p.TotalEvents, p.TotalAtRisk)
	}
	if p.Outcomes["recovered"].Count != 1 || p.Outcomes["escalated"].Rupees != 200 || p.Outcomes["in_flight"].Count != 1 {
		t.Fatalf("outcomes = %+v", p.Outcomes)
	}
	if p.InFlightStates["waiting_on_ptp"] != 1 {
		t.Fatalf("in-flight states = %+v", p.InFlightStates)
	}
}

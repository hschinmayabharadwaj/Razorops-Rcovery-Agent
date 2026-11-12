package rz

import (
	"path/filepath"
	"strings"
	"testing"
)

func testEvents(t *testing.T) []*FlowEvent {
	t.Helper()
	return GenerateEvents(BatchNow())
}

func TestRiskScoreFactors_High(t *testing.T) {
	s := riskScore(RiskInput{History: CustomerHistory{
		PriorDeclineCount90d:    3,
		MandateAgeDays:          10,
		DaysSinceLastDecline:    1,
		PriorChargebackCount90d: 1,
	}})
	if s.Decision != RiskHigh {
		t.Fatalf("decision=%s, want high", s.Decision)
	}
	if !IsHighRisk(s) {
		t.Fatal("isHighRisk false")
	}
	if len(s.Factors) < 3 {
		t.Fatalf("factors=%d, want >=3", len(s.Factors))
	}
	keys := map[string]bool{}
	for _, f := range s.Factors {
		keys[f.Key] = true
	}
	for _, want := range []string{"prior_decline_count_90d", "days_since_last_decline", "mandate_age_days"} {
		if !keys[want] {
			t.Fatalf("missing factor %s; got %v", want, keys)
		}
	}
}

func TestRiskScoreFactors_Low(t *testing.T) {
	s := riskScore(RiskInput{History: CustomerHistory{
		PriorDeclineCount90d:    0,
		MandateAgeDays:          200,
		DaysSinceLastDecline:    60,
		PriorChargebackCount90d: 0,
	}})
	if s.Decision != RiskLow {
		t.Fatalf("decision=%s, want low", s.Decision)
	}
	if IsHighRisk(s) {
		t.Fatal("isHighRisk true for clean history")
	}
}

func TestRiskScoreFactors_CardExpiry(t *testing.T) {
	d := 20
	factors := computeRiskFactors(CustomerHistory{
		PriorDeclineCount90d:    0,
		MandateAgeDays:          200,
		DaysSinceLastDecline:    60,
		PriorChargebackCount90d: 0,
		CardExpiresWithinDays:   &d,
	})
	found := false
	for _, f := range factors {
		if f.Key == "card_expiry_within_60d" {
			found = true
		}
	}
	if !found {
		t.Fatal("missing card_expiry_within_60d factor")
	}
}

func TestRiskScoreClamped(t *testing.T) {
	s := riskScore(RiskInput{History: CustomerHistory{
		PriorDeclineCount90d:    99,
		MandateAgeDays:          0,
		DaysSinceLastDecline:    0,
		PriorChargebackCount90d: 99,
	}})
	if s.Score > 100 || s.Score < 0 {
		t.Fatalf("score=%v out of [0,100]", s.Score)
	}
}

func TestDerivedHistoryDeterministic(t *testing.T) {
	ev := &FlowEvent{
		CustomerID: "cust_abc_00042",
		Signal:     map[string]any{"error_reason": "expired_card"},
	}
	a := DeriveHistory(ev)
	b := DeriveHistory(ev)
	if a.PriorDeclineCount90d != b.PriorDeclineCount90d ||
		a.MandateAgeDays != b.MandateAgeDays ||
		a.DaysSinceLastDecline != b.DaysSinceLastDecline ||
		a.PriorChargebackCount90d != b.PriorChargebackCount90d {
		t.Fatalf("deriveHistory not deterministic: %+v vs %+v", a, b)
	}
	// expired_card signal -> daysSinceLastDecline 1
	if a.DaysSinceLastDecline != 1 {
		t.Fatalf("daysSinceLastDecline=%d, want 1 for expired_card", a.DaysSinceLastDecline)
	}
}

func TestPrescoreReportOverBatch(t *testing.T) {
	events := testEvents(t)
	now := BatchNow()

	audit, err := NewAuditStore(filepath.Join(t.TempDir(), "prescore.log.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if err := audit.Clear(); err != nil {
		t.Fatal(err)
	}
	if _, err := RunBatch(events, audit, RunnerOpts{Now: now}); err != nil {
		t.Fatal(err)
	}
	all, err := audit.All()
	if err != nil {
		t.Fatal(err)
	}
	report := ComputePrescoreReport(events, all, 0)

	if report.TotalEvents != len(events) {
		t.Fatalf("totalEvents=%d, want %d", report.TotalEvents, len(events))
	}
	for _, r := range report.Rows {
		if r.Score < 0 || r.Score > 100 {
			t.Fatalf("row %s score=%d out of range", r.EventId, r.Score)
		}
		if r.HighRiskBefore != (r.Score >= RISK_THRESHOLD_HIGH) {
			t.Fatalf("row %s highRiskBefore=%v but score=%d", r.EventId, r.HighRiskBefore, r.Score)
		}
		if !(r.Recovered || r.FailedToRecover) {
			t.Fatalf("row %s neither recovered nor failed", r.EventId)
		}
	}
}

func TestPrescoreEmitVerifiesChain(t *testing.T) {
	events := testEvents(t)
	now := BatchNow()

	audit, err := NewAuditStore(filepath.Join(t.TempDir(), "prescore.emit.log.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if err := audit.Clear(); err != nil {
		t.Fatal(err)
	}
	if _, err := RunBatch(events, audit, RunnerOpts{Now: now}); err != nil {
		t.Fatal(err)
	}
	base, err := audit.All()
	if err != nil {
		t.Fatal(err)
	}
	report := ComputePrescoreReport(events, base, 0)
	EmitPrescoreAudit(report, audit)
	all, err := audit.All()
	if err != nil {
		t.Fatal(err)
	}
	check := VerifyChain(all)
	if !check.Valid {
		t.Fatalf("chain broken at %d after prescore emit", check.BrokenAtIndex)
	}
	if check.Entries <= len(events) {
		t.Fatalf("entries=%d, want > %d events", check.Entries, len(events))
	}
}

func TestPrescoreHeadline(t *testing.T) {
	report := ComputePrescoreReport(testEvents(t), nil, 0)
	if !strings.Contains(report.Headline, "%") {
		t.Fatal("headline should reference percentages")
	}
	if report.Recall < 0 || report.Recall > 1 || report.Precision < 0 || report.Precision > 1 {
		t.Fatalf("recall=%v precision=%v out of [0,1]", report.Recall, report.Precision)
	}
}

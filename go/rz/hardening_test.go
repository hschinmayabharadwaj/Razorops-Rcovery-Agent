package rz

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

// newTestServer builds a streamServer over a fresh audit log in a temp dir.
func newTestServer(t *testing.T, events []*FlowEvent) *streamServer {
	t.Helper()
	audit, err := NewAuditStore(filepath.Join(t.TempDir(), "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	return &streamServer{audit: audit, hub: NewStreamHub(), mode: ModeSandbox, events: events}
}

func postJSON(t *testing.T, handler http.HandlerFunc, key, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.Header.Set("X-API-Key", key)
	rec := httptest.NewRecorder()
	handler(rec, req)
	return rec
}

func decodeAdminResponse(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response: %v (body=%s)", err, rec.Body.String())
	}
	return out
}

func TestAdminNudgeRefusedForFraudEvenWhenLatestRowIsNoOp(t *testing.T) {
	// Arrange: a fraud event whose latest audit row hides the locked rule.
	event := &FlowEvent{
		EventID: "evt_fraud", Flow: FlowFailedSubscription, CustomerID: "cust_1",
		Amount: 10000, Currency: "INR", Signal: map[string]any{"error_code": "FRAUD_DETECTED"},
	}
	s := newTestServer(t, []*FlowEvent{event})
	rows := []AuditEntry{
		{EventID: "evt_fraud", Flow: FlowFailedSubscription, ReasonBucket: ReasonFraudFlagged,
			RuleFired: RuleFraudSuppress, Decision: DecisionSuppress, Actor: ActorPolicyEngine, State: AgentEscalated},
		{EventID: "evt_fraud", Flow: FlowFailedSubscription, ReasonBucket: ReasonBankDeclinedTransien,
			RuleFired: RuleNoOp, Decision: DecisionEscalate, Actor: ActorLLMCopy, State: AgentEscalated},
	}
	for _, r := range rows {
		if err := s.audit.Append(r); err != nil {
			t.Fatal(err)
		}
	}

	// Act
	rec := postJSON(t, s.handleAdminAction, "admin_key_demo", `{"eventId":"evt_fraud","action":"nudge_retry"}`)

	// Assert
	resp := decodeAdminResponse(t, rec)
	if resp["ok"] != false || resp["refusedBy"] != string(RuleFraudSuppress) {
		t.Fatalf("fraud nudge was not refused by the locked rule: %v", resp)
	}
}

func TestAdminNudgeRefusedForMandateRevokedByReasonBucket(t *testing.T) {
	event := &FlowEvent{
		EventID: "evt_mandate", Flow: FlowMandateRetry, CustomerID: "cust_2",
		Amount: 5000, Currency: "INR", Signal: map[string]any{"error_code": "MANDATE_REVOKED"},
	}
	s := newTestServer(t, []*FlowEvent{event})
	if err := s.audit.Append(AuditEntry{
		EventID: "evt_mandate", Flow: FlowMandateRetry, ReasonBucket: ReasonMandateRevoked,
		RuleFired: RuleNoOp, Decision: DecisionEscalate, Actor: ActorLLMCopy, State: AgentEscalated,
	}); err != nil {
		t.Fatal(err)
	}

	rec := postJSON(t, s.handleAdminAction, "admin_key_demo", `{"eventId":"evt_mandate","action":"select_recovery_channel","channel":"sms"}`)

	resp := decodeAdminResponse(t, rec)
	if resp["ok"] != false || resp["refusedBy"] != string(RuleMandateRevokedEsc) {
		t.Fatalf("mandate_revoked override was not refused: %v", resp)
	}
}

func TestAdminNudgeAllowedForRetryableEvent(t *testing.T) {
	event := &FlowEvent{
		EventID: "evt_ok", Flow: FlowFailedSubscription, CustomerID: "cust_3",
		Amount: 7000, Currency: "INR", Signal: map[string]any{"error_code": "CARD_DECLINED"},
	}
	s := newTestServer(t, []*FlowEvent{event})
	if err := s.audit.Append(AuditEntry{
		EventID: "evt_ok", Flow: FlowFailedSubscription, ReasonBucket: ReasonInsufficientFunds,
		RuleFired: RuleTransientRetry, Decision: DecisionRetry, Actor: ActorPolicyEngine, State: AgentRetryScheduled,
	}); err != nil {
		t.Fatal(err)
	}

	rec := postJSON(t, s.handleAdminAction, "admin_key_demo", `{"eventId":"evt_ok","action":"nudge_retry"}`)

	resp := decodeAdminResponse(t, rec)
	if resp["ok"] != true || resp["decision"] != string(DecisionRetry) {
		t.Fatalf("retryable nudge should be allowed: %v", resp)
	}
}

func TestPaymentEventRejectsReadOnlyCredential(t *testing.T) {
	s := newTestServer(t, nil)
	body := `{"eventId":"pay_1","eventType":"payment.verified","state":"verified","details":"{}"}`

	if rec := postJSON(t, s.handlePaymentEvent, "audit_key_demo", body); rec.Code != http.StatusForbidden {
		t.Fatalf("auditor write got status %d, want 403", rec.Code)
	}
	if rec := postJSON(t, s.handlePaymentEvent, "admin_key_demo", body); rec.Code != http.StatusOK {
		t.Fatalf("admin write got status %d, want 200", rec.Code)
	}
}

func TestPaymentEventLargeDetailsKeepsLogReadable(t *testing.T) {
	s := newTestServer(t, nil)
	details := strings.Repeat("x", 60*1024)
	body, err := json.Marshal(map[string]string{"eventId": "pay_big", "eventType": "payment.verified", "state": "verified", "details": details})
	if err != nil {
		t.Fatal(err)
	}

	if rec := postJSON(t, s.handlePaymentEvent, "admin_key_demo", string(body)); rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", rec.Code)
	}

	entries, err := s.audit.All()
	if err != nil {
		t.Fatalf("log unreadable after large payment event: %v", err)
	}
	if len(entries) != 1 || len(entries[0].Outcome) > maxPaymentDetailsBytes+32 {
		t.Fatalf("details not bounded: entries=%d outcomeLen=%d", len(entries), len(entries[0].Outcome))
	}
}

func TestStoreReadsLinesLongerThanDefaultScannerLimit(t *testing.T) {
	audit, err := NewAuditStore(filepath.Join(t.TempDir(), "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	long := baseEntry(nil)
	long.Outcome = strings.Repeat("y", 100*1024)
	if err := audit.Append(long); err != nil {
		t.Fatal(err)
	}
	if err := audit.Append(baseEntry(nil)); err != nil {
		t.Fatalf("append after a long line failed: %v", err)
	}

	entries, err := audit.All()
	if err != nil || len(entries) != 2 {
		t.Fatalf("entries=%d err=%v, want 2 entries", len(entries), err)
	}
	if v := VerifyChain(entries); !v.Valid {
		t.Fatalf("chain broken at %d", v.BrokenAtIndex)
	}
}

func TestRedactPIIDoesNotLeakDegenerateShapes(t *testing.T) {
	out := RedactPII(map[string]any{
		"customerEmail": "not-an-email-secret",
		"customerName":  "Madonna",
		"customerPhone": "98765",
	})

	if strings.Contains(out["customerEmail"].(string), "secret") {
		t.Fatalf("email without @ leaked: %q", out["customerEmail"])
	}
	if strings.Contains(out["customerName"].(string), "adonna") {
		t.Fatalf("single-word name leaked: %q", out["customerName"])
	}
	if strings.Contains(out["customerPhone"].(string), "987") {
		t.Fatalf("short phone leaked: %q", out["customerPhone"])
	}
}

func TestLoadTunablesFileIsAllOrNothing(t *testing.T) {
	defer ResetTunables()
	ResetTunables()
	// Several valid keys plus one invalid value: nothing may be applied,
	// whatever order the map is iterated in.
	p := writeTunables(t, `{"max_retry_attempts":9,"max_touches_cap":9,"checkout_reminder_cap":9,"mandate_retry_window":9,"voice_call_cap":-1}`)

	if _, err := LoadTunablesFile(p); err == nil {
		t.Fatal("config with a negative value was accepted")
	}

	if got := GetTunables(); got != DefaultTunables() {
		t.Fatalf("partial application leaked: %+v", got)
	}
}

// ptpContext is a committed promise-to-pay whose date is still in the future.
func ptpContext(amount int64) *RecoveryContext {
	now := BatchNow()
	ptpDate := now + 5*24*3600*1000
	return &RecoveryContext{
		EventID: "evt_ptp", Flow: FlowPromiseToPay, CustomerID: "cust_ptp", Amount: amount,
		Currency: "INR", Reason: ReasonPtpCommitted, Now: now, ActivePromiseToPayDate: &ptpDate,
	}
}

func TestStepStateEscalatesHighValuePtpForSupervisorSignOff(t *testing.T) {
	defer ResetTunables()
	ResetTunables()
	threshold := GetTunables().PtpSupervisorThreshold

	atThreshold, err := StepState(ptpContext(threshold))
	if err != nil {
		t.Fatal(err)
	}
	belowThreshold, err := StepState(ptpContext(threshold - 1))
	if err != nil {
		t.Fatal(err)
	}

	if atThreshold.Next.Decision != DecisionEscalate || atThreshold.Next.RuleFired != RulePtpMissedEscalate {
		t.Fatalf("PTP at the supervisor threshold was not escalated: %+v", atThreshold.Next)
	}
	if belowThreshold.Next.Decision != DecisionSuppress || belowThreshold.Next.RuleFired != RulePtpSuppress {
		t.Fatalf("PTP below the threshold should be suppressed until its date: %+v", belowThreshold.Next)
	}
}

func TestStepStateSupervisorThresholdIsTunable(t *testing.T) {
	defer ResetTunables()
	ResetTunables()
	amount := GetTunables().PtpSupervisorThreshold
	SetTunableField(func(tc *TunableConfig) { tc.PtpSupervisorThreshold = amount + 1 })

	step, err := StepState(ptpContext(amount))
	if err != nil {
		t.Fatal(err)
	}

	if step.Next.Decision == DecisionEscalate {
		t.Fatalf("raising the threshold above the amount should stop the escalation: %+v", step.Next)
	}
}

func TestMetricsIgnoreForwardedPaymentEvents(t *testing.T) {
	recovered := baseEntry(nil)
	recovered.State = AgentRecovered
	recovered.Amount = i64p(10000)
	payment := AuditEntry{
		EventID: "payment.verified.pay_1", Flow: FlowPaymentEvent, RuleFired: RuleNoOp,
		Decision: DecisionNone, Actor: ActorPaymentGateway, State: AgentRecovered,
	}
	log := []AuditEntry{recovered, payment}

	m := ComputeMetrics(log)
	e := ComputeEligibility(log)

	if m.TotalEvents != 1 || m.RecoveredCount != 1 {
		t.Fatalf("payment event counted in metrics: total=%d recovered=%d", m.TotalEvents, m.RecoveredCount)
	}
	if e.EligibleRecovered != 1 || e.EligibleEvents != 1 {
		t.Fatalf("payment event counted in eligibility: %+v", e)
	}
}

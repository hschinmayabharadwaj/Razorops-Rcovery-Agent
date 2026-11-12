package rz

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// allowedOrigins returns the CORS allow-list from the ALLOWED_ORIGIN env var
// (comma-separated). If unset, all origins are allowed (demo default — harden
// before production by setting ALLOWED_ORIGIN to the Blazor UI origin).
func allowedOrigins() map[string]bool {
	raw := strings.TrimSpace(os.Getenv("ALLOWED_ORIGIN"))
	if raw == "" {
		return map[string]bool{"*": true}
	}
	out := map[string]bool{}
	for _, o := range strings.Split(raw, ",") {
		if o = strings.TrimSpace(o); o != "" {
			out[o] = true
		}
	}
	return out
}

func originAllowed(origins map[string]bool, origin string) bool {
	if origins["*"] {
		return true
	}
	return origins[origin]
}

// withCORS wraps a handler with CORS headers so browser clients (and any future
// in-browser caller) can reach the API + SSE stream cross-origin.
func withCORS(next http.Handler) http.Handler {
	origins := allowedOrigins()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" && originAllowed(origins, origin) {
			if origins["*"] {
				w.Header().Set("Access-Control-Allow-Origin", "*")
			} else {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Add("Vary", "Origin")
			}
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-API-Key")
			w.Header().Set("Access-Control-Expose-Headers", "X-API-Key")
			w.Header().Set("Access-Control-Max-Age", "600")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		// Don't open up the SSE stream to every origin in a browser unless told.
		// The server still enforces deny-by-default X-API-Key auth on every route.
		next.ServeHTTP(w, r)
	})
}

// streamServer is a minimal stdlib net/http server (no framework) that exposes
// the live audit stream, chain verification, and the JSON adapter surfaces for
// the Blazor frontend. It reads state from the audit store and pushes events
// over the hub. It performs NO rule evaluation or policy decision of its own —
// every number it returns is produced by the existing Go logic (ComputeMetrics,
// ComparePolicies, ComputePrescoreReport, RunSandbox, VerifyChain). It only
// shapes those results into JSON and applies the deny-by-default role gate.

// Size bounds for a forwarded payment event (see handlePaymentEvent).
const (
	maxPaymentEventIDBytes   = 128
	maxPaymentEventTypeBytes = 64
	maxPaymentDetailsBytes   = 2048
)

// readHeaderTimeout bounds how long a client may take to send request headers
// (slow-loris guard). No write timeout is set: /events is a long-lived stream.
const readHeaderTimeout = 10 * time.Second

type streamServer struct {
	audit     *AuditStore
	hub       *StreamHub
	mode      ExecutionMode
	events    []*FlowEvent
	computeMu sync.Mutex
}

// StartStreamServer binds an HTTP server on addr (e.g. ":8090") and serves in a
// background goroutine. The returned *http.Server can be Shutdown'ed by the
// caller; the caller is responsible for keeping the process alive. Events are
// loaded on demand from data/flows for the compute-heavy endpoints.
func StartStreamServer(audit *AuditStore, hub *StreamHub, addr string) (*http.Server, error) {
	s := &streamServer{audit: audit, hub: hub, mode: ModeSandbox}
	if evts, err := LoadEvents("data/flows"); err == nil {
		s.events = evts
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/events", s.handleEvents)
	mux.HandleFunc("/chain-status", s.handleChainStatus)
	mux.HandleFunc("/metrics", s.handleMetrics)
	mux.HandleFunc("/exceptions", s.handleExceptions)
	mux.HandleFunc("/compare-policy", s.handleComparePolicy)
	mux.HandleFunc("/prescore", s.handlePrescore)
	mux.HandleFunc("/sandbox", s.handleSandbox)
	mux.HandleFunc("/demo/tamper", s.handleTamper)
	mux.HandleFunc("/payment-event", s.handlePaymentEvent)
	mux.HandleFunc("/admin/action", s.handleAdminAction)

	srv := &http.Server{Addr: addr, Handler: withCORS(mux), ReadHeaderTimeout: readHeaderTimeout}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			fmt.Fprintln(os.Stderr, "stream-server: serve:", err)
		}
	}()
	return srv, nil
}

// handleEvents is the Server-Sent Events endpoint.
func (s *streamServer) handleEvents(w http.ResponseWriter, r *http.Request) {
	if _, ok := auth(w, r, ActionReadAuditLog); !ok {
		return
	}
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	ch := s.hub.Subscribe()
	defer s.hub.Unsubscribe(ch)

	// Replay existing entries first so a freshly-connected client sees the
	// full audit history before it switches to live events.
	if entries, err := s.audit.All(); err == nil {
		for _, e := range entries {
			b, merr := json.Marshal(streamEvent{EventType: "audit", AuditEntry: e})
			if merr != nil {
				continue
			}
			fmt.Fprintf(w, "data: %s\n\n", b)
			fl.Flush()
		}
	} else {
		fmt.Fprintf(w, "data: %s\n\n", `{"eventType":"chain_status","valid":false,"entries":0,"brokenAt":null}`)
		fl.Flush()
	}

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case payload, ok := <-ch:
			if !ok {
				return
			}
			fmt.Fprintf(w, "data: %s\n\n", payload)
			fl.Flush()
		}
	}
}

type chainStatus struct {
	Valid    bool `json:"valid"`
	Entries  int  `json:"entries"`
	BrokenAt *int `json:"brokenAt"`
}

// handleChainStatus calls VerifyChain on demand and returns plain JSON.
func (s *streamServer) handleChainStatus(w http.ResponseWriter, r *http.Request) {
	if _, ok := auth(w, r, ActionVerifyAnchor); !ok {
		return
	}
	entries, err := s.audit.All()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	v := VerifyChain(entries)
	status := chainStatus{Valid: v.Valid, Entries: v.Entries}
	if !v.Valid {
		n := v.BrokenAtIndex
		status.BrokenAt = &n
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(status)
}

// handleMetrics returns the metrics dashboard (including the eligible-vs-blocked
// segmentation) computed from the current audit log.
func (s *streamServer) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if _, ok := auth(w, r, ActionReadAuditLog); !ok {
		return
	}
	log, err := s.audit.All()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error(), "", "")
		return
	}
	m := ComputeMetrics(log)
	resp := buildMetricsJSON(m)
	resp.Eligibility = ComputeEligibility(log)
	writeJSON(w, http.StatusOK, resp)
}

// handleExceptions returns the human-review exception list, PII-redacted
// server-side.
func (s *streamServer) handleExceptions(w http.ResponseWriter, r *http.Request) {
	if _, ok := auth(w, r, ActionReadExceptionList); !ok {
		return
	}
	log, err := s.audit.All()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error(), "", "")
		return
	}
	m := ComputeMetrics(log)
	writeJSON(w, http.StatusOK, map[string]any{
		"exceptions": buildExceptionsJSON(m.ExceptionList),
	})
}

// handleComparePolicy re-runs the real-vs-naive comparison and returns it as
// JSON.
func (s *streamServer) handleComparePolicy(w http.ResponseWriter, r *http.Request) {
	if _, ok := auth(w, r, ActionReadAuditLog); !ok {
		return
	}
	if s.events == nil {
		writeError(w, http.StatusInternalServerError, "events not loaded", "", "")
		return
	}
	s.computeMu.Lock()
	defer s.computeMu.Unlock()
	realAudit, err := NewAuditStore("data/audit.real.jsonl")
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error(), "", "")
		return
	}
	naiveAudit, err := NewAuditStore("data/audit.naive.jsonl")
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error(), "", "")
		return
	}
	c, err := ComparePolicies(s.events, realAudit, naiveAudit, BatchNow())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error(), "", "")
		return
	}
	v := c.Violations
	writeJSON(w, http.StatusOK, comparisonJSON{
		Real:              buildMetricsJSON(c.Real),
		Naive:             buildMetricsJSON(c.Naive),
		TotalNaiveTouches: c.TotalNaiveTouches,
		Takeaway:          c.Takeaway,
		Violations: violationsJSON{
			FraudRetries:           v.FraudRetries,
			MandateRetries:         v.MandateRetries,
			QuietHourCalls:         v.QuietHourCalls,
			DNcBreaches:            v.DNcBreaches,
			TouchCapBreaches:       v.TouchCapBreaches,
			RetryBudgetBreaches:    v.RetryBudgetBreaches,
			PtpSuppressionBreaches: v.PtpSuppressionBreaches,
			Total:                  v.Total,
		},
	})
}

// handlePrescore computes the risk-prescore report retroactively against the
// current audit log.
func (s *streamServer) handlePrescore(w http.ResponseWriter, r *http.Request) {
	if _, ok := auth(w, r, ActionReadAuditLog); !ok {
		return
	}
	if s.events == nil {
		writeError(w, http.StatusInternalServerError, "events not loaded", "", "")
		return
	}
	log, err := s.audit.All()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error(), "", "")
		return
	}
	report := ComputePrescoreReport(s.events, log, 0)
	writeJSON(w, http.StatusOK, buildPrescoreJSON(report))
}

// handleSandbox runs the tunable sweep and returns every scenario plus the
// locked-rule invariant. The optional ?scenario=X param selects which scenario
// is highlighted; all scenarios are returned for the comparison table.
func (s *streamServer) handleSandbox(w http.ResponseWriter, r *http.Request) {
	if _, ok := auth(w, r, ActionTuneSandbox); !ok {
		return
	}
	if s.events == nil {
		writeError(w, http.StatusInternalServerError, "events not loaded", "", "")
		return
	}
	s.computeMu.Lock()
	defer s.computeMu.Unlock()
	selected := r.URL.Query().Get("scenario")
	report, err := RunSandbox(s.events, BatchNow())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error(), "", "")
		return
	}
	writeJSON(w, http.StatusOK, buildSandboxJSON(report, selected))
}

// handleTamper is a demo-only endpoint gated behind an explicit ExecutionMode
// sandbox check (reusing the sandbox-isolation pattern from execution.go) AND
// the admin-only tune_sandbox role. It flips one field on an IN-MEMORY COPY of
// the log (never the real file), re-runs VerifyChain on the copy, and broadcasts
// the result as a chain_status event.
func (s *streamServer) handleTamper(w http.ResponseWriter, r *http.Request) {
	if _, ok := auth(w, r, ActionTuneSandbox); !ok {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.mode != ModeSandbox {
		http.Error(w, "demo tamper is sandbox-only", http.StatusForbidden)
		return
	}
	entries, err := s.audit.All()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	copy := make([]AuditEntry, len(entries))
	for i := range entries {
		copy[i] = entries[i]
	}
	if len(copy) > 0 {
		copy[0].Decision = DecisionEscalate
	}

	s.broadcastChainStatus(copy)
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte("{}"))
}

// broadcastChainStatus runs VerifyChain over the given (possibly tampered)
// copy and pushes the authoritative result to every subscriber.
func (s *streamServer) broadcastChainStatus(log []AuditEntry) {
	v := VerifyChain(log)
	s.hub.BroadcastStatus(v.Valid, v.Entries, v.BrokenAtIndex)
}

// handlePaymentEvent accepts a payment audit event forwarded by the Blazor
// PaymentAuditService and writes it into the Go audit store so it appears on
// the live SSE stream. The endpoint is intentionally simple: the C# app is the
// authority on payment verification; this side just persists and broadcasts.
func (s *streamServer) handlePaymentEvent(w http.ResponseWriter, r *http.Request) {
	// This endpoint WRITES to the audit log, so a read-only credential (auditor)
	// must not be able to call it: require the admin-intervention permission.
	if _, ok := auth(w, r, ActionAdminIntervention); !ok {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 64*1024))
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}

	var payload struct {
		EventID   string `json:"eventId"`
		EventType string `json:"eventType"`
		State     string `json:"state"`
		Details   string `json:"details"`
	}
	if err := json.Unmarshal(body, &payload); err != nil || payload.EventID == "" {
		http.Error(w, "invalid payload", http.StatusBadRequest)
		return
	}
	if len(payload.EventID) > maxPaymentEventIDBytes || len(payload.EventType) > maxPaymentEventTypeBytes {
		http.Error(w, "eventId or eventType too long", http.StatusBadRequest)
		return
	}
	// Bound the free-text field so one forwarded event can never produce an
	// oversized audit line.
	if len(payload.Details) > maxPaymentDetailsBytes {
		payload.Details = strings.ToValidUTF8(payload.Details[:maxPaymentDetailsBytes], "") + "…(truncated)"
	}

	// Map the payment state to the closest agent state.
	agentState := AgentDetected
	switch payload.State {
	case "verified":
		agentState = AgentRecovered
	case "rejected":
		agentState = AgentEscalated
	case "accepted":
		agentState = AgentDetected
	}

	entry := AuditEntry{
		EventID:      payload.EventID,
		Timestamp:    time.Now().UTC().Format(time.RFC3339),
		Flow:         FlowPaymentEvent,
		ReasonBucket: ReasonBucket(payload.EventType),
		RuleFired:    RuleNoOp,
		Decision:     DecisionNone,
		Actor:        ActorPaymentGateway,
		State:        agentState,
		Outcome:      payload.Details,
	}

	if err := s.audit.Append(entry); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"ok":true}`))
}

// lockedRuleFor reports the LOCKED compliance/safety rule (see LockedRuleIds)
// that blocks any admin override of the event, if one applies. It scans EVERY
// audit entry for the event rather than only the latest one: the latest row is
// often an LLM-copy or a previous admin row whose ruleFired is no_op, which
// would otherwise hide the locked rule that actually stopped the event. The
// reason bucket is checked too, so a fraud_flagged / mandate_revoked event is
// locked even in a flow whose engine reports it under a different rule name.
func lockedRuleFor(entries []AuditEntry, eventID string) (RuleId, bool) {
	for _, e := range entries {
		if e.EventID != eventID {
			continue
		}
		for _, id := range LockedRuleIds {
			if e.RuleFired == id {
				return id, true
			}
		}
		if IsFraudFlagged(e.ReasonBucket) {
			return RuleFraudSuppress, true
		}
		if IsMandateRevoked(e.ReasonBucket) {
			return RuleMandateRevokedEsc, true
		}
	}
	return "", false
}

// executedTouches counts the recovery actions already executed, per the audit
// log, for one event (its attempt number) and for its customer (the touch-cap
// input). An executed action is the row the runner writes after ExecuteAction:
// a policy-engine row in state retrying/contacting that carries a channel.
func executedTouches(entries []AuditEntry, eventID, customerID string) (attempts int, customerTouches int) {
	for _, e := range entries {
		if e.Actor != ActorPolicyEngine || e.Channel == "" {
			continue
		}
		if e.State != AgentRetrying && e.State != AgentContacting {
			continue
		}
		if e.EventID == eventID {
			attempts++
		}
		if customerID != "" && e.CustomerID == customerID {
			customerTouches++
		}
	}
	return attempts, customerTouches
}

// handleAdminAction accepts a pre-approved admin intervention, re-runs the
// decision engine including locked rules, and either executes the action or
// returns an explicit refusal with the rule that blocked it.
func (s *streamServer) handleAdminAction(w http.ResponseWriter, r *http.Request) {
	principal, ok := auth(w, r, ActionAdminIntervention)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 64*1024))
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}
	var req struct {
		EventID string `json:"eventId"`
		Action  string `json:"action"`
		Channel string `json:"channel,omitempty"`
	}
	if err := json.Unmarshal(body, &req); err != nil || req.EventID == "" || req.Action == "" {
		http.Error(w, "invalid payload", http.StatusBadRequest)
		return
	}

	// Find the latest audit entry for this event.
	entries, err := s.audit.All()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var latest *AuditEntry
	for i := range entries {
		if entries[i].EventID == req.EventID {
			latest = &entries[i]
		}
	}
	if latest == nil {
		writeError(w, http.StatusNotFound, "event_not_found", principal, string(ActionAdminIntervention))
		return
	}

	// Find the original FlowEvent for full context reconstruction.
	var sourceEvent *FlowEvent
	for _, ev := range s.events {
		if ev.EventID == req.EventID {
			sourceEvent = ev
			break
		}
	}

	lockedRule, locked := lockedRuleFor(entries, req.EventID)

	refusal := ""
	refusalRule := ""
	var decision Decision
	var state AgentState
	var outcome string
	channel := latest.Channel

	switch req.Action {
	case "nudge_retry":
		if latest.State == AgentRecovered {
			refusal = "event already recovered"
			refusalRule = "already_recovered"
		} else if latest.State == AgentSuppressed {
			refusal = "event is compliance-suppressed"
			refusalRule = "compliance_suppressed"
		} else {
			// Re-run the decision engine if we have the source event.
			if sourceEvent != nil {
				attempts, touches := executedTouches(entries, req.EventID, sourceEvent.CustomerID)
				ctx := buildRecoveryContext(sourceEvent, attempts, touches)
				result, err := StepState(ctx)
				if err == nil {
					decision = result.Audit.Decision
					state = result.Audit.State
				} else {
					decision = DecisionRetry
					state = AgentRetryScheduled
				}
			} else {
				decision = DecisionRetry
				state = AgentRetryScheduled
			}
			if locked {
				refusal = "locked rule " + string(lockedRule) + " blocks retry"
				refusalRule = string(lockedRule)
				decision = DecisionNone
				state = latest.State
			}
			if refusal == "" && decision != DecisionRetry && decision != DecisionContact {
				refusal = "decision engine returned " + string(decision) + " instead of retry"
				refusalRule = string(latest.RuleFired)
			}
		}
		outcome = "Admin nudge retry"

	case "select_recovery_channel":
		if req.Channel == "" {
			http.Error(w, "channel is required for select_recovery_channel", http.StatusBadRequest)
			return
		}
		channel = req.Channel
		if latest.State == AgentRecovered || latest.State == AgentSuppressed {
			refusal = "event is in a terminal state"
			refusalRule = "terminal_state"
		} else if locked {
			refusal = "locked rule " + string(lockedRule) + " blocks channel override"
			refusalRule = string(lockedRule)
		}
		decision = DecisionRetry
		state = AgentRetryScheduled
		outcome = "Admin channel override → " + channel

	case "mark_ptp_fulfilled":
		if latest.State != AgentWaitingOnPtp {
			refusal = "event is not in waiting_on_ptp state"
			refusalRule = "not_ptp_pending"
		} else if locked {
			refusal = "locked rule " + string(lockedRule) + " blocks PTP fulfillment"
			refusalRule = string(lockedRule)
		} else {
			decision = DecisionRecover
			state = AgentRecovered
		}
		outcome = "Admin PTP fulfilled"

	default:
		writeError(w, http.StatusBadRequest, "unknown_action: "+req.Action, principal, string(ActionAdminIntervention))
		return
	}

	// Build the audit entry — success or correct-refusal.
	entryDecision := decision
	entryState := state
	entryOutcome := outcome
	if refusal != "" {
		entryDecision = DecisionNone
		entryState = latest.State
		entryOutcome = "REFUSED: " + refusal
	}

	entry := AuditEntry{
		EventID:      req.EventID,
		Timestamp:    time.Now().UTC().Format(time.RFC3339),
		Flow:         latest.Flow,
		ReasonBucket: latest.ReasonBucket,
		RuleFired:    RuleNoOp,
		Decision:     entryDecision,
		Actor:        ActorHuman,
		State:        entryState,
		Outcome:      entryOutcome,
		Amount:       latest.Amount,
		Currency:     latest.Currency,
		Channel:      channel,
		TriggeredBy:  "admin:" + principal,
	}

	if err := s.audit.Append(entry); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	resp := map[string]any{
		"ok":       refusal == "",
		"eventId":  req.EventID,
		"decision": string(entryDecision),
		"state":    string(entryState),
		"outcome":  entryOutcome,
	}
	if refusal != "" {
		resp["refused"] = true
		resp["refusedBy"] = refusalRule
		resp["refusedReason"] = refusal
	}
	writeJSON(w, http.StatusOK, resp)
}

// buildRecoveryContext constructs a RecoveryContext from a FlowEvent so the
// decision engine can re-evaluate it. The reason bucket is re-derived with
// Classify and the signal fields (PTP date, retry window, DNC flag, ...) are
// carried over via flowContext, so the engine sees the same inputs the batch
// runner gave it — a placeholder reason would hide fraud / mandate_revoked from
// the very rules this re-run exists to enforce.
func buildRecoveryContext(event *FlowEvent, attempt int, customerTouches int) *RecoveryContext {
	base := RecoveryContext{
		EventID:    event.EventID,
		Flow:       event.Flow,
		CustomerID: event.CustomerID,
		InvoiceID:  event.InvoiceID,
		Amount:     event.Amount,
		Currency:   event.Currency,
		Reason:     Classify(event),
		Now:        time.Now().UnixMilli(),
	}
	return flowContext(event, base, attempt, map[string]int{event.CustomerID: customerTouches})
}

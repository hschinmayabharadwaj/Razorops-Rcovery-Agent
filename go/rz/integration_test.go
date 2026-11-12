package rz

// Integration tests: the real batch runner writes a real hash-chained audit
// log, and the production HTTP handler (routes + CORS + auth) is served over a
// real loopback connection. Nothing is mocked; only the port is ephemeral.

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	adminKey    = "admin_key_demo"
	operatorKey = "op_key_demo"
	auditorKey  = "audit_key_demo"
)

// integrationEnv is a running server over a freshly-run canonical batch.
type integrationEnv struct {
	server *httptest.Server
	store  *AuditStore
	events []*FlowEvent
}

func newIntegrationEnv(t *testing.T) *integrationEnv {
	t.Helper()
	ResetTunables()
	events := GenerateEvents(BatchNow())
	store, err := NewAuditStore(filepath.Join(t.TempDir(), "audit.log.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := RunBatch(events, store, RunnerOpts{Now: BatchNow()}); err != nil {
		t.Fatalf("run batch: %v", err)
	}

	hub := NewStreamHub()
	previousHub := BroadcastHub
	BroadcastHub = hub
	s := &streamServer{audit: store, hub: hub, mode: ModeSandbox, events: events, workDir: t.TempDir()}
	server := httptest.NewServer(s.handler())
	t.Cleanup(func() {
		server.Close()
		BroadcastHub = previousHub
	})
	return &integrationEnv{server: server, store: store, events: events}
}

func (e *integrationEnv) do(t *testing.T, method, path, key, body string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, e.server.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if key != "" {
		req.Header.Set("X-API-Key", key)
	}
	resp, err := e.server.Client().Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, raw
}

func (e *integrationEnv) getJSON(t *testing.T, path, key string, into any) {
	t.Helper()
	status, raw := e.do(t, http.MethodGet, path, key, "")
	if status != http.StatusOK {
		t.Fatalf("GET %s: status %d, body %s", path, status, raw)
	}
	if err := json.Unmarshal(raw, into); err != nil {
		t.Fatalf("GET %s: decode: %v (body %s)", path, err, raw)
	}
}

func (e *integrationEnv) log(t *testing.T) []AuditEntry {
	t.Helper()
	entries, err := e.store.All()
	if err != nil {
		t.Fatal(err)
	}
	return entries
}

func TestIntegrationEveryRouteDeniesMissingAndUnknownCredentials(t *testing.T) {
	env := newIntegrationEnv(t)
	routes := []struct{ method, path string }{
		{http.MethodGet, "/events"},
		{http.MethodGet, "/chain-status"},
		{http.MethodGet, "/metrics"},
		{http.MethodGet, "/exceptions"},
		{http.MethodGet, "/compare-policy"},
		{http.MethodGet, "/prescore"},
		{http.MethodGet, "/sandbox"},
		{http.MethodPost, "/demo/tamper"},
		{http.MethodPost, "/payment-event"},
		{http.MethodPost, "/admin/action"},
	}
	for _, route := range routes {
		for _, key := range []string{"", "not_a_real_key"} {
			status, _ := env.do(t, route.method, route.path, key, "{}")
			if status != http.StatusUnauthorized {
				t.Errorf("%s %s with key %q: status %d, want 401", route.method, route.path, key, status)
			}
		}
	}
}

func TestIntegrationRoleMatrixIsEnforcedOverHTTP(t *testing.T) {
	env := newIntegrationEnv(t)
	cases := []struct {
		name, method, path, key string
		want                    int
	}{
		{"auditor reads metrics", http.MethodGet, "/metrics", auditorKey, http.StatusOK},
		{"auditor cannot tune sandbox", http.MethodGet, "/sandbox", auditorKey, http.StatusForbidden},
		{"operator cannot tamper", http.MethodPost, "/demo/tamper", operatorKey, http.StatusForbidden},
		{"operator cannot intervene", http.MethodPost, "/admin/action", operatorKey, http.StatusForbidden},
		{"auditor cannot write payment events", http.MethodPost, "/payment-event", auditorKey, http.StatusForbidden},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status, body := env.do(t, tc.method, tc.path, tc.key, "{}")
			if status != tc.want {
				t.Fatalf("status %d, want %d (body %s)", status, tc.want, body)
			}
		})
	}
}

func TestIntegrationMetricsMatchTheAuditLog(t *testing.T) {
	env := newIntegrationEnv(t)
	want := ComputeMetrics(env.log(t))

	var got metricsJSON
	env.getJSON(t, "/metrics", operatorKey, &got)

	// totalEvents counts events that reached a terminal state; held events
	// (waiting_on_ptp) are still in flight, so it can be below the batch size.
	if got.TotalEvents == 0 || got.TotalEvents > len(env.events) {
		t.Fatalf("totalEvents = %d, want 1..%d", got.TotalEvents, len(env.events))
	}
	if got.TotalEvents != want.TotalEvents || got.RecoveredCount != want.RecoveredCount || got.TouchesSent != want.TouchesSent {
		t.Fatalf("HTTP metrics drifted from the log: got %+v, want %+v", got, want)
	}
	if got.RecoveredCount == 0 || got.RecoveryRate <= 0 || got.RecoveryRate >= 1 {
		t.Fatalf("implausible recovery figures: count=%d rate=%f", got.RecoveredCount, got.RecoveryRate)
	}
	if len(got.ByFlow) != len(FlowTypes) {
		t.Fatalf("byFlow has %d flows, want %d", len(got.ByFlow), len(FlowTypes))
	}
}

func TestIntegrationChainStatusReportsTheVerifiedLog(t *testing.T) {
	env := newIntegrationEnv(t)

	var got chainStatus
	env.getJSON(t, "/chain-status", auditorKey, &got)

	if !got.Valid || got.BrokenAt != nil {
		t.Fatalf("freshly written chain reported invalid: %+v", got)
	}
	if got.Entries != len(env.log(t)) {
		t.Fatalf("entries = %d, want %d", got.Entries, len(env.log(t)))
	}
}

func TestIntegrationExceptionsAreRedacted(t *testing.T) {
	env := newIntegrationEnv(t)
	rawIDs := map[string]bool{}
	for _, ev := range env.events {
		rawIDs[ev.CustomerID] = true
	}

	var got struct {
		Exceptions []exceptionJSON `json:"exceptions"`
	}
	env.getJSON(t, "/exceptions", auditorKey, &got)

	if len(got.Exceptions) == 0 {
		t.Fatal("canonical batch produced no exceptions")
	}
	for _, ex := range got.Exceptions {
		if ex.Customer == "" {
			continue
		}
		if rawIDs[ex.Customer] || !strings.Contains(ex.Customer, "•••") {
			t.Fatalf("exception %s exposes a raw customer id: %q", ex.EventID, ex.Customer)
		}
	}
}

func TestIntegrationPrescoreCoversEveryEvent(t *testing.T) {
	env := newIntegrationEnv(t)

	var got prescoreJSON
	env.getJSON(t, "/prescore", operatorKey, &got)

	if got.TotalEvents != len(env.events) || len(got.Rows) != len(env.events) {
		t.Fatalf("prescore rows = %d (total %d), want %d", len(got.Rows), got.TotalEvents, len(env.events))
	}
	if got.Headline == "" {
		t.Fatal("prescore headline missing")
	}
}

func TestIntegrationComparePolicyReportsNaiveViolations(t *testing.T) {
	env := newIntegrationEnv(t)
	mainLogBefore := len(env.log(t))

	var got comparisonJSON
	env.getJSON(t, "/compare-policy", operatorKey, &got)

	if got.Violations.Total == 0 || got.Violations.FraudRetries == 0 || got.Violations.MandateRetries == 0 {
		t.Fatalf("naive policy should commit fraud + mandate violations: %+v", got.Violations)
	}
	if got.Naive.TouchesSent <= got.Real.TouchesSent {
		t.Fatalf("naive touches (%d) should exceed real touches (%d)", got.Naive.TouchesSent, got.Real.TouchesSent)
	}
	if got.TotalNaiveTouches < got.Violations.Total {
		t.Fatalf("violations (%d) exceed naive touches (%d)", got.Violations.Total, got.TotalNaiveTouches)
	}
	// The real-policy side of the comparison is the same engine as the main log.
	if want := ComputeMetrics(env.log(t)); got.Real.RecoveredCount != want.RecoveredCount || got.Real.TouchesSent != want.TouchesSent {
		t.Fatalf("comparison real metrics drifted from the main log: got %+v, want %+v", got.Real, want)
	}
	if got.Takeaway == "" {
		t.Fatal("takeaway missing")
	}
	// The comparison runs in scratch logs; the served audit log is untouched.
	if after := len(env.log(t)); after != mainLogBefore {
		t.Fatalf("compare-policy appended %d entries to the main audit log", after-mainLogBefore)
	}
}

func TestIntegrationSandboxSweepKeepsLockedRulesAtZero(t *testing.T) {
	env := newIntegrationEnv(t)
	mainLogBefore := len(env.log(t))

	var got sandboxJSON
	env.getJSON(t, "/sandbox?scenario=aggressive", adminKey, &got)

	if !got.LockedInvariant {
		t.Fatal("locked invariant reported broken")
	}
	if got.SelectedScenario != "aggressive" {
		t.Fatalf("selectedScenario = %q, want aggressive", got.SelectedScenario)
	}
	rates := map[string]float64{}
	for _, sc := range got.Scenarios {
		rates[sc.Label] = sc.RecoveryRate
		if sc.LockedViolations.Total != 0 {
			t.Fatalf("scenario %s has %d locked-rule violations", sc.Label, sc.LockedViolations.Total)
		}
	}
	for _, label := range []string{"baseline", "aggressive", "conservative", "high_incentive"} {
		if _, ok := rates[label]; !ok {
			t.Fatalf("scenario %q missing from sweep: %v", label, rates)
		}
	}
	if rates["conservative"] >= rates["aggressive"] {
		t.Fatalf("tunables did not move recovery: conservative %.3f >= aggressive %.3f", rates["conservative"], rates["aggressive"])
	}
	if len(got.LockedRules) != len(LockedRuleIds) {
		t.Fatalf("lockedRules = %v, want %d rules", got.LockedRules, len(LockedRuleIds))
	}
	// The sweep must restore default tunables and leave the served log alone.
	if GetTunables() != DefaultTunables() {
		t.Fatalf("sandbox sweep leaked tunables: %+v", GetTunables())
	}
	if after := len(env.log(t)); after != mainLogBefore {
		t.Fatalf("sandbox appended %d entries to the main audit log", after-mainLogBefore)
	}
}

func TestIntegrationComputeEndpointsFailClosedWithoutEvents(t *testing.T) {
	store, err := NewAuditStore(filepath.Join(t.TempDir(), "audit.log.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	s := &streamServer{audit: store, hub: NewStreamHub(), mode: ModeSandbox, workDir: t.TempDir()}
	server := httptest.NewServer(s.handler())
	defer server.Close()

	for _, path := range []string{"/compare-policy", "/prescore", "/sandbox"} {
		req, err := http.NewRequest(http.MethodGet, server.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("X-API-Key", adminKey)
		resp, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusInternalServerError {
			t.Errorf("%s without events: status %d, want 500", path, resp.StatusCode)
		}
	}
}

func TestIntegrationPaymentEventIsChainedAndExcludedFromMetrics(t *testing.T) {
	env := newIntegrationEnv(t)
	before := ComputeMetrics(env.log(t))
	body := `{"eventId":"payment.verified.pay_it1","eventType":"payment.verified","state":"verified","details":"{\"valid\":true}"}`

	status, raw := env.do(t, http.MethodPost, "/payment-event", adminKey, body)

	if status != http.StatusOK {
		t.Fatalf("status %d, body %s", status, raw)
	}
	log := env.log(t)
	last := log[len(log)-1]
	if last.EventID != "payment.verified.pay_it1" || last.Flow != FlowPaymentEvent || last.Actor != ActorPaymentGateway {
		t.Fatalf("payment event not appended as expected: %+v", last)
	}
	if v := VerifyChain(log); !v.Valid {
		t.Fatalf("chain broken at %d after a payment event", v.BrokenAtIndex)
	}
	after := ComputeMetrics(log)
	if after.TotalEvents != before.TotalEvents || after.RecoveredCount != before.RecoveredCount {
		t.Fatalf("payment event changed recovery metrics: before %d/%d, after %d/%d",
			before.RecoveredCount, before.TotalEvents, after.RecoveredCount, after.TotalEvents)
	}
}

func TestIntegrationPaymentEventRejectsBadRequests(t *testing.T) {
	env := newIntegrationEnv(t)
	cases := []struct {
		name, method, body string
		want               int
	}{
		{"wrong method", http.MethodGet, "", http.StatusMethodNotAllowed},
		{"not json", http.MethodPost, "nope", http.StatusBadRequest},
		{"missing event id", http.MethodPost, `{"eventType":"payment.verified"}`, http.StatusBadRequest},
		{"oversized event id", http.MethodPost, `{"eventId":"` + strings.Repeat("a", maxPaymentEventIDBytes+1) + `"}`, http.StatusBadRequest},
	}
	entriesBefore := len(env.log(t))
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status, body := env.do(t, tc.method, "/payment-event", adminKey, tc.body)
			if status != tc.want {
				t.Fatalf("status %d, want %d (body %s)", status, tc.want, body)
			}
		})
	}
	if got := len(env.log(t)); got != entriesBefore {
		t.Fatalf("rejected requests appended %d audit entries", got-entriesBefore)
	}
}

// firstEventWithRule returns the id of the first batch event whose log contains
// the given rule.
func firstEventWithRule(t *testing.T, log []AuditEntry, rule RuleId) string {
	t.Helper()
	for _, e := range log {
		if e.RuleFired == rule {
			return e.EventID
		}
	}
	t.Fatalf("canonical batch has no event with rule %s", rule)
	return ""
}

func TestIntegrationAdminCannotOverrideLockedRules(t *testing.T) {
	env := newIntegrationEnv(t)
	for _, rule := range []RuleId{RuleFraudSuppress, RuleMandateRevokedEsc} {
		t.Run(string(rule), func(t *testing.T) {
			eventID := firstEventWithRule(t, env.log(t), rule)
			for _, action := range []string{
				`{"eventId":"` + eventID + `","action":"nudge_retry"}`,
				`{"eventId":"` + eventID + `","action":"select_recovery_channel","channel":"sms"}`,
			} {
				status, raw := env.do(t, http.MethodPost, "/admin/action", adminKey, action)
				if status != http.StatusOK {
					t.Fatalf("status %d, body %s", status, raw)
				}
				var resp map[string]any
				if err := json.Unmarshal(raw, &resp); err != nil {
					t.Fatal(err)
				}
				if resp["ok"] != false || resp["refused"] != true {
					t.Fatalf("admin override of %s was not refused: %s", rule, raw)
				}
			}

			log := env.log(t)
			last := log[len(log)-1]
			if last.Actor != ActorHuman || !strings.HasPrefix(last.Outcome, "REFUSED:") || last.TriggeredBy != "admin:admin-demo" {
				t.Fatalf("refusal was not audited against the admin: %+v", last)
			}
			if last.Decision == DecisionRetry || last.Decision == DecisionContact {
				t.Fatalf("refused action still recorded a money-moving decision: %s", last.Decision)
			}
			if v := VerifyChain(log); !v.Valid {
				t.Fatalf("chain broken at %d after refusals", v.BrokenAtIndex)
			}
		})
	}
}

func TestIntegrationAdminActionValidation(t *testing.T) {
	env := newIntegrationEnv(t)
	knownEvent := env.events[0].EventID
	cases := []struct {
		name, body string
		want       int
	}{
		{"unknown event", `{"eventId":"evt_missing","action":"nudge_retry"}`, http.StatusNotFound},
		{"unknown action", `{"eventId":"` + knownEvent + `","action":"refund_everything"}`, http.StatusBadRequest},
		{"channel required", `{"eventId":"` + knownEvent + `","action":"select_recovery_channel"}`, http.StatusBadRequest},
		{"missing fields", `{}`, http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status, body := env.do(t, http.MethodPost, "/admin/action", adminKey, tc.body)
			if status != tc.want {
				t.Fatalf("status %d, want %d (body %s)", status, tc.want, body)
			}
		})
	}
}

// sseClient reads `data:` frames from the /events stream.
type sseClient struct {
	frames chan map[string]any
	cancel context.CancelFunc
}

func openEvents(t *testing.T, env *integrationEnv, key string) *sseClient {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, env.server.URL+"/events", nil)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	req.Header.Set("X-API-Key", key)
	resp, err := env.server.Client().Do(req)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		resp.Body.Close()
		cancel()
		t.Fatalf("/events: status %d, content-type %q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}

	client := &sseClient{frames: make(chan map[string]any, 1024), cancel: cancel}
	go func() {
		defer resp.Body.Close()
		defer close(client.frames)
		sc := bufio.NewScanner(resp.Body)
		sc.Buffer(make([]byte, 0, 64*1024), maxAuditLineBytes)
		for sc.Scan() {
			line := sc.Text()
			if !strings.HasPrefix(line, "data: ") {
				continue
			}
			var frame map[string]any
			if json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &frame) == nil {
				client.frames <- frame
			}
		}
	}()
	t.Cleanup(cancel)
	return client
}

func (c *sseClient) next(t *testing.T) map[string]any {
	t.Helper()
	select {
	case frame, ok := <-c.frames:
		if !ok {
			t.Fatal("event stream closed unexpectedly")
		}
		return frame
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for a stream frame")
	}
	return nil
}

func TestIntegrationEventStreamReplaysHistoryThenStreamsLive(t *testing.T) {
	env := newIntegrationEnv(t)
	history := env.log(t)
	stream := openEvents(t, env, auditorKey)

	// Replay: every existing entry arrives first, in log order.
	for i, want := range history {
		frame := stream.next(t)
		if frame["eventType"] != "audit" || frame["hash"] != want.Hash {
			t.Fatalf("replay frame %d = %v, want audit entry with hash %s", i, frame, want.Hash)
		}
	}

	// Live: a new append is pushed to the open stream.
	status, raw := env.do(t, http.MethodPost, "/payment-event", adminKey,
		`{"eventId":"pay_live1","eventType":"payment.captured","state":"accepted","details":"{}"}`)
	if status != http.StatusOK {
		t.Fatalf("payment-event status %d, body %s", status, raw)
	}
	live := stream.next(t)
	if live["eventId"] != "pay_live1" || live["flow"] != string(FlowPaymentEvent) {
		t.Fatalf("live frame = %v, want the payment event", live)
	}
}

func TestIntegrationTamperDemoFlipsStreamStatusButNotTheRealLog(t *testing.T) {
	env := newIntegrationEnv(t)
	history := env.log(t)
	stream := openEvents(t, env, adminKey)
	for range history {
		stream.next(t)
	}

	status, raw := env.do(t, http.MethodPost, "/demo/tamper", adminKey, "")

	if status != http.StatusOK {
		t.Fatalf("tamper status %d, body %s", status, raw)
	}
	frame := stream.next(t)
	if frame["eventType"] != "chain_status" || frame["valid"] != false || frame["brokenAt"] != float64(0) {
		t.Fatalf("tamper frame = %v, want chain_status invalid at index 0", frame)
	}
	// The demo tampers an in-memory copy only: the persisted chain is untouched.
	if v := VerifyChain(env.log(t)); !v.Valid || v.Entries != len(history) {
		t.Fatalf("real log changed by the tamper demo: %+v", v)
	}
}

func TestIntegrationCORSPreflight(t *testing.T) {
	env := newIntegrationEnv(t)
	req, err := http.NewRequest(http.MethodOptions, env.server.URL+"/metrics", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Origin", "https://dashboard.example")
	req.Header.Set("Access-Control-Request-Method", "GET")

	resp, err := env.server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("preflight status %d, want 204", resp.StatusCode)
	}
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got == "" {
		t.Fatal("preflight missing Access-Control-Allow-Origin")
	}
	if got := resp.Header.Get("Access-Control-Allow-Headers"); !strings.Contains(got, "X-API-Key") {
		t.Fatalf("preflight does not allow the X-API-Key header: %q", got)
	}
}

func TestIntegrationReplayedBatchIsSuppressedEndToEnd(t *testing.T) {
	env := newIntegrationEnv(t)
	before := ComputeMetrics(env.log(t))

	// Re-deliver the entire batch into the same store (webhook replay).
	if _, err := RunBatch(env.events, env.store, RunnerOpts{Now: BatchNow()}); err != nil {
		t.Fatal(err)
	}

	var got metricsJSON
	env.getJSON(t, "/metrics", operatorKey, &got)
	if got.RecoveredCount != before.RecoveredCount || got.TouchesSent != before.TouchesSent || got.TotalEvents != before.TotalEvents {
		t.Fatalf("replay changed metrics: before %+v, after %+v", before, got)
	}
	var chain chainStatus
	env.getJSON(t, "/chain-status", auditorKey, &chain)
	if !chain.Valid {
		t.Fatalf("chain invalid after replay: %+v", chain)
	}
}

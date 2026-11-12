package rz

import (
	"encoding/json"
	"net/http"
)

// HTTP adapter: exposes the working backend logic as JSON endpoints for the
// Blazor frontend. This is a THIN layer only — every number it returns is
// produced by the existing Go logic (ComputeMetrics, ComparePolicies,
// ComputePrescoreReport, RunSandbox, VerifyChain). No business logic is
// reimplemented here; the adapter only shapes Go structs into JSON and applies
// server-side redaction before anything leaves the process.

// ============================================================================
// Metrics + eligibility
// ============================================================================

type flowMetricsJSON struct {
	Events          int     `json:"events"`
	RecoveredCount  int     `json:"recoveredCount"`
	RecoveredRupees float64 `json:"recoveredRupees"`
	Escalated       int     `json:"escalated"`
	Suppressed      int     `json:"suppressed"`
	Abandoned       int     `json:"abandoned"`
	Touches         int     `json:"touches"`
}

type metricsJSON struct {
	TotalEvents       int                       `json:"totalEvents"`
	TotalAtRiskRupees float64                   `json:"totalAtRiskRupees"`
	RecoveredCount    int                       `json:"recoveredCount"`
	RecoveredRupees   float64                   `json:"recoveredRupees"`
	RecoveryRate      float64                   `json:"recoveryRate"`
	TouchesSent       int                       `json:"touchesSent"`
	CostPerRecovery   float64                   `json:"costPerRecovery"`
	EscalatedCount    int                       `json:"escalatedCount"`
	AbandonedCount    int                       `json:"abandonedCount"`
	SuppressedCount   int                       `json:"suppressedCount"`
	ByFlow            map[string]flowMetricsJSON `json:"byFlow"`
	Eligibility       eligibilityJSON           `json:"eligibility"`
}

// eligibilityJSON segments the batch into events that are structurally blocked
// by a locked compliance rule (0% auto-recoverable by design) versus recovery-
// eligible events, and reports both the blended and the eligible-only rate.
type eligibilityJSON struct {
	BlockedByCompliance  int     `json:"blockedByCompliance"`
	EligibleEvents       int     `json:"eligibleEvents"`
	EligibleRecovered    int     `json:"eligibleRecovered"`
	EligibleRecoveryRate float64 `json:"eligibleRecoveryRate"`
	BlendedRecoveryRate  float64 `json:"blendedRecoveryRate"`
}

func buildMetricsJSON(m Metrics) metricsJSON {
	flow := map[string]flowMetricsJSON{}
	for _, f := range FlowTypes {
		fm := m.ByFlow[f]
		flow[string(f)] = flowMetricsJSON{
			Events:          fm.Events,
			RecoveredCount:  fm.RecoveredCount,
			RecoveredRupees: fm.RecoveredRupees,
			Escalated:       fm.Escalated,
			Suppressed:      fm.Suppressed,
			Abandoned:       fm.Abandoned,
			Touches:         fm.Touches,
		}
	}
	return metricsJSON{
		TotalEvents:       m.TotalEvents,
		TotalAtRiskRupees: m.TotalAtRiskRupees,
		RecoveredCount:    m.RecoveredCount,
		RecoveredRupees:   m.RecoveredRupees,
		RecoveryRate:      m.RecoveryRate,
		TouchesSent:       m.TouchesSent,
		CostPerRecovery:   m.CostPerRecovery,
		EscalatedCount:    m.EscalatedCount,
		AbandonedCount:    m.AbandonedCount,
		SuppressedCount:   m.SuppressedCount,
		ByFlow:            flow,
	}
}

// ComputeEligibility derives the blocked-vs-eligible segmentation from the
// audit log. Terminal, non-recovered states that the policy deliberately does
// not auto-resolve (escalated / abandoned / suppressed / waiting_on_ptp) are
// "structurally blocked"; recovered and their carried at-risk set are the
// recovery-eligible population.
func ComputeEligibility(log []AuditEntry) eligibilityJSON {
	terminal := map[string]AuditEntry{}
	seen := map[string]bool{}
	for _, e := range log {
		if e.RuleFired == RuleDuplicateSuppress || e.Flow == FlowPaymentEvent {
			continue
		}
		seen[e.EventID] = true
		if IsTerminalState(e.State) {
			terminal[e.EventID] = e
		}
	}
	total := len(seen)
	recovered := 0
	blocked := 0
	for _, e := range terminal {
		switch e.State {
		case AgentRecovered:
			recovered++
		case AgentEscalated, AgentAbandoned, AgentSuppressed, AgentWaitingOnPtp:
			blocked++
		}
	}
	eligible := recovered + (total - (recovered + blocked))
	eligibleRate := float64(0)
	if eligible > 0 {
		eligibleRate = float64(recovered) / float64(eligible)
	}
	blendedRate := float64(0)
	if total > 0 {
		blendedRate = float64(recovered) / float64(total)
	}
	return eligibilityJSON{
		BlockedByCompliance:  blocked,
		EligibleEvents:       eligible,
		EligibleRecovered:    recovered,
		EligibleRecoveryRate: eligibleRate,
		BlendedRecoveryRate:  blendedRate,
	}
}

// ============================================================================
// Exceptions (redacted server-side)
// ============================================================================

type exceptionJSON struct {
	EventID        string `json:"eventId"`
	Flow           string `json:"flow"`
	Customer       string `json:"customer"`
	InvoiceID      string `json:"invoice"`
	Reason         string `json:"reason"`
	Status         string `json:"status"`
	AmountInRupees float64 `json:"amountInRupees"`
	RuleFired      string `json:"ruleFired"`
	Outcome        string `json:"outcome"`
}

func buildExceptionsJSON(list []ExceptionItem) []exceptionJSON {
	out := make([]exceptionJSON, 0, len(list))
	for _, it := range list {
		redacted := RedactPII(map[string]any{"customerId": it.CustomerID}, "customerId")
		cust, _ := redacted["customerId"].(string)
		out = append(out, exceptionJSON{
			EventID:        it.EventID,
			Flow:           string(it.Flow),
			Customer:       cust,
			InvoiceID:      it.InvoiceID,
			Reason:         string(it.Reason),
			Status:         it.Status,
			AmountInRupees: it.AmountInRupees,
			RuleFired:      it.RuleFired,
			Outcome:        it.Outcome,
		})
	}
	return out
}

// ============================================================================
// Comparison
// ============================================================================

type comparisonJSON struct {
	Real              metricsJSON     `json:"real"`
	Naive             metricsJSON     `json:"naive"`
	Violations        violationsJSON  `json:"violations"`
	TotalNaiveTouches int             `json:"totalNaiveTouches"`
	Takeaway          string          `json:"takeaway"`
}

type violationsJSON struct {
	FraudRetries           int `json:"fraudRetries"`
	MandateRetries         int `json:"mandateRetries"`
	QuietHourCalls         int `json:"quietHourCalls"`
	DNcBreaches            int `json:"dncBreaches"`
	TouchCapBreaches       int `json:"touchCapBreaches"`
	RetryBudgetBreaches    int `json:"retryBudgetBreaches"`
	PtpSuppressionBreaches int `json:"ptpSuppressionBreaches"`
	Total                  int `json:"total"`
}

// ============================================================================
// Prescore
// ============================================================================

type prescoreRowJSON struct {
	EventId         string `json:"eventId"`
	Flow            string `json:"flow"`
	CustomerId      string `json:"customerId"`
	Score           int    `json:"score"`
	Tier            string `json:"tier"`
	TopFactor       string `json:"topFactor"`
	FailedToRecover bool   `json:"failedToRecover"`
	Recovered       bool   `json:"recovered"`
}

type prescoreJSON struct {
	Rows                []prescoreRowJSON `json:"rows"`
	TotalEvents         int               `json:"totalEvents"`
	FailedEvents        int               `json:"failedEvents"`
	HighRiskAmongFailed int               `json:"highRiskAmongFailed"`
	HighRiskTotal       int               `json:"highRiskTotal"`
	Precision           float64           `json:"precision"`
	Recall              float64           `json:"recall"`
	Headline            string            `json:"headline"`
}

func buildPrescoreJSON(r PrescoreReport) prescoreJSON {
	rows := make([]prescoreRowJSON, 0, len(r.Rows))
	for _, row := range r.Rows {
		rows = append(rows, prescoreRowJSON{
			EventId:         row.EventId,
			Flow:            string(row.Flow),
			CustomerId:      row.CustomerId,
			Score:           row.Score,
			Tier:            string(row.Decision),
			TopFactor:       row.TopFactor,
			FailedToRecover: row.FailedToRecover,
			Recovered:       row.Recovered,
		})
	}
	return prescoreJSON{
		Rows:                rows,
		TotalEvents:         r.TotalEvents,
		FailedEvents:        r.FailedEvents,
		HighRiskAmongFailed: r.HighRiskAmongFailed,
		HighRiskTotal:       r.HighRiskTotal,
		Precision:           r.Precision,
		Recall:              r.Recall,
		Headline:            r.Headline,
	}
}

// ============================================================================
// Sandbox
// ============================================================================

type sandboxScenarioJSON struct {
	Label           string        `json:"label"`
	RecoveryRate    float64       `json:"recoveryRate"`
	TouchesSent     int           `json:"touchesSent"`
	CostPerRecovery float64       `json:"costPerRecovery"`
	LockedViolations lockedViolationJSON `json:"lockedViolations"`
}

type lockedViolationJSON struct {
	Fraud          int `json:"fraud"`
	MandateRevoked int `json:"mandateRevoked"`
	DNc            int `json:"dnc"`
	QuietHours     int `json:"quietHours"`
	Total          int `json:"total"`
}

type sandboxJSON struct {
	Scenarios        []sandboxScenarioJSON `json:"scenarios"`
	LockedInvariant  bool                  `json:"lockedInvariant"`
	Headline         string                `json:"headline"`
	SelectedScenario string                `json:"selectedScenario"`
	LockedRules      []string              `json:"lockedRules"`
}

// buildSandboxJSON converts a SandboxReport into its JSON shape. It also emits
// the list of locked rule ids so the UI can render the immovable lock panel.
func buildSandboxJSON(report SandboxReport, selected string) sandboxJSON {
	scenarios := make([]sandboxScenarioJSON, 0, len(report.Scenarios)+1)
	baseline := report.Baseline
	scenarios = append(scenarios, sandboxScenarioJSON{
		Label:           "baseline",
		RecoveryRate:    baseline.RecoveryRate,
		TouchesSent:     baseline.TouchesSent,
		CostPerRecovery: baseline.CostPerRecovery,
		LockedViolations: lockedViolationJSON{},
	})
	for _, s := range report.Scenarios {
		lv := s.LockedViolations
		scenarios = append(scenarios, sandboxScenarioJSON{
			Label:           s.ScenarioLabel,
			RecoveryRate:    s.Metrics.RecoveryRate,
			TouchesSent:     s.Metrics.TouchesSent,
			CostPerRecovery: s.Metrics.CostPerRecovery,
			LockedViolations: lockedViolationJSON{
				Fraud:          lv.Fraud,
				MandateRevoked: lv.MandateRevoked,
				DNc:            lv.DNc,
				QuietHours:     lv.QuietHours,
				Total:          lv.Sum(),
			},
		})
	}
	lockedRules := make([]string, 0, len(LockedRuleIds))
	for _, id := range LockedRuleIds {
		lockedRules = append(lockedRules, string(id))
	}
	if selected == "" {
		selected = "baseline"
	}
	return sandboxJSON{
		Scenarios:        scenarios,
		LockedInvariant:  report.LockedInvariant,
		Headline:         report.Headline,
		SelectedScenario: selected,
		LockedRules:      lockedRules,
	}
}

// ============================================================================
// Auth-aware JSON error responses
// ============================================================================

type errorJSON struct {
	Error  string `json:"error"`
	Reason string `json:"reason,omitempty"`
	Actor  string `json:"actor,omitempty"`
	Action string `json:"action,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, reason, actor, action string) {
	writeJSON(w, status, errorJSON{
		Error:  http.StatusText(status),
		Reason: reason,
		Actor:  actor,
		Action: action,
	})
}

// auth checks the X-API-Key header against the role matrix for the given
// action. Returns the principal on success, or writes a 401/403 and returns
// false. This is the deny-by-default gate for every HTTP surface.
func auth(w http.ResponseWriter, r *http.Request, action Action) (string, bool) {
	key := r.Header.Get("X-API-Key")
	d := Authorize(key, action)
	if !d.Allowed {
		switch d.Reason {
		case "missing_credential", "unknown_credential":
			writeError(w, http.StatusUnauthorized, d.Reason, d.Actor, string(d.Action))
		default:
			writeError(w, http.StatusForbidden, d.Reason, d.Actor, string(d.Action))
		}
		return "", false
	}
	return d.Actor, true
}


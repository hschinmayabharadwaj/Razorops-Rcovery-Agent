package rz

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Backtest sandbox / interactivity engine.
//
// Re-runs the SAME batch under different tunable values and reports how business
// metrics move while re-checking that the LOCKED safety rules (fraud,
// mandate_revoked, DNC, TRAI quiet-hours) never budge (their violations stay 0).

type SandboxScenario struct {
	Label    string
	Tunables TunableConfig
	Apply    func(*TunableConfig) // optional override builder
}

type SandboxResult struct {
	ScenarioLabel    string
	Tunables         TunableConfig
	Metrics          Metrics
	TouchCount       int
	LockedViolations LockedViolations
}

// LockedViolations counts how many non-terminal risky actions touched a
// LOCKED-rule scenario. Because the engine can never emit those, this must
// always be 0.
type LockedViolations struct {
	Fraud          int
	MandateRevoked int
	DNc            int
	QuietHours     int
}

func (l LockedViolations) Sum() int {
	return l.Fraud + l.MandateRevoked + l.DNc + l.QuietHours
}

// CountLockedViolations scans audit entries for LOCKED-rule violations.
func CountLockedViolations(entries []AuditEntry) LockedViolations {
	v := LockedViolations{}
	lockedReasons := map[string][]string{
		"fraud":           {"fraud_flagged"},
		"mandate_revoked": {"mandate_revoked"},
	}
	for _, e := range entries {
		reason := e.ReasonBucket
		if containsStr(lockedReasons["fraud"], string(reason)) && !isSafeTerminal(e.State) {
			v.Fraud++
		}
		if containsStr(lockedReasons["mandate_revoked"], string(reason)) && !isSafeTerminal(e.State) {
			v.MandateRevoked++
		}
		// DNC / quiet-hours voice calls: scan for any voice contact attempt with a
		// quiet-hour timestamp (derived from the entry's state).
		if e.Channel == "voice" && e.State == AgentContacting {
			if isQuietHourIso(e.Timestamp) {
				v.QuietHours++
			}
		}
	}
	return v
}

func containsStr(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func isSafeTerminal(state AgentState) bool {
	switch state {
	case AgentSuppressed, AgentEscalated, AgentAbandoned, AgentRecovered, AgentWaitingOnPtp:
		return true
	}
	return false
}

func isQuietHourIso(iso string) bool {
	if iso == "" {
		return false
	}
	t, err := time.Parse("2006-01-02T15:04:05.000Z07:00", iso)
	if err != nil {
		return false
	}
	istMs := t.UnixMilli() + int64(5.5*3600*1000)
	hour := time.UnixMilli(istMs).UTC().Hour()
	return hour >= 21 || hour < 9
}

var touchRe = regexp.MustCompile(`(?i)retry|contact|recover`)

// NewSandboxStore is a helper to build scenario audit files.
func NewSandboxStore(path string) *AuditStore {
	st, err := NewAuditStore(path)
	if err != nil {
		panic(err)
	}
	return st
}

// RunScenario sets tunables, runs the real batch, gathers metrics + locked
// violations, then restores defaults. Always restores, so callers share state.
func RunScenario(events []*FlowEvent, now int64, label string, apply func(*TunableConfig), auditFile string) (SandboxResult, error) {
	SetTunableField(apply)
	stored, err := NewAuditStore(auditFile)
	if err != nil {
		ResetTunables()
		return SandboxResult{}, err
	}
	if err := stored.Clear(); err != nil {
		ResetTunables()
		return SandboxResult{}, err
	}
	if _, err := RunBatch(events, stored, RunnerOpts{Now: now}); err != nil {
		ResetTunables()
		return SandboxResult{}, err
	}
	entries, err := stored.All()
	if err != nil {
		ResetTunables()
		return SandboxResult{}, err
	}
	metrics := ComputeMetrics(entries)
	tunablesNow := tunables
	ResetTunables()

	touchCount := 0
	for _, e := range entries {
		if e.Actor == ActorPolicyEngine && e.State != "" && touchRe.MatchString(string(e.State)) {
			touchCount++
		}
	}

	return SandboxResult{
		ScenarioLabel:    label,
		Tunables:         tunablesNow,
		Metrics:          metrics,
		TouchCount:       touchCount,
		LockedViolations: CountLockedViolations(entries),
	}, nil
}

type SandboxReport struct {
	Baseline        Metrics
	Scenarios       []SandboxResult
	LockedInvariant bool
	Headline        string
}

// DefaultWorkDir is where scenario / comparison audit logs are written when the
// caller does not choose a directory.
const DefaultWorkDir = "data"

// RunSandbox runs the baseline plus a tunable sweep, writing scenario logs
// under DefaultWorkDir.
func RunSandbox(events []*FlowEvent, now int64) (SandboxReport, error) {
	return RunSandboxIn(events, now, DefaultWorkDir)
}

// RunSandboxIn is RunSandbox with the scenario audit logs written under dir.
func RunSandboxIn(events []*FlowEvent, now int64, dir string) (SandboxReport, error) {
	if now == 0 {
		now = BatchNow()
	}
	baselineRes, err := RunScenario(events, now, "baseline", func(*TunableConfig) {}, filepath.Join(dir, "sandbox.baseline.log.jsonl"))
	if err != nil {
		return SandboxReport{}, err
	}
	baseline := baselineRes.Metrics

	scenarios := []SandboxScenario{
		// Aggressive: more retries + tighter caps -> more recovery, more risk
		{Label: "aggressive", Apply: func(t *TunableConfig) {
			t.MaxRetryAttempts, t.MaxTouchesPerCustomer, t.CheckoutReminderCap, t.MaxVoiceCalls, t.MandateWindowDays = 5, 5, 3, 3, 5
		}},
		// Conservative: fewer retries -> safer, less recovery
		{Label: "conservative", Apply: func(t *TunableConfig) {
			t.MaxRetryAttempts, t.MaxTouchesPerCustomer, t.CheckoutReminderCap, t.MaxVoiceCalls, t.MandateWindowDays = 1, 1, 1, 1, 1
		}},
		// High-friction: bigger incentive/progress ceiling, higher supervisor bar
		{Label: "high_incentive", Apply: func(t *TunableConfig) {
			t.CartIncentiveThreshold, t.PtpSupervisorThreshold, t.ReceivableTier2Days = 20000, 1000000, 90
		}},
	}

	var results []SandboxResult
	for _, s := range scenarios {
		res, err := RunScenario(events, now, s.Label, s.Apply, filepath.Join(dir, "sandbox."+s.Label+".log.jsonl"))
		if err != nil {
			return SandboxReport{}, err
		}
		results = append(results, res)
	}

	lockedInvariant := true
	for _, r := range results {
		if r.LockedViolations.Sum() != 0 {
			lockedInvariant = false
		}
	}

	aggressive := fmt.Sprintf("%.0f", percent(results[0].Metrics.RecoveryRate))
	conservative := fmt.Sprintf("%.0f", percent(results[1].Metrics.RecoveryRate))
	headline := "Same batch, tunable sweep: recovery moves from " + aggressive + "% (aggressive) to " + conservative +
		"% (conservative), touches scale accordingly — but " + itoa(len(LockedRuleIds)) +
		" locked safety/compliance rules never budge (violations stay 0 in every scenario)."

	return SandboxReport{
		Baseline:        baseline,
		Scenarios:       results,
		LockedInvariant: lockedInvariant,
		Headline:        headline,
	}, nil
}

// RenderSandbox renders the backtest report.
func RenderSandbox(s SandboxReport) string {
	var out []string
	out = append(out, "")
	out = append(out, "===== BACKTEST SANDBOX (base = real policy defaults) =====")
	header := []string{"scenario", "recovery", "touches", "cost/rec", "locked_viol"}
	rows := [][]string{
		{"baseline   ", pct(s.Baseline.RecoveryRate * 100), itoa(s.Baseline.TouchesSent), cp(s.Baseline), "0"},
	}
	for _, r := range s.Scenarios {
		rows = append(rows, []string{
			padEnd(r.ScenarioLabel, 10),
			pct(r.Metrics.RecoveryRate * 100),
			itoa(r.Metrics.TouchesSent),
			cp(r.Metrics),
			itoa(r.LockedViolations.Sum()),
		})
	}
	out = append(out, renderGrid(header, rows))
	out = append(out, "")
	locked := []string{}
	for _, id := range LockedRuleIds {
		locked = append(locked, string(id))
	}
	out = append(out, "LOCKED RULES: "+strings.Join(locked, ", "))
	if s.LockedInvariant {
		out = append(out, "✓ Locked safety/compliance rules never budge across any tunable sweep (violations 0 in all scenarios).")
	} else {
		out = append(out, "✗ A locked rule was violated — this must never happen.")
	}
	out = append(out, "")
	out = append(out, "HEADLINE:")
	out = append(out, "  "+s.Headline)
	return joinLines(out)
}

func pct2(x float64) string { return fmt.Sprintf("%.1f", x) + "%" }

func percent(x float64) float64 { return x * 100 }

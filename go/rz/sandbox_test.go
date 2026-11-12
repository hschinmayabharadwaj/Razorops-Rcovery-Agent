package rz

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestSandboxRestoresDefaults(t *testing.T) {
	ResetTunables()
	got := GetTunables()
	want := DefaultTunables()
	if got != want {
		t.Fatalf("tunables not restored: %+v vs %+v", got, want)
	}
}

func TestSandboxReport(t *testing.T) {
	events := testEvents(t)
	now := BatchNow()

	report, err := RunSandboxIn(events, now, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Scenarios) < 3 {
		t.Fatalf("scenarios=%d, want >=3", len(report.Scenarios))
	}
	if report.Baseline.RecoveryRate <= 0 {
		t.Fatal("baseline recoveryRate <= 0")
	}
}

func TestSandboxLockedInvariant(t *testing.T) {
	events := testEvents(t)
	now := BatchNow()

	report, err := RunSandboxIn(events, now, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if !report.LockedInvariant {
		t.Fatal("lockedInvariant should be true")
	}
	for _, s := range report.Scenarios {
		if s.LockedViolations.Sum() != 0 {
			t.Fatalf("scenario %s has locked violations: %+v", s.ScenarioLabel, s.LockedViolations)
		}
	}
}

func TestSandboxTunablesMoveRecovery(t *testing.T) {
	events := testEvents(t)
	now := BatchNow()

	report, err := RunSandboxIn(events, now, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var aggressive, conservative *SandboxResult
	for i := range report.Scenarios {
		switch report.Scenarios[i].ScenarioLabel {
		case "aggressive":
			aggressive = &report.Scenarios[i]
		case "conservative":
			conservative = &report.Scenarios[i]
		}
	}
	if aggressive == nil || conservative == nil {
		t.Fatal("missing aggressive/conservative scenarios")
	}
	if aggressive.Metrics.TouchesSent < conservative.Metrics.TouchesSent {
		t.Fatalf("aggressive touches=%d < conservative touches=%d",
			aggressive.Metrics.TouchesSent, conservative.Metrics.TouchesSent)
	}
}

func TestSandboxHeadline(t *testing.T) {
	report, err := RunSandboxIn(testEvents(t), BatchNow(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(report.Headline, "locked") {
		t.Fatal("headline should mention the locked-rule invariant")
	}
}

func TestSandboxExtremeScenario(t *testing.T) {
	events := testEvents(t)
	res, err := RunScenario(events, BatchNow(), "extreme",
		func(tc *TunableConfig) {
			tc.MaxRetryAttempts = 20
			tc.MaxTouchesPerCustomer = 20
			tc.MaxVoiceCalls = 20
		},
		filepath.Join(t.TempDir(), "sandbox.extreme.log.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if res.LockedViolations.Sum() != 0 {
		t.Fatalf("extreme scenario locked violations: %+v", res.LockedViolations)
	}
}

package rz

import (
	"encoding/json"
	"fmt"
	"os"
)

// Sandbox / backtesting configuration. Two kinds of rule:
//
//	TUNABLE  — business-lever caps a merchant/operator may dial. Recovery
//	           trade-offs move with them (more retries => more recovery, more risk).
//
//	LOCKED   — hard safety/compliance invariants that MUST NOT be overridden by
//	           any tunable: fraud_flagged, mandate_revoked, do-not-call, and
//	           telecom quiet-hours. Their predicates accept NO tunable.
type TunableConfig struct {
	MaxRetryAttempts       int   // per-invoice retry budget
	MaxTouchesPerCustomer  int   // blast-radius cap on outbound touches
	CheckoutReminderCap    int   // max checkout reminders/incentives
	MaxVoiceCalls          int   // max voice call attempts
	CartIncentiveThreshold int64 // paise; min cart value to discount
	PtpSupervisorThreshold int64 // paise; PTPs at/above need human sign-off
	MandateWindowDays      int   // NPCI retry window length
	ReceivableTier2Days    int   // net60 boundary
}

// DefaultTunables mirrors today's shipped constants (see rules.go).
func DefaultTunables() TunableConfig {
	return TunableConfig{
		MaxRetryAttempts:       3,
		MaxTouchesPerCustomer:  3,
		CheckoutReminderCap:    2,
		MaxVoiceCalls:          2,
		CartIncentiveThreshold: 50000,
		PtpSupervisorThreshold: 2000000,
		MandateWindowDays:      3,
		ReceivableTier2Days:    60,
	}
}

// LockedRuleIds are permanently locked and can never be overridden.
var LockedRuleIds = []RuleId{
	RuleFraudSuppress,     // isFraudFlagged
	RuleMandateRevokedEsc, // isMandateRevoked
	RuleVoiceDoNotCall,    // isDoNotCall
	RuleQuietHours,        // TRAI 21:00-09:00 IST
}

var tunableRuleIds = []string{
	"max_retry_attempts",
	"max_touches_cap",
	"checkout_reminder_cap",
	"voice_call_cap",
	"cart_incentive_threshold",
	"ptp_supervisor_threshold",
	"mandate_retry_window",
	"receivable_tier2",
}

// LoadTunablesFile reads a JSON file of named tunable overrides and applies
// them atomically. The key whitelist (tunableRuleIds) is the tunability
// surface: the LOCKED invariants (fraud, mandate_revoked, DNC, quiet-hours)
// have no config key at all, so a config file can never override them. Unknown
// keys and non-integer values are rejected loudly rather than silently ignored.
//
// Example (go/tunables.example.json):
//
//	{ "max_retry_attempts": 3, "ptp_supervisor_threshold": 2000000 }
//
// Values are in the unit each rule natively uses: retry counts in attempts,
// caps in touches/calls/reminders, thresholds in paise, windows in days.
func LoadTunablesFile(path string) (TunableConfig, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return tunables, err
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return tunables, fmt.Errorf("config %s: %w", path, err)
	}
	for k := range m {
		if !isTunableKey(k) {
			return tunables, fmt.Errorf("config %s: unknown or locked key %q", path, k)
		}
	}
	// Validate every key into a private copy first; the live tunables are only
	// replaced once the whole file is known to be good (all-or-nothing).
	next := tunables
	for k, v := range m {
		if err := applyTunableKey(&next, k, v); err != nil {
			return tunables, fmt.Errorf("config %s: %w", path, err)
		}
	}
	return SetTunables(next), nil
}

func isTunableKey(k string) bool {
	for _, v := range tunableRuleIds {
		if v == k {
			return true
		}
	}
	return false
}

// applyTunableKey validates one key/value and writes it into t (a caller-owned
// copy); it never touches the live tunables.
func applyTunableKey(t *TunableConfig, k string, v json.RawMessage) error {
	var iVal int
	var i64Val int64
	switch k {
	case "max_retry_attempts", "max_touches_cap", "checkout_reminder_cap", "voice_call_cap",
		"mandate_retry_window", "receivable_tier2":
		if err := json.Unmarshal(v, &iVal); err != nil {
			return fmt.Errorf("key %q must be an integer", k)
		}
		if iVal < 0 {
			return fmt.Errorf("key %q cannot be negative", k)
		}
	case "cart_incentive_threshold", "ptp_supervisor_threshold":
		if err := json.Unmarshal(v, &i64Val); err != nil {
			return fmt.Errorf("key %q must be an integer (paise)", k)
		}
		if i64Val < 0 {
			return fmt.Errorf("key %q cannot be negative", k)
		}
	default:
		return fmt.Errorf("unknown tunable key %q", k)
	}
	switch k {
	case "max_retry_attempts":
		t.MaxRetryAttempts = iVal
	case "max_touches_cap":
		t.MaxTouchesPerCustomer = iVal
	case "checkout_reminder_cap":
		t.CheckoutReminderCap = iVal
	case "voice_call_cap":
		t.MaxVoiceCalls = iVal
	case "mandate_retry_window":
		t.MandateWindowDays = iVal
	case "receivable_tier2":
		t.ReceivableTier2Days = iVal
	case "cart_incentive_threshold":
		t.CartIncentiveThreshold = i64Val
	case "ptp_supervisor_threshold":
		t.PtpSupervisorThreshold = i64Val
	}
	return nil
}

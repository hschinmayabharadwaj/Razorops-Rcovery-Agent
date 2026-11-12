package rz

import (
	"errors"
	"strconv"
	"time"
)

func itoa(i int) string { return strconv.Itoa(i) }

// StepResult carries the next evaluated step plus its audit entry.
type StepResult struct {
	Next  EvaluatedStep
	Audit AuditEntry
}

// Iso formats epoch ms as a UTC ISO-8601 timestamp matching JS toISOString().
func Iso(ms int64) string {
	return time.UnixMilli(ms).UTC().Format("2006-01-02T15:04:05.000Z07:00")
}

// StepState is the unified pure state transition for any flow. Given a
// RecoveryContext, the engine picks the next state + audit entry. No side effects.
func StepState(ctx *RecoveryContext) (StepResult, error) {
	if ctx == nil {
		return StepResult{}, errors.New("stepState: missing context")
	}

	input := StoppingInput{
		Reason:                 ctx.Reason,
		CurrentAttempt:         ctx.Attempt,
		TouchesForCustomer:     ctx.TouchesForCustomer,
		ActivePromiseToPayDate: ctx.ActivePromiseToPayDate,
		OverdueDays:            ctx.OverdueDays,
		Now:                    ctx.Now,
		RetryWindow:            ctx.RetryWindow,
		DNCFlag:                ctx.DNCFlag,
		CartValue:              ctx.CartValue,
		Visits:                 ctx.Visits,
		RollingSuccessRate:     ctx.RollingSuccessRate,
		// Amount drives PtpNeedsSupervisor: without it the dual-control rule
		// for high-value promise-to-pay events can never fire.
		Amount: ctx.Amount,
	}

	d := DecideForFlow(ctx.Flow, input)
	ts := Iso(ctx.Now)

	base := AuditEntry{
		EventID:      ctx.EventID,
		Timestamp:    ts,
		Flow:         ctx.Flow,
		ReasonBucket: ctx.Reason,
		CustomerID:   ctx.CustomerID,
		InvoiceID:    ctx.InvoiceID,
		Amount:       i64p(ctx.Amount),
		Currency:     ctx.Currency,
		Attempt:      intp(ctx.Attempt),
	}

	next := EvaluatedStep{
		State:     stateFor(d.Decision, ctx.Flow),
		RuleFired: d.RuleFired,
		Decision:  d.Decision,
		Outcome:   outcomeFor(ctx, d.RuleFired, d.Decision),
	}

	audit := base
	audit.RuleFired = d.RuleFired
	audit.Decision = d.Decision
	audit.Actor = ActorPolicyEngine
	audit.State = next.State
	audit.Outcome = next.Outcome

	return StepResult{Next: next, Audit: audit}, nil
}

func stateFor(decision Decision, flow FlowType) AgentState {
	switch decision {
	case DecisionRecover:
		return AgentRecovered
	case DecisionEscalate:
		return AgentEscalated
	case DecisionSuppress:
		return AgentSuppressed
	case DecisionAbandon:
		return AgentAbandoned
	case DecisionHold:
		if flow == FlowPromiseToPay {
			return AgentWaitingOnPtp
		}
		return AgentRetryScheduled
	case DecisionContact:
		return AgentContactScheduled
	case DecisionRetry:
		return AgentRetryScheduled
	default:
		return AgentDetected
	}
}

func outcomeFor(ctx *RecoveryContext, rule RuleId, decision Decision) string {
	who := ctx.CustomerID
	switch rule {
	case RuleFraudSuppress:
		return "Suppressed all recovery for " + who + " (fraud/risk)"
	case RuleMandateRevokedEsc:
		return "Escalated " + ctx.EventID + " to human (mandate revoked, never retried)"
	case RulePromiseToPaySuppress, RulePtpSuppress:
		return "Suppressed touches for " + who + " until active promise-to-pay date passes"
	case RuleExhaustAttemptsEscalate:
		return "Escalated " + ctx.EventID + " to human after " + itoa(ctx.Attempt) + " failed retries"
	case RuleMaxTouchesCap:
		return "Stopped recovery for " + who + ": outbound touch cap reached"
	case RuleMandateRetryWindow:
		return "Held " + ctx.EventID + ": outside NPCI mandate retry window"
	case RuleMandateRetrySeq:
		return "Sequenced " + ctx.EventID + " retry within mandate window"
	case RuleTransientRetry:
		return "Scheduled retry attempt " + itoa(ctx.Attempt+1) + " for " + ctx.EventID
	case RuleCheckoutReminder:
		return "Sending checkout reminder for abandoned cart " + ctx.EventID
	case RuleCartIncentive:
		return "Offering cart incentive to recover abandoned checkout " + ctx.EventID
	case RuleCheckoutAbandon:
		return "Abandoned checkout recovery for " + ctx.EventID + " (error/edge)"
	case RuleRepeatVisitorOnly:
		return "Abandoned " + ctx.EventID + ": one-time visitor, no recovery (spam guard)"
	case RuleInvoiceReminder:
		return "Sent dunning reminder for receivable " + ctx.EventID
	case RuleInvoiceEscalateDun:
		return "Escalated receivable " + ctx.EventID + " to collections (dunning)"
	case RuleDisputeHold:
		return "Held receivable " + ctx.EventID + ": disputed, routed to collections"
	case RuleDegradationAlert:
		return "Alerted on payment degradation for " + ctx.EventID
	case RuleDegradationRecover:
		return "Recovered from degradation window for " + ctx.EventID
	case RuleDegradationEscalate:
		return "Escalated degradation (issuer down) for " + ctx.EventID
	case RuleVoiceCall:
		return "Placing Hinglish voice recovery call for " + ctx.EventID
	case RuleVoiceRetry:
		return "Retrying voice call for " + ctx.EventID + " (unreachable)"
	case RuleVoiceDoNotCall:
		return "Stopped voice recovery for " + who + ": DNC / quiet hours"
	case RuleVoiceEscalateHuman:
		return "Escalated voice recovery for " + ctx.EventID + " to human agent"
	case RulePtpSchedule:
		return "Scheduled promise-to-pay follow-up for " + ctx.EventID
	case RulePtpReminderBefore:
		return "Sent PTP reminder before due date for " + ctx.EventID
	case RulePtpFollowup:
		return "Following up after promise-to-pay date for " + ctx.EventID
	case RulePtpMissedEscalate:
		return "Escalated promise-to-pay (missed/broken) for " + ctx.EventID
	default:
		return string(decision) + " via " + string(rule) + " for " + ctx.EventID
	}
}

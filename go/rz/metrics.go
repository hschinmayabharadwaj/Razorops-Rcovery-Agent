package rz

import "sort"

// Metrics computed purely from the audit log (never asserted).

type ExceptionItem struct {
	EventID        string
	Flow           FlowType
	CustomerID     string
	InvoiceID      string
	Reason         ReasonBucket
	Status         string // escalated | abandoned | waiting_on_ptp
	AmountInRupees float64
	RuleFired      string
	Outcome        string
}

type FlowMetrics struct {
	Events          int
	RecoveredCount  int
	RecoveredRupees float64
	Escalated       int
	Suppressed      int
	Abandoned       int
	Touches         int
}

type Metrics struct {
	TotalEvents       int
	TotalAtRiskRupees float64
	RecoveredCount    int
	RecoveredRupees   float64
	RecoveryRate      float64
	TouchesSent       int
	CostPerRecovery   float64
	EscalatedCount    int
	AbandonedCount    int
	SuppressedCount   int
	ByFlow            map[FlowType]FlowMetrics
	ExceptionList     []ExceptionItem
}

func initFlow() FlowMetrics {
	return FlowMetrics{}
}

// ComputeMetrics derives metrics purely from the log.
func ComputeMetrics(log []AuditEntry) Metrics {
	byFlow := map[FlowType]FlowMetrics{}
	for _, f := range FlowTypes {
		byFlow[f] = initFlow()
	}

	terminal := map[string]AuditEntry{}
	seen := map[string]bool{}
	for _, e := range log {
		// Idempotency-suppression rows stay in the chain (integrity) but are
		// not business activity: they must not overwrite the event's terminal
		// state or inflate per-flow counts/at-risk totals on replay.
		if e.RuleFired == RuleDuplicateSuppress {
			continue
		}
		// Forwarded gateway payment events share the log (and the chain) but are
		// not recovery activity: a verified test payment must not count as a
		// "recovered" event or dilute cost-per-recovery.
		if e.Flow == FlowPaymentEvent {
			continue
		}
		fm := byFlow[e.Flow]
		if !seen[e.EventID] {
			fm.Events++
			seen[e.EventID] = true
		}
		if e.Decision == DecisionRetry || e.Decision == DecisionContact {
			fm.Touches++
		}
		if IsTerminalState(e.State) {
			terminal[e.EventID] = e
		}
		byFlow[e.Flow] = fm
	}

	recoveredCount, recoveredRupees, totalAtRisk := 0, float64(0), float64(0)
	for _, e := range terminal {
		amt := float64(0)
		if e.Amount != nil {
			amt = float64(*e.Amount)
		}
		totalAtRisk += amt
		fm := byFlow[e.Flow]
		switch e.State {
		case AgentRecovered:
			fm.RecoveredCount++
			fm.RecoveredRupees += amt
			recoveredCount++
			recoveredRupees += amt
		case AgentEscalated:
			fm.Escalated++
		case AgentSuppressed:
			fm.Suppressed++
		case AgentAbandoned:
			fm.Abandoned++
		}
		byFlow[e.Flow] = fm
	}

	var exceptionList []ExceptionItem
	for _, e := range terminal {
		if e.State == AgentEscalated || e.State == AgentAbandoned || e.State == AgentWaitingOnPtp {
			amt := float64(0)
			if e.Amount != nil {
				amt = float64(*e.Amount)
			}
			exceptionList = append(exceptionList, ExceptionItem{
				EventID:        e.EventID,
				Flow:           e.Flow,
				CustomerID:     e.CustomerID,
				InvoiceID:      e.InvoiceID,
				Reason:         e.ReasonBucket,
				Status:         string(e.State),
				AmountInRupees: amt / 100,
				RuleFired:      string(e.RuleFired),
				Outcome:        e.Outcome,
			})
		}
	}
	sort.Slice(exceptionList, func(i, j int) bool {
		return exceptionList[i].Flow < exceptionList[j].Flow
	})

	touchesSent := 0
	for _, f := range FlowTypes {
		touchesSent += byFlow[f].Touches
	}

	recoveryRate := float64(0)
	if totalAtRisk > 0 {
		recoveryRate = recoveredRupees / totalAtRisk
	}
	costPerRecovery := float64(0)
	if recoveredCount > 0 {
		costPerRecovery = float64(touchesSent) / float64(recoveredCount)
	}

	escalatedCount, abandonedCount, suppressedCount := 0, 0, 0
	for _, e := range exceptionList {
		switch e.Status {
		case "escalated":
			escalatedCount++
		case "abandoned":
			abandonedCount++
		}
	}
	for _, e := range terminal {
		if e.State == AgentSuppressed {
			suppressedCount++
		}
	}

	return Metrics{
		TotalEvents:       len(terminal),
		TotalAtRiskRupees: totalAtRisk / 100,
		RecoveredCount:    recoveredCount,
		RecoveredRupees:   recoveredRupees / 100,
		RecoveryRate:      recoveryRate,
		TouchesSent:       touchesSent,
		CostPerRecovery:   costPerRecovery,
		EscalatedCount:    escalatedCount,
		AbandonedCount:    abandonedCount,
		SuppressedCount:   suppressedCount,
		ByFlow:            byFlow,
		ExceptionList:     exceptionList,
	}
}

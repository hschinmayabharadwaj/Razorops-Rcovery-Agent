package rz

import "fmt"

// Intelligence bundles the trained decision heads with the history they were
// trained on and their out-of-time evaluation.
//
// Training data is a separate, larger synthetic history (its own seed), run
// through the real policy engine so every label comes from a hash-chained
// audit log, never from the simulator directly. The served batch is never
// trained on, so predictions about it are out-of-sample. The history log is
// kept in memory: it is an intermediate artifact, never live activity.

// Intelligence history defaults.
const (
	IntelligenceHistorySeed  uint32 = 20260917
	IntelligenceHistoryCount        = 800
)

// Intelligence is a trained set of decision heads.
type Intelligence struct {
	Model         *RecoveryModel
	Evaluation    ModelEvaluation
	HistoryEvents int
	HistoryLog    []AuditEntry
	Seed          uint32
}

// TrainIntelligence generates the history batch, runs it through the policy
// engine into an in-memory audit log, evaluates the heads out-of-time, and
// refits the served model on the full history.
func TrainIntelligence(seed uint32, count int) (*Intelligence, error) {
	events := GenerateEventsWith(GenOptions{Seed: seed, Count: count})
	store := NewMemoryAuditStore()
	// The history batch is far larger than the per-batch attempt cap meant for
	// one live run; lift the cap so every history event reaches an outcome.
	unlimited := len(events) * (GetTunables().MaxRetryAttempts + 2) * 4
	if _, err := RunBatch(events, store, RunnerOpts{Now: BatchNow(), MaxBatchAttempts: &unlimited}); err != nil {
		return nil, fmt.Errorf("intelligence: history batch: %w", err)
	}
	log, err := store.All()
	if err != nil {
		return nil, fmt.Errorf("intelligence: read history: %w", err)
	}
	if v := VerifyChain(log); !v.Valid {
		return nil, fmt.Errorf("intelligence: history chain broken at entry %d", v.BrokenAtIndex)
	}

	examples := BuildRecoveryExamples(events, log)
	return &Intelligence{
		Model:         TrainRecoveryModel(examples, DefaultRecoverySmoothing),
		Evaluation:    EvaluateRecoveryHeads(examples, DefaultRecoverySmoothing),
		HistoryEvents: len(events),
		HistoryLog:    log,
		Seed:          seed,
	}, nil
}

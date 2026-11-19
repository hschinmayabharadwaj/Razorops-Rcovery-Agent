package rz

import "sort"

// Recent-context health. Vulcan fuses a payment with recent terminal,
// merchant and gateway activity plus live route-health signals at decision
// time. Our equivalent: how each recovery channel is performing in the
// served audit log compared with its long-run baseline from history, and the
// gateway/issuer degradation signals carried by payment_degradation events.

// Health thresholds.
const (
	// MinHealthSamples is the fewest executed touches before a channel's rate
	// is judged; below it the channel is reported as insufficient data.
	MinHealthSamples = 5
	// DegradedRatio flags a channel whose recent success rate falls below
	// this share of its long-run baseline.
	DegradedRatio = 0.7
)

// Channel health statuses.
const (
	HealthHealthy      = "healthy"
	HealthDegraded     = "degraded"
	HealthInsufficient = "insufficient_data"
)

// ChannelHealth is one recovery channel's recent performance.
type ChannelHealth struct {
	Channel      string
	Touches      int
	Recovered    int
	SuccessRate  float64
	Baseline     float64
	BaselineFrom int
	Status       string
}

// RouteSignal is a gateway/issuer health signal from a degradation event.
type RouteSignal struct {
	EventID     string
	Reason      ReasonBucket
	SuccessRate float64
	LatencyMs   float64
	IssuerDown  bool
	ErrorCode   string
	Status      string
}

// HealthReport is the full health view.
type HealthReport struct {
	Channels []ChannelHealth
	Routes   []RouteSignal
}

type touchKey struct {
	eventID string
	attempt int
}

// channelOutcomes counts executed touches per channel. An executed touch is a
// policy-engine row carrying a channel and an attempt; the runner writes one
// action row per touch plus a recovered row on success, so rows are
// de-duplicated per (event, attempt) and a touch succeeded if any of its rows
// reached the recovered state.
func channelOutcomes(entries []AuditEntry) map[string]outcomeCounts {
	channelOf := map[touchKey]string{}
	succeeded := map[touchKey]bool{}
	order := []touchKey{}
	for _, e := range entries {
		if e.Actor != ActorPolicyEngine || e.Channel == "" || e.Attempt == nil || e.RuleFired == RuleDuplicateSuppress {
			continue
		}
		k := touchKey{e.EventID, *e.Attempt}
		if _, seen := channelOf[k]; !seen {
			channelOf[k] = e.Channel
			order = append(order, k)
		}
		if e.State == AgentRecovered {
			succeeded[k] = true
		}
	}
	out := map[string]outcomeCounts{}
	for _, k := range order {
		c := out[channelOf[k]]
		c.n++
		if succeeded[k] {
			c.pos++
		}
		out[channelOf[k]] = c
	}
	return out
}

// BuildHealthReport compares recent channel performance (served log) with
// the long-run baseline (history log) and collects route signals.
func BuildHealthReport(recent, history []AuditEntry, events []*FlowEvent) HealthReport {
	now := channelOutcomes(recent)
	base := channelOutcomes(history)
	names := map[string]bool{}
	for c := range now {
		names[c] = true
	}
	for c := range base {
		names[c] = true
	}
	channels := make([]ChannelHealth, 0, len(names))
	for name := range names {
		c, b := now[name], base[name]
		h := ChannelHealth{Channel: name, Touches: int(c.n), Recovered: int(c.pos), BaselineFrom: int(b.n)}
		if c.n > 0 {
			h.SuccessRate = c.pos / c.n
		}
		if b.n > 0 {
			h.Baseline = b.pos / b.n
		}
		switch {
		case c.n < MinHealthSamples || b.n < MinHealthSamples:
			h.Status = HealthInsufficient
		case h.SuccessRate < h.Baseline*DegradedRatio:
			h.Status = HealthDegraded
		default:
			h.Status = HealthHealthy
		}
		channels = append(channels, h)
	}
	sort.Slice(channels, func(i, j int) bool { return channels[i].Channel < channels[j].Channel })

	var routes []RouteSignal
	for _, ev := range events {
		if ev.Flow != FlowPaymentDegradation {
			continue
		}
		s := decisionTimeSignal(ev.Signal)
		r := RouteSignal{
			EventID:     ev.EventID,
			Reason:      Classify(ev),
			SuccessRate: numField(s, "success_rate"),
			LatencyMs:   numField(s, "latency_ms"),
			IssuerDown:  boolField(s, "issuer_down"),
			ErrorCode:   strField(s, "error_code"),
			Status:      HealthHealthy,
		}
		if r.IssuerDown || (r.SuccessRate > 0 && SuccessRateBelowThreshold(r.SuccessRate)) || r.LatencyMs > DegradationLatencyMsThreshold {
			r.Status = HealthDegraded
		}
		routes = append(routes, r)
	}
	sort.Slice(routes, func(i, j int) bool { return routes[i].EventID < routes[j].EventID })
	return HealthReport{Channels: channels, Routes: routes}
}

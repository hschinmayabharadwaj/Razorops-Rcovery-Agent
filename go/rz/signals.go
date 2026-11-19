package rz

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Decision-time signal profile: the ONE shared representation every decision
// head reads (the recovery-probability head, the risk head and the work-queue
// ordering). Lesson taken from Razorpay's Vulcan: separate per-task feature
// pipelines drift apart and cannot share what they learn, so build a single
// payment representation and put small task heads on top of it.
//
// Two hard rules, also taken from Vulcan:
//   - decision-time cut-off: only fields known when the decision is taken may
//     enter a profile. Outcome fields (for example signal.recovered on a
//     payment_degradation event) would leak the label and are excluded.
//   - no direct identifiers: names, phone numbers and emails never enter a
//     profile. Stable references (the customer id) are hashed into tokens.
//     Hashing is pseudonymisation, not anonymisation, so profiles are still
//     treated as personal data.

// FailureClass says WHO can fix a failure. Only route-influenceable failures
// can be fixed by choosing a better path or timing; customer-side failures
// need the customer to act, so retrying them only burns touches.
type FailureClass string

const (
	FailureRouteInfluenceable FailureClass = "route_influenceable"
	FailureCustomerSide       FailureClass = "customer_side"
	FailureCustomerLeft       FailureClass = "customer_left"
	FailureBlocked            FailureClass = "blocked"
	FailureUnclassified       FailureClass = "unclassified"
)

var failureClassByReason = map[ReasonBucket]FailureClass{
	// The bank, issuer, gateway or our own checkout failed: a different path,
	// a later attempt or a fixed page can recover it.
	ReasonBankDeclinedTransien: FailureRouteInfluenceable,
	ReasonIssuerDown:           FailureRouteInfluenceable,
	ReasonSuccessRateDrop:      FailureRouteInfluenceable,
	ReasonLatencySpike:         FailureRouteInfluenceable,
	ReasonMandateBankDown:      FailureRouteInfluenceable,
	ReasonSlowCheckout:         FailureRouteInfluenceable,
	ReasonCheckoutError:        FailureRouteInfluenceable,
	// The customer must act (fund the account, renew the card, finish auth).
	ReasonInsufficientFunds:   FailureCustomerSide,
	ReasonCardExpired:         FailureCustomerSide,
	ReasonAuth3dsAbandoned:    FailureCustomerSide,
	ReasonMandateInsufficient: FailureCustomerSide,
	ReasonMandateAuthPending:  FailureCustomerSide,
	// The customer walked away or has not paid yet: a nudge can recover it.
	ReasonPaymentStepAbandoned: FailureCustomerLeft,
	ReasonAddressAbandoned:     FailureCustomerLeft,
	ReasonPriceMismatch:        FailureCustomerLeft,
	ReasonVoiceMissedCall:      FailureCustomerLeft,
	ReasonVoiceAskedCallBack:   FailureCustomerLeft,
	ReasonVoiceUnreachable:     FailureCustomerLeft,
	ReasonOverdueNet30:         FailureCustomerLeft,
	ReasonOverdueNet60:         FailureCustomerLeft,
	ReasonPtpCommitted:         FailureCustomerLeft,
	ReasonPtpMissed:            FailureCustomerLeft,
	ReasonPtpBroken:            FailureCustomerLeft,
	// No automated recovery is allowed at all.
	ReasonFraudFlagged:       FailureBlocked,
	ReasonMandateRevoked:     FailureBlocked,
	ReasonDisputedReceivable: FailureBlocked,
}

// ClassifyFailure maps a reason bucket to the party that can fix it.
func ClassifyFailure(reason ReasonBucket) FailureClass {
	if c, ok := failureClassByReason[reason]; ok {
		return c
	}
	return FailureUnclassified
}

// ProfileExcludedPII lists event fields that never enter a profile.
var ProfileExcludedPII = []string{"customerName", "customerPhone", "customerEmail"}

// ProfileExcludedOutcome lists signal fields that describe the outcome and are
// therefore unknown at decision time.
var ProfileExcludedOutcome = []string{"recovered"}

// Amount bands, in rupees.
const (
	amountBandSmallMaxRupees  = 1_000
	amountBandMediumMaxRupees = 10_000
	amountBandLargeMaxRupees  = 100_000
)

// istOffset is India Standard Time (UTC+05:30) for time-of-day bands.
var istOffset = time.FixedZone("IST", 5*3600+30*60)

// SignalProfile is the shared decision-time representation of one event.
type SignalProfile struct {
	EventID      string
	Flow         FlowType
	Reason       ReasonBucket
	FailureClass FailureClass
	Method       string
	AmountBand   string
	DayPart      string
	CustomerRef  string // hashed customer token, never the raw id
	Amount       int64  // paise
	OccurredAt   int64
	History      CustomerHistory // decision-time customer history (risk head input)
	Tokens       []string        // sorted categorical tokens, for display and audit
}

// BuildSignalProfile builds the decision-time profile of an event.
func BuildSignalProfile(ev *FlowEvent) SignalProfile {
	reason := Classify(ev)
	method := strField(decisionTimeSignal(ev.Signal), "payment_method")
	if method == "" {
		method = "n/a"
	}
	p := SignalProfile{
		EventID:      ev.EventID,
		Flow:         ev.Flow,
		Reason:       reason,
		FailureClass: ClassifyFailure(reason),
		Method:       method,
		AmountBand:   amountBand(ev.Amount),
		DayPart:      dayPart(ev.OccurredAt),
		CustomerRef:  hashedRef("cust", ev.CustomerID),
		Amount:       ev.Amount,
		OccurredAt:   ev.OccurredAt,
		History:      DeriveHistory(&FlowEvent{CustomerID: ev.CustomerID, Amount: ev.Amount, Signal: decisionTimeSignal(ev.Signal)}),
	}
	p.Tokens = []string{
		"flow:" + string(p.Flow),
		"reason:" + string(p.Reason),
		"class:" + string(p.FailureClass),
		"method:" + p.Method,
		"amount:" + p.AmountBand,
		"daypart:" + p.DayPart,
		p.CustomerRef,
	}
	sort.Strings(p.Tokens)
	return p
}

// decisionTimeSignal returns a copy of the signal without outcome fields.
func decisionTimeSignal(signal map[string]any) map[string]any {
	out := make(map[string]any, len(signal))
	for k, v := range signal {
		out[k] = v
	}
	for _, k := range ProfileExcludedOutcome {
		delete(out, k)
	}
	return out
}

func hashedRef(kind, value string) string {
	if strings.TrimSpace(value) == "" {
		return kind + ":none"
	}
	return fmt.Sprintf("%s:%08x", kind, HashStr(value))
}

func amountBand(paise int64) string {
	rupees := paise / 100
	switch {
	case rupees < amountBandSmallMaxRupees:
		return "lt_1k"
	case rupees < amountBandMediumMaxRupees:
		return "1k_10k"
	case rupees < amountBandLargeMaxRupees:
		return "10k_1l"
	default:
		return "gte_1l"
	}
}

func dayPart(ms int64) string {
	if ms == 0 {
		return "unknown"
	}
	hour := time.UnixMilli(ms).In(istOffset).Hour()
	switch {
	case hour >= 9 && hour < 17:
		return "business_hours"
	case hour >= 17 && hour < 21:
		return "evening"
	default:
		return "quiet_hours"
	}
}

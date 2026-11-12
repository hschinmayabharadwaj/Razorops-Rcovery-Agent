package rz

// PII redaction for log / exception-list views.
// The hash chain protects INTEGRITY, not CONFIDENTIALITY: audit entries carry
// customer IDs, invoice IDs, phone numbers and amounts in plaintext. This
// module provides a field-level redaction layer so any read surface can hide
// PII fields unless the caller is authorized. Redaction is intentionally
// conservative: it only masks at presentation time, never from the chain.

var PII_FIELDS = []string{"customerId", "customerName", "customerPhone", "customerEmail"}

const (
	PhoneLen  = 4
	EmailKeep = 2
)

// minMaskablePhoneLen is the shortest phone that can show its 3-char prefix and
// 2-char suffix while still hiding something; anything shorter is fully masked.
const minMaskablePhoneLen = 8

func maskPhone(phone string) string {
	if len(phone) < minMaskablePhoneLen {
		return "••••"
	}
	return phone[:3] + "••••" + phone[len(phone)-2:]
}

func maskEmail(email string) string {
	at := indexOf(email, '@')
	if at < 0 {
		// Not an email shape: there is no domain to keep, so reveal nothing.
		return "•••"
	}
	if at == 0 {
		return "•••@" + email[1:]
	}
	local := email[:at]
	domain := email[at+1:]
	shown := local
	if len(shown) > EmailKeep {
		shown = shown[:EmailKeep]
	}
	return shown + "•••@" + domain
}

func maskName(name string) string {
	if name == "" {
		return "•••"
	}
	parts := splitWords(name)
	if len(parts) == 0 {
		return "•••"
	}
	// Every word is masked to its first character — including a single-word
	// name, which would otherwise be returned in full.
	for i := range parts {
		parts[i] = maskWord(parts[i])
	}
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += " "
		}
		out += p
	}
	return out
}

// maskWord keeps the first character (rune-safe) and masks the rest.
func maskWord(word string) string {
	for _, r := range word {
		return string(r) + "•••"
	}
	return "•••"
}

// RedactPII returns a copy of record with the given PII fields masked.
func RedactPII(record map[string]any, fields ...string) map[string]any {
	if fields == nil {
		fields = PII_FIELDS
	}
	out := make(map[string]any, len(record))
	for k, v := range record {
		out[k] = v
	}
	for _, f := range fields {
		raw, ok := out[f]
		if !ok {
			continue
		}
		s, ok := raw.(string)
		if !ok {
			continue
		}
		switch f {
		case "customerPhone":
			out[f] = maskPhone(s)
		case "customerEmail":
			out[f] = maskEmail(s)
		case "customerName":
			out[f] = maskName(s)
		case "customerId":
			if len(s) > 4 {
				out[f] = "cust_•••" + s[len(s)-4:]
			} else {
				out[f] = "cust_•••" + s
			}
		}
	}
	return out
}

func indexOf(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

func splitWords(s string) []string {
	var out []string
	start := -1
	for i := 0; i < len(s); i++ {
		if s[i] == ' ' || s[i] == '\t' {
			if start >= 0 {
				out = append(out, s[start:i])
				start = -1
			}
		} else {
			if start < 0 {
				start = i
			}
		}
	}
	if start >= 0 {
		out = append(out, s[start:])
	}
	return out
}

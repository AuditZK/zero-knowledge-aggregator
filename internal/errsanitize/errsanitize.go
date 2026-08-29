// Package errsanitize maps an internal error message to a fixed, user-facing
// category message. It is shared by every egress that renders an error for a
// client so the categories cannot drift apart: the gRPC sanitizer, and
// SyncResult.Error, which is persisted in sync_statuses and serialised to
// REST/gRPC without passing through any output sanitizer (SEC-12).
package errsanitize

import "strings"

// Category messages shared by several match substrings — kept as constants so
// the same user-facing text isn't duplicated across rows.
const (
	msgExchangeUnreachable = "could not reach the exchange endpoint"
	msgExchangeTimeout     = "the exchange request timed out"
	msgIPNotWhitelisted    = "server IP not whitelisted on the exchange"
	msgServiceUnavailable  = "service temporarily unavailable"
)

type category struct {
	substr  string
	message string
}

// categories maps a substring that marks an error as safe to surface to the
// end-user (a category of failure they can act on — wrong credentials, IP not
// whitelisted, etc.) to a fixed, infrastructure-free message. SEC-07:
// returning the RAW error text on a match leaked internal detail (e.g. "dial
// tcp internal-db:5432: connect: connection refused" matches "connection
// refused"). First match wins, so more specific substrings come first.
var categories = []category{
	{"invalid credentials", "invalid credentials"},
	{"invalid api key", "invalid API key"},
	{"invalid signature", "invalid API signature"},
	{"auth_failed", "authentication failed"},
	{"unauthorized", "unauthorized"},
	{"insufficient permission", "insufficient API key permissions"},
	{"permission denied", "permission denied"},
	{"ip not whitelist", msgIPNotWhitelisted},
	{"ip restricted", msgIPNotWhitelisted},
	{"whitelist", msgIPNotWhitelisted},
	{"no such host", msgExchangeUnreachable},
	{"connection refused", msgExchangeUnreachable},
	{"deadline exceeded", msgExchangeTimeout},
	{"timeout", msgExchangeTimeout},
	{"validation failed", "validation failed"},
	{"protocol_error", "protocol error"},
	{"failed to create connection", "failed to create connection"},
	{"failed to create user", "failed to create user"},
	{"already exists", "resource already exists"},
	{"not found", "resource not found"},
	{"database not configured", msgServiceUnavailable},
	{"sync service not available", msgServiceUnavailable},
	{"report service not available", msgServiceUnavailable},
	{"service not available", msgServiceUnavailable},
}

// Category returns the canonical message for the failure class msg belongs
// to, or "" when msg matches none — leaving the caller to apply its own
// generic fallback rather than echoing any part of msg.
func Category(msg string) string {
	lower := strings.ToLower(msg)
	for _, c := range categories {
		if strings.Contains(lower, c.substr) {
			return c.message
		}
	}
	return ""
}

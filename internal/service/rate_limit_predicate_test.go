package service

import "testing"

// isRateLimitError is the single predicate that (a) arms the 6h deferred
// retry and (b) flips the recorded status to "pending" instead of "error".
// All three producers must keep matching it: IBKR's own 1018 code, its prose
// variant, and the local token gate's typed error.
func TestIsRateLimitError(t *testing.T) {
	matching := []string{
		"get balance: transient connector error: flex request failed: 1018 - Too many requests have been made from this token. Please try again shortly.",
		"flex request failed: 1018",
		"Too many requests",
		"get balance: transient connector error: shared flex token cooling down (in use 237ms ago; retry after ~03:00 UTC)",
	}
	for _, s := range matching {
		if !isRateLimitError(s) {
			t.Errorf("must match, did not: %q", s)
		}
	}

	nonMatching := []string{
		"",
		"get balance: transient connector error: flex request failed: 1001 - Statement generation in progress",
		"token refresh rejected: ACCESS_DENIED",
		"get balance: invalid credentials",
	}
	for _, s := range nonMatching {
		if isRateLimitError(s) {
			t.Errorf("must not match, did: %q", s)
		}
	}
}

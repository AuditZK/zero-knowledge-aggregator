package connector

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// The bug this gate exists for: two IBKR connections sharing one Flex token
// (CTO+PEA, two query IDs) raced into IBKR within the same millisecond every
// midnight — observed at 00:00:18.185 and 00:00:18.422 on 2026-08-27 — and
// the loser burned a second request on its follow-up GetBalance. IBKR's 1018
// limit is per TOKEN; the report cache and singleflight are keyed
// token:queryID, so neither protected this case.

func TestClaimFlexToken_SecondClaimWithinCooldownDenied(t *testing.T) {
	token := "gate-test-token-A"
	now := time.Now()

	if _, ok := claimFlexToken(token, now); !ok {
		t.Fatal("first claim on a fresh token must be granted")
	}
	last, ok := claimFlexToken(token, now.Add(237*time.Millisecond))
	if ok {
		t.Fatal("second claim 237ms later must be denied — this is the exact CTO/PEA race")
	}
	if !last.Equal(now) {
		t.Fatalf("denial must report the winning claim's time, got %v want %v", last, now)
	}
}

func TestClaimFlexToken_DistinctTokensDoNotInterfere(t *testing.T) {
	now := time.Now()
	if _, ok := claimFlexToken("gate-test-token-B1", now); !ok {
		t.Fatal("first token must claim")
	}
	if _, ok := claimFlexToken("gate-test-token-B2", now); !ok {
		t.Fatal("a different token must not be blocked by the first one's claim")
	}
}

func TestClaimFlexToken_ReopensAfterCooldown(t *testing.T) {
	token := "gate-test-token-C"
	now := time.Now()

	if _, ok := claimFlexToken(token, now); !ok {
		t.Fatal("initial claim must be granted")
	}
	if _, ok := claimFlexToken(token, now.Add(flexTokenCooldown-time.Second)); ok {
		t.Fatal("claim just inside the cooldown must be denied")
	}
	// The denied attempt must NOT have refreshed the claim: the window is
	// measured from the granted request, or the deferred retry could be
	// pushed back forever by its own probes.
	if _, ok := claimFlexToken(token, now.Add(flexTokenCooldown+time.Second)); !ok {
		t.Fatal("claim just past the cooldown must be granted — the 6h deferred retry depends on it")
	}
}

func TestErrFlexTokenBusy_IsTransientAndMatchesRateLimitPredicate(t *testing.T) {
	// Shaped exactly as fetchFlexReport emits it.
	err := fmt.Errorf("%w (in use 3m0s ago; retry after ~03:00 UTC)", ErrFlexTokenBusy)

	if !errors.Is(err, ErrTransient) {
		t.Fatal("token-busy must be transient — it is pacing, not a credential failure")
	}
	if !errors.Is(err, ErrFlexTokenBusy) {
		t.Fatal("the sentinel must survive wrapping so the sync layer can downgrade its log")
	}
	// The sync layer matches on this substring (isRateLimitError) to arm the
	// deferred retry and record status "pending". Renaming the message
	// silently disarms both — this test is the tripwire.
	if !strings.Contains(err.Error(), "shared flex token cooling down") {
		t.Fatalf("error text must carry the machine-readable marker, got: %s", err.Error())
	}
}

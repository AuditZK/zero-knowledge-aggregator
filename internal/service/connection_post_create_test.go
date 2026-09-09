package service

import (
	"context"
	"testing"
	"time"
)

type hookRecorder struct {
	order chan string
}

func newHookRecorder() *hookRecorder { return &hookRecorder{order: make(chan string, 4)} }

func (h *hookRecorder) hook(name string) func(context.Context, string, string, string) {
	return func(_ context.Context, userUID, exchange, label string) {
		h.order <- name + ":" + userUID + "/" + exchange + "/" + label
	}
}

func (h *hookRecorder) next(t *testing.T, want string) {
	t.Helper()
	select {
	case got := <-h.order:
		if got != want {
			t.Fatalf("hook fired %q, want %q", got, want)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("hook %q never fired", want)
	}
}

func (h *hookRecorder) expectNothingMore(t *testing.T) {
	t.Helper()
	select {
	case got := <-h.order:
		t.Fatalf("unexpected extra hook: %q", got)
	case <-time.After(150 * time.Millisecond):
	}
}

// G-H7 / C7: the first live snapshot must run for every new connection, not
// only for callers that asked for a history rebuild. The cTrader OAuth
// callback sends no rebuild_history field, the gateway defaults it to false,
// and the whole hook was skipped — so a new cTrader account had no snapshot,
// no sync_statuses row and no status in the admin until 00:00 UTC.
func TestDispatchPostCreateHooks_SyncRunsWithoutRebuildOptIn(t *testing.T) {
	rec := newHookRecorder()
	svc := &ConnectionService{
		postCreateSyncHook:    rec.hook("sync"),
		postCreateRebuildHook: rec.hook("rebuild"),
	}

	svc.dispatchPostCreateHooks("user-1", "ctrader", "cTrader Account", false)

	rec.next(t, "sync:user-1/ctrader/cTrader Account")
	rec.expectNothingMore(t)
}

// SEC-ZK-001 / SEC-08: the rebuild — which ships decrypted credentials to a
// service outside the enclave for non-IBKR exchanges — stays behind the
// explicit opt-in.
func TestDispatchPostCreateHooks_RebuildStaysOptIn(t *testing.T) {
	rec := newHookRecorder()
	svc := &ConnectionService{
		postCreateSyncHook:    rec.hook("sync"),
		postCreateRebuildHook: rec.hook("rebuild"),
	}

	svc.dispatchPostCreateHooks("user-1", "ctrader", "cTrader Account", true)

	// Order matters: the snapshot the sync writes is the equity anchor the
	// rebuild dispatch reads (EndEquityOverride, 2026-08-04).
	rec.next(t, "sync:user-1/ctrader/cTrader Account")
	rec.next(t, "rebuild:user-1/ctrader/cTrader Account")
	rec.expectNothingMore(t)
}

// A deployment with no rebuild hook wired must still take the first snapshot.
func TestDispatchPostCreateHooks_SyncOnlyDeployment(t *testing.T) {
	rec := newHookRecorder()
	svc := &ConnectionService{postCreateSyncHook: rec.hook("sync")}

	svc.dispatchPostCreateHooks("user-1", "mt5", "Exness", true)

	rec.next(t, "sync:user-1/mt5/Exness")
	rec.expectNothingMore(t)
}

// Nothing wired: no goroutine, no panic.
func TestDispatchPostCreateHooks_NoHooks(t *testing.T) {
	(&ConnectionService{}).dispatchPostCreateHooks("user-1", "ctrader", "x", true)
}

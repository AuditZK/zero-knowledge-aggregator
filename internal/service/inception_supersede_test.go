package service

import (
	"testing"
	"time"

	"github.com/trackrecord/enclave/internal/repository"
)

func day(y int, m time.Month, d int) time.Time {
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}

func snap(ts time.Time, equity, deposits float64) *repository.Snapshot {
	return &repository.Snapshot{Timestamp: ts, TotalEquity: equity, Deposits: deposits}
}

// The bug this exists for, reproduced at the unit level. The connect hook runs
// the live sync first (it writes the equity anchor the rebuild dispatch needs),
// so the connection's first snapshot is TODAY, carrying an inception deposit
// worth the whole balance. The reconstruction then lands 79 earlier days and
// stamps the real inception underneath. Avi's Bybit account came out reporting
// ~22k of capital against ~12k ever deposited, halving his return.
func TestSupersededConnectStamp_ClearsTheConnectTimeStamp(t *testing.T) {
	live := snap(day(2026, time.August, 26), 10093.99, 10093.99)
	got := supersededConnectStamp([]*repository.Snapshot{live}, day(2026, time.June, 8))
	if got == nil {
		t.Fatal("the connect-time stamp was left in place, the account still double-counts its capital")
	}
	if got.Deposits != 0 {
		t.Fatalf("deposits = %v, want 0", got.Deposits)
	}
	if !got.Timestamp.Equal(live.Timestamp) {
		t.Fatalf("cleared the wrong day: %s", got.Timestamp)
	}
	// The caller upserts the returned row; everything but the deposit must
	// survive that round trip.
	if got.TotalEquity != live.TotalEquity {
		t.Fatalf("equity = %v, want %v — the upsert would overwrite the day with a wrong balance", got.TotalEquity, live.TotalEquity)
	}
	if live.Deposits == 0 {
		t.Fatal("the original row was mutated in place; the batch must carry a copy")
	}
}

// IBKR re-emits its whole Flex window on every sync, so a connection with real
// live history reaching back is a different situation entirely — a widened Flex
// window leaves its own stale stamp, which this must not try to guess at.
func TestSupersededConnectStamp_LeavesLongerHistoryAlone(t *testing.T) {
	existing := []*repository.Snapshot{
		snap(day(2026, time.August, 24), 1000, 1000),
		snap(day(2026, time.August, 25), 1000, 0),
		snap(day(2026, time.August, 26), 1000, 0),
	}
	if got := supersededConnectStamp(existing, day(2026, time.June, 8)); got != nil {
		t.Fatalf("cleared a deposit on a connection with real live history: %+v", got)
	}
}

// A row predating the reconstruction is not a connect-time stamp, and clearing
// it would erase a genuine older deposit.
func TestSupersededConnectStamp_IgnoresRowsBeforeInception(t *testing.T) {
	older := snap(day(2026, time.May, 1), 500, 500)
	if got := supersededConnectStamp([]*repository.Snapshot{older}, day(2026, time.June, 8)); got != nil {
		t.Fatal("cleared a deposit dated before the reconstructed inception")
	}
	sameDay := snap(day(2026, time.June, 8), 500, 500)
	if got := supersededConnectStamp([]*repository.Snapshot{sameDay}, day(2026, time.June, 8)); got != nil {
		t.Fatal("cleared the inception day itself")
	}
}

// Only a deposit worth the day's entire equity reads as a stamp. A partial
// transfer is a real cash flow and erasing it would invent a gain.
func TestSupersededConnectStamp_KeepsRealTransfers(t *testing.T) {
	partial := snap(day(2026, time.August, 26), 10000, 2500)
	if got := supersededConnectStamp([]*repository.Snapshot{partial}, day(2026, time.June, 8)); got != nil {
		t.Fatalf("erased a real 2500 deposit: %+v", got)
	}
	none := snap(day(2026, time.August, 26), 10000, 0)
	if got := supersededConnectStamp([]*repository.Snapshot{none}, day(2026, time.June, 8)); got != nil {
		t.Fatal("returned a row that carried no deposit to begin with")
	}
}

// Float equality cannot be exact across the equity/deposit round trip, so the
// match is bounded rather than strict.
func TestSupersededConnectStamp_ToleratesFloatDrift(t *testing.T) {
	drifted := snap(day(2026, time.August, 26), 10093.99233949, 10093.992339490001)
	if got := supersededConnectStamp([]*repository.Snapshot{drifted}, day(2026, time.June, 8)); got == nil {
		t.Fatal("a stamp missed over floating-point noise")
	}
	wayOff := snap(day(2026, time.August, 26), 10093.99, 10093.50)
	if got := supersededConnectStamp([]*repository.Snapshot{wayOff}, day(2026, time.June, 8)); got != nil {
		t.Fatal("matched a deposit that is nowhere near the balance")
	}
}

func TestSupersededConnectStamp_NoExistingHistory(t *testing.T) {
	if got := supersededConnectStamp(nil, day(2026, time.June, 8)); got != nil {
		t.Fatal("invented a correction for a connection with no prior snapshots")
	}
}

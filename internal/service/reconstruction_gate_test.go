package service

import (
	"testing"
	"time"

	"github.com/trackrecord/enclave/internal/repository"
)

func measured(ts time.Time, equity float64) *repository.Snapshot {
	return &repository.Snapshot{Timestamp: ts, TotalEquity: equity}
}

func reconstructed(ts time.Time, equity float64) *repository.Snapshot {
	return &repository.Snapshot{Timestamp: ts, TotalEquity: equity, IsHistorical: true}
}

// The defect, measured on 2026-08-31: a binance reconstruction wrote
// $116,040.69 for a day the live sync had already measured at $94,584.28, and
// it was published. The rebuilder's own witness gate let it through, tolerating
// a 50% divergence.
func TestContradictedDay_RejectsAReconstructionThatRewritesAMeasuredDay(t *testing.T) {
	existing := []*repository.Snapshot{
		measured(day(2026, time.August, 29), 94465.33),
		measured(day(2026, time.August, 30), 94584.28),
	}
	rebuilt := []*repository.Snapshot{
		reconstructed(day(2026, time.August, 29), 115917.33),
		reconstructed(day(2026, time.August, 30), 116040.69),
	}

	got, measuredEq, bad := contradictedDay(rebuilt, existing)

	if !bad {
		t.Fatal("a reconstruction contradicting a measured day was accepted")
	}
	if !got.Timestamp.Equal(day(2026, time.August, 29)) {
		t.Fatalf("reported %s, want the first contradicted day 2026-08-29", got.Timestamp.Format("2006-01-02"))
	}
	if measuredEq != 94465.33 {
		t.Fatalf("measured equity = %v, want 94465.33", measuredEq)
	}
}

// Agreement on every shared day is the whole gate: a reconstruction that
// reproduces what we measured is trusted for the days we did not.
func TestContradictedDay_AcceptsAReconstructionThatReproducesTheOverlap(t *testing.T) {
	existing := []*repository.Snapshot{measured(day(2026, time.August, 30), 94584.28)}
	rebuilt := []*repository.Snapshot{
		reconstructed(day(2026, time.August, 20), 91000),
		reconstructed(day(2026, time.August, 30), 94584.28),
	}

	if _, _, bad := contradictedDay(rebuilt, existing); bad {
		t.Fatal("a reconstruction reproducing the measured day was rejected")
	}
}

// No overlap, nothing to check. A first backfill on a fresh connection must not
// be blocked for lack of a day to compare against.
func TestContradictedDay_NoOverlapPasses(t *testing.T) {
	existing := []*repository.Snapshot{measured(day(2026, time.August, 30), 94584.28)}
	rebuilt := []*repository.Snapshot{reconstructed(day(2026, time.June, 3), 3310.97)}

	if _, _, bad := contradictedDay(rebuilt, existing); bad {
		t.Fatal("rejected a reconstruction that shares no day with the measured series")
	}
}

// Only independently measured days are witnesses. Comparing a reconstruction
// against an earlier reconstruction proves nothing — both come from the same
// instrument and would agree on being wrong together.
func TestContradictedDay_IgnoresPreviouslyReconstructedDays(t *testing.T) {
	existing := []*repository.Snapshot{reconstructed(day(2026, time.August, 30), 81213.19)}
	rebuilt := []*repository.Snapshot{reconstructed(day(2026, time.August, 30), 116040.69)}

	if _, _, bad := contradictedDay(rebuilt, existing); bad {
		t.Fatal("treated an earlier reconstruction as an independent witness")
	}
}

// The epsilon is float slack, not tolerance for being wrong: a cent passes, a
// dollar does not.
func TestContradictedDay_EpsilonIsArithmeticNotJudgement(t *testing.T) {
	existing := []*repository.Snapshot{measured(day(2026, time.August, 30), 94584.28)}

	if _, _, bad := contradictedDay([]*repository.Snapshot{
		reconstructed(day(2026, time.August, 30), 94584.285),
	}, existing); bad {
		t.Fatal("half a cent of float drift rejected a faithful reconstruction")
	}

	if _, _, bad := contradictedDay([]*repository.Snapshot{
		reconstructed(day(2026, time.August, 30), 94585.28),
	}, existing); !bad {
		t.Fatal("a dollar of divergence passed — the gate is a tolerance again")
	}
}

// Days are compared by date, whatever time of day either row carries.
func TestContradictedDay_ComparesByDayNotInstant(t *testing.T) {
	existing := []*repository.Snapshot{
		{Timestamp: time.Date(2026, time.August, 30, 13, 45, 0, 0, time.UTC), TotalEquity: 94584.28},
	}
	rebuilt := []*repository.Snapshot{reconstructed(day(2026, time.August, 30), 116040.69)}

	if _, _, bad := contradictedDay(rebuilt, existing); !bad {
		t.Fatal("a mid-day measured row escaped the comparison")
	}
}

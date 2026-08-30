package repository

import (
	"strings"
	"testing"
)

// The scope built here is spliced straight into a DELETE. A predicate that
// loses the origin term, or that widens past one connection, takes the user's
// live snapshots with it — the one outcome the feature promises can never
// happen.
func TestRebuiltHistoryScope(t *testing.T) {
	t.Run("origin term is always present", func(t *testing.T) {
		for _, tc := range []struct {
			name    string
			isTS    bool
			asLabel bool
		}{
			{"go schema with label", false, true},
			{"go schema without label", false, false},
			{"ts schema with label", true, true},
			{"ts schema without label", true, false},
		} {
			where, _ := rebuiltHistoryScope(tc.isTS, tc.asLabel, "uid-1", "bybit", "acct")
			if !strings.HasSuffix(where, "AND from_external_rebuilder = TRUE") {
				t.Errorf("%s: predicate does not end on the origin term: %q", tc.name, where)
			}
		}
	})

	t.Run("go schema binds user, exchange and label", func(t *testing.T) {
		where, args := rebuiltHistoryScope(false, true, "uid-1", "bybit", "acct")
		if where != "user_uid = $1 AND exchange = $2 AND label = $3 AND from_external_rebuilder = TRUE" {
			t.Fatalf("where = %q", where)
		}
		if len(args) != 3 || args[0] != "uid-1" || args[1] != "bybit" || args[2] != "acct" {
			t.Fatalf("args = %v", args)
		}
	})

	t.Run("ts schema quotes the camelCase user column", func(t *testing.T) {
		where, _ := rebuiltHistoryScope(true, true, "uid-1", "bybit", "acct")
		if !strings.HasPrefix(where, `"userUid" = $1`) {
			t.Fatalf("where = %q", where)
		}
	})

	t.Run("no label column drops the term and its argument", func(t *testing.T) {
		// Binding a placeholder the SQL no longer mentions is a runtime error,
		// so the argument list has to shrink with the clause.
		where, args := rebuiltHistoryScope(false, false, "uid-1", "bybit", "acct")
		if strings.Contains(where, "label") {
			t.Errorf("where still references label: %q", where)
		}
		if len(args) != 2 {
			t.Errorf("args = %v, want user and exchange only", args)
		}
	})

	t.Run("scope never widens to the whole user", func(t *testing.T) {
		where, _ := rebuiltHistoryScope(false, true, "uid-1", "bybit", "acct")
		if !strings.Contains(where, "exchange = $2") {
			t.Errorf("predicate is not scoped to one exchange: %q", where)
		}
	})
}

package connector

import (
	"context"
	"math"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func ptrInt64(v int64) *int64 { return &v }

// E-M5: the demo-reset heuristic compares a deposit's claimed prior balance
// against the balance we reconstructed. That reconstruction used to advance
// only on deposits and withdrawals, ignoring the swaps, commissions, rebates
// and dividends that also move the balance and also report it. Drift far
// enough and a GENUINE deposit is rewritten as a reset — real capital erased
// from the curve, and the account shows a phantom loss.
func TestCTraderCashflowsByDay_LedgerChargesAdvanceTheRunningBalance(t *testing.T) {
	day := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	ms := func(h int) int64 { return day.Add(time.Duration(h) * time.Hour).UnixMilli() }

	cashflows := []ctraderDepositWithdraw{
		// 10:00 — inception deposit of 1000 onto an empty account.
		{OperationType: ctraderOpDeposit, Delta: 100000, Balance: 100000, Timestamp: ms(10), MoneyDigits: 2},
		// 11:00 — a 900 charge (op 21, a swap): not a cash flow, but it
		// reports the balance after, 100. This is the entry that used to be
		// skipped, leaving `running` stuck at 1000.
		{OperationType: 21, Delta: -90000, Balance: 10000, Timestamp: ms(11), MoneyDigits: 2},
		// 12:00 — a real 50 deposit. balanceAfter 150, delta 50, so the
		// ledger's implied prior balance is 100 — which matches the true,
		// charge-adjusted balance. Against the stale 1000 it looks like a
		// zero-then-fund reset (100 < 0.5 * 1000) and the heuristic rewrites
		// it as a 850 WITHDRAWAL.
		{OperationType: ctraderOpDeposit, Delta: 5000, Balance: 15000, Timestamp: ms(12), MoneyDigits: 2},
	}

	byDay := ctraderCashflowsByDay(nil, cashflows)
	got := byDay[day.Format("20060102")]
	if got == nil {
		t.Fatal("no cashflow bucket for the day")
	}
	if want := 1050.0; math.Abs(got.deposits-want) > 1e-9 {
		t.Fatalf("deposits = %v, want %v — the second deposit was rewritten as a reset", got.deposits, want)
	}
	if got.withdrawals != 0 {
		t.Fatalf("withdrawals = %v, want 0 — a genuine deposit was booked as a withdrawal", got.withdrawals)
	}
}

// A genuine demo reset is still caught: the ledger claims an empty prior
// account while the balance curve says otherwise.
func TestCTraderCashflowsByDay_StillCorrectsADemoReset(t *testing.T) {
	day := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	ms := func(h int) int64 { return day.Add(time.Duration(h) * time.Hour).UnixMilli() }

	deals := []cTraderDeal{{
		ExecutionTimestamp:  ms(9),
		MoneyDigits:         2,
		ClosePositionDetail: &struct {
			GrossProfit int64 `json:"grossProfit"`
			Commission  int64 `json:"commission"`
			Swap        int64 `json:"swap"`
			// A POINTER so an absent field and a genuine zero stay
			// distinguishable: the old `Balance == 0` filter dropped every
			// deal that closed the account at exactly 0.00, and the
			// carry-forward builder then drew a flat line at the last
			// positive balance — a blown account rendered as a plateau (E-B).
			Balance     *int64 `json:"balance"`
			MoneyDigits int    `json:"moneyDigits"`
		}{Balance: ptrInt64(500000), MoneyDigits: 2}, // account holds 5000
	}}
	// The reset re-funds 1000 and claims it landed on an empty account.
	cashflows := []ctraderDepositWithdraw{
		{OperationType: ctraderOpDeposit, Delta: 100000, Balance: 100000, Timestamp: ms(10), MoneyDigits: 2},
	}

	byDay := ctraderCashflowsByDay(deals, cashflows)
	got := byDay[day.Format("20060102")]
	if got == nil {
		t.Fatal("no cashflow bucket for the day")
	}
	// Net capital change is 1000 - 5000 = -4000, i.e. a withdrawal.
	if want := 4000.0; math.Abs(got.withdrawals-want) > 1e-9 {
		t.Fatalf("withdrawals = %v, want %v", got.withdrawals, want)
	}
	if got.deposits != 0 {
		t.Fatalf("deposits = %v, want 0 — the discarded balance was counted as fresh capital", got.deposits)
	}
}

// E-M8: an unresolvable symbol used to cost one request per deal, hundreds per
// sync, all of them feeding the per-payload-type rate limit that then blocks
// the history walk.
func TestCTraderGetSymbolName_MemoizesTheMiss(t *testing.T) {
	var symbolCalls atomic.Int32

	server := newCTraderWSServer(t, func(conn *websocket.Conn, msg wsTestMessage) {
		switch msg.PayloadType {
		case ctraderPayloadAppAuthReq:
			sendWSResponse(t, conn, msg.ClientMsgID, ctraderPayloadAppAuthRes, map[string]any{})
		case ctraderPayloadAccountAuthReq:
			sendWSResponse(t, conn, msg.ClientMsgID, ctraderPayloadAccountAuthRes, map[string]any{})
		case ctraderPayloadSymbolByIDReq:
			symbolCalls.Add(1)
			sendWSError(t, conn, msg.ClientMsgID, "SYMBOL_NOT_FOUND", "unknown symbol")
		default:
			t.Errorf("unexpected payloadType: %d", msg.PayloadType)
		}
	})
	defer server.Close()

	c := &CTrader{
		clientID:     "client-id",
		clientSecret: "client-secret",
		accessToken:  "token",
		isLive:       true,
		wsLiveURL:    toWSURL(server.URL),
		httpClient:   &http.Client{Timeout: 5 * time.Second},
	}

	for i := 0; i < 5; i++ {
		if got := c.getSymbolName(context.Background(), 42, 12345); got != "SYMBOL_42" {
			t.Fatalf("got %q, want SYMBOL_42", got)
		}
	}
	if got := symbolCalls.Load(); got != 1 {
		t.Fatalf("resolved the same unknown symbol %d times, want 1", got)
	}
}

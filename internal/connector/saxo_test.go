package connector

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Resolved by runtime type assertion, so a drifted signature would silently
// disable paper detection rather than fail the build.
var _ PaperAccountDetector = (*Saxo)(nil)

func newSaxoTest(t *testing.T, sim bool, handler http.HandlerFunc) *Saxo {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	s := NewSaxo(&Credentials{APIKey: "test-token"}, sim)
	s.baseURL = srv.URL
	return s
}

func saxoWriteClient(w http.ResponseWriter) {
	fmt.Fprint(w, `{"ClientKey":"CK==","DefaultCurrency":"EUR","DefaultAccountKey":"AK=="}`)
}

func TestSaxoExchangeAndPaperDetection(t *testing.T) {
	tests := []struct {
		name         string
		sim          bool
		wantExchange string
	}{
		{name: "live", sim: false, wantExchange: "saxo"},
		{name: "sim", sim: true, wantExchange: "saxo_sim"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := NewSaxo(&Credentials{APIKey: "tok"}, tc.sim)
			if got := s.Exchange(); got != tc.wantExchange {
				t.Fatalf("Exchange() = %q, want %q", got, tc.wantExchange)
			}
			isPaper, err := s.DetectIsPaper(context.Background())
			if err != nil {
				t.Fatalf("DetectIsPaper returned error: %v", err)
			}
			if isPaper != tc.sim {
				t.Fatalf("DetectIsPaper = %v, want %v", isPaper, tc.sim)
			}
		})
	}
}

// Only the SIM gateway is registered: a live Saxo connection would die inside
// the hour on Saxo's 20/40-minute token lifetimes.
func TestFactorySaxoLiveNotRegistered(t *testing.T) {
	f := NewFactory()

	if _, err := f.Create(&Credentials{Exchange: "saxo", APIKey: "tok"}); err == nil {
		t.Fatal("Create(saxo) must fail while live auth is unresolved")
	}
	for _, ex := range f.SupportedExchanges() {
		if ex == "saxo" {
			t.Fatal("SupportedExchanges() must not advertise live saxo")
		}
	}

	conn, err := f.Create(&Credentials{Exchange: "saxo_sim", APIKey: "tok"})
	if err != nil {
		t.Fatalf("Create(saxo_sim) should succeed: %v", err)
	}
	if got := conn.Exchange(); got != "saxo_sim" {
		t.Fatalf("Exchange() = %q, want saxo_sim", got)
	}
}

// Saxo's own numbers reconcile as CashBalance + UnrealizedPositionsValue =
// TotalValue. Reporting UnrealizedMarginProfitLoss instead would leave sync's
// realised balance (Equity - UnrealizedPnL) off by CostToClosePositions.
func TestSaxoGetBalanceReconcilesToCashBalance(t *testing.T) {
	s := newSaxoTest(t, true, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/port/v1/clients/me":
			saxoWriteClient(w)
		case "/port/v1/balances/me":
			fmt.Fprint(w, `{
				"CalculationReliability":"Ok",
				"CashBalance":999956.74,
				"CostToClosePositions":-37.39,
				"Currency":"EUR",
				"MarginAvailableForTrading":978723.61,
				"TotalValue":996386.01,
				"UnrealizedMarginProfitLoss":-3533.34,
				"UnrealizedPositionsValue":-3570.73
			}`)
		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
	})

	bal, err := s.GetBalance(context.Background())
	if err != nil {
		t.Fatalf("GetBalance returned error: %v", err)
	}
	if bal.Equity != 996386.01 {
		t.Fatalf("Equity = %v, want 996386.01 (TotalValue)", bal.Equity)
	}
	if bal.Available != 978723.61 {
		t.Fatalf("Available = %v, want 978723.61", bal.Available)
	}

	// The realised balance sync derives must land exactly on CashBalance.
	realized := bal.Equity - bal.UnrealizedPnL
	if diff := realized - 999956.74; diff > 1e-6 || diff < -1e-6 {
		t.Fatalf("Equity - UnrealizedPnL = %v, want 999956.74 (CashBalance)", realized)
	}
	if bal.Currency != "EUR" {
		t.Fatalf("Currency = %q, want EUR", bal.Currency)
	}
}

func TestSaxoMarketTypeMapping(t *testing.T) {
	tests := []struct {
		assetType string
		want      string
	}{
		{assetType: "FxSpot", want: MarketForex},
		{assetType: "FxForwards", want: MarketForex},
		{assetType: "FxVanillaOption", want: MarketOptions},
		{assetType: "StockOption", want: MarketOptions},
		{assetType: "CfdOnStock", want: MarketCFD},
		{assetType: "CfdOnIndex", want: MarketCFD},
		{assetType: "ContractFutures", want: MarketFutures},
		{assetType: "Stock", want: MarketStocks},
		{assetType: "Bond", want: MarketStocks},
	}

	for _, tc := range tests {
		t.Run(tc.assetType, func(t *testing.T) {
			if got := saxoMarketType(tc.assetType); got != tc.want {
				t.Fatalf("saxoMarketType(%q) = %q, want %q", tc.assetType, got, tc.want)
			}
		})
	}
}

func TestSaxoSymbolFromNetPositionID(t *testing.T) {
	tests := []struct{ in, want string }{
		{in: "EURUSD__FxSpot", want: "EURUSD"},
		{in: "GBPCAD__FxSpot", want: "GBPCAD"},
		{in: "NoSeparator", want: "NoSeparator"},
		{in: "", want: ""},
	}
	for _, tc := range tests {
		if got := saxoSymbol(tc.in); got != tc.want {
			t.Fatalf("saxoSymbol(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestSaxoGetPositions(t *testing.T) {
	s := newSaxoTest(t, true, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/port/v1/clients/me":
			saxoWriteClient(w)
		case "/port/v1/positions/me":
			fmt.Fprint(w, `{"Data":[
				{"NetPositionId":"EURUSD__FxSpot",
				 "PositionBase":{"Amount":-100000,"AssetType":"FxSpot","OpenPrice":1.13715},
				 "PositionView":{"CurrentPrice":1.1339,"ProfitLossOnTradeInBaseCurrency":286.65}},
				{"NetPositionId":"AAPL__Stock",
				 "PositionBase":{"Amount":50,"AssetType":"Stock","OpenPrice":180.5},
				 "PositionView":{"CurrentPrice":190.0,"ProfitLossOnTradeInBaseCurrency":475.0}},
				{"NetPositionId":"FLAT__FxSpot",
				 "PositionBase":{"Amount":0,"AssetType":"FxSpot","OpenPrice":1.0},
				 "PositionView":{"CurrentPrice":1.0,"ProfitLossOnTradeInBaseCurrency":0}}
			]}`)
		}
	})

	positions, err := s.GetPositions(context.Background())
	if err != nil {
		t.Fatalf("GetPositions returned error: %v", err)
	}
	if len(positions) != 2 {
		t.Fatalf("got %d positions, want 2 (zero-amount dropped)", len(positions))
	}

	if positions[0].Side != "short" || positions[0].Size != 100000 || positions[0].Symbol != "EURUSD" {
		t.Fatalf("position[0] = %+v, want short/100000/EURUSD", positions[0])
	}
	if positions[0].UnrealizedPnL != 286.65 || positions[0].MarketType != MarketForex {
		t.Fatalf("position[0] pnl/market = %v/%v, want 286.65/forex", positions[0].UnrealizedPnL, positions[0].MarketType)
	}
	if positions[1].Side != "long" || positions[1].MarketType != MarketStocks {
		t.Fatalf("position[1] = %+v, want long/stocks", positions[1])
	}
}

func TestSaxoGetTradesWindowsAndCosts(t *testing.T) {
	s := newSaxoTest(t, true, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/port/v1/clients/me":
			saxoWriteClient(w)
		case "/port/v1/closedpositions":
			fmt.Fprint(w, `{"__count":3,"Data":[
				{"ClosedPositionUniqueId":"A-B","NetPositionId":"GBPCAD__FxSpot","ClosedPosition":{
					"AssetType":"FxSpot","Amount":80000,"BuyOrSell":"Buy",
					"ClosedProfitLossInBaseCurrency":-171.1138,"ClosingPrice":1.75612,
					"CostOpeningInBaseCurrency":-4.63,"CostClosingInBaseCurrency":-4.62,
					"ExecutionTimeClose":"2026-07-05T22:57:51.935866Z"}},
				{"ClosedPositionUniqueId":"C-D","NetPositionId":"EURUSD__FxSpot","ClosedPosition":{
					"AssetType":"FxSpot","Amount":-100000,"BuyOrSell":"Sell",
					"ClosedProfitLossInBaseCurrency":25.6447,"ClosingPrice":1.13025,
					"CostOpeningInBaseCurrency":-5.65,"CostClosingInBaseCurrency":-5.65,
					"ExecutionTimeClose":"2026-07-06T10:00:00Z"}},
				{"ClosedPositionUniqueId":"E-F","NetPositionId":"OLD__FxSpot","ClosedPosition":{
					"AssetType":"FxSpot","Amount":1000,"BuyOrSell":"Buy",
					"ClosedProfitLossInBaseCurrency":10,"ClosingPrice":1.0,
					"CostOpeningInBaseCurrency":0,"CostClosingInBaseCurrency":0,
					"ExecutionTimeClose":"2026-01-01T10:00:00Z"}}
			]}`)
		}
	})

	trades, err := s.GetTrades(context.Background(),
		time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
		time.Date(2026, 7, 10, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("GetTrades returned error: %v", err)
	}
	if len(trades) != 2 {
		t.Fatalf("got %d trades, want 2 (out-of-window close dropped): %+v", len(trades), trades)
	}

	if trades[0].Side != "buy" || trades[0].Quantity != 80000 || trades[0].Symbol != "GBPCAD" {
		t.Fatalf("trade[0] = %+v, want buy/80000/GBPCAD", trades[0])
	}
	// Costs are reported negative; Fee is a positive magnitude in this package.
	if diff := trades[0].Fee - 9.25; diff > 1e-9 || diff < -1e-9 {
		t.Fatalf("trade[0].Fee = %v, want 9.25 (|opening| + |closing|)", trades[0].Fee)
	}
	if trades[0].FeeCurrency != "EUR" {
		t.Fatalf("trade[0].FeeCurrency = %q, want EUR", trades[0].FeeCurrency)
	}
	if trades[1].Side != "sell" || trades[1].RealizedPnL != 25.6447 {
		t.Fatalf("trade[1] = %+v, want sell/25.6447", trades[1])
	}
}

func TestSaxoClientKeyIsCached(t *testing.T) {
	var clientCalls int
	s := newSaxoTest(t, true, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/port/v1/clients/me":
			clientCalls++
			saxoWriteClient(w)
		case "/port/v1/balances/me":
			fmt.Fprint(w, `{"CashBalance":100,"Currency":"EUR","TotalValue":100,"UnrealizedPositionsValue":0,"MarginAvailableForTrading":100}`)
		}
	})

	ctx := context.Background()
	for range 3 {
		if err := s.TestConnection(ctx); err != nil {
			t.Fatalf("TestConnection returned error: %v", err)
		}
	}
	if clientCalls != 1 {
		t.Fatalf("clients/me called %d times, want 1 (cached)", clientCalls)
	}
}

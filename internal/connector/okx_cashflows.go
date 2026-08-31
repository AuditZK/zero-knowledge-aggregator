package connector

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"
)

// The tracked perimeter is the unified trading account, and every bill of
// type 1 (Transfer) crosses it: the counterpart — funding account,
// sub-account, another user — is never inside, so no leg-pairing pass exists.
// This is the history-rebuilder's exact classification; the two instruments
// must keep agreeing on shared days or the reconstruction gate reads their
// disagreement as a corrupted rebuild.
//
// /api/v5/account/bills serves ~7 days, bills-archive ~3 months. The daily
// sync window (24h, widened to 30d after a gap) fits the live endpoint almost
// always; the archive is fetched only when the window reaches past it.

const (
	okxBillsPageLimit  = 100
	okxMaxBillPages    = 40
	okxBillsLiveWindow = 7 * 24 * time.Hour
	okxBillsPagePace   = 150 * time.Millisecond
)

// okxStableCoins mirrors the rebuilder's set — valued $1, never marked to a
// ticker.
var okxStableCoins = map[string]bool{
	"USDT": true, "USDC": true, "USD": true, "BUSD": true, "DAI": true, "FDUSD": true, "TUSD": true,
}

type okxBill struct {
	BillID  string
	T       time.Time
	Ccy     string
	BalChg  float64
	Type    string
	SubType string
}

func (o *OKX) GetCashflows(ctx context.Context, since time.Time) ([]*Cashflow, error) {
	o.resetCashflowWarnings()

	now := time.Now().UTC()
	bills, err := o.fetchBills(ctx, since, now)
	if err != nil {
		return nil, fmt.Errorf("fetch okx bills: %w", err)
	}

	// One public all-tickers call prices every non-stable transfer currency;
	// skipped entirely when the window moved only stables. A transport
	// failure degrades to stables-only rather than dropping the whole window:
	// a missed USDT transfer books as fabricated performance, which is the
	// defect this file exists to close.
	prices, priced := o.spotUSDPrices(ctx, okxNonStableTransferCcys(bills))
	if !priced {
		o.noteCashflowWarning("okx_spot_pricing_unavailable")
	}

	flows, warnings := okxClassifyCashflows(bills, prices)
	for _, w := range warnings {
		o.noteCashflowWarning(w)
	}
	return flows, nil
}

// okxClassifyCashflows is pure so the perimeter rule stays testable without
// IO. A transfer whose currency cannot be priced is skipped WITH a warning,
// never valued at zero silently — the RWUSD lesson: a coin with no tradable
// pair valued at 0 turns a real deposit into phantom performance.
//
// Types 2 (trade), 7 (interest) and 8 (funding) move value the equity walk
// already absorbs. Any OTHER type that moves balance surfaces as a warning
// and must be classified deliberately, not absorbed — the rebuilder's
// ledger-histogram doctrine, applied live.
func okxClassifyCashflows(bills []okxBill, prices map[string]float64) ([]*Cashflow, []string) {
	warnings := map[string]bool{}
	var flows []*Cashflow

	for _, b := range bills {
		if b.BalChg == 0 {
			continue
		}
		switch b.Type {
		case "1":
			usd, ok := okxValueUSD(b.Ccy, math.Abs(b.BalChg), prices)
			if !ok {
				warnings["okx_transfer_unpriced:"+b.Ccy] = true
				continue
			}
			if b.BalChg < 0 {
				usd = -usd
			}
			flows = append(flows, &Cashflow{Amount: usd, Currency: b.Ccy, Timestamp: b.T})
		case "2", "7", "8":
		default:
			warnings["okx_bill_unclassified:"+b.Type+"/"+b.SubType] = true
		}
	}

	keys := make([]string, 0, len(warnings))
	for k := range warnings {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return flows, keys
}

func okxValueUSD(ccy string, qty float64, prices map[string]float64) (float64, bool) {
	if okxStableCoins[ccy] {
		return qty, true
	}
	if p := prices[ccy]; p > 0 {
		return qty * p, true
	}
	return 0, false
}

func okxNonStableTransferCcys(bills []okxBill) []string {
	seen := map[string]bool{}
	var ccys []string
	for _, b := range bills {
		if b.Type != "1" || b.BalChg == 0 || okxStableCoins[b.Ccy] || seen[b.Ccy] {
			continue
		}
		seen[b.Ccy] = true
		ccys = append(ccys, b.Ccy)
	}
	return ccys
}

// fetchBills merges the live ledger with the archive when the window reaches
// past the live retention, deduped by billId — the rebuilder's fetchBills,
// with its failure policy: the live endpoint failing is fatal (it serves the
// freshest rows), an archive gap shortens the window and says so.
func (o *OKX) fetchBills(ctx context.Context, since, now time.Time) ([]okxBill, error) {
	endpoints := []string{"/api/v5/account/bills"}
	if since.Before(now.Add(-okxBillsLiveWindow)) {
		endpoints = append(endpoints, "/api/v5/account/bills-archive")
	}

	seen := map[string]bool{}
	var bills []okxBill
	for _, endpoint := range endpoints {
		rows, err := o.fetchBillsFrom(ctx, endpoint, since, now, seen)
		if err != nil {
			if endpoint == "/api/v5/account/bills" {
				return nil, err
			}
			o.noteCashflowWarning("okx_bills_archive_unavailable")
			continue
		}
		bills = append(bills, rows...)
	}

	sort.Slice(bills, func(i, j int) bool { return bills[i].T.Before(bills[j].T) })
	return bills, nil
}

func (o *OKX) fetchBillsFrom(ctx context.Context, endpoint string, since, now time.Time, seen map[string]bool) ([]okxBill, error) {
	var bills []okxBill
	after := ""
	for page := 0; page < okxMaxBillPages; page++ {
		if page > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(okxBillsPagePace):
			}
		}

		path := fmt.Sprintf("%s?begin=%d&end=%d&limit=%d", endpoint, since.UnixMilli(), now.UnixMilli(), okxBillsPageLimit)
		if after != "" {
			path += "&after=" + after
		}
		body, err := o.doRequest(ctx, "GET", path)
		if err != nil {
			return nil, err
		}

		var resp struct {
			Data []struct {
				BillID  string `json:"billId"`
				Ts      string `json:"ts"`
				Ccy     string `json:"ccy"`
				BalChg  string `json:"balChg"`
				Type    string `json:"type"`
				SubType string `json:"subType"`
			} `json:"data"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, fmt.Errorf("decode okx bills: %w", err)
		}

		lastID := ""
		for _, b := range resp.Data {
			lastID = b.BillID
			if seen[b.BillID] {
				continue
			}
			seen[b.BillID] = true
			ms, _ := strconv.ParseInt(b.Ts, 10, 64)
			balChg, _ := strconv.ParseFloat(b.BalChg, 64)
			bills = append(bills, okxBill{
				BillID:  b.BillID,
				T:       time.UnixMilli(ms).UTC(),
				Ccy:     strings.ToUpper(b.Ccy),
				BalChg:  balChg,
				Type:    b.Type,
				SubType: b.SubType,
			})
		}
		if len(resp.Data) < okxBillsPageLimit || lastID == "" || lastID == after {
			break
		}
		after = lastID
	}
	return bills, nil
}

// spotUSDPrices returns last prices for ccys from one public all-tickers
// call, USDT quote preferred, USDC accepted. ok=false means the call itself
// failed and non-stable valuation is unavailable this window.
func (o *OKX) spotUSDPrices(ctx context.Context, ccys []string) (map[string]float64, bool) {
	if len(ccys) == 0 {
		return nil, true
	}
	body, err := o.doRequest(ctx, "GET", "/api/v5/market/tickers?instType=SPOT")
	if err != nil {
		return nil, false
	}

	var resp struct {
		Data []struct {
			InstID string `json:"instId"`
			Last   string `json:"last"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, false
	}

	want := map[string]bool{}
	for _, c := range ccys {
		want[c] = true
	}
	prices := map[string]float64{}
	for _, t := range resp.Data {
		base, quote, ok := strings.Cut(t.InstID, "-")
		if !ok || !want[base] {
			continue
		}
		if quote != "USDT" && quote != "USDC" {
			continue
		}
		last, _ := strconv.ParseFloat(t.Last, 64)
		if last <= 0 {
			continue
		}
		if _, have := prices[base]; have && quote == "USDC" {
			continue
		}
		prices[base] = last
	}
	return prices, true
}

// CapabilityWarnings implements CapabilityWarner with markers from the LAST
// GetCashflows call — the sync layer fetches cashflows before it reads the
// warner, so they ride the same sync status as balance-scope gaps.
func (o *OKX) CapabilityWarnings() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]string(nil), o.cashflowWarnings...)
}

func (o *OKX) resetCashflowWarnings() {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.cashflowWarnings = nil
}

func (o *OKX) noteCashflowWarning(w string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	for _, have := range o.cashflowWarnings {
		if have == w {
			return
		}
	}
	o.cashflowWarnings = append(o.cashflowWarnings, w)
}

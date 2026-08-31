package connector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// okxRegionalHosts lists the OKX API domains in probe order.
//
// OKX runs one order book per regulatory entity, and an API key only exists
// on the entity that issued it: a key created on www.okx.com (global) answers
// only there, a key from OKX Europe (accounts registered on my.okx.com, the
// MiCA entity) only on eea.okx.com, a key from OKX US / AU (app.okx.com) only
// on us.okx.com. Every other domain answers 401 code 50119 "API key doesn't
// exist" for it.
//
// Nothing in the credential shape says which entity issued a key and the
// connect form does not ask, so the connector probes: the first domain that
// recognises the key is pinned for the lifetime of the connector. The cost is
// one refused request per region skipped, once per connector instance, i.e.
// once per sync for a non-global account. Observed 2026-08-29: a French
// signup's OKX Europe key was refused three times on the global domain and
// reported to them as bad credentials.
var okxRegionalHosts = []string{
	"https://www.okx.com", // global
	"https://eea.okx.com", // OKX Europe: accounts registered on my.okx.com
	"https://us.okx.com",  // OKX US / AU: accounts registered on app.okx.com
}

// okxUnknownKeyCodes are the OKX error codes meaning "this domain has never
// seen this key": the only signal worth trying the next region on. Every
// other rejection (bad signature 50113, wrong passphrase 50105, IP not
// whitelisted 50110) proves the key exists on the domain that answered, so
// probing further would only turn a precise error into "doesn't exist".
var okxUnknownKeyCodes = map[string]bool{
	"50119": true, // "API key doesn't exist"
	"50111": true, // "Invalid OK-ACCESS-KEY"
}

// OKX implements Connector for OKX exchange
type OKX struct {
	apiKey     string
	apiSecret  string
	passphrase string
	client     *http.Client

	mu    sync.Mutex
	hosts []string // candidate API domains; collapses to one once a key is recognised

	cashflowWarnings []string // markers from the last GetCashflows, guarded by mu
}

// NewOKX creates a new OKX connector
func NewOKX(creds *Credentials) *OKX {
	return newOKXWithHosts(creds, &http.Client{Timeout: 30 * time.Second}, okxRegionalHosts)
}

// newOKXWithHosts is the constructor the tests use to point the connector at
// fake regional hosts.
func newOKXWithHosts(creds *Credentials, client *http.Client, hosts []string) *OKX {
	return &OKX{
		apiKey:     creds.APIKey,
		apiSecret:  creds.APISecret,
		passphrase: creds.Passphrase,
		client:     client,
		hosts:      append([]string(nil), hosts...),
	}
}

func (o *OKX) Exchange() string {
	return "okx"
}

func (o *OKX) sign(timestamp, method, path, body string) string {
	return signHMACBase64(o.apiSecret, timestamp+method+path+body)
}

// candidateHosts returns the domains still in play, in probe order.
func (o *OKX) candidateHosts() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]string(nil), o.hosts...)
}

// pinHost keeps only the domain that recognised the key: every later call on
// this connector goes straight there and no other region is probed again.
func (o *OKX) pinHost(host string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.hosts = []string{host}
}

func (o *OKX) doRequest(ctx context.Context, method, path string) ([]byte, error) {
	hosts := o.candidateHosts()
	if len(hosts) == 0 {
		return nil, errors.New("okx: no API host configured")
	}

	var err error
	for i, host := range hosts {
		var body []byte
		body, err = o.doRequestAt(ctx, host, method, path)
		if err == nil {
			o.pinHost(host)
			return body, nil
		}
		if !okxKeyUnknownHere(body, err) {
			return nil, err
		}
		if i == len(hosts)-1 && i > 0 {
			return nil, fmt.Errorf("okx: API key unknown on every OKX region (%s): %w",
				strings.Join(okxHostNames(hosts), ", "), err)
		}
	}
	return nil, err
}

// doRequestAt signs and sends one request against host. On failure the
// response body comes back alongside the error so the caller can read the
// OKX error code out of it: retryHTTP folds the body into the error text and
// does not retry a 401, so nothing is lost by looking at it.
func (o *OKX) doRequestAt(ctx context.Context, host, method, path string) ([]byte, error) {
	body, err := retryHTTP(o.client, func() (*http.Request, error) {
		timestamp := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
		signature := o.sign(timestamp, method, path, "")

		req, err := http.NewRequestWithContext(ctx, method, host+path, nil)
		if err != nil {
			return nil, err
		}

		req.Header.Set("OK-ACCESS-KEY", o.apiKey)
		req.Header.Set("OK-ACCESS-SIGN", signature)
		req.Header.Set("OK-ACCESS-TIMESTAMP", timestamp)
		req.Header.Set("OK-ACCESS-PASSPHRASE", o.passphrase)
		req.Header.Set("Content-Type", "application/json")
		return req, nil
	})
	if err != nil {
		return body, err
	}

	var result struct {
		Code string `json:"code"`
		Msg  string `json:"msg"`
	}
	json.Unmarshal(body, &result)
	if result.Code != "0" {
		return body, fmt.Errorf("okx API error: %s", vendorErrorDetail(result.Msg))
	}

	return body, nil
}

// okxKeyUnknownHere reports whether a failed request means the answering
// domain has never issued the key, the one case where another region can
// succeed. OKX answers HTTP 401 with a JSON envelope for it, so the body is
// checked first; the error text is the fallback for the paths where only the
// folded body survives.
func okxKeyUnknownHere(body []byte, err error) bool {
	if err == nil {
		return false
	}
	var envelope struct {
		Code string `json:"code"`
	}
	if json.Unmarshal(body, &envelope) == nil && envelope.Code != "" {
		return okxUnknownKeyCodes[envelope.Code]
	}
	msg := err.Error()
	for code := range okxUnknownKeyCodes {
		if strings.Contains(msg, `"code":"`+code+`"`) {
			return true
		}
	}
	return false
}

// okxHostNames strips the scheme for error messages: "www.okx.com" reads as a
// region, "https://www.okx.com" reads as a URL somebody should click.
func okxHostNames(hosts []string) []string {
	names := make([]string, 0, len(hosts))
	for _, h := range hosts {
		names = append(names, strings.TrimPrefix(strings.TrimPrefix(h, "https://"), "http://"))
	}
	return names
}

func (o *OKX) TestConnection(ctx context.Context) error {
	_, err := o.doRequest(ctx, "GET", "/api/v5/account/balance")
	return err
}

func (o *OKX) GetBalance(ctx context.Context) (*Balance, error) {
	body, err := o.doRequest(ctx, "GET", "/api/v5/account/balance")
	if err != nil {
		return nil, err
	}

	var resp struct {
		Data []struct {
			TotalEq string `json:"totalEq"`
			IsoEq   string `json:"isoEq"`
			AdjEq   string `json:"adjEq"`
			Details []struct {
				Ccy      string `json:"ccy"`
				Eq       string `json:"eq"`
				EqUsd    string `json:"eqUsd"`
				AvailBal string `json:"availBal"`
				UPL      string `json:"upl"`
			} `json:"details"`
		} `json:"data"`
	}

	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}

	if len(resp.Data) == 0 {
		return &Balance{Currency: "USDT"}, nil
	}

	account := resp.Data[0]
	equity, _ := strconv.ParseFloat(account.TotalEq, 64)

	var available, unrealized float64
	for _, d := range account.Details {
		rate := okxUSDRate(d.Eq, d.EqUsd)
		availBal, _ := strconv.ParseFloat(d.AvailBal, 64)
		upl, _ := strconv.ParseFloat(d.UPL, 64)
		available += availBal * rate
		unrealized += upl * rate
	}

	return &Balance{
		Available:     available,
		Equity:        equity,
		UnrealizedPnL: unrealized,
		Currency:      "USDT",
	}, nil
}

// okxUSDRate prices one currency line in USD from the pair OKX already returns
// on it. Reading free margin and unrealized P&L off the USDT line alone left
// every account settled in anything else reporting a free margin of zero while
// its total equity stayed right. Falling back to 1 keeps the USD-pegged lines
// correct when OKX omits eqUsd.
func okxUSDRate(eq, eqUSD string) float64 {
	quantity, _ := strconv.ParseFloat(eq, 64)
	usd, _ := strconv.ParseFloat(eqUSD, 64)
	if quantity == 0 || usd == 0 {
		return 1
	}
	return usd / quantity
}

func (o *OKX) GetPositions(ctx context.Context) ([]*Position, error) {
	body, err := o.doRequest(ctx, "GET", "/api/v5/account/positions")
	if err != nil {
		return nil, err
	}

	var resp struct {
		Data []struct {
			InstId   string `json:"instId"`
			PosSide  string `json:"posSide"`
			Pos      string `json:"pos"`
			AvgPx    string `json:"avgPx"`
			MarkPx   string `json:"markPx"`
			Upl      string `json:"upl"`
			InstType string `json:"instType"`
		} `json:"data"`
	}

	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}

	var positions []*Position
	for _, p := range resp.Data {
		size, _ := strconv.ParseFloat(p.Pos, 64)
		if size == 0 {
			continue
		}

		entry, _ := strconv.ParseFloat(p.AvgPx, 64)
		mark, _ := strconv.ParseFloat(p.MarkPx, 64)
		unrealized, _ := strconv.ParseFloat(p.Upl, 64)

		side := "long"
		if p.PosSide == "short" || size < 0 {
			side = "short"
			if size < 0 {
				size = -size
			}
		}

		positions = append(positions, &Position{
			Symbol:        p.InstId,
			Side:          side,
			Size:          size,
			EntryPrice:    entry,
			MarkPrice:     mark,
			UnrealizedPnL: unrealized,
			MarketType:    okxMarketType(p.InstType),
		})
	}

	return positions, nil
}

// okxFillInstTypes are the product lines fills-history is queried on. OKX
// makes instType mandatory and answers for exactly one per call, so asking
// only for SWAP made every spot and margin fill invisible: an account trading
// spot reported zero trades, zero volume and zero fees while its equity moved
// daily. One call per line is the price of seeing them.
var okxFillInstTypes = []string{"SPOT", "MARGIN", "SWAP", "FUTURES", "OPTION"}

// okxMarketType files every fill under swap, whatever product line it came
// from. OKX runs a unified account and this connector cannot split equity per
// product, so the sync layer files the whole balance under one bucket
// (primaryMarketType okx=swap). A fill typed by its own product line would land
// in a bucket holding no equity — per-market return then divides by zero, and
// the equity sits in a bucket showing no activity. Truthful per-product typing
// has to wait for a balance split, in this connector and in the rebuilder
// together.
func okxMarketType(string) string {
	return MarketSwap
}

func (o *OKX) GetTrades(ctx context.Context, start, end time.Time) ([]*Trade, error) {
	var trades []*Trade
	var lastErr error
	answered := false

	for _, instType := range okxFillInstTypes {
		batch, err := o.fillsFor(ctx, instType, start, end)
		if err != nil {
			lastErr = err
			continue
		}
		answered = true
		trades = append(trades, batch...)
	}

	// A product line the account never enabled answers with an error; only a
	// run where every line failed is a real failure worth surfacing.
	if !answered && lastErr != nil {
		return nil, lastErr
	}
	return trades, nil
}

func (o *OKX) fillsFor(ctx context.Context, instType string, start, end time.Time) ([]*Trade, error) {
	path := fmt.Sprintf("/api/v5/trade/fills-history?instType=%s&begin=%d&end=%d&limit=100",
		instType, start.UnixMilli(), end.UnixMilli())

	body, err := o.doRequest(ctx, "GET", path)
	if err != nil {
		return nil, err
	}

	var resp struct {
		Data []struct {
			TradeId  string `json:"tradeId"`
			InstId   string `json:"instId"`
			Side     string `json:"side"`
			FillPx   string `json:"fillPx"`
			FillSz   string `json:"fillSz"`
			Fee      string `json:"fee"`
			FeeCcy   string `json:"feeCcy"`
			Ts       string `json:"ts"`
			InstType string `json:"instType"`
		} `json:"data"`
	}

	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}

	var trades []*Trade
	for _, t := range resp.Data {
		price, _ := strconv.ParseFloat(t.FillPx, 64)
		qty, _ := strconv.ParseFloat(t.FillSz, 64)
		fee, _ := strconv.ParseFloat(t.Fee, 64)
		ts, _ := strconv.ParseInt(t.Ts, 10, 64)

		trades = append(trades, &Trade{
			ID:       t.TradeId,
			Symbol:   t.InstId,
			Side:     t.Side,
			Price:    price,
			Quantity: qty,
			// OKX signs fee from the account's viewpoint — negative when
			// charged, positive on a rebate — while every other connector (and
			// the aggregation summing Trade.Fee) books a cost as positive.
			// Passed through raw, a live day's fees summed NEGATIVE.
			Fee:         -fee,
			FeeCurrency: t.FeeCcy,
			Timestamp:   time.UnixMilli(ts),
			MarketType:  okxMarketType(t.InstType),
		})
	}

	return trades, nil
}

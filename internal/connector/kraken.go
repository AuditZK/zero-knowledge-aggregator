package connector

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

const krakenAPI = "https://api.kraken.com"

// Kraken implements Connector for Kraken exchange.
type Kraken struct {
	apiKey    string
	apiSecret string
	client    *http.Client
}

// NewKraken creates a new Kraken connector.
func NewKraken(creds *Credentials) *Kraken {
	return &Kraken{
		apiKey:    creds.APIKey,
		apiSecret: creds.APISecret,
		client:    &http.Client{Timeout: 30 * time.Second},
	}
}

func (k *Kraken) Exchange() string {
	return "kraken"
}

func (k *Kraken) sign(path, nonce, postData string) (string, error) {
	decodedSecret, err := base64.StdEncoding.DecodeString(k.apiSecret)
	if err != nil {
		return "", fmt.Errorf("decode kraken api secret (must be base64): %w", err)
	}

	sha := sha256.New()
	sha.Write([]byte(nonce + postData))
	shaSum := sha.Sum(nil)

	mac := hmac.New(sha512.New, decodedSecret)
	mac.Write([]byte(path))
	mac.Write(shaSum)

	return base64.StdEncoding.EncodeToString(mac.Sum(nil)), nil
}

func (k *Kraken) doPrivate(ctx context.Context, path string, params url.Values) ([]byte, error) {
	body, err := retryHTTP(k.client, func() (*http.Request, error) {
		if params == nil {
			params = url.Values{}
		}

		// Fresh nonce per attempt — Kraken rejects a replayed nonce, so a
		// retry MUST rebuild and re-sign rather than resend the same request.
		nonce := strconv.FormatInt(time.Now().UnixNano()/int64(time.Millisecond), 10)
		params.Set("nonce", nonce)
		postData := params.Encode()

		signature, err := k.sign(path, nonce, postData)
		if err != nil {
			return nil, err
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, krakenAPI+path, strings.NewReader(postData))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("API-Key", k.apiKey)
		req.Header.Set("API-Sign", signature)
		return req, nil
	})
	if err != nil {
		return nil, err
	}

	var envelope struct {
		Error []string `json:"error"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, err
	}
	if len(envelope.Error) > 0 {
		return nil, fmt.Errorf("kraken API error: %s", strings.Join(envelope.Error, ", "))
	}

	return body, nil
}

func (k *Kraken) TestConnection(ctx context.Context) error {
	_, err := k.doPrivate(ctx, "/0/private/Balance", nil)
	return err
}

func (k *Kraken) GetBalance(ctx context.Context) (*Balance, error) {
	body, err := k.doPrivate(ctx, "/0/private/Balance", nil)
	if err != nil {
		return nil, err
	}

	var resp struct {
		Result map[string]string `json:"result"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}

	// CONN-12 on Kraken, two defects in one function.
	//
	// The first is the shared one: only USD-like assets counted, so BTC/ETH
	// holdings were dropped from equity entirely.
	//
	// The second was worse and is DELETED rather than fixed: when the USD-like
	// total came out at zero, the old code summed the raw QUANTITIES of every
	// asset into a USD figure — 1.5 BTC contributed 1.5 USD. That is not an
	// understatement, it is a number with no unit, and a wrong equity poisons
	// the TWR forever. A typed failure is worth more than a fabricated total.
	var holdings []SpotHolding
	var stableTotal float64
	hasNonStable := false
	for asset, amountStr := range resp.Result {
		amount, _ := strconv.ParseFloat(amountStr, 64)
		if amount <= 0 {
			continue
		}
		norm := normalizeKrakenAsset(asset)
		holdings = append(holdings, SpotHolding{Asset: norm, Amount: amount})
		if IsStablecoinUSD(norm) {
			stableTotal += amount
		} else {
			hasNonStable = true
		}
	}

	priceMap := map[string]float64{}
	if hasNonStable {
		pm, perr := k.fetchPriceMap(ctx)
		if perr != nil {
			return nil, fmt.Errorf("%w: kraken public ticker: %v", ErrSpotPricingUnavailable, perr)
		}
		priceMap = pm
	}
	total := ValueSpotHoldingsUSD(holdings, priceMap)

	return &Balance{
		Available: total,
		Equity:    total,
		Currency:  "USD",
	}, nil
}

// normalizeKrakenAsset maps Kraken's own asset codes onto the plain tickers
// the shared valuation expects. Kraken keeps legacy X/Z prefixes (XXBT, XETH,
// ZUSD), uses XBT for bitcoin and XDG for dogecoin, and suffixes staked or
// yield-bearing variants (ETH2.S, DOT.S, USDC.F) — all of which are the same
// underlying asset for valuation purposes.
func normalizeKrakenAsset(asset string) string {
	a := strings.ToUpper(strings.TrimSpace(asset))
	if i := strings.IndexByte(a, '.'); i > 0 {
		a = a[:i] // ETH2.S -> ETH2, USDC.F -> USDC
	}
	if a == "ETH2" {
		a = "ETH" // staked ether tracks ether; a blanket "2" trim would
		// also maul any asset whose ticker legitimately ends in 2
	}
	switch a {
	case "XXBT", "XBT":
		return "BTC"
	case "XETH":
		return "ETH"
	case "XXDG", "XDG":
		return "DOGE"
	case "XLTC":
		return "LTC"
	case "XXRP":
		return "XRP"
	case "XXLM":
		return "XLM"
	case "XZEC":
		return "ZEC"
	case "XXMR":
		return "XMR"
	case "XREP":
		return "REP"
	case "XMLN":
		return "MLN"
	}
	// Z-prefixed fiat: ZUSD -> USD, ZEUR -> EUR.
	if len(a) == 4 && strings.HasPrefix(a, "Z") {
		return a[1:]
	}
	return a
}

// krakenQuoteSuffixes are checked longest-first so ZUSD wins over USD and
// USDT/USDC are not truncated to USD.
var krakenQuoteSuffixes = []string{"ZUSD", "USDT", "USDC", "USD"}

// fetchPriceMap loads every public pair in one call and keys it Binance-style
// (<ASSET>USDT) so ValueSpotHoldingsUSD resolves it. Kraken pair names carry
// no separator (AAVEUSD, XXBTZUSD), and some carry a venue suffix after a
// colon (AAVEUSD:BTNL) which is skipped.
func (k *Kraken) fetchPriceMap(ctx context.Context) (map[string]float64, error) {
	body, err := retryHTTP(k.client, func() (*http.Request, error) {
		return http.NewRequestWithContext(ctx, http.MethodGet, krakenAPI+"/0/public/Ticker", nil)
	})
	if err != nil {
		return nil, err
	}
	var resp struct {
		Result map[string]struct {
			C []json.RawMessage `json:"c"` // [last trade price, lot volume]
		} `json:"result"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}
	prices := make(map[string]float64, len(resp.Result))
	for pair, t := range resp.Result {
		if len(t.C) == 0 || strings.ContainsRune(pair, ':') {
			continue
		}
		price := ParseLooseNumber(t.C[0])
		if price <= 0 {
			continue
		}
		name := strings.ToUpper(pair)
		for _, suffix := range krakenQuoteSuffixes {
			if !strings.HasSuffix(name, suffix) {
				continue
			}
			base := normalizeKrakenAsset(strings.TrimSuffix(name, suffix))
			if base == "" {
				break
			}
			key := base + "USDT"
			// Longest suffix wins, and the first pair seen for an asset wins
			// over later ones, so a plain AAVEUSD is not overwritten by an
			// exotic variant.
			if _, seen := prices[key]; !seen {
				prices[key] = price
			}
			break
		}
	}
	return prices, nil
}

func (k *Kraken) GetPositions(ctx context.Context) ([]*Position, error) {
	params := url.Values{}
	params.Set("docalcs", "true")

	body, err := k.doPrivate(ctx, "/0/private/OpenPositions", params)
	if err != nil {
		return nil, err
	}

	var resp struct {
		Result map[string]struct {
			Pair string `json:"pair"`
			Type string `json:"type"` // buy/sell
			Vol  string `json:"vol"`
			Cost string `json:"cost"`
			Net  string `json:"net"`
		} `json:"result"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}

	positions := make([]*Position, 0, len(resp.Result))
	for _, p := range resp.Result {
		vol, _ := strconv.ParseFloat(p.Vol, 64)
		if vol == 0 {
			continue
		}

		size := math.Abs(vol)
		cost, _ := strconv.ParseFloat(p.Cost, 64)
		entryPrice := 0.0
		if size > 0 {
			entryPrice = cost / size
		}
		net, _ := strconv.ParseFloat(p.Net, 64)

		side := "long"
		if strings.EqualFold(p.Type, "sell") || vol < 0 {
			side = "short"
		}

		positions = append(positions, &Position{
			Symbol:        p.Pair,
			Side:          side,
			Size:          size,
			EntryPrice:    entryPrice,
			MarkPrice:     entryPrice, // Kraken private endpoint does not return mark price directly.
			UnrealizedPnL: net,
			MarketType:    MarketMargin,
		})
	}

	return positions, nil
}

func (k *Kraken) GetTrades(ctx context.Context, start, end time.Time) ([]*Trade, error) {
	params := url.Values{}
	params.Set("type", "all")
	params.Set("start", strconv.FormatInt(start.Unix(), 10))
	params.Set("end", strconv.FormatInt(end.Unix(), 10))
	params.Set("trades", "true")

	body, err := k.doPrivate(ctx, "/0/private/TradesHistory", params)
	if err != nil {
		return nil, err
	}

	var resp struct {
		Result struct {
			Trades map[string]struct {
				Pair  string  `json:"pair"`
				Type  string  `json:"type"` // buy/sell
				Price string  `json:"price"`
				Vol   string  `json:"vol"`
				Fee   string  `json:"fee"`
				Time  float64 `json:"time"`
			} `json:"trades"`
		} `json:"result"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}

	trades := make([]*Trade, 0, len(resp.Result.Trades))
	for id, t := range resp.Result.Trades {
		price, _ := strconv.ParseFloat(t.Price, 64)
		qty, _ := strconv.ParseFloat(t.Vol, 64)
		fee, _ := strconv.ParseFloat(t.Fee, 64)

		trades = append(trades, &Trade{
			ID:          id,
			Symbol:      t.Pair,
			Side:        strings.ToLower(t.Type),
			Price:       price,
			Quantity:    qty,
			Fee:         fee,
			FeeCurrency: "USD",
			RealizedPnL: 0,
			Timestamp:   time.Unix(int64(t.Time), int64((t.Time-math.Floor(t.Time))*1e9)).UTC(),
			MarketType:  MarketSpot,
		})
	}

	sort.Slice(trades, func(i, j int) bool {
		return trades[i].Timestamp.Before(trades[j].Timestamp)
	})

	return trades, nil
}

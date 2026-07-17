package connector

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	saxoLiveAPI = "https://gateway.saxobank.com/openapi"
	saxoSimAPI  = "https://gateway.saxobank.com/sim/openapi"
)

// Saxo implements Connector for Saxo Bank's OpenAPI.
//
// The token is used as supplied and never refreshed. Saxo's access tokens live
// 20 minutes and its refresh tokens 40 — shorter than the daily sync interval —
// so no refresh scheme built on them can keep a connection alive. Minting
// tokens per-call from a certificate is the only flow that fits an unattended
// reader, and it is not available yet, which is why only the SIM environment is
// wired up in the factory. SIM runs on the developer portal's 24h token.
type Saxo struct {
	token   string
	baseURL string
	isSim   bool
	client  *http.Client

	clientMu     sync.Mutex
	clientKey    string
	baseCurrency string
}

// NewSaxo creates a Saxo connector. apiKey carries the bearer access token.
func NewSaxo(creds *Credentials, sim bool) *Saxo {
	baseURL := saxoLiveAPI
	if sim {
		baseURL = saxoSimAPI
	}
	return &Saxo{
		token:   firstNonEmpty(creds.AccessToken, creds.APIKey),
		baseURL: baseURL,
		isSim:   sim,
		client:  &http.Client{Timeout: 30 * time.Second},
	}
}

func (s *Saxo) Exchange() string {
	if s.isSim {
		return "saxo_sim"
	}
	return "saxo"
}

// DetectIsPaper reports whether this connection targets Saxo's SIM gateway.
// SIM and live are separate hosts with separate credentials, so the gateway the
// connector was built for is authoritative.
func (s *Saxo) DetectIsPaper(_ context.Context) (bool, error) {
	return s.isSim, nil
}

func (s *Saxo) doGet(ctx context.Context, path string, query url.Values) ([]byte, error) {
	reqURL := s.baseURL + path
	if len(query) > 0 {
		reqURL += "?" + query.Encode()
	}

	return retryHTTP(s.client, func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+s.token)
		req.Header.Set("Accept", "application/json")
		return req, nil
	})
}

type saxoClientDetails struct {
	ClientKey       string `json:"ClientKey"`
	DefaultCurrency string `json:"DefaultCurrency"`
}

func (s *Saxo) ensureClient(ctx context.Context) (saxoClientDetails, error) {
	s.clientMu.Lock()
	defer s.clientMu.Unlock()

	if s.clientKey != "" {
		return saxoClientDetails{ClientKey: s.clientKey, DefaultCurrency: s.baseCurrency}, nil
	}

	body, err := s.doGet(ctx, "/port/v1/clients/me", nil)
	if err != nil {
		return saxoClientDetails{}, fmt.Errorf("fetch saxo client: %w", err)
	}

	var details saxoClientDetails
	if err := json.Unmarshal(body, &details); err != nil {
		return saxoClientDetails{}, fmt.Errorf("decode saxo client: %w", err)
	}
	if details.ClientKey == "" {
		return saxoClientDetails{}, fmt.Errorf("saxo client returned no ClientKey")
	}

	s.clientKey = details.ClientKey
	s.baseCurrency = details.DefaultCurrency
	return details, nil
}

func (s *Saxo) TestConnection(ctx context.Context) error {
	_, err := s.ensureClient(ctx)
	return err
}

// GetBalance reports the client-wide balance.
//
// Saxo splits equity into settled cash plus the open positions' value, and the
// two reconcile exactly: CashBalance + UnrealizedPositionsValue = TotalValue.
// UnrealizedPositionsValue is therefore the right unrealised figure to report —
// sync derives the realised balance as Equity - UnrealizedPnL, which lands on
// CashBalance. UnrealizedMarginProfitLoss looks like the same thing but excludes
// the cost of closing the positions, so using it would strand those costs and
// leave the realised balance off by exactly CostToClosePositions.
func (s *Saxo) GetBalance(ctx context.Context) (*Balance, error) {
	body, err := s.doGet(ctx, "/port/v1/balances/me", nil)
	if err != nil {
		return nil, fmt.Errorf("fetch saxo balance: %w", err)
	}

	var resp struct {
		CashBalance               float64 `json:"CashBalance"`
		Currency                  string  `json:"Currency"`
		MarginAvailableForTrading float64 `json:"MarginAvailableForTrading"`
		TotalValue                float64 `json:"TotalValue"`
		UnrealizedPositionsValue  float64 `json:"UnrealizedPositionsValue"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("decode saxo balance: %w", err)
	}

	currency := resp.Currency
	if currency == "" {
		if details, cerr := s.ensureClient(ctx); cerr == nil {
			currency = details.DefaultCurrency
		}
	}

	return &Balance{
		Available:     resp.MarginAvailableForTrading,
		Equity:        resp.TotalValue,
		UnrealizedPnL: resp.UnrealizedPositionsValue,
		Currency:      currency,
	}, nil
}

// saxoMarketType maps Saxo's AssetType to a market bucket. Option is matched
// before everything else because FxVanillaOption is an option rather than a
// forex line, and Cfd before Stock because CfdOnStock is a CFD.
func saxoMarketType(assetType string) string {
	a := strings.ToLower(strings.TrimSpace(assetType))
	switch {
	case strings.Contains(a, "option"):
		return MarketOptions
	case strings.HasPrefix(a, "cfd"):
		return MarketCFD
	case strings.Contains(a, "futures"):
		return MarketFutures
	case strings.HasPrefix(a, "fx"):
		return MarketForex
	default:
		return MarketStocks
	}
}

// saxoSymbol reads the instrument out of a NetPositionId, which Saxo formats as
// "<symbol>__<assetType>" (e.g. "EURUSD__FxSpot"). Deriving it costs nothing,
// where a readable symbol otherwise needs the DisplayAndFormat field group on
// every call.
func saxoSymbol(netPositionID string) string {
	if idx := strings.Index(netPositionID, "__"); idx > 0 {
		return netPositionID[:idx]
	}
	return netPositionID
}

func (s *Saxo) GetPositions(ctx context.Context) ([]*Position, error) {
	body, err := s.doGet(ctx, "/port/v1/positions/me", nil)
	if err != nil {
		return nil, fmt.Errorf("fetch saxo positions: %w", err)
	}

	var resp struct {
		Data []struct {
			NetPositionId string `json:"NetPositionId"`
			PositionBase  struct {
				Amount    float64 `json:"Amount"`
				AssetType string  `json:"AssetType"`
				OpenPrice float64 `json:"OpenPrice"`
			} `json:"PositionBase"`
			PositionView struct {
				CurrentPrice                    float64 `json:"CurrentPrice"`
				ProfitLossOnTradeInBaseCurrency float64 `json:"ProfitLossOnTradeInBaseCurrency"`
			} `json:"PositionView"`
		} `json:"Data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("decode saxo positions: %w", err)
	}

	positions := make([]*Position, 0, len(resp.Data))
	for _, p := range resp.Data {
		if p.PositionBase.Amount == 0 {
			continue
		}

		side := "long"
		if p.PositionBase.Amount < 0 {
			side = "short"
		}

		positions = append(positions, &Position{
			Symbol:     saxoSymbol(p.NetPositionId),
			Side:       side,
			Size:       math.Abs(p.PositionBase.Amount),
			EntryPrice: p.PositionBase.OpenPrice,
			MarkPrice:  p.PositionView.CurrentPrice,
			// Base currency is the account's own, so this sums against the
			// equity GetBalance reports; the instrument-currency figure would not.
			UnrealizedPnL: p.PositionView.ProfitLossOnTradeInBaseCurrency,
			MarketType:    saxoMarketType(p.PositionBase.AssetType),
		})
	}
	return positions, nil
}

// GetTrades reads closed positions and keeps those closed inside the window.
//
// This is the portfolio's closed-positions view, which covers the recent
// closes a daily sync asks for. It is NOT a full trade log: deep history lives
// behind Saxo's reporting service, which is not wired up here, so a long
// backfill would come up short rather than wrong.
func (s *Saxo) GetTrades(ctx context.Context, start, end time.Time) ([]*Trade, error) {
	q := url.Values{}
	q.Set("FieldGroups", "ClosedPosition")

	body, err := s.doGet(ctx, "/port/v1/closedpositions", q)
	if err != nil {
		return nil, fmt.Errorf("fetch saxo closed positions: %w", err)
	}

	var resp struct {
		Data []struct {
			ClosedPositionUniqueId string `json:"ClosedPositionUniqueId"`
			NetPositionId          string `json:"NetPositionId"`
			ClosedPosition         struct {
				AssetType                      string  `json:"AssetType"`
				Amount                         float64 `json:"Amount"`
				BuyOrSell                      string  `json:"BuyOrSell"`
				ClosedProfitLossInBaseCurrency float64 `json:"ClosedProfitLossInBaseCurrency"`
				ClosingPrice                   float64 `json:"ClosingPrice"`
				CostClosingInBaseCurrency      float64 `json:"CostClosingInBaseCurrency"`
				CostOpeningInBaseCurrency      float64 `json:"CostOpeningInBaseCurrency"`
				ExecutionTimeClose             string  `json:"ExecutionTimeClose"`
			} `json:"ClosedPosition"`
		} `json:"Data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("decode saxo closed positions: %w", err)
	}

	details, err := s.ensureClient(ctx)
	if err != nil {
		return nil, err
	}

	trades := make([]*Trade, 0, len(resp.Data))
	for _, d := range resp.Data {
		cp := d.ClosedPosition

		ts, terr := time.Parse(time.RFC3339, cp.ExecutionTimeClose)
		if terr != nil {
			continue
		}
		ts = ts.UTC()
		if ts.Before(start) || ts.After(end) {
			continue
		}

		side := "buy"
		if strings.EqualFold(cp.BuyOrSell, "Sell") {
			side = "sell"
		}

		// Saxo reports costs as negative amounts already netted out of the
		// closed P&L; Fee is a positive magnitude everywhere else in this
		// package, so flip it back.
		fee := math.Abs(cp.CostOpeningInBaseCurrency) + math.Abs(cp.CostClosingInBaseCurrency)

		trades = append(trades, &Trade{
			ID:          firstNonEmpty(d.ClosedPositionUniqueId, d.NetPositionId),
			Symbol:      saxoSymbol(d.NetPositionId),
			Side:        side,
			Price:       cp.ClosingPrice,
			Quantity:    math.Abs(cp.Amount),
			Fee:         fee,
			FeeCurrency: details.DefaultCurrency,
			RealizedPnL: cp.ClosedProfitLossInBaseCurrency,
			Timestamp:   ts,
			MarketType:  saxoMarketType(cp.AssetType),
		})
	}
	return trades, nil
}

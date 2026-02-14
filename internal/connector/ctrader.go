package connector

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

const ctraderAPI = "https://openapi.ctrader.com"

// CTrader is a CFD/Forex broker connector using OAuth 2.0.
type CTrader struct {
	clientID     string
	clientSecret string
	accessToken  string
	client       *http.Client
}

// NewCTrader creates a new cTrader connector.
func NewCTrader(creds *Credentials) *CTrader {
	clientID := creds.ClientID
	if clientID == "" {
		clientID = creds.APIKey
	}
	clientSecret := creds.ClientSecret
	if clientSecret == "" {
		clientSecret = creds.APISecret
	}
	accessToken := creds.AccessToken
	if accessToken == "" {
		accessToken = creds.Passphrase
	}

	return &CTrader{
		clientID:     clientID,
		clientSecret: clientSecret,
		accessToken:  accessToken,
		client:       &http.Client{Timeout: 30 * time.Second},
	}
}

func (c *CTrader) Exchange() string { return "ctrader" }

func (c *CTrader) TestConnection(ctx context.Context) error {
	_, err := c.GetBalance(ctx)
	return err
}

func (c *CTrader) GetBalance(ctx context.Context) (*Balance, error) {
	data, err := c.doGet(ctx, "/v2/webserv/accounts")
	if err != nil {
		return nil, fmt.Errorf("get accounts: %w", err)
	}

	var resp struct {
		Data []struct {
			AccountID  int64  `json:"ctidTraderAccountId"`
			Balance    int64  `json:"balance"`    // In cents
			IsLive     bool   `json:"isLive"`
			BrokerName string `json:"brokerName"`
		} `json:"data"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, err
	}

	if len(resp.Data) == 0 {
		return nil, fmt.Errorf("no cTrader accounts found")
	}

	// Use first account
	acct := resp.Data[0]
	balance := float64(acct.Balance) / 100.0

	return &Balance{
		Equity:    balance,
		Available: balance,
		Currency:  "USD",
	}, nil
}

func (c *CTrader) GetPositions(ctx context.Context) ([]*Position, error) {
	data, err := c.doGet(ctx, "/v2/webserv/openPositions")
	if err != nil {
		return nil, err
	}

	var resp struct {
		Data []struct {
			PositionID int64 `json:"positionId"`
			TradeData  struct {
				SymbolID  int64  `json:"symbolId"`
				TradeSide string `json:"tradeSide"` // "BUY" or "SELL"
				Volume    int64  `json:"volume"`     // In cents
			} `json:"tradeData"`
			Price               float64 `json:"price"`
			UnrealizedNetProfit int64   `json:"unrealizedNetProfit"` // In cents
			SymbolName          string  `json:"symbolName"`
		} `json:"data"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, err
	}

	var positions []*Position
	for _, p := range resp.Data {
		side := "long"
		if p.TradeData.TradeSide == "SELL" {
			side = "short"
		}

		// Determine market type based on symbol
		marketType := detectCTraderMarketType(p.SymbolName)

		positions = append(positions, &Position{
			Symbol:        p.SymbolName,
			Side:          side,
			Size:          float64(p.TradeData.Volume) / 100.0,
			EntryPrice:    p.Price,
			UnrealizedPnL: float64(p.UnrealizedNetProfit) / 100.0,
			MarketType:    marketType,
		})
	}

	return positions, nil
}

func (c *CTrader) GetTrades(ctx context.Context, start, end time.Time) ([]*Trade, error) {
	url := fmt.Sprintf("/v2/webserv/deals?from=%d&to=%d",
		start.UnixMilli(), end.UnixMilli())
	data, err := c.doGet(ctx, url)
	if err != nil {
		return nil, err
	}

	var resp struct {
		Data []struct {
			DealID             int64  `json:"dealId"`
			OrderID            int64  `json:"orderId"`
			SymbolID           int64  `json:"symbolId"`
			TradeSide          string `json:"tradeSide"` // "BUY" or "SELL"
			FilledVolume       int64  `json:"filledVolume"`
			ExecutionPrice     int64  `json:"executionPrice"` // In price cents
			ExecutionTimestamp int64  `json:"executionTimestamp"`
			Commission         int64  `json:"commission"` // In cents
			SymbolName         string `json:"symbolName"`
			DealStatus         string `json:"dealStatus"`
			ClosePositionDetail *struct {
				GrossProfit int64 `json:"grossProfit"`
				Commission  int64 `json:"commission"`
				Swap        int64 `json:"swap"`
			} `json:"closePositionDetail"`
		} `json:"data"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, err
	}

	var trades []*Trade
	for _, d := range resp.Data {
		if d.DealStatus != "FILLED" && d.DealStatus != "PARTIALLY_FILLED" {
			continue
		}

		side := "buy"
		if d.TradeSide == "SELL" {
			side = "sell"
		}

		var pnl float64
		if d.ClosePositionDetail != nil {
			pnl = float64(d.ClosePositionDetail.GrossProfit) / 100.0
		}

		marketType := detectCTraderMarketType(d.SymbolName)

		trades = append(trades, &Trade{
			ID:          fmt.Sprintf("%d", d.DealID),
			Symbol:      d.SymbolName,
			Side:        side,
			Price:       float64(d.ExecutionPrice) / 100000.0,
			Quantity:    float64(d.FilledVolume) / 100.0,
			Fee:         float64(d.Commission) / 100.0,
			FeeCurrency: "USD",
			RealizedPnL: pnl,
			Timestamp:   time.UnixMilli(d.ExecutionTimestamp),
			MarketType:  marketType,
		})
	}

	return trades, nil
}

func (c *CTrader) doGet(ctx context.Context, path string) (json.RawMessage, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", ctraderAPI+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.accessToken)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ctrader API error %d: %s", resp.StatusCode, string(data))
	}

	return data, nil
}

// detectCTraderMarketType guesses market type from symbol name.
func detectCTraderMarketType(symbol string) string {
	// Forex pairs typically have 6 chars (EURUSD, GBPJPY, etc.)
	if len(symbol) == 6 {
		return MarketForex
	}
	// Indices
	indices := []string{"US500", "US30", "US100", "DE30", "UK100", "JP225", "AU200"}
	for _, idx := range indices {
		if symbol == idx {
			return MarketCFD
		}
	}
	// Commodities
	commodities := []string{"XAUUSD", "XAGUSD", "XPTUSD", "USOIL", "UKOIL"}
	for _, c := range commodities {
		if symbol == c {
			return MarketCommodities
		}
	}
	return MarketCFD
}

// Ensure unused import doesn't cause issues
var _ = strconv.Atoi

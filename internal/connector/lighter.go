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

const lighterAPI = "https://mainnet.zklighter.elliot.ai"

// Lighter is a read-only DEX connector for the Lighter Protocol.
type Lighter struct {
	walletAddress string
	client        *http.Client
}

// NewLighter creates a new Lighter connector.
func NewLighter(creds *Credentials) *Lighter {
	addr := creds.WalletAddress
	if addr == "" {
		addr = creds.APIKey // Fallback: wallet address stored in APIKey field
	}
	return &Lighter{
		walletAddress: addr,
		client:        &http.Client{Timeout: 30 * time.Second},
	}
}

func (l *Lighter) Exchange() string { return "lighter" }

func (l *Lighter) TestConnection(ctx context.Context) error {
	_, err := l.GetBalance(ctx)
	return err
}

func (l *Lighter) GetBalance(ctx context.Context) (*Balance, error) {
	data, err := l.doGet(ctx, fmt.Sprintf("/api/v1/account/%s", l.walletAddress))
	if err != nil {
		return nil, err
	}

	var account struct {
		Index             int    `json:"index"`
		L1Address         string `json:"l1_address"`
		AvailableBalance  string `json:"available_balance"`
		Collateral        string `json:"collateral"`
		TotalAssetValue   string `json:"total_asset_value"`
	}
	if err := json.Unmarshal(data, &account); err != nil {
		return nil, fmt.Errorf("parse account: %w", err)
	}

	equity, _ := strconv.ParseFloat(account.TotalAssetValue, 64)
	available, _ := strconv.ParseFloat(account.AvailableBalance, 64)
	collateral, _ := strconv.ParseFloat(account.Collateral, 64)

	return &Balance{
		Equity:        equity,
		Available:     available,
		UnrealizedPnL: equity - collateral,
		Currency:      "USD",
	}, nil
}

func (l *Lighter) GetPositions(ctx context.Context) ([]*Position, error) {
	data, err := l.doGet(ctx, fmt.Sprintf("/api/v1/account/%s", l.walletAddress))
	if err != nil {
		return nil, err
	}

	var account struct {
		Positions []struct {
			MarketID       int    `json:"market_id"`
			Symbol         string `json:"symbol"`
			Sign           int    `json:"sign"` // 1=long, -1=short
			Size           string `json:"size"`
			AvgEntryPrice  string `json:"avg_entry_price"`
			PositionValue  string `json:"position_value"`
			UnrealizedPnl  string `json:"unrealized_pnl"`
			LiquidationPx  string `json:"liquidation_price"`
		} `json:"positions"`
	}
	if err := json.Unmarshal(data, &account); err != nil {
		return nil, err
	}

	var positions []*Position
	for _, p := range account.Positions {
		size, _ := strconv.ParseFloat(p.Size, 64)
		if size == 0 {
			continue
		}

		side := "long"
		if p.Sign < 0 {
			side = "short"
		}

		entryPx, _ := strconv.ParseFloat(p.AvgEntryPrice, 64)
		pnl, _ := strconv.ParseFloat(p.UnrealizedPnl, 64)

		positions = append(positions, &Position{
			Symbol:        p.Symbol,
			Side:          side,
			Size:          size,
			EntryPrice:    entryPx,
			UnrealizedPnL: pnl,
			MarketType:    MarketSwap,
		})
	}

	return positions, nil
}

func (l *Lighter) GetTrades(ctx context.Context, start, end time.Time) ([]*Trade, error) {
	data, err := l.doGet(ctx, fmt.Sprintf("/api/v1/fills/%s", l.walletAddress))
	if err != nil {
		return nil, err
	}

	var resp struct {
		Fills []struct {
			TradeID      int    `json:"trade_id"`
			Timestamp    int64  `json:"timestamp"`
			MarketID     int    `json:"market_id"`
			Symbol       string `json:"symbol"`
			Size         string `json:"size"`
			Price        string `json:"price"`
			IsMakerAsk   bool   `json:"is_maker_ask"`
			AskAccountID int    `json:"ask_account_id"`
			BidAccountID int    `json:"bid_account_id"`
			TakerFee     int    `json:"taker_fee"`
			MakerFee     int    `json:"maker_fee"`
		} `json:"fills"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, err
	}

	var trades []*Trade
	for _, f := range resp.Fills {
		ts := time.UnixMilli(f.Timestamp)
		if ts.Before(start) || ts.After(end) {
			continue
		}

		price, _ := strconv.ParseFloat(f.Price, 64)
		qty, _ := strconv.ParseFloat(f.Size, 64)

		// Determine side based on account position
		side := "buy"
		fee := float64(f.TakerFee) / 1e6 // Assuming fee is in micro-units
		if f.IsMakerAsk {
			side = "sell"
			fee = float64(f.MakerFee) / 1e6
		}

		trades = append(trades, &Trade{
			ID:          fmt.Sprintf("%d", f.TradeID),
			Symbol:      f.Symbol,
			Side:        side,
			Price:       price,
			Quantity:    qty,
			Fee:         fee,
			FeeCurrency: "USD",
			Timestamp:   ts,
			MarketType:  MarketSwap,
		})
	}

	return trades, nil
}

func (l *Lighter) doGet(ctx context.Context, path string) (json.RawMessage, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", lighterAPI+path, nil)
	if err != nil {
		return nil, err
	}

	resp, err := l.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("lighter API error %d: %s", resp.StatusCode, string(data))
	}

	return data, nil
}

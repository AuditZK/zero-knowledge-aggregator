package connector

import (
	"context"
	"time"
)

// Connector defines the interface for exchange connectors
type Connector interface {
	// GetBalance returns current account balance and equity
	GetBalance(ctx context.Context) (*Balance, error)

	// GetPositions returns open positions
	GetPositions(ctx context.Context) ([]*Position, error)

	// GetTrades returns trades within the time range (memory only, never persisted)
	GetTrades(ctx context.Context, start, end time.Time) ([]*Trade, error)

	// TestConnection verifies API credentials
	TestConnection(ctx context.Context) error

	// Exchange returns the exchange identifier
	Exchange() string
}

// Balance represents account balance data
type Balance struct {
	Available     float64 `json:"available"`      // Free balance
	Equity        float64 `json:"equity"`         // Total equity (balance + unrealized)
	UnrealizedPnL float64 `json:"unrealized_pnl"` // Unrealized P&L
	Currency      string  `json:"currency"`
}

// Position represents an open position
type Position struct {
	Symbol        string  `json:"symbol"`
	Side          string  `json:"side"` // "long" or "short"
	Size          float64 `json:"size"`
	EntryPrice    float64 `json:"entry_price"`
	MarkPrice     float64 `json:"mark_price"`
	UnrealizedPnL float64 `json:"unrealized_pnl"`
	MarketType    string  `json:"market_type"` // "spot", "swap", "futures"
}

// Trade represents a single trade (memory only)
type Trade struct {
	ID          string    `json:"id"`
	Symbol      string    `json:"symbol"`
	Side        string    `json:"side"` // "buy" or "sell"
	Price       float64   `json:"price"`
	Quantity    float64   `json:"quantity"`
	Fee         float64   `json:"fee"`
	FeeCurrency string    `json:"fee_currency"`
	RealizedPnL float64   `json:"realized_pnl"`
	Timestamp   time.Time `json:"timestamp"`
	MarketType  string    `json:"market_type"` // "spot", "swap", "futures", "options"
}

// Credentials holds decrypted API credentials
type Credentials struct {
	Exchange   string
	APIKey     string
	APISecret  string
	Passphrase string // Optional, for exchanges like OKX
}

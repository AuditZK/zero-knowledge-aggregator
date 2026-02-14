package connector

import (
	"context"
	"math/rand"
	"time"
)

// MockConnector is a configurable exchange connector for stress testing.
type MockConnector struct {
	exchange string
	balance  *Balance
	trades   []*Trade
	err      error
	delay    time.Duration
}

// MockOption configures a MockConnector.
type MockOption func(*MockConnector)

// WithMockBalance sets the balance the mock returns.
func WithMockBalance(b *Balance) MockOption {
	return func(m *MockConnector) { m.balance = b }
}

// WithMockTrades sets the trades the mock returns.
func WithMockTrades(t []*Trade) MockOption {
	return func(m *MockConnector) { m.trades = t }
}

// WithMockError sets an error for all operations.
func WithMockError(err error) MockOption {
	return func(m *MockConnector) { m.err = err }
}

// WithMockDelay adds simulated latency to all operations.
func WithMockDelay(d time.Duration) MockOption {
	return func(m *MockConnector) { m.delay = d }
}

// NewMock creates a new mock connector with configurable responses.
func NewMock(opts ...MockOption) *MockConnector {
	m := &MockConnector{
		exchange: "mock",
		balance: &Balance{
			Available:     10000.0,
			Equity:        12500.0,
			UnrealizedPnL: 2500.0,
			Currency:      "USD",
		},
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

func (m *MockConnector) GetBalance(ctx context.Context) (*Balance, error) {
	if m.delay > 0 {
		time.Sleep(m.delay)
	}
	if m.err != nil {
		return nil, m.err
	}
	return m.balance, nil
}

func (m *MockConnector) GetPositions(ctx context.Context) ([]*Position, error) {
	if m.delay > 0 {
		time.Sleep(m.delay)
	}
	if m.err != nil {
		return nil, m.err
	}
	return []*Position{
		{
			Symbol:        "BTC/USD",
			Side:          "long",
			Size:          0.5,
			EntryPrice:    45000,
			MarkPrice:     50000,
			UnrealizedPnL: 2500,
			MarketType:    MarketSwap,
		},
	}, nil
}

func (m *MockConnector) GetTrades(ctx context.Context, start, end time.Time) ([]*Trade, error) {
	if m.delay > 0 {
		time.Sleep(m.delay)
	}
	if m.err != nil {
		return nil, m.err
	}
	if m.trades != nil {
		return m.trades, nil
	}
	// Generate some random trades
	var trades []*Trade
	for t := start; t.Before(end); t = t.Add(24 * time.Hour) {
		trades = append(trades, &Trade{
			ID:          t.Format("20060102") + "-mock",
			Symbol:      "BTC/USD",
			Side:        "buy",
			Price:       45000 + rand.Float64()*5000,
			Quantity:    0.01 + rand.Float64()*0.09,
			Fee:         0.5,
			FeeCurrency: "USD",
			Timestamp:   t,
			MarketType:  MarketSwap,
		})
	}
	return trades, nil
}

func (m *MockConnector) TestConnection(ctx context.Context) error {
	if m.delay > 0 {
		time.Sleep(m.delay)
	}
	return m.err
}

func (m *MockConnector) Exchange() string {
	return m.exchange
}

package connector

import "fmt"

// ErrUnsupportedExchange is returned when exchange is not supported
var ErrUnsupportedExchange = fmt.Errorf("unsupported exchange")

// Factory creates exchange connectors
type Factory struct{}

// NewFactory creates a new connector factory
func NewFactory() *Factory {
	return &Factory{}
}

// Create returns a connector for the given credentials
func (f *Factory) Create(creds *Credentials) (Connector, error) {
	switch creds.Exchange {
	// Crypto exchanges
	case "binance":
		return NewBinance(creds), nil
	case "bybit":
		return NewBybit(creds), nil
	case "okx":
		return NewOKX(creds), nil

	// Traditional brokers
	case "ibkr":
		return NewIBKR(creds), nil
	case "alpaca":
		return NewAlpaca(creds), nil
	case "tradestation":
		return NewTradeStation(creds), nil

	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedExchange, creds.Exchange)
	}
}

// SupportedExchanges returns list of supported exchanges
func (f *Factory) SupportedExchanges() []string {
	return []string{
		"binance",
		"bybit",
		"okx",
		"ibkr",
		"alpaca",
		"tradestation",
	}
}

package validation

import (
	"strings"
	"testing"
	"time"
)

func TestValidateUserUID(t *testing.T) {
	tests := []struct {
		name    string
		uid     string
		wantErr bool
	}{
		{"empty", "", true},
		{"clerk id", "user_abc1234567890", false},
		{"uuid", "550e8400-e29b-41d4-a716-446655440000", false},
		{"cuid", "clabcdefghij1234567890", false},
		{"too long", strings.Repeat("a", 101), true},
		{"invalid format", "not-valid", true},
		{"clerk too short", "user_abc", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateUserUID(tt.uid)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateUserUID(%q) error = %v, wantErr %v", tt.uid, err, tt.wantErr)
			}
		})
	}
}

func TestValidateExchange(t *testing.T) {
	tests := []struct {
		name     string
		exchange string
		wantErr  bool
	}{
		{"empty", "", true},
		{"binance", "binance", false},
		{"bybit", "bybit", false},
		{"mock", "mock", false},
		{"unsupported", "kraken", true},
		{"invalid chars", "bin@nce!", true},
		{"case insensitive", "Binance", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateExchange(tt.exchange)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateExchange(%q) error = %v, wantErr %v", tt.exchange, err, tt.wantErr)
			}
		})
	}
}

func TestValidateLabel(t *testing.T) {
	if err := ValidateLabel(""); err != nil {
		t.Error("empty label should be valid")
	}
	if err := ValidateLabel("my-account"); err != nil {
		t.Error("normal label should be valid")
	}
	if err := ValidateLabel(strings.Repeat("x", 256)); err == nil {
		t.Error("label > 255 chars should be invalid")
	}
}

func TestValidateAPIKey(t *testing.T) {
	if err := ValidateAPIKey("normal-key"); err != nil {
		t.Error("normal key should be valid")
	}
	if err := ValidateAPIKey(strings.Repeat("x", 501)); err == nil {
		t.Error("key > 500 chars should be invalid")
	}
}

func TestValidateCreateConnection(t *testing.T) {
	tests := []struct {
		name    string
		req     *CreateConnectionRequest
		wantErr bool
	}{
		{
			"valid CEX",
			&CreateConnectionRequest{
				UserUID: "user_abc1234567890", Exchange: "binance",
				APIKey: "key123", APISecret: "secret456",
			},
			false,
		},
		{
			"valid DEX",
			&CreateConnectionRequest{
				UserUID: "user_abc1234567890", Exchange: "hyperliquid",
				APIKey: "0xWalletAddress",
			},
			false,
		},
		{
			"valid mock",
			&CreateConnectionRequest{
				UserUID: "user_abc1234567890", Exchange: "mock",
				APIKey: "test",
			},
			false,
		},
		{
			"missing api_secret for CEX",
			&CreateConnectionRequest{
				UserUID: "user_abc1234567890", Exchange: "binance",
				APIKey: "key123",
			},
			true,
		},
		{
			"missing api_key",
			&CreateConnectionRequest{
				UserUID: "user_abc1234567890", Exchange: "binance",
			},
			true,
		},
		{
			"invalid user",
			&CreateConnectionRequest{
				UserUID: "bad", Exchange: "binance",
				APIKey: "key", APISecret: "secret",
			},
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateCreateConnection(tt.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateCreateConnection() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateReportRequest(t *testing.T) {
	tests := []struct {
		name    string
		req     *ReportRequest
		wantErr bool
	}{
		{
			"valid",
			&ReportRequest{
				UserUID: "user_abc1234567890", StartDate: "2025-01-01", EndDate: "2025-12-31",
			},
			false,
		},
		{
			"missing start",
			&ReportRequest{
				UserUID: "user_abc1234567890", EndDate: "2025-12-31",
			},
			true,
		},
		{
			"end before start",
			&ReportRequest{
				UserUID: "user_abc1234567890", StartDate: "2025-12-31", EndDate: "2025-01-01",
			},
			true,
		},
		{
			"range too large",
			&ReportRequest{
				UserUID: "user_abc1234567890", StartDate: "2020-01-01", EndDate: "2026-01-01",
			},
			true,
		},
		{
			"invalid date format",
			&ReportRequest{
				UserUID: "user_abc1234567890", StartDate: "01-01-2025", EndDate: "12-31-2025",
			},
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateReportRequest(tt.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateReportRequest() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateTimestampRange(t *testing.T) {
	tests := []struct {
		name      string
		startYear int
		endYear   int
		wantErr   bool
	}{
		{"1 year", 2025, 2026, false},
		{"5 years exact", 2020, 2025, false},
		{"6 years", 2019, 2025, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			start := time.Date(tt.startYear, 1, 1, 0, 0, 0, 0, time.UTC)
			end := time.Date(tt.endYear, 1, 1, 0, 0, 0, 0, time.UTC)
			err := ValidateTimestampRange(start, end)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateTimestampRange() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

package validation

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

const (
	maxUserUIDLen = 100
	maxLabelLen   = 255
	maxAPIKeyLen  = 500
	maxTimestampRangeYears = 5
)

var (
	clerkIDRegex = regexp.MustCompile(`^user_[a-zA-Z0-9]{10,50}$`)
	uuidRegex    = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	cuidRegex    = regexp.MustCompile(`^c[a-z0-9]{20,30}$`)
	exchangeRegex = regexp.MustCompile(`^[a-z0-9_-]+$`)

	supportedExchanges = map[string]bool{
		"binance":      true,
		"bybit":        true,
		"okx":          true,
		"ibkr":         true,
		"alpaca":       true,
		"tradestation": true,
		"hyperliquid":  true,
		"ctrader":      true,
		"lighter":      true,
		"mock":         true,
	}
)

// ValidateUserUID checks if the UID matches Clerk ID, UUID, or CUID format.
func ValidateUserUID(uid string) error {
	if uid == "" {
		return fmt.Errorf("user_uid is required")
	}
	if len(uid) > maxUserUIDLen {
		return fmt.Errorf("user_uid too long: max %d characters", maxUserUIDLen)
	}
	if clerkIDRegex.MatchString(uid) || uuidRegex.MatchString(uid) || cuidRegex.MatchString(uid) {
		return nil
	}
	return fmt.Errorf("invalid user_uid format: must be Clerk ID, UUID, or CUID")
}

// ValidateExchange checks if the exchange is supported.
func ValidateExchange(exchange string) error {
	if exchange == "" {
		return fmt.Errorf("exchange is required")
	}
	lower := strings.ToLower(exchange)
	if !exchangeRegex.MatchString(lower) {
		return fmt.Errorf("invalid exchange format: must match [a-z0-9_-]+")
	}
	if !supportedExchanges[lower] {
		return fmt.Errorf("unsupported exchange: %s", exchange)
	}
	return nil
}

// ValidateLabel checks label constraints.
func ValidateLabel(label string) error {
	if len(label) > maxLabelLen {
		return fmt.Errorf("label too long: max %d characters", maxLabelLen)
	}
	return nil
}

// ValidateAPIKey checks API key length constraints.
func ValidateAPIKey(key string) error {
	if len(key) > maxAPIKeyLen {
		return fmt.Errorf("api_key too long: max %d characters", maxAPIKeyLen)
	}
	return nil
}

// ValidateTimestampRange checks that start < end and range is within maxTimestampRangeYears.
func ValidateTimestampRange(start, end time.Time) error {
	if !start.IsZero() && !end.IsZero() {
		if end.Before(start) {
			return fmt.Errorf("end_date must be after start_date")
		}
		maxEnd := start.AddDate(maxTimestampRangeYears, 0, 0)
		if end.After(maxEnd) {
			return fmt.Errorf("date range too large: max %d years", maxTimestampRangeYears)
		}
	}
	return nil
}

// CreateConnectionRequest represents validated connection input.
type CreateConnectionRequest struct {
	UserUID    string
	Exchange   string
	Label      string
	APIKey     string
	APISecret  string
	Passphrase string
}

// ValidateCreateConnection validates all fields for connection creation.
func ValidateCreateConnection(req *CreateConnectionRequest) error {
	if err := ValidateUserUID(req.UserUID); err != nil {
		return err
	}
	if err := ValidateExchange(req.Exchange); err != nil {
		return err
	}
	if err := ValidateLabel(req.Label); err != nil {
		return err
	}
	if err := ValidateAPIKey(req.APIKey); err != nil {
		return err
	}
	exchange := strings.ToLower(req.Exchange)
	// DEX connectors only need wallet address in APIKey
	isDEX := exchange == "hyperliquid" || exchange == "lighter"
	if req.APIKey == "" {
		return fmt.Errorf("api_key is required")
	}
	if !isDEX && exchange != "mock" && req.APISecret == "" {
		return fmt.Errorf("api_secret is required for %s", exchange)
	}
	return nil
}

// SyncJobRequest represents validated sync input.
type SyncJobRequest struct {
	UserUID  string
	Exchange string // Optional
}

// ValidateSyncRequest validates sync request fields.
func ValidateSyncRequest(req *SyncJobRequest) error {
	if err := ValidateUserUID(req.UserUID); err != nil {
		return err
	}
	if req.Exchange != "" {
		if err := ValidateExchange(req.Exchange); err != nil {
			return err
		}
	}
	return nil
}

// ReportRequest represents validated report input.
type ReportRequest struct {
	UserUID   string
	StartDate string
	EndDate   string
	Benchmark string
}

// ValidateReportRequest validates report request fields.
func ValidateReportRequest(req *ReportRequest) error {
	if err := ValidateUserUID(req.UserUID); err != nil {
		return err
	}
	if req.StartDate == "" {
		return fmt.Errorf("start_date is required")
	}
	if req.EndDate == "" {
		return fmt.Errorf("end_date is required")
	}
	// Validate date format and range
	start, err := time.Parse("2006-01-02", req.StartDate)
	if err != nil {
		return fmt.Errorf("invalid start_date format: use YYYY-MM-DD")
	}
	end, err := time.Parse("2006-01-02", req.EndDate)
	if err != nil {
		return fmt.Errorf("invalid end_date format: use YYYY-MM-DD")
	}
	if err := ValidateTimestampRange(start, end); err != nil {
		return err
	}
	return nil
}

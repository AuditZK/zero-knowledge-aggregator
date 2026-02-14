package signing

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

const (
	SignatureAlgorithm = "Ed25519"
	EnclaveVersion     = "1.0.0-go"
)

// ReportSigner signs performance reports
type ReportSigner struct {
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
}

// NewReportSigner creates a signer from a seed (32 bytes)
func NewReportSigner(seed []byte) (*ReportSigner, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("seed must be %d bytes", ed25519.SeedSize)
	}

	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(ed25519.PublicKey)

	return &ReportSigner{
		privateKey: privateKey,
		publicKey:  publicKey,
	}, nil
}

// NewReportSignerGenerate creates a signer with a new keypair
func NewReportSignerGenerate() *ReportSigner {
	publicKey, privateKey, _ := ed25519.GenerateKey(nil)
	return &ReportSigner{
		privateKey: privateKey,
		publicKey:  publicKey,
	}
}

// PublicKeyHex returns the public key as hex string
func (s *ReportSigner) PublicKeyHex() string {
	return hex.EncodeToString(s.publicKey)
}

// DailyReturn represents a single day's return data
type DailyReturn struct {
	Date             string  `json:"date"`
	NetReturn        float64 `json:"net_return"`
	BenchmarkReturn  float64 `json:"benchmark_return"`
	Outperformance   float64 `json:"outperformance"`
	CumulativeReturn float64 `json:"cumulative_return"`
	NAV              float64 `json:"nav"`
}

// MonthlyReturn represents a single month's return data
type MonthlyReturn struct {
	Date            string  `json:"date"`
	NetReturn       float64 `json:"net_return"`
	BenchmarkReturn float64 `json:"benchmark_return"`
	Outperformance  float64 `json:"outperformance"`
	AUM             float64 `json:"aum"`
}

// RiskMetrics contains risk analysis data
type RiskMetrics struct {
	VaR95              float64 `json:"var_95"`
	VaR99              float64 `json:"var_99"`
	ExpectedShortfall  float64 `json:"expected_shortfall"`
	Skewness           float64 `json:"skewness"`
	Kurtosis           float64 `json:"kurtosis"`
}

// DrawdownPeriod represents a single drawdown event
type DrawdownPeriod struct {
	StartDate string  `json:"start_date"`
	EndDate   string  `json:"end_date"`
	Depth     float64 `json:"depth"`
	Duration  int     `json:"duration"`
	Recovered bool    `json:"recovered"`
}

// DrawdownData contains drawdown analysis
type DrawdownData struct {
	CurrentDrawdown    float64           `json:"current_drawdown"`
	MaxDrawdownDuration int              `json:"max_drawdown_duration"`
	Periods            []*DrawdownPeriod `json:"periods"`
}

// BenchmarkMetrics holds benchmark comparison data for the report.
type BenchmarkMetrics struct {
	BenchmarkName    string  `json:"benchmark_name"`
	BenchmarkReturn  float64 `json:"benchmark_return"`
	Alpha            float64 `json:"alpha"`
	Beta             float64 `json:"beta"`
	InformationRatio float64 `json:"information_ratio"`
	TrackingError    float64 `json:"tracking_error"`
	Correlation      float64 `json:"correlation"`
}

// ReportInput contains the data to include in a signed report
type ReportInput struct {
	UserUID     string
	ReportName  string
	PeriodStart time.Time
	PeriodEnd   time.Time

	// Metrics
	TotalReturn      float64
	AnnualizedReturn float64
	SharpeRatio      float64
	SortinoRatio     float64
	CalmarRatio      float64
	MaxDrawdown      float64
	Volatility       float64
	WinRate          float64
	ProfitFactor     float64
	DataPoints       int
	BaseCurrency     string
	BenchmarkUsed    string

	// Extended data
	Exchanges        []string
	DailyReturns     []DailyReturn
	MonthlyReturns   []MonthlyReturn
	RiskMetrics      *RiskMetrics
	DrawdownData     *DrawdownData
	BenchmarkMetrics *BenchmarkMetrics
}

// SignedReport is the output of signing
type SignedReport struct {
	// Identification
	ReportID    string `json:"report_id"`
	UserUID     string `json:"user_uid"`
	ReportName  string `json:"report_name"`
	GeneratedAt string `json:"generated_at"`

	// Period
	PeriodStart string `json:"period_start"`
	PeriodEnd   string `json:"period_end"`

	// Metrics
	TotalReturn      float64 `json:"total_return"`
	AnnualizedReturn float64 `json:"annualized_return"`
	SharpeRatio      float64 `json:"sharpe_ratio"`
	SortinoRatio     float64 `json:"sortino_ratio"`
	CalmarRatio      float64 `json:"calmar_ratio"`
	MaxDrawdown      float64 `json:"max_drawdown"`
	Volatility       float64 `json:"volatility"`
	WinRate          float64 `json:"win_rate"`
	ProfitFactor     float64 `json:"profit_factor"`
	DataPoints       int     `json:"data_points"`
	BaseCurrency     string  `json:"base_currency"`
	Benchmark        string  `json:"benchmark"`

	// Extended data
	Exchanges        []string          `json:"exchanges,omitempty"`
	DailyReturns     []DailyReturn     `json:"daily_returns,omitempty"`
	MonthlyReturns   []MonthlyReturn   `json:"monthly_returns,omitempty"`
	RiskMetrics      *RiskMetrics      `json:"risk_metrics,omitempty"`
	DrawdownData     *DrawdownData     `json:"drawdown_data,omitempty"`
	BenchmarkMetrics *BenchmarkMetrics `json:"benchmark_metrics,omitempty"`

	// Display params (NOT signed — applied per request)
	Manager string `json:"manager,omitempty"`
	Firm    string `json:"firm,omitempty"`

	// Signature
	Signature          string `json:"signature"`
	PublicKey          string `json:"public_key"`
	SignatureAlgorithm string `json:"signature_algorithm"`
	ReportHash         string `json:"report_hash"`
	EnclaveVersion     string `json:"enclave_version"`
}

// reportPayload is the canonical form for hashing
type reportPayload struct {
	ReportID         string  `json:"report_id"`
	UserUID          string  `json:"user_uid"`
	ReportName       string  `json:"report_name"`
	GeneratedAt      string  `json:"generated_at"`
	PeriodStart      string  `json:"period_start"`
	PeriodEnd        string  `json:"period_end"`
	TotalReturn      float64 `json:"total_return"`
	AnnualizedReturn float64 `json:"annualized_return"`
	SharpeRatio      float64 `json:"sharpe_ratio"`
	MaxDrawdown      float64 `json:"max_drawdown"`
	DataPoints       int     `json:"data_points"`
}

// Sign creates a signed report from input
func (s *ReportSigner) Sign(input *ReportInput) (*SignedReport, error) {
	reportID := uuid.New().String()
	generatedAt := time.Now().UTC().Format(time.RFC3339)

	// Create canonical payload for hashing
	payload := reportPayload{
		ReportID:         reportID,
		UserUID:          input.UserUID,
		ReportName:       input.ReportName,
		GeneratedAt:      generatedAt,
		PeriodStart:      input.PeriodStart.Format("2006-01-02"),
		PeriodEnd:        input.PeriodEnd.Format("2006-01-02"),
		TotalReturn:      input.TotalReturn,
		AnnualizedReturn: input.AnnualizedReturn,
		SharpeRatio:      input.SharpeRatio,
		MaxDrawdown:      input.MaxDrawdown,
		DataPoints:       input.DataPoints,
	}

	// JSON encode for deterministic hashing
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal payload: %w", err)
	}

	// SHA-256 hash
	hash := sha256.Sum256(payloadBytes)
	hashHex := hex.EncodeToString(hash[:])

	// Sign the hash
	signature := ed25519.Sign(s.privateKey, hash[:])
	signatureB64 := base64.StdEncoding.EncodeToString(signature)

	return &SignedReport{
		ReportID:           reportID,
		UserUID:            input.UserUID,
		ReportName:         input.ReportName,
		GeneratedAt:        generatedAt,
		PeriodStart:        input.PeriodStart.Format("2006-01-02"),
		PeriodEnd:          input.PeriodEnd.Format("2006-01-02"),
		TotalReturn:        input.TotalReturn,
		AnnualizedReturn:   input.AnnualizedReturn,
		SharpeRatio:        input.SharpeRatio,
		SortinoRatio:       input.SortinoRatio,
		CalmarRatio:        input.CalmarRatio,
		MaxDrawdown:        input.MaxDrawdown,
		Volatility:         input.Volatility,
		WinRate:            input.WinRate,
		ProfitFactor:       input.ProfitFactor,
		DataPoints:         input.DataPoints,
		BaseCurrency:       input.BaseCurrency,
		Benchmark:          input.BenchmarkUsed,
		Exchanges:          input.Exchanges,
		DailyReturns:       input.DailyReturns,
		MonthlyReturns:     input.MonthlyReturns,
		RiskMetrics:        input.RiskMetrics,
		DrawdownData:       input.DrawdownData,
		BenchmarkMetrics:   input.BenchmarkMetrics,
		Signature:          signatureB64,
		PublicKey:          s.PublicKeyHex(),
		SignatureAlgorithm: SignatureAlgorithm,
		ReportHash:         hashHex,
		EnclaveVersion:     EnclaveVersion,
	}, nil
}

// Verify checks a signature against a report hash
func Verify(reportHash, signatureB64, publicKeyHex string) (bool, error) {
	hash, err := hex.DecodeString(reportHash)
	if err != nil {
		return false, fmt.Errorf("invalid hash: %w", err)
	}

	signature, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return false, fmt.Errorf("invalid signature: %w", err)
	}

	publicKey, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		return false, fmt.Errorf("invalid public key: %w", err)
	}

	if len(publicKey) != ed25519.PublicKeySize {
		return false, fmt.Errorf("public key wrong size")
	}

	return ed25519.Verify(publicKey, hash, signature), nil
}

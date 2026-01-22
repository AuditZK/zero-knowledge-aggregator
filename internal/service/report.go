package service

import (
	"context"
	"fmt"
	"time"

	"github.com/trackrecord/enclave/internal/signing"
)

// ReportService generates signed performance reports
type ReportService struct {
	metricsSvc *MetricsService
	signer     *signing.ReportSigner
}

// NewReportService creates a new report service
func NewReportService(metricsSvc *MetricsService, signer *signing.ReportSigner) *ReportService {
	return &ReportService{
		metricsSvc: metricsSvc,
		signer:     signer,
	}
}

// GenerateReportRequest contains report generation parameters
type GenerateReportRequest struct {
	UserUID            string
	StartDate          time.Time
	EndDate            time.Time
	ReportName         string
	Benchmark          string
	BaseCurrency       string
	IncludeRiskMetrics bool
	IncludeDrawdown    bool
}

// GenerateReport creates a signed performance report
func (s *ReportService) GenerateReport(ctx context.Context, req *GenerateReportRequest) (*signing.SignedReport, error) {
	// Calculate metrics
	metrics, err := s.metricsSvc.Calculate(ctx, req.UserUID, req.StartDate, req.EndDate)
	if err != nil {
		return nil, fmt.Errorf("calculate metrics: %w", err)
	}

	// Build report input
	input := &signing.ReportInput{
		UserUID:       req.UserUID,
		ReportName:    req.ReportName,
		PeriodStart:   metrics.PeriodStart,
		PeriodEnd:     metrics.PeriodEnd,
		TotalReturn:   metrics.TotalReturn,
		SharpeRatio:   metrics.SharpeRatio,
		SortinoRatio:  metrics.SortinoRatio,
		CalmarRatio:   metrics.CalmarRatio,
		MaxDrawdown:   metrics.MaxDrawdown,
		Volatility:    metrics.Volatility,
		WinRate:       metrics.WinRate,
		ProfitFactor:  metrics.ProfitFactor,
		DataPoints:    metrics.DataPoints,
		BaseCurrency:  req.BaseCurrency,
		BenchmarkUsed: req.Benchmark,
	}

	if input.ReportName == "" {
		input.ReportName = fmt.Sprintf("Performance Report %s to %s",
			input.PeriodStart.Format("2006-01-02"),
			input.PeriodEnd.Format("2006-01-02"))
	}

	if input.BaseCurrency == "" {
		input.BaseCurrency = "USD"
	}

	// Sign the report
	return s.signer.Sign(input)
}

// VerifySignature checks if a report signature is valid
func (s *ReportService) VerifySignature(reportHash, signature, publicKey string) (bool, error) {
	return signing.Verify(reportHash, signature, publicKey)
}

// PublicKey returns the signer's public key
func (s *ReportService) PublicKey() string {
	return s.signer.PublicKeyHex()
}

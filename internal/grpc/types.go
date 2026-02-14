package grpc

// Message types for gRPC service
// Using simple structs with JSON tags for JSON codec compatibility

// HealthCheckRequest is empty
type HealthCheckRequest struct{}

// HealthCheckResponse contains service health info
type HealthCheckResponse struct {
	Status        string  `json:"status"`
	Version       string  `json:"version"`
	Timestamp     int64   `json:"timestamp"`
	UptimeSeconds int64   `json:"uptime_seconds"`
	Database      bool    `json:"database"`
	Enclave       bool    `json:"enclave"`
	Uptime        float64 `json:"uptime"`
}

// SyncJobRequest triggers a sync for a user
type SyncJobRequest struct {
	UserUid  string `json:"user_uid"`
	Exchange string `json:"exchange"`
}

// SyncJobResponse contains sync results
type SyncJobResponse struct {
	Success            bool      `json:"success"`
	UserUid            string    `json:"user_uid"`
	Exchange           string    `json:"exchange"`
	Synced             int32     `json:"synced"`
	SnapshotsGenerated int32     `json:"snapshots_generated"`
	LatestSnapshot     *Snapshot `json:"latest_snapshot"`
	Error              string    `json:"error"`
}

// Snapshot represents a point-in-time snapshot
type Snapshot struct {
	Balance   float64 `json:"balance"`
	Equity    float64 `json:"equity"`
	Timestamp int64   `json:"timestamp"`
}

// AggregatedMetricsRequest requests aggregated metrics
type AggregatedMetricsRequest struct {
	UserUid  string `json:"user_uid"`
	Exchange string `json:"exchange"`
}

// AggregatedMetricsResponse contains aggregated metrics
type AggregatedMetricsResponse struct {
	TotalBalance       float64 `json:"total_balance"`
	TotalEquity        float64 `json:"total_equity"`
	TotalRealizedPnl   float64 `json:"total_realized_pnl"`
	TotalUnrealizedPnl float64 `json:"total_unrealized_pnl"`
	TotalFees          float64 `json:"total_fees"`
	TotalTrades        int32   `json:"total_trades"`
	LastSync           int64   `json:"last_sync"`
}

// SnapshotTimeSeriesRequest requests time series data
type SnapshotTimeSeriesRequest struct {
	UserUid   string `json:"user_uid"`
	Exchange  string `json:"exchange"`
	StartDate int64  `json:"start_date"`
	EndDate   int64  `json:"end_date"`
}

// SnapshotTimeSeriesResponse contains time series snapshots
type SnapshotTimeSeriesResponse struct {
	Snapshots []*DailySnapshot `json:"snapshots"`
}

// DailySnapshot represents a daily snapshot
type DailySnapshot struct {
	UserUid         string           `json:"user_uid"`
	Exchange        string           `json:"exchange"`
	Timestamp       int64            `json:"timestamp"`
	TotalEquity     float64          `json:"total_equity"`
	RealizedBalance float64          `json:"realized_balance"`
	UnrealizedPnl   float64          `json:"unrealized_pnl"`
	Deposits        float64          `json:"deposits"`
	Withdrawals     float64          `json:"withdrawals"`
	Breakdown       *MarketBreakdown `json:"breakdown"`
}

// MarketBreakdown contains per-market metrics
type MarketBreakdown struct {
	Global      *MarketMetrics `json:"global"`
	Spot        *MarketMetrics `json:"spot"`
	Swap        *MarketMetrics `json:"swap"`
	Options     *MarketMetrics `json:"options"`
	Stocks      *MarketMetrics `json:"stocks"`
	Futures     *MarketMetrics `json:"futures"`
	Cfd         *MarketMetrics `json:"cfd"`
	Forex       *MarketMetrics `json:"forex"`
	Commodities *MarketMetrics `json:"commodities"`
}

// MarketMetrics contains metrics for a single market type
type MarketMetrics struct {
	Equity          float64 `json:"equity"`
	AvailableMargin float64 `json:"available_margin"`
	Volume          float64 `json:"volume"`
	Trades          int32   `json:"trades"`
	TradingFees     float64 `json:"trading_fees"`
	FundingFees     float64 `json:"funding_fees"`
}

// CreateUserConnectionRequest creates a new exchange connection
type CreateUserConnectionRequest struct {
	UserUid    string `json:"user_uid"`
	Exchange   string `json:"exchange"`
	Label      string `json:"label"`
	ApiKey     string `json:"api_key"`
	ApiSecret  string `json:"api_secret"`
	Passphrase string `json:"passphrase"`
}

// CreateUserConnectionResponse contains connection creation result
type CreateUserConnectionResponse struct {
	Success bool   `json:"success"`
	UserUid string `json:"user_uid"`
	Error   string `json:"error"`
}

// PerformanceMetricsRequest requests performance metrics
type PerformanceMetricsRequest struct {
	UserUid   string `json:"user_uid"`
	Exchange  string `json:"exchange"`
	StartDate int64  `json:"start_date"`
	EndDate   int64  `json:"end_date"`
}

// PerformanceMetricsResponse contains calculated performance metrics
type PerformanceMetricsResponse struct {
	SharpeRatio         float64 `json:"sharpe_ratio"`
	SortinoRatio        float64 `json:"sortino_ratio"`
	CalmarRatio         float64 `json:"calmar_ratio"`
	Volatility          float64 `json:"volatility"`
	DownsideDeviation   float64 `json:"downside_deviation"`
	MaxDrawdown         float64 `json:"max_drawdown"`
	MaxDrawdownDuration int32   `json:"max_drawdown_duration"`
	CurrentDrawdown     float64 `json:"current_drawdown"`
	WinRate             float64 `json:"win_rate"`
	ProfitFactor        float64 `json:"profit_factor"`
	AvgWin              float64 `json:"avg_win"`
	AvgLoss             float64 `json:"avg_loss"`
	PeriodStart         int64   `json:"period_start"`
	PeriodEnd           int64   `json:"period_end"`
	DataPoints          int32   `json:"data_points"`
	Success             bool    `json:"success"`
	Error               string  `json:"error"`
}

// ReportRequest requests a signed report
type ReportRequest struct {
	UserUid            string `json:"user_uid"`
	StartDate          string `json:"start_date"`
	EndDate            string `json:"end_date"`
	Benchmark          string `json:"benchmark"`
	IncludeRiskMetrics bool   `json:"include_risk_metrics"`
	IncludeDrawdown    bool   `json:"include_drawdown"`
	ReportName         string `json:"report_name"`
	BaseCurrency       string `json:"base_currency"`
	Manager            string `json:"manager,omitempty"`
	Firm               string `json:"firm,omitempty"`
}

// ReportBenchmarkMetrics holds benchmark comparison data in the report response
type ReportBenchmarkMetrics struct {
	BenchmarkName    string  `json:"benchmark_name"`
	BenchmarkReturn  float64 `json:"benchmark_return"`
	Alpha            float64 `json:"alpha"`
	Beta             float64 `json:"beta"`
	InformationRatio float64 `json:"information_ratio"`
	TrackingError    float64 `json:"tracking_error"`
	Correlation      float64 `json:"correlation"`
}

// SignedReportResponse contains the signed report with extended analytics
type SignedReportResponse struct {
	Success            bool                    `json:"success"`
	Error              string                  `json:"error"`
	ReportId           string                  `json:"report_id"`
	UserUid            string                  `json:"user_uid"`
	ReportName         string                  `json:"report_name"`
	GeneratedAt        string                  `json:"generated_at"`
	PeriodStart        string                  `json:"period_start"`
	PeriodEnd          string                  `json:"period_end"`
	TotalReturn        float64                 `json:"total_return"`
	AnnualizedReturn   float64                 `json:"annualized_return"`
	SharpeRatio        float64                 `json:"sharpe_ratio"`
	SortinoRatio       float64                 `json:"sortino_ratio"`
	CalmarRatio        float64                 `json:"calmar_ratio"`
	MaxDrawdown        float64                 `json:"max_drawdown"`
	Volatility         float64                 `json:"volatility"`
	WinRate            float64                 `json:"win_rate"`
	ProfitFactor       float64                 `json:"profit_factor"`
	DataPoints         int                     `json:"data_points"`
	BaseCurrency       string                  `json:"base_currency"`
	Benchmark          string                  `json:"benchmark"`
	Exchanges          []string                `json:"exchanges,omitempty"`
	DailyReturns       []ReportDailyReturn     `json:"daily_returns,omitempty"`
	MonthlyReturns     []ReportMonthlyReturn   `json:"monthly_returns,omitempty"`
	RiskMetrics        *ReportRiskMetrics      `json:"risk_metrics,omitempty"`
	DrawdownData       *ReportDrawdownData     `json:"drawdown_data,omitempty"`
	BenchmarkMetrics   *ReportBenchmarkMetrics `json:"benchmark_metrics,omitempty"`
	Manager            string                  `json:"manager,omitempty"`
	Firm               string                  `json:"firm,omitempty"`
	Signature          string                  `json:"signature"`
	PublicKey          string                  `json:"public_key"`
	SignatureAlgorithm string                  `json:"signature_algorithm"`
	ReportHash         string                  `json:"report_hash"`
	EnclaveVersion     string                  `json:"enclave_version"`
	AttestationID      string                  `json:"attestation_id,omitempty"`
	EnclaveMode        string                  `json:"enclave_mode,omitempty"`
}

// ReportDailyReturn is a daily return entry in the report response
type ReportDailyReturn struct {
	Date             string  `json:"date"`
	NetReturn        float64 `json:"net_return"`
	BenchmarkReturn  float64 `json:"benchmark_return"`
	Outperformance   float64 `json:"outperformance"`
	CumulativeReturn float64 `json:"cumulative_return"`
	NAV              float64 `json:"nav"`
}

// ReportMonthlyReturn is a monthly return entry in the report response
type ReportMonthlyReturn struct {
	Date            string  `json:"date"`
	NetReturn       float64 `json:"net_return"`
	BenchmarkReturn float64 `json:"benchmark_return"`
	Outperformance  float64 `json:"outperformance"`
	AUM             float64 `json:"aum"`
}

// ReportRiskMetrics contains risk metrics in the report response
type ReportRiskMetrics struct {
	VaR95             float64 `json:"var_95"`
	VaR99             float64 `json:"var_99"`
	ExpectedShortfall float64 `json:"expected_shortfall"`
	Skewness          float64 `json:"skewness"`
	Kurtosis          float64 `json:"kurtosis"`
}

// ReportDrawdownPeriod represents a drawdown event in the report response
type ReportDrawdownPeriod struct {
	StartDate string  `json:"start_date"`
	EndDate   string  `json:"end_date"`
	Depth     float64 `json:"depth"`
	Duration  int     `json:"duration"`
	Recovered bool    `json:"recovered"`
}

// ReportDrawdownData contains drawdown analysis in the report response
type ReportDrawdownData struct {
	CurrentDrawdown     float64                 `json:"current_drawdown"`
	MaxDrawdownDuration int                     `json:"max_drawdown_duration"`
	Periods             []*ReportDrawdownPeriod `json:"periods"`
}

// VerifySignatureRequest requests signature verification
type VerifySignatureRequest struct {
	ReportHash string `json:"report_hash"`
	Signature  string `json:"signature"`
	PublicKey  string `json:"public_key"`
}

// VerifySignatureResponse contains verification result
type VerifySignatureResponse struct {
	Valid bool   `json:"valid"`
	Error string `json:"error"`
}

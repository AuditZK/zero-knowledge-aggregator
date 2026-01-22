package server

import (
	"net/http"
	"strconv"
	"time"

	"github.com/trackrecord/enclave/internal/service"
	"go.uber.org/zap"
)

var startTime = time.Now()

const version = "1.0.0-go"

type Handler struct {
	logger     *zap.Logger
	connSvc    *service.ConnectionService
	syncSvc    *service.SyncService
	metricsSvc *service.MetricsService
	reportSvc  *service.ReportService
	dbReady    bool
}

func NewHandler(
	logger *zap.Logger,
	connSvc *service.ConnectionService,
	syncSvc *service.SyncService,
	metricsSvc *service.MetricsService,
	reportSvc *service.ReportService,
) *Handler {
	return &Handler{
		logger:     logger,
		connSvc:    connSvc,
		syncSvc:    syncSvc,
		metricsSvc: metricsSvc,
		reportSvc:  reportSvc,
		dbReady:    connSvc != nil,
	}
}

// HealthCheck - GET /health
func (h *Handler) HealthCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status":         "healthy",
		"version":        version,
		"timestamp":      time.Now().Unix(),
		"uptime_seconds": int64(time.Since(startTime).Seconds()),
		"database":       h.dbReady,
	})
}

// CreateUserConnection - POST /api/v1/connection
func (h *Handler) CreateUserConnection(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		UserUID    string `json:"user_uid"`
		Exchange   string `json:"exchange"`
		Label      string `json:"label"`
		APIKey     string `json:"api_key"`
		APISecret  string `json:"api_secret"`
		Passphrase string `json:"passphrase"`
	}

	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"success": false,
			"error":   "invalid request body",
		})
		return
	}

	if req.UserUID == "" || req.Exchange == "" || req.APIKey == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"success": false,
			"error":   "user_uid, exchange, and api_key are required",
		})
		return
	}

	if h.connSvc == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"success": false,
			"error":   "database not configured",
		})
		return
	}

	err := h.connSvc.Create(r.Context(), &service.CreateConnectionRequest{
		UserUID:    req.UserUID,
		Exchange:   req.Exchange,
		Label:      req.Label,
		APIKey:     req.APIKey,
		APISecret:  req.APISecret,
		Passphrase: req.Passphrase,
	})

	if err != nil {
		h.logger.Error("create connection failed",
			zap.String("user_uid", req.UserUID),
			zap.String("exchange", req.Exchange),
			zap.Error(err),
		)
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"success": false,
			"error":   "failed to create connection",
		})
		return
	}

	h.logger.Info("connection created",
		zap.String("user_uid", req.UserUID),
		zap.String("exchange", req.Exchange),
	)

	writeJSON(w, http.StatusOK, map[string]any{
		"success":  true,
		"user_uid": req.UserUID,
	})
}

// ProcessSyncJob - POST /api/v1/sync
func (h *Handler) ProcessSyncJob(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		UserUID  string `json:"user_uid"`
		Exchange string `json:"exchange"`
	}

	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"success": false,
			"error":   "invalid request body",
		})
		return
	}

	if req.UserUID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"success": false,
			"error":   "user_uid is required",
		})
		return
	}

	if h.syncSvc == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"success": false,
			"error":   "sync service not available",
		})
		return
	}

	var results []*service.SyncResult
	var err error

	if req.Exchange != "" {
		result := h.syncSvc.SyncExchange(r.Context(), req.UserUID, req.Exchange)
		results = []*service.SyncResult{result}
	} else {
		results, err = h.syncSvc.SyncUser(r.Context(), req.UserUID)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{
				"success": false,
				"error":   err.Error(),
			})
			return
		}
	}

	anySuccess := false
	for _, r := range results {
		if r.Success {
			anySuccess = true
			break
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"success":  anySuccess,
		"user_uid": req.UserUID,
		"results":  results,
	})
}

// GetMetrics - GET /api/v1/metrics?user_uid=xxx&start=xxx&end=xxx
func (h *Handler) GetMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userUID := r.URL.Query().Get("user_uid")
	if userUID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"success": false,
			"error":   "user_uid is required",
		})
		return
	}

	if h.metricsSvc == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"success": false,
			"error":   "metrics service not available",
		})
		return
	}

	// Parse date range (milliseconds)
	start := time.Now().AddDate(-1, 0, 0) // Default: 1 year ago
	end := time.Now()

	if s := r.URL.Query().Get("start"); s != "" {
		if ms, err := strconv.ParseInt(s, 10, 64); err == nil {
			start = time.UnixMilli(ms)
		}
	}
	if e := r.URL.Query().Get("end"); e != "" {
		if ms, err := strconv.ParseInt(e, 10, 64); err == nil {
			end = time.UnixMilli(ms)
		}
	}

	metrics, err := h.metricsSvc.Calculate(r.Context(), userUID, start, end)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"success":               true,
		"sharpe_ratio":          metrics.SharpeRatio,
		"sortino_ratio":         metrics.SortinoRatio,
		"calmar_ratio":          metrics.CalmarRatio,
		"volatility":            metrics.Volatility,
		"downside_deviation":    metrics.DownsideDeviation,
		"max_drawdown":          metrics.MaxDrawdown,
		"max_drawdown_duration": metrics.MaxDrawdownDuration,
		"current_drawdown":      metrics.CurrentDrawdown,
		"win_rate":              metrics.WinRate,
		"profit_factor":         metrics.ProfitFactor,
		"avg_win":               metrics.AvgWin,
		"avg_loss":              metrics.AvgLoss,
		"total_return":          metrics.TotalReturn,
		"annualized_return":     metrics.AnnualizedReturn,
		"period_start":          metrics.PeriodStart.Unix(),
		"period_end":            metrics.PeriodEnd.Unix(),
		"data_points":           metrics.DataPoints,
	})
}

// GetSnapshots - GET /api/v1/snapshots?user_uid=xxx
func (h *Handler) GetSnapshots(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userUID := r.URL.Query().Get("user_uid")
	if userUID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"success": false,
			"error":   "user_uid is required",
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"success":   true,
		"user_uid":  userUID,
		"snapshots": []any{},
	})
}

// GenerateReport - POST /api/v1/report
func (h *Handler) GenerateReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		UserUID            string `json:"user_uid"`
		StartDate          string `json:"start_date"`
		EndDate            string `json:"end_date"`
		ReportName         string `json:"report_name"`
		Benchmark          string `json:"benchmark"`
		BaseCurrency       string `json:"base_currency"`
		IncludeRiskMetrics bool   `json:"include_risk_metrics"`
		IncludeDrawdown    bool   `json:"include_drawdown"`
	}

	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"success": false,
			"error":   "invalid request body",
		})
		return
	}

	if req.UserUID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"success": false,
			"error":   "user_uid is required",
		})
		return
	}

	if h.reportSvc == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"success": false,
			"error":   "report service not available",
		})
		return
	}

	startDate, err := time.Parse("2006-01-02", req.StartDate)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"success": false,
			"error":   "invalid start_date format (use YYYY-MM-DD)",
		})
		return
	}

	endDate, err := time.Parse("2006-01-02", req.EndDate)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"success": false,
			"error":   "invalid end_date format (use YYYY-MM-DD)",
		})
		return
	}

	report, err := h.reportSvc.GenerateReport(r.Context(), &service.GenerateReportRequest{
		UserUID:            req.UserUID,
		StartDate:          startDate,
		EndDate:            endDate,
		ReportName:         req.ReportName,
		Benchmark:          req.Benchmark,
		BaseCurrency:       req.BaseCurrency,
		IncludeRiskMetrics: req.IncludeRiskMetrics,
		IncludeDrawdown:    req.IncludeDrawdown,
	})

	if err != nil {
		h.logger.Error("generate report failed", zap.Error(err))
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"success":             true,
		"report_id":           report.ReportID,
		"user_uid":            report.UserUID,
		"report_name":         report.ReportName,
		"generated_at":        report.GeneratedAt,
		"period_start":        report.PeriodStart,
		"period_end":          report.PeriodEnd,
		"total_return":        report.TotalReturn,
		"sharpe_ratio":        report.SharpeRatio,
		"max_drawdown":        report.MaxDrawdown,
		"signature":           report.Signature,
		"public_key":          report.PublicKey,
		"signature_algorithm": report.SignatureAlgorithm,
		"report_hash":         report.ReportHash,
		"enclave_version":     report.EnclaveVersion,
	})
}

// VerifySignature - POST /api/v1/verify
func (h *Handler) VerifySignature(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ReportHash string `json:"report_hash"`
		Signature  string `json:"signature"`
		PublicKey  string `json:"public_key"`
	}

	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"valid": false,
			"error": "invalid request body",
		})
		return
	}

	if req.ReportHash == "" || req.Signature == "" || req.PublicKey == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"valid": false,
			"error": "report_hash, signature, and public_key are required",
		})
		return
	}

	if h.reportSvc == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"valid": false,
			"error": "report service not available",
		})
		return
	}

	valid, err := h.reportSvc.VerifySignature(req.ReportHash, req.Signature, req.PublicKey)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"valid": false,
			"error": err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"valid": valid,
	})
}

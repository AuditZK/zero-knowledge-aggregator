package server

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/trackrecord/enclave/internal/attestation"
	"github.com/trackrecord/enclave/internal/encryption"
	"github.com/trackrecord/enclave/internal/repository"
	"github.com/trackrecord/enclave/internal/service"
	tlspkg "github.com/trackrecord/enclave/internal/tls"
	"go.uber.org/zap"
)

var startTime = time.Now()

const version = "1.0.0-go"

type Handler struct {
	logger       *zap.Logger
	connSvc      *service.ConnectionService
	syncSvc      *service.SyncService
	metricsSvc   *service.MetricsService
	reportSvc    *service.ReportService
	snapshotRepo *repository.SnapshotRepo
	userRepo     *repository.UserRepo
	dbReady      bool

	// New services for attestation, TLS, and E2E encryption
	tlsKeygen  *tlspkg.KeyGenerator
	attestSvc  *attestation.Service
	eciesSvc   *encryption.ECIESService
}

type HandlerOptions struct {
	Logger       *zap.Logger
	ConnSvc      *service.ConnectionService
	SyncSvc      *service.SyncService
	MetricsSvc   *service.MetricsService
	ReportSvc    *service.ReportService
	SnapshotRepo *repository.SnapshotRepo
	UserRepo     *repository.UserRepo
	TLSKeygen    *tlspkg.KeyGenerator
	AttestSvc    *attestation.Service
	ECIESSvc     *encryption.ECIESService
}

func NewHandler(
	logger *zap.Logger,
	connSvc *service.ConnectionService,
	syncSvc *service.SyncService,
	metricsSvc *service.MetricsService,
	reportSvc *service.ReportService,
	snapshotRepo *repository.SnapshotRepo,
	userRepo *repository.UserRepo,
) *Handler {
	return &Handler{
		logger:       logger,
		connSvc:      connSvc,
		syncSvc:      syncSvc,
		metricsSvc:   metricsSvc,
		reportSvc:    reportSvc,
		snapshotRepo: snapshotRepo,
		userRepo:     userRepo,
		dbReady:      connSvc != nil,
	}
}

// NewHandlerWithOptions creates a handler with all optional services.
func NewHandlerWithOptions(opts HandlerOptions) *Handler {
	return &Handler{
		logger:       opts.Logger,
		connSvc:      opts.ConnSvc,
		syncSvc:      opts.SyncSvc,
		metricsSvc:   opts.MetricsSvc,
		reportSvc:    opts.ReportSvc,
		snapshotRepo: opts.SnapshotRepo,
		userRepo:     opts.UserRepo,
		dbReady:      opts.ConnSvc != nil,
		tlsKeygen:    opts.TLSKeygen,
		attestSvc:    opts.AttestSvc,
		eciesSvc:     opts.ECIESSvc,
	}
}

// GetTLSFingerprint - GET /api/v1/tls/fingerprint
func (h *Handler) GetTLSFingerprint(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if h.tlsKeygen == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"error": "TLS not configured",
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"fingerprint": h.tlsKeygen.Fingerprint(),
		"algorithm":   "SHA-256",
		"usage":       "Compare with attestation reportData to verify TLS binding",
	})
}

// GetAttestation - GET /api/v1/attestation
func (h *Handler) GetAttestation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if h.attestSvc == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"error": "attestation service not configured",
		})
		return
	}

	report, err := h.attestSvc.GetAttestation(r.Context())
	if err != nil {
		h.logger.Error("attestation failed", zap.Error(err))
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"error": "attestation failed",
		})
		return
	}

	writeJSON(w, http.StatusOK, report)
}

// ConnectCredentials - POST /api/v1/credentials/connect
// Accepts E2E encrypted credentials and creates a connection.
func (h *Handler) ConnectCredentials(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if h.eciesSvc == nil || h.connSvc == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"success": false,
			"error":   "E2E encryption or connection service not configured",
		})
		return
	}

	var req struct {
		UserUID           string `json:"user_uid"`
		Exchange          string `json:"exchange"`
		Label             string `json:"label"`
		EphemeralPubKey   string `json:"ephemeral_public_key"`
		IV                string `json:"iv"`
		Ciphertext        string `json:"ciphertext"`
	}

	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"success": false,
			"error":   "invalid request body",
		})
		return
	}

	if req.UserUID == "" || req.Exchange == "" || req.Ciphertext == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"success": false,
			"error":   "user_uid, exchange, and encrypted credentials are required",
		})
		return
	}

	// Decode hex components
	ephPubKeyBytes, err := hexDecode(req.EphemeralPubKey)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "error": "invalid ephemeral_public_key"})
		return
	}
	ivBytes, err := hexDecode(req.IV)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "error": "invalid iv"})
		return
	}
	ciphertextBytes, err := hexDecode(req.Ciphertext)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "error": "invalid ciphertext"})
		return
	}

	// Decrypt inside enclave
	plaintext, err := h.eciesSvc.Decrypt(ephPubKeyBytes, ivBytes, ciphertextBytes)
	if err != nil {
		h.logger.Error("E2E decryption failed", zap.Error(err))
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"success": false,
			"error":   "decryption failed",
		})
		return
	}

	// Parse decrypted credentials
	var creds struct {
		APIKey     string `json:"api_key"`
		APISecret  string `json:"api_secret"`
		Passphrase string `json:"passphrase"`
	}
	if err := json.Unmarshal(plaintext, &creds); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"success": false,
			"error":   "invalid credential format",
		})
		return
	}

	// Upsert user
	if h.userRepo != nil {
		if _, err := h.userRepo.GetOrCreate(r.Context(), req.UserUID); err != nil {
			h.logger.Error("user upsert failed", zap.Error(err))
		}
	}

	// Create connection
	err = h.connSvc.Create(r.Context(), &service.CreateConnectionRequest{
		UserUID:    req.UserUID,
		Exchange:   req.Exchange,
		Label:      req.Label,
		APIKey:     creds.APIKey,
		APISecret:  creds.APISecret,
		Passphrase: creds.Passphrase,
	})
	if err != nil {
		h.logger.Error("create connection from E2E failed", zap.Error(err))
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"success": false,
			"error":   "failed to create connection",
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"success":  true,
		"user_uid": req.UserUID,
	})
}

func hexDecode(s string) ([]byte, error) {
	return hex.DecodeString(s)
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

	// Upsert user first
	if h.userRepo != nil {
		if _, err := h.userRepo.GetOrCreate(r.Context(), req.UserUID); err != nil {
			h.logger.Error("user upsert failed", zap.Error(err))
			writeJSON(w, http.StatusInternalServerError, map[string]any{
				"success": false,
				"error":   "failed to create user",
			})
			return
		}
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

// GetSnapshots - GET /api/v1/snapshots?user_uid=xxx&exchange=xxx&start=xxx&end=xxx
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

	if h.snapshotRepo == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"success": false,
			"error":   "database not configured",
		})
		return
	}

	// Parse date range (milliseconds)
	start := time.Now().AddDate(-1, 0, 0)
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

	snapshots, err := h.snapshotRepo.GetByUserAndDateRange(r.Context(), userUID, start, end)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	// Filter by exchange if specified
	exchange := r.URL.Query().Get("exchange")
	var result []map[string]any
	for _, snap := range snapshots {
		if exchange != "" && snap.Exchange != exchange {
			continue
		}
		result = append(result, map[string]any{
			"user_uid":         snap.UserUID,
			"exchange":         snap.Exchange,
			"timestamp":        snap.Timestamp.UnixMilli(),
			"total_equity":     snap.TotalEquity,
			"realized_balance": snap.RealizedBalance,
			"unrealized_pnl":   snap.UnrealizedPnL,
			"deposits":         snap.Deposits,
			"withdrawals":      snap.Withdrawals,
			"breakdown":        snap.Breakdown,
		})
	}

	if result == nil {
		result = []map[string]any{}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"success":   true,
		"user_uid":  userUID,
		"snapshots": result,
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
		Manager            string `json:"manager"`
		Firm               string `json:"firm"`
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
		Manager:            req.Manager,
		Firm:               req.Firm,
	})

	if err != nil {
		h.logger.Error("generate report failed", zap.Error(err))
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, report)
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

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/trackrecord/enclave/internal/config"
	"github.com/trackrecord/enclave/internal/encryption"
	"github.com/trackrecord/enclave/internal/repository"
	"github.com/trackrecord/enclave/internal/service"
	"github.com/trackrecord/enclave/internal/signing"
	"go.uber.org/zap"
)

type Server struct {
	cfg     *config.Config
	logger  *zap.Logger
	handler *Handler
	http    *http.Server
	pool    *pgxpool.Pool
}

func New(cfg *config.Config, logger *zap.Logger, pool *pgxpool.Pool, signer *signing.ReportSigner) *Server {
	var connSvc *service.ConnectionService
	var syncSvc *service.SyncService
	var metricsSvc *service.MetricsService
	var reportSvc *service.ReportService

	if pool != nil {
		enc, err := encryption.New(cfg.EncryptionKey)
		if err != nil {
			logger.Error("encryption init failed", zap.Error(err))
		} else {
			connRepo := repository.NewConnectionRepo(pool)
			snapshotRepo := repository.NewSnapshotRepo(pool)

			connSvc = service.NewConnectionService(connRepo, enc)
			syncSvc = service.NewSyncService(connSvc, snapshotRepo, logger)
			metricsSvc = service.NewMetricsService(snapshotRepo)

			if signer != nil {
				reportSvc = service.NewReportService(metricsSvc, signer)
			}
		}
	}

	return &Server{
		cfg:     cfg,
		logger:  logger,
		handler: NewHandler(logger, connSvc, syncSvc, metricsSvc, reportSvc),
		pool:    pool,
	}
}

func (s *Server) Start(ctx context.Context) error {
	mux := http.NewServeMux()

	// Routes
	mux.HandleFunc("/health", s.handler.HealthCheck)
	mux.HandleFunc("/api/v1/connection", s.handler.CreateUserConnection)
	mux.HandleFunc("/api/v1/sync", s.handler.ProcessSyncJob)
	mux.HandleFunc("/api/v1/metrics", s.handler.GetMetrics)
	mux.HandleFunc("/api/v1/snapshots", s.handler.GetSnapshots)
	mux.HandleFunc("/api/v1/report", s.handler.GenerateReport)
	mux.HandleFunc("/api/v1/verify", s.handler.VerifySignature)

	s.http = &http.Server{
		Addr:         fmt.Sprintf(":%d", s.cfg.Port),
		Handler:      s.loggingMiddleware(mux),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s.http.Shutdown(shutdownCtx)
		if s.pool != nil {
			s.pool.Close()
		}
	}()

	s.logger.Info("server starting", zap.String("addr", s.http.Addr))
	return s.http.ListenAndServe()
}

func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		s.logger.Info("request",
			zap.String("method", r.Method),
			zap.String("path", r.URL.Path),
			zap.Duration("duration", time.Since(start)),
		)
	})
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func readJSON(r *http.Request, v any) error {
	return json.NewDecoder(r.Body).Decode(v)
}

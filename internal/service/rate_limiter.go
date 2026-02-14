package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/trackrecord/enclave/internal/repository"
	"go.uber.org/zap"
)

const (
	rateLimitCooldown = 23 * time.Hour
	cleanupRetention  = 7 * 24 * time.Hour
)

// RateLimiterService enforces 23-hour rate limits between syncs.
type RateLimiterService struct {
	repo   *repository.RateLimitRepo
	logger *zap.Logger
}

// NewRateLimiterService creates a new rate limiter service.
func NewRateLimiterService(repo *repository.RateLimitRepo, logger *zap.Logger) *RateLimiterService {
	return &RateLimiterService{
		repo:   repo,
		logger: logger,
	}
}

// CheckRateLimit returns an error if the sync is rate-limited.
func (s *RateLimiterService) CheckRateLimit(ctx context.Context, userUID, exchange, label string) error {
	log, err := s.repo.GetByKey(ctx, userUID, exchange, label)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil // First sync, allowed
		}
		return fmt.Errorf("check rate limit: %w", err)
	}

	elapsed := time.Since(log.LastSyncTime)
	if elapsed < rateLimitCooldown {
		nextAllowed := log.LastSyncTime.Add(rateLimitCooldown)
		return fmt.Errorf("rate limited: next sync allowed at %s (in %s)",
			nextAllowed.Format(time.RFC3339),
			(rateLimitCooldown - elapsed).Round(time.Minute))
	}

	return nil
}

// RecordSync records a successful sync for rate limiting.
func (s *RateLimiterService) RecordSync(ctx context.Context, userUID, exchange, label string) error {
	return s.repo.RecordSync(ctx, userUID, exchange, label)
}

// CleanupOldLogs removes rate limit logs older than 7 days.
func (s *RateLimiterService) CleanupOldLogs(ctx context.Context) error {
	deleted, err := s.repo.CleanupOldLogs(ctx, cleanupRetention)
	if err != nil {
		return fmt.Errorf("cleanup rate limit logs: %w", err)
	}
	if deleted > 0 {
		s.logger.Info("cleaned up rate limit logs", zap.Int64("deleted", deleted))
	}
	return nil
}

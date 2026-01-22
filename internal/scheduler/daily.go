package scheduler

import (
	"context"
	"sync"
	"time"

	"github.com/trackrecord/enclave/internal/repository"
	"github.com/trackrecord/enclave/internal/service"
	"go.uber.org/zap"
)

// DailyScheduler runs sync jobs at 00:00 UTC daily
type DailyScheduler struct {
	syncSvc  *service.SyncService
	userRepo *repository.UserRepo
	logger   *zap.Logger

	stopCh chan struct{}
	wg     sync.WaitGroup
}

// NewDailyScheduler creates a new daily scheduler
func NewDailyScheduler(
	syncSvc *service.SyncService,
	userRepo *repository.UserRepo,
	logger *zap.Logger,
) *DailyScheduler {
	return &DailyScheduler{
		syncSvc:  syncSvc,
		userRepo: userRepo,
		logger:   logger,
		stopCh:   make(chan struct{}),
	}
}

// Start begins the scheduler
func (s *DailyScheduler) Start() {
	s.wg.Add(1)
	go s.run()
	s.logger.Info("daily scheduler started", zap.String("schedule", "00:00 UTC"))
}

// Stop gracefully stops the scheduler
func (s *DailyScheduler) Stop() {
	close(s.stopCh)
	s.wg.Wait()
	s.logger.Info("daily scheduler stopped")
}

func (s *DailyScheduler) run() {
	defer s.wg.Done()

	// Calculate time until next 00:00 UTC
	timer := time.NewTimer(s.timeUntilMidnightUTC())

	for {
		select {
		case <-s.stopCh:
			timer.Stop()
			return

		case <-timer.C:
			s.executeDailySync()
			// Reset timer for next day
			timer.Reset(s.timeUntilMidnightUTC())
		}
	}
}

func (s *DailyScheduler) timeUntilMidnightUTC() time.Duration {
	now := time.Now().UTC()
	nextMidnight := time.Date(now.Year(), now.Month(), now.Day()+1, 0, 0, 0, 0, time.UTC)
	return nextMidnight.Sub(now)
}

func (s *DailyScheduler) executeDailySync() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	s.logger.Info("daily sync started")
	start := time.Now()

	// Get all users with active connections
	users, err := s.userRepo.GetAllWithConnections(ctx)
	if err != nil {
		s.logger.Error("failed to get users for daily sync", zap.Error(err))
		return
	}

	if len(users) == 0 {
		s.logger.Info("no users to sync")
		return
	}

	s.logger.Info("syncing users", zap.Int("count", len(users)))

	var (
		successCount int
		failCount    int
		mu           sync.Mutex
		wg           sync.WaitGroup
	)

	// Sync users concurrently with semaphore (max 10 concurrent)
	sem := make(chan struct{}, 10)

	for _, user := range users {
		wg.Add(1)
		go func(uid string) {
			defer wg.Done()

			sem <- struct{}{}        // Acquire
			defer func() { <-sem }() // Release

			results, err := s.syncSvc.SyncUser(ctx, uid)

			mu.Lock()
			defer mu.Unlock()

			if err != nil {
				failCount++
				s.logger.Error("user sync failed",
					zap.String("user_uid", uid),
					zap.Error(err),
				)
				return
			}

			// Count successes/failures
			for _, r := range results {
				if r.Success {
					successCount++
				} else {
					failCount++
				}
			}
		}(user.UID)
	}

	wg.Wait()

	s.logger.Info("daily sync completed",
		zap.Int("users", len(users)),
		zap.Int("success", successCount),
		zap.Int("failed", failCount),
		zap.Duration("duration", time.Since(start)),
	)
}

// RunNow executes sync immediately (for testing/manual trigger)
func (s *DailyScheduler) RunNow() {
	s.executeDailySync()
}

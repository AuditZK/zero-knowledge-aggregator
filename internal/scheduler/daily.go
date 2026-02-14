package scheduler

import (
	"context"
	"sync"
	"time"

	"github.com/trackrecord/enclave/internal/repository"
	"github.com/trackrecord/enclave/internal/service"
	"go.uber.org/zap"
)

// SyncScheduler ticks every hour and syncs users based on their per-user sync_interval.
// - "hourly" users are synced every tick
// - "daily" users are synced only at the 00:00 UTC tick
type SyncScheduler struct {
	syncSvc  *service.SyncService
	userRepo *repository.UserRepo
	logger   *zap.Logger

	stopCh chan struct{}
	wg     sync.WaitGroup
}

// NewSyncScheduler creates a scheduler that ticks every hour.
func NewSyncScheduler(
	syncSvc *service.SyncService,
	userRepo *repository.UserRepo,
	logger *zap.Logger,
) *SyncScheduler {
	return &SyncScheduler{
		syncSvc:  syncSvc,
		userRepo: userRepo,
		logger:   logger,
		stopCh:   make(chan struct{}),
	}
}

// Start begins the scheduler
func (s *SyncScheduler) Start() {
	s.wg.Add(1)
	go s.run()

	next := s.timeUntilNextHour()
	s.logger.Info("sync scheduler started",
		zap.String("tick", "every hour at :00"),
		zap.String("policy", "per-user sync_interval (hourly/daily)"),
		zap.Duration("next_tick_in", next),
	)
}

// Stop gracefully stops the scheduler
func (s *SyncScheduler) Stop() {
	close(s.stopCh)
	s.wg.Wait()
	s.logger.Info("sync scheduler stopped")
}

func (s *SyncScheduler) run() {
	defer s.wg.Done()

	timer := time.NewTimer(s.timeUntilNextHour())

	for {
		select {
		case <-s.stopCh:
			timer.Stop()
			return

		case <-timer.C:
			s.executeSync()
			timer.Reset(s.timeUntilNextHour())
		}
	}
}

func (s *SyncScheduler) timeUntilNextHour() time.Duration {
	now := time.Now().UTC()
	nextHour := now.Truncate(time.Hour).Add(time.Hour)
	return nextHour.Sub(now)
}

func (s *SyncScheduler) executeSync() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	now := time.Now().UTC()
	isMidnight := now.Hour() == 0

	s.logger.Info("sync tick", zap.Bool("is_midnight", isMidnight))
	start := time.Now()

	// Get all users with active connections (includes sync_interval)
	users, err := s.userRepo.GetAllWithConnections(ctx)
	if err != nil {
		s.logger.Error("failed to get users for sync", zap.Error(err))
		return
	}

	if len(users) == 0 {
		s.logger.Info("no users to sync")
		return
	}

	// Filter: hourly users always, daily users only at midnight
	var toSync []*repository.User
	for _, u := range users {
		if u.SyncInterval == "daily" {
			if isMidnight {
				toSync = append(toSync, u)
			}
		} else {
			// "hourly" (default)
			toSync = append(toSync, u)
		}
	}

	if len(toSync) == 0 {
		s.logger.Info("no users due for sync this tick",
			zap.Int("total_users", len(users)),
		)
		return
	}

	s.logger.Info("syncing users",
		zap.Int("to_sync", len(toSync)),
		zap.Int("total_users", len(users)),
	)

	var (
		successCount int
		failCount    int
		mu           sync.Mutex
		wg           sync.WaitGroup
	)

	sem := make(chan struct{}, 10)

	for _, user := range toSync {
		wg.Add(1)
		go func(u *repository.User) {
			defer wg.Done()

			sem <- struct{}{}
			defer func() { <-sem }()

			results, err := s.syncSvc.SyncUserScheduled(ctx, u.UID)

			mu.Lock()
			defer mu.Unlock()

			if err != nil {
				failCount++
				s.logger.Error("user sync failed",
					zap.String("user_uid", u.UID),
					zap.String("sync_interval", u.SyncInterval),
					zap.Error(err),
				)
				return
			}

			for _, r := range results {
				if r.Success {
					successCount++
				} else {
					failCount++
				}
			}
		}(user)
	}

	wg.Wait()

	s.logger.Info("sync tick completed",
		zap.Int("synced", len(toSync)),
		zap.Int("success", successCount),
		zap.Int("failed", failCount),
		zap.Duration("duration", time.Since(start)),
	)
}

// RunNow executes sync immediately for all eligible users
func (s *SyncScheduler) RunNow() {
	s.executeSync()
}

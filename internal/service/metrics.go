package service

import (
	"context"
	"errors"
	"math"
	"sort"
	"time"

	"github.com/trackrecord/enclave/internal/repository"
)

// PerformanceMetrics holds calculated performance metrics
type PerformanceMetrics struct {
	// Risk-adjusted returns
	SharpeRatio  float64 `json:"sharpe_ratio"`
	SortinoRatio float64 `json:"sortino_ratio"`
	CalmarRatio  float64 `json:"calmar_ratio"`

	// Volatility
	Volatility        float64 `json:"volatility"`         // Annualized
	DownsideDeviation float64 `json:"downside_deviation"` // Annualized

	// Drawdown
	MaxDrawdown         float64 `json:"max_drawdown"`          // Percentage
	MaxDrawdownDuration int     `json:"max_drawdown_duration"` // Days
	CurrentDrawdown     float64 `json:"current_drawdown"`

	// Win/Loss
	WinRate      float64 `json:"win_rate"`      // Percentage of positive days
	ProfitFactor float64 `json:"profit_factor"` // Gross profit / gross loss
	AvgWin       float64 `json:"avg_win"`
	AvgLoss      float64 `json:"avg_loss"`

	// Period info
	TotalReturn      float64   `json:"total_return"`
	AnnualizedReturn float64   `json:"annualized_return"`
	PeriodStart      time.Time `json:"period_start"`
	PeriodEnd        time.Time `json:"period_end"`
	DataPoints       int       `json:"data_points"`
}

// MetricsService calculates performance metrics from snapshots
type MetricsService struct {
	snapshotRepo *repository.SnapshotRepo
}

// NewMetricsService creates a new metrics service
func NewMetricsService(snapshotRepo *repository.SnapshotRepo) *MetricsService {
	return &MetricsService{snapshotRepo: snapshotRepo}
}

// Calculate computes performance metrics for a user within a date range
func (s *MetricsService) Calculate(ctx context.Context, userUID string, start, end time.Time) (*PerformanceMetrics, error) {
	snapshots, err := s.snapshotRepo.GetByUserAndDateRange(ctx, userUID, start, end)
	if err != nil {
		return nil, err
	}

	if len(snapshots) < 2 {
		return nil, errors.New("insufficient data: need at least 2 snapshots")
	}

	// Sort by timestamp
	sort.Slice(snapshots, func(i, j int) bool {
		return snapshots[i].Timestamp.Before(snapshots[j].Timestamp)
	})

	// Calculate daily returns
	returns := s.calculateDailyReturns(snapshots)
	if len(returns) == 0 {
		return nil, errors.New("no valid returns calculated")
	}

	// Core statistics
	avgReturn := mean(returns)
	stdDev := stddev(returns)
	downsideDev := s.downsideDeviation(returns, 0)

	// Annualized metrics (252 trading days)
	annualizedReturn := avgReturn * 252
	annualizedVol := stdDev * math.Sqrt(252)
	annualizedDownside := downsideDev * math.Sqrt(252)

	// Drawdown analysis
	maxDD, maxDDDuration, currentDD := s.analyzeDrawdown(snapshots)

	// Win/Loss analysis
	winRate, profitFactor, avgWin, avgLoss := s.analyzeWinLoss(returns)

	// Total return
	firstEquity := snapshots[0].TotalEquity
	lastEquity := snapshots[len(snapshots)-1].TotalEquity
	totalReturn := (lastEquity - firstEquity) / firstEquity

	// Risk-adjusted ratios (risk-free rate = 0)
	sharpe := 0.0
	if annualizedVol > 0 {
		sharpe = annualizedReturn / annualizedVol
	}

	sortino := 0.0
	if annualizedDownside > 0 {
		sortino = annualizedReturn / annualizedDownside
	}

	calmar := 0.0
	if maxDD > 0 {
		calmar = annualizedReturn / maxDD
	}

	return &PerformanceMetrics{
		SharpeRatio:         sharpe,
		SortinoRatio:        sortino,
		CalmarRatio:         calmar,
		Volatility:          annualizedVol,
		DownsideDeviation:   annualizedDownside,
		MaxDrawdown:         maxDD,
		MaxDrawdownDuration: int(maxDDDuration),
		CurrentDrawdown:     currentDD,
		WinRate:             winRate,
		ProfitFactor:        profitFactor,
		AvgWin:              avgWin,
		AvgLoss:             avgLoss,
		TotalReturn:         totalReturn,
		AnnualizedReturn:    annualizedReturn,
		PeriodStart:         snapshots[0].Timestamp,
		PeriodEnd:           snapshots[len(snapshots)-1].Timestamp,
		DataPoints:          len(snapshots),
	}, nil
}

func (s *MetricsService) calculateDailyReturns(snapshots []*repository.Snapshot) []float64 {
	returns := make([]float64, 0, len(snapshots)-1)

	for i := 1; i < len(snapshots); i++ {
		prev := snapshots[i-1].TotalEquity
		curr := snapshots[i].TotalEquity

		// Adjust for deposits/withdrawals
		deposits := snapshots[i].Deposits
		withdrawals := snapshots[i].Withdrawals
		adjustedPrev := prev + deposits - withdrawals

		if adjustedPrev > 0 {
			ret := (curr - adjustedPrev) / adjustedPrev
			returns = append(returns, ret)
		}
	}

	return returns
}

func (s *MetricsService) downsideDeviation(returns []float64, target float64) float64 {
	var sumSquares float64
	var count int

	for _, r := range returns {
		if r < target {
			diff := r - target
			sumSquares += diff * diff
			count++
		}
	}

	if count == 0 {
		return 0
	}

	return math.Sqrt(sumSquares / float64(count))
}

func (s *MetricsService) analyzeDrawdown(snapshots []*repository.Snapshot) (maxDD, maxDDDuration float64, currentDD float64) {
	if len(snapshots) == 0 {
		return 0, 0, 0
	}

	peak := snapshots[0].TotalEquity
	peakIdx := 0
	maxDDDays := 0

	for i, snap := range snapshots {
		if snap.TotalEquity > peak {
			peak = snap.TotalEquity
			peakIdx = i
		}

		dd := (peak - snap.TotalEquity) / peak
		if dd > maxDD {
			maxDD = dd
			maxDDDays = i - peakIdx
		}
	}

	// Current drawdown
	lastEquity := snapshots[len(snapshots)-1].TotalEquity
	currentDD = (peak - lastEquity) / peak
	if currentDD < 0 {
		currentDD = 0
	}

	return maxDD, float64(maxDDDays), currentDD
}

func (s *MetricsService) analyzeWinLoss(returns []float64) (winRate, profitFactor, avgWin, avgLoss float64) {
	var wins, losses int
	var grossWin, grossLoss float64
	var totalWin, totalLoss float64

	for _, r := range returns {
		if r > 0 {
			wins++
			grossWin += r
			totalWin += r
		} else if r < 0 {
			losses++
			grossLoss += math.Abs(r)
			totalLoss += math.Abs(r)
		}
	}

	total := wins + losses
	if total > 0 {
		winRate = float64(wins) / float64(total)
	}

	if grossLoss > 0 {
		profitFactor = grossWin / grossLoss
	}

	if wins > 0 {
		avgWin = totalWin / float64(wins)
	}

	if losses > 0 {
		avgLoss = totalLoss / float64(losses)
	}

	return
}

// Helper functions
func mean(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	var sum float64
	for _, v := range values {
		sum += v
	}
	return sum / float64(len(values))
}

func stddev(values []float64) float64 {
	if len(values) < 2 {
		return 0
	}
	avg := mean(values)
	var sumSquares float64
	for _, v := range values {
		diff := v - avg
		sumSquares += diff * diff
	}
	return math.Sqrt(sumSquares / float64(len(values)-1))
}

package grpc

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/trackrecord/enclave/internal/repository"
	"github.com/trackrecord/enclave/internal/service"
	"github.com/trackrecord/enclave/internal/validation"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"
)

var startTime = time.Now()

const version = "1.0.0-go"

// Server implements the gRPC EnclaveService
type Server struct {
	logger       *zap.Logger
	connSvc      *service.ConnectionService
	syncSvc      *service.SyncService
	metricsSvc   *service.MetricsService
	reportSvc    *service.ReportService
	snapshotRepo *repository.SnapshotRepo
	userRepo     *repository.UserRepo
	grpcServer   *grpc.Server
}

// NewServer creates a new gRPC server
func NewServer(
	logger *zap.Logger,
	connSvc *service.ConnectionService,
	syncSvc *service.SyncService,
	metricsSvc *service.MetricsService,
	reportSvc *service.ReportService,
	snapshotRepo *repository.SnapshotRepo,
	userRepo *repository.UserRepo,
) *Server {
	return &Server{
		logger:       logger,
		connSvc:      connSvc,
		syncSvc:      syncSvc,
		metricsSvc:   metricsSvc,
		reportSvc:    reportSvc,
		snapshotRepo: snapshotRepo,
		userRepo:     userRepo,
	}
}

// Start starts the gRPC server
func (s *Server) Start(port int) error {
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}

	s.grpcServer = grpc.NewServer(
		grpc.UnaryInterceptor(s.loggingInterceptor),
	)

	// Register service with manual service descriptor
	s.grpcServer.RegisterService(&EnclaveService_ServiceDesc, s)
	reflection.Register(s.grpcServer)

	s.logger.Info("gRPC server starting", zap.Int("port", port))
	return s.grpcServer.Serve(lis)
}

// Stop gracefully stops the server
func (s *Server) Stop() {
	if s.grpcServer != nil {
		s.grpcServer.GracefulStop()
	}
}

func (s *Server) loggingInterceptor(
	ctx context.Context,
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (interface{}, error) {
	start := time.Now()
	resp, err := handler(ctx, req)
	s.logger.Info("grpc request",
		zap.String("method", info.FullMethod),
		zap.Duration("duration", time.Since(start)),
		zap.Error(err),
	)
	return resp, err
}

// HealthCheck implements EnclaveService
func (s *Server) HealthCheck(ctx context.Context, req *HealthCheckRequest) (*HealthCheckResponse, error) {
	uptime := time.Since(startTime).Seconds()
	return &HealthCheckResponse{
		Status:        "healthy",
		Version:       version,
		Timestamp:     time.Now().Unix(),
		UptimeSeconds: int64(uptime),
		Database:      s.connSvc != nil,
		Enclave:       true,
		Uptime:        uptime,
	}, nil
}

// CreateUserConnection implements EnclaveService
func (s *Server) CreateUserConnection(ctx context.Context, req *CreateUserConnectionRequest) (*CreateUserConnectionResponse, error) {
	if s.connSvc == nil {
		return &CreateUserConnectionResponse{
			Success: false,
			Error:   "database not configured",
		}, nil
	}

	if err := validation.ValidateCreateConnection(&validation.CreateConnectionRequest{
		UserUID:   req.UserUid,
		Exchange:  req.Exchange,
		Label:     req.Label,
		APIKey:    req.ApiKey,
		APISecret: req.ApiSecret,
	}); err != nil {
		return &CreateUserConnectionResponse{
			Success: false,
			Error:   err.Error(),
		}, nil
	}

	// Upsert user first
	if s.userRepo != nil {
		if _, err := s.userRepo.GetOrCreate(ctx, req.UserUid); err != nil {
			s.logger.Error("user upsert failed", zap.Error(err))
			return &CreateUserConnectionResponse{
				Success: false,
				Error:   "failed to create user",
			}, nil
		}
	}

	err := s.connSvc.Create(ctx, &service.CreateConnectionRequest{
		UserUID:    req.UserUid,
		Exchange:   req.Exchange,
		Label:      req.Label,
		APIKey:     req.ApiKey,
		APISecret:  req.ApiSecret,
		Passphrase: req.Passphrase,
	})

	if err != nil {
		s.logger.Error("create connection failed", zap.Error(err))
		return &CreateUserConnectionResponse{
			Success: false,
			Error:   "failed to create connection",
		}, nil
	}

	return &CreateUserConnectionResponse{
		Success: true,
		UserUid: req.UserUid,
	}, nil
}

// ProcessSyncJob implements EnclaveService
func (s *Server) ProcessSyncJob(ctx context.Context, req *SyncJobRequest) (*SyncJobResponse, error) {
	if s.syncSvc == nil {
		return &SyncJobResponse{
			Success: false,
			Error:   "sync service not available",
		}, nil
	}

	if err := validation.ValidateSyncRequest(&validation.SyncJobRequest{
		UserUID:  req.UserUid,
		Exchange: req.Exchange,
	}); err != nil {
		return &SyncJobResponse{
			Success: false,
			Error:   err.Error(),
		}, nil
	}

	var result *service.SyncResult
	if req.Exchange != "" {
		result = s.syncSvc.SyncExchange(ctx, req.UserUid, req.Exchange)
	} else {
		results, err := s.syncSvc.SyncUser(ctx, req.UserUid)
		if err != nil {
			return &SyncJobResponse{
				Success: false,
				UserUid: req.UserUid,
				Error:   err.Error(),
			}, nil
		}
		if len(results) > 0 {
			result = results[0]
		}
	}

	if result == nil {
		return &SyncJobResponse{
			Success: false,
			UserUid: req.UserUid,
			Error:   "no results",
		}, nil
	}

	return &SyncJobResponse{
		Success:            result.Success,
		UserUid:            result.UserUID,
		Exchange:           result.Exchange,
		Synced:             int32(result.TradeCount),
		SnapshotsGenerated: 1,
		LatestSnapshot: &Snapshot{
			Equity:    result.SnapshotEquity,
			Timestamp: result.SnapshotTimestamp.Unix(),
		},
		Error: result.Error,
	}, nil
}

// GetPerformanceMetrics implements EnclaveService
func (s *Server) GetPerformanceMetrics(ctx context.Context, req *PerformanceMetricsRequest) (*PerformanceMetricsResponse, error) {
	if s.metricsSvc == nil {
		return &PerformanceMetricsResponse{
			Success: false,
			Error:   "metrics service not available",
		}, nil
	}

	if err := validation.ValidateUserUID(req.UserUid); err != nil {
		return &PerformanceMetricsResponse{Success: false, Error: err.Error()}, nil
	}

	start := time.UnixMilli(req.StartDate)
	end := time.UnixMilli(req.EndDate)

	if req.StartDate == 0 {
		start = time.Now().AddDate(-1, 0, 0)
	}
	if req.EndDate == 0 {
		end = time.Now()
	}

	metrics, err := s.metricsSvc.Calculate(ctx, req.UserUid, start, end)
	if err != nil {
		return &PerformanceMetricsResponse{
			Success: false,
			Error:   err.Error(),
		}, nil
	}

	return &PerformanceMetricsResponse{
		SharpeRatio:         metrics.SharpeRatio,
		SortinoRatio:        metrics.SortinoRatio,
		CalmarRatio:         metrics.CalmarRatio,
		Volatility:          metrics.Volatility,
		DownsideDeviation:   metrics.DownsideDeviation,
		MaxDrawdown:         metrics.MaxDrawdown,
		MaxDrawdownDuration: int32(metrics.MaxDrawdownDuration),
		CurrentDrawdown:     metrics.CurrentDrawdown,
		WinRate:             metrics.WinRate,
		ProfitFactor:        metrics.ProfitFactor,
		AvgWin:              metrics.AvgWin,
		AvgLoss:             metrics.AvgLoss,
		PeriodStart:         metrics.PeriodStart.Unix(),
		PeriodEnd:           metrics.PeriodEnd.Unix(),
		DataPoints:          int32(metrics.DataPoints),
		Success:             true,
	}, nil
}

// GetSnapshotTimeSeries implements EnclaveService
func (s *Server) GetSnapshotTimeSeries(ctx context.Context, req *SnapshotTimeSeriesRequest) (*SnapshotTimeSeriesResponse, error) {
	if s.snapshotRepo == nil {
		return nil, status.Error(codes.Unavailable, "database not configured")
	}

	if err := validation.ValidateUserUID(req.UserUid); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	start := time.UnixMilli(req.StartDate)
	end := time.UnixMilli(req.EndDate)

	if req.StartDate == 0 {
		start = time.Now().AddDate(-1, 0, 0)
	}
	if req.EndDate == 0 {
		end = time.Now()
	}

	snapshots, err := s.snapshotRepo.GetByUserAndDateRange(ctx, req.UserUid, start, end)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	resp := &SnapshotTimeSeriesResponse{
		Snapshots: make([]*DailySnapshot, 0, len(snapshots)),
	}

	for _, snap := range snapshots {
		resp.Snapshots = append(resp.Snapshots, &DailySnapshot{
			UserUid:         snap.UserUID,
			Exchange:        snap.Exchange,
			Timestamp:       snap.Timestamp.UnixMilli(),
			TotalEquity:     snap.TotalEquity,
			RealizedBalance: snap.RealizedBalance,
			UnrealizedPnl:   snap.UnrealizedPnL,
			Deposits:        snap.Deposits,
			Withdrawals:     snap.Withdrawals,
		})
	}

	return resp, nil
}

// GetAggregatedMetrics implements EnclaveService
// Aggregates metrics across all exchange connections for the user
func (s *Server) GetAggregatedMetrics(ctx context.Context, req *AggregatedMetricsRequest) (*AggregatedMetricsResponse, error) {
	if s.snapshotRepo == nil {
		return nil, status.Error(codes.Unavailable, "database not configured")
	}

	if err := validation.ValidateUserUID(req.UserUid); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if req.Exchange != "" {
		if err := validation.ValidateExchange(req.Exchange); err != nil {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
	}

	// Get all active connections for the user
	if s.connSvc == nil {
		// Fallback to single snapshot
		snapshot, err := s.snapshotRepo.GetLatestByUser(ctx, req.UserUid)
		if err != nil {
			return &AggregatedMetricsResponse{}, nil
		}
		return &AggregatedMetricsResponse{
			TotalBalance:       snapshot.RealizedBalance,
			TotalEquity:        snapshot.TotalEquity,
			TotalUnrealizedPnl: snapshot.UnrealizedPnL,
			TotalFees:          snapshot.TotalFees,
			TotalTrades:        int32(snapshot.TotalTrades),
			LastSync:           snapshot.Timestamp.Unix(),
		}, nil
	}

	connections, err := s.connSvc.GetActiveConnections(ctx, req.UserUid)
	if err != nil || len(connections) == 0 {
		return &AggregatedMetricsResponse{}, nil
	}

	resp := &AggregatedMetricsResponse{}
	var lastSync time.Time

	for _, conn := range connections {
		// Filter by exchange if specified
		if req.Exchange != "" && conn.Exchange != req.Exchange {
			continue
		}

		snapshot, err := s.snapshotRepo.GetByUserExchangeAndDate(ctx, req.UserUid, conn.Exchange, time.Time{})
		if err != nil {
			// Try latest by user for this exchange
			latestSnapshots, err := s.snapshotRepo.GetByUserAndDateRange(ctx, req.UserUid, time.Now().AddDate(-1, 0, 0), time.Now())
			if err != nil {
				continue
			}
			// Find latest for this exchange
			for i := len(latestSnapshots) - 1; i >= 0; i-- {
				if latestSnapshots[i].Exchange == conn.Exchange {
					snapshot = latestSnapshots[i]
					break
				}
			}
			if snapshot == nil {
				continue
			}
		}

		resp.TotalBalance += snapshot.RealizedBalance
		resp.TotalEquity += snapshot.TotalEquity
		resp.TotalUnrealizedPnl += snapshot.UnrealizedPnL
		resp.TotalFees += snapshot.TotalFees
		resp.TotalTrades += int32(snapshot.TotalTrades)

		if snapshot.Timestamp.After(lastSync) {
			lastSync = snapshot.Timestamp
		}
	}

	if !lastSync.IsZero() {
		resp.LastSync = lastSync.Unix()
	}

	return resp, nil
}

// GenerateSignedReport implements EnclaveService
func (s *Server) GenerateSignedReport(ctx context.Context, req *ReportRequest) (*SignedReportResponse, error) {
	if s.reportSvc == nil {
		return &SignedReportResponse{
			Success: false,
			Error:   "report service not available",
		}, nil
	}

	if err := validation.ValidateReportRequest(&validation.ReportRequest{
		UserUID:   req.UserUid,
		StartDate: req.StartDate,
		EndDate:   req.EndDate,
		Benchmark: req.Benchmark,
	}); err != nil {
		return &SignedReportResponse{Success: false, Error: err.Error()}, nil
	}

	startDate, err := time.Parse("2006-01-02", req.StartDate)
	if err != nil {
		return &SignedReportResponse{
			Success: false,
			Error:   "invalid start_date format (use YYYY-MM-DD)",
		}, nil
	}

	endDate, err := time.Parse("2006-01-02", req.EndDate)
	if err != nil {
		return &SignedReportResponse{
			Success: false,
			Error:   "invalid end_date format (use YYYY-MM-DD)",
		}, nil
	}

	report, err := s.reportSvc.GenerateReport(ctx, &service.GenerateReportRequest{
		UserUID:            req.UserUid,
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
		s.logger.Error("generate report failed", zap.Error(err))
		return &SignedReportResponse{
			Success: false,
			Error:   err.Error(),
		}, nil
	}

	resp := &SignedReportResponse{
		Success:            true,
		ReportId:           report.ReportID,
		UserUid:            report.UserUID,
		ReportName:         report.ReportName,
		GeneratedAt:        report.GeneratedAt,
		PeriodStart:        report.PeriodStart,
		PeriodEnd:          report.PeriodEnd,
		TotalReturn:        report.TotalReturn,
		AnnualizedReturn:   report.AnnualizedReturn,
		SharpeRatio:        report.SharpeRatio,
		SortinoRatio:       report.SortinoRatio,
		CalmarRatio:        report.CalmarRatio,
		MaxDrawdown:        report.MaxDrawdown,
		Volatility:         report.Volatility,
		WinRate:            report.WinRate,
		ProfitFactor:       report.ProfitFactor,
		DataPoints:         report.DataPoints,
		BaseCurrency:       report.BaseCurrency,
		Benchmark:          report.Benchmark,
		Exchanges:          report.Exchanges,
		Signature:          report.Signature,
		PublicKey:          report.PublicKey,
		SignatureAlgorithm: report.SignatureAlgorithm,
		ReportHash:         report.ReportHash,
		EnclaveVersion:     report.EnclaveVersion,
	}

	// Map daily returns
	if len(report.DailyReturns) > 0 {
		resp.DailyReturns = make([]ReportDailyReturn, len(report.DailyReturns))
		for i, dr := range report.DailyReturns {
			resp.DailyReturns[i] = ReportDailyReturn{
				Date:             dr.Date,
				NetReturn:        dr.NetReturn,
				BenchmarkReturn:  dr.BenchmarkReturn,
				Outperformance:   dr.Outperformance,
				CumulativeReturn: dr.CumulativeReturn,
				NAV:              dr.NAV,
			}
		}
	}

	// Map monthly returns
	if len(report.MonthlyReturns) > 0 {
		resp.MonthlyReturns = make([]ReportMonthlyReturn, len(report.MonthlyReturns))
		for i, mr := range report.MonthlyReturns {
			resp.MonthlyReturns[i] = ReportMonthlyReturn{
				Date:            mr.Date,
				NetReturn:       mr.NetReturn,
				BenchmarkReturn: mr.BenchmarkReturn,
				Outperformance:  mr.Outperformance,
				AUM:             mr.AUM,
			}
		}
	}

	// Map risk metrics
	if report.RiskMetrics != nil {
		resp.RiskMetrics = &ReportRiskMetrics{
			VaR95:             report.RiskMetrics.VaR95,
			VaR99:             report.RiskMetrics.VaR99,
			ExpectedShortfall: report.RiskMetrics.ExpectedShortfall,
			Skewness:          report.RiskMetrics.Skewness,
			Kurtosis:          report.RiskMetrics.Kurtosis,
		}
	}

	// Map drawdown data
	if report.DrawdownData != nil {
		resp.DrawdownData = &ReportDrawdownData{
			CurrentDrawdown:     report.DrawdownData.CurrentDrawdown,
			MaxDrawdownDuration: report.DrawdownData.MaxDrawdownDuration,
		}
		for _, p := range report.DrawdownData.Periods {
			resp.DrawdownData.Periods = append(resp.DrawdownData.Periods, &ReportDrawdownPeriod{
				StartDate: p.StartDate,
				EndDate:   p.EndDate,
				Depth:     p.Depth,
				Duration:  p.Duration,
				Recovered: p.Recovered,
			})
		}
	}

	// Map benchmark metrics
	if report.BenchmarkMetrics != nil {
		resp.BenchmarkMetrics = &ReportBenchmarkMetrics{
			BenchmarkName:    report.BenchmarkMetrics.BenchmarkName,
			BenchmarkReturn:  report.BenchmarkMetrics.BenchmarkReturn,
			Alpha:            report.BenchmarkMetrics.Alpha,
			Beta:             report.BenchmarkMetrics.Beta,
			InformationRatio: report.BenchmarkMetrics.InformationRatio,
			TrackingError:    report.BenchmarkMetrics.TrackingError,
			Correlation:      report.BenchmarkMetrics.Correlation,
		}
	}

	// Display params (not signed)
	resp.Manager = report.Manager
	resp.Firm = report.Firm

	return resp, nil
}

// VerifyReportSignature implements EnclaveService
func (s *Server) VerifyReportSignature(ctx context.Context, req *VerifySignatureRequest) (*VerifySignatureResponse, error) {
	if s.reportSvc == nil {
		return &VerifySignatureResponse{
			Valid: false,
			Error: "report service not available",
		}, nil
	}

	if req.ReportHash == "" || req.Signature == "" || req.PublicKey == "" {
		return &VerifySignatureResponse{
			Valid: false,
			Error: "report_hash, signature, and public_key are required",
		}, nil
	}

	valid, err := s.reportSvc.VerifySignature(req.ReportHash, req.Signature, req.PublicKey)
	if err != nil {
		return &VerifySignatureResponse{
			Valid: false,
			Error: err.Error(),
		}, nil
	}

	return &VerifySignatureResponse{
		Valid: valid,
	}, nil
}

// Service descriptor for manual gRPC registration
var EnclaveService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "enclave.EnclaveService",
	HandlerType: (*EnclaveServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "HealthCheck",
			Handler:    _EnclaveService_HealthCheck_Handler,
		},
		{
			MethodName: "CreateUserConnection",
			Handler:    _EnclaveService_CreateUserConnection_Handler,
		},
		{
			MethodName: "ProcessSyncJob",
			Handler:    _EnclaveService_ProcessSyncJob_Handler,
		},
		{
			MethodName: "GetPerformanceMetrics",
			Handler:    _EnclaveService_GetPerformanceMetrics_Handler,
		},
		{
			MethodName: "GetSnapshotTimeSeries",
			Handler:    _EnclaveService_GetSnapshotTimeSeries_Handler,
		},
		{
			MethodName: "GetAggregatedMetrics",
			Handler:    _EnclaveService_GetAggregatedMetrics_Handler,
		},
		{
			MethodName: "GenerateSignedReport",
			Handler:    _EnclaveService_GenerateSignedReport_Handler,
		},
		{
			MethodName: "VerifyReportSignature",
			Handler:    _EnclaveService_VerifyReportSignature_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "enclave.proto",
}

// EnclaveServiceServer is the server API for EnclaveService
type EnclaveServiceServer interface {
	HealthCheck(context.Context, *HealthCheckRequest) (*HealthCheckResponse, error)
	CreateUserConnection(context.Context, *CreateUserConnectionRequest) (*CreateUserConnectionResponse, error)
	ProcessSyncJob(context.Context, *SyncJobRequest) (*SyncJobResponse, error)
	GetPerformanceMetrics(context.Context, *PerformanceMetricsRequest) (*PerformanceMetricsResponse, error)
	GetSnapshotTimeSeries(context.Context, *SnapshotTimeSeriesRequest) (*SnapshotTimeSeriesResponse, error)
	GetAggregatedMetrics(context.Context, *AggregatedMetricsRequest) (*AggregatedMetricsResponse, error)
	GenerateSignedReport(context.Context, *ReportRequest) (*SignedReportResponse, error)
	VerifyReportSignature(context.Context, *VerifySignatureRequest) (*VerifySignatureResponse, error)
}

// Handlers using JSON codec for simplicity (can be replaced with protobuf codec)
func _EnclaveService_HealthCheck_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(HealthCheckRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(EnclaveServiceServer).HealthCheck(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/enclave.EnclaveService/HealthCheck",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(EnclaveServiceServer).HealthCheck(ctx, req.(*HealthCheckRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _EnclaveService_CreateUserConnection_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CreateUserConnectionRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(EnclaveServiceServer).CreateUserConnection(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/enclave.EnclaveService/CreateUserConnection",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(EnclaveServiceServer).CreateUserConnection(ctx, req.(*CreateUserConnectionRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _EnclaveService_ProcessSyncJob_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SyncJobRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(EnclaveServiceServer).ProcessSyncJob(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/enclave.EnclaveService/ProcessSyncJob",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(EnclaveServiceServer).ProcessSyncJob(ctx, req.(*SyncJobRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _EnclaveService_GetPerformanceMetrics_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(PerformanceMetricsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(EnclaveServiceServer).GetPerformanceMetrics(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/enclave.EnclaveService/GetPerformanceMetrics",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(EnclaveServiceServer).GetPerformanceMetrics(ctx, req.(*PerformanceMetricsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _EnclaveService_GetSnapshotTimeSeries_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SnapshotTimeSeriesRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(EnclaveServiceServer).GetSnapshotTimeSeries(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/enclave.EnclaveService/GetSnapshotTimeSeries",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(EnclaveServiceServer).GetSnapshotTimeSeries(ctx, req.(*SnapshotTimeSeriesRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _EnclaveService_GetAggregatedMetrics_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AggregatedMetricsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(EnclaveServiceServer).GetAggregatedMetrics(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/enclave.EnclaveService/GetAggregatedMetrics",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(EnclaveServiceServer).GetAggregatedMetrics(ctx, req.(*AggregatedMetricsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _EnclaveService_GenerateSignedReport_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ReportRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(EnclaveServiceServer).GenerateSignedReport(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/enclave.EnclaveService/GenerateSignedReport",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(EnclaveServiceServer).GenerateSignedReport(ctx, req.(*ReportRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _EnclaveService_VerifyReportSignature_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(VerifySignatureRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(EnclaveServiceServer).VerifyReportSignature(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/enclave.EnclaveService/VerifyReportSignature",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(EnclaveServiceServer).VerifyReportSignature(ctx, req.(*VerifySignatureRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// JSON codec for gRPC (alternative to protobuf)
type JSONCodec struct{}

func (JSONCodec) Marshal(v interface{}) ([]byte, error) {
	return json.Marshal(v)
}

func (JSONCodec) Unmarshal(data []byte, v interface{}) error {
	return json.Unmarshal(data, v)
}

func (JSONCodec) Name() string {
	return "json"
}

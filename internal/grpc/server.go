package grpc

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/trackrecord/enclave/internal/repository"
	"github.com/trackrecord/enclave/internal/service"
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
) *Server {
	return &Server{
		logger:       logger,
		connSvc:      connSvc,
		syncSvc:      syncSvc,
		metricsSvc:   metricsSvc,
		reportSvc:    reportSvc,
		snapshotRepo: snapshotRepo,
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
	return &HealthCheckResponse{
		Status:        "healthy",
		Version:       version,
		Timestamp:     time.Now().Unix(),
		UptimeSeconds: int64(time.Since(startTime).Seconds()),
		Database:      s.connSvc != nil,
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

	if req.UserUid == "" || req.Exchange == "" || req.ApiKey == "" {
		return &CreateUserConnectionResponse{
			Success: false,
			Error:   "user_uid, exchange, and api_key are required",
		}, nil
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

	if req.UserUid == "" {
		return &SyncJobResponse{
			Success: false,
			Error:   "user_uid is required",
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
func (s *Server) GetAggregatedMetrics(ctx context.Context, req *AggregatedMetricsRequest) (*AggregatedMetricsResponse, error) {
	if s.snapshotRepo == nil {
		return nil, status.Error(codes.Unavailable, "database not configured")
	}

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

// GenerateSignedReport implements EnclaveService
func (s *Server) GenerateSignedReport(ctx context.Context, req *ReportRequest) (*SignedReportResponse, error) {
	if s.reportSvc == nil {
		return &SignedReportResponse{
			Success: false,
			Error:   "report service not available",
		}, nil
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
	})
	if err != nil {
		s.logger.Error("generate report failed", zap.Error(err))
		return &SignedReportResponse{
			Success: false,
			Error:   err.Error(),
		}, nil
	}

	return &SignedReportResponse{
		Success:            true,
		ReportId:           report.ReportID,
		UserUid:            report.UserUID,
		ReportName:         report.ReportName,
		GeneratedAt:        report.GeneratedAt,
		PeriodStart:        report.PeriodStart,
		PeriodEnd:          report.PeriodEnd,
		TotalReturn:        report.TotalReturn,
		SharpeRatio:        report.SharpeRatio,
		MaxDrawdown:        report.MaxDrawdown,
		Signature:          report.Signature,
		PublicKey:          report.PublicKey,
		SignatureAlgorithm: report.SignatureAlgorithm,
		ReportHash:         report.ReportHash,
		EnclaveVersion:     report.EnclaveVersion,
	}, nil
}

// VerifyReportSignature implements EnclaveService
func (s *Server) VerifyReportSignature(ctx context.Context, req *VerifySignatureRequest) (*VerifySignatureResponse, error) {
	if s.reportSvc == nil {
		return &VerifySignatureResponse{
			Valid: false,
			Error: "report service not available",
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

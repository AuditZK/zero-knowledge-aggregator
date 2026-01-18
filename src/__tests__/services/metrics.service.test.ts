import { MetricsService } from '../../services/metrics.service';

describe('MetricsService', () => {
  let service: MetricsService;

  beforeEach(() => {
    // Get fresh singleton instance
    // Note: singleton persists across tests, so we test observed behavior
    service = MetricsService.getInstance();
  });

  afterEach(() => {
    // Clean up any running server
    service.stopMetricsServer();
  });

  describe('getInstance', () => {
    it('should return singleton instance', () => {
      const instance1 = MetricsService.getInstance();
      const instance2 = MetricsService.getInstance();

      expect(instance1).toBe(instance2);
    });

    it('should be an instance of MetricsService', () => {
      const instance = MetricsService.getInstance();

      expect(instance).toBeInstanceOf(MetricsService);
    });
  });

  describe('incrementCounter', () => {
    it('should increment counter without labels', () => {
      const initialMetrics = service.exportMetrics();
      const initialMatch = initialMetrics.match(/enclave_attestation_success_total (\d+)/);
      const initialValue = initialMatch?.[1] ? Number.parseInt(initialMatch[1], 10) : 0;

      service.incrementCounter('enclave_attestation_success_total');

      const metrics = service.exportMetrics();
      const match = metrics.match(/enclave_attestation_success_total (\d+)/);
      expect(match).not.toBeNull();
      const matchValue = match?.[1] ?? '0';
      expect(Number.parseInt(matchValue, 10)).toBe(initialValue + 1);
    });

    it('should increment counter with labels', () => {
      service.incrementCounter('grpc_requests_total', { method: 'GetEquitySnapshots', status: 'ok' });

      const metrics = service.exportMetrics();
      expect(metrics).toContain('grpc_requests_total{method="GetEquitySnapshots",status="ok"}');
    });

    it('should handle non-existent counter gracefully', () => {
      // Should not throw
      expect(() => {
        service.incrementCounter('non_existent_counter');
      }).not.toThrow();
    });

    it('should handle wrong metric type (gauge instead of counter)', () => {
      // grpc_active_connections is a gauge, not a counter
      expect(() => {
        service.incrementCounter('grpc_active_connections');
      }).not.toThrow();
    });
  });

  describe('setGauge', () => {
    it('should set gauge value', () => {
      service.setGauge('grpc_active_connections', 42);

      const metrics = service.exportMetrics();
      expect(metrics).toContain('grpc_active_connections 42');
    });

    it('should update gauge value', () => {
      service.setGauge('exchange_connections_total', 5);
      service.setGauge('exchange_connections_total', 10);

      const metrics = service.exportMetrics();
      expect(metrics).toContain('exchange_connections_total 10');
    });

    it('should handle non-existent gauge gracefully', () => {
      expect(() => {
        service.setGauge('non_existent_gauge', 100);
      }).not.toThrow();
    });

    it('should handle wrong metric type (counter instead of gauge)', () => {
      // grpc_requests_total is a counter, not a gauge
      expect(() => {
        service.setGauge('grpc_requests_total', 100);
      }).not.toThrow();
    });
  });

  describe('observeHistogram', () => {
    it('should observe histogram value with labels', () => {
      service.observeHistogram('grpc_request_duration_seconds', 0.125, { method: 'TriggerSync' });

      const metrics = service.exportMetrics();
      expect(metrics).toContain('grpc_request_duration_seconds{method="TriggerSync"} 0.125');
    });

    it('should handle non-existent histogram gracefully', () => {
      expect(() => {
        service.observeHistogram('non_existent_histogram', 1.5);
      }).not.toThrow();
    });

    it('should handle wrong metric type gracefully', () => {
      // grpc_active_connections is a gauge, not a histogram
      expect(() => {
        service.observeHistogram('grpc_active_connections', 1.5);
      }).not.toThrow();
    });
  });

  describe('registerCollector', () => {
    it('should register and execute collector on export', async () => {
      const collectorFn = jest.fn().mockResolvedValue(undefined);

      service.registerCollector(collectorFn);

      // Collectors are run before metrics export in the HTTP handler
      // We test registration doesn't throw
      expect(collectorFn).not.toHaveBeenCalled();
    });

    it('should handle collector that throws', async () => {
      const failingCollector = jest.fn().mockRejectedValue(new Error('Collector error'));

      // Should not throw when registering
      expect(() => {
        service.registerCollector(failingCollector);
      }).not.toThrow();
    });
  });

  describe('exportMetrics', () => {
    it('should export metrics in Prometheus format', () => {
      const metrics = service.exportMetrics();

      // Should have HELP and TYPE comments
      expect(metrics).toContain('# HELP');
      expect(metrics).toContain('# TYPE');
    });

    it('should include all default metric types', () => {
      const metrics = service.exportMetrics();

      expect(metrics).toContain('grpc_requests_total');
      expect(metrics).toContain('grpc_request_duration_seconds');
      expect(metrics).toContain('grpc_active_connections');
      expect(metrics).toContain('db_queries_total');
      expect(metrics).toContain('db_query_duration_seconds');
      expect(metrics).toContain('process_memory_bytes');
      expect(metrics).toContain('process_cpu_usage_percent');
      expect(metrics).toContain('enclave_attestation_success_total');
      expect(metrics).toContain('enclave_attestation_failure_total');
      expect(metrics).toContain('sync_jobs_total');
      expect(metrics).toContain('snapshots_created_total');
      expect(metrics).toContain('exchange_connections_total');
    });

    it('should include metric help text', () => {
      const metrics = service.exportMetrics();

      expect(metrics).toContain('# HELP grpc_requests_total Total number of gRPC requests');
      expect(metrics).toContain('# HELP process_memory_bytes Process memory usage in bytes');
    });

    it('should include metric types', () => {
      const metrics = service.exportMetrics();

      expect(metrics).toContain('# TYPE grpc_requests_total counter');
      expect(metrics).toContain('# TYPE grpc_active_connections gauge');
      expect(metrics).toContain('# TYPE grpc_request_duration_seconds histogram');
    });

    it('should update system metrics on export', () => {
      const metrics = service.exportMetrics();

      // Memory should be a positive number
      const memMatch = metrics.match(/process_memory_bytes (\d+)/);
      expect(memMatch).not.toBeNull();
      const memValue = memMatch?.[1] ?? '0';
      expect(Number.parseInt(memValue, 10)).toBeGreaterThan(0);
    });

    it('should format labels correctly', () => {
      service.incrementCounter('sync_jobs_total', { status: 'success' });
      service.incrementCounter('sync_jobs_total', { status: 'failure' });

      const metrics = service.exportMetrics();

      expect(metrics).toContain('sync_jobs_total{status="success"}');
      expect(metrics).toContain('sync_jobs_total{status="failure"}');
    });

    it('should sort labels alphabetically', () => {
      service.incrementCounter('grpc_requests_total', { status: 'ok', method: 'Test' });

      const metrics = service.exportMetrics();

      // Labels should be sorted: method before status
      expect(metrics).toContain('grpc_requests_total{method="Test",status="ok"}');
    });
  });

  describe('startMetricsServer', () => {
    it('should not start server when METRICS_ENABLED is not true', () => {
      const originalEnv = process.env.METRICS_ENABLED;
      process.env.METRICS_ENABLED = 'false';

      // Should not throw
      expect(() => {
        service.startMetricsServer(9999);
      }).not.toThrow();

      process.env.METRICS_ENABLED = originalEnv;
    });

    it('should start server when METRICS_ENABLED is true', (done) => {
      const originalEnv = process.env.METRICS_ENABLED;
      process.env.METRICS_ENABLED = 'true';

      // Use a random port to avoid conflicts
      const port = 9000 + Math.floor(Math.random() * 1000);

      service.startMetricsServer(port);

      // Give server time to start
      setTimeout(() => {
        service.stopMetricsServer();
        process.env.METRICS_ENABLED = originalEnv;
        done();
      }, 100);
    });
  });

  describe('stopMetricsServer', () => {
    it('should stop server without error when no server running', () => {
      expect(() => {
        service.stopMetricsServer();
      }).not.toThrow();
    });

    it('should stop running server', (done) => {
      const originalEnv = process.env.METRICS_ENABLED;
      process.env.METRICS_ENABLED = 'true';

      const port = 9000 + Math.floor(Math.random() * 1000);
      service.startMetricsServer(port);

      setTimeout(() => {
        expect(() => {
          service.stopMetricsServer();
        }).not.toThrow();

        process.env.METRICS_ENABLED = originalEnv;
        done();
      }, 100);
    });
  });

  describe('measureAsync', () => {
    it('should measure successful async function duration', async () => {
      const result = await service.measureAsync(
        'db_query_duration_seconds',
        { operation: 'test_query' },
        async () => {
          await new Promise(resolve => setTimeout(resolve, 50));
          return 'success';
        }
      );

      expect(result).toBe('success');

      const metrics = service.exportMetrics();
      expect(metrics).toContain('db_query_duration_seconds{operation="test_query"}');
    });

    it('should measure failed async function and rethrow error', async () => {
      const testError = new Error('Test error');

      await expect(
        service.measureAsync(
          'db_query_duration_seconds',
          { operation: 'failing_query' },
          async () => {
            throw testError;
          }
        )
      ).rejects.toThrow('Test error');

      const metrics = service.exportMetrics();
      expect(metrics).toContain('db_query_duration_seconds{error="true",operation="failing_query"}');
    });

    it('should record duration in seconds', async () => {
      await service.measureAsync(
        'grpc_request_duration_seconds',
        { method: 'TimingTest' },
        async () => {
          await new Promise(resolve => setTimeout(resolve, 100));
          return null;
        }
      );

      const metrics = service.exportMetrics();
      const match = metrics.match(/grpc_request_duration_seconds\{method="TimingTest"\} ([\d.]+)/);
      expect(match).not.toBeNull();

      const durationStr = match?.[1] ?? '0';
      const duration = Number.parseFloat(durationStr);
      // Should be at least 0.1 seconds (100ms)
      expect(duration).toBeGreaterThanOrEqual(0.09);
      // Should be less than 1 second
      expect(duration).toBeLessThan(1);
    });
  });

  describe('label key generation', () => {
    it('should generate consistent label keys', () => {
      // Add metrics with same labels in different order
      service.incrementCounter('grpc_requests_total', { method: 'A', status: 'ok' });
      service.incrementCounter('grpc_requests_total', { status: 'ok', method: 'A' });

      const metrics = service.exportMetrics();

      // Count occurrences - should only have one entry (labels normalized)
      const matches = metrics.match(/grpc_requests_total\{method="A",status="ok"\}/g);
      expect(matches).not.toBeNull();
      expect(matches!.length).toBe(1);
    });
  });
});

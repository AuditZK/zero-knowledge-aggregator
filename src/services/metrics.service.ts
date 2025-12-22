/**
 * Prometheus Metrics Service
 *
 * Exports essential metrics for production monitoring:
 * - gRPC request count, duration, errors
 * - Database query count, duration
 * - Memory usage
 * - CPU usage
 * - Active connections
 *
 * SECURITY: Metrics are AGGREGATED ONLY, no user-specific data
 * - NO user IDs
 * - NO individual balances
 * - NO trade symbols
 * - NO credentials
 *
 * Metrics are exposed at GET /metrics (port 9090, INTERNAL NETWORK ONLY)
 */

import * as http from 'http';
import { getLogger } from '../utils/secure-enclave-logger';

const logger = getLogger('MetricsService');

interface Metric {
  name: string;
  type: 'counter' | 'gauge' | 'histogram';
  help: string;
  value: number | Map<string, number>;
  labels?: string[];
}

type MetricsCollector = () => Promise<void>;

export class MetricsService {
  private static instance: MetricsService;
  private metrics: Map<string, Metric> = new Map();
  private server: http.Server | null = null;
  private collectors: MetricsCollector[] = [];

  private constructor() {
    this.initializeMetrics();
  }

  static getInstance(): MetricsService {
    if (!MetricsService.instance) {
      MetricsService.instance = new MetricsService();
    }
    return MetricsService.instance;
  }

  /**
   * Initialize default metrics
   */
  private initializeMetrics(): void {
    // gRPC metrics
    this.registerMetric({
      name: 'grpc_requests_total',
      type: 'counter',
      help: 'Total number of gRPC requests',
      value: new Map(),
      labels: ['method', 'status']
    });

    this.registerMetric({
      name: 'grpc_request_duration_seconds',
      type: 'histogram',
      help: 'gRPC request duration in seconds',
      value: new Map(),
      labels: ['method']
    });

    this.registerMetric({
      name: 'grpc_active_connections',
      type: 'gauge',
      help: 'Number of active gRPC connections',
      value: 0
    });

    // Database metrics
    this.registerMetric({
      name: 'db_queries_total',
      type: 'counter',
      help: 'Total number of database queries',
      value: new Map(),
      labels: ['operation']
    });

    this.registerMetric({
      name: 'db_query_duration_seconds',
      type: 'histogram',
      help: 'Database query duration in seconds',
      value: new Map(),
      labels: ['operation']
    });

    // System metrics
    this.registerMetric({
      name: 'process_memory_bytes',
      type: 'gauge',
      help: 'Process memory usage in bytes',
      value: 0
    });

    this.registerMetric({
      name: 'process_cpu_usage_percent',
      type: 'gauge',
      help: 'Process CPU usage percentage',
      value: 0
    });

    // Enclave-specific metrics
    this.registerMetric({
      name: 'enclave_attestation_success_total',
      type: 'counter',
      help: 'Total number of successful attestations',
      value: 0
    });

    this.registerMetric({
      name: 'enclave_attestation_failure_total',
      type: 'counter',
      help: 'Total number of failed attestations',
      value: 0
    });

    this.registerMetric({
      name: 'sync_jobs_total',
      type: 'counter',
      help: 'Total number of sync jobs processed',
      value: new Map(),
      labels: ['status']
    });

    this.registerMetric({
      name: 'snapshots_created_total',
      type: 'counter',
      help: 'Total number of snapshots created',
      value: 0
    });

    this.registerMetric({
      name: 'exchange_connections_total',
      type: 'gauge',
      help: 'Total number of active exchange connections',
      value: 0
    });
  }

  /**
   * Register a new metric
   */
  private registerMetric(metric: Metric): void {
    this.metrics.set(metric.name, metric);
  }

  /**
   * Increment a counter metric
   */
  incrementCounter(name: string, labels?: Record<string, string>): void {
    const metric = this.metrics.get(name);
    if (!metric || metric.type !== 'counter') {
      logger.warn(`Counter metric ${name} not found`);
      return;
    }

    if (labels && metric.value instanceof Map) {
      const key = this.getLabelKey(labels);
      const current = metric.value.get(key) || 0;
      metric.value.set(key, current + 1);
    } else if (typeof metric.value === 'number') {
      metric.value++;
    }
  }

  /**
   * Set a gauge metric value
   */
  setGauge(name: string, value: number, labels?: Record<string, string>): void {
    const metric = this.metrics.get(name);
    if (!metric || metric.type !== 'gauge') {
      logger.warn(`Gauge metric ${name} not found`);
      return;
    }

    if (labels && metric.value instanceof Map) {
      const key = this.getLabelKey(labels);
      metric.value.set(key, value);
    } else {
      metric.value = value;
    }
  }

  /**
   * Observe a histogram value (simplified - just stores latest)
   */
  observeHistogram(name: string, value: number, labels?: Record<string, string>): void {
    const metric = this.metrics.get(name);
    if (!metric || metric.type !== 'histogram') {
      logger.warn(`Histogram metric ${name} not found`);
      return;
    }

    if (labels && metric.value instanceof Map) {
      const key = this.getLabelKey(labels);
      metric.value.set(key, value);
    }
  }

  /**
   * Register a collector function that updates business metrics
   * Collectors are called before metrics are exported (on scrape)
   */
  registerCollector(collector: MetricsCollector): void {
    this.collectors.push(collector);
  }

  /**
   * Update system metrics (memory, CPU)
   */
  private updateSystemMetrics(): void {
    // Memory usage
    const memUsage = process.memoryUsage();
    this.setGauge('process_memory_bytes', memUsage.heapUsed);

    // CPU usage (simplified - based on process.cpuUsage())
    const cpuUsage = process.cpuUsage();
    const cpuPercent = (cpuUsage.user + cpuUsage.system) / 1000000; // Convert to seconds
    this.setGauge('process_cpu_usage_percent', cpuPercent);
  }

  /**
   * Run all registered collectors (async)
   */
  private async runCollectors(): Promise<void> {
    await Promise.all(
      this.collectors.map(collector =>
        collector().catch(err => logger.error('Collector failed', err))
      )
    );
  }

  /**
   * Generate label key for Map-based metrics
   */
  private getLabelKey(labels: Record<string, string>): string {
    return Object.entries(labels)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([k, v]) => `${k}="${v}"`)
      .join(',');
  }

  /**
   * Export metrics in Prometheus format
   */
  exportMetrics(): string {
    this.updateSystemMetrics();

    const lines: string[] = [];

    for (const [name, metric] of this.metrics) {
      // HELP line
      lines.push(`# HELP ${name} ${metric.help}`);

      // TYPE line
      lines.push(`# TYPE ${name} ${metric.type}`);

      // Metric values
      if (metric.value instanceof Map) {
        for (const [labels, value] of metric.value) {
          lines.push(`${name}{${labels}} ${value}`);
        }
      } else {
        lines.push(`${name} ${metric.value}`);
      }

      lines.push('');
    }

    return lines.join('\n');
  }

  /**
   * Start HTTP server to expose metrics
   */
  startMetricsServer(port: number = 9090): void {
    if (process.env.METRICS_ENABLED !== 'true') {
      logger.info('Metrics server disabled (METRICS_ENABLED=false)');
      return;
    }

    this.server = http.createServer((req, res) => {
      if (req.method === 'GET' && req.url === '/metrics') {
        // Run collectors before exporting (async)
        this.runCollectors()
          .then(() => {
            const metrics = this.exportMetrics();
            res.writeHead(200, { 'Content-Type': 'text/plain; version=0.0.4' });
            res.end(metrics);
          })
          .catch(err => {
            logger.error('Failed to collect metrics', err);
            res.writeHead(500);
            res.end('Internal Server Error');
          });
      } else if (req.method === 'GET' && req.url === '/health') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: 'ok' }));
      } else {
        res.writeHead(404);
        res.end('Not Found');
      }
    });

    this.server.listen(port, '0.0.0.0', () => {
      logger.info(`Metrics server listening on port ${port}`, {
        endpoint: `http://localhost:${port}/metrics`
      });
    });
  }

  /**
   * Stop metrics server
   */
  stopMetricsServer(): void {
    if (this.server) {
      this.server.close();
      logger.info('Metrics server stopped');
    }
  }

  /**
   * Helper: Measure execution time of async function
   */
  async measureAsync<T>(
    metricName: string,
    labels: Record<string, string>,
    fn: () => Promise<T>
  ): Promise<T> {
    const startTime = Date.now();
    try {
      const result = await fn();
      const duration = (Date.now() - startTime) / 1000; // Convert to seconds
      this.observeHistogram(metricName, duration, labels);
      return result;
    } catch (error) {
      const duration = (Date.now() - startTime) / 1000;
      this.observeHistogram(metricName, duration, { ...labels, error: 'true' });
      throw error;
    }
  }
}

// Export singleton instance
export const metricsService = MetricsService.getInstance();

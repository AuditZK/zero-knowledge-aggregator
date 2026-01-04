import express, { Request, Response, NextFunction } from 'express';
import http from 'http';
import { container } from 'tsyringe';
import { getLogBuffer, clearLogBuffer, getLogger, extractErrorMessage } from './utils/secure-enclave-logger';
import { SevSnpAttestationService } from './services/sev-snp-attestation.service';

const logger = getLogger('HttpLogServer');

/**
 * HTTP Log Server for Enclave
 *
 * Lightweight HTTP server to expose enclave logs via SSE (Server-Sent Events)
 * and AMD SEV-SNP attestation reports for security auditing.
 *
 * ENDPOINTS:
 * - GET /health - Service health check (public)
 * - GET /attestation - Full AMD SEV-SNP attestation report (public)
 * - GET /attestation/info - Platform and attestation method info (public)
 * - GET /logs - Get buffered logs (protected by API key)
 * - GET /logs/stream - SSE stream of real-time logs (protected by API key)
 * - POST /logs/clear - Clear log buffer (protected by API key)
 *
 * SECURITY:
 * - All logs are pre-filtered by TIER 1 + TIER 2 redaction
 * - Attestation endpoint allows external audit verification (public for verification)
 * - Log endpoints protected by LOG_SERVER_API_KEY (SOC 2 requirement)
 * - Set LOG_SERVER_API_KEY env var to enable log access
 */

/**
 * SOC 2 SECURITY: API key middleware for log endpoints
 * Protects sensitive operational logs from unauthorized access
 */
const requireApiKey = (req: Request, res: Response, next: NextFunction): void => {
  const apiKey = process.env.LOG_SERVER_API_KEY;

  // If no API key configured, deny all access to protected endpoints
  if (!apiKey) {
    logger.warn('[HTTP] Log access denied - LOG_SERVER_API_KEY not configured');
    res.status(503).json({
      error: 'Log server not configured. Set LOG_SERVER_API_KEY environment variable.'
    });
    return;
  }

  // Check for API key in header or query param
  const providedKey = req.headers['x-api-key'] || req.query.apiKey;

  if (providedKey !== apiKey) {
    logger.warn('[HTTP] Log access denied - invalid API key', { ip: req.ip });
    res.status(401).json({
      error: 'Invalid or missing API key. Provide X-Api-Key header or ?apiKey= query param.'
    });
    return;
  }

  next();
};
export class HttpLogServer {
  private app: express.Application;
  private port: number;
  private server: http.Server | null = null;
  private sseClients: Set<express.Response> = new Set();

  constructor() {
    this.app = express();
    // Use PORT (Cloud Run) or HTTP_LOG_PORT (Docker), default to 50052
    this.port = parseInt(process.env.PORT || process.env.HTTP_LOG_PORT || '50052');

    this.setupRoutes();
  }

  private setupRoutes(): void {
    // Health check
    this.app.get('/health', (_req, res) => {
      res.json({ status: 'ok', service: 'enclave-log-server' });
    });

    // AMD SEV-SNP Attestation endpoint
    this.app.get('/attestation', async (_req, res) => {
      try {
        const attestationService = container.resolve(SevSnpAttestationService);
        const result = await attestationService.getAttestationReport();

        res.json({
          verified: result.verified,
          enclave: result.enclave,
          sevSnpEnabled: result.sevSnpEnabled,
          measurement: result.measurement,
          reportData: result.reportData,
          platformVersion: result.platformVersion,
          errorMessage: result.errorMessage,
          timestamp: new Date().toISOString()
        });
      } catch (error) {
        logger.error('Attestation endpoint failed', { error: extractErrorMessage(error) });
        res.status(500).json({
          verified: false,
          enclave: false,
          sevSnpEnabled: false,
          error: 'Failed to retrieve attestation',
          timestamp: new Date().toISOString()
        });
      }
    });

    // Attestation platform info endpoint
    this.app.get('/attestation/info', async (_req, res) => {
      try {
        const attestationService = container.resolve(SevSnpAttestationService);
        const info = await attestationService.getAttestationInfo();

        res.json({
          platform: info.platform,
          sevSnpAvailable: info.sevSnpAvailable,
          attestationMethod: info.attestationMethod,
          timestamp: new Date().toISOString()
        });
      } catch (error) {
        logger.error('Attestation info endpoint failed', { error: extractErrorMessage(error) });
        res.status(500).json({
          error: 'Failed to retrieve attestation info',
          timestamp: new Date().toISOString()
        });
      }
    });

    // SSE endpoint for real-time log streaming (protected)
    this.app.get('/logs/stream', requireApiKey, (req, res) => {
      // Set headers for SSE
      res.setHeader('Content-Type', 'text/event-stream');
      res.setHeader('Cache-Control', 'no-cache');
      res.setHeader('Connection', 'keep-alive');
      res.setHeader('Access-Control-Allow-Origin', '*');

      // Send initial connection message
      res.write('data: {"type":"connected","message":"SSE connection established"}\n\n');

      // Add client to set
      this.sseClients.add(res);

      // Send existing logs
      const existingLogs = getLogBuffer();
      existingLogs.forEach(log => {
        res.write(`data: ${log}\n\n`);
      });

      // Handle client disconnect
      req.on('close', () => {
        this.sseClients.delete(res);
      });
    });

    // Get logs (for fallback/polling) - protected
    this.app.get('/logs', requireApiKey, (_req, res) => {
      const logs = getLogBuffer();
      res.json({ logs, count: logs.length });
    });

    // Clear logs (for testing/debugging) - protected
    this.app.post('/logs/clear', requireApiKey, (_req, res) => {
      clearLogBuffer();
      logger.info('[HTTP] Log buffer cleared by authorized request');
      res.json({ success: true, message: 'Logs cleared' });
    });
  }

  /**
   * Broadcast log to all SSE clients
   */
  public broadcastLog(log: string): void {
    this.sseClients.forEach(client => {
      try {
        client.write(`data: ${log}\n\n`);
      } catch (error) {
        // Client disconnected, will be cleaned up by 'close' event
      }
    });
  }

  async start(): Promise<void> {
    return new Promise((resolve) => {
      this.server = this.app.listen(this.port, () => {
        logger.info(`Listening on port ${this.port}`);
        logger.info(`Endpoints available:`);
        logger.info(`  - Health: http://localhost:${this.port}/health`);
        logger.info(`  - Attestation: http://localhost:${this.port}/attestation`);
        logger.info(`  - Attestation Info: http://localhost:${this.port}/attestation/info`);
        logger.info(`  - Logs: http://localhost:${this.port}/logs`);
        logger.info(`  - Logs Stream (SSE): http://localhost:${this.port}/logs/stream`);
        resolve();
      });
    });
  }

  async stop(): Promise<void> {
    return new Promise((resolve) => {
      if (this.server) {
        this.server.close(() => {
          logger.info('Stopped');
          resolve();
        });
      } else {
        resolve();
      }
    });
  }
}

export async function startHttpLogServer(): Promise<HttpLogServer> {
  const server = new HttpLogServer();
  await server.start();
  return server;
}

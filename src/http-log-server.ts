import express from 'express';
import { getLogBuffer, clearLogBuffer } from './utils/secure-enclave-logger';

/**
 * HTTP Log Server for Enclave
 *
 * Lightweight HTTP server to expose enclave logs via SSE (Server-Sent Events).
 * This is simpler and safer than WebSocket, more efficient than polling.
 *
 * SECURITY:
 * - All logs are pre-filtered by TIER 1 + TIER 2 redaction
 * - Read-only SSE stream
 * - No authentication needed (logs are already safe)
 */
export class HttpLogServer {
  private app: express.Application;
  private port: number;
  private server: any;
  private sseClients: Set<express.Response> = new Set();

  constructor() {
    this.app = express();
    this.port = parseInt(process.env.HTTP_LOG_PORT || '50052');

    this.setupRoutes();
  }

  private setupRoutes(): void {
    // Health check
    this.app.get('/health', (_req, res) => {
      res.json({ status: 'ok', service: 'enclave-log-server' });
    });

    // SSE endpoint for real-time log streaming
    this.app.get('/logs/stream', (req, res) => {
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

    // Get logs (for fallback/polling)
    this.app.get('/logs', (_req, res) => {
      const logs = getLogBuffer();
      res.json({ logs, count: logs.length });
    });

    // Clear logs (for testing/debugging)
    this.app.post('/logs/clear', (_req, res) => {
      clearLogBuffer();
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
        console.log(`[HttpLogServer] Listening on port ${this.port}`);
        console.log(`[HttpLogServer] Logs endpoint: http://localhost:${this.port}/logs`);
        resolve();
      });
    });
  }

  async stop(): Promise<void> {
    return new Promise((resolve) => {
      if (this.server) {
        this.server.close(() => {
          console.log('[HttpLogServer] Stopped');
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

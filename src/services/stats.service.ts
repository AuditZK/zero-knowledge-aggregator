/**
 * Lightweight StatsD client — sends UDP metrics to Netdata's built-in StatsD listener.
 * Fire-and-forget: errors are silently ignored to never impact the enclave's critical path.
 * No external dependencies, no HTTP server, <50 lines.
 */
import * as dgram from 'node:dgram';

class StatsService {
  private readonly host: string;
  private readonly port: number;
  private readonly enabled: boolean;
  private readonly socket: dgram.Socket;

  constructor() {
    this.host = process.env.STATSD_HOST ?? 'netdata';
    this.port = Number.parseInt(process.env.STATSD_PORT ?? '8125', 10);
    this.enabled = process.env.STATSD_ENABLED === 'true';
    this.socket = dgram.createSocket('udp4');
    this.socket.unref(); // Never block process exit
  }

  private send(metric: string): void {
    if (!this.enabled) return;
    const buf = Buffer.from(metric);
    this.socket.send(buf, 0, buf.length, this.port, this.host);
  }

  /** Increment a counter (e.g. request counts, error counts) */
  counter(name: string, value = 1): void {
    this.send(`enclave.${name}:${value}|c`);
  }

  /** Set an absolute gauge value (e.g. active connections) */
  gauge(name: string, value: number): void {
    this.send(`enclave.${name}:${value}|g`);
  }

  /** Record a timing in milliseconds */
  timing(name: string, ms: number): void {
    this.send(`enclave.${name}:${ms}|ms`);
  }
}

export const statsService = new StatsService();

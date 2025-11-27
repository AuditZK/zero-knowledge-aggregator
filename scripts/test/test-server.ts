#!/usr/bin/env ts-node
/**
 * Simple web server to test gRPC APIs through a browser
 *
 * Usage:
 *   npm run test:web
 *   Then open http://localhost:3333 in your browser
 */

import express from 'express';
import * as grpc from '@grpc/grpc-js';
import * as protoLoader from '@grpc/proto-loader';
import * as fs from 'fs';
import path from 'path';

const app = express();
const PORT = 3333;

// Enclave HTTP log server URLs
const ENCLAVE_LOG_URL = process.env.ENCLAVE_LOG_URL || 'http://localhost:50052/logs';
const ENCLAVE_SSE_URL = process.env.ENCLAVE_SSE_URL || 'http://localhost:50052/logs/stream';

// Configuration
const PROTO_PATH = path.join(__dirname, '../../src/proto/enclave.proto');
const SERVER_ADDRESS = 'localhost:50051';
const CA_CERT_PATH = path.join(__dirname, '../../certs/ca.crt');

// Load proto
const packageDefinition = protoLoader.loadSync(PROTO_PATH, {
  keepCase: true,
  longs: String,
  enums: String,
  defaults: true,
  oneofs: true
});

// Load TLS certificate
const caCert = fs.readFileSync(CA_CERT_PATH);
const sslCredentials = grpc.credentials.createSsl(caCert);

const protoDescriptor = grpc.loadPackageDefinition(packageDefinition) as any;
const client = new protoDescriptor.enclave.EnclaveService(
  SERVER_ADDRESS,
  sslCredentials
);

app.use(express.json());
app.use(express.static('public'));

// Store for request log streaming only (enclave logs fetched via HTTP polling)
let logBuffer: string[] = [];
const MAX_LOG_BUFFER = 500;

// Helper to add log to buffer
function addLogToBuffer(log: string) {
  logBuffer.push(log);
  if (logBuffer.length > MAX_LOG_BUFFER) {
    logBuffer = logBuffer.slice(-MAX_LOG_BUFFER);
  }
}


// Get request logs endpoint
app.get('/api/logs', (_req, res) => {
  res.json({ logs: logBuffer });
});

// SSE proxy endpoint for enclave logs (real-time streaming)
app.get('/api/enclave-logs/stream', async (req, res) => {
  // Set SSE headers
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');

  try {
    // Proxy SSE stream from enclave
    const response = await fetch(ENCLAVE_SSE_URL);

    if (!response.body) {
      throw new Error('No response body');
    }

    // Pipe the SSE stream to client
    const reader = response.body.getReader();
    const decoder = new TextDecoder();

    req.on('close', () => {
      reader.cancel();
    });

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      const chunk = decoder.decode(value, { stream: true });
      res.write(chunk);
    }
  } catch (error) {
    console.error('[Proxy] Failed to stream enclave logs:', error);
    res.write('data: {"type":"error","message":"Enclave SSE stream unavailable"}\n\n');
  }
});

// Get enclave logs endpoint (fallback polling)
app.get('/api/enclave-logs', async (_req, res) => {
  try {
    const response = await fetch(ENCLAVE_LOG_URL);
    const data = await response.json();
    res.json(data);
  } catch (error) {
    console.error('[Proxy] Failed to fetch enclave logs:', error);
    res.status(503).json({ logs: [], error: 'Enclave log server unavailable' });
  }
});

// Clear request logs endpoint
app.post('/api/logs/clear', (_req, res) => {
  logBuffer = [];
  res.json({ success: true });
});

// Clear enclave logs endpoint (proxy to enclave HTTP server)
app.post('/api/enclave-logs/clear', async (_req, res) => {
  try {
    const response = await fetch(ENCLAVE_LOG_URL.replace('/logs', '/logs/clear'), {
      method: 'POST'
    });
    const data = await response.json();
    res.json(data);
  } catch (error) {
    console.error('[Proxy] Failed to clear enclave logs:', error);
    res.status(503).json({ success: false, error: 'Enclave log server unavailable' });
  }
});

// Health Check endpoint
app.get('/api/health', (_req, res) => {
  const timestamp = new Date().toLocaleTimeString();
  addLogToBuffer(`[${timestamp}] → HealthCheck {}`);
  client.HealthCheck({}, (error: any, response: any) => {
    if (error) {
      addLogToBuffer(`[${timestamp}] ← ERROR: ${error.message}`);
      res.status(500).json({ error: error.message });
    } else {
      const isHealthy = response.status === 0 || response.status === '0' || response.status === 'HEALTHY';
      addLogToBuffer(`[${timestamp}] ← ${isHealthy ? 'HEALTHY' : 'UNHEALTHY'}: ${JSON.stringify(response)}`);
      res.json(response);
    }
  });
});

// Process Sync Job endpoint (sync type is automatic based on exchange)
app.post('/api/sync', (req, res) => {
  const timestamp = new Date().toLocaleTimeString();

  const request: any = {
    user_uid: req.body.user_uid || '550e8400-e29b-41d4-a716-446655440000'
  };

  // Only include exchange if specified
  if (req.body.exchange) request.exchange = req.body.exchange;

  addLogToBuffer(`[${timestamp}] → ProcessSyncJob ${JSON.stringify(request)}`);

  client.ProcessSyncJob(request, (error: any, response: any) => {
    if (error) {
      addLogToBuffer(`[${timestamp}] ← ERROR: ${error.message}`);
      res.status(500).json({ error: error.message, details: error.details });
    } else {
      addLogToBuffer(`[${timestamp}] ← OK: ${JSON.stringify(response)}`);
      res.json(response);
    }
  });
});

// Get Aggregated Metrics endpoint
app.post('/api/metrics', (req, res) => {
  const timestamp = new Date().toLocaleTimeString();
  const request: any = {
    user_uid: req.body.user_uid || '550e8400-e29b-41d4-a716-446655440000'
  };

  // Only include optional fields if they have values (gRPC doesn't distinguish undefined from empty string)
  if (req.body.exchange) request.exchange = req.body.exchange;

  addLogToBuffer(`[${timestamp}] → GetAggregatedMetrics ${JSON.stringify(request)}`);

  client.GetAggregatedMetrics(request, (error: any, response: any) => {
    if (error) {
      addLogToBuffer(`[${timestamp}] ← ERROR: ${error.message}`);
      res.status(500).json({ error: error.message, details: error.details });
    } else {
      addLogToBuffer(`[${timestamp}] ← OK: ${JSON.stringify(response)}`);
      res.json(response);
    }
  });
});

// Get Snapshot Time Series endpoint
app.post('/api/snapshots', (req, res) => {
  const timestamp = new Date().toLocaleTimeString();
  const request: any = {
    user_uid: req.body.user_uid || '550e8400-e29b-41d4-a716-446655440000'
  };

  // Include optional filters
  if (req.body.exchange) request.exchange = req.body.exchange;
  if (req.body.start_date) request.start_date = req.body.start_date;
  if (req.body.end_date) request.end_date = req.body.end_date;

  addLogToBuffer(`[${timestamp}] → GetSnapshotTimeSeries ${JSON.stringify(request)}`);

  client.GetSnapshotTimeSeries(request, (error: any, response: any) => {
    if (error) {
      addLogToBuffer(`[${timestamp}] ← ERROR: ${error.message}`);
      res.status(500).json({ error: error.message, details: error.details });
    } else {
      const count = response.snapshots?.length || 0;
      addLogToBuffer(`[${timestamp}] ← OK: ${count} snapshots`);
      res.json(response);
    }
  });
});

// Create User Connection endpoint
app.post('/api/create-user', (req, res) => {
  const timestamp = new Date().toLocaleTimeString();
  const request: any = {
    exchange: req.body.exchange || 'binance',
    label: req.body.label || 'Main Account',
    api_key: req.body.api_key || '',
    api_secret: req.body.api_secret || '',
    passphrase: req.body.passphrase || ''
  };

  addLogToBuffer(`[${timestamp}] → CreateUserConnection ${JSON.stringify({ exchange: request.exchange, label: request.label })}`);

  client.CreateUserConnection(request, (error: any, response: any) => {
    if (error) {
      addLogToBuffer(`[${timestamp}] ← ERROR: ${error.message}`);
      res.status(500).json({ error: error.message, details: error.details });
    } else {
      addLogToBuffer(`[${timestamp}] ← OK: userUid=${response.user_uid}`);
      res.json(response);
    }
  });
});

// Serve the HTML page
app.get('/', (_req, res) => {
  res.send(`
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Track Record - Enclave Dashboard</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/chartjs-adapter-date-fns"></script>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }

    :root {
      --bg-dark: #0f1419;
      --bg-card: #1a1f2e;
      --bg-input: #252b3b;
      --border: #2d3548;
      --text-primary: #e4e6eb;
      --text-secondary: #8b949e;
      --accent: #58a6ff;
      --accent-green: #3fb950;
      --accent-red: #f85149;
      --accent-orange: #d29922;
    }

    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: var(--bg-dark);
      color: var(--text-primary);
      min-height: 100vh;
    }

    /* Layout */
    .layout {
      display: grid;
      grid-template-columns: 280px 1fr;
      min-height: 100vh;
    }

    /* Sidebar */
    .sidebar {
      background: var(--bg-card);
      border-right: 1px solid var(--border);
      padding: 24px;
      display: flex;
      flex-direction: column;
      gap: 24px;
    }

    .logo {
      display: flex;
      align-items: center;
      gap: 12px;
      padding-bottom: 20px;
      border-bottom: 1px solid var(--border);
    }

    .logo h1 {
      font-size: 20px;
      font-weight: 600;
    }

    .logo-icon {
      width: 36px;
      height: 36px;
      background: linear-gradient(135deg, var(--accent) 0%, #a371f7 100%);
      border-radius: 8px;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 18px;
    }

    /* Config Section */
    .config-section {
      display: flex;
      flex-direction: column;
      gap: 16px;
    }

    .config-section h3 {
      font-size: 12px;
      text-transform: uppercase;
      color: var(--text-secondary);
      letter-spacing: 0.5px;
    }

    .input-group {
      display: flex;
      flex-direction: column;
      gap: 6px;
    }

    .input-group label {
      font-size: 13px;
      color: var(--text-secondary);
    }

    input, select {
      background: var(--bg-input);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 10px 12px;
      color: var(--text-primary);
      font-size: 14px;
      width: 100%;
    }

    input:focus, select:focus {
      outline: none;
      border-color: var(--accent);
    }

    /* Buttons */
    .btn {
      padding: 10px 16px;
      border-radius: 6px;
      font-size: 14px;
      font-weight: 500;
      cursor: pointer;
      border: none;
      transition: all 0.2s;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
    }

    .btn-primary {
      background: var(--accent);
      color: white;
    }

    .btn-primary:hover {
      background: #4c9aed;
    }

    .btn-success {
      background: var(--accent-green);
      color: white;
    }

    .btn-danger {
      background: var(--accent-red);
      color: white;
    }

    .btn-secondary {
      background: var(--bg-input);
      color: var(--text-primary);
      border: 1px solid var(--border);
    }

    .btn-sm {
      padding: 6px 12px;
      font-size: 12px;
    }

    /* Main Content */
    .main {
      padding: 24px;
      overflow-y: auto;
    }

    /* Stats Cards */
    .stats-grid {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 16px;
      margin-bottom: 24px;
    }

    .stat-card {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 20px;
    }

    .stat-card .label {
      font-size: 13px;
      color: var(--text-secondary);
      margin-bottom: 8px;
    }

    .stat-card .value {
      font-size: 28px;
      font-weight: 600;
    }

    .stat-card .change {
      font-size: 13px;
      margin-top: 4px;
    }

    .change.positive { color: var(--accent-green); }
    .change.negative { color: var(--accent-red); }

    /* Breakdown Grid */
    .breakdown-grid {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 16px;
      margin-bottom: 24px;
    }

    .breakdown-card {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 16px;
    }

    .breakdown-header {
      display: flex;
      align-items: center;
      gap: 8px;
      margin-bottom: 12px;
      padding-bottom: 8px;
      border-bottom: 1px solid var(--border);
    }

    .market-name {
      font-weight: 600;
      font-size: 14px;
    }

    .breakdown-stats {
      display: flex;
      flex-direction: column;
      gap: 8px;
    }

    .breakdown-stat {
      display: flex;
      justify-content: space-between;
      align-items: center;
    }

    .breakdown-stat .label {
      font-size: 12px;
      color: var(--text-secondary);
    }

    .breakdown-stat .value {
      font-size: 13px;
      font-weight: 500;
      font-family: monospace;
    }

    /* Chart Container */
    .chart-container {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 24px;
      margin-bottom: 24px;
    }

    .chart-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 20px;
    }

    .chart-header h2 {
      font-size: 18px;
      font-weight: 600;
    }

    .chart-actions {
      display: flex;
      gap: 8px;
    }

    .chart-wrapper {
      position: relative;
      height: 350px;
    }

    /* Logs Panel */
    .logs-panel {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 12px;
      overflow: hidden;
    }

    .logs-header {
      display: flex;
      border-bottom: 1px solid var(--border);
    }

    .log-tab {
      padding: 12px 20px;
      font-size: 14px;
      color: var(--text-secondary);
      cursor: pointer;
      border-bottom: 2px solid transparent;
      transition: all 0.2s;
      background: none;
      border-top: none;
      border-left: none;
      border-right: none;
    }

    .log-tab:hover {
      color: var(--text-primary);
    }

    .log-tab.active {
      color: var(--accent);
      border-bottom-color: var(--accent);
    }

    .logs-content {
      height: 250px;
      overflow-y: auto;
      padding: 16px;
      font-family: 'Monaco', 'Menlo', monospace;
      font-size: 12px;
      background: #0d1117;
    }

    .log-entry {
      padding: 4px 0;
      border-bottom: 1px solid rgba(255,255,255,0.05);
    }

    .log-entry.info { color: #58a6ff; }
    .log-entry.warn { color: #d29922; }
    .log-entry.error { color: #f85149; }
    .log-entry.debug { color: #8b949e; }

    /* Status Badge */
    .status-badge {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 4px 10px;
      border-radius: 12px;
      font-size: 12px;
      font-weight: 500;
    }

    .status-badge.healthy {
      background: rgba(63, 185, 80, 0.15);
      color: var(--accent-green);
    }

    .status-badge.error {
      background: rgba(248, 81, 73, 0.15);
      color: var(--accent-red);
    }

    .status-dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background: currentColor;
    }

    /* Actions Panel */
    .actions-panel {
      display: flex;
      flex-direction: column;
      gap: 12px;
      margin-top: auto;
      padding-top: 20px;
      border-top: 1px solid var(--border);
    }

    /* Modal */
    .modal-overlay {
      display: none;
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      bottom: 0;
      background: rgba(0,0,0,0.7);
      z-index: 1000;
      align-items: center;
      justify-content: center;
    }

    .modal-overlay.show {
      display: flex;
    }

    .modal {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 24px;
      width: 500px;
      max-height: 80vh;
      overflow-y: auto;
    }

    .modal h2 {
      margin-bottom: 20px;
      font-size: 18px;
    }

    .modal-actions {
      display: flex;
      gap: 12px;
      margin-top: 20px;
      justify-content: flex-end;
    }

    /* Response Display */
    .response-box {
      background: #0d1117;
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 16px;
      font-family: monospace;
      font-size: 12px;
      max-height: 200px;
      overflow-y: auto;
      margin-top: 12px;
      white-space: pre-wrap;
    }

    .response-box.success {
      border-color: var(--accent-green);
    }

    .response-box.error {
      border-color: var(--accent-red);
    }

    /* Empty State */
    .empty-state {
      text-align: center;
      padding: 60px 20px;
      color: var(--text-secondary);
    }

    .empty-state-icon {
      font-size: 48px;
      margin-bottom: 16px;
    }

    /* Server Info */
    .server-info {
      display: flex;
      gap: 16px;
      font-size: 12px;
      color: var(--text-secondary);
      padding: 12px 16px;
      background: var(--bg-input);
      border-radius: 8px;
      margin-bottom: 16px;
    }

    .server-info span {
      display: flex;
      align-items: center;
      gap: 6px;
    }
  </style>
</head>
<body>
  <div class="layout">
    <!-- Sidebar -->
    <aside class="sidebar">
      <div class="logo">
        <div class="logo-icon">TR</div>
        <h1>Track Record</h1>
      </div>

      <div class="config-section">
        <h3>Configuration</h3>
        <div class="input-group">
          <label>User UID</label>
          <input type="text" id="user-uid" value="b84b7c70-31e7-498b-b815-79583b4649b2" />
        </div>
        <div class="input-group">
          <label>Exchange (optional)</label>
          <select id="exchange-filter">
            <option value="">All Exchanges</option>
            <option value="ibkr">IBKR</option>
            <option value="binance">Binance</option>
            <option value="coinbase">Coinbase</option>
            <option value="bitget">Bitget</option>
          </select>
        </div>
      </div>

      <div class="config-section">
        <h3>Actions</h3>
        <button class="btn btn-primary" onclick="runSync()">
          <span>Initialize Sync</span>
        </button>
        <p style="font-size: 11px; color: var(--text-secondary); margin-top: 8px;">
          IBKR: Auto-backfill 365 days (1st sync)<br>
          Crypto: Current snapshot only
        </p>
      </div>

      <div class="actions-panel">
        <button class="btn btn-secondary" onclick="loadSnapshots()">
          Load Snapshots
        </button>
        <button class="btn btn-secondary" onclick="checkHealth()">
          Health Check
        </button>
        <button class="btn btn-secondary" onclick="showCreateUserModal()">
          + Add Connection
        </button>
      </div>

      <div class="server-info">
        <span>gRPC: localhost:50051</span>
        <span id="health-status" class="status-badge healthy">
          <span class="status-dot"></span>
          Checking...
        </span>
      </div>
    </aside>

    <!-- Main Content -->
    <main class="main">
      <!-- Stats -->
      <div class="stats-grid">
        <div class="stat-card">
          <div class="label">Total Equity</div>
          <div class="value" id="stat-equity">--</div>
          <div class="change" id="stat-equity-change"></div>
        </div>
        <div class="stat-card">
          <div class="label">Realized Balance</div>
          <div class="value" id="stat-realized">--</div>
        </div>
        <div class="stat-card">
          <div class="label">Unrealized P&L</div>
          <div class="value" id="stat-unrealized">--</div>
        </div>
        <div class="stat-card">
          <div class="label">Snapshots</div>
          <div class="value" id="stat-snapshots">--</div>
          <div class="change" id="stat-date-range"></div>
        </div>
      </div>

      <!-- Market Breakdown -->
      <div class="breakdown-grid" id="breakdown-section" style="display: none;">
        <!-- Global - always shown -->
        <div class="breakdown-card" id="global-card">
          <div class="breakdown-header">
            <span class="market-name">Global</span>
          </div>
          <div class="breakdown-stats">
            <div class="breakdown-stat">
              <span class="label">Volume</span>
              <span class="value" id="global-volume">--</span>
            </div>
            <div class="breakdown-stat">
              <span class="label">Trades</span>
              <span class="value" id="global-trades">--</span>
            </div>
            <div class="breakdown-stat">
              <span class="label">Trading Fees</span>
              <span class="value" id="global-trading-fees">--</span>
            </div>
            <div class="breakdown-stat">
              <span class="label">Funding Fees</span>
              <span class="value" id="global-funding-fees">--</span>
            </div>
          </div>
        </div>
        <!-- Crypto: Spot -->
        <div class="breakdown-card crypto-card" id="spot-card" style="display: none;">
          <div class="breakdown-header">
            <span class="market-name">Spot</span>
          </div>
          <div class="breakdown-stats">
            <div class="breakdown-stat"><span class="label">Volume</span><span class="value" id="spot-volume">--</span></div>
            <div class="breakdown-stat"><span class="label">Trades</span><span class="value" id="spot-trades">--</span></div>
            <div class="breakdown-stat"><span class="label">Trading Fees</span><span class="value" id="spot-trading-fees">--</span></div>
          </div>
        </div>
        <!-- Crypto: Swap/Perp -->
        <div class="breakdown-card crypto-card" id="swap-card" style="display: none;">
          <div class="breakdown-header">
            <span class="market-name">Swap/Perp</span>
          </div>
          <div class="breakdown-stats">
            <div class="breakdown-stat"><span class="label">Volume</span><span class="value" id="swap-volume">--</span></div>
            <div class="breakdown-stat"><span class="label">Trades</span><span class="value" id="swap-trades">--</span></div>
            <div class="breakdown-stat"><span class="label">Trading Fees</span><span class="value" id="swap-trading-fees">--</span></div>
            <div class="breakdown-stat"><span class="label">Funding Fees</span><span class="value" id="swap-funding-fees">--</span></div>
          </div>
        </div>
        <!-- IBKR: Stocks -->
        <div class="breakdown-card ibkr-card" id="stocks-card" style="display: none;">
          <div class="breakdown-header">
            <span class="market-name">Stocks</span>
          </div>
          <div class="breakdown-stats">
            <div class="breakdown-stat"><span class="label">Equity</span><span class="value" id="stocks-equity">--</span></div>
            <div class="breakdown-stat"><span class="label">Volume</span><span class="value" id="stocks-volume">--</span></div>
            <div class="breakdown-stat"><span class="label">Trades</span><span class="value" id="stocks-trades">--</span></div>
            <div class="breakdown-stat"><span class="label">Trading Fees</span><span class="value" id="stocks-trading-fees">--</span></div>
          </div>
        </div>
        <!-- IBKR: CFD -->
        <div class="breakdown-card ibkr-card" id="cfd-card" style="display: none;">
          <div class="breakdown-header">
            <span class="market-name">CFD</span>
          </div>
          <div class="breakdown-stats">
            <div class="breakdown-stat"><span class="label">Volume</span><span class="value" id="cfd-volume">--</span></div>
            <div class="breakdown-stat"><span class="label">Trades</span><span class="value" id="cfd-trades">--</span></div>
            <div class="breakdown-stat"><span class="label">Trading Fees</span><span class="value" id="cfd-trading-fees">--</span></div>
          </div>
        </div>
        <!-- IBKR: Futures -->
        <div class="breakdown-card ibkr-card" id="futures-card" style="display: none;">
          <div class="breakdown-header">
            <span class="market-name">Futures</span>
          </div>
          <div class="breakdown-stats">
            <div class="breakdown-stat"><span class="label">Volume</span><span class="value" id="futures-volume">--</span></div>
            <div class="breakdown-stat"><span class="label">Trades</span><span class="value" id="futures-trades">--</span></div>
            <div class="breakdown-stat"><span class="label">Trading Fees</span><span class="value" id="futures-trading-fees">--</span></div>
          </div>
        </div>
        <!-- IBKR: Forex -->
        <div class="breakdown-card ibkr-card" id="forex-card" style="display: none;">
          <div class="breakdown-header">
            <span class="market-name">Forex</span>
          </div>
          <div class="breakdown-stats">
            <div class="breakdown-stat"><span class="label">Volume</span><span class="value" id="forex-volume">--</span></div>
            <div class="breakdown-stat"><span class="label">Trades</span><span class="value" id="forex-trades">--</span></div>
            <div class="breakdown-stat"><span class="label">Trading Fees</span><span class="value" id="forex-trading-fees">--</span></div>
          </div>
        </div>
        <!-- IBKR: Commodities -->
        <div class="breakdown-card ibkr-card" id="commodities-card" style="display: none;">
          <div class="breakdown-header">
            <span class="market-name">Commodities</span>
          </div>
          <div class="breakdown-stats">
            <div class="breakdown-stat"><span class="label">Equity</span><span class="value" id="commodities-equity">--</span></div>
            <div class="breakdown-stat"><span class="label">Volume</span><span class="value" id="commodities-volume">--</span></div>
            <div class="breakdown-stat"><span class="label">Trades</span><span class="value" id="commodities-trades">--</span></div>
            <div class="breakdown-stat"><span class="label">Trading Fees</span><span class="value" id="commodities-trading-fees">--</span></div>
          </div>
        </div>
        <!-- Shared: Options -->
        <div class="breakdown-card" id="options-card" style="display: none;">
          <div class="breakdown-header">
            <span class="market-name">Options</span>
          </div>
          <div class="breakdown-stats">
            <div class="breakdown-stat"><span class="label">Equity</span><span class="value" id="options-equity">--</span></div>
            <div class="breakdown-stat"><span class="label">Volume</span><span class="value" id="options-volume">--</span></div>
            <div class="breakdown-stat"><span class="label">Trades</span><span class="value" id="options-trades">--</span></div>
            <div class="breakdown-stat"><span class="label">Trading Fees</span><span class="value" id="options-trading-fees">--</span></div>
          </div>
        </div>
      </div>

      <!-- Equity Chart -->
      <div class="chart-container">
        <div class="chart-header">
          <h2>Equity Over Time</h2>
          <div class="chart-actions">
            <button class="btn btn-sm btn-secondary" onclick="setChartRange(30)">30D</button>
            <button class="btn btn-sm btn-secondary" onclick="setChartRange(90)">90D</button>
            <button class="btn btn-sm btn-secondary" onclick="setChartRange(180)">6M</button>
            <button class="btn btn-sm btn-secondary" onclick="setChartRange(365)">1Y</button>
            <button class="btn btn-sm btn-secondary" onclick="setChartRange(0)">All</button>
          </div>
        </div>
        <div class="chart-wrapper">
          <canvas id="equity-chart"></canvas>
        </div>
      </div>

      <!-- Volume Chart -->
      <div class="chart-container" id="volume-chart-section" style="display: none;">
        <div class="chart-header">
          <h2>Trading Volume</h2>
          <div class="chart-actions">
            <button class="btn btn-sm btn-secondary volume-mode active" onclick="setVolumeMode('volume')">Volume ($)</button>
            <button class="btn btn-sm btn-secondary volume-mode" onclick="setVolumeMode('orders')">Orders</button>
          </div>
        </div>
        <div class="chart-wrapper">
          <canvas id="volume-chart"></canvas>
        </div>
      </div>

      <!-- Logs -->
      <div class="logs-panel">
        <div class="logs-header">
          <button class="log-tab active" onclick="switchLogTab('request')">Request Logs</button>
          <button class="log-tab" onclick="switchLogTab('enclave')">Enclave Logs</button>
        </div>
        <div id="logs-content" class="logs-content">
          <div style="color: #8b949e;">Waiting for activity...</div>
        </div>
      </div>
    </main>
  </div>

  <!-- Create User Modal -->
  <div class="modal-overlay" id="create-user-modal">
    <div class="modal">
      <h2>Add Exchange Connection</h2>

      <div class="input-group" style="margin-bottom: 16px;">
        <label>Broker Type</label>
        <select id="modal-broker-type" onchange="updateModalFields()">
          <option value="crypto">Crypto Exchange</option>
          <option value="ibkr">Interactive Brokers (IBKR)</option>
          <option value="alpaca">Alpaca Markets</option>
        </select>
      </div>

      <div id="modal-crypto-fields">
        <div class="input-group" style="margin-bottom: 16px;">
          <label>Exchange</label>
          <select id="modal-crypto-exchange">
            <option value="binance">Binance</option>
            <option value="coinbase">Coinbase</option>
            <option value="bitget">Bitget</option>
            <option value="bybit">Bybit</option>
            <option value="okx">OKX</option>
          </select>
        </div>
        <div class="input-group" style="margin-bottom: 16px;">
          <label>Label</label>
          <input type="text" id="modal-crypto-label" value="Main Account" />
        </div>
        <div class="input-group" style="margin-bottom: 16px;">
          <label>API Key</label>
          <input type="text" id="modal-crypto-key" placeholder="Your API key" />
        </div>
        <div class="input-group" style="margin-bottom: 16px;">
          <label>API Secret</label>
          <input type="password" id="modal-crypto-secret" placeholder="Your API secret" />
        </div>
        <div class="input-group" style="margin-bottom: 16px;">
          <label>Passphrase (optional)</label>
          <input type="password" id="modal-crypto-passphrase" placeholder="Required for some exchanges" />
        </div>
      </div>

      <div id="modal-ibkr-fields" style="display: none;">
        <div class="input-group" style="margin-bottom: 16px;">
          <label>Label</label>
          <input type="text" id="modal-ibkr-label" value="IBKR Account" />
        </div>
        <div class="input-group" style="margin-bottom: 16px;">
          <label>Flex Token</label>
          <input type="password" id="modal-ibkr-token" placeholder="Flex Web Service Token" />
        </div>
        <div class="input-group" style="margin-bottom: 16px;">
          <label>Query ID</label>
          <input type="text" id="modal-ibkr-query" placeholder="Flex Query ID" />
        </div>
      </div>

      <div id="modal-alpaca-fields" style="display: none;">
        <div class="input-group" style="margin-bottom: 16px;">
          <label>Label</label>
          <input type="text" id="modal-alpaca-label" value="Alpaca Account" />
        </div>
        <div class="input-group" style="margin-bottom: 16px;">
          <label>API Key</label>
          <input type="text" id="modal-alpaca-key" placeholder="Your API key" />
        </div>
        <div class="input-group" style="margin-bottom: 16px;">
          <label>API Secret</label>
          <input type="password" id="modal-alpaca-secret" placeholder="Your API secret" />
        </div>
      </div>

      <div id="modal-response" class="response-box" style="display: none;"></div>

      <div class="modal-actions">
        <button class="btn btn-secondary" onclick="hideCreateUserModal()">Cancel</button>
        <button class="btn btn-primary" onclick="createUserConnection()">Create</button>
      </div>
    </div>
  </div>

  <script>
    // Global state
    let allSnapshots = [];
    let equityChart = null;
    let volumeChart = null;
    let volumeMode = 'volume'; // 'volume' or 'orders'
    let currentLogTab = 'request';
    let requestLogs = [];
    let enclaveLogs = [];

    // Initialize chart
    function initChart() {
      const ctx = document.getElementById('equity-chart').getContext('2d');
      equityChart = new Chart(ctx, {
        type: 'line',
        data: {
          datasets: [{
            label: 'Total Equity',
            data: [],
            borderColor: '#58a6ff',
            backgroundColor: 'rgba(88, 166, 255, 0.1)',
            fill: true,
            tension: 0.4,
            pointRadius: 0,
            pointHoverRadius: 6
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          interaction: {
            intersect: false,
            mode: 'index'
          },
          plugins: {
            legend: {
              display: false
            },
            tooltip: {
              backgroundColor: '#1a1f2e',
              titleColor: '#e4e6eb',
              bodyColor: '#e4e6eb',
              borderColor: '#2d3548',
              borderWidth: 1,
              padding: 12,
              displayColors: false,
              callbacks: {
                label: function(context) {
                  return '$' + context.parsed.y.toLocaleString(undefined, {minimumFractionDigits: 2, maximumFractionDigits: 2});
                }
              }
            }
          },
          scales: {
            x: {
              type: 'time',
              time: {
                unit: 'day',
                displayFormats: {
                  day: 'MMM d'
                }
              },
              grid: {
                color: 'rgba(255,255,255,0.05)'
              },
              ticks: {
                color: '#8b949e'
              }
            },
            y: {
              grid: {
                color: 'rgba(255,255,255,0.05)'
              },
              ticks: {
                color: '#8b949e',
                callback: function(value) {
                  return '$' + value.toLocaleString();
                }
              }
            }
          }
        }
      });
    }

    // Update chart with data
    function updateChart(snapshots, days = 0) {
      let filtered = snapshots;

      if (days > 0) {
        const cutoff = Date.now() - (days * 24 * 60 * 60 * 1000);
        filtered = snapshots.filter(s => {
          const ts = typeof s.timestamp === 'string' ? parseInt(s.timestamp) : s.timestamp;
          return ts >= cutoff;
        });
      }

      const data = filtered.map(s => ({
        x: new Date(typeof s.timestamp === 'string' ? parseInt(s.timestamp) : s.timestamp),
        y: parseFloat(s.total_equity || s.totalEquity || 0)
      })).sort((a, b) => a.x - b.x);

      equityChart.data.datasets[0].data = data;
      equityChart.update();
    }

    function setChartRange(days) {
      updateChart(allSnapshots, days);
    }

    // Initialize volume chart
    function initVolumeChart() {
      const ctx = document.getElementById('volume-chart').getContext('2d');
      volumeChart = new Chart(ctx, {
        type: 'bar',
        data: {
          datasets: [{
            label: 'Volume',
            data: [],
            backgroundColor: 'rgba(63, 185, 80, 0.6)',
            borderColor: '#3fb950',
            borderWidth: 1
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: { display: false },
            tooltip: {
              backgroundColor: '#1a1f2e',
              titleColor: '#e4e6eb',
              bodyColor: '#e4e6eb',
              borderColor: '#2d3548',
              borderWidth: 1,
              padding: 12,
              callbacks: {
                label: function(context) {
                  if (volumeMode === 'volume') {
                    return '$' + context.parsed.y.toLocaleString(undefined, {minimumFractionDigits: 2});
                  }
                  return context.parsed.y.toLocaleString() + ' orders';
                }
              }
            }
          },
          scales: {
            x: {
              type: 'time',
              time: { unit: 'day', displayFormats: { day: 'MMM d' } },
              grid: { color: 'rgba(255,255,255,0.05)' },
              ticks: { color: '#8b949e' }
            },
            y: {
              grid: { color: 'rgba(255,255,255,0.05)' },
              ticks: {
                color: '#8b949e',
                callback: function(value) {
                  if (volumeMode === 'volume') {
                    if (value >= 1000000) return '$' + (value/1000000).toFixed(1) + 'M';
                    if (value >= 1000) return '$' + (value/1000).toFixed(1) + 'K';
                    return '$' + value;
                  }
                  return value.toLocaleString();
                }
              }
            }
          }
        }
      });
    }

    // Update volume chart
    function updateVolumeChart(snapshots) {
      const hasBreakdown = snapshots.some(s => s.breakdown && s.breakdown.global);
      document.getElementById('volume-chart-section').style.display = hasBreakdown ? 'block' : 'none';

      if (!hasBreakdown || !volumeChart) return;

      const data = snapshots
        .filter(s => s.breakdown && s.breakdown.global)
        .map(s => ({
          x: new Date(typeof s.timestamp === 'string' ? parseInt(s.timestamp) : s.timestamp),
          y: volumeMode === 'volume'
            ? parseFloat(s.breakdown.global.volume || 0)
            : parseInt(s.breakdown.global.orders || s.breakdown.global.trades || 0)
        }))
        .sort((a, b) => a.x - b.x);

      volumeChart.data.datasets[0].data = data;
      volumeChart.data.datasets[0].label = volumeMode === 'volume' ? 'Volume ($)' : 'Orders';
      volumeChart.data.datasets[0].backgroundColor = volumeMode === 'volume'
        ? 'rgba(63, 185, 80, 0.6)'
        : 'rgba(88, 166, 255, 0.6)';
      volumeChart.data.datasets[0].borderColor = volumeMode === 'volume' ? '#3fb950' : '#58a6ff';
      volumeChart.update();
    }

    // Switch volume mode
    function setVolumeMode(mode) {
      volumeMode = mode;
      document.querySelectorAll('.volume-mode').forEach(btn => btn.classList.remove('active'));
      event.target.classList.add('active');
      updateVolumeChart(allSnapshots);
    }

    // Load snapshots
    async function loadSnapshots() {
      const userUid = document.getElementById('user-uid').value;
      const exchange = document.getElementById('exchange-filter').value;

      try {
        const response = await fetch('/api/snapshots', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            user_uid: userUid,
            exchange: exchange || undefined
          })
        });

        const data = await response.json();

        if (data.error) {
          addLog('error', 'Failed to load snapshots: ' + data.error);
          return;
        }

        allSnapshots = data.snapshots || [];
        addLog('info', 'Loaded ' + allSnapshots.length + ' snapshots');

        // Update stats
        updateStats(allSnapshots);

        // Update charts
        updateChart(allSnapshots);
        updateVolumeChart(allSnapshots);

      } catch (error) {
        addLog('error', 'Error: ' + error.message);
      }
    }

    // Update stats cards
    function updateStats(snapshots) {
      if (snapshots.length === 0) {
        document.getElementById('stat-equity').textContent = '--';
        document.getElementById('stat-realized').textContent = '--';
        document.getElementById('stat-unrealized').textContent = '--';
        document.getElementById('stat-snapshots').textContent = '0';
        document.getElementById('stat-date-range').textContent = '';
        return;
      }

      // Sort by timestamp
      const sorted = [...snapshots].sort((a, b) => {
        const tsA = typeof a.timestamp === 'string' ? parseInt(a.timestamp) : a.timestamp;
        const tsB = typeof b.timestamp === 'string' ? parseInt(b.timestamp) : b.timestamp;
        return tsB - tsA;
      });

      const latest = sorted[0];
      const oldest = sorted[sorted.length - 1];

      const equity = parseFloat(latest.total_equity || latest.totalEquity || 0);
      const realized = parseFloat(latest.realized_balance || latest.realizedBalance || 0);
      const unrealized = parseFloat(latest.unrealized_pnl || latest.unrealizedPnL || 0);

      document.getElementById('stat-equity').textContent = '$' + equity.toLocaleString(undefined, {minimumFractionDigits: 2, maximumFractionDigits: 2});
      document.getElementById('stat-realized').textContent = '$' + realized.toLocaleString(undefined, {minimumFractionDigits: 2, maximumFractionDigits: 2});
      document.getElementById('stat-unrealized').textContent = '$' + unrealized.toLocaleString(undefined, {minimumFractionDigits: 2, maximumFractionDigits: 2});
      document.getElementById('stat-snapshots').textContent = snapshots.length.toString();

      // Date range
      const firstDate = new Date(typeof oldest.timestamp === 'string' ? parseInt(oldest.timestamp) : oldest.timestamp);
      const lastDate = new Date(typeof latest.timestamp === 'string' ? parseInt(latest.timestamp) : latest.timestamp);
      document.getElementById('stat-date-range').textContent = firstDate.toLocaleDateString() + ' - ' + lastDate.toLocaleDateString();

      // Calculate change if we have enough data
      if (sorted.length >= 2) {
        const previous = sorted[1];
        const prevEquity = parseFloat(previous.total_equity || previous.totalEquity || 0);
        if (prevEquity > 0) {
          const change = ((equity - prevEquity) / prevEquity) * 100;
          const changeEl = document.getElementById('stat-equity-change');
          changeEl.textContent = (change >= 0 ? '+' : '') + change.toFixed(2) + '%';
          changeEl.className = 'change ' + (change >= 0 ? 'positive' : 'negative');
        }
      }

      // Update market breakdown
      updateBreakdown(snapshots);
    }

    // Format large numbers
    function formatNumber(num) {
      if (num >= 1000000) return (num / 1000000).toFixed(2) + 'M';
      if (num >= 1000) return (num / 1000).toFixed(2) + 'K';
      return num.toFixed(2);
    }

    // Update breakdown section - supports both crypto (spot/swap) and traditional (stocks/cfd/futures)
    function updateBreakdown(snapshots) {
      // Categories: crypto = spot/swap, traditional = stocks/cfd/futures/forex/commodities
      const categories = ['global', 'spot', 'swap', 'stocks', 'cfd', 'futures', 'forex', 'commodities', 'options'];
      const totals = {};
      categories.forEach(cat => {
        totals[cat] = { equity: 0, volume: 0, trades: 0, trading_fees: 0, funding_fees: 0 };
      });

      let hasBreakdown = false;

      snapshots.forEach(snapshot => {
        const b = snapshot.breakdown;
        if (!b) return;
        hasBreakdown = true;

        categories.forEach(cat => {
          if (b[cat]) {
            totals[cat].equity += parseFloat(b[cat].equity || 0);
            totals[cat].volume += parseFloat(b[cat].volume || 0);
            totals[cat].trades += parseInt(b[cat].trades || 0);
            totals[cat].trading_fees += parseFloat(b[cat].trading_fees || 0);
            totals[cat].funding_fees += parseFloat(b[cat].funding_fees || 0);
          }
        });
      });

      // Show/hide breakdown section
      const section = document.getElementById('breakdown-section');
      section.style.display = hasBreakdown ? 'grid' : 'none';

      if (!hasBreakdown) return;

      // Global - always show if breakdown exists
      document.getElementById('global-volume').textContent = '$' + formatNumber(totals.global.volume);
      document.getElementById('global-trades').textContent = totals.global.trades.toLocaleString();
      document.getElementById('global-trading-fees').textContent = '$' + formatNumber(totals.global.trading_fees);
      document.getElementById('global-funding-fees').textContent = '$' + formatNumber(totals.global.funding_fees);
      document.getElementById('global-card').style.display = 'block';

      // Helper to update and show/hide a category card
      function updateCategoryCard(cat, hasEquity = false) {
        const card = document.getElementById(cat + '-card');
        if (!card) return;

        const hasData = totals[cat].volume > 0 || totals[cat].trades > 0 || totals[cat].equity > 0;
        if (hasData) {
          if (hasEquity) {
            const eqEl = document.getElementById(cat + '-equity');
            if (eqEl) eqEl.textContent = '$' + formatNumber(totals[cat].equity);
          }
          document.getElementById(cat + '-volume').textContent = '$' + formatNumber(totals[cat].volume);
          document.getElementById(cat + '-trades').textContent = totals[cat].trades.toLocaleString();
          document.getElementById(cat + '-trading-fees').textContent = '$' + formatNumber(totals[cat].trading_fees);
          const ffEl = document.getElementById(cat + '-funding-fees');
          if (ffEl) ffEl.textContent = '$' + formatNumber(totals[cat].funding_fees);
          card.style.display = 'block';
        } else {
          card.style.display = 'none';
        }
      }

      // Crypto categories
      updateCategoryCard('spot', false);
      updateCategoryCard('swap', false);

      // IBKR/Traditional categories
      updateCategoryCard('stocks', true);     // Has equity from stockValue
      updateCategoryCard('cfd', false);       // No equity data from IBKR
      updateCategoryCard('futures', false);   // No equity data from IBKR
      updateCategoryCard('forex', false);     // No equity data from IBKR
      updateCategoryCard('commodities', true); // Has equity from commodityValue

      // Options (shared, with equity)
      updateCategoryCard('options', true);
    }

    // Run sync (type is automatic based on exchange)
    async function runSync() {
      const userUid = document.getElementById('user-uid').value;
      const exchange = document.getElementById('exchange-filter').value;

      addLog('info', 'Starting sync for ' + (exchange || 'all exchanges') + '...');

      try {
        const response = await fetch('/api/sync', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            user_uid: userUid,
            exchange: exchange || undefined
          })
        });

        const data = await response.json();

        if (data.error) {
          addLog('error', 'Sync failed: ' + data.error);
        } else {
          addLog('info', 'Sync completed: ' + (data.message || JSON.stringify(data)));
          // Reload snapshots after sync
          setTimeout(loadSnapshots, 1000);
        }
      } catch (error) {
        addLog('error', 'Sync error: ' + error.message);
      }
    }

    // Health check
    async function checkHealth() {
      try {
        const response = await fetch('/api/health');
        const data = await response.json();

        const statusEl = document.getElementById('health-status');
        const isHealthy = data.status === 0 || data.status === '0' || data.status === 'HEALTHY';

        if (isHealthy) {
          statusEl.className = 'status-badge healthy';
          statusEl.innerHTML = '<span class="status-dot"></span>Healthy';
          addLog('info', 'Health check: OK');
        } else {
          statusEl.className = 'status-badge error';
          statusEl.innerHTML = '<span class="status-dot"></span>Error';
          addLog('error', 'Health check: FAILED');
        }
      } catch (error) {
        const statusEl = document.getElementById('health-status');
        statusEl.className = 'status-badge error';
        statusEl.innerHTML = '<span class="status-dot"></span>Offline';
        addLog('error', 'Health check error: ' + error.message);
      }
    }

    // Logging
    function addLog(level, message) {
      const timestamp = new Date().toLocaleTimeString();
      const log = { timestamp, level, message };

      if (currentLogTab === 'request') {
        requestLogs.push(log);
        if (requestLogs.length > 200) requestLogs.shift();
      }

      renderLogs();
    }

    function renderLogs() {
      const container = document.getElementById('logs-content');
      const logs = currentLogTab === 'request' ? requestLogs : enclaveLogs;

      if (logs.length === 0) {
        container.innerHTML = '<div style="color: #8b949e;">Waiting for activity...</div>';
        return;
      }

      container.innerHTML = logs.map(log => {
        const levelClass = log.level || 'info';
        return '<div class="log-entry ' + levelClass + '">[' + log.timestamp + '] ' + log.message + '</div>';
      }).join('');

      container.scrollTop = container.scrollHeight;
    }

    function switchLogTab(tab) {
      currentLogTab = tab;
      document.querySelectorAll('.log-tab').forEach(t => t.classList.remove('active'));
      event.target.classList.add('active');
      renderLogs();
    }

    // Modal functions
    function showCreateUserModal() {
      document.getElementById('create-user-modal').classList.add('show');
    }

    function hideCreateUserModal() {
      document.getElementById('create-user-modal').classList.remove('show');
      document.getElementById('modal-response').style.display = 'none';
    }

    function updateModalFields() {
      const type = document.getElementById('modal-broker-type').value;
      document.getElementById('modal-crypto-fields').style.display = type === 'crypto' ? 'block' : 'none';
      document.getElementById('modal-ibkr-fields').style.display = type === 'ibkr' ? 'block' : 'none';
      document.getElementById('modal-alpaca-fields').style.display = type === 'alpaca' ? 'block' : 'none';
    }

    async function createUserConnection() {
      const type = document.getElementById('modal-broker-type').value;
      let request = {};

      if (type === 'crypto') {
        request = {
          exchange: document.getElementById('modal-crypto-exchange').value,
          label: document.getElementById('modal-crypto-label').value,
          api_key: document.getElementById('modal-crypto-key').value,
          api_secret: document.getElementById('modal-crypto-secret').value,
          passphrase: document.getElementById('modal-crypto-passphrase').value
        };
      } else if (type === 'ibkr') {
        request = {
          exchange: 'ibkr',
          label: document.getElementById('modal-ibkr-label').value,
          api_key: document.getElementById('modal-ibkr-token').value,
          api_secret: document.getElementById('modal-ibkr-query').value
        };
      } else if (type === 'alpaca') {
        request = {
          exchange: 'alpaca',
          label: document.getElementById('modal-alpaca-label').value,
          api_key: document.getElementById('modal-alpaca-key').value,
          api_secret: document.getElementById('modal-alpaca-secret').value
        };
      }

      try {
        const response = await fetch('/api/create-user', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(request)
        });

        const data = await response.json();
        const responseBox = document.getElementById('modal-response');
        responseBox.style.display = 'block';

        if (data.error) {
          responseBox.className = 'response-box error';
          responseBox.textContent = 'Error: ' + data.error;
        } else {
          responseBox.className = 'response-box success';
          responseBox.textContent = 'Success! User UID: ' + data.user_uid;
          document.getElementById('user-uid').value = data.user_uid;
          addLog('info', 'Created connection: ' + data.user_uid);
        }
      } catch (error) {
        const responseBox = document.getElementById('modal-response');
        responseBox.style.display = 'block';
        responseBox.className = 'response-box error';
        responseBox.textContent = 'Error: ' + error.message;
      }
    }

    // SSE for enclave logs
    function connectEnclaveSSE() {
      try {
        const eventSource = new EventSource('/api/enclave-logs/stream');

        eventSource.onmessage = (event) => {
          try {
            const data = JSON.parse(event.data);
            if (data.type === 'connected' || data.type === 'error') return;

            const parsed = JSON.parse(event.data);
            const timestamp = new Date(parsed.timestamp).toLocaleTimeString();
            enclaveLogs.push({
              timestamp,
              level: (parsed.level || 'info').toLowerCase(),
              message: parsed.message + (parsed.metadata ? ' ' + JSON.stringify(parsed.metadata) : '')
            });

            if (enclaveLogs.length > 200) enclaveLogs.shift();
            if (currentLogTab === 'enclave') renderLogs();
          } catch (e) {
            // Raw log
            enclaveLogs.push({
              timestamp: new Date().toLocaleTimeString(),
              level: 'info',
              message: event.data
            });
            if (currentLogTab === 'enclave') renderLogs();
          }
        };
      } catch (error) {
        console.error('SSE connection failed:', error);
      }
    }

    // Initialize
    document.addEventListener('DOMContentLoaded', () => {
      initChart();
      initVolumeChart();
      checkHealth();
      loadSnapshots();
      connectEnclaveSSE();

      // Auto-refresh health every 30s
      setInterval(checkHealth, 30000);
    });
  </script>
</body>
</html>
  `);
});

app.listen(PORT, () => {
  console.log(`\n🚀 Track Record Dashboard`);
  console.log(`📍 Open in browser: http://localhost:${PORT}`);
  console.log(`🔗 gRPC Server: localhost:50051 (TLS)`);
  console.log(`🔌 Enclave Log Server: http://localhost:50052/logs/stream (SSE real-time)\n`);
});

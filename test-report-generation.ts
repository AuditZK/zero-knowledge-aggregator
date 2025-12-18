/**
 * Test Script for Report Generation gRPC Endpoint
 *
 * Tests the GenerateSignedReport and VerifyReportSignature RPCs
 *
 * Usage:
 *   npx ts-node test-report-generation.ts
 *
 * Make sure the enclave server is running:
 *   npm run dev (or GRPC_INSECURE=true npm run dev for development)
 */

import * as grpc from '@grpc/grpc-js';
import * as protoLoader from '@grpc/proto-loader';
import path from 'path';

// Configuration
const GRPC_HOST = process.env.GRPC_HOST || 'localhost';
const GRPC_PORT = process.env.GRPC_PORT || '50051';
const TEST_USER_UID = process.env.TEST_USER_UID || 'b26e86aa-d7e0-471a-ad0e-9cf7e5106660';

// Load proto
const PROTO_PATH = path.join(__dirname, 'src/proto/enclave.proto');
const packageDefinition = protoLoader.loadSync(PROTO_PATH, {
  keepCase: true,
  longs: String,
  enums: String,
  defaults: true,
  oneofs: true
});

const enclaveProto = grpc.loadPackageDefinition(packageDefinition) as any;

// Create client
const client = new enclaveProto.enclave.EnclaveService(
  `${GRPC_HOST}:${GRPC_PORT}`,
  grpc.credentials.createInsecure()
);

// Promisify gRPC calls
function promisify<T>(fn: (request: any, callback: (error: Error | null, response: T) => void) => void, request: any): Promise<T> {
  return new Promise((resolve, reject) => {
    fn.call(client, request, (error: Error | null, response: T) => {
      if (error) reject(error);
      else resolve(response);
    });
  });
}

// Test functions
async function testHealthCheck(): Promise<boolean> {
  console.log('\n=== Health Check ===');
  try {
    const response = await promisify<any>(client.HealthCheck, {});
    console.log('Status:', response.status === '0' || response.status === 0 ? 'HEALTHY' : 'UNHEALTHY');
    console.log('Enclave:', response.enclave);
    console.log('Version:', response.version);
    console.log('Uptime:', response.uptime, 'seconds');
    return true;
  } catch (error) {
    console.error('Health check failed:', error);
    return false;
  }
}

async function testGenerateSignedReport(userUid: string, options: {
  benchmark?: string;
  includeRiskMetrics?: boolean;
  includeDrawdown?: boolean;
  startDate?: string;
  endDate?: string;
} = {}): Promise<any> {
  console.log('\n=== Generate Signed Report ===');
  console.log('User UID:', userUid);
  console.log('Options:', options);

  try {
    const request = {
      user_uid: userUid,
      start_date: options.startDate || '',
      end_date: options.endDate || '',
      benchmark: options.benchmark || '',
      include_risk_metrics: options.includeRiskMetrics || false,
      include_drawdown: options.includeDrawdown || false,
      report_name: 'Test Report',
      base_currency: 'USD'
    };

    const response = await promisify<any>(client.GenerateSignedReport, request);

    if (!response.success) {
      console.error('Report generation failed:', response.error);
      return null;
    }

    console.log('\n--- Report Metadata ---');
    console.log('Report ID:', response.report_id);
    console.log('Generated At:', response.generated_at);
    console.log('Period:', response.period_start, '->', response.period_end);
    console.log('Data Points:', response.data_points);
    console.log('Benchmark:', response.benchmark || 'None');

    console.log('\n--- Core Metrics ---');
    console.log('Total Return:', (response.total_return * 100).toFixed(2) + '%');
    console.log('Annualized Return:', (response.annualized_return * 100).toFixed(2) + '%');
    console.log('Volatility:', (response.volatility * 100).toFixed(2) + '%');
    console.log('Sharpe Ratio:', response.sharpe_ratio?.toFixed(3) || 'N/A');
    console.log('Sortino Ratio:', response.sortino_ratio?.toFixed(3) || 'N/A');
    console.log('Max Drawdown:', (response.max_drawdown * 100).toFixed(2) + '%');
    console.log('Calmar Ratio:', response.calmar_ratio?.toFixed(3) || 'N/A');

    if (options.includeRiskMetrics && response.var_95) {
      console.log('\n--- Risk Metrics ---');
      console.log('VaR 95%:', (response.var_95 * 100).toFixed(2) + '%');
      console.log('VaR 99%:', (response.var_99 * 100).toFixed(2) + '%');
      console.log('Expected Shortfall:', (response.expected_shortfall * 100).toFixed(2) + '%');
      console.log('Skewness:', response.skewness?.toFixed(3) || 'N/A');
      console.log('Kurtosis:', response.kurtosis?.toFixed(3) || 'N/A');
    }

    if (options.benchmark && response.alpha) {
      console.log('\n--- Benchmark Metrics ---');
      console.log('Alpha:', (response.alpha * 100).toFixed(2) + '%');
      console.log('Beta:', response.beta?.toFixed(3) || 'N/A');
      console.log('Information Ratio:', response.information_ratio?.toFixed(3) || 'N/A');
      console.log('Tracking Error:', (response.tracking_error * 100).toFixed(2) + '%');
      console.log('Correlation:', response.correlation?.toFixed(3) || 'N/A');
    }

    if (options.includeDrawdown && response.drawdown_periods?.length > 0) {
      console.log('\n--- Drawdown Periods ---');
      response.drawdown_periods.forEach((period: any, i: number) => {
        console.log(`  ${i + 1}. ${period.start_date} -> ${period.end_date}: ${(period.depth * 100).toFixed(2)}% (${period.duration} days, ${period.recovered ? 'recovered' : 'not recovered'})`);
      });
    }

    console.log('\n--- Chart Data ---');
    console.log('Daily Returns:', response.daily_returns?.length || 0, 'data points');
    console.log('Monthly Returns:', response.monthly_returns?.length || 0, 'data points');

    if (response.daily_returns?.length > 0) {
      console.log('First daily:', response.daily_returns[0]);
      console.log('Last daily:', response.daily_returns[response.daily_returns.length - 1]);
    }

    console.log('\n--- Cryptographic Signature ---');
    console.log('Signature Algorithm:', response.signature_algorithm);
    console.log('Report Hash:', response.report_hash?.substring(0, 32) + '...');
    console.log('Signature:', response.signature?.substring(0, 32) + '...');
    console.log('Public Key:', response.public_key?.substring(0, 32) + '...');

    console.log('\n--- Enclave Attestation ---');
    console.log('Enclave Version:', response.enclave_version);
    console.log('Enclave Mode:', response.enclave_mode);
    console.log('Attestation ID:', response.attestation_id || 'N/A');

    return response;
  } catch (error) {
    console.error('Generate report failed:', error);
    return null;
  }
}

async function testVerifySignature(reportHash: string, signature: string, publicKey: string): Promise<boolean> {
  console.log('\n=== Verify Report Signature ===');
  console.log('Hash:', reportHash.substring(0, 32) + '...');

  try {
    const request = {
      report_hash: reportHash,
      signature: signature,
      public_key: publicKey
    };

    const response = await promisify<any>(client.VerifyReportSignature, request);

    console.log('Valid:', response.valid);
    if (response.error) {
      console.log('Error:', response.error);
    }

    return response.valid;
  } catch (error) {
    console.error('Verify signature failed:', error);
    return false;
  }
}

// Main test runner
async function main() {
  console.log('========================================');
  console.log('Report Generation Test Script');
  console.log('========================================');
  console.log(`Connecting to ${GRPC_HOST}:${GRPC_PORT}`);
  console.log(`Test User UID: ${TEST_USER_UID}`);

  // 1. Health check
  const healthy = await testHealthCheck();
  if (!healthy) {
    console.error('\nServer is not healthy, aborting tests');
    process.exit(1);
  }

  // 2. Basic report (no benchmark, no risk metrics)
  console.log('\n\n========================================');
  console.log('Test 1: Basic Report (no options)');
  console.log('========================================');
  const basicReport = await testGenerateSignedReport(TEST_USER_UID);

  // 3. Report with risk metrics
  console.log('\n\n========================================');
  console.log('Test 2: Report with Risk Metrics');
  console.log('========================================');
  await testGenerateSignedReport(TEST_USER_UID, {
    includeRiskMetrics: true,
    includeDrawdown: true
  });

  // 4. Report with benchmark (SPY)
  console.log('\n\n========================================');
  console.log('Test 3: Report with SPY Benchmark');
  console.log('========================================');
  await testGenerateSignedReport(TEST_USER_UID, {
    benchmark: 'SPY',
    includeRiskMetrics: true,
    includeDrawdown: true
  });

  // 5. Verify signature
  if (basicReport && basicReport.report_hash && basicReport.signature && basicReport.public_key) {
    console.log('\n\n========================================');
    console.log('Test 4: Verify Report Signature');
    console.log('========================================');
    const isValid = await testVerifySignature(
      basicReport.report_hash,
      basicReport.signature,
      basicReport.public_key
    );
    console.log('\nSignature verification:', isValid ? 'PASSED' : 'FAILED');

    // Test with tampered hash
    console.log('\n--- Testing tampered hash ---');
    const tamperedHash = basicReport.report_hash.replace(/[0-9]/g, '0');
    const tamperedValid = await testVerifySignature(
      tamperedHash,
      basicReport.signature,
      basicReport.public_key
    );
    console.log('Tampered signature verification:', tamperedValid ? 'FAILED (should reject)' : 'PASSED (correctly rejected)');
  }

  console.log('\n\n========================================');
  console.log('All Tests Complete');
  console.log('========================================');
}

main().catch(console.error);

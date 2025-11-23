#!/usr/bin/env ts-node
/**
 * Interactive gRPC API Tester
 *
 * Usage:
 *   npm run test-api           # Run all tests
 *   ts-node test-api.ts        # Direct execution
 */

import * as grpc from '@grpc/grpc-js';
import * as protoLoader from '@grpc/proto-loader';
import path from 'path';

// Configuration
const PROTO_PATH = path.join(__dirname, 'src/proto/enclave.proto');
const SERVER_ADDRESS = 'localhost:50051';

// Load proto
const packageDefinition = protoLoader.loadSync(PROTO_PATH, {
  keepCase: true,
  longs: String,
  enums: String,
  defaults: true,
  oneofs: true
});

const protoDescriptor = grpc.loadPackageDefinition(packageDefinition) as any;
const client = new protoDescriptor.enclave.EnclaveService(
  SERVER_ADDRESS,
  grpc.credentials.createInsecure()
);

// Color output
const colors = {
  reset: '\x1b[0m',
  green: '\x1b[32m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  cyan: '\x1b[36m'
};

function log(color: keyof typeof colors, message: string) {
  console.log(`${colors[color]}${message}${colors.reset}`);
}

function logSection(title: string) {
  console.log('\n' + '='.repeat(60));
  log('cyan', `  ${title}`);
  console.log('='.repeat(60) + '\n');
}

// Test functions
async function testHealthCheck() {
  logSection('TEST 1: Health Check');

  return new Promise((resolve, reject) => {
    client.HealthCheck({}, (error: any, response: any) => {
      if (error) {
        log('red', `❌ Error: ${error.message}`);
        reject(error);
      } else {
        log('green', '✅ Success');
        console.log(JSON.stringify(response, null, 2));
        resolve(response);
      }
    });
  });
}

async function testProcessSyncJob() {
  logSection('TEST 2: Process Sync Job (Incremental)');

  const request = {
    user_uid: '550e8400-e29b-41d4-a716-446655440000',
    type: 'INCREMENTAL'
  };

  log('yellow', 'Request:');
  console.log(JSON.stringify(request, null, 2));
  console.log();

  return new Promise((resolve, reject) => {
    client.ProcessSyncJob(request, (error: any, response: any) => {
      if (error) {
        log('red', `❌ Error: ${error.message}`);
        console.log('Details:', error.details);
        reject(error);
      } else {
        log('green', '✅ Success');
        console.log(JSON.stringify(response, null, 2));
        resolve(response);
      }
    });
  });
}

async function testProcessSyncJobWithExchange() {
  logSection('TEST 3: Process Sync Job (Specific Exchange)');

  const request = {
    user_uid: '550e8400-e29b-41d4-a716-446655440000',
    type: 'INCREMENTAL',
    exchange: 'binance'
  };

  log('yellow', 'Request:');
  console.log(JSON.stringify(request, null, 2));
  console.log();

  return new Promise((resolve, reject) => {
    client.ProcessSyncJob(request, (error: any, response: any) => {
      if (error) {
        log('red', `❌ Error: ${error.message}`);
        console.log('Details:', error.details);
        reject(error);
      } else {
        log('green', '✅ Success');
        console.log(JSON.stringify(response, null, 2));
        resolve(response);
      }
    });
  });
}

async function testProcessSyncJobHistorical() {
  logSection('TEST 4: Process Sync Job (Historical)');

  const now = Date.now();
  const oneDayAgo = now - (24 * 60 * 60 * 1000);

  const request = {
    user_uid: '550e8400-e29b-41d4-a716-446655440000',
    type: 'HISTORICAL',
    exchange: 'binance',
    start_date: oneDayAgo.toString(),
    end_date: now.toString()
  };

  log('yellow', 'Request:');
  console.log(JSON.stringify(request, null, 2));
  console.log();

  return new Promise((resolve, reject) => {
    client.ProcessSyncJob(request, (error: any, response: any) => {
      if (error) {
        log('red', `❌ Error: ${error.message}`);
        console.log('Details:', error.details);
        reject(error);
      } else {
        log('green', '✅ Success');
        console.log(JSON.stringify(response, null, 2));
        resolve(response);
      }
    });
  });
}

async function testGetAggregatedMetrics() {
  logSection('TEST 5: Get Aggregated Metrics (All Exchanges)');

  const request = {
    user_uid: '550e8400-e29b-41d4-a716-446655440000'
  };

  log('yellow', 'Request:');
  console.log(JSON.stringify(request, null, 2));
  console.log();

  return new Promise((resolve, reject) => {
    client.GetAggregatedMetrics(request, (error: any, response: any) => {
      if (error) {
        log('red', `❌ Error: ${error.message}`);
        console.log('Details:', error.details);
        reject(error);
      } else {
        log('green', '✅ Success');
        console.log(JSON.stringify(response, null, 2));
        resolve(response);
      }
    });
  });
}

async function testGetAggregatedMetricsWithExchange() {
  logSection('TEST 6: Get Aggregated Metrics (Specific Exchange)');

  const request = {
    user_uid: '550e8400-e29b-41d4-a716-446655440000',
    exchange: 'binance'
  };

  log('yellow', 'Request:');
  console.log(JSON.stringify(request, null, 2));
  console.log();

  return new Promise((resolve, reject) => {
    client.GetAggregatedMetrics(request, (error: any, response: any) => {
      if (error) {
        log('red', `❌ Error: ${error.message}`);
        console.log('Details:', error.details);
        reject(error);
      } else {
        log('green', '✅ Success');
        console.log(JSON.stringify(response, null, 2));
        resolve(response);
      }
    });
  });
}

// Main execution
async function runAllTests() {
  log('blue', '\n🚀 Starting Enclave gRPC API Tests\n');
  log('cyan', `Server: ${SERVER_ADDRESS}`);
  log('cyan', `Proto: ${PROTO_PATH}\n`);

  let passed = 0;
  let failed = 0;

  const tests = [
    { name: 'Health Check', fn: testHealthCheck },
    { name: 'Process Sync Job', fn: testProcessSyncJob },
    { name: 'Process Sync Job (Exchange)', fn: testProcessSyncJobWithExchange },
    { name: 'Process Sync Job (Historical)', fn: testProcessSyncJobHistorical },
    { name: 'Get Aggregated Metrics', fn: testGetAggregatedMetrics },
    { name: 'Get Aggregated Metrics (Exchange)', fn: testGetAggregatedMetricsWithExchange }
  ];

  for (const test of tests) {
    try {
      await test.fn();
      passed++;
      await new Promise(resolve => setTimeout(resolve, 500)); // Small delay between tests
    } catch (error) {
      failed++;
      // Error already logged in test function
    }
  }

  // Summary
  logSection('Test Summary');
  log('green', `✅ Passed: ${passed}`);
  if (failed > 0) {
    log('red', `❌ Failed: ${failed}`);
  }
  log('cyan', `Total: ${passed + failed}`);

  console.log('\n');
  process.exit(failed > 0 ? 1 : 0);
}

// Run tests
runAllTests().catch((error) => {
  log('red', `\n❌ Fatal error: ${error.message}`);
  process.exit(1);
});

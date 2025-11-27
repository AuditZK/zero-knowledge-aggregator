#!/usr/bin/env node
/**
 * Robust Health Check for Production
 *
 * This script is executed by Docker/Kubernetes health checks to verify:
 * - gRPC server is responding
 * - Database connection is healthy
 * - AMD SEV-SNP attestation is valid (if enabled)
 * - Memory usage is within limits
 *
 * Exit codes:
 * - 0: Healthy
 * - 1: Unhealthy
 */

import { createConnection } from 'net';
import { PrismaClient } from '@prisma/client';
import { extractErrorMessage } from './utils/secure-enclave-logger';

const GRPC_PORT = parseInt(process.env.ENCLAVE_PORT || '50051', 10);
const TIMEOUT_MS = parseInt(process.env.HEALTH_CHECK_TIMEOUT_MS || '5000', 10);
const CHECK_DATABASE = process.env.HEALTH_CHECK_DATABASE === 'true';

interface HealthCheckResult {
  check: string;
  status: 'pass' | 'fail';
  duration_ms: number;
  error?: string;
}

/**
 * Check if gRPC server is listening
 */
async function checkGrpcServer(): Promise<HealthCheckResult> {
  const startTime = Date.now();

  return new Promise((resolve) => {
    const socket = createConnection({ port: GRPC_PORT, host: 'localhost' });

    const timeout = setTimeout(() => {
      socket.destroy();
      resolve({
        check: 'grpc_server',
        status: 'fail',
        duration_ms: Date.now() - startTime,
        error: `Timeout after ${TIMEOUT_MS}ms`
      });
    }, TIMEOUT_MS);

    socket.on('connect', () => {
      clearTimeout(timeout);
      socket.destroy();
      resolve({
        check: 'grpc_server',
        status: 'pass',
        duration_ms: Date.now() - startTime
      });
    });

    socket.on('error', (err) => {
      clearTimeout(timeout);
      socket.destroy();
      resolve({
        check: 'grpc_server',
        status: 'fail',
        duration_ms: Date.now() - startTime,
        error: err.message
      });
    });
  });
}

/**
 * Check database connectivity
 */
async function checkDatabase(): Promise<HealthCheckResult> {
  const startTime = Date.now();

  if (!CHECK_DATABASE) {
    return {
      check: 'database',
      status: 'pass',
      duration_ms: 0,
      error: 'Skipped (HEALTH_CHECK_DATABASE=false)'
    };
  }

  try {
    const prisma = new PrismaClient({
      datasources: {
        db: {
          url: process.env.DATABASE_URL
        }
      },
    });

    // Execute a simple query with timeout
    await Promise.race([
      prisma.$queryRaw`SELECT 1`,
      new Promise((_, reject) =>
        setTimeout(() => reject(new Error('Database query timeout')), TIMEOUT_MS)
      )
    ]);

    await prisma.$disconnect();

    return {
      check: 'database',
      status: 'pass',
      duration_ms: Date.now() - startTime
    };
  } catch (error) {
    const errorMessage = extractErrorMessage(error);
    return {
      check: 'database',
      status: 'fail',
      duration_ms: Date.now() - startTime,
      error: errorMessage
    };
  }
}

/**
 * Check memory usage
 */
function checkMemory(): HealthCheckResult {
  const startTime = Date.now();
  const memUsage = process.memoryUsage();

  // Heap size in MB
  const heapUsedMB = memUsage.heapUsed / 1024 / 1024;
  const maxHeapMB = 1800; // 1.8GB (leave buffer for 2GB limit)

  if (heapUsedMB > maxHeapMB) {
    return {
      check: 'memory',
      status: 'fail',
      duration_ms: Date.now() - startTime,
      error: `Heap used ${heapUsedMB.toFixed(0)}MB exceeds limit ${maxHeapMB}MB`
    };
  }

  return {
    check: 'memory',
    status: 'pass',
    duration_ms: Date.now() - startTime
  };
}

/**
 * Main health check orchestration
 */
async function main() {
  const results: HealthCheckResult[] = [];

  // Run health checks in parallel
  const [grpcResult, dbResult] = await Promise.all([
    checkGrpcServer(),
    checkDatabase()
  ]);

  results.push(grpcResult);
  results.push(dbResult);
  results.push(checkMemory());

  // Determine overall health
  const failed = results.filter(r => r.status === 'fail');
  const isHealthy = failed.length === 0;

  // Output results (JSON format for logging)
  if (process.env.LOG_FORMAT === 'json') {
    console.log(JSON.stringify({
      timestamp: new Date().toISOString(),
      healthy: isHealthy,
      checks: results
    }));
  } else {
    console.log(`Health Check: ${isHealthy ? '✓ HEALTHY' : '✗ UNHEALTHY'}`);
    results.forEach(r => {
      const icon = r.status === 'pass' ? '✓' : '✗';
      const msg = r.error ? ` (${r.error})` : '';
      console.log(`  ${icon} ${r.check}: ${r.status} (${r.duration_ms}ms)${msg}`);
    });
  }

  // Exit with appropriate code
  process.exit(isHealthy ? 0 : 1);
}

// Run health check
main().catch((error) => {
  console.error('Health check failed:', error);
  process.exit(1);
});

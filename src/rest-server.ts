import express from 'express';
import { container } from 'tsyringe';
import { EnclaveWorker } from './enclave-worker';
import { CreateUserConnectionRequestSchema } from './validation/grpc-schemas';
import { getLogger } from './utils/secure-enclave-logger';

const logger = getLogger('REST-Server');
const app = express();

// Middleware
app.use(express.json());

// Health check endpoint
app.get('/health', (_req, res) => {
  res.json({ status: 'ok', service: 'enclave-rest' });
});

/**
 * POST /api/v1/credentials/connect
 * Auditable credential submission endpoint
 *
 * User sends exchange credentials directly to enclave via simple curl/HTTP POST.
 * JSON payload is fully visible (auditable), credentials encrypted with AES-256-GCM.
 */
app.post('/api/v1/credentials/connect', async (req, res) => {
  try {
    // Validate request with existing Zod schema (same as gRPC)
    const validation = CreateUserConnectionRequestSchema.safeParse({
      user_uid: req.body.user_uid,
      exchange: req.body.exchange,
      label: req.body.label || `${req.body.exchange} account (direct connect)`,
      api_key: req.body.api_key,
      api_secret: req.body.api_secret,
      passphrase: req.body.passphrase
    });

    if (!validation.success) {
      logger.warn('[REST] Invalid request', {
        errors: validation.error.issues,
        body: req.body
      });

      return res.status(400).json({
        success: false,
        error: 'Invalid request',
        details: validation.error.issues
      });
    }

    const data = validation.data;

    logger.info('[REST] Processing credential submission', {
      user_uid: data.user_uid,
      exchange: data.exchange
    });

    // Call existing EnclaveWorker method (same business logic as gRPC)
    const worker = container.resolve(EnclaveWorker);
    await worker.createUserConnection({
      userUid: data.user_uid,
      exchange: data.exchange,
      label: data.label,
      apiKey: data.api_key,
      apiSecret: data.api_secret,
      passphrase: data.passphrase
    });

    logger.info('[REST] Connection created successfully', {
      user_uid: data.user_uid,
      exchange: data.exchange
    });

    return res.json({
      success: true,
      user_uid: data.user_uid,
      exchange: data.exchange,
      message: 'Credentials encrypted and stored in enclave'
    });

  } catch (error: any) {
    logger.error('[REST] Connection creation failed:', error);

    return res.status(500).json({
      success: false,
      error: error.message || 'Failed to create connection'
    });
  }
});

/**
 * Start REST server for auditable credential submission
 * @param port Port to listen on (default: 3050)
 * @returns HTTP server instance for graceful shutdown
 */
export function startRestServer(port: number = 3050) {
  const server = app.listen(port, '0.0.0.0', () => {
    logger.info(`🌐 REST server listening on http://0.0.0.0:${port}`);
    logger.info('✅ Auditable credential submission enabled');
    logger.info('📝 Endpoint: POST /api/v1/credentials/connect');
  });

  return server;
}

# Development Guide - Track Record Enclave

This guide explains how to develop the Enclave Worker locally.

## Prerequisites

- Node.js 20.x
- Docker Desktop
- npm 10.x

## Quick Start

### 1. Install Dependencies

```bash
npm install
```

### 2. Start PostgreSQL Database

```bash
npm run docker:up
```

This starts PostgreSQL on port 5434 (to avoid conflicts with other services).

### 3. Setup Environment Variables

Copy `.env.example` to `.env`:

```bash
cp .env.example .env
```

The default values work for local development.

### 4. Initialize Database Schema

```bash
npm run prisma:generate
npm run db:push
```

### 5. Start Enclave gRPC Server

```bash
npm run dev
```

The gRPC server starts on port 50051.

## Development Workflow

### Running the Enclave

```bash
# Start PostgreSQL
npm run docker:up

# Start Enclave gRPC server (auto-reload on file changes)
npm run dev
```

### Database Operations

```bash
# Push schema changes to database
npm run db:push

# Create and apply migrations
npm run db:migrate

# Open Prisma Studio (database GUI)
npm run db:studio

# View PostgreSQL logs
npm run docker:logs
```

### Stopping Services

```bash
# Stop Enclave (Ctrl+C)

# Stop PostgreSQL
npm run docker:down
```

## Testing with Gateway

The Enclave communicates with the Gateway via gRPC. To test the full system:

### Terminal 1: Enclave (this repo)
```bash
cd C:\Users\jimmy\Desktop\track-record-enclave
npm run docker:up
npm run dev
```

### Terminal 2: Gateway (aggregator-basic)
```bash
cd C:\Users\jimmy\Desktop\track_record_site\aggregator-basic
npm run dev:gateway
```

The Gateway (HTTP on port 3001) connects to the Enclave (gRPC on port 50051).

## Architecture

```
┌─────────────────────────────────────┐
│  track-record-enclave (THIS REPO)  │
│  ├── src/                           │
│  │   ├── services/                  │  ← Core enclave logic
│  │   ├── connectors/                │  ← Exchange integrations
│  │   ├── repositories/              │  ← Database access
│  │   └── index.ts                   │  ← gRPC server entry point
│  ├── docker-compose.dev.yml         │  ← PostgreSQL for dev
│  └── .env                            │  ← Local config
└─────────────────────────────────────┘
         ↑ gRPC (port 50051)
         │
┌─────────────────────────────────────┐
│  aggregator-basic (GATEWAY)        │
│  ├── src/gateway/                   │  ← HTTP API Gateway
│  └── src/controllers/               │  ← REST endpoints
└─────────────────────────────────────┘
```

## Database Connection

- **Development**: PostgreSQL on `localhost:5434`
- **User**: `enclave_user`
- **Password**: `enclavepass123` (configured in `.env`)
- **Database**: `aggregator_db`

## File Structure

```
track-record-enclave/
├── src/
│   ├── services/
│   │   ├── encryption-service.ts       # AES-256-GCM credential decryption
│   │   ├── trade-sync-service.ts       # Exchange synchronization
│   │   └── equity-snapshot-aggregator.ts  # P&L calculation
│   ├── connectors/
│   │   ├── CcxtExchangeConnector.ts    # Binance, Bitget, MEXC
│   │   ├── IbkrFlexConnector.ts        # Interactive Brokers
│   │   └── AlpacaConnector.ts          # Alpaca Markets
│   ├── repositories/
│   │   └── enclave-repository.ts       # Database layer
│   ├── proto/
│   │   └── enclave.proto               # gRPC service definition
│   └── index.ts                        # gRPC server entry point
├── prisma/
│   └── schema.prisma                   # Database schema
├── docker-compose.dev.yml              # Development PostgreSQL
├── .env.example                        # Environment template
└── package.json                        # Dependencies and scripts
```

## Common Tasks

### Adding a New Exchange Connector

1. Create connector in `src/connectors/NewExchangeConnector.ts`
2. Implement `IExchangeConnector` interface
3. Register in dependency injection container
4. Add tests

### Modifying gRPC API

1. Update `src/proto/enclave.proto`
2. Regenerate TypeScript types
3. Update server handlers in `src/index.ts`
4. Update Gateway client calls

### Database Schema Changes

```bash
# 1. Edit prisma/schema.prisma
# 2. Generate Prisma client
npm run prisma:generate

# 3. Push to dev database
npm run db:push

# 4. Create migration for production
npm run db:migrate
```

## Deployment

This repository is the **source of truth** for production deployments.

### Building for Production

```bash
npm install
npm run prisma:generate
npm run build
```

### Docker Build (Production)

```bash
docker build -t enclave:latest .
```

This build is deployed to AMD SEV-SNP VMs.

## Security Notes

- **NEVER commit `.env`** to Git
- **NEVER log credentials** (check `src/utils/logger.ts`)
- **ALWAYS test locally** before deploying to production
- **ALWAYS run `npm audit`** before releases

## Troubleshooting

### Port 5434 already in use

```bash
# Check what's using the port
netstat -ano | findstr :5434

# Stop the container
npm run docker:down
```

### Database connection errors

```bash
# Check PostgreSQL is running
docker ps | grep enclave_postgres_dev

# View logs
npm run docker:logs

# Restart database
npm run docker:down && npm run docker:up
```

### Prisma client not found

```bash
npm run prisma:generate
```

## Questions?

See the main [README.md](README.md) for architecture and security model.

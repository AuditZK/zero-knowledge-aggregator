# Enclave VPS Deployment - REST Server Fix

## Problem
REST server on port 3050 is not accessible from outside the VPS.

## Solution Steps

### 1. SSH to Enclave VPS
```bash
ssh jimmy@34.77.144.221
cd /root/zero-knowledge-aggregator
```

### 2. Pull Latest Code
```bash
git pull origin main
```

### 3. Rebuild and Restart Container
```bash
# Stop current container
docker compose -f docker-compose.enclave.yml down

# Rebuild with new REST server code
docker compose -f docker-compose.enclave.yml build --no-cache

# Start container with proper environment
docker compose -f docker-compose.enclave.yml up -d
```

### 4. Verify Container is Running
```bash
docker ps | grep enclave_service
```

Expected output:
```
CONTAINER ID   IMAGE                              PORTS                    NAMES
xxx            zero-knowledge-aggregator-enclave  0.0.0.0:3050->3050/tcp   enclave_service
                                                   0.0.0.0:50051->50051/tcp
```

### 5. Check Container Logs
```bash
docker compose -f docker-compose.enclave.yml logs -f enclave-service
```

Look for:
```
[ENCLAVE] REST server started { port: 3050, endpoint: 'POST /api/v1/credentials/connect' }
```

### 6. Test REST Server from Inside Container
```bash
docker exec enclave_service curl -X POST http://localhost:3050/api/v1/credentials/connect \
  -H "Content-Type: application/json" \
  -d '{"user_uid": "test", "exchange": "binance", "api_key": "test", "api_secret": "test"}'
```

Expected: JSON response (even if validation fails, proves server is running)

### 7. Test from VPS Host
```bash
curl -X POST http://localhost:3050/api/v1/credentials/connect \
  -H "Content-Type: application/json" \
  -d '{"user_uid": "test", "exchange": "binance", "api_key": "test", "api_secret": "test"}'
```

### 8. Configure Google Cloud Firewall

**Check if port 3050 is open:**
```bash
# On Google Cloud Console
gcloud compute firewall-rules list | grep 3050
```

**If port 3050 is NOT in firewall rules, add it:**
```bash
gcloud compute firewall-rules create allow-enclave-rest \
  --direction=INGRESS \
  --priority=1000 \
  --network=default \
  --action=ALLOW \
  --rules=tcp:3050 \
  --source-ranges=0.0.0.0/0 \
  --target-tags=enclave-vm

# Tag your VM instance
gcloud compute instances add-tags tee-milan-01 --tags=enclave-vm --zone=europe-west4-a
```

**Or use the Google Cloud Console:**
1. Go to VPC network → Firewall
2. Click "Create Firewall Rule"
3. Name: `allow-enclave-rest`
4. Targets: Specified target tags → `enclave-vm`
5. Source IP ranges: `0.0.0.0/0`
6. Protocols and ports: `tcp:3050`
7. Click "Create"

### 9. Test from External Network
```bash
# From your local machine (Windows PowerShell)
curl -X POST http://34.77.144.221:3050/api/v1/credentials/connect `
  -H "Content-Type: application/json" `
  -d '{"user_uid": "test", "exchange": "binance", "api_key": "test", "api_secret": "test"}'
```

### 10. Verify Environment Variables

Check that .env file on VPS has correct database URL:
```bash
cat /root/zero-knowledge-aggregator/.env
```

Should contain:
```bash
DATABASE_URL="postgresql://enclave_user:Yz8nQwE4rT6uI2oP@82.165.143.149:5436/enclave_db"
REST_PORT=3050
ENCRYPTION_KEY="..."
JWT_SECRET="..."
```

## Troubleshooting

### Container won't start
```bash
# Check detailed logs
docker compose -f docker-compose.enclave.yml logs enclave-service

# Check if port is already in use
netstat -tuln | grep 3050
```

### REST server not starting
```bash
# Check if TypeScript compiled correctly
docker exec enclave_service ls -la dist/rest-server.js

# Check Node.js errors
docker exec enclave_service node -e "require('./dist/rest-server')"
```

### Database connection issues
```bash
# Test DB connection from VPS
psql "postgresql://enclave_user:Yz8nQwE4rT6uI2oP@82.165.143.149:5436/enclave_db" -c "SELECT 1"
```

## Quick Restart Command

```bash
cd /root/zero-knowledge-aggregator && \
  git pull origin main && \
  docker compose -f docker-compose.enclave.yml down && \
  docker compose -f docker-compose.enclave.yml build --no-cache && \
  docker compose -f docker-compose.enclave.yml up -d && \
  docker compose -f docker-compose.enclave.yml logs -f
```

## Expected Final State

✅ Container running: `docker ps` shows enclave_service with ports 3050, 50051, 50052, 9092
✅ REST server logs: `[ENCLAVE] REST server started { port: 3050 }`
✅ Firewall rule: Google Cloud firewall allows TCP port 3050
✅ External access: `curl http://34.77.144.221:3050/health` returns `{"status":"ok","service":"enclave-rest"}`

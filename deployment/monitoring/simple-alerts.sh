#!/bin/bash
# =============================================================================
# Simple Alerting Script (NO Kubernetes/Prometheus Operator required)
# =============================================================================
# This script monitors the enclave health and sends alerts if issues detected
#
# Setup (cron job):
#   */5 * * * * /opt/track-record-enclave/deployment/monitoring/simple-alerts.sh
#
# Alerting methods:
#   - Email (sendmail)
#   - Slack webhook
#   - PagerDuty
#   - Custom webhook
# =============================================================================

set -euo pipefail

# Configuration
METRICS_URL="http://localhost:9090/metrics"
HEALTH_URL="http://localhost:9090/health"
ALERT_EMAIL="${ALERT_EMAIL:-ops@trackrecord.com}"
SLACK_WEBHOOK="${SLACK_WEBHOOK:-}"
PAGERDUTY_KEY="${PAGERDUTY_KEY:-}"

# Thresholds
MAX_MEMORY_BYTES=1800000000  # 1.8GB (90% of 2GB limit)
MAX_ERROR_RATE=0.01          # 1% error rate
MAX_RESPONSE_TIME=5          # 5 seconds

# Alert if enclave is down
check_health() {
  local response=$(curl -sf "$HEALTH_URL" -m 5 || echo "DOWN")

  if [ "$response" = "DOWN" ]; then
    send_alert "🚨 CRITICAL: Enclave is DOWN" \
      "The enclave service is not responding to health checks.\n\nImmediate action required."
    return 1
  fi

  return 0
}

# Alert if memory usage is high
check_memory() {
  local mem_usage=$(curl -sf "$METRICS_URL" 2>/dev/null | grep '^process_memory_bytes' | awk '{print $2}')

  if [ -z "$mem_usage" ]; then
    send_alert "⚠️ WARNING: Cannot read memory metrics" \
      "Unable to fetch memory usage from Prometheus endpoint."
    return 1
  fi

  if (( $(echo "$mem_usage > $MAX_MEMORY_BYTES" | bc -l) )); then
    local mem_gb=$(echo "scale=2; $mem_usage / 1024 / 1024 / 1024" | bc)
    send_alert "⚠️ WARNING: High memory usage" \
      "Memory usage: ${mem_gb}GB (threshold: 1.8GB)\n\nPossible memory leak detected."
    return 1
  fi

  return 0
}

# Alert if gRPC error rate is high
check_error_rate() {
  local metrics=$(curl -sf "$METRICS_URL" 2>/dev/null)

  local total_requests=$(echo "$metrics" | grep 'grpc_requests_total' | grep -v '^#' | awk '{sum += $2} END {print sum}')
  local error_requests=$(echo "$metrics" | grep 'grpc_requests_total{.*status="error"' | awk '{sum += $2} END {print sum}')

  if [ -z "$total_requests" ] || [ "$total_requests" = "0" ]; then
    # No requests yet, skip check
    return 0
  fi

  local error_rate=$(echo "scale=4; $error_requests / $total_requests" | bc)

  if (( $(echo "$error_rate > $MAX_ERROR_RATE" | bc -l) )); then
    local error_percent=$(echo "scale=2; $error_rate * 100" | bc)
    send_alert "⚠️ WARNING: High gRPC error rate" \
      "Error rate: ${error_percent}% (threshold: 1%)\n\nTotal requests: $total_requests\nFailed requests: $error_requests"
    return 1
  fi

  return 0
}

# Alert if attestation is failing
check_attestation() {
  local metrics=$(curl -sf "$METRICS_URL" 2>/dev/null)

  local attestation_failures=$(echo "$metrics" | grep '^enclave_attestation_failure_total' | awk '{print $2}')

  if [ -z "$attestation_failures" ]; then
    return 0
  fi

  if [ "$attestation_failures" -gt 0 ]; then
    send_alert "🚨 CRITICAL: AMD SEV-SNP attestation failures" \
      "Attestation failures detected: $attestation_failures\n\nThis may indicate a security breach or hardware issue.\n\nAction: Investigate immediately."
    return 1
  fi

  return 0
}

# Send alert via multiple channels
send_alert() {
  local title="$1"
  local message="$2"
  local timestamp=$(date -u +"%Y-%m-%d %H:%M:%S UTC")

  local full_message="$title\n\n$message\n\nTimestamp: $timestamp\nHost: $(hostname)"

  echo -e "$full_message"

  # Email
  if command -v sendmail &> /dev/null && [ -n "$ALERT_EMAIL" ]; then
    echo -e "Subject: [Enclave Alert] $title\n\n$full_message" | sendmail "$ALERT_EMAIL"
  fi

  # Slack
  if [ -n "$SLACK_WEBHOOK" ]; then
    curl -X POST "$SLACK_WEBHOOK" \
      -H 'Content-Type: application/json' \
      -d "{\"text\":\"$title\",\"attachments\":[{\"text\":\"$message\",\"color\":\"danger\"}]}" \
      &>/dev/null || true
  fi

  # PagerDuty
  if [ -n "$PAGERDUTY_KEY" ]; then
    curl -X POST https://events.pagerduty.com/v2/enqueue \
      -H 'Content-Type: application/json' \
      -d "{\"routing_key\":\"$PAGERDUTY_KEY\",\"event_action\":\"trigger\",\"payload\":{\"summary\":\"$title\",\"severity\":\"error\",\"source\":\"enclave-monitor\"}}" \
      &>/dev/null || true
  fi
}

# Main monitoring logic
main() {
  local issues=0

  # Run all checks
  check_health || ((issues++))
  check_memory || ((issues++))
  check_error_rate || ((issues++))
  check_attestation || ((issues++))

  if [ $issues -eq 0 ]; then
    echo "[$(date -u +"%Y-%m-%d %H:%M:%S")] All checks passed ✓"
  else
    echo "[$(date -u +"%Y-%m-%d %H:%M:%S")] $issues issue(s) detected"
  fi

  exit $issues
}

main

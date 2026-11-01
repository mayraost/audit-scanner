#!/bin/sh
# Wrapper um den Nachtlauf (von crond aufgerufen): kleines Log-Rotate + Scan.
set -u
LOG_DIR=/app/logs
REPORTS_DIR=/app/reports
MAX_LOG_BYTES=5000000

mkdir -p "$LOG_DIR" "$REPORTS_DIR" 2>/dev/null || true

# Grobes Rotate: >5 MB → Start-Tail behalten
if [ -f "${LOG_DIR}/scan.log" ] && [ "$(wc -c < "${LOG_DIR}/scan.log")" -gt "$MAX_LOG_BYTES" ]; then
  tail -c 500000 "${LOG_DIR}/scan.log" > "${LOG_DIR}/scan.log.tmp" && mv "${LOG_DIR}/scan.log.tmp" "${LOG_DIR}/scan.log"
fi

echo "=== scan start $(date -u '+%Y-%m-%dT%H:%M:%SZ') ==="

# Scanner selbst toucht den Heartbeat am Ende des Runs — hier nochmal defensiv
# bei Erfolg, damit Healthcheck auch ohne vollen Telegram-Rundumschlag stimmt.
if node /app/dist/index.js scan; then
  touch "$REPORTS_DIR/.heartbeat"
  echo "=== scan ok $(date -u '+%Y-%m-%dT%H:%M:%SZ') ==="
else
  rc=$?
  echo "=== scan FAILED rc=$rc $(date -u '+%Y-%m-%dT%H:%M:%SZ') ==="
  exit $rc
fi

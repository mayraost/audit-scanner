#!/bin/sh
# Wrapper um den Nachtlauf (von crond aufgerufen): kleines Log-Rotate + Scan.
set -u
LOG_DIR=/app/logs
REPORTS_DIR=/app/reports
MAX_LOG_BYTES=5000000

mkdir -p "$LOG_DIR" "$REPORTS_DIR" 2>/dev/null || true

# Ownership-Hinweis (Bug 09.11.2026): crond demoted den Job auf `node`
# (uid 1000) — ein chown durch den Job ist deshalb NICHT möglich ("Operation
# not permitted") und wäre hier nur irreführendes Wunschdenken. Die echte
# Absicherung liegt (a) im root-Entrypoint, der die Volumes beim Container-
# Start rekursiv auf node:node setzt, und (b) im Scanner selbst: saveDigestCache()
# loggt Schreibfehler nur noch als Warnung statt den Lauf abzubrechen.
# Grobes Rotate: >5 MB → Start-Tail behalten
if [ -f "${LOG_DIR}/scan.log" ] && [ "$(wc -c < "${LOG_DIR}/scan.log")" -gt "$MAX_LOG_BYTES" ]; then
  tail -c 500000 "${LOG_DIR}/scan.log" > "${LOG_DIR}/scan.log.tmp" && mv "${LOG_DIR}/scan.log.tmp" "${LOG_DIR}/scan.log"
fi

echo "=== scan start $(date -u '+%Y-%m-%dT%H:%M:%SZ') ==="

# Scanner selbst toucht den Heartbeat am Ende des Runs — hier nochmal defensiv
# bei Erfolg, damit Healthcheck auch ohne vollen Telegram-Rundumschlag stimmt.
#
# Fehlschlag-Alarm (v1.7.4, Vorfall 08./09.11.2026): bei rc != 0 geht eine
# Telegram-Meldung "⚠️ CVE-Audit FEHLGESCHLAGEN" raus (Formatierung + Versand
# in TypeScript, src/failure-notify.ts). `|| true` + `rc`-Merker: ein kaputter
# Telegram-Versand darf den Original-Exit-Code NICHT überdecken.
# Der Heartbeat bleibt im else-Zweig bewusst unangetastet — erst dann flippt
# der HEALTHCHECK nach 48 h ohne Erfolgslauf auf unhealthy.
if node /app/dist/index.js scan; then
  touch "$REPORTS_DIR/.heartbeat"
  echo "=== scan ok $(date -u '+%Y-%m-%dT%H:%M:%SZ') ==="
else
  rc=$?
  echo "=== scan FAILED rc=$rc $(date -u '+%Y-%m-%dT%H:%M:%SZ') ==="
  node /app/dist/index.js notify-failure --rc "$rc" --log "${LOG_DIR}/scan.log" \
    || echo "WARN: notify-failure selbst fehlgeschlagen (Scan-rc=$rc bleibt)."
  exit "$rc"
fi

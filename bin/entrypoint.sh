#!/bin/sh
# Busybox crond als PID 1 (Spec §7): Crontab aus CRON_SCHEDULE gerendert,
# ENV aus Container geerbt (GH_TOKEN / TELEGRAM_* implizit lesbar im Job).
# Keine Secrets im Image-Layer — ENV folgt zur Laufzeit.
set -u

CRON_DIR=/app/crontabs
LOG_DIR=/app/logs
REPORTS_DIR=/app/reports
CACHE_DIR=/app/.cache
CRON_SCHEDULE="${CRON_SCHEDULE:-0 16 * * *}"

mkdir -p "$CRON_DIR" "$LOG_DIR" "$REPORTS_DIR" "$CACHE_DIR/trivy" 2>/dev/null || true
# Boot-Touch: Heartbeat atmungsfrisch setzen, damit HEALTHCHECK nicht sofort failt
touch "$REPORTS_DIR/.heartbeat"

# busybox crond liest eine Crontab-Datei je user im Crontab-Dir; Nutzername =
# Dateiname. Wir laufen als node → Datei heißt "node".
cat > "$CRON_DIR/node" <<EOF
${CRON_SCHEDULE} /bin/sh /app/bin/scan-wrapper.sh >> ${LOG_DIR}/scan.log 2>&1
EOF

exec crond -f -l 8 -c "$CRON_DIR"

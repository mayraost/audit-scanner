#!/bin/sh
# Busybox crond als PID 1 (Spec §7): Crontab aus CRON_SCHEDULE gerendert,
# ENV aus Container geerbt (GH_TOKEN / TELEGRAM_* implizit lesbar im Job).
# Keine Secrets im Image-Layer — ENV folgt zur Laufzeit.
#
# Achtung (Bug 02.11.2026): busybox crond braucht zwingend root:
#   1) Crontab-Files werden nur geladen, wenn root-owned (crond.c DAEMON_UID 0).
#   2) non-root crond kann Jobs nicht ausführen (setgroups → EPERM → Job stirbt).
# crond demoted Jobs selbst per setuid auf den File-Owner ("node") → Job läuft
# als node; ENV-Secrets werden weiterhin an den Job vererbt.
# Kein USER node mehr (Dockerfile) — deshalb wird dieses Skript als root laufen.
set -u

CRON_DIR=/app/crontabs
LOG_DIR=/app/logs
REPORTS_DIR=/app/reports
CACHE_DIR=/app/.cache
CRON_SCHEDULE="${CRON_SCHEDULE:-0 16 * * *}"

mkdir -p "$CRON_DIR" "$LOG_DIR" "$REPORTS_DIR" "$CACHE_DIR/trivy" 2>/dev/null || true
# Boot-Touch: Heartbeat atmungsfrisch setzen, damit HEALTHCHECK nicht sofort failt.
# Herzschlag-Updates passieren später als node (crond-Job) → Volumen-Files bleiben node-owned.
touch "$REPORTS_DIR/.heartbeat"
chown node:node "$REPORTS_DIR/.heartbeat" "$REPORTS_DIR" "$LOG_DIR" 2>/dev/null || true

# busybox crond liest eine Crontab-Datei je user im Crontab-Dir; Nutzername =
# Dateiname. Hier als root geschrieben → File ist root-owned (Pflicht fürs Laden).
# Jobs laufen dann automatisch als node (setuid auf File-Owner).
cat > "$CRON_DIR/node" <<EOF
${CRON_SCHEDULE} /bin/sh /app/bin/scan-wrapper.sh >> ${LOG_DIR}/scan.log 2>&1
EOF

# -L: crond-Log (Job-Start/Ende, Fehler) ins Logs-Volumen statt stummem syslog —
# syslog fehlt im Container (/dev/log), ohne -L wäre crond komplett still.
exec crond -f -l 8 -L "${LOG_DIR}/crond.log" -c "$CRON_DIR"

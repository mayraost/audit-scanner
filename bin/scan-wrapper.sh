#!/bin/sh
# Wrapper um den Nachtlauf (von crond aufgerufen): kleines Log-Rotate + Scan.
#
# Abbruch-Absicherung (v1.7.5): Bis v1.7.4 meldete nur der else-Zweig einen
# Fehlschlag. Starb der Wrapper dagegen selbst — OOM-Kill, SIGTERM beim
# Deploy-Rollover, SIGKILL nach Timeout — wurde der else-Zweig nie erreicht
# und der Ausfall blieb still. Deshalb jetzt ein trap auf EXIT/TERM/INT/HUP:
# ein Merker-File ("alarm zugesagt") verhindert Doppelmeldungen, der trap
# feuert nur, wenn kein rc-Pfad den Alarm schon abgeschickt hat.
set -u
LOG_DIR=/app/logs
REPORTS_DIR=/app/reports
MAX_LOG_BYTES=5000000
# Merker: existiert = irgendein Pfad hat den Alarm bereits ausgelöst/erledigt.
ALARM_MARKER="${LOG_DIR}/.failure-alarm-sent"
SCAN_LOG="${LOG_DIR}/scan.log"

mkdir -p "$LOG_DIR" "$REPORTS_DIR" 2>/dev/null || true

# Ownership-Hinweis (Bug 09.11.2026): crond demoted den Job auf `node`
# (uid 1000) — ein chown durch den Job ist deshalb NICHT möglich ("Operation
# not permitted") und wäre hier nur irreführendes Wunschdenken. Die echte
# Absicherung liegt (a) im root-Entrypoint, der die Volumes beim Container-
# Start rekursiv auf node:node setzt, und (b) im Scanner selbst: saveDigestCache()
# loggt Schreibfehler nur noch als Warnung statt den Lauf abzubrechen.

# Alarm senden — genau einmal. Rückgabe immer 0: der Exit-Code des Wrappers
# (bzw. des Scans) darf durch einen kaputten Telegram-Versand nie kippen.
#
# ACHTUNG: POSIX sh kennt kein `local` — Variablennamen hier bewusst mit
# Präfix `sa_`, damit sie NICHT `rc`/`reason`/`code` des Aufrufers (on_abort,
# Hauptpfad) überschreiben. Genau das war in einem ersten Entwurf ein Bug.
send_alarm() {
  sa_rc="$1"
  sa_reason="${2:-}"
  if [ -f "$ALARM_MARKER" ]; then
    return 0
  fi
  : > "$ALARM_MARKER" 2>/dev/null || true
  if [ -n "$sa_reason" ]; then
    node /app/dist/index.js notify-failure --rc "$sa_rc" --log "$SCAN_LOG" --reason "$sa_reason" \
      || echo "WARN: notify-failure selbst fehlgeschlagen (rc=$sa_rc bleibt)."
  else
    node /app/dist/index.js notify-failure --rc "$sa_rc" --log "$SCAN_LOG" \
      || echo "WARN: notify-failure selbst fehlgeschlagen (rc=$sa_rc bleibt)."
  fi
  return 0
}

# trap-Pfad: nur relevant, wenn der Wrapper selbst endet, ohne dass ein
# rc-Pfad den Alarm quittiert hat (abgebrochener/KILLED Prozess).
on_abort() {
  ab_code="$?"
  # Merker schon gesetzt? Dann hat der normale Pfad übernommen.
  if [ -f "$ALARM_MARKER" ]; then
    exit "$ab_code"
  fi
  echo "=== scan ABGEBROCHEN rc=$ab_code $(date -u '+%Y-%m-%dT%H:%M:%SZ') ==="
  send_alarm "$ab_code" "Lauf abgebrochen (Signal/Exit ohne Scan-Ergebnis, rc=$ab_code) — z. B. OOM-Kill, SIGTERM beim Deploy-Rollover oder Timeout"
  exit "$ab_code"
}
trap on_abort EXIT HUP INT TERM

# Alten Merker aus dem Vortag entfernen — sonst unterdrückt er den Alarm.
rm -f "$ALARM_MARKER" 2>/dev/null || true

# Grobes Rotate: >5 MB → Start-Tail behalten
if [ -f "$SCAN_LOG" ] && [ "$(wc -c < "$SCAN_LOG")" -gt "$MAX_LOG_BYTES" ]; then
  tail -c 500000 "$SCAN_LOG" > "${SCAN_LOG}.tmp" && mv "${SCAN_LOG}.tmp" "$SCAN_LOG"
fi

echo "=== scan start $(date -u '+%Y-%m-%dT%H:%M:%SZ') ==="

# Scanner selbst toucht den Heartbeat am Ende des Runs — hier nochmal defensiv
# bei Erfolg, damit Healthcheck auch ohne vollen Telegram-Rundumschlag stimmt.
#
# Fehlschlag-Alarm (v1.7.4, Vorfall 08./09.11.2026): bei rc != 0 geht eine
# Telegram-Meldung "⚠️ CVE-Audit FEHLGESCHLAGEN" raus (Formatierung + Versand
# in TypeScript, src/failure-notify.ts). Der Merker + `rc`-Weiterreichung
# stellen sicher, dass ein kaputter Telegram-Versand den echten Exit-Code
# NICHT überdeckt.
# Der Heartbeat bleibt im Fehlerfall bewusst unangetastet — erst dann flippt
# der HEALTHCHECK nach 48 h ohne Erfolgslauf auf unhealthy.
if node /app/dist/index.js scan; then
  touch "$REPORTS_DIR/.heartbeat"
  # Erfolg quittiert den Alarm-Merker, damit der EXIT-trap nicht feuert.
  : > "$ALARM_MARKER" 2>/dev/null || true
  echo "=== scan ok $(date -u '+%Y-%m-%dT%H:%M:%SZ') ==="
  exit 0
else
  rc=$?
  echo "=== scan FAILED rc=$rc $(date -u '+%Y-%m-%dT%H:%M:%SZ') ==="
  # Merker VOR dem Versand setzen: sendet der Alarm, quittiert er den trap;
  # scheitert er, soll der trap nicht ein zweites Mal senden.
  send_alarm "$rc" ""
  exit "$rc"
fi

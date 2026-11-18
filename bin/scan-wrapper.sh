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
  if [ -n "$sa_reason" ]; then
    node /app/dist/index.js notify-failure --rc "$sa_rc" --log "$SCAN_LOG" --reason "$sa_reason"
  else
    node /app/dist/index.js notify-failure --rc "$sa_rc" --log "$SCAN_LOG"
  fi
  sa_gesendet=$?
  # Merker NUR bei erfolgreichem Versand setzen (v1.7.6, Vorfall 14.11.2026):
  # vorher wurde er VOR dem Senden gesetzt — ein einziger "fetch failed" beim
  # Versand machte den Alarm damit endgueltig stumm (trap unterdrueckt, kein
  # zweiter Versuch). Jetzt bleibt der Merker offen, der EXIT-trap wiederholt
  # den Versand einmal (inkl. der 3 Retries in telegram.ts).
  if [ "$sa_gesendet" = "0" ]; then
    : > "$ALARM_MARKER" 2>/dev/null || true
  else
    echo "WARN: notify-failure fehlgeschlagen (rc=$sa_gesendet) — Merker bleibt offen, trap wiederholt einmal."
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
# NICHT überdeckt. Seit v1.7.6 wird der Merker erst NACH erfolgreichem Versand
# gesetzt — ein gescheiterter Alarm wird vom EXIT-trap einmal wiederholt.
# Der Heartbeat bleibt im Fehlerfall bewusst unangetastet — erst dann flippt
# der HEALTHCHECK nach 26 h ohne Erfolgslauf auf unhealthy.
hb_mtime() { stat -c %Y "$REPORTS_DIR/.heartbeat" 2>/dev/null || echo 0; }

# Crash-Resilienz (v1.8.1): Ein nativer V8-Abbruch ist prozessweit tödlich,
# aber nicht reproduzierbar und liegt NICHT in unserem JS-Code — Vorfall
# 14.11.2026 (rc=139, SIGSEGV) und 18.11.2026 (rc=133, SIGTRAP:
# `Check failed: page_->ContainsLimit(...)` in einem V8-Worker-Thread, also
# Heap-/GC-Interna). Solange der Lauf noch KEINEN Report geschrieben hat
# (Heartbeat-mtime unverändert), wird er genau EINMAL wiederholt. Das ist
# idempotent: Fix-/Pins-/Image-PRs werden über den Branch-Namen dedupliziert
# (`cve-audit/*-<datum>` → findOpenPr → status 'exists', kein Duplikat).
RETRY_DELAY_SECONDS="${RETRY_DELAY_SECONDS:-5}"
NATIVE_CRASH_CODES="133 134 139" # SIGTRAP (V8-CHECK/Fatal), SIGABRT, SIGSEGV

hb_before=$(hb_mtime)
if node /app/dist/index.js scan; then
  touch "$REPORTS_DIR/.heartbeat"
  # Erfolg quittiert den Alarm-Merker, damit der EXIT-trap nicht feuert.
  : > "$ALARM_MARKER" 2>/dev/null || true
  echo "=== scan ok $(date -u '+%Y-%m-%dT%H:%M:%SZ') ==="
  exit 0
else
  # rc MUSS im else-Zweig gelesen werden: ein `if` ohne else liefert selbst 0.
  rc=$?
fi
first_rc=$rc
echo "=== scan FAILED rc=$rc $(date -u '+%Y-%m-%dT%H:%M:%SZ') ==="

case " $NATIVE_CRASH_CODES " in
  *" $rc "*)
    if [ "$(hb_mtime)" -le "$hb_before" ]; then
      echo "=== scan NATIVE-CRASH rc=$rc — Wiederholung nach ${RETRY_DELAY_SECONDS}s $(date -u '+%Y-%m-%dT%H:%M:%SZ') ==="
      sleep "$RETRY_DELAY_SECONDS" 2>/dev/null || true
      hb_before=$(hb_mtime)
      if node /app/dist/index.js scan; then
        touch "$REPORTS_DIR/.heartbeat"
        : > "$ALARM_MARKER" 2>/dev/null || true
        echo "=== scan ok (nach Wiederholung) $(date -u '+%Y-%m-%dT%H:%M:%SZ') ==="
        exit 0
      else
        rc=$?
      fi
      echo "=== scan FAILED rc=$rc (Wiederholung ebenfalls gescheitert) $(date -u '+%Y-%m-%dT%H:%M:%SZ') ==="
      send_alarm "$rc" "nativer V8-Abbruch (erster Lauf rc=$first_rc), Wiederholung ebenfalls gescheitert (rc=$rc)"
      exit "$rc"
    fi
    echo "=== scan NATIVE-CRASH rc=$rc — keine Wiederholung: Report/Heartbeat wurde bereits geschrieben ==="
    ;;
esac

send_alarm "$rc" ""
exit "$rc"

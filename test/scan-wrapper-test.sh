#!/bin/sh
# Harness: scan-wrapper.sh gegen Szenarien prüfen (kein echter Scan, kein Telegram).
# Fake-`node` protokolliert notify-failure-Aufrufe in $CALLS.
set -u
W="$(cd "$(dirname "$0")/.." && pwd)/bin/scan-wrapper.sh"
ROOT="${TMPDIR:-/tmp/opencode}/wraptest"
PASS=0; FAIL=0
ok(){ PASS=$((PASS+1)); echo "OK   $1"; }
no(){ FAIL=$((FAIL+1)); echo "FAIL $1"; }

setup() {
  unset NODE_SCAN_RC NODE_NOTIFY_RC SCAN_SEQ FAKE_HB_TOUCH 2>/dev/null || true
  rm -rf "$ROOT"; mkdir -p "$ROOT/logs" "$ROOT/reports" "$ROOT/bin"
  CALLS="$ROOT/calls.txt"; : > "$CALLS"; export CALLS
  SCAN_SEQ="$ROOT/scan.seq"; : > "$SCAN_SEQ"; export SCAN_SEQ
  cat > "$ROOT/bin/node" <<'EOF'
#!/bin/sh
# Fake-node: unterscheidet per Subcommand (letztes Argument vor den Flags).
# SCAN_SEQ: Datei mit rc-Werten, je Lauf die erste Zeile (Wiederholungs-Tests).
# FAKE_HB_TOUCH: Datei, die der "Scan" vor dem Exit toucht (Report geschrieben).
case "$*" in
  *"index.js scan")
    [ -n "${FAKE_HB_TOUCH:-}" ] && touch "$FAKE_HB_TOUCH"
    if [ -n "${SCAN_SEQ:-}" ] && [ -s "$SCAN_SEQ" ]; then
      s_rc=$(sed -n 1p "$SCAN_SEQ")
      sed -e '1d' "$SCAN_SEQ" > "$SCAN_SEQ.tmp" && mv "$SCAN_SEQ.tmp" "$SCAN_SEQ"
      echo "[fake] scan läuft (seq rc=$s_rc)"; exit "$s_rc"
    fi
    echo "[fake] scan läuft"; exit "${NODE_SCAN_RC:-0}" ;;
  *" notify-failure "*)
    echo "NOTIFY $(printf '%s' "$*" | sed 's#.*notify-failure ##')" >> "$CALLS"
    exit "${NODE_NOTIFY_RC:-0}" ;;
  *) exit 0 ;;
esac
EOF
  chmod +x "$ROOT/bin/node"
  sed -e "s#/app/logs#$ROOT/logs#g" -e "s#/app/reports#$ROOT/reports#g" \
      -e "s#/app/dist/index.js#$ROOT/dist/index.js#g" "$W" > "$ROOT/wrap.sh"
  chmod +x "$ROOT/wrap.sh"
}
go() { NODE_SCAN_RC="${1:-0}" RETRY_DELAY_SECONDS=0 PATH="$ROOT/bin:$PATH" "$ROOT/wrap.sh" >"$ROOT/out.log" 2>&1; local_r=$?; echo "$local_r"; }

# 1) Erfolg
setup
rc=$(go 0)
[ "$rc" = "0" ] && ok "Erfolg: rc=0" || no "Erfolg: rc=$rc"
[ -s "$CALLS" ] && no "Erfolg: Alarm gesendet ($(cat $CALLS))" || ok "Erfolg: KEIN Alarm"
[ -f "$ROOT/reports/.heartbeat" ] && ok "Erfolg: Heartbeat gesetzt" || no "Erfolg: Heartbeat fehlt"

# 2) Scan scheitert: genau EIN Alarm (trap darf nicht doppelt feuern)
setup
rc=$(go 7)
n=$(wc -l < "$CALLS")
[ "$rc" = "7" ] && ok "Fehler: rc=7 erhalten" || no "Fehler: rc=$rc"
[ "$n" = "1" ] && ok "Fehler: genau 1 Alarm (kein Doppel durch trap)" || no "Fehler: $n Alarme"
[ -f "$ROOT/reports/.heartbeat" ] && no "Fehler: Heartbeat wurde gesetzt" || ok "Fehler: Heartbeat unangetastet"

# 3) notify-failure scheitert dauerhaft: Scan-rc bleibt, trap wiederholt einmal
setup
NODE_SCAN_RC=7 NODE_NOTIFY_RC=5 PATH="$ROOT/bin:$PATH" "$ROOT/wrap.sh" >/dev/null 2>&1; rc=$?
[ "$rc" = "7" ] && ok "notify kaputt: Scan-rc=7 bleibt" || no "notify kaputt: rc=$rc (erwartet 7)"
n=$(wc -l < "$CALLS")
[ "$n" = "2" ] && ok "notify kaputt: 2 Versuche (Haupt + trap)" || no "notify kaputt: $n Versuche (erwartet 2)"
[ -f "$ROOT/logs/.failure-alarm-sent" ] && no "notify kaputt: Merker trotzdem gesetzt" || ok "notify kaputt: Merker offen"

# 3b) notify-failure scheitert EINMAL, trap-Versuch klappt: Merker wird gesetzt
setup
cat > "$ROOT/bin/node" <<'EOF'
#!/bin/sh
case "$*" in
  *"index.js scan") echo "[fake] scan scheitert"; exit 7 ;;
  *" notify-failure "*)
    echo "NOTIFY $(printf '%s' "$*" | sed 's#.*notify-failure ##')" >> "$CALLS"
    if [ -f "$CALLS.flaky" ]; then exit 0; fi
    : > "$CALLS.flaky"; exit 5 ;;
  *) exit 0 ;;
esac
EOF
chmod +x "$ROOT/bin/node"
PATH="$ROOT/bin:$PATH" "$ROOT/wrap.sh" >/dev/null 2>&1; rc=$?
[ "$rc" = "7" ] && ok "notify flaky: Scan-rc=7 bleibt" || no "notify flaky: rc=$rc (erwartet 7)"
n=$(wc -l < "$CALLS")
[ "$n" = "2" ] && ok "notify flaky: 2 Versuche" || no "notify flaky: $n Versuche (erwartet 2)"
[ -f "$ROOT/logs/.failure-alarm-sent" ] && ok "notify flaky: Merker nach Erfolg gesetzt" || no "notify flaky: Merker fehlt"

# 4) SIGTERM an den Wrapper: Alarm MIT Abbruch-Grund
setup
cat > "$ROOT/bin/node" <<'EOF'
#!/bin/sh
case "$*" in
  *"index.js scan") echo "[fake] hängt"; sleep 30; exit 0 ;;
  *" notify-failure "*) echo "NOTIFY $(printf '%s' "$*" | sed 's#.*notify-failure ##')" >> "$CALLS"; exit 0 ;;
  *) exit 0 ;;
esac
EOF
chmod +x "$ROOT/bin/node"
PATH="$ROOT/bin:$PATH" "$ROOT/wrap.sh" >/dev/null 2>&1 &
WPID=$!
sleep 1; kill -TERM $WPID 2>/dev/null; wait $WPID 2>/dev/null; rc=$?
n=$(wc -l < "$CALLS")
[ "$n" = "1" ] && ok "SIGTERM: Alarm gesendet" || no "SIGTERM: $n Alarme"
grep -q -- "--reason" "$CALLS" && ok "SIGTERM: Abbruch-Grund mitgegeben" || no "SIGTERM: kein --reason"

# 5) Vortags-Merker unterdrückt Alarm NICHT
setup; touch "$ROOT/logs/.failure-alarm-sent"
rc=$(go 3)
n=$(wc -l < "$CALLS")
[ "$n" = "1" ] && ok "Alter Merker: Alarm kommt trotzdem" || no "Alter Merker: $n Alarme (unterdrückt!)"
[ "$rc" = "3" ] && ok "Alter Merker: rc=3" || no "Alter Merker: rc=$rc"

# 6) Nativer V8-Crash (133 = SIGTRAP) → genau EINE Wiederholung, danach Erfolg
setup; printf '133\n0\n' > "$SCAN_SEQ"
rc=$(go 133)
n=$(wc -l < "$CALLS")
[ "$rc" = "0" ] && ok "Crash 133: Wiederholung rettet den Lauf (rc=0)" || no "Crash 133: rc=$rc (erwartet 0)"
[ "$n" = "0" ] && ok "Crash 133: KEIN Alarm (Wiederholung erfolgreich)" || no "Crash 133: $n Alarme"
grep -q "NATIVE-CRASH rc=133" "$ROOT/out.log" && ok "Crash 133: Wiederholung geloggt" || no "Crash 133: kein Log-Eintrag"
grep -q "scan ok (nach Wiederholung)" "$ROOT/out.log" && ok "Crash 133: Erfolg quittiert" || no "Crash 133: kein Erfolgs-Log"
[ -f "$ROOT/reports/.heartbeat" ] && ok "Crash 133: Heartbeat gesetzt" || no "Crash 133: Heartbeat fehlt"

# 7) Zwei native Crashes → Alarm MIT Grund, rc bleibt der des 2. Laufs
setup; printf '133\n139\n' > "$SCAN_SEQ"
rc=$(go 133)
n=$(wc -l < "$CALLS")
[ "$rc" = "139" ] && ok "Crash 2×: rc des 2. Laufs (139) bleibt" || no "Crash 2×: rc=$rc (erwartet 139)"
[ "$n" = "1" ] && ok "Crash 2×: genau 1 Alarm" || no "Crash 2×: $n Alarme"
grep -q "V8-Abbruch" "$CALLS" && ok "Crash 2×: Alarm nennt den Grund" || no "Crash 2×: kein --reason mit V8-Grund"
grep -q "Wiederholung ebenfalls gescheitert" "$ROOT/out.log" && ok "Crash 2×: 2. Lauf geloggt" || no "Crash 2×: 2. Lauf nicht geloggt"

# 8) Crash NACH dem Report (Heartbeat frisch getoucht) → KEINE Wiederholung
setup; printf '133\n' > "$SCAN_SEQ"
FAKE_HB_TOUCH="$ROOT/reports/.heartbeat" RETRY_DELAY_SECONDS=0 PATH="$ROOT/bin:$PATH" \
  "$ROOT/wrap.sh" >"$ROOT/out.log" 2>&1; rc=$?
n=$(wc -l < "$CALLS")
[ "$rc" = "133" ] && ok "Crash nach Report: rc=133" || no "Crash nach Report: rc=$rc"
[ "$n" = "1" ] && ok "Crash nach Report: 1 Alarm" || no "Crash nach Report: $n Alarme"
grep -q "keine Wiederholung" "$ROOT/out.log" && ok "Crash nach Report: KEINE Wiederholung" || no "Crash nach Report: doch wiederholt"

echo "----"; echo "PASS=$PASS FAIL=$FAIL"
[ "$FAIL" = "0" ] || exit 1

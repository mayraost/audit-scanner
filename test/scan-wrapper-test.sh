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
  unset NODE_SCAN_RC NODE_NOTIFY_RC 2>/dev/null || true
  rm -rf "$ROOT"; mkdir -p "$ROOT/logs" "$ROOT/reports" "$ROOT/bin"
  CALLS="$ROOT/calls.txt"; : > "$CALLS"; export CALLS
  cat > "$ROOT/bin/node" <<'EOF'
#!/bin/sh
# Fake-node: unterscheidet per Subcommand (letztes Argument vor den Flags).
case "$*" in
  *"index.js scan")
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
go() { NODE_SCAN_RC="${1:-0}" PATH="$ROOT/bin:$PATH" "$ROOT/wrap.sh" >"$ROOT/out.log" 2>&1; local_r=$?; echo "$local_r"; }

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

# 3) notify-failure scheitert: Scan-rc bleibt
setup
NODE_SCAN_RC=7 NODE_NOTIFY_RC=5 PATH="$ROOT/bin:$PATH" "$ROOT/wrap.sh" >/dev/null 2>&1; rc=$?
[ "$rc" = "7" ] && ok "notify kaputt: Scan-rc=7 bleibt" || no "notify kaputt: rc=$rc (erwartet 7)"

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

echo "----"; echo "PASS=$PASS FAIL=$FAIL"
[ "$FAIL" = "0" ] || exit 1

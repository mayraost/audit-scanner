// Selbsttest des Fehlschlag-Alarms (v1.7.4), OFFLINE — kein Netzwerk, kein
// Telegram-Versand, kein Scan. Prüft nur die reine Formatierung:
// 1) Titel ist als Ausfall erkennbar und NICHT der Erfolgsreport-Titel.
// 2) rc, UTC-Zeitpunkt und Host landen in der Nachricht.
// 3) Tail: nur die letzten N Zeilen, leere Zeilen fallen weg.
// 4) Kappung: sehr lange Zeilen bleiben unter dem Telegram-Budget.
// 5) Secret-Redaktion (Bot-Token in URL, ghp_…, Authorization-Header).
// 6) Nachricht bleibt unter 4096 Zeichen (Telegram-Limit).

import {
  FAILURE_TAIL_LINES,
  FAILURE_TAIL_MAX_CHARS,
  failureTail,
  failureTitle,
  redactSecrets,
  renderFailureMessage,
} from './failure-notify.js';

/** Telegram sendMessage-Limit (Zeichen je Nachricht). */
const TELEGRAM_MAX = 4096;

export function failureNotifyTest(): number {
  let ok = true;
  const check = (label: string, cond: boolean, detail = ''): void => {
    process.stdout.write(`${cond ? 'OK  ' : 'FAIL'} ${label}${detail ? ` — ${detail}` : ''}\n`);
    ok &&= cond;
  };

  const at = '2026-11-09T15:00:01.234Z';
  const logText = [
    '=== scan start 2026-11-09T15:00:00Z ===',
    ...Array.from({ length: 20 }, (_, i) => `zeile-${i + 1}`),
    '',
    'Error: EACCES: permission denied, open \'/app/reports/digests.json\'',
    '=== scan FAILED rc=1 2026-11-09T15:00:01Z ===',
  ].join('\n');
  const msg = renderFailureMessage({ rc: 1, logText, at, hostname: 'audit-scanner' });

  // 1) Titel
  check('Titel = FEHLGESCHLAGEN', failureTitle(new Date(at)).startsWith('⚠️ CVE-Audit FEHLGESCHLAGEN 2026-11-09'), failureTitle(new Date(at)));
  check('Titel nicht mit Erfolgsreport verwechselbar', !/^🔐/.test(failureTitle(new Date(at))));
  check('Nachricht als Fehlschlag markiert', msg.includes('FEHLGESCHLAGEN') && msg.includes('KEIN Report'));

  // 2) Kontext
  check('rc in Nachricht', msg.includes('Exit-Code: 1'));
  check('UTC-Zeitpunkt in Nachricht', msg.includes(at));
  check('Host in Nachricht', msg.includes('Container/Host: audit-scanner'));

  // 3) Tail = letzte N Zeilen, letzte Zeile präsent
  const tail = failureTail(logText);
  const tailLines = tail.split('\n');
  check(`Tail hat max ${FAILURE_TAIL_LINES} Zeilen`, tailLines.length <= FAILURE_TAIL_LINES, `${tailLines.length} Zeilen`);
  check('Tail enthält die letzte Logzeile', tail.includes('=== scan FAILED rc=1'));
  check('Tail enthält keine leeren Zeilen', !tailLines.some((l) => l.trim() === ''));
  check('leerer Log → Platzhalter', failureTail('') === '(kein Log-Tail verfügbar)');

  // 4) Kappung bei Monster-Zeilen
  const huge = 'X'.repeat(FAILURE_TAIL_MAX_CHARS * 3);
  const hugeTail = failureTail(`vorne\n${huge}`);
  check('Kappung auf maxChars', hugeTail.length <= FAILURE_TAIL_MAX_CHARS + 20, `${hugeTail.length} Zeichen`);
  check('Kappung behält ENDE der Zeile', hugeTail.endsWith('X') && hugeTail.startsWith('…(gekürzt)'));

  // 5) Redaktion
  const dirty = redactSecrets(
    [
      'POST https://api.telegram.org/bot123456789:AAFakeTokenValue/sendMessage 400',
      'bad credentials: ghp_' + 'a'.repeat(30),
      'bad credentials: github_pat_' + 'b'.repeat(30),
      'headers: Authorization: Bearer abcdef123456',
    ].join('\n')
  );
  check('Bot-Token redigiert', !dirty.includes('AAFakeTokenValue') && dirty.includes('bot<redacted>'));
  check('ghp_-Token redigiert', !dirty.includes('ghp_aaaa'));
  check('github_pat_-Token redigiert', !dirty.includes('github_pat_bbbb'));
  check('Bearer-Header redigiert', !dirty.includes('abcdef123456'));
  check('harmlose Zeilen bleiben lesbar', redactSecrets('EACCES: digests.json').includes('digests.json'));

  // 6) Nachricht bleibt unter dem Telegram-Limit, auch bei maximalem Tail
  const worst = renderFailureMessage({
    rc: 137,
    logText: Array.from({ length: 50 }, () => 'Y'.repeat(FAILURE_TAIL_MAX_CHARS)).join('\n'),
    at,
    hostname: 'x'.repeat(300),
  });
  check(`Nachricht < ${TELEGRAM_MAX} Zeichen (Worst Case)`, worst.length < TELEGRAM_MAX, `${worst.length} Zeichen`);
  check('unbekannter rc wird benannt', renderFailureMessage({ rc: null, logText: '', at }).includes('Exit-Code: unbekannt'));

  // 7) Abbruch-Variante (v1.7.5, trap-Pfad): eigener Wortlaut, kein „KEIN Report"
  const aborted = renderFailureMessage({
    rc: 143,
    logText: 'x',
    at,
    reason: 'Lauf abgebrochen (Signal)',
  });
  check('Abbruch: sagt ABGEBROCHEN', aborted.includes('ABGEBROCHEN'));
  check('Abbruch: behauptet NICHT "KEIN Report"', !aborted.includes('KEIN Report'));
  check('Abbruch: Grund enthalten', aborted.includes('Lauf abgebrochen'));
  // Ohne --reason muss weiterhin der normale Fehlschlag-Text kommen.
  check('ohne --reason: alte Formulierung', renderFailureMessage({ rc: 1, logText: '', at }).includes('FEHLGESCHLAGEN'));

  process.stdout.write(ok ? './ notify-failure-test PASS\n' : '✗ notify-failure-test FAIL\n');
  return ok ? 0 : 1;
}

// Fehlschlag-Alarm (v1.7.4): Telegram-Nachricht, wenn der Nachtlauf NICHT
// durchläuft.
//
// Motivation (Vorfall 08./09.11.2026): Ein Scan brach mit
// `EACCES: permission denied, open '/app/reports/digests.json'` ab. Weil der
// Wrapper nur im Erfolgsfall den Heartbeat toucht, zeigte der HEALTHCHECK den
// Container noch bis zu 48 h als `healthy`, und Telegram kannte bisher nur den
// Erfolgspfad (sendTelegramFromReport) → der Ausfall blieb zwei Tage unbemerkt.
//
// Design:
// - Aufruf aus `bin/scan-wrapper.sh` im else-Zweig:
//     node /app/dist/index.js notify-failure --rc <rc> --log <logfile>
//   Die Shell bleibt dünn: sie kennt nur rc + Logpfad, die Formatierung und
//   der Versand passieren hier (wiederverwendet sendTelegramReport →
//   gleiche ENV-/Auth-/Chunking-Logik wie der Erfolgsreport, kein Duplikat).
// - Titel ist bewusst NICHT `🔐 CVE-Audit …`, sondern `⚠️ CVE-Audit
//   FEHLGESCHLAGEN …` — ein Ausfall darf auf keinen Fall wie ein normaler
//   Report aussehen (kein „grüner“ Scan gemeint).
// - Fehlende TELEGRAM_* ENV → Skip (sendTelegramReport loggt das bereits und
//   bricht den Rest nicht ab), Netzwerkfehler → false, kein Throw.
// - Secrets: der Log-Tail wird VOR dem Senden redigiert (Telegram-URLs mit
//   Bot-Token, `ghp_…`/`github_pat_…`, `Authorization:`-Header) — im Container
//   leakt zwar nichts, der Scan schreibt aber auch GitHub-API-Fehler ins Log.

import os from 'node:os';

import { log } from './config.js';
import { sendTelegramReport } from './telegram.js';

/** Zeilen aus dem Scan-Log, die als Fehler-Kontext mitgeschickt werden. */
export const FAILURE_TAIL_LINES = 15;
/**
 * Zeichen-Budget für den Tail: Telegram erlaubt 4096 Zeichen/Nachricht; der
 * Rahmen (Titel, rc, Host, Hinweise) belegt ein paar hundert → 1800 bleibt
 * sicher darunter, auch bei sehr langen Zeilen (z. B. trivy-Dumps).
 */
export const FAILURE_TAIL_MAX_CHARS = 1800;

/** Einzeiler-Feld (rc, Host) — sehr lange Werte hart kürzen. */
function trim(s: string, max: number): string {
  const flat = s.replace(/\s+/g, ' ').trim();
  return flat.length <= max ? flat : `${flat.slice(0, max - 1)}…`;
}

/**
 * Secret-Redaktion für alles, was aus fremden Logzeilen stammt.
 * Reihenfolge egal (die Muster überschneiden sich nicht), Ziel ist nur:
 * Token/Strings dürfen NIE im Telegram-Kanal landen.
 */
export function redactSecrets(text: string): string {
  return text
    // Telegram-Bot-API-URLs enthalten das Token im Pfad (/bot<id>:<secret>/).
    .replace(/bot\d+:[A-Za-z0-9_-]+/g, 'bot<redacted>')
    // GitHub-Tokens (classic + fine-grained PAT).
    .replace(/\bghp_[A-Za-z0-9]{20,}/g, '<redacted-token>')
    .replace(/\bgithub_pat_[A-Za-z0-9_]{20,}/g, '<redacted-token>')
    // Generische Bearer-/Authorization-Header in Fehlermeldungen.
    .replace(/(Authorization:\s*(?:Bearer|token)\s+)\S+/gi, '$1<redacted>');
}

/**
 * Letzte N Zeilen eines Log-Textes, redigiert + auf maxChars gekürzt
 * (Kappung von VORNE, damit die letzten — relevantesten — Zeilen bleiben).
 * Leere Eingabe → `(kein Log-Tail verfügbar)`.
 */
export function failureTail(
  logText: string,
  lines = FAILURE_TAIL_LINES,
  maxChars = FAILURE_TAIL_MAX_CHARS
): string {
  const tail = logText
    .split('\n')
    .filter((l) => l.trim().length > 0)
    .slice(-lines)
    .join('\n');
  const redacted = redactSecrets(tail).trim();
  if (!redacted) return '(kein Log-Tail verfügbar)';
  if (redacted.length <= maxChars) return redacted;
  return `…(gekürzt)\n${redacted.slice(redacted.length - maxChars)}`;
}

export interface FailureDetails {
  /** Exit-Code des fehlgeschlagenen `scan`-Laufs (0/leer → als 1 gemeldet). */
  rc: number | string | null;
  /** Inhalt des Scan-Logs (Wrapper liest `/app/logs/scan.log`). */
  logText: string;
  /** Zeitpunkt des Fehlschlags (UTC-ISO); Default = jetzt. */
  at?: string;
  /** Hostname; Default = os.hostname(). */
  hostname?: string;
}

/** Titelzeile — bewusst unterscheidbar vom Erfolgsreport (`🔐 CVE-Audit <datum>`). */
export function failureTitle(at: Date = new Date()): string {
  return `⚠️ CVE-Audit FEHLGESCHLAGEN ${at.toISOString().slice(0, 10)}`;
}

/**
 * Nachrichtentext des Ausfall-Alarms. Reine Funktion (kein I/O), damit sie
 * offline testbar ist (`notify-failure-test`).
 */
export function renderFailureMessage(d: FailureDetails): string {
  const at = d.at ?? new Date().toISOString();
  const rc = d.rc === null || d.rc === '' ? 'unbekannt' : String(d.rc);
  const host = trim(d.hostname ?? os.hostname(), 80);
  const reason = `scan beendet mit rc=${rc}`;
  return [
    'Der nächtliche CVE-Scan ist FEHLGESCHLAGEN — es liegt KEIN Report vor.',
    `Exit-Code: ${rc}`,
    `Zeitpunkt (UTC): ${at}`,
    `Container/Host: ${host}`,
    `Grund: ${reason}`,
    '',
    `Letzte ${FAILURE_TAIL_LINES} Log-Zeilen (${trim('/app/logs/scan.log', 120)}):`,
    '```',
    failureTail(d.logText),
    '```',
    '',
    'Hinweis: Der Heartbeat wurde NICHT erneuert — der HEALTHCHECK flippt nach',
    '48 h ohne Erfolgslauf auf unhealthy. Prüfen:',
    '  docker exec <container> tail -50 /app/logs/scan.log',
  ].join('\n');
}

/**
 * Meldet den Fehlschlag auf Telegram. Gibt zurück, ob wirklich gesendet
 * wurde (false = ENV fehlt / Senden fehlgeschlagen) — wirft NIE, damit der
 * Wrapper den Original-Exit-Code des Scans weiterreichen kann.
 */
export async function notifyScanFailure(d: FailureDetails): Promise<boolean> {
  const at = d.at ?? new Date().toISOString();
  try {
    return await sendTelegramReport(failureTitle(new Date(at)), renderFailureMessage({ ...d, at }));
  } catch (err) {
    const m = err instanceof Error ? err.message : String(err);
    log(`WARN: Fehlschlag-Alarm konnte nicht gesendet werden (Scan-rc bleibt unberührt): ${m}`);
    return false;
  }
}

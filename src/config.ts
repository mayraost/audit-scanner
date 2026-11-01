// Runtime-Konfiguration: ENV-Parsing, Token-Resolution, Pfad-Konventionen.
// SECURITY: Alle Secrets kommen ausschließlich aus ENV (Coolify-injected im Container).
// Kein Fallback auf Secret-Dateien. Lokaler Dev-Fallback: `gh auth token` (gh CLI),
// NUR wenn GH_TOKEN fehlt — im Container ist GH_TOKEN immer gesetzt.

import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

export const OWNER = 'mayraost';

/** Container-Erkennung: im Coolify-Container existiert /.dockerenv. */
export const IS_CONTAINER = fs.existsSync('/.dockerenv');

/** Arbeitsverzeichnis im Image: /app. */
export const WORK_DIR = process.env.WORK_DIR ?? (IS_CONTAINER ? '/app' : process.cwd());

export const REPORTS_DIR = process.env.REPORTS_DIR ?? path.join(WORK_DIR, 'reports');
export const TRIVY_CACHE_DIR =
  process.env.TRIVY_CACHE_DIR ?? path.join(WORK_DIR, '.cache', 'trivy');
export const TRIVY_BIN = process.env.TRIVY_BIN ?? 'trivy';
export const CRON_SCHEDULE = process.env.CRON_SCHEDULE ?? '0 16 * * *';
export const HEARTBEAT_FILE = path.join(REPORTS_DIR, '.heartbeat');

export const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN ?? '';
export const TELEGRAM_CHAT_ID = process.env.TELEGRAM_CHAT_ID ?? '';
/** optionaler MarkdownV2-Modus; Default: plain text (Spec §6: Escaping-Problematik). */
export const TELEGRAM_PARSE_MODE = process.env.TELEGRAM_PARSE_MODE === 'MarkdownV2'
  ? 'MarkdownV2'
  : '';

export function fixPrsEnabled(): boolean {
  return /^(1|true|yes)$/i.test(process.env.ENABLE_FIX_PRS ?? '');
}

export function skipRepos(): string[] {
  return (process.env.SKIP_REPOS ?? '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}

export function telegramConfigured(): boolean {
  return TELEGRAM_BOT_TOKEN.length > 0 && TELEGRAM_CHAT_ID.length > 0;
}

let cachedToken: string | undefined;

/**
 * GitHub-Token: ENV `GH_TOKEN` (Container-Pfad) oder Dev-Fallback `gh auth token`
 * (lokale, authed gh-CLI; im Container niemals nötig).
 */
export function githubToken(): string {
  if (cachedToken) return cachedToken;
  const env = process.env.GH_TOKEN?.trim();
  if (env) {
    cachedToken = env;
    return cachedToken;
  }
  try {
    cachedToken = execFileSync('gh', ['auth', 'token'], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    }).trim();
    log('GH_TOKEN nicht gesetzt — Dev-Fallback: lokales `gh auth token` wird verwendet.');
    if (!cachedToken) throw new Error('leer');
    return cachedToken;
  } catch {
    throw new Error(
      'Keine Auth: GH_TOKEN nicht gesetzt und `gh auth token` (lokale gh-CLI) nicht verfügbar.'
    );
  }
}

/** Zeitstempel-konsistenter Logger. */
export function log(message: string): void {
  process.stderr.write(`[${new Date().toISOString()}] ${message}\n`);
}

export function parseIsoDateKey(d = new Date()): string {
  return d.toISOString().slice(0, 10); // YYYY-MM-DD (UTC)
}

export function ensureDir(p: string): string {
  fs.mkdirSync(p, { recursive: true });
  return p;
}

export function tmpRoot(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'cve-audit-'));
}

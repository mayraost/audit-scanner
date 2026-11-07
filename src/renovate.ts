// Renovate als ANALYSE-Quelle (v1.7.0) — Owner-Entscheidung:
// 1. Der Scanner behält die PR-Hoheit. Renovate läuft ausschließlich als
//    `--dry-run=lookup` (kein Branch, kein Commit, kein PR) und liefert nur
//    Vorschläge für EXAKT GEPINNTE deps (Floating-Specs findet der Pinning-
//    Scanner exakt und braucht kein Renovate).
// 2. Soaking filtert Renovate selbst (`minimumReleaseAge` aus der Scanner-
//    Config, abgeleitet aus UPDATE_MIN_AGE_DAYS = EINE Regelquelle) — der
//    Scanner filtert NICHT nochmal nach Alter.
// 3. Alle Renovate-Vorschläge landen im bestehenden Pins-PR
//    (`cve-audit/pins-<date>`, siehe pinning.ts) — nie ein eigener PR.
//
// Maschinenlesbarkeit (verifiziert gegen renovate@44.222.1):
// - `--log-format=json` existiert NICHT; nur Env `LOG_FORMAT=json`
//   (dann landet auch der Debug-Log als JSONL auf stdout).
// - Ohne `--onboarding=false --require-config=ignored` bricht der Platform-
//   `local`-Lauf mit "does not support local presets" ab.
// - Die Update-Daten stehen im Log-Objekt `msg === "packageFiles with updates"`
//   unter `config` (Map manager → packageFiles[]), NICHT unter `packageFiles`.
//
// Fail-soft: fehlt der Bin oder schlägt der Lauf fehl (Timeout, Exit≠0,
// kaputter Output), gibt es `{ ok: false, note }` — nie ein Throw. Der
// Aufrufer degradiert still auf den Pinning-Scanner.

import { execFile, execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { promisify } from 'node:util';

import { log, tmpRoot } from './config.js';
import { soakingMinAgeDays } from './soaking.js';

const execFileP = promisify(execFile);

/** Bin-Name/-Pfad (Image: `renovate` im PATH, lokal z. B. npx-Installation). */
export function renovateBin(): string {
  return process.env.RENOVATE_BIN?.trim() || 'renovate';
}

/**
 * ENABLE_RENOVATE (Default 0): ohne explizites Opt-in ändert sich nichts am
 * Deploy-Verhalten — dann wird Renovate gar nicht erst aufgerufen.
 */
export function renovateEnabled(): boolean {
  return /^(1|true|yes)$/i.test(process.env.ENABLE_RENOVATE ?? '');
}

/** Timeout je Repo (Default 120 s, Override via RENOVATE_TIMEOUT_MS). */
export function renovateTimeoutMs(): number {
  const raw = process.env.RENOVATE_TIMEOUT_MS?.trim();
  const n = raw ? Number(raw) : Number.NaN;
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : 120_000;
}

/**
 * Ein Update-Vorschlag, reduziert auf die Felder, die der Pins-PR/Report
 * braucht. `newVersion` ist die HÖCHSTE Version aus `updates[]` eines deps.
 */
export interface RenovateCandidate {
  packageFile: string;
  depName: string;
  depType: string;
  currentValue: string;
  newVersion: string;
  updateType: string;
  releaseTimestamp: string | null;
  ageDays: number | null;
  isBreaking: boolean;
}

/** Ergebnis eines Lookup-Laufs; `note` erklärt Fehler/leere Läufe. */
export interface RenovateResult {
  ok: boolean;
  candidates: RenovateCandidate[];
  note?: string;
}

// ———————————————————————— Verfügbarkeit (gecacht) ————————————————————————

let availability: boolean | undefined;

/**
 * Prüft `renovate --version` (Bin via RENOVATE_BIN, Default `renovate`).
 * Gecacht pro Prozess; fehlt der Bin → false (Aufrufer loggt einmal).
 */
export function renovateAvailable(): boolean {
  if (availability !== undefined) return availability;
  const bin = renovateBin();
  try {
    const out = execFileSync(bin, ['--version'], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
      timeout: 20_000,
    }).trim();
    // In diesem Repo: reine Versionsausgabe ("44.222.1"). `available` ist eine
    // dist-tags-Warnung von `npm view`, nicht der Renovate-Bin — akzeptieren,
    // damit der häufige Alias/Shim-Fall nicht still degradiert.
    availability = /^\d+\.\d+\.\d+/.test(out) || /^available\b/.test(out);
  } catch {
    availability = false;
  }
  return availability;
}

// ————————————————————————— Konfiguration + Lauf ——————————————————————————

/** Soaking-Dauer als Renovate-Duration (`"3 days"`); 0 → `"0 days"` (aus). */
export function minimumReleaseAge(): string {
  return `${soakingMinAgeDays()} days`;
}

/**
 * Inhalt der temporären Renovate-Config. Schreibt NIE ins gescannte Repo
 * (Aufrufer legt sie im tmp-Dir ab und setzt `RENOVATE_CONFIG_FILE`).
 * `rangeStrategy: pin` + `prCreation: never`: Renovate kann prinzipiell nicht
 * committen — die PR-Hoheit bleibt beim Scanner.
 */
export function renovateConfig(): Record<string, unknown> {
  return {
    $schema: 'https://docs.renovatebot.com/renovate-schema.json',
    extends: ['config:base'],
    minimumReleaseAge: minimumReleaseAge(),
    rangeStrategy: 'pin',
    prCreation: 'never',
    rebaseWhen: 'never',
  };
}

/**
 * Startet `renovate --dry-run=lookup --platform=local …` IN `repoDir` und
 * parst die JSONL-Ausgabe. Timeout exit≠0/leer → `{ ok: false, note }`.
 */
export async function runRenovateLookup(repoDir: string, opts?: { timeoutMs?: number }): Promise<RenovateResult> {
  const work = tmpRoot();
  try {
    const configPath = path.join(work, 'renovate-global.json');
    fs.writeFileSync(configPath, `${JSON.stringify(renovateConfig(), null, 2)}\n`);
    const { stdout } = await execFileP(
      renovateBin(),
      [
        '--dry-run=lookup',
        '--platform=local',
        '--onboarding=false',
        '--require-config=ignored',
      ],
      {
        cwd: repoDir,
        timeout: opts?.timeoutMs ?? renovateTimeoutMs(),
        // Debug-JSONL für große Monorepos: hart kappen statt Puffer-Overflow.
        maxBuffer: 64 * 1024 * 1024,
        env: {
          ...process.env,
          LOG_LEVEL: 'debug',
          LOG_FORMAT: 'json',
          RENOVATE_CONFIG_FILE: configPath,
          // Cache im tmp-Dir (kein Schreiben ins gescannte Repo, kein
          // Renovate-Profil-Pfad im Home des Users).
          RENOVATE_CACHE_DIR: path.join(work, 'cache'),
          RENOVATE_BASE_DIR: work,
        },
      }
    );
    return parseRenovateLog(stdout);
  } catch (err) {
    // execFile wirft bei Exit≠0 UND bei Timeout (SIGTERM + code null).
    const e = err as { killed?: boolean; signal?: string; code?: number | string | null; message?: string };
    const note = e.killed
      ? `Timeout nach ${opts?.timeoutMs ?? renovateTimeoutMs()} ms`
      : `Renovate-Lauf fehlgeschlagen (exit ${String(e.code ?? e.signal ?? '?')}): ${(e.message ?? '?').slice(0, 200)}`;
    return { ok: false, candidates: [], note };
  } finally {
    fs.rmSync(work, { recursive: true, force: true });
  }
}

// ————————————————————————————— Parser ———————————————————————————————————

/** Roh-Form einer Update-Zeile aus dem Renovate-JSONL (nur gelesene Felder). */
interface RawUpdate {
  newVersion?: unknown;
  updateType?: unknown;
  releaseTimestamp?: unknown;
  newVersionAgeInDays?: unknown;
  isBreaking?: unknown;
}

interface RawDep {
  depName?: unknown;
  depType?: unknown;
  currentValue?: unknown;
  updates?: unknown;
}

interface RawPackageFile {
  packageFile?: unknown;
  deps?: unknown;
}

function asString(v: unknown): string | null {
  return typeof v === 'string' && v.length > 0 ? v : null;
}

function asNumber(v: unknown): number | null {
  return typeof v === 'number' && Number.isFinite(v) ? v : null;
}

/**
 * Wählt aus `updates[]` die HÖCHSTE `newVersion`. Verglichen wird
 * `localeCompare(…, numeric: true)` — bewusst semver-frei (Renovate kann
 * nicht-npm-Versionen liefern; Numerik-Vergleich reicht, `newVersionAgeInDays`
 * stammt aus genau diesem Eintrag). Einträge ohne `newVersion` fliegen raus.
 */
function highestUpdate(updates: unknown): RawUpdate | null {
  if (!Array.isArray(updates)) return null;
  let best: RawUpdate | null = null;
  let bestVersion = '';
  for (const u of updates as unknown[]) {
    if (!u || typeof u !== 'object') continue;
    const cand = u as RawUpdate;
    const version = asString(cand.newVersion);
    if (!version) continue;
    if (best === null || version.localeCompare(bestVersion, undefined, { numeric: true }) > 0) {
      best = cand;
      bestVersion = version;
    }
  }
  return best;
}

/**
 * Parser für die Renovate-JSONL-Ausgabe (stdout, zeilenweise). Sucht das
 * Log-Objekt `msg === "packageFiles with updates"`, liest `config`
 * (Map manager → packageFiles[]) und reduziert auf `RenovateCandidate[]`.
 *
 * - Nur deps mit nicht-leeren `updates[]`.
 * - Je dep nur die höchste `newVersion`.
 * - Kein Treffer / kaputte Zeilen → `{ ok: false, note }` (kein Crash;
 *   einzelne Nicht-JSON-Zeilen werden übersprungen).
 */
export function parseRenovateLog(stdout: string): RenovateResult {
  let found = false;
  const candidates: RenovateCandidate[] = [];
  for (const line of stdout.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed.startsWith('{')) continue;
    let obj: Record<string, unknown>;
    try {
      obj = JSON.parse(trimmed) as Record<string, unknown>;
    } catch {
      continue; // Müll-Zeile (z. B. Shell-Warnung moderiert auf stdout)
    }
    if (obj.msg !== 'packageFiles with updates') continue;
    found = true;
    const config = obj.config;
    if (!config || typeof config !== 'object') continue;
    for (const packageFiles of Object.values(config as Record<string, unknown>)) {
      if (!Array.isArray(packageFiles)) continue;
      for (const pf of packageFiles as unknown[]) {
        if (!pf || typeof pf !== 'object') continue;
        const file = pf as RawPackageFile;
        const packageFile = asString(file.packageFile) ?? 'package.json';
        if (!Array.isArray(file.deps)) continue;
        for (const d of file.deps as unknown[]) {
          if (!d || typeof d !== 'object') continue;
          const dep = d as RawDep;
          const depName = asString(dep.depName);
          if (!depName) continue;
          const best = highestUpdate(dep.updates);
          if (!best) continue; // nur deps MIT Updates
          candidates.push({
            packageFile,
            depName,
            depType: asString(dep.depType) ?? 'dependencies',
            currentValue: asString(dep.currentValue) ?? '',
            newVersion: asString(best.newVersion) ?? '',
            updateType: asString(best.updateType) ?? 'unknown',
            releaseTimestamp: asString(best.releaseTimestamp),
            ageDays: asNumber(best.newVersionAgeInDays),
            isBreaking: best.isBreaking === true,
          });
        }
      }
    }
  }
  if (!found) return { ok: false, candidates: [], note: 'kein "packageFiles with updates"-Objekt im Renovate-Log' };
  return { ok: true, candidates };
}

// ———————————————————————— Einbindung in den Scan ——————————————————————

/** Einmal-Log: Bin fehlt → still degradieren, aber sichtbar einmal melden. */
let unavailableLogged = false;

/**
 * Renovate-Kandidaten für ein Repo (bereits gegen die package.json
 * abgeglichen in pinning.ts). Deaktiviert/fehlend → leeres Ergebnis.
 */
export async function collectRenovateCandidates(repoDir: string): Promise<RenovateResult> {
  if (!renovateEnabled()) return { ok: false, candidates: [], note: 'ENABLE_RENOVATE nicht gesetzt' };
  if (!renovateAvailable()) {
    if (!unavailableLogged) {
      log(
        `Renovate (${renovateBin()}) nicht verfügbar — Renovate-Updates werden übersprungen, ` +
          'Pinning-Scan läuft unverändert weiter.'
      );
      unavailableLogged = true;
    }
    return { ok: false, candidates: [], note: 'renovate-Bin fehlt' };
  }
  return runRenovateLookup(repoDir);
}

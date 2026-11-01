// PR-Dedupe-State (reports/state.json, Volume audit-reports — Pfad konsistent
// mit REPORTS_DIR-Handling): persistente Liste angelegter Fix-PRs je Repo, um
// (a) keine Duplikat-PRs zu erzeugen und (b) täglich an offene CVEs zu erinnern.
// Schema tolerant laden: corrupt/alter JSON → leerer State (Rebuild-from-GitHub
// passiert implizit über 'created'/'exists'-Pfade in fix-pr.ts — Dokumentation README).

import fs from 'node:fs';
import path from 'node:path';

import { OWNER, REPORTS_DIR, ensureDir, log } from './config.js';
import { ghJsonOrNull } from './github.js';

export interface StateFinding {
  package: string;
  version: string;
  severity: string;
  ghsaId: string | null; // null = trivy-only ohne GH-Advisory
}

export interface PrEntry {
  branch: string;
  prUrl: string;
  prNumber: number;
  ghsaIds: string[];
  createdAt: string; // ISO
  lastSeen: string; // ISO — letzter Lauf, in dem der PR noch offen war
  findings: StateFinding[];
}

export interface State {
  prs: Record<string, PrEntry[]>;
}

const EMPTY_STATE: State = { prs: {} };

export function stateFilePath(): string {
  return path.join(REPORTS_DIR, 'state.json');
}

function isPrEntry(v: unknown): v is PrEntry {
  if (typeof v !== 'object' || v === null) return false;
  const e = v as Partial<PrEntry>;
  return (
    typeof e.branch === 'string' &&
    typeof e.prUrl === 'string' &&
    typeof e.prNumber === 'number' &&
    typeof e.createdAt === 'string' &&
    typeof e.lastSeen === 'string' &&
    Array.isArray(e.findings) &&
    Array.isArray(e.ghsaIds)
  );
}

/** Defensiver Parse (Schema tolerant; corrupt → null → Rebuild aus GitHub). */
export function parseState(raw: string): State | null {
  let json: unknown;
  try {
    json = JSON.parse(raw);
  } catch {
    return null;
  }
  if (typeof json !== 'object' || json === null) return null;
  const prs = (json as { prs?: unknown }).prs;
  if (typeof prs !== 'object' || prs === null) return null;
  const state: State = { prs: {} };
  for (const [repo, entries] of Object.entries(prs as Record<string, unknown>)) {
    if (!Array.isArray(entries)) continue;
    const valid = entries.filter(isPrEntry);
    if (valid.length > 0) state.prs[repo] = valid;
  }
  return state;
}

/** state.json laden — fehlend/corrupt = leerer State (nur Log, nie Throw). */
export function loadState(): State {
  try {
    const raw = fs.readFileSync(stateFilePath(), 'utf8');
    const state = parseState(raw);
    if (!state) {
      log('WARN: state.json corrupt — State wird neu aufgebaut (leer gestartet).');
      return structuredClone(EMPTY_STATE);
    }
    return state;
  } catch {
    return structuredClone(EMPTY_STATE); // fehlt → erster Lauf
  }
}

/** State-Persist: reports/state.json atomar genug (Volume, nur Scanner schreibt). */
export function saveState(state: State): void {
  ensureDir(REPORTS_DIR);
  fs.writeFileSync(stateFilePath(), JSON.stringify(state, null, 2) + '\n');
}

export function entriesForRepo(state: State, repo: string): PrEntry[] {
  return state.prs[repo] ?? [];
}

/** Eintrag anlegen/aktualisieren (identifiziert über prNumber). */
export function upsertEntry(state: State, repo: string, entry: PrEntry): void {
  const list = (state.prs[repo] ??= []);
  const idx = list.findIndex((e) => e.prNumber === entry.prNumber);
  if (idx >= 0) list[idx] = entry;
  else list.push(entry);
}

/** lastSeen auf jetzt setzen (PR war diesen Lauf noch offen). */
export function touchLastSeen(state: State, repo: string, prNumber: number): void {
  const entry = entriesForRepo(state, repo).find((e) => e.prNumber === prNumber);
  if (entry) entry.lastSeen = new Date().toISOString();
}

/** State-Eintrag entfernen (PR geschlossen/gemergt → Findings gelten wieder als neu). */
export function removeEntry(state: State, repo: string, prNumber: number): void {
  const list = state.prs[repo];
  if (!list) return;
  state.prs[repo] = list.filter((e) => e.prNumber !== prNumber);
  if (state.prs[repo]!.length === 0) delete state.prs[repo];
}

/** Enthält einer der offenen Entries diesen Finding (pkg+ghsa)? */
export function isKnownFinding(state: State, repo: string, pkg: string, ghsaId: string | null): boolean {
  const key = `${pkg.toLowerCase()}|${ghsaId ?? 'trivy'}`;
  return entriesForRepo(state, repo).some((e) =>
    e.findings.some((f) => `${f.package.toLowerCase()}|${f.ghsaId ?? 'trivy'}` === key)
  );
}

export interface PrOpenStatus {
  open: boolean;
  prUrl: string | null;
  prNumber: number | null;
}

/** Remote-Check: offener PR zur Branch-ID? (GET /pulls?head=…&state=open). */
export async function prOpenStatus(repo: string, branch: string): Promise<PrOpenStatus> {
  const prs = await ghJsonOrNull<Array<{ html_url: string; number: number }>>(
    `/repos/${OWNER}/${repo}/pulls?state=open&head=${OWNER}:${encodeURIComponent(branch)}`
  );
  if (!prs || prs.length === 0) return { open: false, prUrl: null, prNumber: null };
  return { open: true, prUrl: prs[0]!.html_url, prNumber: prs[0]!.number };
}

/**
 * State je Repo gegen GitHub reconcilen:
 * - PR noch offen → lastSeen aktualisieren, Entry bleibt.
 * - PR geschlossen/gemergt/branch weg → Entry entfernen (Findings wieder "neu",
 *   ggf. wird beim nächsten vulnerability-Aufkommen ein normaler neuer PR erzeugt).
 */
export async function reconcileRepo(state: State, repo: string): Promise<PrEntry[]> {
  const open: PrEntry[] = [];
  for (const entry of entriesForRepo(state, repo)) {
    let status: PrOpenStatus;
    try {
      status = await prOpenStatus(repo, entry.branch);
    } catch (err) {
      // API-Fehler: konservativ Entry behalten (nicht als gelöscht werten)
      const msg = err instanceof Error ? err.message : String(err);
      log(`WARN: PR-Status-Check ${repo}/${entry.branch} fehlgeschlagen (Entry behalten): ${msg}`);
      open.push(entry);
      continue;
    }
    if (status.open) {
      entry.prUrl = status.prUrl ?? entry.prUrl;
      entry.prNumber = status.prNumber ?? entry.prNumber;
      entry.lastSeen = new Date().toISOString();
      open.push(entry);
    } else {
      log(`${repo}: Fix-PR #${entry.prNumber} (${entry.branch}) nicht mehr offen — State-Eintrag entfernt.`);
      removeEntry(state, repo, entry.prNumber);
    }
  }
  return open;
}

/** Alter in Tagen (abgerundet) seit createdAt. */
export function ageDays(entry: PrEntry, now = new Date()): number {
  const created = Date.parse(entry.createdAt);
  if (Number.isNaN(created)) return 0;
  return Math.max(0, Math.floor((now.getTime() - created) / 86_400_000));
}

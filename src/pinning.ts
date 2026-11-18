// Pinning-Enforcement (v1.5.0, Regel „Dependency-Pinning & Update-Pflicht" aus
// AGENTS.md): KEINE floating versions — npm-Specifier müssen exakt sein.
// - Detection je gescanntes Repo: alle deps aus dependencies/devDependencies
//   (Fix-Kandidaten) + optionalDependencies/peerDependencies (observed,
//   report-only). Floating = semver.valid(spec) === null (startet mit ^ ~ >= * x,
//   Ranges, "latest", Teilversionen wie 1.x / 1.2).
// - severity: warn = production dep (dependencies), info = devDependencies +
//   optional/peer. Kein CVE-Bezug, KEIN LLM (deterministisch).
// - latest über registry.npmjs.org (dist-tags.latest), Cache pro pkg.
// - Fix-PR (immer-PR-Policy): ALLE floating deps eines Repos → exakte latest-
//   Versionen in EINEM PR (branch cve-audit/pins-<date>), alle package.json-
//   Manifests des Repos in derselben Branch. Downgrade-Guard analog CVE-Fix
//   (niemals auf kleinere Version). Lockfile-Regen im Manifestverzeichnis.
//
// v1.7.2 (belegt 2026-11-07, CVE-Audit-Lauf):
// - KEIN `[skip ci]` mehr in Pins-PR-Commits: Coolify überspringt bei dem Marker
//   den Auto-Deploy und antwortet dem Webhook trotzdem 200 OK → 5 Apps ohne
//   Deploy-Record bei komplett grünen Webhooks.
// - Peer-Awareness: der Pin berücksichtigt `peerDependencies` anderer direkter
//   Deps (payload 3.x verlangt graphql ^16, latest war 17.x → `npm ci` ERESOLVE).
// - Lockfile-Regen + Manifest-Schreibvorgang sind ALLES-ODER-NICHTS und laufen
//   VOR dem PUT (vorher: Manifest-PUT zuerst, Regen-Fehler danach → Manifest
//   ohne Lockfile im PR, PR-Body behauptete trotzdem "regenerated").
//
// v1.8.0 (Beta-Kanal-PRs): Pakete, die BEREITS auf einem Pre-Release stehen
// (`payload 4.0.0-beta.7`), bekommen ein echtes Update-Ziel und damit einen
// Pins-PR:
// - beta → beta: neuestes Beta/RC im SELBEN Kanal (`beta.7 → beta.9`).
// - beta → stable: das stabile Release ist da (`4.0.0-beta.7 → 4.0.0`).
// - NIE stable → beta: stabile Pins laufen nicht in diesen Zweig (kein
//   Beta-Hinweis, kein PR) — Owner-Regel, verhindert Dauerrauschen.
// - Weiterhin Info-only: Exoten (nightly/canary/insiders), optional/peer-Deps
//   und Kandidaten ohne Soaking-Reife.

import fs from 'node:fs';
import path from 'node:path';

import semver from 'semver';

import { OWNER, log } from './config.js';
import { b64, decodeB64, ghFetch, ghJson, ghJsonOrNull } from './github.js';
import type { RepoInfo } from './inventory.js';
import { regenerateLockfile, type FixResult } from './fix-pr.js';
import { channelCompatible, classifyPrerelease } from './prerelease.js';
import { npmVersionPublishedAt } from './publish-dates.js';
import type { RenovateCandidate } from './renovate.js';
import { collectRenovateCandidates, renovateEnabled } from './renovate.js';
import { updateEligibility, type Eligibility } from './soaking.js';
import { upsertEntry, type State } from './state.js';


export type PinSection =
  | 'dependencies'
  | 'devDependencies'
  | 'optionalDependencies'
  | 'peerDependencies';

export interface PinFinding {
  pkg: string;
  current: string;
  /** dist-tags.latest der npm-Registry (null = lookup fehlgeschlagen). */
  latest: string | null;
  section: PinSection;
  /** Repo-relativer package.json-Pfad (z. B. apps/web/package.json). */
  manifestPath: string;
  /** warn = production dep; info = dev/optional/peer (kein CVE). */
  severity: 'info' | 'warn';
  /** v1.7.0: woher der Vorschlag stammt (floating-Pin oder Renovate-Analyse). */
  source?: 'pinning' | 'renovate';
  /** v1.7.0: Renovate-updateType (major/minor/patch/pin/digest). */
  updateType?: string;
  /** v1.7.0: Alter der Zielversion in Tagen (Renovate releaseTimestamp). */
  releaseAgeDays?: number | null;
  /** v1.7.0: Major-/Breaking-Update → nur Report, nie PR. */
  majorOrBreaking?: boolean;
  /** v1.6.0: Paket steht bereits auf einem Pre-Release-Kanal (beta/rc/alpha). */
  betaPin?: boolean;
  /** v1.6.0: Publish-Datum der Ziel-Version (Soaking). */
  latestPublishedAt?: string | null;
  /** v1.6.0: Soaking-Entscheidung für das Pin-Ziel. */
  eligibility?: Eligibility;
  eligibilityLabel?: string;
  ageDays?: number | null;
  /**
   * v1.6.0/v1.8.0: neuerer Beta/RC-Kandidat im selben Kanal. Seit v1.8.0 ein
   * echtes PR-Ziel (beta → beta), nicht mehr nur Info.
   */
  prereleaseHint?: string | null;
  /** v1.6.0: Publish-Datum des Beta-Kandidaten. */
  prereleasePublishedAt?: string | null;
  /** v1.6.0: Soaking-Entscheidung für den Beta-Kandidaten. */
  prereleaseEligibility?: Eligibility;
  prereleaseLabel?: string;
  /** v1.7.2: Peer-Konflikt — der Kandidat wurde bewusst NICHT auf `latest` gepinnt. */
  peerConflict?: PeerConflict;
  /**
   * v1.7.2: tatsächliches Pin-Ziel. Abweichung von `latest` bei Peer-Ausweichen
   * (v1.7.2) und bei Beta-Kanal-Updates (v1.8.0: beta → beta oder beta → stable).
   */
  pinTarget?: string;
  /** v1.8.0: Art des Beta-Ziels — `beta` = Kanal-Update, `stable` = Kanal-Abschluss. */
  pinTargetKind?: 'beta' | 'stable';
}

export interface PinScanResult {
  findings: PinFinding[];
  /**
   * PR-Kandidaten: deps/devDeps, Ziel vorhanden (floating → `latest`, Beta →
   * `pinTarget`), kein Protocol/Path-Spec, kein Downgrade, Soaking reif.
   */
  fixable: PinFinding[];
}

const PIN_SECTIONS: PinSection[] = [
  'dependencies',
  'devDependencies',
  'optionalDependencies',
  'peerDependencies',
];

const PR_SECTIONS: PinSection[] = ['dependencies', 'devDependencies'];

// ———————————————— v1.7.2: injizierbare Abhängigkeiten (Tests offline) —————————
//
// Der Pins-Pfad hat drei Kontaktpunkte nach außen: npm-Registry (Packument),
// GitHub-contents-API (GET/PUT) und den Lockfile-Regen (spawn npm/pnpm).
// Alle laufen über dieses Interface, damit `pinning-test` mit Fakes laufen und
// die PR-Erzeugung (Commit-Reihenfolge, fail-closed, Peer-Gate) beweisen kann,
// ohne Netz und ohne echte PRs. Default = Produktions-Implementierung.

/** Peer-Konflikt: `dep` deklariert eine Peer-Range, die das Pin-Ziel verletzt. */
export interface PeerConflict {
  /** Paket, das die Peer-Range deklariert (z. B. `@payloadcms/next`). */
  dep: string;
  /** Version dieser dep, aus der die Range stammt (z. B. `4.0.0-beta.7`). */
  depVersion: string;
  /** Deklarierte Range (z. B. `^16.8.1`). */
  range: string;
  /** Range-konforme Ausweichversion (null = keine ermittelbar). */
  fallback: string | null;
}

/** GitHub-contents-Datei inkl. Blob-SHA (Spec Gotcha 1: sha = Blob-SHA). */
export interface GhFile {
  sha: string;
  content: string;
}

export interface PinDeps {
  /** npm-Packument (dist-tags + time[]) oder null bei Fehler. */
  packument: (pkg: string) => Promise<NpmPackument | null>;
  /** `peerDependencies` einer Paketversion (`npm view pkg@ver peerDependencies`). */
  peerDepsOf: (pkg: string, version: string) => Promise<Record<string, string> | null>;
  /** Versionsliste eines Pakets (für Range-Ausweichkandidaten); null = unbekannt. */
  versionsOf: (pkg: string) => Promise<string[] | null>;
  /** Publish-Datum einer Version (Soaking) — injizierbar für Offline-Tests. */
  publishedAt: (pkg: string, version: string) => Promise<{ publishedAt: string | null }>;
  /** Repo-relativer Pfad unter `ref` → Datei oder null (404). */
  contentsGet: (repo: string, filePath: string, ref: string) => Promise<GhFile | null>;
  /** Datei schreiben (sha = Blob-SHA). message ohne `[skip ci]`. */
  contentsPut: (
    repo: string,
    filePath: string,
    branch: string,
    blobSha: string,
    content: string,
    message: string
  ) => Promise<void>;
  /** Lockfile-Regen (tmp-Dir + npm/pnpm CLI). */
  regenerate: typeof regenerateLockfile;
  /** PR anlegen → Nummer + URL. */
  createPr: (
    repo: string,
    opts: { title: string; head: string; base: string; body: string; draft: boolean }
  ) => Promise<{ number: number; url: string }>;
  /** Branch von einem Commit-SHA anlegen. */
  createRef: (repo: string, branch: string, sha: string) => Promise<'created' | 'ref-exists'>;
  /** Branch löschen (Crash-Rest ohne offenen PR; 404 = schon weg, ok). */
  deleteRef: (repo: string, branch: string) => Promise<void>;
  /** Default-Branch-Head-SHA. */
  headSha: (repo: string, defaultBranch: string) => Promise<string>;
  /** Offener PR für die Branch → Nummer + URL oder null. */
  findOpenPr: (repo: string, branch: string) => Promise<{ number: number; url: string } | null>;
}

/** Default-Deps = echte Registry/API/CLI. Tests überschreiben einzelne Felder. */
export function pinDeps(): PinDeps {
  return {
    packument: (pkg) => npmPackument(pkg),
    peerDepsOf: (pkg, version) => npmPeerDependencies(pkg, version),
    versionsOf: (pkg) => npmVersions(pkg),
    publishedAt: async (pkg, version) => {
      const r = await npmVersionPublishedAt(pkg, version);
      return { publishedAt: r.publishedAt };
    },
    contentsGet: (repo, filePath, ref) =>
      ghJsonOrNull<GhFile>(`/repos/${OWNER}/${repo}/contents/${filePath}?ref=${encodeURIComponent(ref)}`),
    contentsPut: async (repo, filePath, branch, blobSha, content, message) => {
      const res = await ghFetch(
        `/repos/${OWNER}/${repo}/contents/${filePath}?branch=${encodeURIComponent(branch)}`,
        { method: 'PUT', body: JSON.stringify({ message, content: b64(content), sha: blobSha, branch }) }
      );
      if (!res.ok) throw new Error(`contents-PUT ${filePath} ${res.status}: ${(await res.text()).slice(0, 250)}`);
    },
    regenerate: regenerateLockfile,
    createPr: async (repo, o) => {
      const pr = await ghJson<{ html_url: string; number: number }>(`/repos/${OWNER}/${repo}/pulls`, {
        method: 'POST',
        body: JSON.stringify({ title: o.title, head: o.head, base: o.base, body: o.body, draft: o.draft }),
      });
      return { number: pr.number, url: pr.html_url };
    },
    createRef: (repo, branch, sha) => tryCreateRef(repo, branch, sha),
    deleteRef: (repo, branch) => deleteRef(repo, branch),
    headSha: async (repo, defaultBranch) => {
      const ref = await ghJson<{ object: { sha: string } }>(
        `/repos/${OWNER}/${repo}/git/ref/heads/${defaultBranch}`
      );
      return ref.object.sha;
    },
    findOpenPr: (repo, branch) => findOpenPr(repo, branch),
  };
}

/**
 * Floating-Detection je specifier. Exakt NUR für `semver.valid(spec)`.
 * Protocol-/Path-/Composite-Specs (workspace:, link:, file:, npm:, git*, http*)
 * sind keine Registry-Versions-Specs → kein Finding (sonst würde pins-PR
 * "workspace:*"-Refs sinnlos auf feste Versionen setzen).
 */
export function isFloatingSpec(spec: unknown): spec is string {
  const s = typeof spec === 'string' ? spec.trim() : '';
  if (!s) return false;
  if (/^[a-z][a-z0-9+.-]*:/i.test(s)) return false; // workspace:/npm:/git+ssh:/http:
  if (!s.startsWith('@') && s.includes('/')) return false; // Pfad-Spec (packages/utils, ../lib)
  return semver.valid(s) === null;
}

/**
 * Exakt gepinnter PRE-RELEASE (v1.6.0, N2): `"7.1.0-beta"` ist `semver.valid`
 * → per Definition nicht "floating", aber wir wollen trotzdem wissen, ob im
 * selben Kanal ein neueres Beta existiert (Owner: "Beta updates nur anzeigen,
 * wenn package bereits als beta hinterlegt ist"). Kein Pins-PR, keine Zensur.
 */
export function isPinnedPrereleaseSpec(spec: unknown): spec is string {
  const s = typeof spec === 'string' ? spec.trim() : '';
  if (!s || s.includes(' ')) return false;
  const v = semver.valid(s);
  if (!v) return false;
  return semver.prerelease(v) !== null;
}

/**
 * Untergrenze einer Floating-Range, sofern diese ein Pre-Release ist (v1.8.0):
 * `^4.0.0-beta.7` → `4.0.0-beta.7`. Stabile Ranges/`*` → null. Damit werden
 * auch Ranges als Beta-Kanal erkannt (nie aber `stable → beta`, weil eine
 * stabile Untergrenze null ergibt).
 */
export function prereleaseFloor(spec: unknown): string | null {
  const s = typeof spec === 'string' ? spec.trim() : '';
  if (!s) return null;
  const min = semver.minVersion(s);
  if (!min || semver.prerelease(min.version) === null) return null;
  return min.version;
}

/** Sammle package.json-Dateien (repoDir-Checkout nach Tarball-Entpacken). */
function findPackageJsonFiles(root: string): string[] {
  const out: string[] = [];
  const walk = (dir: string): void => {
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, e.name);
      if (e.isDirectory()) {
        if (e.name === 'node_modules' || e.name === '.git' || e.name === '.next' || e.name === 'dist') continue;
        walk(full);
      } else if (e.isFile() && e.name === 'package.json') {
        out.push(full);
      }
    }
  };
  walk(root);
  return out;
}

// ————————————————— npm-Registry latest-Lookup (cache pro pkg) —————————————————

interface NpmPackument {
  'dist-tags'?: Record<string, string>;
  time?: Record<string, string>;
  /** Alle veröffentlichten Versionen mit Metadaten (v1.7.2: Peer-Gate). */
  versions?: Record<string, { peerDependencies?: Record<string, string> }>;
}

/**
 * Öffentlicher Read-only-Blick in das Packument (v1.7.2): nur `versions` +
 * `time` + `dist-tags` — bewusst eine Kopie via JSON-Roundtrip (dieselbe
 * Form wie `npm view <pkg> --json`), damit Aufrufer wie `pinning-test` bzw.
 * Triage-Code nicht die großen Metadaten-Blobs in den Speicher halten.
 */
export interface PackumentView {
  'dist-tags'?: Record<string, string>;
  time?: Record<string, string>;
  versions?: Record<string, { peerDependencies?: Record<string, string> }>;
}

const packumentCache = new Map<string, PackumentView | null>();

/**
 * Packument (dist-tags + time[] + versions[] inkl. peerDependencies) via
 * registry.npmjs.org. Fehler → null. Ein Fetch je pkg deckt damit sowohl den
 * latest-Lookup als auch das Peer-Gate (v1.7.2) ab; `time`/`versions` werden
 * konsumiert, die großen `versions` — nur die relevanten Felder bleiben im
 * Speicher (dist-tags/time/peerDependencies), der Rest nicht.
 */
export async function npmPackument(pkg: string): Promise<PackumentView | null> {
  if (packumentCache.has(pkg)) return packumentCache.get(pkg)!;
  let out: PackumentView | null = null;
  try {
    // Pkg-Namen sind restriktives Charset ([a-z0-9@/._-]) → direkt in URL ok;
    // scoped '@scope/name' mit unverschlüsseltem Slash (npm-Registry-Konvention).
    const res = await fetch(`https://registry.npmjs.org/${pkg}`, { signal: AbortSignal.timeout(10_000) });
    if (res.ok) out = (await res.json()) as PackumentView;
  } catch (err) {
    log(`npm-Latest-Lookup fehlgeschlagen für ${pkg}: ${err instanceof Error ? err.message : '?'}`);
  }
  packumentCache.set(pkg, out);
  return out;
}

/** dist-tags.latest (Kompatibilitäts-Wrapper, v1.5.0). */
async function npmLatest(pkg: string): Promise<string | null> {
  const p = await npmPackument(pkg);
  return p?.['dist-tags']?.latest ?? null;
}

/**
 * Versionsliste eines Pakets (v1.7.2, Peer-Gate): alle `versions[]` aus dem
 * Packument. Fehler → null (Aufrufer fail-closed).
 */
async function npmVersions(pkg: string): Promise<string[] | null> {
  const p = await npmPackument(pkg);
  return p?.versions ? Object.keys(p.versions) : null;
}

/**
 * `peerDependencies` einer konkreten Paketversion (v1.7.2) — funktional
 * gleichwertig zu `npm view <pkg>@<ver> peerDependencies --json`, aber über das
 * ohnehin gecachte Packument (kein spawn, kein zusätzlicher HTTP-Call).
 * Version unbekannt → null ("keine Peer-Aussage"), vorhanden ohne peers → {}.
 */
async function npmPeerDependencies(pkg: string, version: string): Promise<Record<string, string> | null> {
  const p = await npmPackument(pkg);
  const v = p?.versions?.[version];
  if (!v) return null;
  return v.peerDependencies ?? {};
}

/**
 * Upgrade-Ziel für ein Paket, das BEREITS auf einem Pre-Release-Kanal liegt
 * (v1.8.0). Höchste neuere Version aus den dist-tags, die entweder
 *
 * - denselben Kanal hat (`beta → beta`, `rc → rc`, `alpha → alpha`), oder
 * - ein STABILES Release ist (`beta → stable` = Kanal abgeschlossen).
 *
 * Bewusst NICHT möglich: `stable → beta` (Aufrufer prüft `current`), Kanal-
 * Wechsel (`rc → beta`) und Exoten (`nightly`/`canary`/`insiders` — die werden
 * nie automatisch gebumpt, unabhängig von `SHOW_EXOTIC_PRERELEASES`).
 *
 * `kind` steuert Report/PR-Body: `beta` = Kanal-Update, `stable` = Abschluss.
 */
export function prereleaseUpgradeTarget(
  current: string,
  distTags: Record<string, string> | undefined
): { target: string; kind: 'beta' | 'stable' } | null {
  if (!distTags) return null;
  // WICHTIG: die VOLLE Version vergleichen, nicht coerce() — coerce() strippt
  // den Prerelease-Teil ("4.0.0-beta.7" → "4.0.0"), wodurch 4.0.0-beta.8 nie
  // größer wäre (Bug v1.6.0, im Prod-Report aufgefallen).
  const cur = semver.valid(current) ?? semver.coerce(current)?.version ?? null;
  // Nur Pakete, die SCHON im Pre-Release-Kanal sind → nie stable → beta.
  if (!cur || semver.prerelease(cur) === null) return null;
  const candidates: Array<{ target: string; kind: 'beta' | 'stable' }> = [];
  for (const version of Object.values(distTags)) {
    if (!semver.valid(version)) continue;
    if (!semver.gt(version, cur)) continue;
    if (semver.prerelease(version) === null) {
      candidates.push({ target: version, kind: 'stable' });
      continue;
    }
    const cls = classifyPrerelease(version);
    if (cls.cls === 'exotic') continue; // nightly/canary/insiders: nie automatisch
    if (!channelCompatible(current, version)) continue; // rc ≠ beta
    candidates.push({ target: version, kind: 'beta' });
  }
  if (candidates.length === 0) return null;
  // Höchste Version gewinnt: liegt das stabile Release über dem neuesten Beta,
  // ist das der Abschluss (beta.9 < 4.0.0 → stable).
  candidates.sort((a, b) => semver.rcompare(a.target, b.target));
  return candidates[0] ?? null;
}

/**
 * Renovate-Kandidaten (v1.7.0) in PinFinding überführen.
 *
 * Arbeitsteilung: der Pinning-Scanner findet FLOATING Specs (`^1.2.3`),
 * Renovate ergänzt EXAKT gepinnte deps, für die es eine neuere Version gibt —
 * die sieht der Pinning-Scanner per Definition nicht. Soaking ist bereits
 * Renovates Sache (`minimumReleaseAge`), hier wird NICHT erneut gefiltert.
 *
 * Guards: Major/Breaking → nur Report, nie PR (Owner-Regel "Major-Sprünge nur
 * bewusst"). Major-Sprünge müssen von Hand entschieden werden.
 */
export function renovateToPinFindings(
  repoDir: string,
  candidates: RenovateCandidate[],
  findings: PinFinding[]
): PinFinding[] {
  return mapRenovateCandidates(candidates, findings, (c) =>
    path.posix.join(...path.relative(repoDir, path.join(repoDir, c.packageFile)).split(path.sep))
  );
}

/**
 * Server-Variante ohne Checkout: `packageFile` aus dem Renovate-Log ist bereits
 * repo-relativ (`--platform=local` mit cwd = Repo-Root). Verhalten identisch zu
 * `renovateToPinFindings` — Tests nutzen diese Form (kein tmp-Repo nötig).
 */
export function renovateCandidatesToPinFindings(
  candidates: RenovateCandidate[],
  findings: PinFinding[]
): PinFinding[] {
  return mapRenovateCandidates(candidates, findings, (c) =>
    path.posix.normalize(c.packageFile).replace(/^\.\//, '')
  );
}

function mapRenovateCandidates(
  candidates: RenovateCandidate[],
  findings: PinFinding[],
  manifestRel: (c: RenovateCandidate) => string
): PinFinding[] {
  const out: PinFinding[] = [];
  const seen = new Set(findings.map((f) => `${f.manifestPath}|${f.pkg}`));
  for (const c of candidates) {
    const rel = manifestRel(c);
    const key = `${rel}|${c.depName}`;
    if (seen.has(key)) continue; // schon als floating Pin erfasst → keine Doppelmeldung
    seen.add(key);
    const section: PinSection = c.depType === 'devDependencies' ? 'devDependencies' : 'dependencies';
    out.push({
      pkg: c.depName,
      current: c.currentValue,
      latest: c.newVersion,
      section,
      manifestPath: rel,
      severity: section === 'dependencies' ? 'warn' : 'info',
      source: 'renovate',
      updateType: c.updateType,
      releaseAgeDays: c.ageDays,
      // Soaking lief bereits in Renovate → als reif behandelt.
      eligibility: 'eligible',
      eligibilityLabel: c.ageDays === null ? 'reif (Renovate)' : `reif (${c.ageDays}d)`,
      ageDays: c.ageDays,
      // Major/Breaking bleiben report-only (kein PR).
      majorOrBreaking: c.updateType === 'major' || c.isBreaking === true,
    });
  }
  return out;
}

// ———————————————— v1.7.2: Peer-Awareness beim Pinnen (Defekt 2) ——————————————
//
// Beleg 2026-11-07 (private-ai-interface): der Scanner pinnte `graphql` blind auf
// `dist-tags.latest` (17.0.2), Payload 3.93.0 deklariert aber
// `peerDependencies.graphql: "^16.8.1"` → `npm ci` bricht mit ERESOLVE, Deploy
// failed. Ein früherer Hand-Commit hatte das dort schon auf 16.14.2 gelöst —
// der Scanner hat es rückgängig gemacht.
//
// Regel: bevor ein `latest` angewandt wird, prüfen, ob ANDERE direkte Deps
// desselben Manifests eine Peer-Range für dieses Paket deklarieren. Passt
// `latest` nicht, wird auf die höchste Range-konforme Version ausgewichen; ist
// keine ermittelbar, fliegt der Kandidat aus dem PR (fail-closed).
//
// Bewusste Grenzen:
// - "Installierte" Version = die im Manifest deklarierte (exakt) bzw. die
//   höchste von der floating Spec erlaubte (Scanner installiert nie).
// - Peer-Deklarationen aus transitive Deps im Lockfile können Registry-only
//   nicht erreicht werden (kein Install) — dafür bleibt der Lockfile-Regen +
//   der fail-closed-Pfad (Defekt 3) die Netz-Absicherung: bricht npm, kommt
//   der Pin gar nicht erst in den PR.

const DIRECT_SECTIONS: PinSection[] = ['dependencies', 'devDependencies', 'optionalDependencies'];

/** Höchste Version, die eine (floating) Spec zulässt — Basis für peerDepsOf. */
export function effectiveVersion(spec: string, versions: string[] | null): string | null {
  const s = spec.trim();
  const exact = semver.valid(s);
  if (exact) return exact;
  if (!versions || versions.length === 0) return null;
  const stable = versions.filter((v) => semver.valid(v) && semver.prerelease(v) === null);
  const pool = stable.length > 0 ? stable : versions.filter((v) => semver.valid(v));
  let range: semver.Range | null = null;
  try {
    range = new semver.Range(s);
  } catch {
    range = null;
  }
  const allowed = range ? pool.filter((v) => range!.test(v)) : pool;
  if (allowed.length === 0) return null;
  return allowed.sort((a, b) => semver.rcompare(a, b))[0] ?? null;
}

/**
 * Peer-Gate für ein Pin-Ziel (v1.7.2).
 *
 * `deps` = direkte Deps des Manifests (ohne das zu pinnende Paket).
 * Rückgabe:
 * - `null` → niemand deklariert eine Peer-Range mit Einspruch → `latest` ok.
 * - `PeerConflict` mit `fallback` → Ausweichversion innerhalb der Range.
 * - `PeerConflict` mit `fallback: null` → Kandidat auslassen (fail-closed).
 *
 * Nicht-semver-Ranges (`*`, `>=", `latest`, `workspace:*`) werden ignoriert —
 * sie können nicht "verletzt" werden. Auflösbare Ausweichkandidaten schließen
 * Pre-Releases aus (Owner-Regel: keine Beta-Zukäufe durch den Scanner).
 */
export async function peerGate(
  pkg: string,
  latest: string,
  deps: Record<string, string>,
  lookup: {
    peerDepsOf: PinDeps['peerDepsOf'];
    versionsOf: PinDeps['versionsOf'];
  }
): Promise<PeerConflict | null> {
  const violations: Array<{ dep: string; depVersion: string; range: string }> = [];
  for (const [dep, spec] of Object.entries(deps)) {
    if (dep === pkg) continue;
    // Non-string-Specs (künftige npm-Aliase etc.) sind keine Versionsangabe.
    const specStr = typeof spec === 'string' ? spec : '';
    if (semver.valid(specStr) === null && !isFloatingSpec(specStr)) continue; // Protocol/Path
    const versions = await lookup.versionsOf(dep);
    const depVersion = effectiveVersion(specStr, versions);
    if (!depVersion) continue; // Version nicht bestimmbar → keine Peer-Aussage
    const peers = await lookup.peerDepsOf(dep, depVersion);
    const range = peers?.[pkg];
    if (!range || !semver.validRange(range)) continue;
    if (semver.satisfies(latest, range)) continue;
    violations.push({ dep, depVersion, range });
  }
  if (violations.length === 0) return null;

  // Ausweichkandidat: höchste Version, die ALLE verletzten Ranges erfüllt.
  const allVersions = (await lookup.versionsOf(pkg)) ?? [];
  const candidates = allVersions.filter(
    (v) => semver.valid(v) && semver.prerelease(v) === null && violations.every((x) => semver.satisfies(v, x.range))
  );
  const fallback = candidates.sort((a, b) => semver.rcompare(a, b))[0] ?? null;
  const primary = violations[0]!;
  return { ...primary, fallback };
}

/** Peer-Konflikt als PR-Body-Zeile. */
export function peerConflictLabel(c: PeerConflict): string {
  const head = `peer-Konflikt mit ${c.dep}@${c.depVersion} (requires ${c.range})`;
  return c.fallback ? `${head} → Ausweichversion ${c.fallback}` : `${head} — keine passende Version, Pin ausgelassen`;
}

/**
 * Peer-Gate über eine Liste von Findings anwenden (v1.7.2): liest je Finding
 * die direkten Deps des Manifests aus dem Checkout und setzt `peerConflict`
 * bzw. `pinTarget`. Wird für Renovate-Kandidaten genutzt (der Floating-Pfad
 * gated bereits beim Parsen, weil er die Sektionen ohnehin offen hat).
 */
export async function applyPeerGateToFindings(
  findings: PinFinding[],
  repoDir: string,
  deps: PinDeps
): Promise<void> {
  const manifestCache = new Map<string, Record<string, unknown>>();
  for (const f of findings) {
    if (!PR_SECTIONS.includes(f.section) || !f.latest || f.betaPin || f.majorOrBreaking) continue;
    let json = manifestCache.get(f.manifestPath);
    if (!json) {
      try {
        json = JSON.parse(fs.readFileSync(path.join(repoDir, f.manifestPath), 'utf8')) as Record<string, unknown>;
      } catch {
        continue; // Manifest nicht lesbar → keine Peer-Aussage (Regen ist Netz)
      }
      manifestCache.set(f.manifestPath, json);
    }
    const others: Record<string, string> = {};
    for (const s of DIRECT_SECTIONS) {
      const sect = json[s];
      if (!sect || typeof sect !== 'object') continue;
      for (const [k, v] of Object.entries(sect as Record<string, unknown>)) {
        if (typeof v === 'string' && k !== f.pkg) others[k] = v;
      }
    }
    const conflict = await peerGate(f.pkg, f.latest, others, {
      peerDepsOf: deps.peerDepsOf,
      versionsOf: deps.versionsOf,
    });
    if (!conflict) continue;
    f.peerConflict = conflict;
    if (conflict.fallback) f.pinTarget = conflict.fallback;
  }
}

/**
 * Pinning-Scan je Repo: alle package.json (ohne node_modules) parsen, floating
 * deps sammeln, je pkg latest bestimmen. Der Pr-RepoDir-Checkout ist bereits
 * entpackt (scan.ts ruft das nach downloadTarball).
 */
export async function collectPinning(
  repo: RepoInfo,
  repoDir: string,
  deps: PinDeps = pinDeps()
): Promise<PinScanResult> {
  const findings: PinFinding[] = [];
  const files = findPackageJsonFiles(repoDir);
  for (const file of files) {
    const rel = path.posix.join(...path.relative(repoDir, file).split(path.sep));
    let json: Record<string, unknown>;
    try {
      json = JSON.parse(fs.readFileSync(file, 'utf8')) as Record<string, unknown>;
    } catch (err) {
      log(`Pinning-Scan ${repo.name}: ${rel} unparsable — ${err instanceof Error ? err.message : '?'}`);
      continue;
    }
    for (const section of PIN_SECTIONS) {
      const sectionDeps = json[section];
      if (!sectionDeps || typeof sectionDeps !== 'object') continue;
      for (const [pkg, spec] of Object.entries(sectionDeps as Record<string, unknown>)) {
        const specStr = typeof spec === 'string' ? spec.trim() : String(spec);
        const floating = isFloatingSpec(spec);
        const betaPinned = !floating && isPinnedPrereleaseSpec(spec);
        if (!floating && !betaPinned) continue;
        const packument = await deps.packument(pkg);
        const latest = packument?.['dist-tags']?.latest ?? null;
        // v1.8.0: Basis des Beta-Kanals. Exakter Pre-Release-Pin → die Version
        // selbst; floating Pre-Release-Range (`^4.0.0-beta.7`) → ihre
        // Untergrenze. Stabile Specs liefern null (nie stable → beta).
        const betaBase = betaPinned ? specStr : floating ? prereleaseFloor(specStr) : null;
        const finding: PinFinding = {
          pkg,
          current: specStr,
          latest,
          section,
          manifestPath: rel,
          severity: section === 'dependencies' ? 'warn' : 'info',
          betaPin: betaBase !== null,
        };
        // Soaking (v1.6.0): Alter des Ziel-Kandidaten bestimmen. latest ist kein
        // CVE-Fix (kein Advisory-Bezug im Pinning-Pfad) → nur die 3-Tage-Regen.
        // Beta-Pakete bekommen ihr Ziel weiter unten (latest ist dort oft die
        // stabile 3.x-Linie und damit kein sinnvolles Pin-Ziel).
        if (floating && latest && betaBase === null) {
          const pub = await deps.publishedAt(pkg, latest);
          const el = updateEligibility({
            variantChange: false,
            publishedAt: pub.publishedAt,
            cveFix: false,
          });
          finding.latestPublishedAt = pub.publishedAt;
          finding.eligibility = el.eligibility;
          finding.eligibilityLabel = el.label;
          finding.ageDays = el.ageDays;
        }
        // Beta-Kanal (v1.8.0): Pakete, die BEREITS auf einem Pre-Release
        // stehen, bekommen ein echtes Update-Ziel — beta → beta (neueres Beta
        // im selben Kanal) oder beta → stable (Kanal abgeschlossen). NIE
        // stable → beta: stabile Pins laufen gar nicht erst in diesen Zweig.
        if (betaBase !== null) {
          const up = prereleaseUpgradeTarget(betaBase, packument?.['dist-tags']);
          if (up) {
            const pub = await deps.publishedAt(pkg, up.target);
            const el = updateEligibility({
              variantChange: false,
              publishedAt: pub.publishedAt,
              cveFix: false,
            });
            finding.pinTarget = up.target;
            finding.pinTargetKind = up.kind;
            finding.latestPublishedAt = pub.publishedAt;
            finding.eligibility = el.eligibility;
            finding.eligibilityLabel = el.label;
            finding.ageDays = el.ageDays;
            if (up.kind === 'beta') {
              // Report-Spalte "Beta/RC" zeigt den Kanal-Kandidaten (Kompat.).
              finding.prereleaseHint = up.target;
              finding.prereleasePublishedAt = pub.publishedAt;
              finding.prereleaseEligibility = el.eligibility;
              finding.prereleaseLabel = el.label;
            }
          } else if (floating) {
            // Kein neueres Ziel: floating Pre-Release trotzdem auf die
            // Kanal-Untergrenze pinnen (Pinning-Policy: keine Ranges).
            finding.pinTarget = betaBase;
            finding.pinTargetKind = 'beta';
            finding.eligibilityLabel = 'Pin auf Kanal-Untergrenze';
          }
        }
        // Peer-Gate (v1.7.2): nur PR-Sektionen, nur mit echtem Pin-Ziel. Die
        // Range-/Versions-Lookups laufen über dieselben injizierten Deps wie
        // der Packument-Fetch (Tests: offline).
        if (PR_SECTIONS.includes(section) && latest && !finding.betaPin) {
          const others: Record<string, string> = {};
          for (const s of DIRECT_SECTIONS) {
            const sect = json[s];
            if (!sect || typeof sect !== 'object') continue;
            for (const [k, v] of Object.entries(sect as Record<string, unknown>)) {
              if (typeof v === 'string' && k !== pkg) others[k] = v;
            }
          }
          const conflict = await peerGate(pkg, latest, others, {
            peerDepsOf: deps.peerDepsOf,
            versionsOf: deps.versionsOf,
          });
          if (conflict) {
            finding.peerConflict = conflict;
            if (conflict.fallback) {
              // Ausweichen: Range-konforme Version pinnt die dep, ohne deren
              // Peer-Vertrag zu brechen. `latest` bleibt informativ erhalten.
              finding.pinTarget = conflict.fallback;
              if (conflict.fallback !== finding.current) {
                const pub = await deps.publishedAt(pkg, conflict.fallback);
                const el = updateEligibility({
                  variantChange: false,
                  publishedAt: pub.publishedAt,
                  cveFix: false,
                });
                finding.latestPublishedAt = pub.publishedAt;
                finding.eligibility = el.eligibility;
                finding.eligibilityLabel = el.label;
                finding.ageDays = el.ageDays;
              }
            }
            log(`Pinning-Scan ${repo.name}: ${pkg} — ${peerConflictLabel(conflict)}`);
          }
        }
        findings.push(finding);
      }
    }
  }

  // Renovate-Analyse (v1.7.0): ergänzt EXAKT gepinnte deps, die der Floating-
  // Scanner prinzipiell nicht sieht. Renovate erzeugt NIE eigene PRs — die
  // Vorschläge landen im gemeinsamen Pins-PR. Nicht verfügbar → silent skip.
  if (renovateEnabled()) {
    const ren = await collectRenovateCandidates(repoDir);
    if (ren.ok) {
      // v1.7.2: auch Renovate-Ziele laufen durch das Peer-Gate — ein
      // Renovate-Bump in eine fremde Peer-Range bricht `npm ci` genauso
      // (gleicher ERESOLVE-Klassiker wie graphql/payload).
      const bumped = renovateToPinFindings(repoDir, ren.candidates, findings);
      await applyPeerGateToFindings(bumped, repoDir, deps);
      findings.push(...bumped);
    } else if (ren.note) {
      log(`Renovate ${repo.name}: ${ren.note}`);
    }
  }

  const fixable: PinFinding[] = [];
  for (const f of findings) {
    if (!PR_SECTIONS.includes(f.section)) continue; // optional/peer = report-only
    // Beta-Kanal (v1.8.0): ein echtes Ziel gibt es nur bei beta → beta oder
    // beta → stable. Ohne Ziel (kein neueres Beta, kein stabiles Release)
    // bleibt das Finding reine Report-Info. Soaking gilt auch hier.
    if (f.betaPin) {
      if (!f.pinTarget) continue;
      if (f.eligibility === 'too-young') continue;
      fixable.push(f);
      continue;
    }
    if (!f.latest) continue;
    // Peer-Konflikt ohne Ausweichversion → fail-closed, kein Pin (v1.7.2).
    if (f.peerConflict && !f.pinTarget) continue;
    // Renovate-Major-/Breaking-Updates: nur Report, nie PR (Owner-Regel).
    if (f.majorOrBreaking) continue;
    // Soaking (v1.6.0): nur reife Ziel-Versionen werden gepinnt. Zu junge
    // Kandidaten bleiben im Report ("zu jung (2d)") und warten auf den nächsten Lauf.
    if (f.eligibility === 'too-young') continue;
    // Downgrade-Guard: latest muss >= (Major) der floating Referenz liegen
    const target = f.pinTarget ?? f.latest;
    const curCoerced = semver.coerce(f.current);
    const latestCoerced = semver.valid(target) ? semver.coerce(target) : null;
    if (curCoerced && latestCoerced && semver.lt(latestCoerced, curCoerced)) {
      log(`Pinning-Scan: ${f.pkg} ${target} < ${f.current} (Downgrade) — report-only.`);
      continue;
    }
    fixable.push(f);
  }

  return { findings, fixable };
}

// ——————————————————————————————— Pins-Fix-PR ————————————————————————————————

export function pinsBranchName(date = new Date()): string {
  return `cve-audit/pins-${date.toISOString().slice(0, 10)}`;
}

/**
 * Pins-PR (immer-PR-Policy, deterministisch OHNE LLM): alle fixable floating
 * deps eines Repos in EINEM PR, alle package.json-Manifests in EINER Branch.
 * Lockfile-Regen über das ABDECKENDE Lockfile (eigenes Verzeichnis oder
 * Workspace-Root bei Monorepos) — siehe findCoveringLockfile; ohne Lockfile
 * wird der Kandidat fail-closed ausgelassen (v1.7.0).
 */
/** Vom Regen berücksichtigte Lockfile-Variante + abgedecktes Manifest. */
export interface LockTarget {
  eco: 'npm' | 'pnpm' | 'yarn';
  /** Repo-relativer Pfad des Lockfiles (z. B. `package-lock.json`). */
  path: string;
  sha: string;
  content: string;
  /**
   * Weitere Manifeste im selben Regen-Topf (npm `workspaces`): der Regen läuft
   * in einem tmp-Dir mit dem ROOT-`package.json`; damit npm die geänderten
   * Nested-Manifeste einbezieht, werden sie zusätzlich hineingelegt.
   */
  pkgJsonOverrides?: Record<string, string>;
}

/**
 * Lockfile bestimmen, das ein Manifest abdeckt (v1.7.0, Owner-Anforderung).
 *
 * Reihenfolge:
 * 1. Verzeichnis des Manifests selbst (`apps/web/package.json` →
 *    `apps/web/package-lock.json`) — eigenständiges Projekt.
 * 2. Aufwärts bis Repo-Root: das erste gefundene Lockfile. Ein npm-Root-
 *    `package-lock.json` mit `workspaces` deckt alle Nested-Manifeste ab;
 *    `pnpm-lock.yaml` an der Workspace-Wurzel ebenso.
 *
 * `null` = kein abdeckendes Lockfile → Aufrufer muss fail-closed abbrechen.
 */
export async function findCoveringLockfile(
  repo: string,
  branch: string,
  manifestPath: string,
  deps: PinDeps = pinDeps()
): Promise<LockTarget | null> {
  const LOCK_NAMES: Array<{ name: string; eco: 'npm' | 'pnpm' | 'yarn' }> = [
    { name: 'package-lock.json', eco: 'npm' },
    { name: 'pnpm-lock.yaml', eco: 'pnpm' },
    { name: 'yarn.lock', eco: 'yarn' },
  ];
  // Kandidaten-Verzeichnisse: Manifest-Dir, dann jede Ebene bis zum Root.
  const dirs: string[] = [];
  let dir = path.posix.dirname(manifestPath);
  dirs.push(dir === '.' ? '' : dir);
  while (dirs[dirs.length - 1] !== '' && dirs.length < 12) {
    const parent = path.posix.dirname(dirs[dirs.length - 1]!);
    dirs.push(parent === '.' ? '' : parent);
  }

  for (const d of dirs) {
    for (const lock of LOCK_NAMES) {
      const lockPath = d ? `${d}/${lock.name}` : lock.name;
      const file = await deps.contentsGet(repo, lockPath, branch);
      if (!file) continue;
      // yarn.lock-Regen ist nicht automatisiert (siehe fix-pr.ts) → nicht
      // als "abdeckend" melden, sonst entstünde wieder ein PR ohne Lockfile.
      if (lock.eco === 'yarn') {
        log(`Pins-PR ${repo}: ${lockPath} gefunden, yarn-Regen nicht automatisiert — übersprungen.`);
        continue;
      }
      // Nested-Manifest: Root-Lockfile deckt nur ab, wenn es Workspaces nutzt.
      if (d === '' && manifestPath.includes('/')) {
        const rootPkg = await deps.contentsGet(repo, 'package.json', branch);
        const ws = rootPkg
          ? (JSON.parse(decodeB64(rootPkg.content)) as { workspaces?: unknown }).workspaces
          : undefined;
        if (!ws) continue; // Root-Lockfile ohne workspaces deckt Nested-Manifest nicht ab
      }
      return { eco: lock.eco, path: lockPath, sha: file.sha, content: decodeB64(file.content) };
    }
  }
  return null;
}

export async function createPinsPr(
  repo: RepoInfo,
  findings: PinFinding[],
  state: State,
  deps: PinDeps = pinDeps()
): Promise<FixResult> {
  if (findings.length === 0) return { status: 'skipped', note: 'keine fixbaren Pins' };
  if (repo.archived) return { status: 'skipped', note: 'Repo archived — kein Pins-PR (hard guard)' };

  const branch = pinsBranchName();
  const hasBeta = findings.some((f) => f.betaPin);
  const byManifest = new Map<string, PinFinding[]>();
  for (const f of findings) {
    const cur = byManifest.get(f.manifestPath);
    if (cur) cur.push(f);
    else byManifest.set(f.manifestPath, [f]);
  }

  try {
    // Offenen PR zur Branch-ID checken (Dedupe, analog Foto-PRs)
    const open = await deps.findOpenPr(repo.name, branch);
    if (open) return { status: 'exists', prUrl: open.url, prNumber: open.number, branch };

    const headSha = await deps.headSha(repo.name, repo.defaultBranch);
    let created = await deps.createRef(repo.name, branch, headSha);
    if (created === 'ref-exists') {
      const openNow = await deps.findOpenPr(repo.name, branch);
      if (openNow) return { status: 'exists', prUrl: openNow.url, prNumber: openNow.number, branch };
      // Crash-Rest (v1.8.1): Branch ohne PR → neu aufsetzen, sonst bliebe
      // `changed` false und der PR entstünde nie (Vorfall 18.11.2026).
      log(`Pins-PR ${repo.name}: Branch ${branch} existiert ohne offenen PR — wird neu aufgesetzt.`);
      await deps.deleteRef(repo.name, branch);
      created = await deps.createRef(repo.name, branch, headSha);
      if (created === 'ref-exists') {
        return { status: 'failed', branch, note: `Branch ${branch} ließ sich nicht neu aufsetzen` };
      }
    }

    const bumped: string[] = [];
    const notes: string[] = [];
    const lockfiles: string[] = [];
    const skipped: string[] = [];
    let changed = false;
    for (const [manifestPath, manifestFindings] of byManifest) {
      const pkgFile = await deps.contentsGet(repo.name, manifestPath, branch);
      if (!pkgFile) {
        notes.push(`${manifestPath} fehlt auf Branch — ${manifestFindings.map((f) => f.pkg).join(', ')} übersprungen`);
        continue;
      }
      let json: Record<string, unknown>;
      try {
        json = JSON.parse(decodeB64(pkgFile.content)) as Record<string, unknown>;
      } catch {
        notes.push(`${manifestPath}: unparsable — ${manifestFindings.map((f) => f.pkg).join(', ')} übersprungen`);
        continue;
      }
      const fileBumped: string[] = [];
      for (const f of manifestFindings) {
        const dep = json[f.section] as Record<string, string> | undefined;
        if (!dep || dep[f.pkg] === undefined) continue;
        const target = f.pinTarget ?? f.latest;
        if (!target) continue;
        if (dep[f.pkg] === target) continue; // zwischendrin exakt geworden
        // Peer-Konflikt ohne Ausweichversion → dieser Kandidat bleibt draußen
        // (fail-closed; der Grund steht im PR-Body, nicht im Manifest-Commit).
        if (f.peerConflict && !f.pinTarget) {
          skipped.push(`${manifestPath}: ${f.pkg} — ${peerConflictLabel(f.peerConflict)}`);
          continue;
        }
        dep[f.pkg] = target;
        const peerSuffix = f.peerConflict
          ? `, Peer-Ausweichen: ${f.peerConflict.dep}@${f.peerConflict.depVersion} requires ${f.peerConflict.range} (latest wäre ${f.latest})`
          : '';
        const betaSuffix = f.betaPin
          ? f.pinTargetKind === 'stable'
            ? ', Beta-Kanal abgeschlossen (beta → stable)'
            : f.pinTarget !== (prereleaseFloor(f.current) ?? f.current)
              ? ', Beta-Kanal (beta → beta)'
              : ', Beta-Kanal (Range → exakt)'
          : '';
        fileBumped.push(
          `${f.pkg}: ${f.current} → ${target} (${f.section}${
            semver.major(semver.coerce(target) ?? '0.0.0') !== semver.major(semver.coerce(f.current) ?? '0.0.0')
              ? ', ⚠️ major jump'
              : ''
          }${peerSuffix}${betaSuffix})`
        );
      }
      if (fileBumped.length === 0) continue;
      const updatedPkg = `${JSON.stringify(json, null, 2)}\n`;

      // Lockfile-Regeneration (v1.7.0): das Manifest kann im Repo-Root liegen
      // ODER in einem Unterverzeichnis (Monorepo). Zuständig ist das Lockfile,
      // das das Manifest abdeckt: bei npm das Root-`package-lock.json` mit
      // `workspaces`, sonst das nächste Lockfile im eigenen Verzeichnis.
      // Findet sich keines, fliegt der Kandidat fail-closed aus dem PR —
      // ein PR ohne passendes Lockfile bricht `npm ci` und ist wertlos.
      const lockTarget = await findCoveringLockfile(repo.name, branch, manifestPath, deps);
      if (!lockTarget) {
        skipped.push(...fileBumped.map((b) => `${manifestPath}: ${b} — kein abdeckendes Lockfile gefunden`));
        notes.push(`${manifestPath}: kein abdeckendes Lockfile gefunden — Pin nicht angewandt (fail-closed)`);
        continue;
      }
      // ALLES-ODER-NICHTS (v1.7.2, Defekt 3): der Regen läuft VOR jedem
      // Schreibzugriff. Schlägt er fehl, wird weder Manifest noch Lockfile
      // geschrieben — vorher landete das Manifest trotzdem im PR und der
      // Body behauptete fälschlich "Lockfiles were regenerated".
      let regen;
      try {
        regen = await deps.regenerate(lockTarget.eco, updatedPkg, lockTarget.content, lockTarget.pkgJsonOverrides);
      } catch (err) {
        regen = { changed: false, note: err instanceof Error ? err.message : String(err) };
      }
      if (!regen.changed || regen.content === undefined) {
        skipped.push(...fileBumped.map((b) => `${manifestPath}: ${b} — Lockfile-Regen ${lockTarget.path} fehlgeschlagen`));
        notes.push(
          `${manifestPath}: Lockfile-Regen von ${lockTarget.path} fehlgeschlagen` +
            `${regen.note ? ` (${regen.note})` : ''} — Pin nicht angewandt`
        );
        continue;
      }
      // Reihenfolge: erst Lockfile, dann Manifest. Bricht der zweite PUT, ist
      // der PR unvollständig statt inkonsistent auf branch-Ebene — beide
      // Commits entstehen aber vor dem PR, ein offener PR zeigt stets beides.
      await deps.contentsPut(
        repo.name,
        lockTarget.path,
        branch,
        lockTarget.sha,
        regen.content,
        `chore(cve-audit): regen ${lockTarget.path} (exact pins)`
      );
      await deps.contentsPut(
        repo.name,
        manifestPath,
        branch,
        pkgFile.sha,
        updatedPkg,
        `chore(cve-audit): pin dependencies in ${manifestPath} to exact versions`
      );
      changed = true;
      bumped.push(...fileBumped);
      if (!lockfiles.includes(lockTarget.path)) lockfiles.push(lockTarget.path);
    }

    if (!changed) {
      return {
        status: 'skipped',
        branch,
        note: (notes[0] ?? skipped[0] ?? 'keine anwendbaren Pins').slice(0, 280),
      };
    }

    const pr = await deps.createPr(repo.name, {
      title: hasBeta
        ? 'chore(cve-audit): pin dependencies to exact versions (incl. beta channel updates)'
        : 'chore(cve-audit): pin floating dependencies to exact versions',
      head: branch,
      base: repo.defaultBranch,
      body: pinsPrBody(repo.name, findings, bumped, notes, lockfiles, skipped),
      // Draft, wenn ein Kandidat fail-closed rausflog: der PR ist bewusst
      // unvollständig und braucht menschliche Entscheidung, kein Auto-Merge.
      draft: skipped.length > 0,
    });
    // State-Eintrag kind 'pins' → kein CVE-Reminder-Dupe, dedupe weiterer Läufe.
    upsertEntry(state, repo.name, {
      branch,
      prUrl: pr.url,
      prNumber: pr.number,
      ghsaIds: [],
      createdAt: new Date().toISOString(),
      lastSeen: new Date().toISOString(),
      findings: [],
      kind: 'pins',
    });
    log(`${repo.name}: Pins-PR #${pr.number} im State erfasst.`);
    return { status: 'created', prUrl: pr.url, prNumber: pr.number, branch, bumped };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    log(`WARN: Pins-PR für ${repo.name} fehlgeschlagen: ${msg}`);
    return { status: 'failed', branch, note: msg.slice(0, 300) };
  }
}

async function findOpenPr(repo: string, branch: string): Promise<{ url: string; number: number } | null> {
  const prs = await ghJsonOrNull<Array<{ html_url: string; number: number }>>(
    `/repos/${OWNER}/${repo}/pulls?state=open&head=${OWNER}:${encodeURIComponent(branch)}`
  );
  return prs && prs.length > 0 ? { url: prs[0]!.html_url, number: prs[0]!.number } : null;
}

async function tryCreateRef(repo: string, branch: string, sha: string): Promise<'created' | 'ref-exists'> {
  const res = await ghFetch(`/repos/${OWNER}/${repo}/git/refs`, {
    method: 'POST',
    body: JSON.stringify({ ref: `refs/heads/${branch}`, sha }),
  });
  if (res.ok) return 'created';
  const body = await res.text();
  if (res.status === 422 && /exists/i.test(body)) return 'ref-exists';
  throw new Error(`ref-create ${res.status}: ${body.slice(0, 200)}`);
}

/**
 * Crash-Rest aufräumen (v1.8.1): Starb der Lauf zwischen `createRef` und
 * `createPr` (nativer V8-Abbruch, siehe scan-wrapper.sh), blieb ein Branch
 * ohne PR zurück. Beim nächsten Lauf ist `changed` dann false (die Pins stehen
 * schon auf dem Branch) und der PR würde NIE entstehen. Deshalb: Branch ohne
 * offenen PR wird gelöscht und frisch vom aktuellen Base-Head aufgesetzt —
 * die Pins werden deterministisch neu angewendet.
 */
async function deleteRef(repo: string, branch: string): Promise<void> {
  const res = await ghFetch(
    `/repos/${OWNER}/${repo}/git/refs/heads/${encodeURIComponent(branch)}`,
    { method: 'DELETE' }
  );
  // 404 = schon weg (idempotent). Andere Fehler (403/422) sind echt und
  // sollen den PR-Pfad als 'failed' melden, nicht still weiterlaufen.
  if (!res.ok && res.status !== 404) {
    throw new Error(`ref-delete ${res.status}: ${(await res.text()).slice(0, 200)}`);
  }
}

function pinsPrBody(
  repo: string,
  findings: PinFinding[],
  bumped: string[],
  notes: string[],
  lockfiles: string[] = [],
  skipped: string[] = []
): string {
  const lines: string[] = [
    'Automatically generated by the `audit-scanner` (pinning enforcement run).',
    '',
    '### Why',
    'Per repo policy ("Dependency-Pinning & Update-Pflicht"): **no floating',
    'versions** — all npm specifiers must be exact (`x.y.z`), never `^`/`~`/',
    'ranges/`*`. This PR pins every floating dependency to the latest exact',
    'version published at the time of the scan.',
    '',
    'Packages that are **already on a pre-release channel** are updated inside',
    'that channel (`beta → beta`) or to the stable release that closes it',
    '(`beta → stable`). A package on stable is **never** moved into a pre-release',
    'channel.',
    '',
    'Peer contracts are respected: if another direct dependency declares a',
    '`peerDependencies` range for a package, the pin is the highest version',
    'inside that range (never a version that would break `npm ci` with ERESOLVE).',
    '',
    '### Pinned to exact versions',
  ];
  for (const b of bumped) lines.push(`- ${b}`);
  const betaBumps = findings.filter(
    (f) =>
      f.betaPin &&
      f.pinTarget &&
      // Nur echte Updates listen — ein reiner Range→exakt-Pin (Untergrenze)
      // steht schon in der Liste oben.
      f.pinTarget !== (prereleaseFloor(f.current) ?? f.current)
  );
  if (betaBumps.length > 0) {
    lines.push(
      '',
      '### Beta/RC channel updates',
      'Only packages already on a pre-release channel (no `stable → beta`):'
    );
    for (const f of betaBumps) {
      const kind = f.pinTargetKind === 'stable' ? 'beta → stable' : 'beta → beta';
      lines.push(`- \`${f.pkg}\`: ${f.current} → ${f.pinTarget} (${kind}, ${f.eligibilityLabel ?? '?'})`);
    }
  }
  const peerSkipped = findings.filter(
    (f) => f.peerConflict && !f.pinTarget && !f.betaPin && (f.section === 'dependencies' || f.section === 'devDependencies')
  );
  if (peerSkipped.length > 0) {
    lines.push('', '### Not pinned — peer conflict (fail-closed):');
    for (const f of peerSkipped) lines.push(`- \`${f.pkg}@${f.current}\` in \`${f.manifestPath}\` — ${peerConflictLabel(f.peerConflict!)}`);
  }
  const unreported = findings.filter((f) => f.section === 'optionalDependencies' || f.section === 'peerDependencies');
  if (unreported.length > 0) {
    lines.push('', '### Report-only (optional/peer dependencies — not pinned by policy):');
    for (const f of unreported) lines.push(`- \`${f.pkg}@${f.current}\` in \`${f.manifestPath}\` (${f.section})`);
  }
  if (notes.length > 0) {
    lines.push('', '### Notes');
    for (const n of notes) lines.push(`> ℹ️ ${n}`);
  }
  lines.push('', '### Checks before merge', 'No `[skip ci]` marker: these commits must trigger the normal');
  lines.push('deploy/build pipeline.');
  if (lockfiles.length > 0) {
    lines.push(
      '',
      `Lockfile(s) regenerated in-place together with the manifest changes: ${lockfiles.map((l) => `\`${l}\``).join(', ')}.`,
      'Manifest and lockfile are always changed in the same commit set — no pin lands',
      'without its regenerated lockfile.'
    );
  } else {
    lines.push('', 'No manifest change was applied, so no lockfile regeneration was needed.');
  }
  if (skipped.length > 0) {
    lines.push(
      '',
      `> ⚠️ ${skipped.length} pin candidate(s) NOT applied — the manifest was left untouched`,
      '> for these (lockfile regeneration failed, no covering lockfile, or peer',
      '> conflict without a matching version). Do **not** merge expecting them to be',
      '> pinned; fix the cause and let the next run produce a clean PR.'
    );
    lines.push('', '<details><summary>Skipped candidates</summary>', '');
    for (const s of skipped) lines.push(`- ${s}`);
    lines.push('', '</details>');
  }
  lines.push('', 'CI must be green. No auto-merge — human approval required.');
  return lines.join('\n');
}

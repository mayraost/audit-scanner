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

import fs from 'node:fs';
import path from 'node:path';

import semver from 'semver';

import { OWNER, log } from './config.js';
import { decodeB64, ghFetch, ghJson, ghJsonOrNull } from './github.js';
import type { RepoInfo } from './inventory.js';
import { regenerateLockfile, putContent, type FixResult } from './fix-pr.js';
import { channelCompatible, classifyPrerelease, showExoticPrereleases } from './prerelease.js';
import { npmVersionPublishedAt } from './publish-dates.js';
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
  /** v1.6.0: Publish-Datum der Ziel-Version (Soaking). */
  latestPublishedAt?: string | null;
  /** v1.6.0: Soaking-Entscheidung für das Pin-Ziel. */
  eligibility?: Eligibility;
  eligibilityLabel?: string;
  ageDays?: number | null;
  /** v1.6.0: neuerer Beta/RC-Kandidat (Kanal-kompatibel) — NUR Info, nie PR. */
  prereleaseHint?: string | null;
  /** v1.6.0: Publish-Datum des Beta-Kandidaten. */
  prereleasePublishedAt?: string | null;
  /** v1.6.0: Soaking-Entscheidung für den Beta-Kandidaten. */
  prereleaseEligibility?: Eligibility;
  prereleaseLabel?: string;
}

export interface PinScanResult {
  findings: PinFinding[];
  /** PR-Kandidaten: deps/devDeps, latest vorhanden, kein Protocol/Path-Spec, kein Downgrade. */
  fixable: PinFinding[];
}

const PIN_SECTIONS: PinSection[] = [
  'dependencies',
  'devDependencies',
  'optionalDependencies',
  'peerDependencies',
];

const PR_SECTIONS: PinSection[] = ['dependencies', 'devDependencies'];

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
}

const packumentCache = new Map<string, NpmPackument | null>();

/** Packument (dist-tags + time[]) via registry.npmjs.org. Fehler → null. */
async function npmPackument(pkg: string): Promise<NpmPackument | null> {
  if (packumentCache.has(pkg)) return packumentCache.get(pkg)!;
  let out: NpmPackument | null = null;
  try {
    // Pkg-Namen sind restriktives Charset ([a-z0-9@/._-]) → direkt in URL ok;
    // scoped '@scope/name' mit unverschlüsseltem Slash (npm-Registry-Konvention).
    const res = await fetch(`https://registry.npmjs.org/${pkg}`, { signal: AbortSignal.timeout(10_000) });
    if (res.ok) out = (await res.json()) as NpmPackument;
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
 * Neuester Kanal-kompatibler Pre-Release-Kandidat (v1.6.0, N2): höchste Version
 * aus den dist-tags mit `-beta`/`-rc`/`-alpha`, die NEUER als `current` ist und
 * im selben Kanal liegt. Exoten (`next`, `dev`, `insiders`) werden nur bei
 * SHOW_EXOTIC_PRERELEASES berücksichtigt. NIE Bump-Ziel — nur Info.
 */
function betaCandidate(
  current: string,
  distTags: Record<string, string> | undefined
): string | null {
  if (!distTags) return null;
  const cur = semver.coerce(current);
  const candidates: string[] = [];
  for (const [tag, version] of Object.entries(distTags)) {
    if (!semver.valid(version)) continue;
    if (semver.prerelease(version) === null) continue;
    const cls = classifyPrerelease(version);
    if (cls.cls === 'exotic' && !showExoticPrereleases()) continue;
    if (!channelCompatible(current, version)) continue;
    const v = semver.coerce(version);
    if (cur && v && !semver.gt(v, cur)) continue;
    // `next`/`dev`-dist-tags sind oft Build-Snapshots; nur bei explicitem Opt-in
    if (cls.cls === 'exotic' && !/^(next|dev|insiders|canary|nightly)$/i.test(tag)) continue;
    candidates.push(version);
  }
  if (candidates.length === 0) return null;
  return candidates.sort((a, b) => semver.rcompare(a, b))[0] ?? null;
}

/**
 * Pinning-Scan je Repo: alle package.json (ohne node_modules) parsen, floating
 * deps sammeln, je pkg latest bestimmen. Der Pr-RepoDir-Checkout ist bereits
 * entpackt (scan.ts ruft das nach downloadTarball).
 */
export async function collectPinning(repo: RepoInfo, repoDir: string): Promise<PinScanResult> {
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
      const deps = json[section];
      if (!deps || typeof deps !== 'object') continue;
      for (const [pkg, spec] of Object.entries(deps as Record<string, unknown>)) {
        const floating = isFloatingSpec(spec);
        const betaPinned = !floating && isPinnedPrereleaseSpec(spec);
        if (!floating && !betaPinned) continue;
        const packument = await npmPackument(pkg);
        const latest = packument?.['dist-tags']?.latest ?? null;
        const finding: PinFinding = {
          pkg,
          current: typeof spec === 'string' ? spec.trim() : String(spec),
          // betaPinned: kein "latest exact"-Ziel (stable != Beta-Kanal), sondern
          // der Kanal-Nachbar aus prereleaseHint.
          latest: floating ? latest : null,
          section,
          manifestPath: rel,
          severity: section === 'dependencies' ? 'warn' : 'info',
        };
        // Soaking (v1.6.0): Alter des Ziel-Kandidaten bestimmen. latest ist kein
        // CVE-Fix (kein Advisory-Bezug im Pinning-Pfad) → nur die 3-Tage-Regen.
        if (floating && latest) {
          const pub = await npmVersionPublishedAt(pkg, latest);
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
        // Beta-Hinweis (v1.6.0, N2): NUR für Pakete, die schon auf einem
        // Beta/RC-Kanal liegen — und nur Bericht, nie Bump-Ziel.
        if (betaPinned) {
          const beta = betaCandidate(finding.current, packument?.['dist-tags']);
          if (beta) {
            finding.prereleaseHint = beta;
            const pub = await npmVersionPublishedAt(pkg, beta);
            const el = updateEligibility({
              variantChange: false,
              publishedAt: pub.publishedAt,
              cveFix: false,
            });
            finding.prereleasePublishedAt = pub.publishedAt;
            finding.prereleaseEligibility = el.eligibility;
            finding.prereleaseLabel = el.label;
          }
        }
        findings.push(finding);
      }
    }
  }

  const fixable = findings.filter((f) => {
    if (!PR_SECTIONS.includes(f.section)) return false; // optional/peer = report-only
    if (!f.latest) return false; // deckt auch betaPinned (latest=null) ab
    // Soaking (v1.6.0): nur reife Ziel-Versionen werden gepinnt. Zu junge
    // Kandidaten bleiben im Report ("zu jung (2d)") und warten auf den nächsten Lauf.
    if (f.eligibility === 'too-young') return false;
    // Downgrade-Guard: latest muss >= (Major) der floating Referenz liegen
    const curCoerced = semver.coerce(f.current);
    const latestCoerced = semver.valid(f.latest) ? semver.coerce(f.latest) : null;
    if (curCoerced && latestCoerced && semver.lt(latestCoerced, curCoerced)) {
      log(`Pinning-Scan: ${f.pkg} latest ${f.latest} < ${f.current} (Downgrade) — report-only.`);
      return false;
    }
    return true;
  });

  return { findings, fixable };
}

// ——————————————————————————————— Pins-Fix-PR ————————————————————————————————

export function pinsBranchName(date = new Date()): string {
  return `cve-audit/pins-${date.toISOString().slice(0, 10)}`;
}

/**
 * Pins-PR (immer-PR-Policy, deterministisch OHNE LLM): alle fixable floating
 * deps eines Repos in EINEM PR, alle package.json-Manifests in EINER Branch.
 * Lockfile-Regen nur wenn Lockfile im SELBEN Verzeichnis wie das Manifest liegt
 * (monorepo root package-lock := dir ''; nested manifests → manual regen Note).
 */
export async function createPinsPr(
  repo: RepoInfo,
  findings: PinFinding[],
  state: State
): Promise<FixResult> {
  if (findings.length === 0) return { status: 'skipped', note: 'keine fixbaren Pins' };
  if (repo.archived) return { status: 'skipped', note: 'Repo archived — kein Pins-PR (hard guard)' };

  const branch = pinsBranchName();
  const byManifest = new Map<string, PinFinding[]>();
  for (const f of findings) {
    const cur = byManifest.get(f.manifestPath);
    if (cur) cur.push(f);
    else byManifest.set(f.manifestPath, [f]);
  }

  try {
    // Offenen PR zur Branch-ID checken (Dedupe, analog Foto-PRs)
    const open = await findOpenPr(repo.name, branch);
    if (open) return { status: 'exists', prUrl: open.url, prNumber: open.number, branch };

    const ref = await ghJson<{ object: { sha: string } }>(
      `/repos/${OWNER}/${repo.name}/git/ref/heads/${repo.defaultBranch}`
    );
    const created = await tryCreateRef(repo.name, branch, ref.object.sha);
    if (created === 'ref-exists') {
      const openNow = await findOpenPr(repo.name, branch);
      if (openNow) return { status: 'exists', prUrl: openNow.url, prNumber: openNow.number, branch };
      log(`Pins-PR ${repo.name}: Branch ${branch} existiert ohne offenen PR — update fort.`);
    }

    const bumped: string[] = [];
    const notes: string[] = [];
    let changed = false;
    for (const [manifestPath, manifestFindings] of byManifest) {
      const pkgFile = await ghJsonOrNull<{ sha: string; content: string }>(
        `/repos/${OWNER}/${repo.name}/contents/${manifestPath}?ref=${encodeURIComponent(branch)}`
      );
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
        if (dep[f.pkg] === f.latest) continue; // zwischendrin exakt geworden
        dep[f.pkg] = f.latest!;
        fileBumped.push(`${f.pkg}: ${f.current} → ${f.latest} (${f.section}${semver.major(semver.coerce(f.latest!) ?? '0.0.0') !== semver.major(semver.coerce(f.current) ?? '0.0.0') ? ', ⚠️ major jump' : ''})`);
      }
      if (fileBumped.length === 0) continue;
      const updatedPkg = `${JSON.stringify(json, null, 2)}\n`;
      await putContent(
        repo.name,
        manifestPath,
        branch,
        pkgFile.sha,
        updatedPkg,
        `chore(cve-audit): pin floating dependencies in ${manifestPath} to exact versions [skip ci]`
      );
      changed = true;
      bumped.push(...fileBumped);

      // Lockfile im selben Manifestverzeichnis (dir '' = Repo-Root) regenerieren.
      const lockDir = path.posix.dirname(manifestPath) === '.' ? '' : path.posix.dirname(manifestPath);
      let lockNote: string | null = null;
      if (lockDir !== '') {
        lockNote = 'nested manifest — Lockfile-Regen nicht automatisiert (root-Lockfile)';
      } else {
        for (const eco of ['npm', 'pnpm', 'yarn'] as const) {
          const lockPath = eco === 'npm' ? 'package-lock.json' : eco === 'pnpm' ? 'pnpm-lock.yaml' : 'yarn.lock';
          const lockFile = await ghJsonOrNull<{ sha: string; content: string }>(
            `/repos/${OWNER}/${repo.name}/contents/${lockPath}?ref=${encodeURIComponent(branch)}`
          );
          if (!lockFile) continue;
          const regen = await regenerateLockfile(eco, updatedPkg, decodeB64(lockFile.content));
          if (regen.changed && regen.content !== undefined) {
            await putContent(
              repo.name,
              lockPath,
              branch,
              lockFile.sha,
              regen.content,
              `chore(cve-audit): regen ${lockPath} (exact pins) [skip ci]`
            );
          } else if (regen.note) {
            lockNote = regen.note;
          }
          break; // nur das existierende (erste) Lockfile berücksichtigen
        }
      }
      if (lockNote) notes.push(`${manifestPath}: ${lockNote}`);
    }

    if (!changed) return { status: 'skipped', branch, note: 'keine anwendbaren Pins' };

    const pr = await ghJson<{ html_url: string; number: number }>(
      `/repos/${OWNER}/${repo.name}/pulls`,
      {
        method: 'POST',
        body: JSON.stringify({
          title: 'chore(cve-audit): pin floating dependencies to exact versions',
          head: branch,
          base: repo.defaultBranch,
          body: pinsPrBody(repo.name, findings, bumped, notes),
        }),
      }
    );
    // State-Eintrag kind 'pins' → kein CVE-Reminder-Dupe, dedupe weiterer Läufe.
    upsertEntry(state, repo.name, {
      branch,
      prUrl: pr.html_url,
      prNumber: pr.number,
      ghsaIds: [],
      createdAt: new Date().toISOString(),
      lastSeen: new Date().toISOString(),
      findings: [],
      kind: 'pins',
    });
    log(`${repo.name}: Pins-PR #${pr.number} im State erfasst.`);
    return { status: 'created', prUrl: pr.html_url, prNumber: pr.number, branch, bumped };
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

function pinsPrBody(repo: string, findings: PinFinding[], bumped: string[], notes: string[]): string {
  const lines: string[] = [
    'Automatically generated by the `audit-scanner` (pinning enforcement run).',
    '',
    '### Why',
    'Per repo policy ("Dependency-Pinning & Update-Pflicht"): **no floating',
    'versions** — all npm specifiers must be exact (`x.y.z`), never `^`/`~`/',
    'ranges/`*`. This PR pins every floating dependency to the latest exact',
    'version published at the time of the scan.',
    '',
    '### Pinned to exact versions',
  ];
  for (const b of bumped) lines.push(`- ${b}`);
  const unreported = findings.filter((f) => f.section === 'optionalDependencies' || f.section === 'peerDependencies');
  if (unreported.length > 0) {
    lines.push('', '### Report-only (optional/peer dependencies — not pinned by policy):');
    for (const f of unreported) lines.push(`- \`${f.pkg}@${f.current}\` in \`${f.manifestPath}\` (${f.section})`);
  }
  if (notes.length > 0) {
    lines.push('', '### Notes');
    for (const n of notes) lines.push(`> ℹ️ ${n}`);
  }
  lines.push(
    '',
    '### Checks before merge',
    'Lockfiles were regenerated in-place (`npm install --package-lock-only` /',
    'pnpm `install --lockfile-only` style). Run the full install locally before',
    'merging when in doubt. CI must be green. No auto-merge — human approval',
    'required.'
  );
  return lines.join('\n');
}

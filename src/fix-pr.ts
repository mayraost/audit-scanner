// Fix-PRs (opt-in, ENABLE_FIX_PRS=1): REST-only, kein git clone (Spec §5).
// - Branch cve-audit/fixes-<YYYY-MM-DD> ab Default-Branch-Head
// - package.json via GET→PUT /contents; sha = BLOB-SHA der Datei (Spec Gotcha 1!)
// - direkte Bumps in dependencies/devDeps; transitive via npm `overrides`
//   bzw. `pnpm.overrides` (Spec §5: transitive Deps nicht hart import-bumpen)
// - Lockfile-Regen: tmp-Dir + `npm install --package-lock-only --ignore-scripts`
//   bzw. pnpm `install --lockfile-only` via corepack; Lockfile per PUT (Spec Gotcha 2:
//   base64 ohne Zeilenumbrüche)
// - PR via POST /pulls; Dedupe: max 1 PR/Repo/Tag (day-scoped Branch + open-PR-Check)

import { execFile } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';

import semver from 'semver';

import { OWNER, log, parseIsoDateKey } from './config.js';
import { b64, decodeB64, ghFetch, ghJson, ghJsonOrNull } from './github.js';
import { generatePrBodyCveSections } from './llm.js';
import type { Ecosystem, RepoInfo } from './inventory.js';

export interface FixFinding {
  pkg: string;
  version: string;
  patched: string | null; // aus first_patched_version.identifier
  ghsas: string[];
  severity: string;
  summary?: string; // Advisory-Summary (für LLM-PR-Body)
}

export interface FixResult {
  status: 'created' | 'exists' | 'skipped' | 'failed';
  prUrl?: string;
  prNumber?: number;
  branch?: string;
  bumped?: string[];
  note?: string;
}

const SECTIONS = [
  'dependencies',
  'devDependencies',
  'optionalDependencies',
  'peerDependencies',
] as const;

const execFileP = promisify(execFile);

export function fixBranchName(date = new Date()): string {
  return `cve-audit/fixes-${parseIsoDateKey(date)}`;
}

export async function createFixPr(
  repo: RepoInfo,
  lockfileEcosystem: Ecosystem,
  findings: FixFinding[]
): Promise<FixResult> {
  if (findings.length === 0) return { status: 'skipped', note: 'keine verwertbaren Fixes' };
  if (lockfileEcosystem === 'pip' || lockfileEcosystem === 'go' || lockfileEcosystem === 'cargo') {
    return {
      status: 'skipped',
      note: `Auto-Fix nur für npm/pnpm/yarn (Ökosystem hier: ${lockfileEcosystem})`,
    };
  }
  if (findings.every((f) => !f.patched)) {
    return { status: 'skipped', note: 'kein first_patched_version verfügbar' };
  }

  const branch = fixBranchName();
  try {
    // Offenen PR zur Branch-ID checken (Dedupe, auch wenn Branch schon existiert)
    const existing = await findOpenPr(repo.name, branch);
    if (existing) return { status: 'exists', prUrl: existing.url, prNumber: existing.number, branch };

    // Base-SHA (Default-Branch-Head) ermitteln + Branch anlegen (idempotent)
    const ref = await ghJson<{ object: { sha: string } }>(
      `/repos/${OWNER}/${repo.name}/git/ref/heads/${repo.defaultBranch}`
    );
    const created = await tryCreateRef(repo.name, branch, ref.object.sha);
    if (created === 'ref-exists') {
      const openNow = await findOpenPr(repo.name, branch);
      if (openNow) return { status: 'exists', prUrl: openNow.url, prNumber: openNow.number, branch };
      log(`Fix-PR ${repo.name}: Branch ${branch} existiert ohne offenen PR — update fort.`);
    }

    // package.json-Blob auf Branch holen (GET /contents liefert Blob-SHA → Pflicht für PUT)
    const pkgFile = await ghJsonOrNull<{ sha: string; content: string }>(
      `/repos/${OWNER}/${repo.name}/contents/package.json?ref=${encodeURIComponent(branch)}`
    );
    if (!pkgFile) return { status: 'skipped', branch, note: 'kein package.json am Repo-Root' };

    const originalPkg = decodeB64(pkgFile.content);
    const { updatedPkg, bumped, overridesAdded } = applyBumps(originalPkg, lockfileEcosystem, findings);
    if (updatedPkg === null) {
      return { status: 'skipped', branch, note: 'keine fixbaren Deps in package.json' };
    }

    await putContent(
      repo.name,
      'package.json',
      branch,
      pkgFile.sha,
      updatedPkg,
      'chore(cve-audit): bump vulnerable dependencies [skip ci]'
    );

    // pnpm >= 12 liest pnpm.overrides aus package.json NICHT mehr ("The pnpm field
    // is no longer read") → overrides als top-level Block in pnpm-workspace.yaml.
    let workspaceYaml: string | null = null;
    if (lockfileEcosystem === 'pnpm' && overridesAdded.length > 0) {
      try {
        workspaceYaml = await renderPnpmWorkspaceOverrides(repo.name, branch, parseOverridesAdded(overridesAdded));
      } catch (err) {
        log(`Fix-PR ${repo.name}: pnpm-workspace.yaml-Update fehlgeschlagen: ${err instanceof Error ? err.message : String(err)}`);
      }
    }

    // Lockfile regenerieren und pushen (nur wenn geändert)
    let lockNote: string | null = null;
    const lockPath = lockfilePath(lockfileEcosystem, repo.lockedPath);
    if (lockPath) {
      const lockFile = await ghJsonOrNull<{ sha: string; content: string }>(
        `/repos/${OWNER}/${repo.name}/contents/${lockPath}?ref=${encodeURIComponent(branch)}`
      );
      if (lockFile) {
        const regenerated = await regenerateLockfile(
          lockfileEcosystem,
          updatedPkg,
          decodeB64(lockFile.content),
          workspaceYaml !== null ? { 'pnpm-workspace.yaml': workspaceYaml } : undefined
        );
        if (regenerated.changed && regenerated.content !== undefined) {
          await putContent(
            repo.name,
            lockPath,
            branch,
            lockFile.sha,
            regenerated.content,
            'chore(cve-audit): regen lockfile [skip ci]'
          );
        } else {
          lockNote = regenerated.note ?? null;
        }
      }
    }

    const pr = await ghJson<{ html_url: string; number: number }>(
      `/repos/${OWNER}/${repo.name}/pulls`,
      {
        method: 'POST',
        body: JSON.stringify({
          title: 'chore(cve-audit): bump vulnerable dependencies',
          head: branch,
          base: repo.defaultBranch,
          body: await prBody(repo.name, findings, bumped, overridesAdded, lockNote),
        }),
      }
    );
    return { status: 'created', prUrl: pr.html_url, prNumber: pr.number, branch, bumped };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    log(`WARN: Fix-PR für ${repo.name} fehlgeschlagen: ${msg}`);
    return { status: 'failed', branch, note: msg.slice(0, 300) };
  }
}

async function findOpenPr(repo: string, branch: string): Promise<{ url: string; number: number } | null> {
  const prs = await ghJsonOrNull<Array<{ html_url: string; number: number }>>(
    `/repos/${OWNER}/${repo}/pulls?state=open&head=${OWNER}:${encodeURIComponent(branch)}`
  );
  return prs && prs.length > 0 ? { url: prs[0]!.html_url, number: prs[0]!.number } : null;
}

/** "pkg → version"-Einträge aus overridesAdded zurück in eine Map zerlegen. */
function parseOverridesAdded(entries: string[]): Record<string, string> {
  const map: Record<string, string> = {};
  for (const e of entries) {
    const m = /^(.+?) → (.+)$/.exec(e);
    if (m) map[m[1]!] = m[2]!;
  }
  return map;
}

/**
 * overrides als top-level Block in pnpm-workspace.yaml rendern und ins Repo
 * schreiben (pnpm >= 12: pnpm.overrides in package.json wird nicht mehr gelesen).
 * Merge: existierende Einträge bleiben, neue überschreiben. Return: gerenderter
 * YAML-Content (für das tmp-Dir des Lockfile-Regens). Überspringer-Fallback lämpt.
 */
async function renderPnpmWorkspaceOverrides(
  repo: string,
  branch: string,
  ov: Record<string, string>
): Promise<string> {
  const file = await ghJsonOrNull<{ sha: string; content: string }>(
    `/repos/${OWNER}/${repo}/contents/pnpm-workspace.yaml?ref=${encodeURIComponent(branch)}`
  );
  const text = file ? decodeB64(file.content) : '';
  const updated = renderPnpmWorkspaceYaml(text, ov);

  const res = await ghFetch(
    `/repos/${OWNER}/${repo}/contents/pnpm-workspace.yaml?branch=${encodeURIComponent(branch)}`,
    {
      method: 'PUT',
      body: JSON.stringify({
        message: 'chore(cve-audit): pnpm overrides in pnpm-workspace.yaml [skip ci]',
        content: b64(updated),
        sha: file?.sha,
        branch,
      }),
    }
  );
  if (!res.ok) {
    const body = await res.text();
    throw new Error(`pnpm-workspace.yaml PUT ${res.status}: ${body.slice(0, 200)}`);
  }
  return updated;
}

/** pnpm-workspace.yaml-Text mit gemergtem flachem overrides-Block neu rendern. */
function renderPnpmWorkspaceYaml(text: string, ov: Record<string, string>): string {
  // Existierende (flache) overrides-Einträge erfassen: Block `overrides:` bis zur
  // nächsten top-level Zeile (kein Leading-Space) oder Dateiende.
  const blockRe = /^overrides:\n((?:[ \t][^\n]*\n|[ \t]*\n)*)/m;
  const m = blockRe.exec(text);
  const existing: Record<string, string> = {};
  if (m) {
    for (const line of m[1]!.split('\n')) {
      const e = /^[ \t]+("?)([^":\s]+)\1:[ \t]*("?)([^":\n]+)\3[ \t]*$/.exec(line);
      if (e) existing[e[2]!] = e[4]!;
    }
  }
  const merged = { ...existing, ...ov };

  const block =
    'overrides:\n' +
    Object.keys(merged)
      .sort()
      .map((k) => `  "${k}": "${merged[k]}"\n`)
      .join('');

  if (m) {
    return text.slice(0, m.index) + block + text.slice(m.index + m[0]!.length);
  }
  return text.replace(/\n*$/, '\n\n') + block;
}

async function tryCreateRef(
  repo: string,
  branch: string,
  sha: string
): Promise<'created' | 'ref-exists'> {
  const res = await ghFetch(`/repos/${OWNER}/${repo}/git/refs`, {
    method: 'POST',
    body: JSON.stringify({ ref: `refs/heads/${branch}`, sha }),
  });
  if (res.ok) return 'created';
  const body = await res.text();
  if (res.status === 422 && /exists/i.test(body)) return 'ref-exists';
  throw new Error(`ref-create ${res.status}: ${body.slice(0, 200)}`);
}

function lockfilePath(eco: Ecosystem, fallback: string | null): string | null {
  const known: Record<string, string> = {
    npm: 'package-lock.json',
    pnpm: 'pnpm-lock.yaml',
    yarn: 'yarn.lock',
  };
  const hit = known[eco];
  return hit ?? fallback ?? null;
}

/** package.json-Fixes anwenden; Returns null-Content, wenn NICHTS pratikabel verändert wurde. */
function applyBumps(
  pkgJson: string,
  eco: Ecosystem,
  findings: FixFinding[]
): { updatedPkg: string | null; bumped: string[]; overridesAdded: string[] } {
  let json: Record<string, unknown>;
  try {
    json = JSON.parse(pkgJson) as Record<string, unknown>;
  } catch {
    return { updatedPkg: null, bumped: [], overridesAdded: [] };
  }
  const bumped: string[] = [];
  const overridesAdded: string[] = [];

  const fixes = findings.filter((f) => f.patched !== null);
  for (const f of fixes) {
    const patched = f.patched as string;
    let directSection: (typeof SECTIONS)[number] | null = null;
    for (const section of SECTIONS) {
      const obj = json[section];
      if (obj && typeof obj === 'object' && f.pkg in (obj as Record<string, unknown>)) {
        directSection = section;
        break;
      }
    }
    if (directSection) {
      const dep = json[directSection] as Record<string, string>;
      const old = dep[f.pkg];
      // Downgrade-Guard: first_patched kann unterhalb der installierten Version
      // liegen (mehrgliedrige Advisory-Ranges) → kein Major-Rückwärts-Bump
      // (z. B. mermaid ^11.4.1 → ^10.9.3). Stattdessen Finding überspringen.
      const oldCoerced = old ? semver.coerce(old) : null;
      const patchedCoerced = semver.coerce(patched);
      if (
        oldCoerced &&
        patchedCoerced &&
        semver.major(patchedCoerced) < semver.major(oldCoerced)
      ) {
        log(`Fix-PR: ${f.pkg} ${patched} < ${old} (Major-Downgrade) — übersprungen.`);
        continue;
      }
      // Versionsstil des Repos erhalten (^ / ~), sonst exakte gepatchte Version
      const target =
        old?.startsWith('^') === true
          ? `^${patched}`
          : old?.startsWith('~') === true
            ? `~${patched}`
            : patched;
      if (old !== target) {
        dep[f.pkg] = target;
        bumped.push(`${f.pkg}: ${old ?? '?'} → ${target}`);
      }
      continue;
    }
    // Transitive: overrides statt fake Bump in dependencies
    if (eco === 'npm' || eco === 'yarn') {
      const ov = (json.overrides ??= {}) as Record<string, string>;
      const target = patched;
      if (ov[f.pkg] !== target) {
        ov[f.pkg] = target;
        overridesAdded.push(`${f.pkg} → ${target}`);
      }
    } else if (eco === 'pnpm') {
      // pnpm >= 12: pnpm.overrides in package.json wird NICHT mehr gelesen →
      // nur Auflistung; Block landet in pnpm-workspace.yaml (siehe createFixPr).
      const target = patched;
      overridesAdded.push(`${f.pkg} → ${target}`);
    }
  }

  if (bumped.length === 0 && overridesAdded.length === 0) {
    return { updatedPkg: null, bumped, overridesAdded };
  }
  return { updatedPkg: `${JSON.stringify(json, null, 2)}\n`, bumped, overridesAdded };
}

async function putContent(
  repo: string,
  filePath: string,
  branch: string,
  blobSha: string,
  content: string,
  message: string
): Promise<void> {
  // ACHTUNG (Spec Gotcha 1): bei existierender Datei ist `sha` der Blob-SHA der
  // Datei (aus contents-GET) — NICHT ein Commit-SHA. Content: base64 ohne Wraps.
  const res = await ghFetch(
    `/repos/${OWNER}/${repo}/contents/${filePath}?branch=${encodeURIComponent(branch)}`,
    {
      method: 'PUT',
      body: JSON.stringify({ message, content: b64(content), sha: blobSha, branch }),
    }
  );
  if (!res.ok) {
    const body = await res.text();
    throw new Error(`contents-PUT ${filePath} ${res.status}: ${body.slice(0, 250)}`);
  }
}

interface RegenResult {
  changed: boolean;
  content?: string;
  note?: string;
}

/** Lockfile im tmp-Checkout regenerieren (Spec: npm/pnpm, keine Scripts, kein node_modules). */
async function regenerateLockfile(
  eco: Ecosystem,
  pkgJson: string,
  lockContent: string,
  extraFiles?: Record<string, string>
): Promise<RegenResult> {
  const lockPath = lockfilePath(eco, null);
  if (!lockPath) return { changed: false, note: 'kein bekanntes Lockfile' };

  const dir = mkdtempSync(path.join(os.tmpdir(), `cve-fix-${eco}-`));
  writeFileSync(path.join(dir, 'package.json'), pkgJson);
  writeFileSync(path.join(dir, lockPath), lockContent);
  for (const [name, content] of Object.entries(extraFiles ?? {})) {
    writeFileSync(path.join(dir, name), content);
  }

  try {
    if (eco === 'npm') {
      await execFileP(
        'npm',
        ['install', '--package-lock-only', '--ignore-scripts', '--no-audit', '--no-fund'],
        {
          cwd: dir,
          // npm >= 12 schließt remote-tarball-Bezüge standardmäßig vom
          // Regenerieren aus (EALLOWREMOTE); für lockfile-only Regen erlaubt.
          env: { ...process.env, NPM_CONFIG_ALLOW_REMOTE: 'all' },
          timeout: 5 * 60_000,
        }
      );
    } else if (eco === 'pnpm') {
      await execFileP('corepack', ['pnpm', 'install', '--lockfile-only'], {
        cwd: dir,
        env: { ...process.env, COREPACK_ENABLE_DOWNLOAD_PROMPT: '0' },
        timeout: 5 * 60_000,
      });
    } else {
      // yarn 1: regen (install --no-save) braucht Workspace-Kontext → Flag im PR-Body nennen
      return {
        changed: false,
        note: 'yarn.lock-Regen nicht automatisiert — nach Merge manuell `yarn install` laufen lassen',
      };
    }
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return {
      changed: false,
      note: `Lockfile-Regen fehlgeschlagen (${msg.slice(0, 150)}) — manuell regenerieren`,
    };
  }
  const out = readFileSync(path.join(dir, lockPath), 'utf8');
  return { changed: out !== lockContent, content: out };
}

async function prBody(
  repo: string,
  findings: FixFinding[],
  bumped: string[],
  overridesAdded: string[],
  lockNote: string | null
): Promise<string> {
  // CVE-Absätze via LLM (ENGLISCH), falls enabled — deterministischer Fallback:
  // kompakte Bullet-Liste wie bisher.
  const cveLlm = await generatePrBodyCveSections({
    repo,
    findings: findings.map((f) => ({
      pkg: f.pkg,
      version: f.version,
      patched: f.patched,
      ghsas: f.ghsas,
      severity: f.severity,
      summaries: f.summary ? [f.summary] : [],
    })),
  });

  const lines: string[] = [
    'Automatically generated by the `audit-scanner` (CVE auto-fix run).',
    '',
    '### Affected dependencies (high/critical)',
  ];
  for (const f of findings) {
    lines.push(
      `- \`${f.pkg}@${f.version}\` → \`${f.patched ?? 'no fix version available yet'}\` (${f.severity}; ${f.ghsas.join(', ') || 'no GHSA ids in scope'})`
    );
  }
  if (cveLlm) {
    lines.push('', '### CVE details', '', cveLlm);
  }
  if (bumped.length) {
    lines.push('', '### Direct bumps in package.json');
    for (const b of bumped) lines.push(`- ${b}`);
  }
  if (overridesAdded.length) {
    lines.push('', '### Transitive dependencies (overrides block)');
    for (const o of overridesAdded) lines.push(`- ${o}`);
  }
  if (lockNote) {
    lines.push('', `> ⚠️ ${lockNote}`);
  }
  lines.push(
    '',
    '### Checks before merge',
    'CI must be green before merging. No auto-merge — human approval required.'
  );
  return lines.join('\n');
}

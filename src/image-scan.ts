// Image-Scan (v1.4.0): Dockerfile-/Compose-Datei-Scan nach Tarball-Entpacken.
// - Parse aller `FROM <image>` + `COPY/ADD --from=<image>` (BuildKit-Flags,
//   Stage-Namen, numerische Stage-Indizes ausgeschlossen) + compose-`image:`
//   -Felder, robust gegen Kommentare; `$VAR`-Refs → Skip mit Note.
// - Je dedupliziertem Image-Ref: trivy image scan ohne Docker-Daemon
//   (Registry-API direkt, gemeinsamer DB-Cache), HIGH/CRITICAL-Zählung;
//   private/404-Images graceful skip mit Note.
// - Freshness-Check via Registry-Tag-Liste (Docker Hub / GHCR, anonymous token
//   flow); digest-pinned / latest / invalid Tags → Skip mit Note.
// - Fix-PR-Policy: PR nur für EXAKT gepinnte Tags (x.y.z) mit neuerer Version
//   im selben Major. Floating-Tags (z. B. node:24-alpine) aktualisieren sich
//   implizit beim Rebuild → nur Report, kein PR.

import { execFile } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { promisify } from 'node:util';

import semver from 'semver';

import { OWNER, TRIVY_BIN, TRIVY_CACHE_DIR, log } from './config.js';
import { b64, decodeB64, ghFetch, ghJson, ghJsonOrNull } from './github.js';
import type { RepoInfo } from './inventory.js';
import type { FixResult } from './fix-pr.js';
import { loadState, saveState, upsertEntry, type State } from './state.js';

const execFileP = promisify(execFile);

export type Registry = 'docker-hub' | 'ghcr' | 'other';

export interface ImageFinding {
  /** Image-Ref wie im File geschrieben (z. B. "aquasec/trivy:0.76.1"). */
  image: string;
  /** Image-Name ohne Tag (ohne Registry-Prefix). */
  base: string;
  /** Tag-Teil des Refs ("latest" wenn Tag-less). */
  current: string;
  registry: Registry;
  /** Exakt gepinnt (x.y.z, Variant-Suffix erlaubt) → PR-Kandidat. */
  pinned: boolean;
  /** Number-Float (24-alpine, 17.5) → aktualisiert sich beim Rebuild. */
  floating: boolean;
  digestPinned: boolean;
  /** Repo-relative Files (Dockerfile/compose), in denen der Ref gefunden wurde. */
  sourceFiles: string[];
  vulns: { high: number; critical: number };
  /** Neuester gepinnter Tag im selben Major (incl. Variant-Fallback), sonst null. */
  newestSameMajor: string | null;
  /** pinned && strictly-newer same-major bei der Registry verfügbar. */
  updateAvailable: boolean;
  /** Skip-/Hinweis-Grund (private, latest, Variable, 404 …). */
  note?: string;
}

/** Bump-Plan (je File): literal `${base}:${oldTag}` → `${base}:${newTag}`. */
export interface ImageBumpPlan {
  file: string;
  bumps: Array<{ from: string; to: string }>;
}

export interface ImageScanResult {
  findings: ImageFinding[];
  bumpPlan: ImageBumpPlan[]; // nur pinned + updateAvailable
}

const DOCKERFILE_RE = /^dockerfile(\.[^.]+)?$/i;
const COMPOSE_RE = /^(docker-)?compose\.ya?ml$/i;

function findManifestFiles(root: string): string[] {
  const out: string[] = [];
  const walk = (dir: string): void => {
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, e.name);
      if (e.isDirectory()) {
        if (e.name === 'node_modules' || e.name === '.git' || e.name === '.next') continue;
        walk(full);
      } else if (e.isFile()) {
        if (DOCKERFILE_RE.test(e.name) || COMPOSE_RE.test(e.name)) out.push(full);
      }
    }
  };
  walk(root);
  return out;
}

interface TokResult {
  type: 'FROM' | 'COPY' | 'ADD';
  /** Image-/Stage-Ref (ggf. undefined bei nicht auflösbarem Token). */
  ref?: string;
  /** Copy/from-Flag gefunden (COPY/ADD) — auch SET wenn ref undef */
  isFromRef: boolean;
  reason?: string;
}

/** Whitespace-Tokens je Dockerfile-Zeile; null bei Kommentar/leer/anderer Instruction. */
function parseInstr(line: string): TokResult | null {
  const l = line.trim();
  if (!l || l.startsWith('#')) return null;
  const raw = l.split(/\s+/);
  const instr = raw[0]!.toUpperCase();
  if (instr !== 'FROM' && instr !== 'COPY' && instr !== 'ADD') return null;

  if (instr === 'FROM') {
    // erstes Nicht-Flag-Token nach FROM = Ref (BuildKit-Flags wie --platform=…)
    for (let j = 1; j < raw.length; j++) {
      const tok = raw[j]!;
      if (tok.startsWith('--')) continue;
      if (/^AS$/i.test(tok)) break; // "FROM AS x" malform
      if (tok.includes('$')) return { type: 'FROM', isFromRef: false, reason: `FROM-Ref ${tok} enthält Variable` };
      return { type: 'FROM', ref: tok, isFromRef: true };
    }
    return { type: 'FROM', isFromRef: false, reason: 'FROM ohne auflösbaren Ref' };
  }
  // COPY/ADD: Flags überspringen; --from=X extrahieren, erstes Nicht-Flag beendet Flags.
  for (let j = 1; j < raw.length; j++) {
    const tok = raw[j]!;
    if (tok.startsWith('--')) {
      const m = /^--from=(.+)$/.exec(tok);
      if (m) {
        const v = unquote(m[1]!);
        if (v.includes('$')) return { type: instr, isFromRef: true, reason: `--from ${v} enthält Variable` };
        return { type: instr, ref: v, isFromRef: true };
      }
      continue;
    }
    break; // Quellobjekt erreicht — kein --from in der Zeile
  }
  return null;
}

function unquote(s: string): string {
  const m = /^"(.*)"$/.exec(s) ?? /^'(.*)'$/.exec(s);
  return m ? m[1]! : s;
}

/** Dockerfile-Zeilen → Images (2 Pässe: Stage-Namen zuerst, dann FROM/COPY --from). */
function parseDockerfile(lines: string[]): { images: string[]; unresolved: string[] } {
  const stages = new Set<string>();
  const stageIndices = new Set<string>();
  let next = 0;
  const unresolved: string[] = [];
  for (const line of lines) {
    const t = parseInstr(line);
    if (t?.reason && t.type === 'FROM') unresolved.push(`FROM: ${t.reason}`);
    if (t?.type !== 'FROM') continue;
    // Malformed-Fälle ohne Ref zählen trotzdem als Stage-Index
    const m = /^\s*FROM\s+(?:--\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?\s*$/i;
    const mm = m.exec(line.trim());
    if (mm?.[2]) stages.add(mm[2]!);
    stageIndices.add(String(next++));
  }
  const images: string[] = [];
  for (const line of lines) {
    const t = parseInstr(line);
    if (!t) continue;
    if (t.reason) {
      unresolved.push(t.reason);
      continue;
    }
    if (t.type === 'FROM' && t.ref) {
      const ref = t.ref;
      if (ref.toLowerCase() === 'scratch') continue; // kein Image
      if (stages.has(ref) || stageIndices.has(ref)) continue; // Stage-Re-Base, kein Image
      images.push(ref);
    } else if ((t.type === 'COPY' || t.type === 'ADD') && t.ref) {
      const from = t.ref;
      if (stages.has(from) || stageIndices.has(from)) continue; // Stage-Referenz
      images.push(from);
    }
  }
  return { images, unresolved };
}

/** Compose-`image:`-Felder (Zeilen-Regex, robust vs. inline-Kommentare/Quotes). */
function parseCompose(lines: string[]): string[] {
  const out: string[] = [];
  for (const raw of lines) {
    const m = /^\s*image:\s*(["']?)(\S+?)\1\s*(#.*)?$/.exec(raw);
    if (m?.[2]) out.push(unquote(m[2]!));
  }
  return out;
}

function splitRef(ref: string): { base: string; tag: string | null; digest: string | null; registry: Registry } {
  let rest = ref;
  let digest: string | null = null;
  const at = rest.indexOf('@');
  if (at !== -1) {
    digest = rest.slice(at + 1);
    rest = rest.slice(0, at);
  }
  let registry: Registry = 'docker-hub';
  let base = rest;
  const slash = rest.indexOf('/');
  const firstSeg = slash === -1 ? '' : rest.slice(0, slash);
  if (slash !== -1 && (firstSeg.includes('.') || firstSeg.includes(':') || firstSeg === 'localhost')) {
    if (/^ghcr\.io$/i.test(firstSeg)) registry = 'ghcr';
    else if (/^(docker\.io|index\.docker\.io|registry-1\.docker\.io)$/i.test(firstSeg)) registry = 'docker-hub';
    else registry = 'other';
    base = rest.slice(slash + 1);
  }
  let tag: string | null = null;
  const cIdx = base.lastIndexOf(':');
  const sIdx = base.lastIndexOf('/');
  if (cIdx > sIdx) {
    tag = base.slice(cIdx + 1);
    base = base.slice(0, cIdx);
  }
  return { base, tag, digest, registry };
}

interface TagSemantics {
  major: number | null;
  comps: number;
  variant: string; // Suffix nach der Nummer (ohne '+'/'-'), '' = keiner
  pinned: boolean; // x.y.z (+variants)
  floating: boolean; // 24 / 24.7 / 24-alpine / 17.5
  prerelease: boolean; // -alpha/-beta/-rc/-dev/…
  valid: boolean; // nutzbar für Freshness
}

function tagSemantics(tag: string): TagSemantics {
  const m = /^v?(\d+(?:\.\d+)*)([-+].*)?$/.exec(tag);
  const base: TagSemantics = {
    major: null,
    comps: 0,
    variant: '',
    pinned: false,
    floating: false,
    prerelease: false,
    valid: false,
  };
  if (!m) return { ...base, valid: false };
  const comps = (m[1] as string).split('.').map(Number);
  const suffix = (m[2] as string) ?? '';
  const variant = suffix ? suffix.slice(1) : '';
  const prerelease = /^-(alpha|beta|rc|dev|edge|snapshot|pre)/i.test(suffix) || suffix.startsWith('+rc');
  let pinned = comps.length >= 3 && !prerelease;
  let floating = comps.length < 3 && !prerelease;
  return {
    major: comps[0]!,
    comps: comps.length,
    variant,
    pinned,
    floating,
    prerelease,
    valid: true,
  };
}

async function registryToken(base: string, registry: Registry): Promise<string | null> {
  if (registry === 'docker-hub') {
    const repo = base.includes('/') ? base : `library/${base}`;
    const res = await fetch(`https://auth.docker.io/token?service=registry.docker.io&scope=repository:${repo}:pull`);
    if (!res.ok) return null;
    const j = (await res.json()) as { token?: string };
    return j.token ?? '';
  }
  if (registry === 'ghcr') {
    const res = await fetch(`https://ghcr.io/token?scope=repository:${base}:pull`);
    if (!res.ok) return null;
    const j = (await res.json()) as { token?: string };
    return j.token ?? '';
  }
  return null;
}

/** Tags/list via Registry v2-API. 401/403 → null ('privat'), 404 → null. */
async function fetchRegistryTags(base: string, registry: Registry): Promise<{ tags: string[] | null; note?: string }> {
  if (registry === 'other') return { tags: null, note: 'Freshness nur Docker Hub/GHCR — übersprungen' };
  try {
    const token = await registryToken(base, registry);
    if (token === null) return { tags: null, note: 'Token-Fetch fehlgeschlagen' };
    const repo = registry === 'docker-hub' && !base.includes('/') ? `library/${base}` : base;
    const url = registry === 'docker-hub' ? `https://registry-1.docker.io/v2/${repo}/tags/list?n=1000` : `https://ghcr.io/v2/${base}/tags/list?n=1000`;
    const out: string[] = [];
    let u: string | null = url;
    let depth = 0;
    while (u && depth < 2) {
      const res = await fetch(u, token ? { headers: { Authorization: `Bearer ${token}` } } : {});
      if (res.status === 401 || res.status === 403) return { tags: null, note: 'nicht öffentlich (401/403) — übersprungen' };
      if (res.status === 404) return { tags: null, note: 'unbekannt (404) — übersprungen' };
      if (!res.ok) return { tags: null, note: `tags/list ${res.status}` };
      const j = (await res.json()) as { tags?: string[] | null };
      if (Array.isArray(j.tags)) out.push(...j.tags.filter((t) => typeof t === 'string' && t.length > 0));
      const link = res.headers.get('link');
      u = link?.includes('rel="next"') ? /<([^>]+)>/.exec(link)?.[1] ?? null : null;
      depth++;
    }
    return { tags: [...new Set(out)] };
  } catch (err) {
    return { tags: null, note: `Registry-Fehler: ${err instanceof Error ? err.message.slice(0, 120) : '?'}` };
  }
}

function stripVariant(tag: string): string {
  return tag.replace(/([-+].*)$/, '');
}

/**
 * Neuester gepinnter Tag im selben Major; Variant-Suffix wird bevorzugt exakt
 * gematcht, sonst Prefix-Fallback (`alpine` → `alpine3.22`). Pre-Releases aus,
 * vergleiche semver (strippte Variante). Rückgabe auch floating-Fällen als
 * Info; nur für pinned-Refs wirfold ein PR gebaut.
 */
function newestSameMajorTag(currentTag: string, tags: string[]): string | null {
  const cur = tagSemantics(currentTag);
  if (!cur.valid || cur.major === null) return null;
  const cand = tags
    .map((t) => ({ tag: t, sem: tagSemantics(t) }))
    .filter((c) => c.sem.valid && c.sem.major === cur.major && c.sem.pinned);
  if (cand.length === 0) return null;

  const sameVariant = cur.variant
    ? cand.filter(
        (c) =>
          c.sem.variant === cur.variant ||
          c.sem.variant.startsWith(`${cur.variant}`) // alpine + alpine3.22
      )
    : [];
  const pool = sameVariant.length > 0 ? sameVariant : cand;

  const scored = pool.sort((a, b) => {
    const va = semver.coerce(stripVariant(a.tag)) ?? '0.0.0';
    const vb = semver.coerce(stripVariant(b.tag)) ?? '0.0.0';
    return semver.compare(va, vb);
  });
  const newest = scored.at(-1);
  return newest ? newest.tag : null;
}

function strictlyNewer(currentTag: string, candidateTag: string): boolean {
  const a = semver.coerce(stripVariant(currentTag));
  const b = semver.coerce(stripVariant(candidateTag));
  if (!a || !b) return false;
  return semver.gt(b, a);
}

interface ImgTrivyResult {
  Results?: Array<{
    Vulnerabilities?: Array<{ VulnerabilityID: string; PkgName?: string; Severity?: string } | null> | null;
  }>;
}

async function trivyImageScan(
  image: string,
  outPath: string
): Promise<{ high: number; critical: number; error?: string }> {
  try {
    await execFileP(
      TRIVY_BIN,
      ['image', '--scanners', 'vuln', '--severity', 'HIGH,CRITICAL', '--format', 'json',
        '--cache-dir', TRIVY_CACHE_DIR, '--quiet', '--output', outPath, image],
      { timeout: 12 * 60_000, maxBuffer: 256 * 1024 * 1024 }
    );
  } catch (err) {
    const msg = err instanceof Error ? `${err.message} ${'stderr' in err ? String((err as { stderr?: string }).stderr) : ''}` : String(err);
    if (/401|403|unauthorized|forbidden/i.test(msg)) return { high: 0, critical: 0, error: 'private/nicht öffentlich — übersprungen' };
    if (/404|not found|does not exist/i.test(msg)) return { high: 0, critical: 0, error: 'unbekannt (404) — übersprungen' };
    if (/denied/i.test(msg)) return { high: 0, critical: 0, error: 'access denied — übersprungen' };
    return { high: 0, critical: 0, error: `trivy-Fehler: ${msg.slice(0, 200)}` };
  }
  let json: ImgTrivyResult;
  try {
    json = JSON.parse(fs.readFileSync(outPath, 'utf8')) as ImgTrivyResult;
  } catch (err) {
    return { high: 0, critical: 0, error: `trivy-JSON unparsable: ${err instanceof Error ? err.message.slice(0, 150) : '?'}` };
  }
  let high = 0;
  let critical = 0;
  const seen = new Set<string>();
  for (const r of json.Results ?? []) {
    for (const v of r.Vulnerabilities ?? []) {
      if (!v || (v.Severity !== 'HIGH' && v.Severity !== 'CRITICAL')) continue;
      const key = `${v.VulnerabilityID}|${v.PkgName ?? ''}`;
      if (seen.has(key)) continue;
      seen.add(key);
      if (v.Severity === 'HIGH') high++;
      else critical++;
    }
  }
  return { high, critical };
}

/**
 * Je Repo: Dockerfiles + Compose-Files parsen → Refs deduplizieren → trivy
 * image scan + Freshness je Ref (Konkurrenz 3). Bump-Plan nur für pinned
 * + strictly-newer same-major (PR-Kandidaten). Kein trivy → kein Image-Scan.
 */
export async function scanRepoImages(
  repo: RepoInfo,
  repoDir: string,
  scanTmp: string,
  trivyAvailable: boolean
): Promise<ImageScanResult> {
  const files = findManifestFiles(repoDir);
  if (files.length === 0 || !trivyAvailable) return { findings: [], bumpPlan: [] };

  const byKey = new Map<string, ImageFinding>();
  for (const file of files) {
    const rel = path.relative(repoDir, file);
    let lines: string[] = [];
    try {
      lines = fs.readFileSync(file, 'utf8').split(/\r?\n/);
    } catch (err) {
      log(`Image-Scan ${repo.name}: ${rel} unparsable — ${err instanceof Error ? err.message : String(err)}`);
      continue;
    }
    const isDockerfile = DOCKERFILE_RE.test(path.basename(file));
    const isCompose = COMPOSE_RE.test(path.basename(file));
    const refs = [
      ...(isDockerfile ? (() => {
        const { images, unresolved } = parseDockerfile(lines);
        for (const u of unresolved) log(`Image-Scan ${repo.name} ${rel}: ${u} — übersprungen.`);
        return images;
      })() : []),
      ...(isCompose ? parseCompose(lines) : []),
    ];
    for (const ref of refs) addRef(byKey, ref, rel);
  }

  const findings = [...byKey.values()];
  const bumpPlan: ImageBumpPlan[] = [];
  const CONC = 3;
  for (let i = 0; i < findings.length; i += CONC) {
    await Promise.all(findings.slice(i, i + CONC).map(async (f) => {
      const safe = f.image.replace(/[^A-Za-z0-9._\-/@:]/g, '_');
      if (f.note) return; // latest/tagless/digest/invalid → kein Scan, Note bleibt stehen
      const outPath = path.join(scanTmp, `${repo.name}.img-${i}-${safe.replace(/[/:@]/g, '_')}.trivy.json`);
      const vulns = await trivyImageScan(f.image, outPath);
      f.vulns.high = vulns.high;
      f.vulns.critical = vulns.critical;
      if (vulns.error) {
        f.note = vulns.error;
        return;
      }
      if (f.digestPinned) return; // Freshness bewusst skippt (digest satt)
      const { tags, note } = await fetchRegistryTags(f.base, f.registry);
      if (!tags) {
        f.note = note ?? 'keine Tag-Liste';
        return;
      }
      const newest = newestSameMajorTag(f.current, tags);
      f.newestSameMajor = newest;
      if (f.pinned && newest && strictlyNewer(f.current, newest)) {
        f.updateAvailable = true;
        for (const file of f.sourceFiles) {
          const existing = bumpPlan.find((p) => p.file === file);
          const bump = { from: f.image, to: `${f.base}:${newest}` };
          if (existing) existing.bumps.push(bump);
          else bumpPlan.push({ file, bumps: [bump] });
        }
      }
    }));
  }
  return { findings, bumpPlan };
}

/** Ref in den Dedupe-Index aufnehmen (sourceFiles mergen, once-Logik). */
function addRef(byKey: Map<string, ImageFinding>, ref: string, rel: string): void {
  if (byKey.has(ref)) {
    const f = byKey.get(ref)!;
    if (!f.sourceFiles.includes(rel)) f.sourceFiles.push(rel);
    return;
  }
  const { base, tag, digest, registry } = splitRef(ref);
  const sem = tagSemantics(tag ?? 'latest');
  if (!tag) {
    byKey.set(ref, mkFinding(ref, base, 'latest', sem, rel, false, 'kein Tag (latest implizit) — übersprungen'));
    return;
  }
  if (tag === 'latest') {
    byKey.set(ref, mkFinding(ref, base, tag, sem, rel, false, 'latest — kein Pin, kein Freshness-Check'));
    return;
  }
  if (digest) {
    byKey.set(ref, mkFinding(ref, base, tag, { ...sem, pinned: false, floating: false }, rel, true,
      'digest-pinned — Freshness übersprungen (Digest an Ref)'));
    return;
  }
  if (!sem.valid) {
    byKey.set(ref, mkFinding(ref, base, tag, sem, rel, false, `nicht-numerischer Tag (${tag}) — Freshness übersprungen`));
    return;
  }
  if (sem.prerelease) {
    byKey.set(ref, mkFinding(ref, base, tag, sem, rel, false, `Pre-Release-Tag (${tag}) — übersprungen`));
    return;
  }
  byKey.set(ref, mkFinding(ref, base, tag, sem, rel, false));
}

function mkFinding(
  image: string,
  base: string,
  current: string,
  sem: ReturnType<typeof tagSemantics>,
  rel: string,
  digestPinned: boolean,
  note?: string
): ImageFinding {
  return {
    image,
    base,
    current,
    registry: splitRef(image).registry,
    pinned: sem.pinned && !digestPinned,
    floating: sem.floating,
    digestPinned,
    sourceFiles: [rel],
    vulns: { high: 0, critical: 0 },
    newestSameMajor: null,
    updateAvailable: false,
    note,
  };
}

// ——————————————————————————————— Image-Fix-PR ———————————————————————————————

function imageBranchName(date = new Date()): string {
  return `cve-audit/images-${date.toISOString().slice(0, 10)}`;
}

/** Fix-PR für gepinnte, veraltete Image-Tags (immer-PR-Policy, ohne LLM). */
export async function createImagePr(repo: RepoInfo, bumpPlan: ImageBumpPlan[]): Promise<FixResult> {
  if (bumpPlan.length === 0) return { status: 'skipped', note: 'keine Image-Bump-Kandidaten' };
  // HARD GUARD: archivierte Repos bekommen nie Fix-PRs.
  if (repo.archived) return { status: 'skipped', note: 'Repo archived — kein Image-PR (hard guard)' };

  const branch = imageBranchName();
  const state: State = loadState(); // Dedupe analog zu CVE-Fix-PRs (reports/state.json)
  try {
    const existing = await findOpenImagePr(repo.name, branch);
    if (existing) return { status: 'exists', prUrl: existing.url, prNumber: existing.number, branch };

    const ref = await ghJson<{ object: { sha: string } }>(
      `/repos/${OWNER}/${repo.name}/git/ref/heads/${repo.defaultBranch}`
    );
    const created = await tryCreateRef(repo.name, branch, ref.object.sha);
    if (created === 'ref-exists') {
      const openNow = await findOpenImagePr(repo.name, branch);
      if (openNow) return { status: 'exists', prUrl: openNow.url, prNumber: openNow.number, branch };
      log(`Image-PR ${repo.name}: Branch ${branch} existiert ohne offenen PR — update fort.`);
    }

    const bumps: string[] = [];
    let changed = false;
    for (const planFile of bumpPlan) {
      const file = await ghJsonOrNull<{ sha: string; content: string }>(
        `/repos/${OWNER}/${repo.name}/contents/${planFile.file}?ref=${encodeURIComponent(branch)}`
      );
      if (!file) {
        log(`Image-PR ${repo.name}: ${planFile.file} fehlt auf Branch — übersprungen.`);
        continue;
      }
      const original = decodeB64(file.content);
      let updated = original;
      for (const b of planFile.bumps) updated = replaceTag(updated, b.from, b.to);
      if (updated === original) {
        log(`Image-PR ${repo.name}: ${planFile.file} unverändert (Refs nicht auffindbar) — übersprungen.`);
        continue;
      }
      const res = await ghFetch(
        `/repos/${OWNER}/${repo.name}/contents/${planFile.file}?branch=${encodeURIComponent(branch)}`,
        {
          method: 'PUT',
          body: JSON.stringify({
            message: `chore(cve-audit): bump docker image tags in ${planFile.file} [skip ci]`,
            content: b64(updated),
            sha: file.sha,
            branch,
          }),
        }
      );
      if (!res.ok) throw new Error(`contents-PUT ${planFile.file} ${res.status}: ${(await res.text()).slice(0, 200)}`);
      changed = true;
      for (const b of planFile.bumps) bumps.push(`${planFile.file}: ${b.from} → ${b.to}`);
    }

    if (!changed) return { status: 'skipped', branch, note: 'keine anwendbaren Bumps' };

    const pr = await ghJson<{ html_url: string; number: number }>(
      `/repos/${OWNER}/${repo.name}/pulls`,
      {
        method: 'POST',
        body: JSON.stringify({
          title: 'chore(cve-audit): bump pinned docker image tags',
          head: branch,
          base: repo.defaultBranch,
          body: imagePrBody(repo.name, bumps),
        }),
      }
    );
    // State-Eintrag analog zu CVE-Fix-PRs (kind 'image' → kein CVE-Reminder)
    upsertEntry(state, repo.name, {
      branch,
      prUrl: pr.html_url,
      prNumber: pr.number,
      ghsaIds: [],
      createdAt: new Date().toISOString(),
      lastSeen: new Date().toISOString(),
      findings: [],
      kind: 'image',
    });
    saveState(state);
    log(`${repo.name}: Image-PR #${pr.number} im State erfasst.`);
    return { status: 'created', prUrl: pr.html_url, prNumber: pr.number, branch, bumped: bumps };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    log(`WARN: Image-PR für ${repo.name} fehlgeschlagen: ${msg}`);
    return { status: 'failed', branch, note: msg.slice(0, 300) };
  }
}

async function findOpenImagePr(repo: string, branch: string): Promise<{ url: string; number: number } | null> {
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

/** Literal-Swap `from` → `to` mit Tag-Grenze (kein Anhängsel aus Zahlen/Punkten). */
export function replaceTag(content: string, from: string, to: string): string {
  const esc = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  // boolean boundary: Ende der Tag-Route — danach kann @digest, AS/, Whitespace oder
  // Zeilenende folgen; NICHT: weitere Versionssprecher (Zahl/Punkt/-buchstabe?).
  const re = new RegExp(`${esc(from)}(?![0-9.])`, 'g');
  return content.replace(re, to);
}

function imagePrBody(repo: string, bumps: string[]): string {
  return [
    'Automatically generated by the `audit-scanner` (image tag bump run).',
    '',
    '### Pinned docker image tags (newer same-major version at the registry)',
    '',
    ...bumps.map((b) => `- ${b}`),
    '',
    '### Policy note',
    'Only **exactly pinned** tags (`x.y.z`) are bumped, and only to a newer',
    'version of the same major. Floating tags (e.g. `node:24-alpine`)',
    'intentionally stay — they already resolve to the newest matching build',
    'on every rebuild.',
    '',
    '### Checks before merge',
    'Rebuild the image after merging and verify the app starts healthy.',
    'CI must be green before merging. No auto-merge — human approval required.',
  ].join('\n');
}

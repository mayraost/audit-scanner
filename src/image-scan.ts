// Image-Scan (v1.4.0): Dockerfile-/Compose-Datei-Scan nach Tarball-Entpacken.
// - Parse aller `FROM <image>` + `COPY/ADD --from=<image>` (BuildKit-Flags,
//   Stage-Namen, numerische Stage-Indizes ausgeschlossen) + compose-`image:`
//   -Felder, robust gegen Kommentare; `$VAR`-Refs → Skip mit Note.
// - Je dedupliziertem Image-Ref: trivy image scan ohne Docker-Daemon
//   (Registry-API direkt, gemeinsamer DB-Cache), HIGH/CRITICAL-Zählung;
//   private/404-Images graceful skip mit Note.
// - Freshness-Check via Registry-Tag-Liste (Docker Hub / GHCR, anonymous token
//   flow); digest-pinned / latest / invalid Tags → Skip mit Note.
// - Fix-PR-Policy (v1.5.0, AGENTS.md "Keine floating versions"):
//   a) EXAKT gepinnte Tags (x.y.z) mit neuerer Version im selben Major → PR-Bump
//      auf den neueren exakten Tag.
//   b) FLOATING Major-Tags (z. B. node:24-alpine, 24, 17.5) → NOCH ein PR:
//      floating → neuester EXAKTER Tag im selben Major (+ Variant-Fallback:
//      alpine → alpine3.24). Floating aktualisiert sich zwar beim Rebuild, aber
//      exakte Pins sind Pflicht (Volo Reproducibility + Digest-Audit-Sicherheit).
//   c) `latest` / tagless → report-only Note (kein PR — Major-Sprung-Risiko).

import { execFile } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { promisify } from 'node:util';

import semver from 'semver';

import { OWNER, TRIVY_BIN, TRIVY_CACHE_DIR, log } from './config.js';
import { b64, decodeB64, ghFetch, ghJson, ghJsonOrNull } from './github.js';
import type { RepoInfo } from './inventory.js';
import type { FixResult } from './fix-pr.js';
import { imagePublishedAt } from './publish-dates.js';
import { updateEligibility, type Eligibility } from './soaking.js';
import { upsertEntry, type State } from './state.js';

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
  /** Neuester EXAKTER (3-Komp) Tag im selben Major — floating→pin-Bump-Ziel. */
  exactPin: string | null;
  /** pinned && strictly-newer same-major bei der Registry verfügbar. */
  updateAvailable: boolean;
  /**
   * Variant-Drift (v1.6.0): semver-identischer, aber variant-differenter neuerer
   * Registry-Tag (z. B. aktuell `0.8.7-pg17`, neu `0.8.7-pg17-trixie` = anderer
   * OS-Basis-Token). REIN REPORT-ONLY: kein Bump-Plan, kein PR — Variant-/OS-
   * Wechsel ist ein Risiko, keine Update-Empfehlung. null = kein Drift.
   */
  variantDrift?: string | null;
  /** Skip-/Hinweis-Grund (private, latest, Variable, 404 …). */
  note?: string;
  /** v1.6.0: Publish-Datum des Kandidaten (Soaking), null = unbekannt. */
  newestPublishedAt?: string | null;
  /** v1.6.0: Soaking-Entscheidung für den Kandidaten. */
  eligibility?: Eligibility;
  /** v1.6.0: Klartext-Status (z. B. "zu jung (2d)"). */
  eligibilityLabel?: string;
  /** v1.6.0: Alter des Kandidaten in Tagen. */
  ageDays?: number | null;
}

/** Bump-Plan (je File): literal `${base}:${oldTag}` → `${base}:${newTag}`. */
export interface ImageBumpPlan {
  file: string;
  bumps: Array<{ from: string; to: string }>;
}

export interface ImageScanResult {
  findings: ImageFinding[];
  bumpPlan: ImageBumpPlan[]; // pinned+newer AND floating (→ exact pin)
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

/**
 * Tag-Semantik (exportiert für `image-freshness-test`, siehe src/index.ts).
 */
export function tagSemantics(tag: string): TagSemantics {
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

/**
 * Bekannte OS-/Distro-Release-Token in Docker-Tags (v1.6.0). Extrafügen der
 * Kandidaten-Varianten um höchstens EINEN Token aus dieser Liste gelten als
 * "gleiche Variante, andere OS-Basis" (z. B. `alpine` → `alpine3.24`,
 * `slim` → `slim-trixie`) — NICHT als Versions-Update. Alles andere, was die
 * Tokens nicht als Präfix enthält, ist eine fremde Variante.
 * Erweitern nur mit belegten Tag-Repos (Bookworm/Bullseye/Buster/Noble/Jammy
 * sind die gängigen Debian/Ubuntu-Slugs bei library-Images).
 */
const OS_RELEASE_TOKENS: ReadonlySet<string> = new Set([
  'trixie',
  'bookworm',
  'bullseye',
  'buster',
  'stretch',
  'noble',
  'jammy',
  'focal',
  'slim',
  'nanoserver',
  'scratch',
]);
/** Token-zerlegte Variante (`slim-trixie` → ['slim','trixie'], '' → []). */
function variantTokens(variant: string): string[] {
  return variant ? variant.split('-').filter((t) => t.length > 0) : [];
}

/** OS-Release-Token-Form: bekannter Slug oder `alpine3.24` / `alpine3`. */
function isOsReleaseToken(tok: string): boolean {
  const l = tok.toLowerCase();
  if (OS_RELEASE_TOKENS.has(l)) return true;
  return /^alpine\d(\.\d+)?$/.test(l);
}

/**
 * Variant-Kompatibilität (v1.6.0, token-basiert): true, wenn die Tokens des
 * current-Tags Präfix der Kandidaten-Tokens sind und der Kandidat HÖCHSTENS
 * einen zusätzlichen Token hat, der ein bekanntes OS-Release ist.
 * Damit: `alpine` → `alpine3.24` ✓, `slim` → `slim-trixie` ✓,
 * `pg17` → `pg17-trixie` ✓ (OS-Basis-Wechsel, KEIN Versions-Bump → siehe
 * strictlyNewer), `pg17` → `pg17-trixie-foo` ✗, `pg17` → `bookworm` ✗.
 * Bewusste Restriktion: lieber kein "update verfügbar" als ein falscher Bump
 * (Variant-Wechsel = OS-Basis-/Risiko-Wechsel).
 */
function variantCompatible(curVariant: string, candVariant: string): boolean {
  const cur = variantTokens(curVariant);
  const cand = variantTokens(candVariant);
  if (cur.length > cand.length) return false;
  for (let i = 0; i < cur.length; i++) {
    if (cur[i]!.toLowerCase() !== cand[i]!.toLowerCase()) return false;
  }
  const extra = cand.slice(cur.length);
  if (extra.length === 0) return true; // exakt gleiche Tokens
  return extra.length === 1 && isOsReleaseToken(extra[0]!);
}

/** Variante ohne OS-Release-Token (`pg17-trixie` → `pg17`, `alpine3.24` → ``). */
function variantWithoutOsTokens(variant: string): string {
  return variantTokens(variant).filter((t) => !isOsReleaseToken(t)).join('-');
}

/**
 * Variante OHNE die OS-Basis (`slim-trixie` → `slim`, `pg17` → `pg17`,
 * `alpine3.24` → ``). Für OS-Basis-Vergleiche: gleiche Nicht-OS-Tokens ==
 * gleiche Linux-Distri-Familie, nur anderer Release-Slug.
 */
function variantDistro(variant: string): string {
  return variantTokens(variant)
    .filter((t) => !isOsReleaseToken(t))
    .join('-');
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
    // Hub cappt n bei 100 + lexicographic Sortierung → zuverlässiger bis-Ende-Paging
    // (typisch ≤ ~20 Seiten): projekt-heat ok, nur je einmal je Image/Tag.
    while (u && depth < 25) {
      const res = await fetch(u, token ? { headers: { Authorization: `Bearer ${token}` } } : {});
      if (res.status === 401 || res.status === 403) return { tags: null, note: 'nicht öffentlich (401/403) — übersprungen' };
      if (res.status === 404) return { tags: null, note: 'unbekannt (404) — übersprungen' };
      if (!res.ok) return { tags: null, note: `tags/list ${res.status}` };
      const j = (await res.json()) as { tags?: string[] | null };
      if (Array.isArray(j.tags)) out.push(...j.tags.filter((t) => typeof t === 'string' && t.length > 0));
      const link = res.headers.get('link');
      const nextPath = link?.includes('rel="next"') ? /<([^>]+)>/.exec(link)?.[1] ?? null : null;
      // Registry liefert relative next-URLs (`/v2/...`) — absolu Badge bauen.
      u = nextPath ? (nextPath.startsWith('http') ? nextPath : new URL(nextPath, new URL(u)).toString()) : null;
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

/** Registry-sortierbarer Semver-Wert eines Tags (Variant gestrippt). */
function coerceTag(tag: string): semver.SemVer {
  return semver.coerce(stripVariant(tag)) ?? new semver.SemVer('0.0.0');
}

/**
 * CVE-Ausnahme für Image-Bumps (v1.6.0, bewusst STRENG).
 *
 * Ein Base-Image-Bump (node:26.13 → 26.14) beweist KEINEN CVE-Fix — er kann
 * einen mitbringen, muss aber nicht (Review §6.3, Owner-Entscheidung "streng").
 * Einzige Ausnahme: Security-Werkzeuge, deren Releases per Definition
 * Vulnerability-/Signatur-Daten ausliefern — dort ist JEDES Update ein
 * Security-Release, die 3-Tage-Regen kontraproduktiv.
 *
 * Der belegbare Einzelfall-Fix (advisory.firstPatched == Zielversion) wird im
 * Paket-Scan ausgewertet, nicht hier.
 */
export function isSecurityToolBump(base: string): boolean {
  return /^aquasec\/trivy$/i.test(base) || /^anchore\/(grype|syft)$/i.test(base);
}

/**
 * Neuester gepinnter Tag im selben Major; Variant-Suffix wird token-basiert
 * gematcht (v1.6.0, siehe variantCompatible: `alpine` → `alpine3.24` ja,
 * `pg17` → `pg17-trixie` nur als OS-Basis-Drift, nie als Versions-Bump).
 * Pre-Releases aus, verglichen wird semver (strippte Variante).
 *
 * Invarianten (alle als Filter, damit `scored.at(-1)` nie blind gewinnt):
 * - Kandidat ist NIE semver-kleiner als currentTag (sonst kein Downgrade-Bump).
 * - pinned-current: nur 3-Komp-Kandidaten ("pinned never DOWN into floating").
 * - Variante: exakt gleiche Tokens zuerst; erst wenn kein semver-neuerer
 *   gleicher-Varianten-Tag existiert, dürfen OS-Basis-Varianten (genau ein
 *   zusätzlicher OS-Release-Token) als "newest"-Info dienen.
 */
export function newestSameMajorTag(currentTag: string, tags: string[]): string | null {
  const cur = tagSemantics(currentTag);
  if (!cur.valid || cur.major === null) return null;
  const curVer = coerceTag(currentTag);
  const cand = tags
    .map((t) => ({ tag: t, sem: tagSemantics(t), ver: coerceTag(t) }))
    .filter(
      (c) =>
        c.sem.valid && c.sem.major === cur.major && !c.sem.prerelease && !semver.lt(c.ver, curVer) &&
        (cur.pinned ? c.sem.pinned : true)
    );
  if (cand.length === 0) return null;

  const newestOf = (pool: typeof cand): string | null =>
    [...pool].sort((a, b) => semver.compare(a.ver, b.ver)).at(-1)?.tag ?? null;

  // 1) exakt gleiche Variant-Tokens (± Groß-/Kleinschreibung)
  const sameVariant = newestOf(cand.filter((c) => c.sem.variant === cur.variant));
  if (sameVariant !== null && (!cur.variant || strictlyNewer(currentTag, sameVariant))) return sameVariant;
  // 2) sonst OS-Basis-Kandidaten (gleiche Nicht-OS-Tokens, genau 1 Zusatz-Token):
  //    nur INFO ("andere Basis verfügbar") — strictlyNewer ist dort i. d. R. false.
  if (cur.variant) {
    const osDrift = cand.filter(
      (c) =>
        c.sem.variant !== cur.variant &&
        variantCompatible(cur.variant, c.sem.variant) &&
        variantWithoutOsTokens(c.sem.variant) === variantWithoutOsTokens(cur.variant)
    );
    const drift = newestOf(osDrift);
    if (drift !== null) return drift;
  }
  return sameVariant;
}

/**
 * Variant-Drift (v1.6.0): neuester Registry-Tag im selben Major, der semver-
 * GLEICH dem current-Tag ist, aber eine andere Variante (andere OS-Basis,
 * z. B. `pg17` → `pg17-trixie`, `slim` → `slim-trixie`) hat. Report-only —
 * kein Bump, kein PR. null, wenn kein solcher Tag existiert.
 */
export function variantDriftTag(currentTag: string, tags: string[]): string | null {
  const cur = tagSemantics(currentTag);
  if (!cur.valid || cur.prerelease || cur.major === null) return null;
  const curVer = coerceTag(currentTag);
  const drift = tags
    .map((t) => ({ tag: t, sem: tagSemantics(t), ver: coerceTag(t) }))
    .filter(
      (c) =>
        c.sem.valid && !c.sem.prerelease && c.sem.major === cur.major &&
        c.tag !== currentTag && c.sem.variant !== cur.variant &&
        // Der variantenlose Tag (z. B. `26.13.0`) ist KEIN Drift — das ist
        // derselbe Stand ohne OS-Suffix, kein alternatives Base-Image.
        c.sem.variant !== '' &&
        c.sem.comps === cur.comps && semver.eq(c.ver, curVer)
    )
    .sort((a, b) => {
      // Stabil & relevant: gleiche Linux-Distri-Familie zuerst
      // (pg17 → pg17-trixie, slim → slim-trixie), dann alphabetisch.
      const da = Number(variantDistro(a.sem.variant) === variantDistro(cur.variant));
      const db = Number(variantDistro(b.sem.variant) === variantDistro(cur.variant));
      return db - da || a.tag.localeCompare(b.tag);
    });
  return drift[0]?.tag ?? null;
}

/**
 * Streng neuer (v1.6.0, Invariante dokumentiert): verglichen wird NUR der
 * Zahlen-Teil (Variant gestrippt). Ergebnis ist damit zwangsläufig `false`
 * bei semver-Gleichheit, auch wenn sich die Varianten unterscheiden — ein
 * Variant-/OS-Wechsel (`pg17` → `pg17-trixie`, `slim` → `slim-trixie`) ist
 * KEIN Update-Kandidat (eigene Kategorie `variantDrift`, report-only).
 */
export function strictlyNewer(currentTag: string, candidateTag: string): boolean {
  const a = semver.coerce(stripVariant(currentTag));
  const b = semver.coerce(stripVariant(candidateTag));
  if (!a || !b) return false;
  return semver.gt(b, a);
}

/**
 * Floating→Pin-Bump-Ziel: neuester EXAKTER (3-Komp, non-prerelease) Tag im
 * selben Major. Variant des current-Tags wird token-basiert gematcht
 * (`alpine` → alpine3.x, `slim` → `slim-trixie`), sonst Fallback auf alle
 * 3-Komp-Tags — oder variant-frei, wenn current variant-los war. null, wenn
 * kein Pinned-Kandidat.
 */
export function newestExactTag(currentTag: string, tags: string[]): string | null {
  const cur = tagSemantics(currentTag);
  if (!cur.valid || cur.major === null || cur.prerelease) return null;
  const cand = tags
    .map((t) => ({ tag: t, sem: tagSemantics(t), ver: coerceTag(t) }))
    .filter((c) => c.sem.valid && c.sem.pinned && !c.sem.prerelease && c.sem.major === cur.major);
  if (cand.length === 0) return null;
  const sameVariant = cur.variant
    ? cand.filter((c) => variantCompatible(cur.variant, c.sem.variant))
    : cand.filter((c) => c.sem.variant === '');
  const pool = sameVariant.length > 0 ? sameVariant : cand;
  const scored = [...pool].sort((a, b) => semver.compare(a.ver, b.ver));
  return scored.at(-1)?.tag ?? null;
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
  // trivy image sequential (DB-Download-LockContention vermeiden); frisch
  // installierte Container-DB ist gecacht, typisch ≤ 5 Images je Repo.
  for (const f of findings) {
    const safe = f.image.replace(/[^A-Za-z0-9._\-/@:]/g, '_');
    if (f.note) continue; // latest/tagless/digest/invalid → kein Scan, Note bleibt stehen
    const outPath = path.join(scanTmp, `${repo.name}.img-${safe.replace(/[/:@]/g, '_')}.trivy.json`);
    const vulns = await trivyImageScan(f.image, outPath);
    f.vulns.high = vulns.high;
    f.vulns.critical = vulns.critical;
    if (vulns.error) {
      f.note = vulns.error;
      continue;
    }
    if (f.digestPinned) continue; // Freshness bewusst übersprungen (digest satt)
    const { tags, note } = await fetchRegistryTags(f.base, f.registry);
    if (!tags) {
      f.note = note ?? 'keine Tag-Liste';
      continue;
    }
    const newest = newestSameMajorTag(f.current, tags);
    const exact = newestExactTag(f.current, tags);
    f.newestSameMajor = newest ?? exact;
    f.exactPin = exact;
    // Variant-Drift (v1.6.0): semver-gleicher Tag mit anderer OS-/Variant-Basis
    // (z. B. pg17 → pg17-trixie) → report-only Marker, KEIN Bump, KEIN PR.
    f.variantDrift = variantDriftTag(f.current, tags);
    if (f.pinned && newest && strictlyNewer(f.current, newest)) {
      f.updateAvailable = true;
      // Soaking (v1.6.0): PR nur, wenn der Ziel-Tag die Mindest-Reife hat.
      // Ohne belegbaren CVE-Fix gilt der Streit-Wert UPDATE_MIN_AGE_DAYS.
      const cveFix = isSecurityToolBump(f.base);
      const age = await imagePublishedAt(f.base, newest, f.registry);
      const el = updateEligibility({
        variantChange: false,
        publishedAt: age.publishedAt,
        cveFix,
      });
      f.newestPublishedAt = age.publishedAt;
      f.eligibility = el.eligibility;
      f.eligibilityLabel = el.label;
      f.ageDays = el.ageDays;
      if (el.eligibility === 'too-young') continue; // Info ja, PR nein
      for (const file of f.sourceFiles) {
        const existing = bumpPlan.find((p) => p.file === file);
        const bump = { from: f.image, to: `${f.base}:${newest}` };
        if (existing) existing.bumps.push(bump);
        else bumpPlan.push({ file, bumps: [bump] });
      }
      continue;
    }
    if (f.floating && exact) {
      // v1.5.0 Enforcement: floating Major-Tag → exakten Tag pinnen (PR), auch
      // wennś frisch ist (exact-Pin-Pflicht). updateAvailable = zusätzlich
      // neuer als die Auflösung hinter dem floating Tag.
      if (strictlyNewer(f.current, exact)) f.updateAvailable = true;
      // Soaking gilt auch für den Pin-Bump, aber ohne CVE-Bezug (nur Info-Zeile
      // bei zu jung): ein Floating-Tag ist kein Fix, sondern Hygiene.
      const age = await imagePublishedAt(f.base, exact, f.registry);
      const el = updateEligibility({
        variantChange: false,
        publishedAt: age.publishedAt,
        cveFix: false,
      });
      f.newestPublishedAt = age.publishedAt;
      f.eligibility = el.eligibility;
      f.eligibilityLabel = el.label;
      f.ageDays = el.ageDays;
      if (el.eligibility === 'too-young') continue;
      for (const file of f.sourceFiles) {
        const existing = bumpPlan.find((p) => p.file === file);
        const bump = { from: f.image, to: `${f.base}:${exact}` };
        if (existing) existing.bumps.push(bump);
        else bumpPlan.push({ file, bumps: [bump] });
      }
    }
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
    byKey.set(ref, mkFinding(ref, base, 'latest', sem, rel, false, 'kein Tag (latest implizit) — report-only: kein Pin'));
    return;
  }
  if (tag === 'latest') {
    byKey.set(ref, mkFinding(ref, base, tag, sem, rel, false, 'latest — report-only (Major-Sprung-Risiko), kein Pin-PR'));
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
    exactPin: null,
    updateAvailable: false,
    variantDrift: null,
    note,
  };
}

// ——————————————————————————————— Image-Fix-PR ———————————————————————————————

function imageBranchName(date = new Date()): string {
  return `cve-audit/images-${date.toISOString().slice(0, 10)}`;
}

/**
 * Fix-PR für gepinnte, veraltete Image-Tags (immer-PR-Policy, ohne LLM).
 * `state` = geteiltes PR-Scann-State-Objekt (KEIN eigenes load/save — sonst
 * überschreibt runScan-EndsaveState den Eintrag: lost update).
 */
export async function createImagePr(repo: RepoInfo, bumpPlan: ImageBumpPlan[], state: State): Promise<FixResult> {
  if (bumpPlan.length === 0) return { status: 'skipped', note: 'keine Image-Bump-Kandidaten' };
  // HARD GUARD: archivierte Repos bekommen nie Fix-PRs.
  if (repo.archived) return { status: 'skipped', note: 'Repo archived — kein Image-PR (hard guard)' };

  const branch = imageBranchName();
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
            message: `chore(cve-audit): pin docker image tags to exact versions [skip ci]`,
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
          title: 'chore(cve-audit): pin docker image tags to exact versions',
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

/**
 * Literal-Swap `from` → `to` mit Ref-Grenzen auf BEIDEN Seiten (v1.5.3, P1-Fix).
 * - links: kein Zeichen, das Teil eines Ref-Tokens sein könnte (sonst matcht
 *   `node:24` mitten in `my-node:24` oder `node:240`).
 * - rechts: kein Anhängsel aus Zahlen/Punkten UND kein `-`/`+`-Suffix — sonst
 *   wird `node:24` in `node:24-alpine` zu `node:24.12.0-alpine-alpine`.
 * Erlaubt bleiben: `@<digest>`, Whitespace, `AS`/` as `, Zeilenende, `/` (Pfad).
 */
export function replaceTag(content: string, from: string, to: string): string {
  const esc = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const re = new RegExp(`(?<![A-Za-z0-9._/-])${esc(from)}(?![A-Za-z0-9._-])`, 'g');
  return content.replace(re, to);
}

function imagePrBody(repo: string, bumps: string[]): string {
  return [
    'Automatically generated by the `audit-scanner` (image pin enforcement run).',
    '',
    '### Docker image tags pinned to exact versions',
    '',
    ...bumps.map((b) => `- ${b}`),
    '',
    '### Policy note',
    'Per repo policy ("Dependency-Pinning & Update-Pflicht"): **no floating',
    'versions**. Exactly pinned tags are bumped to the newest same-major exact',
    'tag; floating major tags (e.g. `node:24-alpine`) are pinned to the newest',
    'exact tag of the same major (with OS-variant fallback). `latest`/tagless',
    'refs are report-only (`latest` can introduce a major jump) — pin those',
    'manually first.',
    '',
    '### Checks before merge',
    'Rebuild the image after merging and verify the app starts healthy.',
    'CI must be green before merging. No auto-merge — human approval required.',
  ].join('\n');
}

// Upstream-Release-Check (v1.6.3) — Ergänzung zur Registry-Freshness.
// Belegt am 2026-11-07 (Owner-Fund, private-ai-interface):
//
//   Image `mcr.microsoft.com/playwright/mcp:v0.0.83` → Report sagte "aktuell".
//   GitHub-Release `microsoft/playwright-mcp` = v0.0.84 (published 2026-10-31),
//   aber MCR `tags/list` endet bei v0.0.83 und `manifests/v0.0.84` → 404:
//   Das Release existiert, das Image wurde nie gepusht.
//
// Lehre: **Registry-Tags sind NICHT die Release-Wahrheit.** Der Image-Freshness-
// Check kann nur sagen "kein neuerer Tag auf DIESER Registry" — nicht "du bist
// aktuell". Dieser Check fragt deshalb zusätzlich die GitHub-Releases des
// Upstream-Projekts ab und prüft per Manifest-HEAD, ob der Release-Tag auf der
// Registry überhaupt publiziert wurde.
//
// v1.7.1 (belegt 2026-11-07): Registry-Tags tragen ihre EIGENE Präfix-Konvention.
// `aquasecurity/trivy` released `v0.76.2`, Docker Hub taggt `aquasec/trivy` aber
// als `0.76.2` — der verbatim übergebene Release-Tag 404-te und der Report
// behauptete fälschlich "kein Image publiziert". MCR `playwright/mcp` taggt
// dagegen MIT `v` — dort passte es nur zufällig. Der Manifest-Lookup probiert
// deshalb beide Varianten (registryTagCandidates) und behauptet "kein Image"
// erst, wenn ALLE belastbar 404 sind.
//
// Alles reine HTTP-Calls (GitHub über ghJson, Manifest über publish-dates);
// kein Docker-Daemon. Fehler werfen NIE: `latestRelease: null` + `note`.

import semver from 'semver';

import { log } from './config.js';
import { ghJson } from './github.js';
import { imageDigest, type DigestRegistry } from './publish-dates.js';

const HTTP_TIMEOUT_MS = 10_000;

/** Registry-Kennung (identisch zu image-scan.Registry, hier lokal entkoppelt). */
export type ReleaseRegistry = DigestRegistry;

/** Ein GitHub-Release, so wie es der Check braucht (nur die relevanten Felder). */
export interface GhRelease {
  tag_name?: string;
  name?: string | null;
  draft?: boolean;
  prerelease?: boolean;
}

/** Ergebnis des Upstream-Release-Checks. */
export interface UpstreamReleaseResult {
  /** Neuestes nicht-Pre-Release-Release-Tag (z. B. "v0.0.84"), null = unbekannt. */
  latestRelease: string | null;
  /** Release ist semver-neuer als der gepinnte Tag. */
  newerThanTag: boolean;
  /** Release neuer als Tag, aber Tag fehlt auf der Registry (kein Image). */
  releaseWithoutImage?: boolean;
  /** Klartext-Hinweis für Report/Telegram (z. B. "kein Image auf MCR (404)"). */
  note?: string;
}

/**
 * Explizite, GEPFLEGTE Mapping-Tabelle Image-Name → GitHub-Repo (owner/name)
 * für Fälle, wo der Image-Name NICHT den Upstream-Owner trägt.
 *
 * - `playwright/mcp` (MCR) → microsoft/playwright-mcp: Beleg-Fall v0.0.84.
 * - `aquasec/trivy` → aquasecurity/trivy (Image-Owner ≠ Repo-Owner).
 * - Docker-Official-Images (`postgres`, `node`, `python`, `golang`, `alpine`,
 *   `library/*`) → `null`: kein sinnvolles GH-Release (Releases gibt es, aber
 *   sie korrespondieren nicht 1:1 zu den Registry-Tags der Offiziellen Images)
 *   — lieber keine Aussage als eine falsche.
 *
 * Neue Einträge nur mit belegtem Upstream-Repo ergänzen (Key = Image-Name
 * ohne Tag/Registry-Prefix, lowercase).
 */
export const UPSTREAM_REPOS: ReadonlyMap<string, string | null> = new Map<string, string | null>([
  ['playwright/mcp', 'microsoft/playwright-mcp'],
  ['aquasec/trivy', 'aquasecurity/trivy'],
  ['anchore/grype', 'anchore/grype'],
  ['anchore/syft', 'anchore/syft'],
  ['pgvector/pgvector', 'pgvector/pgvector'],
  ['searxng/searxng', 'searxng/searxng'],
  // Docker-Official-Images: bewusst KEIN Upstream-Repo (siehe Doc-Kommentar).
  ['postgres', null],
  ['node', null],
  ['python', null],
  ['golang', null],
  ['alpine', null],
]);

/** Cache pro Prozess: `base` → Ergebnis (Releases/Tags ändern sich binnen eines Laufs nicht). */
const cache = new Map<string, UpstreamReleaseResult>();

/**
 * Upstream-Repo aus dem Image-Namen ermitteln.
 *
 * Reihenfolge: (1) exakte Mapping-Tabelle, (2) `library/*` → kein Repo,
 * (3) Prefix-Heuristik (Image-Name sieht selbst wie `owner/name` aus → als
 * GH-Repo versuchen; single-segment bleibt unknown, weil ein Docker-Hub-Name
 * ohne Owner KEINEN Owner liefert).
 */
export function upstreamRepoFor(base: string): string | null {
  const b = base.trim().toLowerCase().replace(/^docker\.io\//, '');
  if (UPSTREAM_REPOS.has(b)) return UPSTREAM_REPOS.get(b) ?? null;
  if (b.startsWith('library/')) return null;
  if (!b.includes('/')) return null;
  // Heuristik: `owner/name` (genau zwei Segmente) → owner/name ist plausibel
  // das GH-Repo. Mehr Segmente (z. B. `microsoft/dotnet/runtime-deps`) sind
  // MCR-Pfade, keine GH-Repos → unknown (kein Raten).
  const parts = b.split('/');
  if (parts.length !== 2 || !parts[0] || !parts[1]) return null;
  for (const known of UPSTREAM_REPOS.values()) {
    if (known && known.toLowerCase() === b) return known;
  }
  return b;
}

/** Ersten nicht-Pre-Release-nicht-Draft-Release-Tag aus einer Release-Liste ziehen. */
export function latestStableRelease(releases: GhRelease[]): string | null {
  for (const r of releases) {
    if (r.draft === true || r.prerelease === true) continue;
    const tag = (r.tag_name ?? '').trim();
    if (tag) return tag;
  }
  return null;
}

/**
 * Semver-Vergleich `currentTag` vs `releaseTag`. Beide dürfen `v`-Präfix haben;
 * Build-Meta (`2026.11.1-9ded3bec1`) wird per `semver.coerce` auf den
 * Zahlen-Teil reduziert. Nicht vergleichbar (kein coerce möglich) → null,
 * NICHT false — der Aufrufer setzt dann `newerThanTag: false` + note.
 */
export function releaseIsNewer(currentTag: string, releaseTag: string): boolean | null {
  const a = semver.coerce(currentTag.trim());
  const b = semver.coerce(releaseTag.trim());
  if (!a || !b) return null;
  return semver.gt(b, a);
}

/** Netzwerk-Abhängigkeiten des Checks — im Selbsttest injizierbar (offline). */
export interface ReleaseCheckDeps {
  /** GitHub-Releases eines Repos (GET /repos/<repo>/releases?per_page=10). */
  fetchReleases?: (repo: string) => Promise<GhRelease[]>;
  /**
   * Existiert `<tag>` auf der Registry? true/false bei belastbarer Antwort,
   * null wenn unbekannt (other-Registry, Fehler) → keine Manifest-Aussage.
   */
  manifestExists?: (base: string, tag: string, registry: ReleaseRegistry) => Promise<boolean | null>;
}

/**
 * Registry-Tag-Kandidaten für einen GitHub-Release-Tag (v1.7.1, belegt 2026-11-07).
 *
 * **Registry-Tags tragen ihre EIGENE Präfix-Konvention — nicht die des Git-Tags.**
 * Der Check übergab den Release-Tag bisher verbatim an den Manifest-Lookup:
 * `aquasecurity/trivy` released `v0.76.2`, aber Docker Hub taggt `aquasec/trivy`
 * als `0.76.2` → `manifests/v0.76.2` = 404 → Report fälschlich
 * "kein Image publiziert", obwohl das Image existiert. Umgekehrt taggt MCR
 * `playwright/mcp` als `v0.0.83` (dort passte es zufällig).
 *
 * Reihenfolge: (1) Tag verbatim, (2) Präfix-Flip (`v0.76.2` → `0.76.2`,
 * `0.76.2` → `v0.76.2`). Beide Kandidaten werden geprüft, BEVOR "kein Image"
 * behauptet wird — sonst entsteht der False-Positive erneut in Gegenrichtung.
 * Leere/Einzel-`v`-Tags liefern nur den Original-Kandidaten.
 */
export function registryTagCandidates(releaseTag: string): string[] {
  const tag = releaseTag.trim();
  if (!tag) return [];
  const flipped = /^v\d/i.test(tag) ? tag.slice(1) : /^\d/.test(tag) ? `v${tag}` : null;
  return flipped ? [tag, flipped] : [tag];
}

/** Registry-Label für Klartext-Notes. */
function registryLabel(registry: ReleaseRegistry): string {
  return registry === 'docker-hub' ? 'Docker Hub' : registry === 'ghcr' ? 'GHCR' : registry === 'mcr' ? 'MCR' : 'Registry';
}

async function defaultFetchReleases(repo: string): Promise<GhRelease[]> {
  const res = await ghJson<GhRelease[]>(`/repos/${repo}/releases?per_page=10`);
  return Array.isArray(res) ? res : [];
}

/**
 * Manifest-Existenz per Digest-Lookup: `digest !== null` → Tag publiziert;
 * 404-Note → nicht publiziert; alles andere (Token-/Netzwerkfehler,
 * `other`-Registry) → null (unbekannt, keine falsche Aussage).
 */
async function defaultManifestExists(
  base: string,
  tag: string,
  registry: ReleaseRegistry
): Promise<boolean | null> {
  const d = await imageDigest(base, tag, registry);
  if (d.digest !== null) return true;
  const note = d.note ?? '';
  if (/404|Manifest unbekannt/.test(note)) return false;
  return null;
}

/**
 * Registry-Probe über ALLE sinnvollen Tag-Kandidaten (v1.7.1).
 *
 * - `exists: true` → erster Kandidat, der ein Manifest hat (`matchedTag`).
 * - `exists: false` → ALLE Kandidaten waren belastbar 404. Nur dann darf der
 *   Report "kein Image" behaupten.
 * - `exists: null` → mindestens ein Kandidat war nicht belastbar (Netz-/Auth-
 *   Fehler) und keiner hat getroffen → unbekannt, keine falsche Aussage.
 */
async function probeRegistryTag(
  manifestExists: (base: string, tag: string, registry: ReleaseRegistry) => Promise<boolean | null>,
  base: string,
  releaseTag: string,
  registry: ReleaseRegistry
): Promise<{ exists: boolean | null; matchedTag?: string }> {
  const candidates = registryTagCandidates(releaseTag);
  if (candidates.length === 0) return { exists: null };
  let unknown = false;
  for (const tag of candidates) {
    const res = await manifestExists(base, tag, registry);
    if (res === true) return { exists: true, matchedTag: tag };
    if (res === null) unknown = true;
  }
  return { exists: unknown ? null : false };
}

/**
 * Upstream-Release-Check für ein Image-Ref.
 *
 * Aussagen:
 * - kein Upstream-Repo bekannt → `latestRelease: null`, `newerThanTag: false`,
 *   note "kein Upstream-Repo bekannt" (kein Fehler, keine falsche Aussage).
 * - Release nicht neuer (oder nicht vergleichbar) → `newerThanTag: false`.
 * - Release neuer + Tag FEHLT auf der Registry → `newerThanTag: true` +
 *   `releaseWithoutImage: true` + note "v0.0.84 released, aber kein Image auf
 *   MCR (404)" — der Registry-Freshness-Check sagt hier NICHT "aktuell".
 */
export async function upstreamReleaseCheck(
  opts: { base: string; currentTag: string; registry: ReleaseRegistry },
  deps: ReleaseCheckDeps = {}
): Promise<UpstreamReleaseResult> {
  const key = `${opts.registry}|${opts.base}|${opts.currentTag}`;
  const hit = cache.get(key);
  if (hit) return hit;

  const repo = upstreamRepoFor(opts.base);
  if (!repo) {
    const out: UpstreamReleaseResult = {
      latestRelease: null,
      newerThanTag: false,
      note: 'kein Upstream-Repo bekannt',
    };
    cache.set(key, out);
    return out;
  }

  let out: UpstreamReleaseResult;
  try {
    const releases = await (deps.fetchReleases ?? defaultFetchReleases)(repo);
    const latestRelease = latestStableRelease(releases);
    if (!latestRelease) {
      out = { latestRelease: null, newerThanTag: false, note: `${repo}: kein stabiles Release gefunden` };
    } else {
      const newer = releaseIsNewer(opts.currentTag, latestRelease);
      if (newer === null) {
        out = {
          latestRelease,
          newerThanTag: false,
          note: `Versionen nicht semver-vergleichbar (${opts.currentTag} vs ${latestRelease})`,
        };
      } else if (newer === false && !/^v?\d/.test(opts.currentTag.trim())) {
        // current-Tag gar nicht numerisch (z. B. `main-20261101`) → keine Aussage.
        out = {
          latestRelease,
          newerThanTag: false,
          note: `Tag ${opts.currentTag} nicht semver-vergleichbar (${latestRelease})`,
        };
      } else if (!newer) {
        out = { latestRelease, newerThanTag: false };
      } else {
        const label = registryLabel(opts.registry);
        if (opts.registry === 'other') {
          // Kein Manifest-Support → nur die Release-Info, keine Image-Aussage.
          out = {
            latestRelease,
            newerThanTag: true,
            note: `${latestRelease} released (${repo}) — Registry ohne Manifest-Check`,
          };
        } else {
          const probe = await probeRegistryTag(
            deps.manifestExists ?? defaultManifestExists,
            opts.base,
            latestRelease,
            opts.registry
          );
          if (probe.exists === true) {
            out = { latestRelease, newerThanTag: true };
            if (probe.matchedTag && probe.matchedTag !== latestRelease.trim()) {
              // Präfix-Flip hat gegriffen: den echten Registry-Tag nennen, damit
              // der Mensch den passenden Pin direkt sieht.
              out.note = `${latestRelease} released → Registry-Tag ${probe.matchedTag}`;
            }
          } else if (probe.exists === false) {
            out = {
              latestRelease,
              newerThanTag: true,
              releaseWithoutImage: true,
              note: `${latestRelease} released, aber kein Image auf ${label} (404; geprüft: ${registryTagCandidates(latestRelease).join(', ')})`,
            };
          } else {
            out = {
              latestRelease,
              newerThanTag: true,
              note: `${latestRelease} released, Image-Status auf ${label} unbekannt`,
            };
          }
        }
      }
    }
  } catch (err) {
    // Kein Abbruch: der Check ist reine Zusatzinfo zum Registry-Freshness.
    const msg = err instanceof Error ? err.message.slice(0, 120) : '?';
    log(`Upstream-Release-Check ${opts.base}: ${msg}`);
    out = { latestRelease: null, newerThanTag: false, note: `Release-Check fehlgeschlagen (${repo})` };
  }
  cache.set(key, out);
  return out;
}

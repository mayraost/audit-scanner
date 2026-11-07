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
          const exists = await (deps.manifestExists ?? defaultManifestExists)(
            opts.base,
            latestRelease,
            opts.registry
          );
          if (exists === true) {
            out = { latestRelease, newerThanTag: true };
          } else if (exists === false) {
            out = {
              latestRelease,
              newerThanTag: true,
              releaseWithoutImage: true,
              note: `${latestRelease} released, aber kein Image auf ${label} (404)`,
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

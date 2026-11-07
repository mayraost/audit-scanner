// Publish-Datum-Lookup (v1.6.0) — Zulieferung für soaking.ts.
// Belegt im Strategie-Review (docs/update-vuln-strategy-review.md §6.1, §10):
//
// | Ökosystem | Quelle                                          | Feld                                   |
// |-----------|-------------------------------------------------|----------------------------------------|
// | npm       | GET registry.npmjs.org/<pkg>                    | time[<version>]                        |
// | Docker    | GET hub.docker.com/v2/repositories/<repo>/tags/<tag> | tag_last_pushed               |
// | GHCR      | GET ghcr.io/v2/<repo>/manifests/<tag> (OCI)     | annotations["org.opencontainers.image.created"] |
// | PyPI      | GET pypi.org/pypi/<pkg>/json                    | releases[<ver>][0].upload_time_iso_8601 |
//
// Kein Docker-Daemon nötig, alles reine HTTP-Calls. Fehlt das Datum (404,
// private Registry, fehlende OCI-Annotation) → null → soaking.ts fail-open.

import { log } from './config.js';

const HTTP_TIMEOUT_MS = 10_000;

/** Ergebnis eines Datum-Lookups; `note` erklärt ein fehlendes Datum. */
export interface PublishDateResult {
  publishedAt: string | null;
  note?: string;
}

/** Cache pro Prozess: `<key>|<version>` → Ergebnis (Datum ist unveränderlich). */
const cache = new Map<string, PublishDateResult>();

async function getJson(url: string, headers: Record<string, string> = {}): Promise<unknown | null> {
  try {
    const res = await fetch(url, { headers, signal: AbortSignal.timeout(HTTP_TIMEOUT_MS) });
    if (!res.ok) return null;
    return (await res.json()) as unknown;
  } catch (err) {
    log(`Publish-Date-Lookup fehlgeschlagen (${url}): ${err instanceof Error ? err.message : '?'}`);
    return null;
  }
}

/**
 * npm: `time[<version>]` aus dem Packument. Das Packument kann groß sein
 * (z. B. typescript ~10 MB), wird aber ohnehin schon von pinning.ts geladen —
 * hier bewusst getrennt (nur bei Bedarf).
 */
async function npmPublishedAt(pkg: string, version: string): Promise<PublishDateResult> {
  const json = (await getJson(`https://registry.npmjs.org/${pkg}`)) as
    | { time?: Record<string, string> }
    | null;
  const iso = json?.time?.[version];
  return iso ? { publishedAt: iso } : { publishedAt: null, note: 'kein time[]-Eintrag' };
}

/** Docker Hub: `tag_last_pushed` (nicht `last_updated` = Pull-Aktivität). */
async function dockerHubPublishedAt(repo: string, tag: string): Promise<PublishDateResult> {
  // Official-Images liegen unter library/<name>.
  const full = repo.includes('/') ? repo : `library/${repo}`;
  const json = (await getJson(
    `https://hub.docker.com/v2/repositories/${full}/tags/${encodeURIComponent(tag)}`
  )) as { tag_last_pushed?: string; last_updated?: string } | null;
  const iso = json?.tag_last_pushed ?? null;
  return iso ? { publishedAt: iso } : { publishedAt: null, note: 'Tag nicht in Docker Hub' };
}

/**
 * GHCR: Publish-Datum steckt in der OCI-Annotation `org.opencontainers.image.created`
 * des Manifest(-Index). `tags/list` liefert KEIN Datum → eigener Manifest-Call.
 */
async function ghcrPublishedAt(repo: string, tag: string): Promise<PublishDateResult> {
  try {
    const tokenRes = await fetch(`https://ghcr.io/token?scope=repository:${repo}:pull`, {
      signal: AbortSignal.timeout(HTTP_TIMEOUT_MS),
    });
    if (!tokenRes.ok) return { publishedAt: null, note: `GHCR-Token ${tokenRes.status}` };
    const { token } = (await tokenRes.json()) as { token?: string };
    if (!token) return { publishedAt: null, note: 'GHCR-Token leer' };
    const res = await fetch(`https://ghcr.io/v2/${repo}/manifests/${tag}`, {
      headers: {
        Authorization: `Bearer ${token}`,
        Accept:
          'application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json',
      },
      signal: AbortSignal.timeout(HTTP_TIMEOUT_MS),
    });
    if (!res.ok) return { publishedAt: null, note: `GHCR-Manifest ${res.status}` };
    const m = (await res.json()) as {
      annotations?: Record<string, string>;
      manifests?: Array<{ annotations?: Record<string, string> }>;
    };
    const iso =
      m.annotations?.['org.opencontainers.image.created'] ??
      m.manifests?.[0]?.annotations?.['org.opencontainers.image.created'] ??
      null;
    return iso ? { publishedAt: iso } : { publishedAt: null, note: 'keine OCI-created-Annotation' };
  } catch (err) {
    return {
      publishedAt: null,
      note: `GHCR-Fehler: ${err instanceof Error ? err.message.slice(0, 80) : '?'}`,
    };
  }
}

/** PyPI: `releases[<version>][0].upload_time_iso_8601` (yanked empfehlen: skip). */
async function pypiPublishedAt(pkg: string, version: string): Promise<PublishDateResult> {
  const json = (await getJson(`https://pypi.org/pypi/${pkg}/json`)) as
    | { releases?: Record<string, Array<{ upload_time_iso_8601?: string; yanked?: boolean }>> }
    | null;
  const files = json?.releases?.[version];
  const iso = files?.[0]?.upload_time_iso_8601 ?? null;
  return iso ? { publishedAt: iso } : { publishedAt: null, note: 'Version nicht auf PyPI' };
}

/**
 * Einheitlicher Einstieg für den Image-Scan. `registry` entscheidet die Quelle
 * (image-scan.splitRef liefert 'docker-hub' | 'ghcr' | 'other').
 */
export async function imagePublishedAt(
  base: string,
  tag: string,
  registry: 'docker-hub' | 'ghcr' | 'other'
): Promise<PublishDateResult> {
  const key = `image|${registry}|${base}|${tag}`;
  const hit = cache.get(key);
  if (hit) return hit;
  let out: PublishDateResult;
  if (registry === 'docker-hub') out = await dockerHubPublishedAt(base, tag);
  else if (registry === 'ghcr') out = await ghcrPublishedAt(base, tag);
  else out = { publishedAt: null, note: 'Registry ohne Publish-Datum (fail-open)' };
  cache.set(key, out);
  return out;
}

/** Einheitlicher Einstieg für den npm-Pinning-Scan. */
export async function npmVersionPublishedAt(pkg: string, version: string): Promise<PublishDateResult> {
  const key = `npm|${pkg}|${version}`;
  const hit = cache.get(key);
  if (hit) return hit;
  const out = await npmPublishedAt(pkg, version);
  cache.set(key, out);
  return out;
}

/** PyPI-Variante (für künftige pip-Scans; heute noch nicht im Pinning-Scan). */
export async function pypiVersionPublishedAt(pkg: string, version: string): Promise<PublishDateResult> {
  const key = `pypi|${pkg}|${version}`;
  const hit = cache.get(key);
  if (hit) return hit;
  const out = await pypiPublishedAt(pkg, version);
  cache.set(key, out);
  return out;
}

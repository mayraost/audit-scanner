// GitHub Security Advisories (/advisories) — Spec §4:
// - `affects=pkg@<concrete-version>` (keine Range-Queries → Match in eigenem Code)
// - severity LOCALL filtern (high/critical), weil `severity=high,critical` → 422
// - semver-Match gegen vulnerable_version_range (komma-separierte Comparators)
// - first_patched_version.identifier als Fix-Ziel
// Hinweis: /advisories liefert pro Treffer das volle Objekt inklusive
// vulnerabilities[] — kein zweiter Call je Advisory nötig.

import { ghPaginate } from './github.js';
import semver from 'semver';
import { log } from './config.js';

export interface AdvisoryHit {
  ghsa: string;
  severity: string; // high | critical (nach Filter)
  summary: string;
  range: string; // vulnerable_version_range
  firstPatched: string | null;
}

interface RawAdvisory {
  ghsa_id: string;
  severity: string;
  summary: string;
  vulnerabilities: Array<{
    package: { name: string; ecosystem: string };
    vulnerable_version_range: string;
    first_patched_version: { identifier: string } | null;
  }>;
  references?: Array<{ url: string }>;
}

/** Trivy/Ökosystem → GitHub-Advisory-Ecosystem. */
export const GH_ECOSYSTEM: Record<string, string> = {
  npm: 'npm',
  pnpm: 'npm',
  yarn: 'npm',
  pip: 'pip',
  go: 'go',
  cargo: 'crates.io',
};

const cache = new Map<string, AdvisoryHit[]>();

/**
 * Advisories für pkg@version laden (paginiert), lokal auf high/critical + Name-
 * match + Semver-Range filtern. Cache pro (ecosystem, pkg, version) für Nachtlauf.
 */
export async function fetchAdvisories(
  ecosystem: string,
  pkg: string,
  version: string
): Promise<AdvisoryHit[]> {
  const ghEco = GH_ECOSYSTEM[ecosystem];
  if (!ghEco) return [];
  const key = `${ghEco}|${pkg}|${version}`;
  const hit = cache.get(key);
  if (hit) return hit;

  let raw: RawAdvisory[];
  try {
    const path = `/advisories?ecosystem=${encodeURIComponent(ghEco)}&affects=${encodeURIComponent(`${pkg}@${version}`)}`;
    raw = await ghPaginate<RawAdvisory>(path);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    log(`WARN: /advisories für ${pkg}@${version} (${ghEco}) fehlgeschlagen: ${msg}`);
    cache.set(key, []);
    return [];
  }

  const out: AdvisoryHit[] = [];
  for (const a of raw) {
    if (a.severity !== 'high' && a.severity !== 'critical') continue;
    for (const v of a.vulnerabilities ?? []) {
      if (v.package.name.toLowerCase() !== pkg.toLowerCase()) continue;
      if (ghEco === 'npm' && !semverSatisfies(version, v.vulnerable_version_range)) continue;
      out.push({
        ghsa: a.ghsa_id,
        severity: a.severity,
        summary: a.summary,
        range: v.vulnerable_version_range,
        firstPatched: v.first_patched_version?.identifier ?? null,
      });
    }
  }
  cache.set(key, out);
  return out;
}

/**
 * Semver-Match: GitHub-Range wie ">= 4.0.0, < 4.17.2" — komma-Split, alle
 * Comparatori müssen matchen. semver.satisfies je Teil.
 * Version ohne valides Semver (z. B. PEP-440 bei pip) → keine strenge Aussage
 * → nicht ausfiltern (Name-Match gelangt durch).
 */
export function semverSatisfies(version: string, range: string): boolean {
  const trimmed = range.trim();
  if (!trimmed) return true;
  if (!semver.valid(version)) return true; // kein Semver → nicht streng ausfiltern
  const parts = trimmed.split(',').map((p) => p.trim());
  for (const p of parts) {
    if (!p) continue;
    if (!semver.satisfies(version, p)) return false;
  }
  return true;
}

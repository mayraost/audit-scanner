// Soaking / Cooldown (v1.6.0): Ein Update wird erst angeboten, wenn die
// Zielversion mindestens UPDATE_MIN_AGE_DAYS Tage alt ist — Schutz gegen
// Package-Poisoning (frisch publizierte, kompromittierte Releases).
//
// EINZIGE Ausnahme: ein BELEGTER H/C-CVE-Fix (advisory.firstPatched == Kandidat
// oder ein Security-Release-Tool wie aquasec/trivy). Eine „Base-Image-Patch-
// Version = CVE-Fix"-Heuristik gibt es bewusst NICHT — ein Bump beweist keinen
// Fix (Review §6.3, Entscheidung des Owners: streng).
//
// Eigenschaften:
// - REIN deterministisch: keine IO, kein State, kein „skip"-Gedächtnis.
//   Ein Tag, der heute 2 Tage alt ist, ist morgen 3 Tage alt → eligible.
// - Fail-open bei unbekanntem Publish-Datum: nie ein Update blockieren, nur
//   weil eine Registry kein Datum liefert (dann als `unknown-age` markiert).

/** Ergebnis der Eligibility-Prüfung (Report-Status je Kandidat). */
export type Eligibility = 'eligible' | 'too-young' | 'cve-exempt' | 'rejected-variant';

export interface EligibilityResult {
  eligibility: Eligibility;
  /** Alter des Kandidaten in ganzen Tagen (null = kein/ungültiges Datum). */
  ageDays: number | null;
  /** Menschenlesbarer Report-Status (z. B. "reif (5d)", "zu jung (2d)" …). */
  label: string;
}

/**
 * SOAKING_MIN_AGE_DAYS: Minimales Alter einer Zielversion, bevor sie als Update
 * angeboten wird. Default 3 (Package-Poisoning-Fenster: Registry-Hold von
 * PyPI/npm + Zeit für Malware-Scanner). 0 = Soaking aus (Legacy-Verhalten).
 */
export function soakingMinAgeDays(): number {
  const raw = process.env.UPDATE_MIN_AGE_DAYS?.trim();
  if (raw === undefined || raw === '') return 3;
  const n = Number(raw);
  if (!Number.isFinite(n) || n < 0) return 3;
  return n;
}

/** Alter in ganzen Tagen zwischen `publishedAt` und `now` (ISO-8601). */
export function ageInDays(publishedAt: string | null, now: Date = new Date()): number | null {
  if (!publishedAt) return null;
  const t = Date.parse(publishedAt);
  if (!Number.isFinite(t)) return null;
  const ms = now.getTime() - t;
  if (ms < 0) return 0; // Uhr-Skew/Registry-Zukunft → wie "gerade eben" behandeln
  return Math.floor(ms / 86_400_000);
}

/**
 * Zentrale Entscheidungsfunktion (pur, testbar). Reihenfolge der Gates:
 * 1. Variant-Wechsel (OS-Basis) → nie ein Update (`rejected-variant`).
 * 2. Belegter H/C-CVE-Fix → sofort (`cve-exempt`), Alter irrelevant.
 * 3. Soaking aus (minAgeDays === 0) oder Datum unbekannt → `eligible`.
 * 4. Alter >= minAgeDays → `eligible`, sonst `too-young`.
 */
export function updateEligibility(opts: {
  /** true = Variant-/OS-Basis-Wechsel (siehe image-scan.variantCompatible). */
  variantChange: boolean;
  /** Publish-Datum des Kandidaten (ISO-8601) — null wenn unbekannt. */
  publishedAt: string | null;
  /** true = Kandidat fixt einen belegten HIGH/CRITICAL-CVE. */
  cveFix: boolean;
  minAgeDays?: number;
  now?: Date;
}): EligibilityResult {
  const minAge = opts.minAgeDays ?? soakingMinAgeDays();
  const age = ageInDays(opts.publishedAt, opts.now);

  if (opts.variantChange) {
    return { eligibility: 'rejected-variant', ageDays: age, label: 'Variant-Wechsel — kein Update' };
  }
  if (opts.cveFix) {
    const a = age === null ? '?' : `${age}d`;
    return { eligibility: 'cve-exempt', ageDays: age, label: `CVE-Fix, sofort (${a})` };
  }
  if (minAge === 0) {
    return { eligibility: 'eligible', ageDays: age, label: 'Soaking aus' };
  }
  if (age === null) {
    return { eligibility: 'eligible', ageDays: null, label: 'unbekanntes Alter (fail-open)' };
  }
  if (age >= minAge) {
    return { eligibility: 'eligible', ageDays: age, label: `reif (${age}d)` };
  }
  return { eligibility: 'too-young', ageDays: age, label: `zu jung (${age}d)` };
}

/** Kurzform für Report-Zellen: `eligible`-Labels ohne Präfix, sonst markiert. */
export function eligibilityBadge(r: EligibilityResult): string {
  switch (r.eligibility) {
    case 'eligible':
      return r.ageDays === null ? '✓ reif (Alter unbekannt)' : `✓ ${r.label}`;
    case 'too-young':
      return `⏳ ${r.label}`;
    case 'cve-exempt':
      return `🔴 ${r.label}`;
    case 'rejected-variant':
      return `⛔ ${r.label}`;
  }
}

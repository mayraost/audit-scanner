// Pre-Release-/Beta-Klassifikation (v1.6.0, N2): Betas werden ERKANNT und als
// Info gemeldet — aber NIE automatisch gebumpt (kein Pin-PR, kein Image-Bump).
//
// Drei Klassen (Review §5.1):
// - `channel`   — Beta/RC/Alpha (`-beta`, `-rc.1`, `-alpha`): sichtbar, prüfbar.
// - `exotic`    — Nightly/Canary/Dev/Insiders/Snapshot/Preview: dauerhaft
//                 ungewollt → Default stumm (SHOW_EXOTIC_PRERELEASES=1 zum Zeigen).
// - `stable`    — kein Pre-Release.
//
// Rauschkontrolle: Info nur, wenn der Kandidat selbst die Soaking-Reife hat
// (Soaking-Badge kommt aus soaking.ts) — sonst bleibt er "zu jung".

export type PrereleaseClass = 'stable' | 'channel' | 'exotic';

export type PrereleaseChannel = 'alpha' | 'beta' | 'rc' | 'pre' | null;

const CHANNEL_RE = /^[-.]?(alpha|beta|rc|pre)(?:[.\-]?\d)*$/i;
const EXOTIC_RE = /^[-.]?(nightly|canary|dev|insiders|snapshot|edge|preview|next|weekly|main|master)/i;

/**
 * Klassifiziert einen Versions-STRING (npm) bzw. Tag-Suffix (Docker).
 * `version` = "7.1.0-beta", "2.5.0rc1", "1.0.0-nightly.20260101", "26.13.0-alpine3.24".
 */
export function classifyPrerelease(version: string): {
  cls: PrereleaseClass;
  channel: PrereleaseChannel;
} {
  // npm-Semver: "-beta.1" | "-rc.2" | "-alpha" | "-nightly.…"
  const semverPre = /^\d+(?:\.\d+)*[-+](.+)$/.exec(version)?.[1] ?? null;
  // PEP-440: "2.5.0rc1" / "1.12.0b3"
  const pep440 = /^\d+(?:\.\d+)*(?:[-.]?)((?:a|b|rc)\d+)$/i.exec(version)?.[1] ?? null;
  const pre = semverPre ?? pep440;
  if (!pre) return { cls: 'stable', channel: null };

  if (EXOTIC_RE.test(pre)) return { cls: 'exotic', channel: null };
  const ch = CHANNEL_RE.exec(pre)?.[1]?.toLowerCase() ?? null;
  if (ch === 'a') return { cls: 'channel', channel: 'alpha' };
  if (ch === 'b') return { cls: 'channel', channel: 'beta' };
  if (ch === 'alpha' || ch === 'beta' || ch === 'rc' || ch === 'pre') {
    return { cls: 'channel', channel: ch as PrereleaseChannel };
  }
  // Unbekanntes Suffix (z. B. "-insiders.2022", "-v8", Docker-Varianten wie
  // "-alpine3.24"): KEIN Pre-Release-Kanal → stable. Wichtig, weil dieselbe
  // Funktion auch Docker-Tags klassifiziert (26.13.0-alpine3.24 ist kein RC).
  return { cls: 'stable', channel: null };
}

/** Exoten im Report/Telegram mitzählen? Default: aus. */
export function showExoticPrereleases(): boolean {
  return /^(1|true|yes)$/i.test(process.env.SHOW_EXOTIC_PRERELEASES ?? '');
}

/**
 * Beta-Hinweis (v1.6.0): NUR wenn das Paket sich BEREITS auf einem Pre-Release-
 * Kanal befindet (Owner-Entscheidung: keine „es gibt eine Beta"-Werbung für
 * stabile Pakete — das erzeugt Dauerrauschen bei payload/next/tailwind).
 *
 * Vorgeschlagen wird ausschließlich der neueste Pre-Release im SELBEN Kanal
 * (rc → rc, beta → beta), der neuer als der current-Stand ist. Channel-Wechsel
 * (rc → beta) und stable → beta sind ausdrücklich NICHT vorgesehen.
 */
export function channelCompatible(current: string, candidate: string): boolean {
  const c = classifyPrerelease(current);
  const n = classifyPrerelease(candidate);
  if (n.cls === 'stable' || n.cls === 'exotic') return false;
  if (c.cls === 'stable' || c.cls === 'exotic') return false; // KEINE Beta-Werbung
  return c.channel === n.channel;
}

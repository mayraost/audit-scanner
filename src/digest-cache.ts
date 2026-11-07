// Digest-Cache (v1.6.2): persistenter Vergleich der Manifest-Digests je
// Image-Ref — erkennt, ob ein (exakt gepinnter) Tag BEWEGLICH ist.
//
// Motivation (Prod-Report 2026-11-07, Owner-Feedback): "Rebuild" hilft bei
// exakt gepinnten Tags nur, wenn der Tag selbst auf einen neuen Digest zeigt
// (z. B. `node:24-alpine` neu gedreht, oder ein neu getaggtes Patch-Image).
// Bei einem unveränderlichen Tag bringt ein Rebuild nichts — dort muss der
// Pin auf einen neueren Tag hochgezogen werden. Der Digest-Vergleich trennt
// die zwei Fälle belegbar statt zu raten.
//
// Ablage bewusst NICHT in state.json (PR-State): die Datei liegt im
// persistenten Report-Volume (`REPORTS_DIR`) direkt daneben, eigener Inhalt.
//
//   reports/digests.json
//   { "<image-ref>": { "digest": "sha256:…", "firstSeen": "<iso>",
//                      "lastSeen": "<iso>",
//                      "changes": [ { "digest": "sha256:…", "seenAt": "<iso>" } ] } }
//
// Verhalten analog state.ts: fehlend/corrupt → leerer Cache (Log, nie Throw);
// Einträge, deren Image-Ref seit PRUNE_AFTER_DAYS nicht mehr gesehen wurde,
// werden beim Save entfernt.

import fs from 'node:fs';
import path from 'node:path';

import { REPORTS_DIR, ensureDir, log } from './config.js';

/** Verfall: Image-Ref nicht mehr im Inventar → nach 90 Tagen entfernen. */
export const PRUNE_AFTER_DAYS = 90;
const DAY_MS = 86_400_000;

/** Ein Digest-Wechsel (Historie, neuester Stand zuletzt). */
export interface DigestChange {
  digest: string;
  seenAt: string; // ISO
}

/** Cache-Eintrag je Image-Ref (`base:tag` wie im Dockerfile geschrieben). */
export interface DigestEntry {
  /** Zuletzt gesehener Manifest-Digest (`Docker-Content-Digest`). */
  digest: string;
  firstSeen: string; // ISO — erster Lookup dieser Ref
  lastSeen: string; // ISO — letzter Lauf, in dem die Ref noch im Inventar war
  changes: DigestChange[];
}

export type DigestCache = Record<string, DigestEntry>;

export function digestCachePath(): string {
  return path.join(REPORTS_DIR, 'digests.json');
}

function isDigestChange(v: unknown): v is DigestChange {
  if (typeof v !== 'object' || v === null) return false;
  const c = v as Partial<DigestChange>;
  return typeof c.digest === 'string' && c.digest.length > 0 && typeof c.seenAt === 'string';
}

function isDigestEntry(v: unknown): v is DigestEntry {
  if (typeof v !== 'object' || v === null) return false;
  const e = v as Partial<DigestEntry>;
  return (
    typeof e.digest === 'string' &&
    e.digest.length > 0 &&
    typeof e.firstSeen === 'string' &&
    typeof e.lastSeen === 'string' &&
    Array.isArray(e.changes) &&
    e.changes.every(isDigestChange)
  );
}

/**
 * Defensiver Parse: korruptes JSON oder falsche Struktur → null (= neu
 * anfangen). Einzelne kaputte Einträge werden verworfen, der Rest bleibt.
 */
export function parseDigestCache(raw: string): DigestCache | null {
  let json: unknown;
  try {
    json = JSON.parse(raw);
  } catch {
    return null;
  }
  if (typeof json !== 'object' || json === null || Array.isArray(json)) return null;
  const cache: DigestCache = {};
  for (const [ref, entry] of Object.entries(json as Record<string, unknown>)) {
    if (isDigestEntry(entry)) cache[ref] = { ...entry, changes: entry.changes.map((c) => ({ ...c })) };
  }
  return cache;
}

/** digests.json laden — fehlend/corrupt = leerer Cache (nur Log, nie Throw). */
export function loadDigestCache(file = digestCachePath()): DigestCache {
  try {
    const raw = fs.readFileSync(file, 'utf8');
    const cache = parseDigestCache(raw);
    if (!cache) {
      log('WARN: digests.json corrupt — Digest-Cache wird leer neu gestartet.');
      return {};
    }
    return cache;
  } catch {
    return {}; // fehlt → erster Lauf
  }
}

/** Eintrag für eine Image-Ref (undefined = noch nie gesehen). */
export function getDigestEntry(cache: DigestCache, imageRef: string): DigestEntry | undefined {
  return cache[imageRef];
}

/**
 * Lookup-Ergebnis: `digest` null = Lookup fehlgeschlagen (Struktur bleibt
 * unangetastet), sonst Jahrgang/Historie fortschreiben.
 */
export function putDigest(
  cache: DigestCache,
  imageRef: string,
  digest: string | null,
  now: Date = new Date()
): void {
  const iso = now.toISOString();
  const existing = cache[imageRef];
  if (digest === null) {
    // Nur lastSeen nachziehen — kein Digest-Wechsel ohne Lookup-Beleg.
    if (existing && Number.isNaN(Date.parse(existing.lastSeen)) === false) existing.lastSeen = iso;
    return;
  }
  if (!existing) {
    cache[imageRef] = { digest, firstSeen: iso, lastSeen: iso, changes: [{ digest, seenAt: iso }] };
    return;
  }
  existing.lastSeen = iso;
  if (existing.digest !== digest) {
    existing.digest = digest;
    existing.changes.push({ digest, seenAt: iso });
  }
}

/**
 * Ist der Tag beweglich? Vergleich des aktuellen Digests mit dem zuletzt
 * gesehenen Stand VOR diesem Lauf. `previousDigest` = Stand vor dem Update
 * (null beim ersten Lookup). `changed` nur bei zwei bekannten, verschiedenen
 * Digests — ein fehlgeschlagener Lookup ist nie ein Wechsel.
 */
export function digestTransition(
  previous: DigestEntry | undefined,
  current: string | null
): { digestChanged: boolean; previousDigest: string | null } {
  if (current === null) return { digestChanged: false, previousDigest: previous?.digest ?? null };
  if (!previous) return { digestChanged: false, previousDigest: null };
  return { digestChanged: previous.digest !== current, previousDigest: previous.digest };
}

/** Einträge, deren `lastSeen` älter als PRUNE_AFTER_DAYS ist, in-place entfernen. */
export function pruneDigestCache(
  cache: DigestCache,
  now: Date = new Date(),
  maxAgeDays = PRUNE_AFTER_DAYS
): number {
  let removed = 0;
  for (const [ref, entry] of Object.entries(cache)) {
    const seen = Date.parse(entry.lastSeen);
    if (Number.isNaN(seen)) {
      delete cache[ref]; // unbrauchbarer Zeitstempel → nie wieder sauber einsortierbar
      removed++;
      continue;
    }
    if (now.getTime() - seen > maxAgeDays * DAY_MS) {
      delete cache[ref];
      removed++;
    }
  }
  return removed;
}

/** digests.json persistieren (Volume, nur der Scanner schreibt; nicht atomar nötig). */
export function saveDigestCache(cache: DigestCache, file = digestCachePath()): void {
  ensureDir(path.dirname(file));
  fs.writeFileSync(file, JSON.stringify(cache, null, 2) + '\n');
}

/**
 * Cache für einen Scan-Lauf öffnen und am Ende wieder schreiben. Der Runner
 * muss pro Image-Ref `lookup(ref)` aufrufen — nur so wird `lastSeen`
 * fortgeschrieben (Grundlage für den 90-Tage-Prune) und der Wechsel VOR dem
 * Update erkannt.
 */
export interface DigestSession {
  /** belegter Digest + Wechsel gegenüber dem Stand vor diesem Lauf. */
  lookup(imageRef: string, digest: string | null): { digestChanged: boolean; previousDigest: string | null; digest: string | null };
  /** 90-Tage-Prune + Write (nur nach erfolgreichem Scan-Lauf aufrufen). */
  save(): void;
}

export function openDigestSession(now: Date = new Date(), file = digestCachePath()): DigestSession {
  const cache = loadDigestCache(file);
  return {
    lookup(imageRef, digest) {
      const previous = getDigestEntry(cache, imageRef);
      const { digestChanged, previousDigest } = digestTransition(previous, digest);
      putDigest(cache, imageRef, digest, now);
      return { digestChanged, previousDigest, digest };
    },
    save() {
      const removed = pruneDigestCache(cache, now);
      if (removed > 0) log(`digests.json: ${removed} Eintrag/Einträge älter als ${PRUNE_AFTER_DAYS} Tage entfernt.`);
      saveDigestCache(cache, file);
    },
  };
}

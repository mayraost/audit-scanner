// Minimaler GitHub-REST-Client (fetch-basiert, kein gh-Binary, kein SDK).
// Siehe Spec: tarball, trees, contents PUT (blob-SHA!), refs, pulls, /advisories.

import { githubToken, log } from './config.js';

const API_BASE = 'https://api.github.com';

/** Nur Statistik für den Report (kein Secret!). */
export const ghStats = { apiCalls: 0 };

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

interface GhError extends Error {
  status?: number;
}

export async function ghFetch(pathOrUrl: string, init: RequestInit = {}): Promise<Response> {
  const url = pathOrUrl.startsWith('http') ? pathOrUrl : API_BASE + pathOrUrl;
  const res = await fetch(url, {
    ...init,
    headers: {
      Authorization: `Bearer ${githubToken()}`,
      Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
      'User-Agent': 'audit-scanner',
      ...(typeof init.headers === 'object' ? init.headers : {}),
    },
  });
  ghStats.apiCalls++;

  // Core-Bucket-Rate-Limit (5000/h): einmal defensiv warten statt hart abbrechen.
  if (res.status === 403 && res.headers.get('x-ratelimit-remaining') === '0') {
    const resetMs = Number(res.headers.get('x-ratelimit-reset') ?? 0) * 1000;
    const waitMs = Math.min(Math.max(resetMs - Date.now(), 1000), 300_000);
    log(`GitHub Rate-Limit aktiv — warte ${Math.ceil(waitMs / 1000)}s …`);
    await sleep(waitMs);
    return ghFetch(url, init);
  }
  return res;
}

function ghErrorMessage(path: string, status: number, body: string): string {
  return `GitHub API ${status} für ${path}: ${body.slice(0, 400)}`;
}

/** GET → JSON. Non-2xx wirft. */
export async function ghJson<T = unknown>(path: string, init: RequestInit = {}): Promise<T> {
  const res = await ghFetch(path, init);
  if (!res.ok) {
    const body = await res.text();
    const err: GhError = new Error(ghErrorMessage(path, res.status, body));
    err.status = res.status;
    throw err;
  }
  return (await res.json()) as T;
}

/** GET → JSON; 404 liefert null (kein Throw). */
export async function ghJsonOrNull<T = unknown>(path: string): Promise<T | null> {
  const res = await ghFetch(path);
  if (res.status === 404) return null;
  if (!res.ok) {
    const body = await res.text();
    throw new Error(ghErrorMessage(path, res.status, body));
  }
  return (await res.json()) as T;
}

/** GET → roher Body als ArrayBuffer (z. B. Tarball; keine JSON-Fehler-Route). */
export async function ghBinary(path: string): Promise<ArrayBuffer> {
  const res = await ghFetch(path, { headers: { Accept: 'application/vnd.github+json' } });
  if (!res.ok) {
    const body = await res.text();
    throw new Error(ghErrorMessage(path, res.status, body));
  }
  return res.arrayBuffer();
}

/** Paging via Link-Header (rel="next"), per_page=100, page=1,2,… */
export async function ghPaginate<T = unknown>(path: string, perPage = 100): Promise<T[]> {
  const sep = path.includes('?') ? '&' : '?';
  let url: string | null = `${path}${sep}per_page=${perPage}`;
  const out: T[] = [];
  while (url) {
    const res = await ghFetch(url);
    if (!res.ok) {
      const body = await res.text();
      throw new Error(ghErrorMessage(url, res.status, body));
    }
    const items = (await res.json()) as T[];
    out.push(...items);
    url = nextLink(res.headers.get('link'));
  }
  return out;
}

function nextLink(linkHeader: string | null): string | null {
  if (!linkHeader) return null;
  for (const part of linkHeader.split(',')) {
    const segments = part.split(';');
    const rel = segments.find((s) => s.trim().startsWith('rel=')) ?? '';
    if (rel.includes('"next"')) {
      const m = segments[0]?.match(/<([^>]+)>/);
      if (m?.[1]) return m[1];
    }
  }
  return null;
}

/** base64 ohne Zeilenumbrüche — Pflicht für PUT-contents (Spec Gotcha 2). */
export function b64(content: string): string {
  return Buffer.from(content, 'utf8').toString('base64');
}

export function decodeB64(text: string): string {
  return Buffer.from(text, 'base64').toString('utf8');
}

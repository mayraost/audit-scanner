// LLM-Triage (opt-in, DEEPINFRA_API_KEY): DeepInfra OpenAI-kompatibler Endpoint.
// - Triage je Finding: decision suppress/remediate/investigate + confidence + reason.
//   Nur suppress && confidence >= 0.75 → aus Fix-PR ausgenommen ("LLM-suppressed").
//   Alles andere läuft deterministisch im normalen Report/PR-Flow weiter.
// - Batching: <= BULK_THRESHOLD Findings → max 1 Call je Finding (Konkurrenz 4);
//   > Threshold → Bulk-Mode (alle Findings, EINE Message, JSON-Array out).
// - Reasoning-Model (GLM): min. 800 completion tokens je Triage-Call einplanen.
// - SECURITY: DEEPINFRA_API_KEY geht nur in den Authorization-Header — niemals
//   loggen/printen. Fehlender Key → graceful skip ("LLM disabled", Scan läuft weiter).

import { DEEPINFRA_API_KEY, LLM_BASE_URL, LLM_MODEL, log } from './config.js';

export type TriageDecisionType = 'remediate' | 'suppress' | 'investigate';

export interface TriageDecision {
  decision: TriageDecisionType;
  confidence: number; // 0..1
  reason: string; // <=120 chars
}

/** LLM-Eingabe je Finding (bewusst knapp). */
export interface TriageInput {
  id: string; // stable key: `${repo}|${pkg}|${ghsa}|${version}`
  repo: string;
  pkg: string;
  version: string;
  vulnerableRange?: string;
  severity?: string;
  ghsa?: string;
  summary?: string;
  firstPatched?: string | null;
  /** aus Manifest geparst: Package in devDependencies (nicht in dependencies). */
  devOnly: boolean;
}

export interface PrBodyContext {
  repo: string;
  findings: Array<{
    pkg: string;
    version: string;
    patched: string | null;
    ghsas: string[];
    severity: string;
    summaries?: string[];
  }>;
}

let disabledLogged = false;

export function llmEnabled(): boolean {
  if (DEEPINFRA_API_KEY.length > 0) return true;
  if (!disabledLogged) {
    disabledLogged = true;
    log('LLM disabled: DEEPINFRA_API_KEY nicht gesetzt — Triage/PR-Body deterministisch weiter.');
  }
  return false;
}

const BULK_THRESHOLD = 20; // >20 Findings → Bulk-Mode
const CONCURRENCY = 4;
const MIN_TRIAGE_TOKENS = 800; // Reasoning-Model: Budget für reasoning + content

/** Ein Chat-Completion-Call. Wirft bei Hard-Errors; Statuscode NW-Log ohne Secrets. */
export async function chat(messages: Array<{ role: string; content: string }>, maxTokens: number): Promise<string> {
  const res = await fetch(`${LLM_BASE_URL}/chat/completions`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${DEEPINFRA_API_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ model: LLM_MODEL, messages, max_tokens: maxTokens, temperature: 0.1 }),
    signal: AbortSignal.timeout(120_000),
  });
  if (!res.ok) {
    const bodyText = await res.text();
    throw new Error(`LLM-Call ${res.status}: ${bodyText.slice(0, 200)}`);
  }
  const json = (await res.json()) as {
    choices?: Array<{ message?: { content?: string | null } }>;
  };
  const content = json.choices?.[0]?.message?.content ?? '';
  // Reasoning-Model: falls content leer, reasoning-Feld retten (best effort)
  if (content.trim().length > 0) return stripThink(content);
  const alt = (json as { choices?: Array<{ message?: Record<string, unknown> }> }).choices?.[0]
    ?.message as Record<string, unknown> | undefined;
  const reasoning = typeof alt?.reasoning === 'string' ? alt.reasoning : undefined;
  return stripThink(reasoning ?? '');
}

/** Denkt-Blöcke und Code-Fences um JSON strippen. */
function stripThink(text: string): string {
  const cleaned = text.replace(/<think>[\s\S]*?<\/think>/g, '');
  return cleaned.trim();
}

/** JSON aus LLM-Text extrahieren (Fences/Text drumherum toleriert). */
export function parseJsonLoose(text: string): unknown {
  const trimmed = text.trim().replace(/^```(?:json)?\s*/i, '').replace(/```\s*$/, '');
  const start = trimmed.search(/[[{]/);
  if (start === -1) throw new Error('LLM-Antwort ohne JSON');
  const slice = trimmed.slice(start);
  try {
    return JSON.parse(slice);
  } catch {
    // letzte Klammer kürzen (bei abgeschnittenem Output)
    const lastBrack = Math.max(slice.lastIndexOf(']'), slice.lastIndexOf('}'));
    if (lastBrack > 0) return JSON.parse(slice.slice(0, lastBrack + 1));
    throw new Error('LLM-Antwort: JSON nicht parsebar');
  }
}

const TRIAGE_SYSTEM = `You are a security-vulnerability triage assistant for JavaScript/TypeScript and other repositories. For each input finding you output strictly valid JSON, no prose.
For every finding decide:
- "decision": "remediate" (default: real risk, bump the dependency), "suppress" (exclude from auto-fix PR), or "investigate" (insufficient info).
- "confidence": 0..1 number.
- "reason": at most 120 characters, English.
Suppress ONLY if at least one criterion clearly holds:
(a) the package appears ONLY in devDependencies (flag devOnly=true) AND no plausible runtime path exists;
(b) the vulnerable code path is provably not reachable in this project type/context;
(c) the fix requires a breaking major upgrade AND the repo appears inactive/abandoned.
When in doubt use "investigate" or "remediate", never marginal suppressions.`;

function triageUser(items: TriageInput[]): string {
  const payload = items.map((i) => ({
    id: i.id,
    repo: i.repo,
    package: i.pkg,
    installedVersion: i.version,
    vulnerableRange: i.vulnerableRange ?? null,
    severity: i.severity ?? null,
    ghsa: i.ghsa ?? null,
    summary: i.summary ? i.summary.slice(0, 220) : null,
    firstPatched: i.firstPatched ?? null,
    devOnly: i.devOnly,
  }));
  return JSON.stringify({ findings: payload });
}

interface TriageOutItem {
  id?: string;
  decision?: string;
  confidence?: number;
  reason?: string;
}

const FALLBACK: TriageDecision = {
  decision: 'investigate',
  confidence: 0,
  reason: 'LLM unavailable — defaulting to normal review',
};

function normalize(item: TriageOutItem): TriageDecision {
  const rawDecision = String(item.decision ?? '').toLowerCase();
  const decision: TriageDecisionType =
    rawDecision === 'suppress' ? 'suppress'
    : rawDecision === 'remediate' ? 'remediate'
    : rawDecision === 'investigate' ? 'investigate'
    : 'investigate';
  const confidence = Math.max(0, Math.min(1, Number(item.confidence) || 0));
  const reason = String(item.reason ?? '').replace(/\s+/g, ' ').slice(0, 120);
  return { decision, confidence, reason };
}

/** Einzelner Triage-Chunk inkl. 1 Retry; on failure → FALLBACK je Item. */
async function triageChunk(items: TriageInput[]): Promise<Map<string, TriageDecision>> {
  const out = new Map<string, TriageDecision>();
  const maxTokens = Math.min(8000, 800 + 250 * items.length);
  let lastErr: Error | null = null;
  for (let attempt = 0; attempt <= 1; attempt++) {
    try {
      const text = await chat(
        [
          { role: 'system', content: TRIAGE_SYSTEM },
          { role: 'user', content: triageUser(items) },
        ],
        maxTokens
      );
      const parsed = parseJsonLoose(text) as unknown;
      const arr: TriageOutItem[] = Array.isArray(parsed)
        ? (parsed as TriageOutItem[])
        : ((parsed as { findings?: TriageOutItem[] }).findings as TriageOutItem[] | undefined) ??
          [parsed as TriageOutItem];
      const byId = new Map<string, TriageOutItem>();
      for (const item of arr) if (item && item.id !== undefined) byId.set(String(item.id), item);
      for (const item of items) {
        // Match-Strategie: erst per id; sonst 1 Ergebnis je Chunk → für alle gilt;
        // sonst positional (LLM hält Reihenfolge meist ein)
        const idx = items.indexOf(item);
        const hit =
          byId.get(item.id) ??
          (arr.length === 1 ? arr[0] : arr.length === items.length ? arr[idx] : undefined);
        out.set(item.id, hit ? normalize(hit) : FALLBACK);
      }
      return out;
    } catch (err) {
      lastErr = err instanceof Error ? err : new Error(String(err));
    }
  }
  log(`WARN: LLM-Triage fehlgeschlagen (2 Versuche, ${items.length} Finding(s)): ${lastErr?.message ?? '?'}`);
  for (const item of items) out.set(item.id, FALLBACK);
  return out;
}

/**
 * Findings triagieren. <=20 Findings: 1 Call je Finding (Konkurrenz 4, max 1 Call
 * je Package); >20: Bulk-Mode (Chunks à 30, eine Message pro Chunk).
 * Antwort-Map: key = TriageInput.id. Default-Hit für fehlende IDs: FALLBACK.
 */
export async function triageFindings(inputs: TriageInput[]): Promise<Map<string, TriageDecision>> {
  const empty = new Map<string, TriageDecision>();
  if (!llmEnabled()) return empty;
  for (const key of ['id']) void key; // noop (types)
  if (inputs.length === 0) return empty;

  const t0 = Date.now();
  const decisions = new Map<string, TriageDecision>();
  if (inputs.length > BULK_THRESHOLD) {
    for (let i = 0; i < inputs.length; i += 30) {
      const chunk = inputs.slice(i, i + 30);
      for (const [k, v] of await triageChunk(chunk)) decisions.set(k, v);
    }
  } else {
    // je 4 parallel: 1 Call je Finding, max 1 je Package
    const queue = [...inputs];
    const workers = Array.from({ length: Math.min(CONCURRENCY, queue.length) }, async () => {
      for (;;) {
        const item = queue.shift();
        if (!item) return;
        const res = await triageChunk([item]);
        const hit = res.get(item.id);
        if (hit) decisions.set(item.id, hit);
      }
    });
    await Promise.all(workers);
  }
  log(`LLM-Triage: ${inputs.length} Finding(s) in ${Math.round((Date.now() - t0) / 1000)} s bearbeitet.`);
  return decisions;
}

/**
 * Markdown-Text für Fix-PR (ENGLISCH): Absatz je CVE (Risiko 2-3 Sätze + was
 * gebumpert wird + Advisory-Quelle). Nur der CVE-Teil kommt vom LLM; Bumps/
 * Overrides/Lockfile-Note/Checks-Markierung hängt der Caller deterministisch an.
 */
export async function generatePrBodyCveSections(ctx: PrBodyContext): Promise<string | null> {
  if (!llmEnabled()) return null;
  if (ctx.findings.length === 0) return null;
  const payload = {
    repository: ctx.repo,
    findings: ctx.findings.map((f) => ({
      package: f.pkg,
      installedVersion: f.version,
      fixedVersion: f.patched,
      severity: f.severity,
      advisories: f.ghsas.map((g) => `https://github.com/advisories/${g}`),
      summaries: f.summaries ?? [],
    })),
  };
  const maxTokens = Math.min(8000, 1200 + 300 * ctx.findings.length);
  try {
    const text = await chat(
      [
        {
          role: 'system',
          content:
            'You write concise, strictly factual security-fix pull-request descriptions in ENGLISH markdown. Output ONLY the per-vulnerability sections, no title, no header, no closing text. For EACH finding produce one section: a "### `package-name@installed-version`" heading, then 2-3 sentences describing the risk (what the vulnerability allows, how it could affect this repository), then one line "Bump: `package` `installedVersion` -> `fixedVersion`". Include an advisory source link from the provided list on its own line (format "- Source: <url>"). If fixedVersion is null, state clearly that no fix is available and skip the bump line. No invented facts.',
        },
        { role: 'user', content: JSON.stringify(payload) },
      ],
      maxTokens
    );
    const body = stripThink(text).trim();
    if (body.length < 20) return null;
    return body;
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    log(`WARN: LLM-PR-Body fehlgeschlagen — deterministischer Template-Fallback: ${msg}`);
    return null;
  }
}

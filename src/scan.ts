// Scan-Orchestrierung (Spec "Ausführungsreihenfolge"):
// 1 Inventar (§1/§2c) → 2 je scanbares Repo: tarball + extract (§3) → 3 trivy fs
// → 4 high/critical filtern + /advisories-Crosscheck (§4) → 5 optional Fix-PR (§5)
// → 6 report.json/report.md + .heartbeat + Telegram (§6). exit 0.

import { execFile } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { promisify } from 'node:util';

import {
  HEARTBEAT_FILE,
  OWNER,
  REPORTS_DIR,
  TRIVY_BIN,
  TRIVY_CACHE_DIR,
  ensureDir,
  log,
  parseIsoDateKey,
  tmpRoot,
} from './config.js';
import { ghBinary, ghStats } from './github.js';
import { fetchAdvisories, GH_ECOSYSTEM, type AdvisoryHit } from './advisories.js';
import { loadInventory, MANIFEST_MAP, type Ecosystem, type RepoInfo } from './inventory.js';
import { createFixPr, type FixFinding, type FixResult } from './fix-pr.js';
import { createImagePr, scanRepoImages, type ImageFinding } from './image-scan.js';
import {
  ageDays,
  entriesForRepo,
  isKnownFinding,
  loadState,
  reconcileRepo,
  saveState,
  upsertEntry,
  type State,
  type StateFinding,
} from './state.js';
import { sendTelegramReport } from './telegram.js';
import { llmEnabled, triageFindings, type TriageDecision, type TriageInput } from './llm.js';

const execFileP = promisify(execFile);

export interface PackageFinding {
  pkg: string;
  version: string;
  severity: 'high' | 'critical';
  advisory: AdvisoryHit | null; // null = trivy-only (kein GH-Advisory-Treffer)
  ecosystem: string; // GitHub-Advisory-Ecosystem (aus Trivy-Evidenz, rekultiviert)
  devOnly: boolean; // package.json: nur in devDependencies
  /** Ökosystem des Evidenz-Manifests (aus Trivy-Target-Pfad). */
  manifestEco: Ecosystem | null;
  /** Repo-relativer Pfad des Evidenz-Manifests (z. B. docker/db-mcp/requirements.txt). */
  manifestPath: string;
  llm?: TriageDecision; // LLM-Triage-Entscheid (wenn DEEPINFRA_API_KEY gesetzt)
}

/** Triage-konform: suppress + confidence >= 0.75 → aus Fix-PR ausgenommen. */
export function isSuppressed(f: PackageFinding): boolean {
  return f.llm?.decision === 'suppress' && f.llm.confidence >= 0.75;
}

export interface RepoResult {
  name: string;
  private: boolean;
  defaultBranch: string;
  ecosystem: Ecosystem | null;
  status:
    | 'scanned'
    | 'skipped-config'
    | 'skipped-no-manifest'
    | 'skipped-env'
    | 'skipped-archived'
    | 'trivy-missing'
    | 'error';
  note?: string;
  trivyIds?: number; // high/critical-rohfunde aus trivy
  findings: PackageFinding[];
  fixPr?: FixResult;
  /** Image-Scan (Dockerfile/compose): Refs, vulns, Freshness (v1.4.0). */
  images?: ImageFinding[];
  imagePr?: FixResult;
}

export interface ReminderInfo {
  repo: string;
  prUrl: string;
  prNumber: number;
  ageDays: number;
  createdAt: string;
  findings: StateFinding[]; // offene CVEs (ghsaId + package) laut State-Eintrag
}

export interface Report {
  generatedAt: string;
  owner: string;
  summary: {
    reposTotal: number;
    scanned: number;
    findings: number;
    suppressed: number; // LLM-suppressed (decision suppress + conf >= 0.75)
    fixPrs: number;
    imagePrs: number; // Image-Tag-Bump-PRs (separate section, fixPrs-Umgebung)
    apiCalls: number;
    reminders: number; // offene Fix-PRs (Reminder-Sektion)
  };
  reminders: ReminderInfo[];
  repos: RepoResult[];
}

interface TrivyVuln {
  VulnerabilityID: string;
  PkgName: string;
  InstalledVersion: string;
  Severity?: string;
  FixedVersion?: string;
  PrimaryURL?: string;
  // Durchreich-Felder aus Results[] (Target-Pfad + Ökosystem-Type der Evidenz):
  Target?: string;
  ScanType?: string;
}

interface TrivyResult {
  Results?: Array<{
    Target: string;
    Type?: string;
    Vulnerabilities?: TrivyVuln[] | null;
  }>;
}

export async function runScan(opts: {
  sendTelegram: boolean;
  fixPrs: boolean;
  onlyRepos?: string[]; // --only=repo1,repo2 → Inventar filtern (Debug/Probe-Lauf)
}): Promise<Report> {
  let inventory = await loadInventory();
  if (opts.onlyRepos && opts.onlyRepos.length > 0) {
    const wanted = new Set(opts.onlyRepos.map((r) => r.trim()));
    inventory = inventory.filter((r) => wanted.has(r.name));
    log(`--only aktiv: ${inventory.length} Repos gefiltert (${opts.onlyRepos.join(', ')}).`);
    if (inventory.length === 0) {
      log('WARN: --only hat kein Repos ergeben.');
    }
  }
  const runDate = parseIsoDateKey();

  // PR-Dedupe-State: nur aktiv, wenn Fix-PRs generell an sind (ENABLE_FIX_PRS=1).
  // Ohne Fix-PRs bleibt Verhalten wie bisher (kein state.json, kein Reminder).
  const state: State = opts.fixPrs ? loadState() : { prs: {} };
  if (opts.fixPrs) {
    // Je Repo mit State-Einträgen: PR-Remote-Status prüfen (geschlossene raus,
    // offene lastSeen-Refresh) — einmal je Lauf, Basis für Reminder + Dedupe.
    for (const repo of Object.keys(state.prs)) {
      try {
        await reconcileRepo(state, repo);
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        log(`WARN: State-Reconciliation für ${repo} fehlgeschlagen: ${msg}`);
      }
    }
    saveState(state);
  }

  const results: RepoResult[] = [];
  const scanTmp = tmpRoot();

  // Trivy-Verfügbarkeit EINMAL klären (lokal ohne Docker/Image eher fehlend)
  const trivyAvailable = await checkTrivy();
  if (!trivyAvailable) {
    log(
      'trivy nicht verfügbar (TRIVY_BIN) — Vulnerability-Scan wird pro Repo übersprungen.'
    );
  }

  try {
    for (const repo of inventory) {
      const res: RepoResult = {
        name: repo.name,
        private: repo.private,
        defaultBranch: repo.defaultBranch,
        ecosystem: repo.ecosystem,
        status: 'skipped-no-manifest',
        findings: [],
      };

      if (repo.configSkip) {
        res.status =
          repo.skipSource === 'SKIP_REPOS'
            ? 'skipped-env'
            : repo.skipSource === 'archived'
              ? 'skipped-archived'
              : 'skipped-config';
        res.note = `Skip via ${repo.skipSource === 'archived' ? 'archived-Repo (hard guard)' : repo.skipSource ?? 'unbekannt'}`;
        results.push(res);
        continue;
      }
      if (!repo.ecosystem || repo.manifestPaths.length === 0) {
        res.note = 'kein scanbares Manifest (package-lock/pnpm-lock/yarn.lock/requirements/go.mod/Cargo.toml)';
        results.push(res);
        continue;
      }
      if (!trivyAvailable) {
        res.status = 'trivy-missing';
        res.note = 'trivy binary fehlt (lokal? Container Image einsetzen)';
        results.push(res);
        continue;
      }
      if (repo.treeTruncated) {
        log(`HINWEIS ${repo.name}: tree truncated=true — Manifestliste ggf. unvollständig.`);
      }

      try {
        const repoDir = await downloadTarball(scanTmp, repo);
        const trivyReport = await runTrivy(repo.name, repoDir, scanTmp);
        const nums = collectFindings(trivyReport);
        results.push(
          await finalizeRepoResult(res, nums, repo, opts.fixPrs, repoDir, state)
        );
        // Image-Scan (v1.4.0): Dockerfiles/compose parsen → trivy image (ohne
        // daemon) + Freshness; optional Image-Tag-Bump-PR (nur pinned, immer-PR).
        try {
          const img = await scanRepoImages(repo, repoDir, scanTmp, trivyAvailable);
          res.images = img.findings;
          if (opts.fixPrs && img.bumpPlan.length > 0) {
            res.imagePr = await createImagePr(repo, img.bumpPlan, state);
          }
        } catch (ierr) {
          const imsg = ierr instanceof Error ? ierr.message : String(ierr);
          log(`WARN: Image-Scan für ${repo.name} fehlgeschlagen: ${imsg}`);
        }
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        log(`WARN: Scan-Fehler für ${repo.name}: ${msg}`);
        const failure: RepoResult = { ...res, status: 'error', note: msg.slice(0, 300), findings: [] };
        results.push(failure);
      }
    }
  } finally {
    fs.rmSync(scanTmp, { recursive: true, force: true });
  }

  const report: Report = {
    generatedAt: new Date().toISOString(),
    owner: OWNER,
    summary: {
      reposTotal: inventory.length,
      scanned: results.filter((r) => r.status === 'scanned').length,
      findings: results.reduce((n, r) => n + r.findings.length, 0),
      suppressed: results.reduce((n, r) => n + r.findings.filter(isSuppressed).length, 0),
      fixPrs: results.filter((r) => r.fixPr?.status === 'created').length,
      imagePrs: results.filter((r) => r.imagePr?.status === 'created').length,
      apiCalls: ghStats.apiCalls,
      reminders: collectReminders(state).length,
    },
    reminders: collectReminders(state),
    repos: results,
  };

  // State persistieren (lastSeen-Updates + ggf. neu angelegte PR-Einträge)
  if (opts.fixPrs) saveState(state);

  // Report-Ablage + Heartbeat (auch wenn Telegram skip). --only-Run (Probe-Lauf)
  // bekommt suffixed Report-Files — Tages-Full-Scan-Report bleibt unangetastet.
  const outDir = ensureDir(path.join(REPORTS_DIR, runDate));
  const suffix = opts.onlyRepos && opts.onlyRepos.length > 0 ? onlyReportSuffix(opts.onlyRepos) : '';
  fs.writeFileSync(path.join(outDir, `report${suffix}.json`), JSON.stringify(report, null, 2));
  fs.writeFileSync(path.join(outDir, `report${suffix}.md`), renderMarkdown(report));
  ensureDir(REPORTS_DIR);
  fs.writeFileSync(HEARTBEAT_FILE, new Date().toISOString());
  log(`Report geschrieben: ${outDir}${suffix ? ` (report${suffix}.* — --only-Run, Full-Scan-Report unangetastet)` : ''}`);

  if (opts.sendTelegram) await sendTelegramFromReport(report);
  return report;
}

/** Trivy-Type → Manifest-Ökosystem Fallback (wenn Target-Bname unbekannt). */
const TRIVY_TYPE_ECO: Record<string, Ecosystem> = {
  npm: 'npm',
  pip: 'pip',
  python: 'pip',
  golang: 'go',
  cargo: 'cargo',
};

/**
 * Trivy-Target-Pfad (<tarball-topdir>/<rel>) → { eco, manifestPath }.
 * Topdir-Präfix (basename des Scan-Roots) wird gestreift; Fallback: Trivy-Type.
 */
function manifestInfo(target: string, repoDir: string): { eco: Ecosystem; manifestPath: string } | null {
  if (!target) return null;
  let rel = target;
  const top = path.basename(repoDir);
  if (rel.startsWith(`${top}/`)) rel = rel.slice(top.length + 1);
  const base = rel.split('/').pop() ?? rel;
  const eco = MANIFEST_MAP[base];
  if (eco) return { eco, manifestPath: rel };
  // Type-Fallback (trivy liefert z. B. "package.json (pip)"-Targets):
  // Type-Marker am Ende des Targets (Klammer-Suffix) prüfen, sonst npm-Familie annehmen.
  const typeMarker = /\(([^)]+)\)\s*$/.exec(target)?.[1]?.toLowerCase();
  return {
    eco: TRIVY_TYPE_ECO[typeMarker ?? ''] ?? 'npm',
    manifestPath: rel,
  };
}

/** Erganzt trivy-Rohfunde (high/critical) mit /advisories als Crosscheck. */
async function finalizeRepoResult(
  res: RepoResult,
  raw: TrivyVuln[],
  repo: RepoInfo,
  fixPrsEnabledFlag: boolean,
  repoDir: string,
  state: State
): Promise<RepoResult> {
  res.trivyIds = raw.length;
  res.status = 'scanned';

  const fixed: PackageFinding[] = [];
  const seen = new Set<string>();
  for (const v of raw) {
    const mi = manifestInfo(v.Target ?? '', repoDir);
    const ghEco = mi ? GH_ECOSYSTEM[mi.eco] ?? mi.eco : 'npm';
    const vulnKey = `${v.VulnerabilityID}|${v.PkgName}|${v.InstalledVersion}|${mi?.manifestPath ?? ''}`;
    const hits = mi ? await fetchAdvisories(ghEco, v.PkgName, v.InstalledVersion) : [];
    if (hits.length === 0) {
      // trivy-only (z. B. NVIDIA-/OS-Feed ohne GH-Advisory) immer noch anzeigen
      if (v.Severity === 'HIGH' || v.Severity === 'CRITICAL') {
        if (seen.has(vulnKey)) continue;
        seen.add(vulnKey);
        fixed.push({
          pkg: v.PkgName,
          version: v.InstalledVersion,
          severity: v.Severity.toLowerCase() as 'high' | 'critical',
          devOnly: false,
          advisory: null,
          ecosystem: ghEco,
          manifestEco: mi?.eco ?? null,
          manifestPath: mi?.manifestPath ?? '',
        });
      }
      continue;
    }
    for (const h of hits) {
      const advKey = `${vulnKey}|${h.ghsa}|${h.range}`;
      if (seen.has(advKey)) continue;
      seen.add(advKey);
      fixed.push({
        pkg: v.PkgName,
        version: v.InstalledVersion,
        severity: h.severity as 'high' | 'critical',
        devOnly: false,
        advisory: h,
        ecosystem: ghEco,
        manifestEco: mi?.eco ?? null,
        manifestPath: mi?.manifestPath ?? '',
      });
    }
  }

  res.findings = fixed;

  markDevOnly(res, repoDir);
  if (res.findings.length > 0 && llmEnabled()) await applyTriage(res);

  if (fixPrsEnabledFlag) {
    // PR-Dedupe (State): Findings, für die bereits ein offener Fix-PR existiert,
    // gelten nicht als "neu" — sie erscheinen nur in der Reminder-Sektion (Acknowledged).
    // Suppressed Findings bleiben weiterhin in der suppressed-Sektion (bewusst verworfen).
    if (entriesForRepo(state, res.name).length > 0) {
      const before = res.findings.length;
      res.findings = res.findings.filter(
        (f) =>
          isSuppressed(f) ||
          !isKnownFinding(state, res.name, f.pkg, f.advisory?.ghsa ?? null)
      );
      const deduped = before - res.findings.length;
      if (deduped > 0) {
        log(`${res.name}: ${deduped} Finding(s) bereits durch offenen Fix-PR abgedeckt — nur Reminder.`);
      }
    }

    // Fix-PR: pro (Package + Evidenz-Manifest) verwertbare Fix-Version (first_patched)
    // zusammenfassen; LLM-suppressed Findings (suppress + conf >= 0.75) → aus PR ausgenommen.
    // Gruppierung über manifestPath: gleiche Paketnamen in unterschiedlichen Manifests
    // (z. B. pip `mcp` + npm-Paket) werden getrennt behandelt.
    const findings = new Map<string, FixFinding>();
    for (const f of res.findings) {
      if (isSuppressed(f)) continue;
      if (!f.advisory?.firstPatched) continue;
      if (!f.manifestEco) continue;
      const key = `${f.pkg}|${f.manifestPath}`;
      const cur = findings.get(key);
      if (cur) {
        if (!cur.ghsas.includes(f.advisory.ghsa)) cur.ghsas.push(f.advisory.ghsa);
        if (!cur.summary && f.advisory.summary) cur.summary = f.advisory.summary;
        // höchste Patch-Version erhöhen
        if (f.advisory.firstPatched.localeCompare(cur.patched ?? '', undefined, { numeric: true }) > 0) {
          cur.patched = f.advisory.firstPatched;
        }
      } else {
        findings.set(key, {
          pkg: f.pkg,
          version: f.version,
          patched: f.advisory.firstPatched,
          ghsas: [f.advisory.ghsa],
          severity: f.advisory.severity,
          summary: f.advisory.summary,
          manifestEco: f.manifestEco,
          manifestPath: f.manifestPath,
        });
      }
    }
    if (findings.size > 0 && (res.trivyIds ?? 0) > 0) {
      const fixFindings = [...findings.values()];
      res.fixPr = await createFixPr(repo, fixFindings);
      recordFixPrInState(state, res.name, res.fixPr, fixFindings);
    }
  }

  return res;
}

/**
 * Fix-PR-Ergebnis in state.json verbuchen:
 * - 'created': neuer State-Eintrag (Phasen-Branch, prUrl/prNumber, Findings).
 * - 'exists': PR war offen aber (noch) nicht im State (z. B. nach corrupt-Reset)
 *   → Rebuild-from-GitHub: Eintrag nachbilden.
 */
function recordFixPrInState(
  state: State,
  repo: string,
  fixPr: FixResult,
  findings: FixFinding[]
): void {
  if (!fixPr.prUrl || fixPr.prNumber === undefined || !fixPr.branch) return;
  if (fixPr.status !== 'created' && fixPr.status !== 'exists') return;

  const now = new Date().toISOString();
  const stateFindings: StateFinding[] = [];
  const ghsaIds: string[] = [];
  for (const f of findings) {
    if (f.ghsas.length === 0) {
      stateFindings.push({ package: f.pkg, version: f.version, severity: f.severity, ghsaId: null });
    }
    for (const ghsa of f.ghsas) {
      ghsaIds.push(ghsa);
      stateFindings.push({ package: f.pkg, version: f.version, severity: f.severity, ghsaId: ghsa });
    }
  }

  const existing = entriesForRepo(state, repo).find((e) => e.prNumber === fixPr.prNumber);
  if (existing) {
    existing.lastSeen = now;
    return;
  }
  upsertEntry(state, repo, {
    branch: fixPr.branch!,
    prUrl: fixPr.prUrl,
    prNumber: fixPr.prNumber,
    ghsaIds,
    createdAt: now,
    lastSeen: now,
    findings: stateFindings,
  });
  log(`${repo}: Fix-PR #${fixPr.prNumber} im State erfasst (${fixPr.status}).`);
}

/** Offene Fix-PRs aus dem reconciled State → Reminder-Infos (Alt in Tagen). */
function collectReminders(state: State, now = new Date()): ReminderInfo[] {
  const out: ReminderInfo[] = [];
  for (const [repo, entries] of Object.entries(state.prs)) {
    for (const entry of entries) {
      if (entry.kind === 'image') continue; // Image-PRs sind keine CVE-Reminder
      out.push({
        repo,
        prUrl: entry.prUrl,
        prNumber: entry.prNumber,
        ageDays: ageDays(entry, now),
        createdAt: entry.createdAt,
        findings: entry.findings,
      });
    }
  }
  return out.sort((a, b) => a.repo.localeCompare(b.repo) || b.createdAt.localeCompare(a.createdAt));
}

/** devOnly je Finding aus package.json am Repo-Root bestimmen. */
function markDevOnly(res: RepoResult, repoDir: string): void {
  const devDeps = new Set<string>();
  const deps = new Set<string>();
  try {
    const pkgJson = JSON.parse(
      fs.readFileSync(path.join(repoDir, 'package.json'), 'utf8')
    ) as Record<string, Record<string, unknown>>;
    for (const k of Object.keys(pkgJson.devDependencies ?? {})) devDeps.add(k.toLowerCase());
    for (const k of Object.keys(pkgJson.dependencies ?? {})) deps.add(k.toLowerCase());
  } catch {
    // kein package.json am Root (pip/go/cargo) → devOnly bleibt false
  }
  for (const f of res.findings) {
    f.devOnly = devDeps.has(f.pkg.toLowerCase()) && !deps.has(f.pkg.toLowerCase());
  }
}

/** LLM-Triage auf alle Findings eines Repos anwenden (Ergebnis an f.llm). */
async function applyTriage(res: RepoResult): Promise<void> {
  const pairs = res.findings.map((f) => {
    const id = `${res.name}|${f.pkg}|${f.advisory?.ghsa ?? 'trivy'}|${f.version}`;
    const input: TriageInput = {
      id,
      repo: res.name,
      pkg: f.pkg,
      version: f.version,
      vulnerableRange: f.advisory?.range,
      severity: f.severity,
      ghsa: f.advisory?.ghsa,
      summary: f.advisory?.summary,
      firstPatched: f.advisory?.firstPatched,
      devOnly: f.devOnly,
    };
    return { f, input };
  });
  const decisions = await triageFindings(pairs.map((p) => p.input));
  for (const { f, input } of pairs) {
    f.llm = decisions.get(input.id) ?? { decision: 'investigate', confidence: 0, reason: 'LLM unavailable — normal flow' };
  }
}

async function downloadTarball(scanTmp: string, repo: RepoInfo): Promise<string> {
  const dest = path.join(scanTmp, `${repo.name}.tar.gz`);
  const buf = await ghBinary(
    `/repos/${OWNER}/${repo.name}/tarball/${repo.defaultBranch}`
  );
  fs.writeFileSync(dest, Buffer.from(buf));
  const extractDir = path.join(scanTmp, `${repo.name}-src`);
  fs.mkdirSync(extractDir, { recursive: true });
  // gh-Tarball enthält EINEN Top-Level-Ordner (owner-repo-sha) — extract & locate
  await execFileP('tar', ['xzf', dest, '-C', extractDir], { timeout: 3 * 60_000 });
  const entries = fs.readdirSync(extractDir);
  if (entries.length !== 1) throw new Error(`tarball-Struktur unerwartet (${entries.length} Einträge)`);
  const root = path.join(extractDir, entries[0] as string);
  return root;
}

function trivyArgs(target: string, outPath: string): string[] {
  return [
    'fs',
    '--scanners',
    'vuln',
    '--format',
    'json',
    '--skip-dirs',
    'node_modules',
    '--cache-dir',
    TRIVY_CACHE_DIR,
    '--quiet',
    '--output',
    outPath,
    target,
  ];
}

async function checkTrivy(): Promise<boolean> {
  if (path.isAbsolute(TRIVY_BIN)) return fs.existsSync(TRIVY_BIN);
  for (const p of (process.env.PATH ?? '').split(path.delimiter)) {
    if (p && fs.existsSync(path.join(p, TRIVY_BIN))) return true;
  }
  return false;
}

async function runTrivy(repo: string, target: string, scanTmp: string): Promise<TrivyResult> {
  const outPath = path.join(scanTmp, `${repo}.trivy.json`);
  await execFileP(TRIVY_BIN, trivyArgs(target, outPath), {
    timeout: 15 * 60_000,
    maxBuffer: 256 * 1024 * 1024,
  });
  return JSON.parse(fs.readFileSync(outPath, 'utf8')) as TrivyResult;
}

function collectFindings(report: TrivyResult): TrivyVuln[] {
  const out: TrivyVuln[] = [];
  for (const result of report.Results ?? []) {
    for (const v of result.Vulnerabilities ?? []) {
      if (v.Severity === 'HIGH' || v.Severity === 'CRITICAL') {
        // Evidenz-Kontext (Target-Pfad + Type) mit durchreichen — Basis für
        // per-Finding-Ökosystem + Manifest-Auflösung im Fix-PR.
        out.push({ ...v, Target: result.Target, ScanType: result.Type });
      }
    }
  }
  const seen = new Set<string>();
  return out.filter((v) => {
    const key = `${v.VulnerabilityID}|${v.PkgName}|${v.InstalledVersion}|${v.Target}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

/**
 * Dateisystem-sicherer Report-File-Suffix für --only-Runs (Probe-Lauf):
 * Repos zu einem stabilen Tag normalisieren (z. B. ["private-ai-interface"]
 * → ".only-private-ai-interface", mehrere: "-joined", gekürzt auf 60 Zeichen).
 * Tages-Report (report.md/json) bleibt dadurch vom Full-Scan unangetastet.
 */
function onlyReportSuffix(repos: string[]): string {
  const tag = repos
    .map((r) => r.toLowerCase().replace(/[^a-z0-9._-]+/g, '-').replace(/^-+|-+$/g, ''))
    .filter(Boolean)
    .join('-')
    .slice(0, 60)
    .replace(/-+$/g, '');
  return tag.length > 0 ? `.only-${tag}` : '.only';
}

function renderMarkdown(report: Report): string {
  const summaryLine =
    `*Repos*: ${report.summary.reposTotal} total / ${report.summary.scanned} gescannt · ` +
    `high/critical-Advisory-Funde: ${report.summary.findings} · LLM-suppressed: ${report.summary.suppressed} · ` +
    `Fix-PRs: ${report.summary.fixPrs}${report.summary.imagePrs ? ` (+${report.summary.imagePrs} Image)` : ''} · offene Fix-PRs (Reminder): ${report.summary.reminders} · ` +
    `GitHub-API-Calls: ${report.summary.apiCalls}`;
  const lines: string[] = [
    `# CVE-Audit-Report (mayraost)`,
    '',
    `*Generated*: ${report.generatedAt}`,
    summaryLine,
    '',
  ];
  if (report.reminders.length > 0) {
    lines.push('## ⏰ Offene CVEs (Fix-PR wartet)', '');
    for (const rem of report.reminders) {
      lines.push(`### ${rem.repo} — Tag ${rem.ageDays}, offen seit ${rem.createdAt.slice(0, 10)}`);
      for (const f of rem.findings) {
        lines.push(`- ${f.ghsaId ?? '(trivy-only)'} ${f.package}@${f.version} [${f.severity}]`);
      }
      lines.push('', `PR: ${rem.prUrl}`, '');
    }
  }
  for (const r of report.repos) {
    lines.push(`## ${r.name}${r.private ? ' (private)' : ''} — ${r.status}`);
    if (r.note) lines.push(`*Hinweis*: ${r.note}`);
    const suppressed = r.findings.filter(isSuppressed);
    const visible = r.findings.filter((f) => !isSuppressed(f));
    if (visible.length > 0) {
      lines.push('', '| Package | Version | Severity | GHSA | Fix |', '|---|---|---|---|---|');
      for (const f of visible) {
        lines.push(
          `| ${f.pkg} | ${f.version} | ${f.severity} | ${f.advisory?.ghsa ?? '—'} | ${f.advisory?.firstPatched ?? '—'} |`
        );
      }
    }
    if (suppressed.length > 0) {
      lines.push('', '### LLM-suppressed (nicht im Fix-PR)');
      for (const f of suppressed) {
        lines.push(
          `- \`${f.pkg}@${f.version}\` ${f.advisory?.ghsa ?? '(trivy)'} — ${f.llm?.reason ?? '?'} ` +
            `(confidence ${(f.llm?.confidence ?? 0).toFixed(2)})`
        );
      }
    }
    if (r.fixPr?.prUrl) lines.push('', `Fix-PR: ${r.fixPr.prUrl} (${r.fixPr.status})`);
    if (r.imagePr?.prUrl) lines.push('', `Image-PR: ${r.imagePr.prUrl} (${r.imagePr.status})`);
    if (r.images?.length) lines.push('', imageTable(r.images));
    lines.push('');
  }
  return lines.join('\n');
}

/** 🐳-Sektion je Repo (Report-MD): nur Images mit vulns/update/note. */
function imageTable(images: ImageFinding[]): string {
  const rows: string[] = [];
  for (const f of images) {
    const vc = `H${f.vulns.high}/C${f.vulns.critical}`;
    if (f.note) {
      rows.push(`| ${f.image} | — | — | — | ${f.note} |`);
    } else if (f.updateAvailable) {
      rows.push(`| ${f.image} | ${f.current} | ${f.newestSameMajor} | ${vc} | ⚠️ update verfügbar |`);
    } else {
      rows.push(
        `| ${f.image} | ${f.current} | ${f.newestSameMajor ?? '—'} | ${vc} | ` +
          (f.pinned ? 'aktuell' : 'floating (aktualisiert sich beim Rebuild)') + ' |'
      );
    }
  }
  return [
    '### 🐳 Images (Dockerfile/compose)',
    '| Image | Current | Newest same-major | Vulns H/C | Status |',
    '|---|---|---|---|---|',
    ...rows,
  ].join('\n');
}

async function sendTelegramFromReport(report: Report): Promise<void> {
  const date = parseIsoDateKey(new Date(report.generatedAt));
  const hasNew =
    report.repos.some((r) => r.findings.some((f) => !isSuppressed(f))) ||
    report.repos.some((r) => r.images?.some((i) => i.updateAvailable) ?? false);
  const hasReminders = report.reminders.length > 0;
  if (!hasNew && !hasReminders) {
    // Keine neuen Funde UND keine offenen Fix-PRs → gar kein Versand (kein Spam).
    log('Telegram skip: keine neuen Findings und keine offenen Fix-PRs — kein Versand.');
    return;
  }
  const title = `🔐 CVE-Audit ${date} (mayraost)`;
  const body = telegramBody(report, hasNew);
  await sendTelegramReport(title, body);
}

/** Reminder-Sektion: offene Fix-PRs mit Alter in Tagen + offene CVEs (kompakt). */
function reminderLines(report: Report): string[] {
  const lines: string[] = [];
  for (const rem of report.reminders) {
    lines.push(`⏰ Offene CVEs (Fix-PR wartet, Tag ${rem.ageDays}): *${rem.repo}*`);
    for (const f of rem.findings) {
      const ghsa = f.ghsaId ?? 'trivy-only';
      lines.push(`  • ${ghsa} ${f.package}@${f.version} [${f.severity}]`);
    }
    lines.push(`  🛠 PR offen: ${rem.prUrl}`);
    lines.push('');
  }
  if (lines.length > 0 && lines.at(-1) === '') lines.pop();
  return lines;
}

function telegramBody(report: Report, hasNewFindings: boolean): string {
  const lines: string[] = [];
  const totalCount = report.repos.reduce((n, r) => n + r.findings.length, 0);
  const suppressedCount = report.repos.reduce((n, r) => n + r.findings.filter(isSuppressed).length, 0);
  const withFinds = report.repos.filter((r) => r.findings.some((f) => !isSuppressed(f)));

  // Reminder-Sektion IMMER zuerst (JEDEN Lauf mit offenen Fix-PRs, auch ohne neue Funde);
  // dedupete alte Findings erscheinen NUR hier, nicht doppelt in der Finding-Sektion.
  lines.push(...reminderLines(report));

  if (!hasNewFindings) {
    // Nur-Reminder-Nachricht (kurz) — keine weiteren Sektionen.
    return lines.join('\n\n');
  }
  if (withFinds.length === 0) {
    lines.push('✅ Keine neuen high/critical-Security-Advisories gefunden.');
  }
  for (const r of withFinds) {
    const visible = r.findings.filter((f) => !isSuppressed(f));
    lines.push(`*${r.name}* (${r.ecosystem ?? '?'}, ${visible.length} Funde):`);
    for (const f of visible) {
      const fix = f.advisory?.firstPatched
        ? `→ fix: ${f.advisory.firstPatched}`
        : '⚠️ keine gepatchte Version';
      const ghsa = f.advisory?.ghsa ? ` ${f.advisory.ghsa}` : '';
      const sum = f.advisory?.summary ? ` — ${trim(f.advisory.summary, 140)}` : '';
      lines.push(`  • ${f.pkg} ${f.version} [${f.severity}]${ghsa}${sum} ${fix}`);
    }
    if (r.fixPr?.prUrl) lines.push(`  🛠 Fix-PR: ${r.fixPr.prUrl}`);
    lines.push('');
  }
  if (suppressedCount > 0) {
    lines.push(`🔇 LLM-suppressed: ${suppressedCount}/${totalCount} Funde (Details im Report „LLM-suppressed“-Sektion).`);
  }
  // 🐳 Image-Sektion: nur Repos mit Image-Refs und zumindest vulns>0 oder Update.
  const imgRepos = report.repos.filter(
    (r) => r.images?.some((i) => !i.note && (i.updateAvailable || i.vulns.high + i.vulns.critical > 0))
  );
  if (imgRepos.length > 0) {
    lines.push('🐳 Image-Scan (Dockerfile/compose):');
    for (const r of imgRepos) {
      lines.push(`*${r.name}*:`);
      for (const f of r.images!) {
        if (f.note || (!f.updateAvailable && f.vulns.high + f.vulns.critical === 0)) continue;
        const vc = `H${f.vulns.high}/C${f.vulns.critical}`;
        if (f.updateAvailable) {
          lines.push(`  • ${f.image} → ${f.newestSameMajor} ⚠️ update verfügbar [${vc}]`);
        } else {
          lines.push(
            `  • ${f.image} [${vc}] — ${f.pinned ? 'pinned, aktuell' : 'floating (Rebuild aktualisiert)'}`
          );
        }
      }
      if (r.imagePr?.prUrl) lines.push(`  🛠 Image-PR: ${r.imagePr.prUrl}`);
      lines.push('');
    }
  }
  const unscannable = report.repos.filter(
    (r) => r.status.startsWith('skipped') || r.status === 'error' || r.status === 'trivy-missing'
  );
  if (unscannable.length > 0) {
    lines.push('Nicht gescannt:');
    for (const r of unscannable) {
      lines.push(`  ⏭ ${r.name}: ${r.status}${r.note ? ` (${trim(r.note, 60)})` : ''}`);
    }
  }
  const fixed = report.repos.filter((r) => r.fixPr?.status === 'created');
  if (fixed.length > 0) {
    lines.push(`Fix-PRs diesmal: ${fixed.map((r) => r.name).join(', ')}`);
  }
  const imgFixed = report.repos.filter((r) => r.imagePr?.status === 'created');
  if (imgFixed.length > 0) {
    lines.push(`🐳 Image-Bump-PRs diesmal: ${imgFixed.map((r) => r.name).join(', ')}`);
  }
  return lines.join('\n\n');
}

function trim(s: string, max: number): string {
  return s.length > max ? `${s.slice(0, max - 1)}…` : s;
}

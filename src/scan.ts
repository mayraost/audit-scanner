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
import { loadInventory, type Ecosystem, type RepoInfo } from './inventory.js';
import { createFixPr, type FixFinding, type FixResult } from './fix-pr.js';
import { sendTelegramReport } from './telegram.js';
import { llmEnabled, triageFindings, type TriageDecision, type TriageInput } from './llm.js';

const execFileP = promisify(execFile);

export interface PackageFinding {
  pkg: string;
  version: string;
  severity: 'high' | 'critical';
  advisory: AdvisoryHit | null; // null = trivy-only (kein GH-Advisory-Treffer)
  ecosystem: string;
  devOnly: boolean; // package.json: nur in devDependencies
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
    | 'trivy-missing'
    | 'error';
  note?: string;
  trivyIds?: number; // high/critical-rohfunde aus trivy
  findings: PackageFinding[];
  fixPr?: FixResult;
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
    apiCalls: number;
  };
  repos: RepoResult[];
}

interface TrivyVuln {
  VulnerabilityID: string;
  PkgName: string;
  InstalledVersion: string;
  Severity?: string;
  FixedVersion?: string;
  PrimaryURL?: string;
}

interface TrivyResult {
  Results?: Array<{
    Target: string;
    Type?: string;
    Vulnerabilities?: TrivyVuln[] | null;
  }>;
}

export async function runScan(opts: { sendTelegram: boolean; fixPrs: boolean }): Promise<Report> {
  const runDate = parseIsoDateKey();
  const inventory = await loadInventory();

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
        res.status = repo.skipSource === 'SKIP_REPOS' ? 'skipped-env' : 'skipped-config';
        res.note = `Skip via ${repo.skipSource ?? 'unbekannt'}`;
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
        const nums = collectFindings(trivyReport, repo.ecosystem);
        results.push(await finalizeRepoResult(res, nums, repo, opts.fixPrs, repoDir));
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
      apiCalls: ghStats.apiCalls,
    },
    repos: results,
  };

  // Report-Ablage + Heartbeat (auch wenn Telegram skip)
  const outDir = ensureDir(path.join(REPORTS_DIR, runDate));
  fs.writeFileSync(path.join(outDir, 'report.json'), JSON.stringify(report, null, 2));
  fs.writeFileSync(path.join(outDir, 'report.md'), renderMarkdown(report));
  ensureDir(REPORTS_DIR);
  fs.writeFileSync(HEARTBEAT_FILE, new Date().toISOString());
  log(`Report geschrieben: ${outDir}`);

  if (opts.sendTelegram) await sendTelegramFromReport(report);
  return report;
}

/** Erganzt trivy-Rohfunde (high/critical) mit /advisories als Crosscheck. */
async function finalizeRepoResult(
  res: RepoResult,
  raw: TrivyVuln[],
  repo: RepoInfo,
  fixPrsEnabledFlag: boolean,
  repoDir: string
): Promise<RepoResult> {
  res.trivyIds = raw.length;
  res.status = 'scanned';
  const ghEco = GH_ECOSYSTEM[repo.ecosystem as Ecosystem] ?? repo.ecosystem ?? 'npm';

  const advisoriesByPkg = new Map<string, AdvisoryHit[]>(); // key pkg — Advisory-Cache greift
  const fixed: PackageFinding[] = [];
  for (const v of raw) {
    const hits = await fetchAdvisories(ghEco, v.PkgName, v.InstalledVersion);
    advisoriesByPkg.set(v.PkgName, hits);
    if (hits.length === 0) {
      // trivy-only (z. B. NVIDIA-/OS-Feed ohne GH-Advisory) immer noch anzeigen
      if (v.Severity === 'HIGH' || v.Severity === 'CRITICAL') {
        fixed.push({
          pkg: v.PkgName,
          version: v.InstalledVersion,
          severity: v.Severity.toLowerCase() as 'high' | 'critical',
          devOnly: false,
          advisory: null,
          ecosystem: ghEco,
        });
      }
    }
  }

  // Dedupe je pkg+version: alle VULN-Referenzen pro Package sammeln
  for (const [pkg, hits] of advisoriesByPkg) {
    if (hits.length === 0) continue;
    const versions = new Set(
      raw.filter((v) => v.PkgName === pkg).map((v) => v.InstalledVersion)
    );
    for (const version of versions) {
      for (const h of hits) {
        fixed.push({
          pkg,
          version,
          severity: h.severity as 'high' | 'critical',
          devOnly: false,
          advisory: h,
          ecosystem: ghEco,
        });
      }
    }
  }

  // ein Package-Matching nur 1× je Advisory-Rangliste: dedupe nach pkg+version+ghsaRange
  const seen = new Set<string>();
  res.findings = fixed.filter((f) => {
    const key = `${f.pkg}|${f.version}|${f.advisory?.ghsa ?? 'trivy'}|${f.advisory?.range ?? ''}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  markDevOnly(res, repoDir);
  if (res.findings.length > 0 && llmEnabled()) await applyTriage(res);

  if (fixPrsEnabledFlag) {
    // Fix-PR: pro Advisory verwertbare Fix-Version (first_patched) zusammenfassen;
    // LLM-suppressed Findings (suppress + confidence >= 0.75) → aus PR ausgenommen
    const findings = new Map<string, FixFinding>();
    for (const f of res.findings) {
      if (isSuppressed(f)) continue;
      if (!f.advisory?.firstPatched) continue;
      const cur = findings.get(f.pkg);
      if (cur) {
        if (!cur.ghsas.includes(f.advisory.ghsa)) cur.ghsas.push(f.advisory.ghsa);
        if (!cur.summary && f.advisory.summary) cur.summary = f.advisory.summary;
        // höchste Patch-Version erhöhen
        if (f.advisory.firstPatched.localeCompare(cur.patched ?? '', undefined, { numeric: true }) > 0 && f.advisory.firstPatched) {
          cur.patched = f.advisory.firstPatched;
        }
      } else {
        findings.set(f.pkg, {
          pkg: f.pkg,
          version: f.version,
          patched: f.advisory.firstPatched,
          ghsas: [f.advisory.ghsa],
          severity: f.advisory.severity,
          summary: f.advisory.summary,
        });
      }
    }
    if (repo.ecosystem && findings.size > 0 && (res.trivyIds ?? 0) > 0) {
      res.fixPr = await createFixPr(repo, repo.ecosystem, [...findings.values()]);
    }
  }

  return res;
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

function collectFindings(report: TrivyResult, eco: Ecosystem): TrivyVuln[] {
  const out: TrivyVuln[] = [];
  for (const result of report.Results ?? []) {
    for (const v of result.Vulnerabilities ?? []) {
      if (v.Severity === 'HIGH' || v.Severity === 'CRITICAL') out.push(v);
    }
  }
  void eco;
  const seen = new Set<string>();
  return out.filter((v) => {
    const key = `${v.VulnerabilityID}|${v.PkgName}|${v.InstalledVersion}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function renderMarkdown(report: Report): string {
  const summaryLine =
    `*Repos*: ${report.summary.reposTotal} total / ${report.summary.scanned} gescannt · ` +
    `high/critical-Advisory-Funde: ${report.summary.findings} · LLM-suppressed: ${report.summary.suppressed} · ` +
    `Fix-PRs: ${report.summary.fixPrs} · GitHub-API-Calls: ${report.summary.apiCalls}`;
  const lines: string[] = [
    `# CVE-Audit-Report (mayraost)`,
    '',
    `*Generated*: ${report.generatedAt}`,
    summaryLine,
    '',
  ];
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
    lines.push('');
  }
  return lines.join('\n');
}

async function sendTelegramFromReport(report: Report): Promise<void> {
  const date = parseIsoDateKey(new Date(report.generatedAt));
  const title = `🔐 CVE-Audit ${date} (mayraost)`;
  const body = telegramBody(report);
  await sendTelegramReport(title, body);
}

function telegramBody(report: Report): string {
  const lines: string[] = [];
  const totalCount = report.repos.reduce((n, r) => n + r.findings.length, 0);
  const suppressedCount = report.repos.reduce((n, r) => n + r.findings.filter(isSuppressed).length, 0);
  const withFinds = report.repos.filter((r) => r.findings.some((f) => !isSuppressed(f)));

  if (withFinds.length === 0) {
    lines.push('✅ Keine high/critical-Security-Advisories gefunden.');
  }
  for (const r of withFinds) {
    const visible = r.findings.filter((f) => !isSuppressed(f));
    lines.push(`*${r.name}* (${r.ecosystem ?? '?'}, ${visible.length} Funde):`);
    for (const f of visible) {
      const fix = f.advisory?.firstPatched ? `→ fix: ${f.advisory.firstPatched}` : '→ keine Fix-Info';
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
  return lines.join('\n\n');
}

function trim(s: string, max: number): string {
  return s.length > max ? `${s.slice(0, max - 1)}…` : s;
}

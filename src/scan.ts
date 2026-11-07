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
import { openDigestSession } from './digest-cache.js';
import { collectPinning, createPinsPr, type PinFinding } from './pinning.js';
import {
  ageDays,
  entriesForRepo,
  isKnownFinding,
  isNovelImageVuln,
  loadState,
  markImageVulnsReported,
  reconcileRepo,
  saveState,
  upsertEntry,
  type State,
  type StateFinding,
} from './state.js';
import { sendTelegramReport } from './telegram.js';
import { llmEnabled, triageFindings, type TriageDecision, type TriageInput } from './llm.js';
import { eligibilityBadge } from './soaking.js';

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
  /** Pinning-Scan (v1.5.0): floating npm-specs je package.json (kein CVE). */
  pins?: PinFinding[];
  pinsPr?: FixResult;
}

export interface ReminderInfo {
  repo: string;
  prUrl: string;
  prNumber: number;
  ageDays: number;
  createdAt: string;
  findings: StateFinding[]; // offene CVEs (ghsaId + package) laut State-Eintrag
}

/**
 * Image-Vuln-Finding (v1.5.2): Base-Image-CVEs je Repo+Image, aggregiert über
 * alle Repos — eigene, gezählte Findings statt nur Tabellenzeile. Nur Einträge
 * mit high+critical > 0.
 */
export interface ImageVulnFinding {
  repo: string;
  image: string;
  sourceFiles: string[];
  high: number;
  critical: number;
  /**
   * v1.6.2: ehrliche Empfehlung statt pauschalem "Rebuild". Bei einem
   * beweglichen Tag (`digestChanged === true`) zieht ein Rebuild einen neuen
   * Digest; bei stabilem/unbekanntem Tag hilft nur ein neuer Tag.
   */
  digestChanged?: boolean;
  digest?: string | null;
  previousDigest?: string | null;
  /** v1.6.3: es gibt einen neueren Tag auf der Registry (Pin hochziehen hilft). */
  updateAvailable?: boolean;
  /** v1.6.3: neuestes Upstream-GitHub-Release (Info, wenn kein Image publiziert). */
  upstreamLatest?: string | null;
}

/**
 * Empfehlungszeile für gepinnte Images mit CVEs (v1.6.2). Bisher stand hier
 * pauschal "Rebuild/Base-Image aktualisieren" — bei einem unveränderlichen
 * exakten Tag bringt ein Rebuild aber nichts (Owner-Feedback Prod-Report
 * 2026-11-07).
 */
export function imageVulnAdvice(
  f: Pick<ImageVulnFinding, 'digestChanged' | 'updateAvailable' | 'upstreamLatest'>
): string {
  // 1) Beweglicher Tag: Rebuild zieht den aktuellen Digest.
  if (f.digestChanged) return 'Tag beweglich, Rebuild zieht neuen Digest';
  // 2) Neuerer Tag existiert: Pin nachziehen.
  if (f.updateAvailable) return 'Pin auf neueren Tag erhöhen';
  // 3) Release existiert, aber kein Image: warten, nichts tun.
  if (f.upstreamLatest) return `nur Release ${f.upstreamLatest}, kein neueres Image — abwarten`;
  // 4) Nichts verfügbar: ehrlich sagen, statt zum Handeln zu drängen.
  return 'keine neuere Version verfügbar — CVEs im Base-Image';
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
    imagePrs: number; // Image-Tag-Pin-PRs (v1.4.0, Floating-Pin-Enforcement)
    pinsPrs: number; // npm-Pins-PRs (v1.5.0, package.json exact-pin Enforcement)
    unpinned: number; // alle observed floatingSpecifier (deps+dev+optional+peer)
    apiCalls: number;
    reminders: number; // offene Fix-PRs (Reminder-Sektion)
    imageVulns: { high: number; critical: number; images: number }; // Summe Base-Image-CVEs
    /** v1.7.0: Vorschläge aus der Renovate-Analyse (separat von `unpinned`). */
    renovateUpdates?: number;
  };
  reminders: ReminderInfo[]; // offene CVE-Fix-PRs (⏰-Sektion)
  pinsReminders: ReminderInfo[]; // offene Pins-PRs (📌-Sektion, findings leer) — JEDEN Lauf erwähnen
  imageVulnFindings: ImageVulnFinding[]; // Base-Image-CVEs (v1.5.2), sortiert crit/high/image
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
  // Digest-Cache (v1.6.2): belegter Vergleich der Manifest-Digests je Ref
  // (beweglicher Tag vs. unveränderlicher Pin). Wird erst NACH erfolgreichem
  // Lauf geschrieben (wie state.json) — kein Write in finally.
  const digestSession = openDigestSession();

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
          const img = await scanRepoImages(repo, repoDir, scanTmp, trivyAvailable, digestSession);
          res.images = img.findings;
          if (opts.fixPrs && img.bumpPlan.length > 0) {
            res.imagePr = await createImagePr(repo, img.bumpPlan, state);
          }
        } catch (ierr) {
          const imsg = ierr instanceof Error ? ierr.message : String(ierr);
          log(`WARN: Image-Scan für ${repo.name} fehlgeschlagen: ${imsg}`);
        }
        // Pinning-Scan (v1.5.0): package.json-Specifier exakt? Floating-DEPS
        // (deps/devDeps) → Pins-PR (alle Manifests, EIN PR). optional/peer nur
        // report-only. KEIN LLM (deterministisch, keine Triage).
        try {
          const pin = await collectPinning(repo, repoDir);
          res.pins = pin.findings;
          if (opts.fixPrs && pin.fixable.length > 0) {
            res.pinsPr = await createPinsPr(repo, pin.fixable, state);
          }
        } catch (perr) {
          const pmsg = perr instanceof Error ? perr.message : String(perr);
          log(`WARN: Pinning-Scan für ${repo.name} fehlgeschlagen: ${pmsg}`);
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

  // Digest-Cache persistieren (90-Tage-Prune + Write), nur wenn der Lauf bis
  // hierhin kam — Throws aus dem Loop landen gar nicht erst hier.
  digestSession.save();

  const imageVulns = collectImageVulnFindings(results);
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
      pinsPrs: results.filter((r) => r.pinsPr?.status === 'created').length,
      unpinned: results.reduce((n, r) => n + (r.pins?.length ?? 0), 0),
      renovateUpdates: results.reduce(
        (n, r) => n + (r.pins?.filter((p) => p.source === 'renovate').length ?? 0),
        0
      ),
      apiCalls: ghStats.apiCalls,
      reminders: collectReminders(state).length,
      imageVulns: {
        high: imageVulns.reduce((n, f) => n + f.high, 0),
        critical: imageVulns.reduce((n, f) => n + f.critical, 0),
        images: imageVulns.length,
      },
    },
    reminders: collectReminders(state),
    pinsReminders: collectPinsReminders(state),
    imageVulnFindings: imageVulns,
    repos: results,
  };

  // State persistieren (lastSeen-Updates + ggf. neu angelegte PR-Einträge).
  // imageVulns-Register wird bewusst HIER NOCH NICHT fortgeschrieben — erst
  // nach erfolgreichem Telegram-Versand (sendTelegramFromReport), sonst gingen
  // Novel-Findings bei Telegram-Fehler/Deploy-Neustart verloren.
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

  if (opts.sendTelegram) await sendTelegramFromReport(report, state, opts.fixPrs);
  return report;
}

/**
 * Base-Image-CVEs (v1.5.2) als eigene Findings: je Repo+Image nur Einträge mit
 * high+critical > 0, sortiert absteigend nach (critical, high, image).
 * Reine Projektion der Image-Scan-Ergebnisse — keine Zusatz-Calls.
 */
export function collectImageVulnFindings(repos: RepoResult[]): ImageVulnFinding[] {
  const out: ImageVulnFinding[] = [];
  for (const r of repos) {
    for (const f of r.images ?? []) {
      const high = f.vulns.high;
      const critical = f.vulns.critical;
      if (high + critical === 0) continue;
      out.push({
        repo: r.name,
        image: f.image,
        sourceFiles: [...f.sourceFiles],
        high,
        critical,
        digestChanged: f.digestChanged ?? false,
        digest: f.digest ?? null,
        previousDigest: f.previousDigest ?? null,
        // v1.6.3: Signale für die ehrliche Empfehlung — ohne diese beiden weiß
        // die 🛡-Zeile nicht, ob überhaupt eine neuere Version existiert.
        updateAvailable: f.updateAvailable ?? false,
        upstreamLatest: f.upstreamLatest ?? null,
      });
    }
  }
  return out.sort(
    (a, b) =>
      b.critical - a.critical ||
      b.high - a.high ||
      a.image.localeCompare(b.image) ||
      a.repo.localeCompare(b.repo)
  );
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

/** Offene CVE-Fix-PRs aus dem reconciled State → Reminder-Infos (Alt in Tagen). */
function collectReminders(state: State, now = new Date()): ReminderInfo[] {
  const out: ReminderInfo[] = [];
  for (const [repo, entries] of Object.entries(state.prs)) {
    for (const entry of entries) {
      // Image-PRs: kein Reminder; Pins-PRs: eigene Reminder-Sektion (collectPinsReminders).
      if (entry.kind && entry.kind !== 'cve') continue;
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

/**
 * Offene Pins-PRs (kind 'pins') → eigene Reminder-Infos. Anders als Image-PRs
 * JEDEN Lauf sichtbar erwähnen, solange der PR offen ist (statt nur im
 * Erst-Erfassungs-Lauf). findings sind im Pins-Entry leer —
 * es gibt kein floating-dep-Count-Feld im State; Zähler daher entfallen.
 */
function collectPinsReminders(state: State, now = new Date()): ReminderInfo[] {
  const out: ReminderInfo[] = [];
  for (const [repo, entries] of Object.entries(state.prs)) {
    for (const entry of entries) {
      if (entry.kind !== 'pins') continue;
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
  const iv = report.summary.imageVulns;
  // Image-Vuln-Zähler nur bei > 0 — bestehende Optik nicht aufblähen.
  const imageVulnPart = iv.images > 0 ? ` · Image-Vulns: H${iv.high}/C${iv.critical} (${iv.images} Images)` : '';
  const summaryLine =
    `*Repos*: ${report.summary.reposTotal} total / ${report.summary.scanned} gescannt · ` +
    `high/critical-Advisory-Funde: ${report.summary.findings} · LLM-suppressed: ${report.summary.suppressed} · ` +
    `Fix-PRs: ${report.summary.fixPrs}` +
    `${report.summary.imagePrs ? ` (+${report.summary.imagePrs} Image)` : ''}` +
    `${report.summary.pinsPrs ? ` (+${report.summary.pinsPrs} Pins)` : ''} · ` +
    `unpinned deps: ${report.summary.unpinned} · ` +
    `${report.summary.renovateUpdates ? `Renovate-Vorschläge: ${report.summary.renovateUpdates} · ` : ''}` +
    `offene Fix-PRs (Reminder): ${report.summary.reminders}` +
    `${imageVulnPart} · ` +
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
  if (report.imageVulnFindings.length > 0) {
    // 🛡-Sektion im MD-Report (v1.6.2): Base-Image-CVEs mit ehrlicher
    // Empfehlung — Rebuild nur bei bewegtem Tag, sonst Pin auf neuen Tag.
    lines.push('## 🛡 Image-Vulns (Base-Image)', '');
    lines.push('| Repo | Image | Vulns H/C | Empfehlung |', '|---|---|---|---|');
    for (const f of report.imageVulnFindings) {
      lines.push(`| ${f.repo} | ${f.image} | H${f.high}/C${f.critical} | ${imageVulnAdvice(f)} |`);
    }
    lines.push('');
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
    if (r.pinsPr?.prUrl) lines.push('', `Pins-PR: ${r.pinsPr.prUrl} (${r.pinsPr.status})`);
    if (r.images?.length) lines.push('', imageTable(r.images));
    if (r.pins?.length) lines.push('', pinningTable(r.pins));
    lines.push('');
  }
  return lines.join('\n');
}

/** 📌-Sektion je Repo (Report-MD): floating npm-Specifier (v1.5.0 Enforcement). */
function pinningTable(pins: PinFinding[]): string {
  const rows = pins.map((p) => {
    // v1.6.0: Soaking-Status (reif / zu jung) + Beta-Hinweis (nur Info).
    const soak = p.eligibility
      ? eligibilityBadge({ eligibility: p.eligibility, ageDays: p.ageDays ?? null, label: p.eligibilityLabel ?? '' })
      : '—';
    const beta = p.prereleaseHint
      ? `ℹ️ ${p.prereleaseHint} (${p.prereleaseLabel ?? '?'})`
      : '—';
    // v1.7.0: Quelle sichtbar machen (floating-Pin vs. Renovate-Analyse).
    const src = p.source === 'renovate' ? (p.majorOrBreaking ? 'rnv (major)' : 'renovate') : 'pin';
    return `| ${p.pkg} | ${p.current} | ${p.latest ?? '—'} | ${p.section} | ${p.severity} | ${soak} | ${beta} | ${src} |`;
  });
  return [
    '### 📌 Unpinned deps (package.json) — Floating-Specifier',
    '| Package | Current | Latest exact | Scope | Sev | Soaking | Beta/RC | Src |',
    '|---|---|---|---|---|---|---|---|',
    ...rows,
  ].join('\n');
}

/**
 * v1.6.3: Upstream-Release neuer als der Tag, aber KEIN neuerer Registry-Tag
 * (Registry und Release laufen auseinander — z. B. playwright-mcp: Release
 * v0.0.84 da, MCR-Image fehlt). Reine Report-Information, kein Telegram-Trigger.
 */
export function upstreamNewerOnly(
  f: Pick<ImageFinding, 'note' | 'updateAvailable' | 'floating' | 'exactPin' | 'upstreamLatest'>
): boolean {
  return (
    !f.note &&
    !f.updateAvailable &&
    !(f.floating && f.exactPin) &&
    typeof f.upstreamLatest === 'string' &&
    f.upstreamLatest.length > 0
  );
}

/** 🐳-Sektion je Repo (Report-MD): nur Images mit vulns/update/note. */
function imageTable(images: ImageFinding[]): string {
  const rows: string[] = [];
  for (const f of images) {
    const vc = `H${f.vulns.high}/C${f.vulns.critical}`;
    // v1.6.0: Soaking-Status ("reif (5d)" / "zu jung (2d)" / "CVE-Fix, sofort").
    const soak = f.eligibility
      ? eligibilityBadge({ eligibility: f.eligibility, ageDays: f.ageDays ?? null, label: f.eligibilityLabel ?? '' })
      : '';
    if (f.note) {
      rows.push(`| ${f.image} | — | — | — | ${f.note} |`);
    } else if (f.updateAvailable) {
      const status =
        f.eligibility === 'too-young'
          ? `⏳ update verfügbar, aber ${f.eligibilityLabel}`
          : `⚠️ update verfügbar${soak ? ` (${soak})` : ''}`;
      rows.push(`| ${f.image} | ${f.current} | ${f.newestSameMajor} | ${vc} | ${status} |`);
    } else if (f.floating && f.exactPin) {
      const status =
        f.eligibility === 'too-young'
          ? `floating → pin ${f.exactPin} (⏳ ${f.eligibilityLabel})`
          : `floating → pin ${f.exactPin}`;
      rows.push(`| ${f.image} | ${f.current} | ${f.exactPin} | ${vc} | ${status} |`);
    } else if (f.variantDrift) {
      // v1.6.0: semver-gleicher Tag mit anderer OS-Basis (pg17 → pg17-trixie,
      // slim → slim-bookworm). Kein Bump/PR — nur Sichtbarkeit im Report.
      rows.push(`| ${f.image} | ${f.current} | — | ${vc} | variant drift: ${f.variantDrift} |`);
    } else if (upstreamNewerOnly(f)) {
      // v1.6.3: Registry hat nichts Neueres, das Upstream-Release schon —
      // hier KEIN "aktuell" mehr (Registry-Tags sind nicht die Release-Wahrheit).
      rows.push(
        `| ${f.image} | ${f.current} | — | ${vc} | ` +
          `ℹ️ Release ${f.upstreamLatest} existiert, kein Image publiziert${f.upstreamNote ? ` (${f.upstreamNote})` : ''} |`
      );
    } else {
      // v1.6.2: Digest-Vergleich belegt, ob ein Rebuild überhaupt etwas zieht.
      const digestPart =
        f.digestChanged === true
          ? ' · Tag beweglich (Rebuild zieht neuen Digest)'
          : '';
      rows.push(
        `| ${f.image} | ${f.current} | ${f.newestSameMajor ?? '—'} | ${vc} | ` +
          (f.pinned
            ? `pinned, aktuell${digestPart}`
            : `floating (Rebuild${f.digestChanged === true ? ' zieht neuen Digest' : ' aktualisiert'})`) + ' |'
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

/**
 * Novel Image-Vulns (v1.5.2): Findings, deren (high, critical) sich vom State-
 * Register unterscheiden ODER die im Register fehlen. State = undefined/leer
 * (erster Lauf, ENABLE_FIX_PRS=0) → ALLE Findings sind novel (nur Report,
 * kein State-Write).
 */
export function novelImageVulns(
  report: Report,
  state: State | undefined
): Array<ImageVulnFinding & { novel: true }> {
  return report.imageVulnFindings
    .filter((f) => !state || isNovelImageVuln(state, f.repo, f.image, f.high, f.critical))
    .map((f) => ({ ...f, novel: true as const }));
}

async function sendTelegramFromReport(report: Report, state: State, fixPrs: boolean): Promise<void> {
  const date = parseIsoDateKey(new Date(report.generatedAt));
  // Novel-Register nur mit echtem State (ENABLE_FIX_PRS=1) — sonst alle novel.
  const novel = novelImageVulns(report, fixPrs ? state : undefined);
  const hasNew =
    report.repos.some((r) => r.findings.some((f) => !isSuppressed(f))) ||
    report.repos.some((r) => r.images?.some((i) => i.updateAvailable) ?? false) ||
    // Base-Image-CVEs zählen nur, wenn SIE neu sind/ihre Zahl sich geändert hat.
    novel.length > 0 ||
    // Neue Pins-PRs / neue exakte Image-Pinning-Bumps zählen als "neu" (v1.5.0)
    report.repos.some((r) => r.pinsPr?.status === 'created') ||
    report.repos.some((r) => r.imagePr?.status === 'created');
  const hasReminders = report.reminders.length > 0 || report.pinsReminders.length > 0;
  if (!hasNew && !hasReminders) {
    // Keine neuen Funde UND keine offenen Fix-PRs → gar kein Versand (kein Spam).
    log('Telegram skip: keine neuen Findings und keine offenen Fix-PRs — kein Versand.');
    return;
  }
  const title = `🔐 CVE-Audit ${date} (mayraost)`;
  const body = telegramBody(report, hasNew, novel);
  const sent = await sendTelegramReport(title, body);
  // Register erst NACH erfolgreichem Versand fortschreiben und sofort
  // persistieren — sonst würde ein Telegram-Fehler die Novel-Meldung beim
  // nächsten Lauf verschlucken (ohne Fix-PRs: kein State, kein Write).
  if (sent && novel.length > 0) {
    for (const repo of new Set(novel.map((n) => n.repo))) {
      markImageVulnsReported(
        state,
        repo,
        novel.filter((n) => n.repo === repo).map((n) => ({ image: n.image, high: n.high, critical: n.critical }))
      );
    }
    if (fixPrs) saveState(state);
  }
  if (!sent) log('WARN: Telegram-Versand fehlgeschlagen — Image-Vuln-Register NICHT fortgeschrieben (nächster Lauf meldet erneut).');
}


/** Reminder-Sektion: offene CVE-Fix-PRs + offene Pins-PRs (Alt in Tagen, kompakt). */
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
  // Pins-PRs NACH der CVE-Reminder-Sektion, eigener Zeilentyp (kein ⏰-Mix).
  for (const rem of report.pinsReminders) {
    lines.push(`📌 Pins-PR offen (floating deps): *${rem.repo}* → ${rem.prUrl} (seit ${rem.ageDays} Tagen)`);
  }
  if (lines.length > 0 && lines.at(-1) === '') lines.pop();
  return lines;
}

/** Max. Zeilen in der 🛡-Sektion; Rest wird zu "… +N weitere (Report)". */
export const IMAGE_VULN_TELEGRAM_MAX_LINES = 15;

/**
 * 🛡-Sektion "Image-Vulns (Base-Image)" (v1.5.2): NUR die novel Image-Vulns
 * (neue H/C-Zahl je Repo+Image), gruppiert je Repo, gekappt auf
 * IMAGE_VULN_TELEGRAM_MAX_LINES Zeilen. Leer wenn keine novel Einträge.
 * Empfehlung je Zeile (v1.6.2) aus imageVulnAdvice — kompakt (< 120 Zeichen).
 */
export function imageVulnLines(
  novel: Array<Pick<ImageVulnFinding, 'repo' | 'image' | 'high' | 'critical' | 'digestChanged'>>
): string[] {
  if (novel.length === 0) return [];
  const lines: string[] = [];
  let shown = 0;
  for (const repo of [...new Set(novel.map((n) => n.repo))]) {
    const entries = novel.filter((n) => n.repo === repo);
    if (shown >= IMAGE_VULN_TELEGRAM_MAX_LINES) break;
    lines.push(`*${repo}*:`);
    for (const e of entries) {
      if (shown >= IMAGE_VULN_TELEGRAM_MAX_LINES) break;
      const advice = e.digestChanged === true
        ? '→ Tag beweglich, Rebuild zieht neuen Digest'
        : '→ Pin auf neueren Tag erhöhen (Rebuild hilft nicht)';
      lines.push(trim(`  • ${e.image} [H${e.high}/C${e.critical}] ${advice}`, 120));
      shown++;
    }
    lines.push('');
  }
  const rest = novel.length - shown;
  if (rest > 0) lines.push(`  … +${rest} weitere (Report)`);
  while (lines.at(-1) === '') lines.pop();
  return lines;
}

export function telegramBody(
  report: Report,
  hasNewFindings: boolean,
  novelImageVulns: Array<Pick<ImageVulnFinding, 'repo' | 'image' | 'high' | 'critical' | 'digestChanged'>> = []
): string {
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
    lines.push('✅ Keine neuen high/critical-Advisories in Lockfile-Dependencies (npm/pip/go).');
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
  // 🐳 Image-Sektion: nur relevante Einträge — Update verfügbar, floating
  // 🐳 Image-Sektion: nur ECHTE Handlungspunkte — Update verfügbar oder floating
  // (Pin-Enforcement/„Rebuild aktualisiert"). variantDrift (v1.6.1) ist bewusst
  // NICHT mehr drin: semver-gleicher Tag mit anderer OS-Basis ist kein Update
  // und war reines Rauschen (Prod-Alert 2026-11-07). Steht nur im Report.
  // Pinned+aktuelle Images sind ebenfalls raus (→ 🛡-Sektion für CVEs).
  // v1.6.3: upstreamNewerOnly (Release existiert, Image fehlt) ist ebenfalls
  // KEIN Handlungspunkt → löst keinen Versand aus; wenn der Alert aber ohnehin
  // rausgeht, bekommt das Repo seine Zeile (ehrlicher als "aktuell").
  const imgRepos = report.repos.filter(
    (r) =>
      !!r.imagePr?.prUrl ||
      r.images?.some((i) => !i.note && (i.updateAvailable || i.floating || upstreamNewerOnly(i)))
  );
  if (imgRepos.length > 0) {
    lines.push('🐳 Image-Scan (Dockerfile/compose):');
    for (const r of imgRepos) {
      lines.push(`*${r.name}*:`);
      for (const f of r.images!) {
        // skip: unscannable (note), pinned+aktuell und reiner variantDrift —
        // nur echte Handlungspunkte (Update/floating) plus v1.6.3 die
        // Release-ohne-Image-Info kommen in den Alert.
        if (f.note || (!f.updateAvailable && !f.floating && !upstreamNewerOnly(f))) continue;
        const vc = `H${f.vulns.high}/C${f.vulns.critical}`;
        // v1.6.0 Soaking: zu junge Kandidaten werden im Alert NICHT als Aktion
        // gezeigt (nur Report) — Package-Poisoning-Schutz.
        if (f.updateAvailable && f.eligibility === 'too-young') {
          lines.push(`  • ${f.image} → ${f.newestSameMajor} ⏳ ${f.eligibilityLabel} (Report) [${vc}]`);
        } else if (f.updateAvailable) {
          const badge = f.eligibility === 'cve-exempt' ? ' 🔴 CVE-Fix' : '';
          lines.push(`  • ${f.image} → ${f.newestSameMajor} ⚠️ update verfügbar${badge} [${vc}]`);
        } else if (f.floating && f.exactPin) {
          const badge = f.eligibility === 'too-young' ? ` ⏳ ${f.eligibilityLabel}` : '';
          lines.push(`  • ${f.image} → pin ${f.exactPin}${badge} [${vc}]`);
        } else if (upstreamNewerOnly(f)) {
          // v1.6.3: NICHT "aktuell" — Release da, Image fehlt (kein Trigger).
          lines.push(`  • ${f.image} [${vc}] — ℹ️ Release ${f.upstreamLatest} existiert, kein Image publiziert`);
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
  // ℹ️ Beta-Hinweise (v1.6.0, N2): NUR für Pakete, die bereits auf einem
  // Beta/RC-Kanal liegen — keine "es gibt eine Beta"-Werbung für stabile Pakete.
  // Zusätzlich muss der Kandidat die Soaking-Reife haben (kein Rauschen).
  const betaLines: string[] = [];
  for (const r of report.repos) {
    const betas = (r.pins ?? []).filter(
      (p) => p.prereleaseHint && p.prereleaseEligibility === 'eligible'
    );
    if (betas.length === 0) continue;
    betaLines.push(`*${r.name}*:`);
    for (const p of betas) {
      betaLines.push(`  • ${p.pkg} ${p.current} → ${p.prereleaseHint} (${p.prereleaseLabel ?? '?'})`);
    }
  }
  if (betaLines.length > 0) {
    lines.push(['ℹ️ Beta/RC-Updates (Paket bereits im Beta-Kanal):', ...betaLines].join('\n'));
    lines.push('');
  }
  // 🛡 Base-Image-Vulns (v1.5.2) — SEPARAT von der 🐳-Sektion: hier landen die
  // CVEs gepinnter+aktueller Images, die oben bewusst gefiltert werden. Nur
  // NOVEL-Einträge (State-Register), damit kein Spam bei jedem Lauf.
  const ivLines = imageVulnLines(novelImageVulns);
  if (ivLines.length > 0) {
    lines.push(['🛡 Image-Vulns (Base-Image):', ...ivLines].join('\n'));
    lines.push('');
  }
  // Nur echte Fehler erwähnen — skipped-Repos (z. B. kein scanbares Manifest)
  // sind normal und erzeugen sonst nur Rauschen.
  const unscannable = report.repos.filter(
    (r) => r.status === 'error' || r.status === 'trivy-missing'
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
    for (const r of imgFixed) {
      lines.push(`🐳 Image-Pin-PR (floating image tag): *${r.name}* → ${r.imagePr!.prUrl}`);
    }
  }
  const pinsFixed = report.repos.filter((r) => r.pinsPr?.status === 'created');
  if (pinsFixed.length > 0) {
    for (const r of pinsFixed) {
      lines.push(`📌 Pins-PR (floating deps): *${r.name}* → ${r.pinsPr!.prUrl}`);
    }
  }
  return lines.join('\n\n');
}

function trim(s: string, max: number): string {
  return s.length > max ? `${s.slice(0, max - 1)}…` : s;
}

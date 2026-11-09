// CLI-Einstieg: audit-scanner [scan|inventory|test-telegram|notify-failure]

import { CRON_SCHEDULE, fixPrsEnabled, log } from './config.js';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import semver from 'semver';
import {
  newestExactTag,
  newestSameMajorTag,
  replaceTag,
  isSecurityToolBump,
  strictlyNewer,
  tagSemantics,
  variantDriftTag,
} from './image-scan.js';
import { channelCompatible, classifyPrerelease } from './prerelease.js';
import {
  latestStableRelease,
  registryTagCandidates,
  releaseIsNewer,
  upstreamReleaseCheck,
  upstreamRepoFor,
  type GhRelease,
} from './release-check.js';
import { isPinnedPrereleaseSpec, renovateToPinFindings } from './pinning.js';
import { parseRenovateLog } from './renovate.js';
import { ageInDays, updateEligibility } from './soaking.js';
import { loadInventory } from './inventory.js';
import { llmEnabled, triageFindings, type TriageInput } from './llm.js';
import {
  IMAGE_VULN_TELEGRAM_MAX_LINES,
  collectImageVulnFindings,
  imageVulnAdvice,
  imageVulnLines,
  novelImageVulns,
  runScan,
  telegramBody,
  upstreamNewerOnly,
  type Report,
  type RepoResult,
} from './scan.js';
import type { ImageFinding } from './image-scan.js';
import {
  ageDays,
  isKnownFinding,
  loadState,
  markImageVulnsReported,
  parseState,
  prOpenStatus,
  upsertEntry,
  type State,
} from './state.js';
import { sendTelegramReport } from './telegram.js';
import { failureNotifyTest } from './failure-notify-test.js';
import { notifyScanFailure, renderFailureMessage } from './failure-notify.js';
import {
  loadDigestCache,
  openDigestSession,
  parseDigestCache,
  pruneDigestCache,
  type DigestCache,
} from './digest-cache.js';

function usage(): never {
  process.stdout.write(`audit-scanner — Nightly CVE-Scan der mayraost-Repos

  ${'$'} audit-scanner <COMMAND>

COMMANDS
  scan          Inventar + tarball + trivy fs + Advisories + (opt) Fix-PRs + Telegram
                Fix-PRs nur mit ENABLE_FIX_PRS=1; Repos via SKIP_REPOS oder
                repo-lokaler Datei .cve-audit-skip ausklammerbar.
                scan --only=repo1,repo2: nur diese Repos scannen (Probe-Lauf,
                Full-Scan-Zeit sparen; Report suffixed als report.only-<repos>.md
                — Tages-Full-Report unangetastet; state/Telegram-Flow unverändert).
  inventory     Nur Inventarlisting (Repos + erkannte Manifests/Ökosysteme).
  test-telegram 1 Test-Nachricht via TELEGRAM_BOT_TOKEN/TELEGRAM_CHAT_ID senden.
  notify-failure  Fehlschlag-Alarm (v1.7.4): Telegram-Nachricht "⚠️ CVE-Audit
                FEHLGESCHLAGEN" mit rc, UTC-Zeitpunkt, Host + Log-Tail.
                Aufruf aus bin/scan-wrapper.sh im else-Zweig:
                  notify-failure --rc <rc> [--log <datei>]
                Fehlende TELEGRAM_* ENV → Skip; Sende-Fehler → nur Warnung.
                Exit-Code bleibt immer 0 (der Wrapper reicht den Scan-rc aus).
  notify-failure-test  Render-Selbsttest des Fehlschlags-Alarms (rc/UTC/Host,
                Tail-Kappung, Secret-Redaktion) — kein Netzwerk, kein Versand.
  triage-test   LLM-Triage mit 2 Fake-Findings prüfen (kein Scan, kein Telegram).
  state-test    PR-Dedupe-State: parse/reconciliation-Selbsttest mit simulierten Entries,
                PR-Status-Check gegen mayraost/audit-scanner (Fake-Branch → kein offener
                PR erwartet). Keine echten PRs, kein Telegram-Versand.
  image-vulns-test  Image-Vuln-Findings/Novelty: synthetische Report-/State-Objekte,
                Legacy-state.json, H/C-Änderung, Telegram-🛡-Sektion + Kappung.
                Kein Scan, kein Telegram-Versand.
  image-freshness-test  Image-Tag-Freshness-Selbsttest (Variant-Token-Matching,
                newestSameMajor/newestExactTag/strictlyNewer/variantDrift) mit
                statischen Tag-Listen — kein Netzwerk, kein PR.
  soaking-test  Soaking (3-Tage-Regel) + Pre-Release-Klassifikation: reine
                Entscheidungsfunktionen mit fixer Fake-Uhr — kein Netzwerk.
                Prüft: 2d→too-young, 3d→eligible, CVE→sofort, Variant-Wechsel→
                rejected, unbekanntes Datum→fail-open, stable→beta VERBOTEN.
  digest-test   Digest-Cache (v1.6.2): korruptes digests.json → leerer Start,
                erster/zweiter Lauf (stabil) vs. geänderter Digest (beweglicher
                Tag), 90-Tage-Prune. Fake-Datei in tmp, kein Netzwerk.
  release-version-test  Upstream-Release-Check (v1.6.3): Registry-Tags sind nicht
                die Release-Wahrheit (playwright-mcp v0.0.84 released, MCR-Tag
                404). v1.7.1: Registry-Präfix ≠ Git-Präfix (trivy v0.76.2 vs
                Docker-Hub 0.76.2) → beide Kandidaten geprüft. Fake-Releases/
                -Manifeste, kein Netzwerk.
  pinning-test  Pins-PR-Qualität (v1.7.2) OFFLINE mit Fake-Registry/GitHub/
                Lockfile-Regen: Peer-Konflikt → Ausweichversion oder kein Pin,
                Regen-Fehler → kein Manifest-Commit im PR (fail-closed, Draft +
                ⚠️), kein [skip ci] in Commit-Messages, Image-Tag-Präfix-Flip
                (Docker Hub/MCR/Quay). Kein Netz, kein PR, kein Telegram.

ENV
  GH_TOKEN            Pflicht (Bearer für api.github.com). Dev-Fallback lokal:
                      \`gh auth token\` (gh-CLI), wenn GH_TOKEN fehlt — im Container
                      ist GH_TOKEN immer gesetzt.
  TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID   Telegram-Notify (optional, sonst Skip).
  ENABLE_FIX_PRS      "1" aktiviert Auto-Fix-PRs (Standard: aus).
  SKIP_REPOS          Kommagetrennte Repo-Skip-Liste.
  CRON_SCHEDULE       cron-String für busybox crond (Standard: ${CRON_SCHEDULE} UTC).
  TRIVY_BIN           trivy-Pfad (Standard: trivy im PATH).
  DEEPINFRA_API_KEY   LLM-Triage + LLM-PR-Bodies (optional; fehlt → "LLM disabled").
  LLM_MODEL           Default: zai-org/GLM-5.3-Flash.
  LLM_BASE_URL        Default: https://api.deepinfra.com/v1/openai.

`);
  process.exit(1);
}

async function main(): Promise<void> {
  const cmd = process.argv[2];
  // --only=repo1,repo2 → Inventarfilter (Probe-Lauf einzelner Repos ohne Full-Scan)
  const onlyArg = process.argv.slice(3).find((a) => a.startsWith('--only='));
  const onlyRepos = onlyArg
    ? onlyArg.slice('--only='.length).split(',').map((s) => s.trim()).filter(Boolean)
    : undefined;
  switch (cmd) {
    case 'scan': {
      if (onlyRepos) log(`scan --only=${onlyRepos.join(',')}`);
      const report = await runScan({
        sendTelegram: true,
        fixPrs: fixPrsEnabled(),
        onlyRepos,
      });
      log(
        `scan fertig: ${report.summary.scanned}/${report.summary.reposTotal} Repos gescannt, ` +
          `${report.summary.findings} high/critical, ${report.summary.fixPrs} Fix-PRs ` +
          `(+${report.summary.imagePrs} Image-PRs, +${report.summary.pinsPrs} Pins-PRs, ` +
          `${report.summary.unpinned} unpinned deps), ${report.summary.apiCalls} API-Calls.`
      );
      return;
    }
    case 'inventory': {
      const repos = await loadInventory();
      for (const r of repos) {
        const eco = r.ecosystem ?? '—';
        const flags: string[] = [r.private ? 'private' : 'public'];
        if (r.configSkip) flags.push(`skip(${r.skipSource})`);
        if (r.manifestPaths.length === 0 && !r.configSkip) flags.push('ohne Manifest');
        process.stdout.write(`${r.name.padEnd(24)} ${eco.padEnd(7)} branch=${r.defaultBranch.padEnd(8)} ${flags.join(', ')}\n`);
      }
      process.stdout.write(`→ ${repos.length} Repos\n`);
      return;
    }
    case 'test-telegram': {
      const ok = await sendTelegramReport('✅ audit-scanner Test-Report', body());
      process.exitCode = ok ? 0 : 2;
      return;
    }
    case 'notify-failure': {
      // Ausfall-Alarm (v1.7.4), aus bin/scan-wrapper.sh im else-Zweig. Bewusst
      // IMMER exit 0: der Wrapper reicht den Original-rc des Scans weiter, ein
      // kaputter Telegram-Versand darf den echten Fehler nicht überdecken.
      const args = process.argv.slice(3);
      const flag = (name: string): string | undefined => {
        const i = args.indexOf(`--${name}`);
        return i >= 0 ? args[i + 1] : undefined;
      };
      const rcArg = flag('rc') ?? null;
      const logArg = flag('log') ?? '';
      // Log-Tail: fehlende/unlesbare Datei ist kein Fehler → Platzhalter.
      let logText = '';
      if (logArg) {
        try {
          logText = fs.readFileSync(logArg, 'utf8');
        } catch (err) {
          const m = err instanceof Error ? err.message : String(err);
          log(`WARN: Fehlschlag-Alarm: Log ${logArg} nicht lesbar (${m}) — Tail entfällt.`);
        }
      }
      const details = { rc: rcArg, logText };
      if (process.env.NOTIFY_FAILURE_DRY_RUN === '1') {
        // Verifikation ohne Produktions-Chat: gerenderten Text auf stderr
        // ausgeben statt senden (keine KI, kein Netzwerk).
        process.stderr.write(`${renderFailureMessage(details)}\n`);
        return;
      }
      // False (ENV fehlt / Senden fehlgeschlagen) ist ok — notifyScanFailure
      // loggt selbst und wirft nie.
      await notifyScanFailure(details);
      return;
    }
    case 'notify-failure-test': {
      // Purer Render-Selbsttest des Fehlschlag-Alarms (v1.7.4): kein Netzwerk,
      // kein Telegram-Versand, kein Scan.
      process.exitCode = failureNotifyTest();
      return;
    }
    case 'state-test': {
      process.exitCode = await stateTest();
      return;
    }
    case 'image-freshness-test': {
      // Purer Selbsttest der Image-Freshness-Matching-Logik (v1.6.0):
      // kein Scan, kein Registry-Zugriff, kein PR, kein Telegram.
      process.exitCode = await imageFreshnessTest();
      return;
    }
    case 'image-vulns-test': {
      // Purer Selbsttest der Image-Vuln-Novelty (v1.5.2): synthetische
      // Report-/State-Objekte, kein Scan, kein Telegram-Versand.
      process.exitCode = imageVulnsTest();
      return;
    }
    case 'soaking-test': {
      // Purer Selbsttest von Soaking + Pre-Release-Klassifikation (v1.6.0):
      // fixe Fake-Uhr, kein Netzwerk, kein Scan.
      process.exitCode = soakingTest();
      return;
    }
    case 'renovate-test': {
      // Renovate-Parser + Lockfile-Abdeckung (v1.7.0): reines Fixture-Parsing,
      // kein Renovate-Aufruf, kein Netzwerk.
      process.exitCode = renovateTest();
      return;
    }
    case 'digest-test': {
      // Purer Selbsttest des Digest-Caches (v1.6.2): Fake-Datei in tmp,
      // fixe Fake-Uhr, kein Netzwerk, kein Scan.
      process.exitCode = digestTest();
      return;
    }
    case 'pinning-test': {
      // Pins-PR-Qualität (v1.7.2): Fake-Registry/GitHub/Regen injiziert,
      // kein Netzwerk, kein PR, kein Telegram.
      const { pinningTest } = await import('./pinning-test.js');
      process.exitCode = await pinningTest();
      return;
    }
    case 'release-version-test': {
      // Purer Selbsttest des Upstream-Release-Checks (v1.6.3): Fake-Releases +
      // Fake-Manifest-Antworten injiziert, kein Netzwerk, kein Scan.
      process.exitCode = await releaseVersionTest();
      return;
    }
    case 'triage-test': {
      // gibt die LLM-Entscheidung für 2 Fake-Findings aus (keine Secrets im Output)
      if (!llmEnabled()) {
        process.exitCode = 2; // DEEPINFRA_API_KEY fehlt
        return;
      }
      const fake: TriageInput[] = [
        {
          id: 'fake-repo|lodash|GHSA-0000-aaaa|4.17.15',
          repo: 'fake-repo',
          pkg: 'lodash',
          version: '4.17.15',
          vulnerableRange: '<4.17.21',
          severity: 'critical',
          ghsa: 'GHSA-0000-aaaa',
          summary: 'Prototype pollution in lodash',
          firstPatched: '4.17.21',
          devOnly: false,
        },
        {
          id: 'fake-repo|some-devtool|GHSA-0000-bbbb|1.0.0',
          repo: 'fake-repo',
          pkg: 'some-devtool',
          version: '1.0.0',
          vulnerableRange: '<1.0.1',
          severity: 'high',
          ghsa: 'GHSA-0000-bbbb',
          summary: 'ReDoS in a build-time formatter (devDependencies only)',
          firstPatched: '1.0.1',
          devOnly: true,
        },
      ];
      const decisions = await triageFindings(fake);
      process.stdout.write(JSON.stringify(Object.fromEntries(decisions), null, 2) + '\n');
      process.exitCode = decisions.size === fake.length ? 0 : 1;
      return;
    }
    default:
      usage();
  }
}

function body(): string {
  return [
    'Audit-Scanner: Telegram-Zugang konfiguriert.',
    'Dies ist eine Testnachricht vom `node dist/index.js test-telegram`.',
    'Enthält KEINE Repo-Daten — reine Config-Signalnachricht.',
  ].join('\n');
}

/**
 * Purer Selbsttest der State-/Dedupe-Logik (kein Scan, kein PR, kein Telegram):
 * 1) parseState tolerant: corrupt JSON → null; valid JSON → State.
 * 2) Dedupe-Matching: isKnownFinding rejex über simulierte Entries.
 * 3) PR-Status-Check gegen echtes Repo (mayraost/audit-scanner) mit Fake-Branch,
 *    der garantiert nicht existiert → { open:false } = "kein offener PR".
 * 4) loadState/saveState Roundtrip in REPORTS_DIR (echte state.json unangetastet
 *    lassen: nur schreiben, wenn noch keine existiert).
 */
async function stateTest(): Promise<number> {
  let ok = true;

  // 1 corrupt parse
  const corrupt = parseState('{ nicht-json <<<');
  process.stdout.write(`corrupt-parse: ${corrupt === null ? 'OK (null)' : 'FAIL'}\n`);
  ok &&= corrupt === null;

  // 1 valid parse
  const valid: State = {
    prs: {
      demo: [
        {
          branch: 'cve-audit/fixes-2099-01-01',
          prUrl: 'https://github.com/mayraost/demo/pull/1',
          prNumber: 1,
          ghsaIds: ['GHSA-0000-aaaa'],
          createdAt: new Date(Date.now() - 3 * 86_400_000).toISOString(),
          lastSeen: new Date().toISOString(),
          findings: [{ package: 'lodash', version: '4.17.15', severity: 'critical', ghsaId: 'GHSA-0000-aaaa' }],
        },
      ],
    },
  };
  const parsed = parseState(JSON.stringify(valid));
  process.stdout.write(`valid-parse: ${parsed?.prs.demo?.length === 1 ? 'OK' : 'FAIL'}\n`);
  ok &&= parsed?.prs.demo?.length === 1;

  // 2 dedupe matching
  const st: State = { prs: { demo: parsed?.prs.demo ?? [] } };
  const known = isKnownFinding(st, 'demo', 'LODASH', 'GHSA-0000-aaaa');
  const unknown = isKnownFinding(st, 'demo', 'lodash', 'GHSA-0000-bbbb');
  process.stdout.write(`dedupe known=${known ? 'OK' : 'FAIL'} unknown=${unknown ? 'FAIL' : 'OK'}\n`);
  ok &&= known && !unknown;

  // 2b upsert + age
  upsertEntry(st, 'demo', { ...st.prs.demo![0]!, prNumber: 2, branch: 'cve-audit/fixes-2099-01-02' });
  ok &&= st.prs.demo!.length === 2;
  const age = ageDays(st.prs.demo![0]!);
  process.stdout.write(`upsert/age: entries=2 ${age === 3 ? 'age=3d OK' : `age=${age}d (Tag-Differenz, ok wenn >=2)`}\n`);

  // 3 remote check gegen echtes Repo (Fake-Branch → kein offener PR)
  const status = await prOpenStatus('audit-scanner', 'cve-audit/fixes-2099-01-01');
  process.stdout.write(
    `prOpenStatus(audit-scanner, fake-branch): open=${status.open} ${!status.open ? 'OK (kein offener PR)' : 'FAIL'}\n`
  );
  ok &&= !status.open;

  // 4 state-Persist-Datei existiert? (nur Info — state.json wird vom echten Scan gepflegt)
  const state = loadState();
  process.stdout.write(
    `loadState: prs=${JSON.stringify(Object.keys(state.prs))} (leer = erster Lauf, ok)\n`
  );

  process.stdout.write(ok ? './ state-test PASS\n' : '✗ state-test FAIL\n');
  return ok ? 0 : 1;
}

/**
 * Purer Selbsttest der Image-Freshness-Matching-Logik (v1.6.0, kein Netzwerk,
 * kein Scan, kein PR, kein Telegram). Statische Tag-Listen aus dem echten
 * Prod-Report 2026-11-07 (private-ai-interface) + Regression-Fälle:
 * 1) pgvector `0.8.7-pg17` mit `pg17-trixie`/`pg17-bookworm` → kein Bump-Ziel,
 *    variantDrift = `0.8.7-pg17-trixie`, strictlyNewer = false.
 * 2) node `26.13.0-alpine3.24` → newest = exakt dieser Tag, strictlyNewer false.
 * 3) node `24-alpine` (floating) → exactPin `24.12.0-alpine3.24`.
 * 4) postgres `17.11-alpine3.24` + nur 2-Komp-Kandidat → kein Bump-Ziel.
 * 5) node `22.23.4-slim` + `slim-trixie`/`23.1.0-slim` → kein Major-Jump,
 *    kein trixie-Bump, strictlyNewer false.
 */
async function imageFreshnessTest(): Promise<number> {
  let ok = true;
  const check = (label: string, pass: boolean, detail = ''): void => {
    process.stdout.write(`${pass ? 'OK  ' : 'FAIL'} ${label}${detail ? ` — ${detail}` : ''}\n`);
    ok &&= pass;
  };

  // 0) tagSemantics-Basics (Variant = Suffix nach der Nummer)
  const sem = tagSemantics('0.8.7-pg17');
  check(
    'tagSemantics(0.8.7-pg17)',
    sem.valid && sem.pinned && !sem.floating && sem.comps === 3 && sem.variant === 'pg17',
    `pinned=${sem.pinned} variant=${sem.variant}`
  );
  check('tagSemantics(24-alpine) floating', tagSemantics('24-alpine').floating === true);

  // 1) pgvector: Variant-Drift (OS-Basis-Wechsel) ist KEIN Bump-Kandidat
  const pgTags = [
    '0.8.7',
    '0.8.7-pg17',
    '0.8.7-pg17-trixie',
    '0.8.7-pg17-bookworm',
    '0.8.7-pg18',
    '0.8.6',
    '0.8.6-pg17',
    '0.8.6-pg17-trixie',
    '0.8.6-pg17-bookworm',
  ];
  const pgNewest = newestSameMajorTag('0.8.7-pg17', pgTags);
  check(
    "pgvector newestSameMajorTag('0.8.7-pg17') = 0.8.7 (kein pg17-trixie-Bump)",
    pgNewest === null || strictlyNewer('0.8.7-pg17', pgNewest) === false,
    `newest=${pgNewest ?? 'null'}`
  );
  check(
    'pgvector strictlyNewer(pg17, pg17-trixie) = false',
    strictlyNewer('0.8.7-pg17', '0.8.7-pg17-trixie') === false
  );
  const pgDrift = variantDriftTag('0.8.7-pg17', pgTags);
  check(
    'pgvector variantDrift = 0.8.7-pg17-* (nicht der variantenlose Tag)',
    pgDrift === '0.8.7-pg17-trixie' || pgDrift === '0.8.7-pg17-bookworm',
    `drift=${pgDrift ?? 'null'}`
  );

  // 2) node alpin3.24 muss weiter matchen (alpine-Prefix-Regel)
  const node26 = ['26.13.0-alpine3.24', '26.12.0-alpine3.24', '26.13.0-alpine3.21'];
  const n26 = newestSameMajorTag('26.13.0-alpine3.24', node26);
  check(
    "node newestSameMajorTag('26.13.0-alpine3.24')",
    n26 !== null && tagSemantics(n26).major === 26,
    `newest=${n26 ?? 'null'}`
  );
  check('node strictlyNewer(false) → bleibt aktuell', n26 !== null && strictlyNewer('26.13.0-alpine3.24', n26) === false);
  const n26drift = variantDriftTag('26.13.0-alpine3.24', node26);
  check('node variantDrift (semver-gleich, andere alpine-Version) vorhanden', n26drift === '26.13.0-alpine3.21', `drift=${n26drift ?? 'null'}`);

  // 3) floating Major-Tag → exactPin im selben Major
  const n24 = newestExactTag('24-alpine', ['24.12.0-alpine3.24']);
  check(
    "node newestExactTag('24-alpine') = 24.12.0-alpine3.24",
    n24 !== null && tagSemantics(n24).pinned && tagSemantics(n24).major === 24,
    `exact=${n24 ?? 'null'}`
  );

  // 4) pinned never DOWN into floating: `17.11-alpine3.24` wird von der
  //    2-Komp-Regel als floating klassifiziert → kein exaktPin; ein 2-Komp-
  //    Kandidat ist NIE Bump-Ziel im pinned-PR-Pfad (pinned=false).
  const pgExact = newestExactTag('17.11-alpine3.24', ['17.12-alpine3.24']);
  check("postgres newestExactTag('17.11-alpine3.24') = null (2-Komp)", pgExact === null, `exact=${pgExact ?? 'null'}`);
  const pgMajor = newestSameMajorTag('17.11-alpine3.24', ['17.12-alpine3.24']);
  check(
    "postgres newestSameMajorTag('17.11-alpine3.24') 2-Komp nur Info (pinned=false)",
    pgMajor === null || !tagSemantics(pgMajor).pinned,
    `newest=${pgMajor ?? 'null'} pinned=${pgMajor ? tagSemantics(pgMajor).pinned : 'n/a'}`
  );

  // 5) slim-Variante: kein Major-Jump; kein Bump auf `-slim-trixie` (semver-
  //    gleich = OS-Basis-Wechsel, nur variant-drift-Marker), strictlyNewer false
  const slimTags = ['22.23.4-slim', '22.23.4-slim-trixie', '22.23.4-bookworm', '23.1.0-slim'];
  const slim = newestSameMajorTag('22.23.4-slim', slimTags);
  check(
    "node newestSameMajorTag('22.23.4-slim') kein Major-Jump auf 23",
    slim === null || tagSemantics(slim).major === 22,
    `newest=${slim ?? 'null'}`
  );
  check(
    'node slim strictlyNewer(false) → aktuell (kein Bump)',
    slim === null || strictlyNewer('22.23.4-slim', slim) === false,
    `newest=${slim ?? 'null'}`
  );
  const slimDrift = variantDriftTag('22.23.4-slim', slimTags);
  const slimDriftOk = slimDrift !== null && tagSemantics(slimDrift).major === 22 &&
    strictlyNewer('22.23.4-slim', slimDrift) === false;
  check(
    'node slim variantDrift gesetzt (report-only, kein Bump)',
    slimDriftOk,
    `drift=${slimDrift ?? 'null'}`
  );
  // exactPin für slim: exakt gleiche Variante hat Vorrang vor dem OS-Drift
  const slimExact = newestExactTag('22.23.4-slim', slimTags);
  check(
    "node newestExactTag('22.23.4-slim') keine 23.x",
    slimExact === null || tagSemantics(slimExact).major === 22,
    `exact=${slimExact ?? 'null'}`
  );

  // 6) (C)-Invariante: newest nie semver-kleiner als current
  const older = ['1.5.0', '1.4.9'];
  const back = newestSameMajorTag('1.9.0', older);
  check("newestSameMajorTag nie kleiner als current ('1.9.0' vs 1.5.0)", back === null, `newest=${back ?? 'null'}`);

  // 7) P1-Regression replaceTag (v1.5.3): kein Anhängsel bei Teil-Treffern.
  //    `node:24` darf NICHT in `node:24-alpine` matchen (→ …-alpine-alpine).
  const rt: Array<[string, string, string, string]> = [
    ['FROM node:24-alpine AS base', 'node:24-alpine', 'node:24.12.0-alpine', 'FROM node:24.12.0-alpine AS base'],
    ['FROM node:24-alpine AS base', 'node:24', 'node:24.12.0-alpine', 'FROM node:24-alpine AS base'],
    ['FROM node:24@sha256:abc AS b', 'node:24', 'node:24.12.0', 'FROM node:24.12.0@sha256:abc AS b'],
    ['FROM my-node:24 AS c', 'node:24', 'node:26', 'FROM my-node:24 AS c'],
    ['FROM node:240 AS d', 'node:24', 'node:26', 'FROM node:240 AS d'],
  ];
  for (const [content, from, to, expected] of rt) {
    const got = replaceTag(content, from, to);
    check(`replaceTag(${from} → ${to})`, got === expected, `got=${JSON.stringify(got)}`);
  }

  // 8) Regression variantDriftTag (v1.6.1): der variantenlose Tag ist KEIN
  //    Drift. Prod-Alert 2026-11-07 zeigte "variant drift: 26.13.0" für alle
  //    node-Pins — reines Rauschen, semver-gleicher Stand ohne OS-Suffix.
  const nodeTags = ['26.13.0', '26.13.0-alpine3.24', '26.13.0-alpine3.21', '26.12.0-alpine3.24'];
  const bare = variantDriftTag('26.13.0-alpine3.24', nodeTags);
  check('variantDriftTag ignoriert variantenlosen Tag', bare !== '26.13.0', `drift=${bare ?? 'null'}`);
  const pgTags2 = ['0.8.7-pg17', '0.8.7-pg17-bookworm', '0.8.7-pg17-trixie'];
  const pgDrift2 = variantDriftTag('0.8.7-pg17', pgTags2);  check('variantDriftTag erkennt echte OS-Drift', pgDrift2 !== null && pgDrift2 !== '0.8.7-pg17', `drift=${pgDrift2 ?? 'null'}`);

  process.stdout.write(ok ? './ image-freshness-test PASS\n' : '✗ image-freshness-test FAIL\n');
  return ok ? 0 : 1;
}

/** Minimales ImageFinding für den Selbsttest (nur Felder, die der Report-Bau liest). */
function fakeImage(image: string, high: number, critical: number, sourceFiles: string[]): ImageFinding {
  return {
    image,
    base: image.split(':')[0] ?? image,
    current: image.split(':')[1] ?? 'latest',
    registry: 'docker-hub',
    pinned: true,
    floating: false,
    digestPinned: false,
    sourceFiles,
    vulns: { high, critical },
    newestSameMajor: null,
    exactPin: null,
    updateAvailable: false,
  };
}

function fakeRepo(name: string, images: ImageFinding[]): RepoResult {
  return {
    name,
    private: false,
    defaultBranch: 'main',
    ecosystem: 'npm',
    status: 'scanned',
    findings: [],
    images,
  };
}

/**
 * Selbsttest der Image-Vuln-Findings (v1.5.2, rein synthetisch — kein Scan,
 * kein Netz, kein Telegram):
 * 1) Alte state.json OHNE imageVulns-Feld bleibt parsbart.
 * 2) Novelty: zwei Repos mit gleicher H/C-Zahl → 1. Lauf novel, nach
 *    markImageVulnsReported + Save/Load-Roundtrip 2. Lauf nicht mehr novel.
 * 3) Geänderte Zahl (H6 → H7) → wieder novel.
 * 4) telegramBody enthält die 🛡-Sektion und kappt bei > 15 Zeilen.
 */
/**
 * Purer Selbsttest Soaking + Pre-Release (v1.6.0): fixe Fake-Uhr, kein Netzwerk.
 * Kernregeln des Owners: Updates erst nach UPDATE_MIN_AGE_DAYS (=3) Tagen,
 * Ausnahme NUR bei belegtem H/C-CVE-Fix; Beta-Hinweis NUR für Pakete, die
 * schon im Beta-Kanal liegen.
 */
/**
 * Selbsttest Renovate (v1.7.0): Parser + Einordnung in PinFinding.
 * Offline — eingebettetes JSONL-Fixture in der echten Renovate-Log-Form
 * (`msg === "packageFiles with updates"`, Daten unter `config`).
 */
function renovateTest(): number {
  let ok = true;
  const check = (label: string, cond: boolean, detail = ''): void => {
    process.stdout.write(`${cond ? 'OK  ' : 'FAIL'} ${label}${detail ? ` — ${detail}` : ''}\n`);
    ok &&= cond;
  };

  const updateLog = (deps: unknown[]): string =>
    JSON.stringify({
      name: 'renovate',
      level: 20,
      msg: 'packageFiles with updates',
      repository: 'local',
      config: { npm: [{ packageFile: 'package.json', deps }] },
      time: new Date().toISOString(),
    });

  const dep = (depName: string, currentValue: string, updates: unknown[]): unknown => ({
    depName,
    currentValue,
    depType: 'dependencies',
    datasource: 'npm',
    updates,
  });
  const upd = (newVersion: string, updateType: string, age?: number): unknown => ({
    newVersion,
    newValue: newVersion,
    updateType,
    isBreaking: updateType === 'major',
    releaseTimestamp: '2026-11-01T00:00:00.000Z',
    newVersionAgeInDays: age,
  });

  // 1) Parser: zwei deps mit Updates
  const multi = [
    updateLog([
      dep('lodash', '4.17.15', [upd('4.18.1', 'minor', 219)]),
      dep('semver', '7.6.0', [upd('7.8.6', 'minor', 5)]),
      dep('unchanged', '1.0.0', []),
    ]),
  ].join('\n');
  const r1 = parseRenovateLog(multi);
  check('Parser: ok + 2 Kandidaten', r1.ok && r1.candidates.length === 2, `n=${r1.candidates.length}`);

  // 2) höchste newVersion je dep gewinnt
  const highest = updateLog([
    dep('pkg', '1.0.0', [upd('1.0.2', 'patch', 9), upd('1.2.0', 'minor', 4), upd('1.0.1', 'patch', 12)]),
  ]);
  const r2 = parseRenovateLog(highest);
  check(
    'Parser: höchste newVersion je dep',
    r2.candidates[0]?.newVersion === '1.2.0',
    r2.candidates[0]?.newVersion ?? 'n/a'
  );

  // 3) releaseTimestamp → ageDays
  check('Parser: ageDays übernommen', r2.candidates[0]?.ageDays === 4, String(r2.candidates[0]?.ageDays));

  // 4) kaputter/leerer Output → ok:false, kein Crash
  const r4 = parseRenovateLog('{"kein":"jsonl"}\nMüll\n');
  check('Parser: kaputter Output → ok:false', r4.ok === false && r4.candidates.length === 0, r4.note ?? '');

  // 5) Major/Breaking nie fixable, minor schon
  const withMajor = parseRenovateLog(
    updateLog([dep('big', '1.0.0', [upd('2.0.0', 'major', 30)]), dep('small', '1.0.0', [upd('1.0.1', 'patch', 3)])])
  );
  const mapped = renovateToPinFindings('.', withMajor.candidates, []);
  const majorF = mapped.find((f) => f.pkg === 'big');
  const minorF = mapped.find((f) => f.pkg === 'small');
  check('Major-Update als majorOrBreaking markiert', majorF?.majorOrBreaking === true);
  check('Patch-Update nicht majorOrBreaking', minorF?.majorOrBreaking === false);
  check('Renovate-Quelle gesetzt', minorF?.source === 'renovate');

  // 6) Dedupe: bereits als floating Pin erfasst → keine Doppelmeldung
  const dedupe = renovateToPinFindings('.', withMajor.candidates, [
    { pkg: 'small', current: '^1.0.0', latest: '1.0.1', section: 'dependencies', manifestPath: 'package.json', severity: 'warn' },
  ]);
  check('Dedupe gegen floating-Findings', !dedupe.some((f) => f.pkg === 'small'), `n=${dedupe.length}`);

  process.stdout.write(ok ? './ renovate-test PASS\n' : '✗ renovate-test FAIL\n');
  return ok ? 0 : 1;
}

function soakingTest(): number {
  let ok = true;
  const check = (label: string, cond: boolean, detail = ''): void => {
    process.stdout.write(`${cond ? 'OK  ' : 'FAIL'} ${label}${detail ? ` — ${detail}` : ''}\n`);
    ok &&= cond;
  };
  const now = new Date('2026-11-07T12:00:00Z');
  const ago = (n: number): string => new Date(now.getTime() - n * 86_400_000).toISOString();
  const el = (o: Partial<Parameters<typeof updateEligibility>[0]>): ReturnType<typeof updateEligibility> =>
    updateEligibility({ variantChange: false, publishedAt: null, cveFix: false, minAgeDays: 3, now, ...o });

  // Soaking-Gates
  check('2 Tage alt → too-young', el({ publishedAt: ago(2) }).eligibility === 'too-young');
  check('3 Tage alt → eligible', el({ publishedAt: ago(3) }).eligibility === 'eligible');
  check('2 Tage + CVE-Fix → cve-exempt', el({ publishedAt: ago(2), cveFix: true }).eligibility === 'cve-exempt');
  check('0 Tage + CVE-Fix → cve-exempt', el({ publishedAt: ago(0), cveFix: true }).eligibility === 'cve-exempt');
  check('unbekanntes Datum → fail-open', el({ publishedAt: null }).eligibility === 'eligible');
  check(
    'Variant-Wechsel schlägt CVE-Ausnahme',
    el({ variantChange: true, publishedAt: ago(9), cveFix: true }).eligibility === 'rejected-variant'
  );
  check('UPDATE_MIN_AGE_DAYS=0 → sofort', el({ publishedAt: ago(0), minAgeDays: 0 }).eligibility === 'eligible');
  check('Alter wird korrekt gerundet', ageInDays(ago(2), now) === 2, `age=${ageInDays(ago(2), now)}d`);
  check('Future-Datum → 0d', ageInDays(new Date(now.getTime() + 86_400_000).toISOString(), now) === 0);

  // Pre-Release-Klassifikation
  const cls: Array<[string, string, string | null]> = [
    ['7.1.0-beta', 'channel', 'beta'],
    ['7.0.1-rc.2', 'channel', 'rc'],
    ['1.0.0-alpha', 'channel', 'alpha'],
    ['7.1.0-dev.20261107.1', 'exotic', null],
    ['4.6.2-insiders.20220225', 'exotic', null],
    ['7.0.2', 'stable', null],
    ['26.13.0-alpine3.24', 'stable', null],
  ];
  for (const [v, expCls, expCh] of cls) {
    const r = classifyPrerelease(v);
    check(`classify(${v})`, r.cls === expCls && r.channel === expCh, `${r.cls}/${r.channel}`);
  }

  // Owner-Regel: Beta-Updates NUR für Pakete, die bereits Beta sind
  check('stable → beta VERBOTEN', channelCompatible('7.0.2', '7.1.0-beta') === false);
  check('beta → beta erlaubt', channelCompatible('7.1.0-beta.1', '7.1.0-beta.2'));
  check('rc → rc erlaubt', channelCompatible('7.0.1-rc.1', '7.0.1-rc.2'));
  check('beta → rc VERBOTEN', channelCompatible('7.1.0-beta', '7.0.1-rc.2') === false);
  check('pinned-beta erkannt', isPinnedPrereleaseSpec('7.1.0-beta'));
  check('stable nicht als beta', isPinnedPrereleaseSpec('7.0.2') === false);
  check('floating nicht als beta', isPinnedPrereleaseSpec('^7.0.2') === false);
  // Regression (Prod-Report 2026-11-07): prerelease-Vergleich über coerce() ist
  // kaputt — coerce("4.0.0-beta.7") = "4.0.0", damit wäre beta.8 nie "größer".
  {
    const semverMod = semver;
    const cur = semverMod.valid('4.0.0-beta.7') ?? semverMod.coerce('4.0.0-beta.7')!.version;
    check(
      'beta.8 > beta.7 (voller semver-Vergleich)',
      semverMod.gt('4.0.0-beta.8', cur),
      `cur=${cur}`
    );
  }

  // CVE-Ausnahme ist bewusst streng: nur Security-Tools, KEIN Base-Image-Patch
  check('aquasec/trivy → sofort', isSecurityToolBump('aquasec/trivy'));
  check('node → KEINE Ausnahme', isSecurityToolBump('node') === false);
  check('postgres → KEINE Ausnahme', isSecurityToolBump('postgres') === false);

  process.stdout.write(ok ? './ soaking-test PASS\n' : '✗ soaking-test FAIL\n');
  return ok ? 0 : 1;
}

/**
 * Purer Selbsttest des Digest-Caches (v1.6.2, kein Netzwerk, kein Scan):
 * 1) korruptes digests.json → leerer Cache, kein Crash.
 * 2) erster Lauf setzt Digest + firstSeen; zweiter Lauf gleicher Digest →
 *    digestChanged=false (stabiler Tag).
 * 3) geänderter Digest → digestChanged=true + previousDigest (bewegl. Tag).
 * 4) 91 Tage alter Eintrag wird geprunt, frischer bleibt.
 * Zusätzlich: die Report-Empfehlung (imageVulnAdvice) klingt je Fall ehrlich.
 * Die Fake-Datei liegt in einem tmp-Dir — die echte reports/digests.json
 * wird nicht angefasst.
 */
function digestTest(): number {
  let ok = true;
  const check = (label: string, cond: boolean, detail = ''): void => {
    process.stdout.write(`${cond ? 'OK  ' : 'FAIL'} ${label}${detail ? ` — ${detail}` : ''}\n`);
    ok &&= cond;
  };
  const fakeDir = fs.mkdtempSync(path.join(os.tmpdir(), 'digest-test-'));
  const file = path.join(fakeDir, 'digests.json');
  const ref = 'node:26.13.0-alpine3.24';
  const shaA = 'sha256:' + 'a'.repeat(64);
  const shaB = 'sha256:' + 'b'.repeat(64);
  const t0 = new Date('2026-11-07T12:00:00Z');
  const at = (days: number): Date => new Date(t0.getTime() + days * 86_400_000);

  try {
    // 1) korruptes JSON → leerer Start ohne Crash
    fs.writeFileSync(file, '{ nicht-json <<<');
    const corrupt = loadDigestCache(file);
    check('korruptes digests.json → leerer Cache', Object.keys(corrupt).length === 0, `entries=${Object.keys(corrupt).length}`);
    check('parseDigestCache(garbage) = null', parseDigestCache('[]') === null);

    // 2) erster Lauf → firstSeen; zweiter Lauf gleicher Digest → stabil
    fs.writeFileSync(file, '{}\n');
    const run1 = openDigestSession(t0, file);
    const l1 = run1.lookup(ref, shaA);
    run1.save();
    const after1 = loadDigestCache(file);
    check('lauf1 digest gesetzt', l1.digest === shaA && after1[ref]?.digest === shaA, `digest=${String(after1[ref]?.digest).slice(0, 20)}…`);
    check('lauf1 firstSeen = jetzt', after1[ref]?.firstSeen === t0.toISOString(), after1[ref]?.firstSeen);
    check('lauf1 digestChanged=false (erstes Mal gesehen)', l1.digestChanged === false && l1.previousDigest === null);

    const run2 = openDigestSession(at(1), file);
    const l2 = run2.lookup(ref, shaA);
    run2.save();
    const after2 = loadDigestCache(file);
    check('lauf2 gleicher Digest → stabil', l2.digestChanged === false && l2.previousDigest === shaA);
    check('lauf2 firstSeen unverändert, lastSeen nachgezogen',
      after2[ref]?.firstSeen === t0.toISOString() && after2[ref]?.lastSeen === at(1).toISOString());
    check('lauf2 keine neue Änderungshistorie', after2[ref]?.changes.length === 1, `changes=${after2[ref]?.changes.length}`);

    // 3) geänderter Digest → beweglicher Tag
    const run3 = openDigestSession(at(2), file);
    const l3 = run3.lookup(ref, shaB);
    run3.save();
    const after3 = loadDigestCache(file);
    check('lauf3 geänderter Digest → digestChanged=true', l3.digestChanged === true && l3.previousDigest === shaA);
    check('lauf3 Historie wächst', after3[ref]?.changes.length === 2 && after3[ref]?.changes[1]?.digest === shaB);

    // 3b) Lookup-Fehler (null) ist KEIN Wechsel
    const run3b = openDigestSession(at(3), file);
    const l3b = run3b.lookup(ref, null);
    check('Lookup-Fehler → digestChanged=false, Digest bleibt', l3b.digestChanged === false && l3b.digest === null);

    // 4) Prune: 91 Tage alte Ref fliegt raus, frische bleibt
    const cache: DigestCache = {
      'old:1.0.0': { digest: shaA, firstSeen: at(-120).toISOString(), lastSeen: at(-91).toISOString(), changes: [] },
      'fresh:1.0.0': { digest: shaB, firstSeen: at(-5).toISOString(), lastSeen: at(-1).toISOString(), changes: [] },
    };
    const removed = pruneDigestCache(cache, t0);
    check('prune entfernt 91-Tage-Eintrag', removed === 1 && !('old:1.0.0' in cache), `removed=${removed}`);
    check('prune behält frischen Eintrag', 'fresh:1.0.0' in cache);

    // 5) Report-Empfehlung klingt ehrlich je Fall
    const moving = imageVulnAdvice({ digestChanged: true });
    const newerTag = imageVulnAdvice({ digestChanged: false, updateAvailable: true });
    const releaseOnly = imageVulnAdvice({ digestChanged: false, updateAvailable: false, upstreamLatest: 'v0.0.84' });
    const nothing = imageVulnAdvice({ digestChanged: false, updateAvailable: false, upstreamLatest: null });
    check('Empfehlung beweglicher Tag', /beweglich.*Rebuild/.test(moving), moving);
    check('Empfehlung neuer Tag (kein Rebuild-Rat)', /Pin auf neueren Tag/.test(newerTag) && !/Rebuild zieht/.test(newerTag), newerTag);
    // v1.6.3: Release ohne Image (playwright/mcp v0.0.84) darf NICHT zum Pin raten.
    check('Empfehlung Release ohne Image', /abwarten/.test(releaseOnly) && !/Pin auf neueren/.test(releaseOnly), releaseOnly);
    check('Empfehlung ohne alles: ehrlich, kein Handlungsdruck', /keine neuere Version/.test(nothing) && !/Pin auf neueren/.test(nothing), nothing);
    const line = imageVulnLines([{ repo: 'demo', image: ref, high: 6, critical: 0, digestChanged: false }]).find((l) => l.includes('•')) ?? '';
    check('Telegram-Zeile ≤ 120 Zeichen', line.length > 0 && line.length <= 120, `${line.length} Zeichen`);
  } finally {
    fs.rmSync(fakeDir, { recursive: true, force: true });
  }

  process.stdout.write(ok ? './ digest-test PASS\n' : '✗ digest-test FAIL\n');
  return ok ? 0 : 1;
}

/**
 * Purer Selbsttest des Upstream-Release-Checks (v1.6.3, KEIN Netzwerk):
 * GitHub-Releases + Manifest-Existenz werden injiziert (Fake-Daten).
 * 1) v0.0.83 vs Release v0.0.84 → newerThanTag=true.
 * 2) Tag fehlt auf der Registry (404 simuliert) → Note enthält "kein Image".
 * 3) Docker-Official-Image `node` → kein Upstream-Repo, kein Fehler.
 * 4) nicht-vergleichbare Version (2026.11.1-9ded3bec1) → kein Crash, false + note.
 * 5) Prerelease-/Draft-Releases werden ignoriert.
 * Zusätzlich: Registry-Fehler beim Release-Fetch → kein Throw, Report sagt
 * NICHT "aktuell" (upstreamNewerOnly nur bei echtem neueren Release).
 */
async function releaseVersionTest(): Promise<number> {
  let ok = true;
  const check = (label: string, cond: boolean, detail = ''): void => {
    process.stdout.write(`${cond ? 'OK  ' : 'FAIL'} ${label}${detail ? ` — ${detail}` : ''}\n`);
    ok &&= cond;
  };
  const releasesFor = (tags: string[], prereleaseAt: number[] = [], draftAt: number[] = []): GhRelease[] =>
    tags.map((tag_name, i) => ({ tag_name, prerelease: prereleaseAt.includes(i), draft: draftAt.includes(i) }));

  // (a) playwright/mcp: Registry-Tag v0.0.83, Upstream-Release v0.0.84
  const pw = await upstreamReleaseCheck(
    { base: 'playwright/mcp', currentTag: 'v0.0.83', registry: 'mcr' },
    {
      fetchReleases: async () => releasesFor(['v0.0.84', 'v0.0.83']),
      manifestExists: async () => true,
    }
  );
  check('(a) v0.0.83 vs Release v0.0.84 → newerThanTag', pw.newerThanTag === true, `note=${pw.note ?? '—'}`);
  check('(a) latestRelease = v0.0.84', pw.latestRelease === 'v0.0.84', String(pw.latestRelease));
  check('(a) Mapping playwright/mcp → microsoft/playwright-mcp', upstreamRepoFor('playwright/mcp') === 'microsoft/playwright-mcp');
  check('(a) Manifest vorhanden → KEINE "kein Image"-Note', pw.releaseWithoutImage !== true && !/kein Image/.test(pw.note ?? ''));

  // (b) Release da, Tag fehlt auf der Registry (404 simuliert)
  const headChecked: string[] = [];
  const missing = await upstreamReleaseCheck(
    { base: 'playwright/mcp', currentTag: 'v0.0.83-mcr', registry: 'mcr' },
    {
      // Cache-Hinweis: key = registry|base|currentTag — `-mcr`-Suffix hält den
      // Fall getrennt von (a), die Logik ist dieselbe (coerce strippt das Suffix).
      // anderer current-Tag als (a): der Prozess-Cache ist je Ref gekeyt.
      fetchReleases: async () => releasesFor(['v0.0.84']),
      manifestExists: async (base, tag, registry) => {
        headChecked.push(`${base}:${tag}@${registry}`);
        return false;
      },
    }
  );
  check('(b) Tag fehlt (404) → note enthält "kein Image"', /kein Image/.test(missing.note ?? ''), missing.note ?? '—');
  check('(b) note nennt Registry-Label + 404', /MCR/.test(missing.note ?? '') && /404/.test(missing.note ?? ''));
  check('(b) releaseWithoutImage = true', missing.releaseWithoutImage === true);
  // v1.7.1: verbatim zuerst, dann Präfix-Flip — "kein Image" erst nach beiden 404.
  check('(b) Manifest-Check verbatim + Präfix-Flip',
    headChecked.join('|') === 'playwright/mcp:v0.0.84@mcr|playwright/mcp:0.0.84@mcr', headChecked.join('|'));

  // (c) Docker-Official-Image: kein Upstream-Repo, kein Fehler, kein Netzwerk
  let fetchCalled = false;
  const nodeRes = await upstreamReleaseCheck(
    { base: 'node', currentTag: '26.13.0-alpine3.24', registry: 'docker-hub' },
    {
      fetchReleases: async () => {
        fetchCalled = true;
        return [];
      },
    }
  );
  const libRes = await upstreamReleaseCheck({ base: 'library/node', currentTag: '26.13.0', registry: 'docker-hub' });
  check('(c) node → kein Upstream-Repo', upstreamRepoFor('node') === null && nodeRes.latestRelease === null && !fetchCalled);
  check('(c) node → newerThanTag=false, kein Fehler', nodeRes.newerThanTag === false && /kein Upstream-Repo/.test(nodeRes.note ?? ''), nodeRes.note ?? '—');
  check('(c) library/node → kein Upstream-Repo', upstreamRepoFor('library/node') === null && libRes.newerThanTag === false);

  // (d) nicht semver-vergleichbare Versionen → kein Crash, false + note
  const odd = await upstreamReleaseCheck(
    { base: 'cloudflare/cloudflared', currentTag: '2026.11.1-9ded3bec1', registry: 'ghcr' },
    {
      fetchReleases: async () => releasesFor(['2026.11.1-beta-x']),
      manifestExists: async () => true,
    }
  );
  check("(d) '2026.11.1-9ded3bec1' → kein Crash", odd.latestRelease !== undefined, `latest=${String(odd.latestRelease)}`);
  const odd2 = await upstreamReleaseCheck(
    { base: 'demo/tool', currentTag: 'main-20261101', registry: 'ghcr' },
    { fetchReleases: async () => releasesFor(['v9.9.9']) }
  );
  check('(d) nicht vergleichbar → newerThanTag=false + note', odd2.newerThanTag === false && /nicht semver-vergleichbar/.test(odd2.note ?? ''), odd2.note ?? '—');
  check('(d) releaseIsNewer(Build-Meta) reduziert auf Zahlen-Teil', releaseIsNewer('2026.11.0-abc', '2026.11.1-9ded3bec1') === true);

  // (e) Prerelease-/Draft-Releases werden ignoriert
  // Index 0 = prerelease, Index 1 = draft → beide raus, v0.0.83 bleibt.
  const latest = latestStableRelease(releasesFor(['v0.0.85', 'v0.0.84', 'v0.0.83'], [0], [1]));
  check('(e) latestStableRelease überspringt prerelease/draft', latest === 'v0.0.83', String(latest));
  const preOnly = await upstreamReleaseCheck(
    { base: 'playwright/mcp', currentTag: 'v0.0.84', registry: 'mcr' },
    {
      fetchReleases: async () => releasesFor(['v0.0.85', 'v0.0.84'], [0]),
      manifestExists: async () => false,
    }
  );
  check('(e) nur Prerelease neuer → stable v0.0.84 genommen, kein 0.0.85',
    preOnly.latestRelease === 'v0.0.84' && preOnly.newerThanTag === false, `latest=${String(preOnly.latestRelease)}`);
  const draftOnly = await upstreamReleaseCheck(
    { base: 'pgvector/pgvector', currentTag: '0.8.7', registry: 'docker-hub' },
    {
      fetchReleases: async () => releasesFor(['v0.9.0', 'v0.8.7'], [], [0]),
      manifestExists: async () => true,
    }
  );
  check('(e) Draft-Release wird ignoriert', draftOnly.latestRelease === 'v0.8.7' && draftOnly.newerThanTag === false, String(draftOnly.latestRelease));

  // (f) Fehler im Release-Fetch → kein Throw, keine falsche Aussage
  const broken = await upstreamReleaseCheck(
    { base: 'aquasec/trivy', currentTag: '0.76.2', registry: 'docker-hub' },
    {
      fetchReleases: async () => {
        throw new Error('simulierter GitHub-Fehler');
      },
    }
  );
  check('(f) Fetch-Fehler → latestRelease null, kein Throw', broken.latestRelease === null && broken.newerThanTag === false, broken.note ?? '—');
  check('(f) Mapping aquasec/trivy → aquasecurity/trivy', upstreamRepoFor('aquasec/trivy') === 'aquasecurity/trivy');

  // (g) Report-Text: Registry aktuell + Release ohne Image ≠ "aktuell"
  const baseFinding: ImageFinding = {
    image: 'playwright/mcp:v0.0.83',
    base: 'playwright/mcp',
    current: 'v0.0.83',
    registry: 'mcr',
    pinned: true,
    floating: false,
    digestPinned: false,
    sourceFiles: ['Dockerfile'],
    vulns: { high: 0, critical: 0 },
    newestSameMajor: null,
    exactPin: null,
    updateAvailable: false,
  };
  check('(g) upstreamNewerOnly erkennt Release-ohne-Image', upstreamNewerOnly({ ...baseFinding, upstreamLatest: 'v0.0.84' }));
  check('(g) ohne Release → KEIN upstream-Only', !upstreamNewerOnly({ ...baseFinding, upstreamLatest: null }));
  check('(g) mit Update → upstream-Only false', !upstreamNewerOnly({ ...baseFinding, upstreamLatest: 'v0.0.84', updateAvailable: true }));

  // (h) v1.7.1: Registry-Tag-Präfix ≠ Git-Release-Tag-Präfix.
  // Beleg 2026-11-07: aquasec/trivy (Docker Hub: 0.76.2) vs Git-Tag v0.76.2.
  check('(h) candidates v0.76.2 → [v0.76.2, 0.76.2]', registryTagCandidates('v0.76.2').join('|') === 'v0.76.2|0.76.2');
  check('(h) candidates 0.76.2 → [0.76.2, v0.76.2]', registryTagCandidates('0.76.2').join('|') === '0.76.2|v0.76.2');
  check('(h) candidates ohne Präfix-Nummer → nur verbatim', registryTagCandidates('main-20261101').join('|') === 'main-20261101');
  const trivyFixed = await upstreamReleaseCheck(
    { base: 'demo/trivy-lookalike', currentTag: '0.76.1', registry: 'docker-hub' },
    {
      fetchReleases: async () => releasesFor(['v0.76.2', 'v0.76.1']),
      // Docker-Hub-Variante: nur der Tag OHNE v existiert → verbatim (v0.76.2) 404.
      manifestExists: async (_b, tag) => tag === '0.76.2',
    }
  );
  check('(h) trivy-Fall: v-Release, ungeprefixter Registry-Tag → Image vorhanden',
    trivyFixed.newerThanTag === true && trivyFixed.releaseWithoutImage !== true && /Registry-Tag 0\.76\.2/.test(trivyFixed.note ?? ''),
    trivyFixed.note ?? '—');
  const mcrStillMissing = await upstreamReleaseCheck(
    { base: 'playwright/mcp', currentTag: 'v0.0.82-x', registry: 'mcr' },
    {
      // Cache-Key-Trennung über den current-Tag; Logik identisch zu (b).
      fetchReleases: async () => releasesFor(['v0.0.84']),
      // MCR-Variante: weder v0.0.84 noch 0.0.84 existieren → echt kein Image.
      manifestExists: async () => false,
    }
  );
  check('(h) playwright-Fall: BEIDE Kandidaten 404 → weiterhin "kein Image"',
    mcrStillMissing.releaseWithoutImage === true && /geprüft: v0\.0\.84, 0\.0\.84/.test(mcrStillMissing.note ?? ''),
    mcrStillMissing.note ?? '—');
  const unknownProbe = await upstreamReleaseCheck(
    { base: 'demo/unknown-probe', currentTag: '1.0.0', registry: 'ghcr' },
    {
      fetchReleases: async () => releasesFor(['v1.1.0']),
      // Ein Kandidat 404, der andere unbelastbar (null) → KEINE "kein Image"-Aussage.
      manifestExists: async (_b, tag) => (tag === 'v1.1.0' ? false : null),
    }
  );
  check('(h) unbelastbare Probe (null) → keine falsche "kein Image"-Behauptung',
    unknownProbe.releaseWithoutImage !== true && /unbekannt/.test(unknownProbe.note ?? ''),
    unknownProbe.note ?? '—');

  process.stdout.write(ok ? './ release-version-test PASS\n' : '✗ release-version-test FAIL\n');
  return ok ? 0 : 1;
}

function imageVulnsTest(): number {  let ok = true;  const check = (label: string, cond: boolean): void => {
    process.stdout.write(`${label}: ${cond ? 'OK' : 'FAIL'}\n`);
    ok &&= cond;
  };

  // 1) Abwärtskompatibler Parse: alte state.json ohne imageVulns-Feld.
  const oldRaw = JSON.stringify({ prs: { demo: [] } });
  const oldParsed = parseState(oldRaw);
  check('legacy-parse (ohne imageVulns)', oldParsed !== null && oldParsed.imageVulns === undefined);

  // 2) Erster Lauf: zwei Repos, gleiche H/C-Zahl → beide novel.
  const reports: Report[] = [
    {
      generatedAt: new Date().toISOString(),
      owner: 'mayraost',
      summary: {
        reposTotal: 2,
        scanned: 2,
        findings: 0,
        suppressed: 0,
        fixPrs: 0,
        imagePrs: 0,
        pinsPrs: 0,
        unpinned: 0,
        apiCalls: 0,
        reminders: 0,
        imageVulns: { high: 12, critical: 0, images: 2 },
      },
      reminders: [],
      pinsReminders: [],
      imageVulnFindings: collectImageVulnFindings([
        fakeRepo('repo-a', [fakeImage('node:26.13.0-alpine3.24', 6, 0, ['Dockerfile'])]),
        fakeRepo('repo-b', [fakeImage('node:26.13.0-alpine3.24', 6, 0, ['docker/Dockerfile'])]),
      ]),
      repos: [],
    },
  ];
  const first = reports[0]!;
  check('imageVulnFindings count (2)', first.imageVulnFindings.length === 2);
  const state: State = { prs: {} };
  const run1 = novelImageVulns(first, state);
  check('run1 novel=2 (fehlt im State)', run1.length === 2);

  // Nach "Versand": Register fortschreiben + JSON-Roundtrip (wie saveState/loadState).
  markImageVulnsReported(state, 'repo-a', [{ image: 'node:26.13.0-alpine3.24', high: 6, critical: 0 }]);
  markImageVulnsReported(state, 'repo-b', [{ image: 'node:26.13.0-alpine3.24', high: 6, critical: 0 }]);
  const persisted = parseState(JSON.stringify(state));
  check(
    'roundtrip imageVulns H6/C0',
    persisted?.imageVulns?.['repo-a']?.['node:26.13.0-alpine3.24'] === 'H6/C0' &&
      persisted?.imageVulns?.['repo-b']?.['node:26.13.0-alpine3.24'] === 'H6/C0'
  );
  const run2 = novelImageVulns(first, persisted ?? state);
  check('run2 novel=0 (bekannt)', run2.length === 0);

  // 3) Geänderte Zahl H6 → H7 → wieder novel (nur das geänderte Repo).
  const changed: Report = {
    ...first,
    imageVulnFindings: collectImageVulnFindings([
      fakeRepo('repo-a', [fakeImage('node:26.13.0-alpine3.24', 7, 0, ['Dockerfile'])]),
      fakeRepo('repo-b', [fakeImage('node:26.13.0-alpine3.24', 6, 0, ['docker/Dockerfile'])]),
    ]),
  };
  const run3 = novelImageVulns(changed, persisted ?? state);
  check(
    'run3 novel=1 (H6→H7)',
    run3.length === 1 && run3[0]?.repo === 'repo-a' && run3[0]?.high === 7
  );

  // 4) Telegram-Sektion: vorhanden + Kappung bei > 15 Zeilen.
  const many = Array.from({ length: 20 }, (_, i) =>
    fakeImage(`img${String(i).padStart(2, '0')}:1.0.0`, 1, 0, ['Dockerfile'])
  );
  const manyReport: Report = {
    ...first,
    summary: { ...first.summary, imageVulns: { high: 20, critical: 0, images: 20 } },
    imageVulnFindings: collectImageVulnFindings([fakeRepo('repo-many', many)]),
    repos: [fakeRepo('repo-many', many)],
  };
  const manyNovel = novelImageVulns(manyReport, { prs: {} });
  const bodyMany = telegramBody(manyReport, true, manyNovel);
  const ivLines = imageVulnLines(manyNovel).filter((l) => l.trim().startsWith('•')).length;
  check(
    'telegram 🛡-Sektion vorhanden',
    bodyMany.includes('🛡 Image-Vulns (Base-Image):') && bodyMany.includes('• img00:1.0.0 [H1/C0]')
  );
  check(`telegram cap ${IMAGE_VULN_TELEGRAM_MAX_LINES} Zeilen`, ivLines === IMAGE_VULN_TELEGRAM_MAX_LINES);
  check(
    'telegram Bild-Zeilen gekappt (16..19 fehlen)',
    bodyMany.includes('• img14:1.0.0') && !bodyMany.includes('• img15:1.0.0') && !bodyMany.includes('• img19:1.0.0')
  );
  check('telegram "+5 weitere (Report)"', bodyMany.includes('… +5 weitere (Report)'));
  // Novel-Regel unverändert: Body ohne novel-Einträge enthält keine 🛡-Sektion.
  const bodyNone = telegramBody(first, true, []);
  check('telegram ohne novel → keine 🛡-Sektion', !bodyNone.includes('🛡 Image-Vulns'));

  process.stdout.write(ok ? './ image-vulns-test PASS\n' : '✗ image-vulns-test FAIL\n');
  return ok ? 0 : 1;
}

main().catch((err) => {
  const msg = err instanceof Error ? err.stack ?? err.message : String(err);
  log(`FATAL: ${msg}`);
  process.exit(1);
});

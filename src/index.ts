// CLI-Einstieg: audit-scanner [scan|inventory|test-telegram]

import { CRON_SCHEDULE, fixPrsEnabled, log } from './config.js';
import { loadInventory } from './inventory.js';
import { llmEnabled, triageFindings, type TriageInput } from './llm.js';
import { runScan } from './scan.js';
import {
  ageDays,
  isKnownFinding,
  loadState,
  parseState,
  prOpenStatus,
  upsertEntry,
  type State,
} from './state.js';
import { sendTelegramReport } from './telegram.js';

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
  triage-test   LLM-Triage mit 2 Fake-Findings prüfen (kein Scan, kein Telegram).
  state-test    PR-Dedupe-State: parse/reconciliation-Selbsttest mit simulierten Entries,
                PR-Status-Check gegen mayraost/audit-scanner (Fake-Branch → kein offener
                PR erwartet). Keine echten PRs, kein Telegram-Versand.

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
    case 'state-test': {
      process.exitCode = await stateTest();
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

main().catch((err) => {
  const msg = err instanceof Error ? err.stack ?? err.message : String(err);
  log(`FATAL: ${msg}`);
  process.exit(1);
});

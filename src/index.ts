// CLI-Einstieg: audit-scanner [scan|inventory|test-telegram]

import { CRON_SCHEDULE, fixPrsEnabled, log } from './config.js';
import { loadInventory } from './inventory.js';
import { runScan } from './scan.js';
import { sendTelegramReport } from './telegram.js';

function usage(): never {
  process.stdout.write(`audit-scanner — Nightly CVE-Scan der mayraost-Repos

  ${'$'} audit-scanner <COMMAND>

COMMANDS
  scan          Inventar + tarball + trivy fs + Advisories + (opt) Fix-PRs + Telegram
                Fix-PRs nur mit ENABLE_FIX_PRS=1; Repos via SKIP_REPOS oder
                repo-lokaler Datei .cve-audit-skip ausklammerbar.
  inventory     Nur Inventarlisting (Repos + erkannte Manifests/Ökosysteme).
  test-telegram 1 Test-Nachricht via TELEGRAM_BOT_TOKEN/TELEGRAM_CHAT_ID senden.

ENV
  GH_TOKEN            Pflicht (Bearer für api.github.com). Dev-Fallback lokal:
                      \`gh auth token\` (gh-CLI), wenn GH_TOKEN fehlt — im Container
                      ist GH_TOKEN immer gesetzt.
  TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID   Telegram-Notify (optional, sonst Skip).
  ENABLE_FIX_PRS      "1" aktiviert Auto-Fix-PRs (Standard: aus).
  SKIP_REPOS          Kommagetrennte Repo-Skip-Liste.
  CRON_SCHEDULE       cron-String für busybox crond (Standard: ${CRON_SCHEDULE} UTC).
  TRIVY_BIN           trivy-Pfad (Standard: trivy im PATH).

`);
  process.exit(1);
}

async function main(): Promise<void> {
  const cmd = process.argv[2];
  switch (cmd) {
    case 'scan': {
      const report = await runScan({ sendTelegram: true, fixPrs: fixPrsEnabled() });
      log(
        `scan fertig: ${report.summary.scanned}/${report.summary.reposTotal} Repos gescannt, ` +
          `${report.summary.findings} high/critical, ${report.summary.fixPrs} Fix-PRs, ` +
          `${report.summary.apiCalls} API-Calls.`
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

main().catch((err) => {
  const msg = err instanceof Error ? err.stack ?? err.message : String(err);
  log(`FATAL: ${msg}`);
  process.exit(1);
});

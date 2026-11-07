// Selbsttest Pins-Qualität (v1.7.2) — OFFLINE: keine Registry, kein GitHub,
// kein Lockfile- Subprozess. Alle Außenkontakte (npm-Packument, GitHub
// contents GET/PUT, Lockfile-Regen, PR-Erzeugung) laufen über injizierte Fakes
// (`PIN_DEPS`), die Produktions-Pfade sind identisch (createPinsPr/peerGate).
//
// Regressionen (belegt im CVE-Audit-Lauf 2026-11-07):
// - D1 `[skip ci]`: Commit-Marker ließ Coolify den Deploy still überspringen
//   (Webhook 200 OK, kein Deploy-Record). Keine Commit-Message darf ihn tragen.
// - D2 Peer-Blindheit: `graphql` ^17 gepinnt, Payload 3.93 verlangt ^16.8.1 →
//   `npm ci` ERESOLVE. Peer-Gate weicht auf die Range-Version aus bzw. lässt
//   den Pin fail-closed aus.
// - D3 Lockfile fail-open: Manifest-PUT vor dem Regen, Regen-Fehler führte nur
//   zu `continue` → Merges ohne Lockfile (private-ai-interface #5/#9,
//   scobio2026 #8, internal-dashboard #5). PR-Body behauptete trotzdem
//   "Lockfiles were regenerated". Jetzt: alles-oder-nichts, draft + ⚠️.
// - D4 Image-Release-Check: Registry-Tag-Präfix (Docker Hub ohne `v`, MCR mit
//   `v`, Quay) und nie "kein Image" aus einer unbelastbaren Probe.
//
// Ausführung: `npm run pinning-test` (bzw. `node dist/index.js pinning-test`).

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import semver from 'semver';

import type { PinDeps, PinFinding, GhFile } from './pinning.js';
import { createPinsPr, effectiveVersion, peerConflictLabel, peerGate } from './pinning.js';
import { isBelievable, registryTagCandidates, type ManifestProbe } from './release-check.js';
import { splitRef } from './image-scan.js';
import type { RepoInfo } from './inventory.js';
import type { State } from './state.js';

/** Registry-Fixture: pkg → { latest, versions: {ver: peerDeps} }. */
interface FakePkg {
  latest: string;
  versions: Record<string, Record<string, string>>;
}

export interface PinTestFakes {
  registry?: Record<string, FakePkg>;
  /** repo-relativer Pfad → Datei-Inhalt (Branch-Stand). */
  files?: Record<string, string>;
  /** Regenerat: lockPath → geänderter Inhalt ODER Fehler-Note (null = unchanged). */
  regen?: (lockContent: string, pkgJson: string) => { content: string | null; note?: string };
  /** Kandidaten, für die der Regen fehlschlagen soll (pkg-Namen). */
  regenFailsFor?: string[];
  pr?: 'created' | 'fail';
}

export interface PinTestRecorder {
  puts: Array<{ path: string; message: string; content: string }>;
  prBodies: string[];
  prDrafts: boolean[];
}

const REPO = {
  name: 'demo-repo',
  private: false,
  defaultBranch: 'main',
  ecosystem: 'npm',
  manifestPaths: ['package.json'],
  archived: false,
  skipSource: null,
  configSkip: false,
} as unknown as RepoInfo;

/** Komplette Fake-`PinDeps` (nur die für die Tests relevanten Felder). */
export function fakeDeps(
  f: PinTestFakes,
  rec: PinTestRecorder
): PinDeps {
  const files = { ...(f.files ?? {}) };
  const reg = f.registry ?? {};
  const packument = (pkg: string) => {
    const p = reg[pkg];
    if (!p) return Promise.resolve(null);
    const versions: Record<string, { peerDependencies?: Record<string, string> }> = {};
    for (const [v, peers] of Object.entries(p.versions)) versions[v] = { peerDependencies: peers };
    return Promise.resolve({ 'dist-tags': { latest: p.latest }, versions });
  };
  return {
    packument,
    peerDepsOf: async (pkg, version) => (await packument(pkg))?.versions?.[version]?.peerDependencies ?? null,
    versionsOf: async (pkg) => {
      const p = await packument(pkg);
      return p?.versions ? Object.keys(p.versions) : null;
    },
    contentsGet: async (_repo, filePath): Promise<GhFile | null> =>
      filePath in files ? { sha: `sha-${filePath}`, content: Buffer.from(files[filePath]!, 'utf8').toString('base64') } : null,
    contentsPut: async (_repo, filePath, _branch, _sha, content, message) => {
      rec.puts.push({ path: filePath, message, content });
      files[filePath] = content;
    },
    regenerate: async (_eco, pkgJson, lockContent) => {
      const pkg = JSON.parse(pkgJson) as { dependencies?: Record<string, string>; devDependencies?: Record<string, string> };
      const names = [...Object.keys(pkg.dependencies ?? {}), ...Object.keys(pkg.devDependencies ?? {})];
      if (f.regenFailsFor?.some((p) => names.includes(p))) {
        return { changed: false, note: `simulierter ERESOLVE für ${f.regenFailsFor.join(', ')}` };
      }
      const r = f.regen ? f.regen(lockContent, pkgJson) : { content: lockContent };
      return r.content === null
        ? { changed: false, note: r.note ?? 'simulierter Regen-Fehler' }
        : { changed: r.content !== lockContent, content: r.content };
    },
    createPr: async (_repo, o) => {
      if (f.pr === 'fail') throw new Error('simulierter PR-Fehler');
      rec.prBodies.push(o.body);
      rec.prDrafts.push(o.draft);
      return { number: 42, url: 'https://github.com/mayraost/demo-repo/pull/42' };
    },
    createRef: async () => 'created',
    headSha: async () => 'deadbeef',
    findOpenPr: async () => null,
  };
}

function finding(pkg: string, current: string, latest: string, extra: Partial<PinFinding> = {}): PinFinding {
  return {
    pkg,
    current,
    latest,
    section: 'dependencies',
    manifestPath: 'package.json',
    severity: 'warn',
    eligibility: 'eligible',
    ...extra,
  };
}

/**
 * Kompletter Pins-PR-Durchlauf ohne Netz: `collectPinning` wird nicht
 * gebraucht (Scan läuft im tmp-Checkout) — die Peer-Gate-Bewertung ist hier
 * explizit vorab gesetzt, damit der PR-Pfad isoliert testbar bleibt.
 */
async function runPr(f: PinTestFakes, findings: PinFinding[]): Promise<{ rec: PinTestRecorder; result: Awaited<ReturnType<typeof createPinsPr>> }> {
  const rec: PinTestRecorder = { puts: [], prBodies: [], prDrafts: [] };
  const state: State = { prs: {} };
  const result = await createPinsPr(REPO, findings, state, fakeDeps(f, rec));
  return { rec, result };
}

/** Projekt-Fixture: Manifest mit Lockfile. */
const PKG = `${JSON.stringify(
  { name: 'demo', version: '1.0.0', dependencies: { lodash: '^4.17.0', '@payloadcms/next': '4.0.0-beta.7', graphql: '^16.8.1' } },
  null,
  2
)}\n`;
const LOCK = `${JSON.stringify({ name: 'demo', lockfileVersion: 3, packages: { '': { dependencies: {} } } }, null, 2)}\n`;

export async function pinningTest(): Promise<number> {
  let ok = true;
  const check = (label: string, pass: boolean, detail = ''): void => {
    process.stdout.write(`${pass ? 'OK  ' : 'FAIL'} ${label}${detail ? ` — ${detail}` : ''}\n`);
    ok &&= pass;
  };

  // ————————————————————— D2: Peer-Awareness (Offline-Registry) —————————————————
  // Real-Fall 2026-11-07: @payloadcms/next 4.0.0-beta.7 (bzw. 3.93.0) verlangt
  // peer graphql ^16.8.1, dist-tags.latest von graphql war 17.0.2.
  const lookup = {
    peerDepsOf: async (pkg: string, version: string): Promise<Record<string, string>> =>
      pkg === '@payloadcms/next' && version === '4.0.0-beta.7' ? { graphql: '^16.8.1' } : {},
    versionsOf: async (pkg: string) =>
      pkg === 'graphql'
        ? ['15.10.1', '16.8.1', '16.14.2', '17.0.0', '17.0.2']
        : pkg === '@payloadcms/next'
          ? ['4.0.0-beta.7']
          : null,
  };
  const clash = await peerGate('graphql', '17.0.2', { '@payloadcms/next': '4.0.0-beta.7' }, lookup);
  check(
    'D2 Peer-Konflikt erkannt (graphql 17.0.2 vs payload peer ^16.8.1)',
    clash?.dep === '@payloadcms/next' && clash.depVersion === '4.0.0-beta.7' && clash.range === '^16.8.1',
    clash ? JSON.stringify(clash) : 'kein Konflikt'
  );
  check('D2 Ausweichen auf höchste Range-Version (16.14.2, nicht 17.x)', clash?.fallback === '16.14.2', String(clash?.fallback));
  check(
    'D2 PR-Body-Label nennt Peer-Range + Ausweichversion',
    /peer-Konflikt mit @payloadcms\/next@4\.0\.0-beta\.7 \(requires \^16\.8\.1\) → Ausweichversion 16\.14\.2/.test(
      peerConflictLabel(clash!)
    ),
    peerConflictLabel(clash!)
  );
  const noConflict = await peerGate('graphql', '16.14.2', { '@payloadcms/next': '4.0.0-beta.7' }, lookup);
  check('D2 passendes latest → kein Konflikt', noConflict === null);

  // Kein Range-konformer Kandidat → fail-closed (null)
  const hopeless = await peerGate('graphql', '17.0.2', { '@payloadcms/next': '4.0.0-beta.7' }, {
    peerDepsOf: async (): Promise<Record<string, string>> => ({ graphql: '^16.8.1' }),
    versionsOf: async (pkg) => (pkg === 'graphql' ? ['17.0.0', '17.0.2'] : ['4.0.0-beta.7']),
  });
  check('D2 keine passende Version → fallback null (fail-closed)', hopeless !== null && hopeless.fallback === null);

  // Nicht-semver-Ranges (`*`, `latest`) dürfen keinen Pin blockieren
  const wildcard = await peerGate('graphql', '17.0.2', { payload: '3.93.0' }, {
    peerDepsOf: async (): Promise<Record<string, string>> => ({ graphql: '*' }),
    versionsOf: async (pkg) => (pkg === 'graphql' ? ['17.0.2'] : ['3.93.0']),
  });
  check('D2 peer "*" blockiert keinen Pin', wildcard === null);

  // floating Spec → "installierte" Version = höchste erlaubte Version
  check('D2 effectiveVersion(^16.8.1) = 16.14.2', effectiveVersion('^16.8.1', ['16.8.1', '16.14.2', '17.0.2']) === '16.14.2');
  check('D2 effectiveVersion(exakt) bleibt exakt', effectiveVersion('3.93.0', ['3.94.0']) === '3.93.0');

  // Findet der Regen trotz Peer-Gate einen Konflikt (transitive Peer), muss der
  // Manifest-Pin fail-closed draußen bleiben — Kern von D3.
  // (Das Manifest hat sonst keine Änderung; nur `graphql` ist floating.)
  const t3b = await runPr(
    {
      files: { 'package.json': PKG, 'package-lock.json': LOCK },
      regenFailsFor: ['graphql', '@payloadcms/next'],
    },
    [finding('graphql', '^16.8.1', '17.0.2', { peerConflict: { dep: '@payloadcms/next', depVersion: '4.0.0-beta.7', range: '^16.8.1', fallback: null } })]
  );
  check('D3b Peer-Konflikt ohne Fallback → kein Manifest-PUT', t3b.rec.puts.length === 0, `puts=${t3b.rec.puts.length}`);
  check(
    'D3b Status skipped, Note nennt Peer-Konflikt',
    t3b.result.status === 'skipped' && /peer/i.test(t3b.result.note ?? ''),
    `${t3b.result.status}/${t3b.result.note ?? ''}`
  );

  // ————————————— D3: Lockfile fail-closed (Regen scheitert → kein Pin) —————————————
  {
    const { rec, result } = await runPr(
      {
        files: { 'package.json': PKG, 'package-lock.json': LOCK },
        regenFailsFor: ['graphql'],
      },
      [finding('graphql', '^16.8.1', '17.0.2')]
    );
    const manifestPut = rec.puts.some((p) => p.path === 'package.json');
    const lockPut = rec.puts.some((p) => p.path === 'package-lock.json');
    check('D3 Regen scheitert → KEIN package.json-PUT', !manifestPut);
    check('D3 Regen scheitert → KEIN package-lock.json-PUT', !lockPut);
    check('D3 Regen scheitert → Status skipped (kein PR)', result.status === 'skipped', `${result.status} ${result.note ?? ''}`);
  }

  // Kein abdeckendes Lockfile → fail-closed
  {
    const { rec, result } = await runPr({ files: { 'package.json': PKG } }, [finding('lodash', '^4.17.0', '4.18.1')]);
    check('D3 kein Lockfile → kein Manifest-PUT', rec.puts.length === 0, `puts=${rec.puts.length}`);
    check('D3 kein Lockfile → skipped mit Note', result.status === 'skipped' && /Lockfile/i.test(result.note ?? ''), result.note ?? '');
  }

  // Erfolgsfall: Lockfile ZUERST, dann Manifest — beide im PR, kein [skip ci]
  {
    const { rec, result } = await runPr(
      {
        files: { 'package.json': PKG, 'package-lock.json': LOCK },
        regen: () => ({ content: LOCK.replace('{}', '{"lodash":"4.18.1"}') }),
      },
      [finding('lodash', '^4.17.0', '4.18.1')]
    );
    const order = rec.puts.map((p) => p.path);
    check('D3 Erfolg: Lockfile-Commit vor Manifest-Commit', order.join(',') === 'package-lock.json,package.json', order.join(','));
    check('D3 Erfolg: PR erstellt (nicht draft bei sauberem Lauf)', result.status === 'created' && rec.prDrafts[0] === false, `${result.status} draft=${rec.prDrafts[0]}`);
    check('D3 Erfolg: Manifest enthält exakten Pin', /"lodash": "4\.18\.1"/.test(rec.puts.find((p) => p.path === 'package.json')?.content ?? ''));
    const body = rec.prBodies[0] ?? '';
    check(
      'D3 Erfolg: PR-Body nennt regeneriertes Lockfile',
      /Lockfile\(s\) regenerated in-place/.test(body) && body.includes('`package-lock.json`'),
      body.split('\n').find((l) => /Lockfile/.test(l)) ?? '—'
    );
    check('D3 Erfolg: kein ⚠️-Skip-Block', !/NOT applied/.test(body));
  }

  // Teilausfall: von zwei Manifests scheitert eines → PR enthält nur das
  // saubere Manifest als Draft + ⚠️-Hinweis (nicht mergen als "vollständig").
  {
    const mono = {
      workspaces: ['packages/*'],
      dependencies: { lodash: '^4.17.21' },
    };
    const webPkg = `${JSON.stringify({ name: 'web', dependencies: { graphql: '^16.8.1' } }, null, 2)}\n`;
    const { rec, result } = await runPr(
      {
        files: {
          'package.json': `${JSON.stringify(mono, null, 2)}\n`,
          'package-lock.json': LOCK,
          'packages/web/package.json': webPkg,
        },
        regen: (lockContent, pkgJson) =>
          pkgJson.includes('"graphql"')
            ? { content: null, note: 'simulierter ERESOLVE für graphql' }
            : { content: `${lockContent} ` },
      },
      [
        finding('lodash', '^4.17.21', '4.18.1'),
        finding('graphql', '^16.8.1', '17.0.2', { manifestPath: 'packages/web/package.json' }),
      ]
    );
    const touched = rec.puts.map((p) => p.path);
    check('D3 Teilausfall: nur Root-Manifest+Lockfile geschrieben', touched.join(',') === 'package-lock.json,package.json', touched.join(',') || '—');
    const body = rec.prBodies[0] ?? '';
    check('D3 Teilausfall: PR ist Draft', rec.prDrafts[0] === true, String(rec.prDrafts[0]));
    check('D3 Teilausfall: PR-Body ⚠️ "NOT applied" + Kandidat genannt', /NOT applied/.test(body) && /graphql/.test(body));
    check('D3 Teilausfall: Status created', result.status === 'created', result.status);
  }

  // ————————————————— D1: kein [skip ci] in erzeugten Messages —————————————————
  {
    const { rec } = await runPr(
      {
        files: { 'package.json': PKG, 'package-lock.json': LOCK },
        regen: () => ({ content: `${LOCK} ` }),
      },
      [finding('lodash', '^4.17.0', '4.18.1')]
    );
    check('D1 Commit-Messages erzeugt (2)', rec.puts.length === 2, `n=${rec.puts.length}`);
    const withSkip = rec.puts.filter((p) => /\[skip (ci|cd)\]/i.test(p.message));
    check('D1 keine [skip ci]/[skip cd]-Marker in Pins-Commits', withSkip.length === 0, withSkip.map((p) => p.message).join(' | '));
    check(
      'D1 Commit-Messages im chore(cve-audit)-Format',
      rec.puts.every((p) => /^chore\(cve-audit\): /.test(p.message)),
      rec.puts.map((p) => p.message).join(' | ')
    );
  }

  // ————————————— D4: Image-Release-Tag-Präfix (Docker Hub / MCR / Quay) —————————————
  check('D4 Docker Hub: v0.76.2 → [v0.76.2, 0.76.2]', registryTagCandidates('v0.76.2').join('|') === 'v0.76.2|0.76.2');
  check('D4 Docker Hub: 0.76.2 → [0.76.2, v0.76.2]', registryTagCandidates('0.76.2').join('|') === '0.76.2|v0.76.2');
  check('D4 MCR: v0.0.84 → [v0.0.84, 0.0.84]', registryTagCandidates('v0.0.84').join('|') === 'v0.0.84|0.0.84');
  // MCR bestätigt live: manifests/v0.0.83 = 200, manifests/0.0.83 = 404.
  const mcrProbe: ManifestProbe = { status: 'absent', tried: ['v0.0.84', '0.0.84'] };
  check('D4 MCR beide 404 → "kein Image" erlaubt', isBelievable(mcrProbe) === 'absent');
  const mcrHit: ManifestProbe = { status: 'present', tried: ['v0.0.83', '0.0.83'], matched: 'v0.0.83' };
  check('D4 MCR v-Tag gefunden → present (kein falsches "kein Image")', isBelievable(mcrHit) === 'present');
  const flaky: ManifestProbe = { status: 'unknown', tried: ['v1.1.0', '1.1.0'], unknown: ['1.1.0'] };
  check('D4 unbelastbare Probe → unknown (keine Behauptung)', isBelievable(flaky) === 'unknown');
  // Quay verhält sich live wie MCR: Tag trägt `v` (quay.io/argoproj/argocd: v2.13.0 = 200).
  const quayProbe: ManifestProbe = { status: 'present', tried: ['v2.13.0', '2.13.0'] };
  check('D4 Quay v-Tag → present', isBelievable(quayProbe) === 'present');

  // Registry-Erkennung: quay.io → 'quay' (Release-Check nutzt denselben Präfix-Flip)
  check('D4 splitRef quay.io → registry=quay', splitRef('quay.io/argoproj/argocd:v2.13.0').registry === 'quay');
  check('D4 splitRef mcr → registry=mcr', splitRef('mcr.microsoft.com/playwright/mcp:v0.0.83').registry === 'mcr');
  check('D4 splitRef docker.io → registry=docker-hub', splitRef('aquasec/trivy:0.76.2').registry === 'docker-hub');
  check(
    'D4 ghcr-Build-Meta-Tag bleibt verbatim (kein erfundener Flip)',
    registryTagCandidates('2026.11.1-9ded3bec1').join('|') === '2026.11.1-9ded3bec1'
  );
  check('D4 Notizen/Tags: v2.13.0 flippt (Quay/MCR-Muster)', registryTagCandidates('v2.13.0').join('|') === 'v2.13.0|2.13.0');
  check('D4 Nicht-Versions-Tag bleibt verbatim', registryTagCandidates('main-20261101').join('|') === 'main-20261101');

  // ————————————————————————— Manifest-Version in der Sandbox —————————————————————————
  // (nur als Guard: die Fixtures müssen semver-gültig bleiben)
  check('Fixture-PKG parst', semver.valid('4.0.0-beta.7') !== null);
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'pinning-test-'));
  try {
    fs.writeFileSync(path.join(tmp, 'package.json'), PKG);
    check('Fixture-PKG ist wohlgeformt', Object.keys(JSON.parse(fs.readFileSync(path.join(tmp, 'package.json'), 'utf8'))).length > 0);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }

  process.stdout.write(ok ? './ pinning-test PASS\n' : '✗ pinning-test FAIL\n');
  return ok ? 0 : 1;
}

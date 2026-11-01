// Inventar: alle Owner-Repos (public+private, forks excluded) per /user/repos
// (paginiert) + Manifest-Discovery über Git-Trees API (Spec §2c).
// `HEAD` als tree-ref resolved den Default-Branch (getestet).

import { OWNER, log, skipRepos } from './config.js';
import { ghJson, ghPaginate } from './github.js';

export type Ecosystem = 'npm' | 'pnpm' | 'yarn' | 'pip' | 'go' | 'cargo';

/** Lockfile-/Manifest-Basename → Ökosystem (nur oberste Ebene je Repo-Hauptprojekt). */
export const MANIFEST_MAP: Record<string, Ecosystem> = {
  'package-lock.json': 'npm',
  'pnpm-lock.yaml': 'pnpm',
  'yarn.lock': 'yarn',
  'requirements.txt': 'pip',
  'go.mod': 'go',
  'Cargo.toml': 'cargo',
};

export interface RepoInfo {
  name: string;
  private: boolean;
  defaultBranch: string;
  manifestPaths: string[];
  ecosystem: Ecosystem | null;
  lockedPath: string | null;
  /** Repo wird übersprungen (ENV-Skip-Liste oder Repo-Konfig-Datei `.cve-audit-skip`). */
  configSkip: boolean;
  skipSource: 'SKIP_REPOS' | '.cve-audit-skip' | null;
  treeTruncated: boolean;
}

interface RawRepo {
  name: string;
  fork?: boolean;
  private?: boolean;
  default_branch?: string;
}

interface RawTree {
  truncated?: boolean;
  tree: Array<{ path: string; type?: string }>;
}

export async function loadInventory(): Promise<RepoInfo[]> {
  const repos = await ghPaginate<RawRepo>('/user/repos?sort=full_name&affiliation=owner');
  const owned = repos.filter((r) => r.fork === false && r.name);
  log(`Inventar: ${owned.length} Owner-Repos (forks excluded).`);

  const out: RepoInfo[] = [];
  for (const repo of owned) {
    const name = repo.name as string;
    const defaultBranch = repo.default_branch ?? 'main';
    const envSkip = skipRepos().includes(name);
    const info: RepoInfo = {
      name,
      private: repo.private ?? false,
      defaultBranch,
      manifestPaths: [],
      ecosystem: null,
      lockedPath: null,
      configSkip: envSkip,
      skipSource: envSkip ? 'SKIP_REPOS' : null,
      treeTruncated: false,
    };
    if (envSkip) {
      out.push(info); // ENV-Skip: Tree-Lookup unnötig
      continue;
    }
    try {
      const tree = await ghJson<RawTree>(
        `/repos/${OWNER}/${name}/git/trees/${defaultBranch}?recursive=1`
      );
      const paths = tree.tree
        .map((t) => t.path)
        .filter((p) => !p.includes('node_modules/'));

      const manifests = [...new Set(paths.filter((p) => MANIFEST_MAP[base(p)] !== undefined))];
      const first = manifests[0];
      const eco = first !== undefined ? MANIFEST_MAP[base(first)] ?? null : null;
      const lockedPath = pickLockedPath(manifests);
      const configSkip = paths.includes('.cve-audit-skip');

      out.push({
        ...info,
        manifestPaths: manifests,
        ecosystem: eco,
        lockedPath,
        configSkip,
        skipSource: configSkip ? '.cve-audit-skip' : null,
        treeTruncated: tree.truncated === true,
      });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      log(`WARN: Tree-API-Fehler für ${name}: ${msg}`); // leeres Info-Objekt bleibt stehen
      out.push(info);
    }
  }
  return out;
}

function base(p: string): string {
  const i = p.lastIndexOf('/');
  return i === -1 ? p : p.slice(i + 1);
}

function pickLockedPath(manifests: string[]): string | null {
  const priority: Ecosystem[] = ['npm', 'pnpm', 'yarn', 'pip', 'go', 'cargo'];
  for (const eco of priority) {
    const hit = manifests.find((p) => MANIFEST_MAP[base(p)] === eco && p === base(p));
    if (hit) return hit; // Lockfile auf Repo-Root bevorzugt
  }
  const any = manifests.find((p) => p === base(p));
  return any ?? null;
}

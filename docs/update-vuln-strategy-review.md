# Update- & Vulnerability-Strategy-Review (audit-scanner)

**Stand:** 2026-11-07 · **Reviewer:** Subagent (analyze-only, keine Änderungen an `src/*`, `package.json`, `Dockerfile`, `docker-compose.yml`, `README.md`)
**Ziel:** Bewertung des Ist-Zustands von Update-/Vuln-Erkennung + Design-Skizzen für die neuen Anforderungen N1 (bessere Wege als Eigenbau), N2 (BETA-Erkennung, Info-only), N3 (3-Tage-Soaking mit CVE-Ausnahme), N4 (Tests/Verifikation, Code-Risiken).

> **Parallel in Arbeit (nicht als Ist-Zustand dokumentiert, aus der Bewertung ausgeklammert):**
> (a) `src/image-scan.ts` — Freshness/Variant-Drift (`variantDrift`, `variantCompatible`, `OS_RELEASE_TOKENS`, `variantDriftTag`, Selbsttest `image-freshness-test`), fälschliches „aktuell" bei Variant-Wechsel.
> (b) `src/scan.ts` + `src/state.ts` — Base-Image-Vulns als eigene Findings (`ImageVulnFinding`, `imageVulnFindings`, `imageVulns`-Novelty-Register, 🛡-Telegram-Sektion), plus `src/index.ts` `image-vulns-test`.
> Wo diese Themen doch hungrig angefragt werden (N3-CVE-Ausnahme beim Image-Bump), beschreibe ich nur die **Schnittstelle**, nicht deren aktuellen Code.

---

## 1. Executive Summary

1. **Grundarchitektur bleibt Eigenbau.** Cross-Repo-Inventar, Pins-Policy, Telegram-Bündelung und PR-Anlage in einem deterministischen Lauf sind mit keinem Fremdtool in dieser Form abbildbar. Aufwand, das zu ersetzen: **L**.
2. **Aber: Datenquellen modernisieren.** `trivy image` je Ref (12-Min-Timeout, DB-Download, ~19 Refs/12 Repos) ist der teuerste Block. Trivy liefert nur CVE-IDs ohne CVSS/EPSS/KEV — Priorisierung fehlt komplett.
3. **Empfehlung N1 (Kern):** OSV.dev `querybatch` als **primärer Advisory-Layer** für npm/pip/go/cargo (1 Call/Repo statt 1 Call/Vuln gegen `/advisories`), Trivy bleibt Scanner (Lockfile-Evidenz). EPSS+KEV als reine Priorisierungs-Annotation (keine Suppress-Logik). **M**.
4. **Empfehlung N1 (Fremdtools):** Renovate **nicht** als Ersatz, aber `minimumReleaseAge: "3 days"` + `vulnerabilityAlerts` als **Vorlage** für unsere Soaking-Regel (N3) — die Semantik ist identisch, wir bauen sie aber im Scanner nach, weil PR-/Telegram-Konsolidierung Eigenbau bleibt. **M**.
5. **N2 BETAs:** Kein Hard-Filter mehr, sondern **drei Klassen**: `prerelease-hint` (Info), `prerelease-current` (Repo steht schon im Pre-Release-Kanal), `prerelease-exotic` (Muttern, die man dauerhaft nicht will). Report-only, **nie** PR. **S**.
6. **N3 Soaking:** Rein deterministisch zur Laufzeit (`publishedAt` vs `now`), **kein** State nötig, keine „skip"-Persistenz. Publish-Datum ist für alle relevanten Quellen **ohne Docker-Daemon** verfügbar — verifiziert (npm `time`, Docker Hub `tag_last_pushed`, GHCR OCI-Annotation `org.opencontainers.image.created`, PyPI `upload_time_iso_8601`, deps.dev `publishedAt`). **M**.
7. **N3 CVE-Ausnahme:** Zwei Trigger — (a) Paket-Scan: `first_patched` der Advisory entspricht der Zielversion, (b) Image-Bump: Trivy meldet im **Ziel-Image** weniger H/C als im aktuellen. (b) ist teuer (Extra-Scan); preiswerter Ersatz: Base-OS-Patch-Release-Erkennung. **M**.
8. **Kritischer Bug gefunden (P1):** `replaceTag()` in `src/image-scan.ts:833` matcht Substrings ohne Tag-Grenze links → `node:24-alpine` → `node:24.12.0-alpine-alpine`. Real reproduzierbar mit gültigem Bump-Plan. Fix: ganze Ref-Token mit Grenzen `(?<![A-Za-z0-9._/-])…(?![A-Za-z0-9._-])`. **S**.
9. **Zweiter Bug (P2):** Trivy-DB-Update wird nicht auf einen dichten Cache gesetzt (Probe-Report 2026-11-07 zeigt 6 H auf `node:26.13.0-alpine3.24` bei 5 Repos gleichzeitig — plausibel entweder Echtbefund oder DB-Version-Drift). Vor jeder Aufstockung der Checks prüfen: **ein** DB-Stand je Lauf (Lockfile-artiges Cache-Snapshot).
10. **Nicht ändern:** PR-Branch-Schema (`cve-audit/*-<date>`), State-Dedupe, Lockfile-Regen, Telegram-Chunking, LLM-Triage-Default (deterministischer Fallback ist korrekt).
11. **Tests (N4):** 4 Selbsttests vorhanden (`state-test`, `image-freshness-test`, `image-vulns-test`, `triage-test`), aber **keine** Unit-Tests für Parser (`parseInstr`, `parseCompose`, `replaceTag`, `tagSemantics`, `bumpRequirementsTxt`, `semverSatisfies`) und **keine** CI-Pipeline. Das ist die dünnste Stelle.
12. **Aufwand gesamt (empfohlen):** ca. **1 × L**, **3 × M**, **3 × S** → 6–9 Personentage. Reihenfolge siehe §8.

---

## 2. Ist-Zustand

### 2.1 Pipeline je Prüfart

| Prüfart | Einstieg | Quelle | Output | Fix-PR |
|---|---|---|---|---|
| **Inventar** | `src/inventory.ts:52` `loadInventory()` | `GET /user/repos?sort=full_name&affiliation=owner` (paginiert) + `GET /repos/{owner}/{name}/git/trees/{branch}?recursive=1` | `RepoInfo[]` (archivierte hart gefiltert `:63–65`) | — |
| **Tarball** | `src/scan.ts:635` `downloadTarball()` | `GET /repos/.../tarball/{branch}` → `tar xzf` | `repoDir` | — |
| **CVE-Scan (fs)** | `src/scan.ts:677` `runTrivy()` | `trivy fs --scanners vuln` (kein `--severity` → lokal gefiltert `:686–704`); DB-Cache in `TRIVY_CACHE_DIR` | `TrivyVuln[]` (H/C) | `cve-audit/fixes-<date>` |
| **Advisory-Crosscheck** | `src/advisories.ts:52` `fetchAdvisories()` | `GET /advisories?ecosystem=<eco>&affects=<pkg>@<ver>` **je Finding** (paginiert), lokal semver-match | `AdvisoryHit[]` (`ghsa`, `severity`, `range`, `firstPatched`) | Grundlage für `firstPatched` |
| **LLM-Triage** | `src/scan.ts:612` `applyTriage()` | DeepInfra, OpenAI-kompatibel; suppress nur bei conf ≥ 0.75 (`:63`) | `f.llm` | suppress → kein PR |
| **Image-Ref-Erkennung** | `src/image-scan.ts:83` `findManifestFiles()` → `parseInstr` / `parseCompose` | Dockerfile (`FROM`, `COPY/ADD --from`), Compose (`image:`) | dedup. `ImageFinding` | — |
| **Image-Vulns** | `src/image-scan.ts:509` `trivyImageScan()` | `trivy image` via Registry-API (kein Daemon), `--severity HIGH,CRITICAL` | `{high, critical}` **nur Zähler**, keine IDs | — (Report-only) |
| **Freshness** | `src/image-scan.ts:360` `fetchRegistryTags()` | `auth.docker.io`/`ghcr.io` token + `GET /v2/.../tags/list`, Paginierung bis 25 Seiten | `newestSameMajorTag()`, `newestExactTag()` | `cve-audit/images-<date>` |
| **Pinning (npm)** | `src/pinning.ts:119` `collectPinning()` | alle `package.json` (ohne `node_modules`), floating = `semver.valid(spec)===null` (`:65`) | `PinFinding[]` | `cve-audit/pins-<date>` |
| **Pinning-Lookup** | `src/pinning.ts:96` `npmLatest()` | `GET registry.npmjs.org/<pkg>` → **nur `dist-tags.latest`** | `latest` | Ziel-Version |
| **PR-Dedupe/State** | `src/state.ts:126/141` | `reports/state.json` im Volume `audit-reports` | offene PRs je Repo | — |
| **Telegram** | `src/scan.ts:840` `sendTelegramFromReport()` | Bot-API, plain text, Chunk 4000 | 1–N Messages | — |

### 2.2 Belege: Quellen und ihre Grenzen

**a) Gescannte Einheiten (Ist):** Nur Repos mit einem der `MANIFEST_MAP`-Einträge (`package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `requirements.txt`, `go.mod`, `Cargo.toml`) werden gescannt — `src/scan.ts:222–226`. Fehlt die Lockfile, fällt das Repo als `skipped-no-manifest` raus, auch wenn ein `package.json` existiert. Probe-Report 2026-11-07: 12 Repos im Inventar, **8 gescannt**, 4 mit `skipped-no-manifest` (`coolify-postgres`, `homeassistant`, `placeholder-404`, `wiki-hub`).

**b) Advisory-Crosscheck N Calls:** Ein `fetchAdvisories()`-Call pro Finding (`src/scan.ts:405`). Bei 54+43+77+97+25+6×5 = **~330** H/C-Findings im heutigen Report wären das ~330 paginierte GitHub-API-Aufrufe — im Probe-Report standen nur 22 `apiCalls`, weil die meisten Findings **trivy-only** ohne Advisory-Treffer waren (die initialen `fetchAdvisories` zählen nicht in `ghStats`, weil `ghPaginate` intern `ghFetch` nutzt? — plausibel, aber die Zahl wirkt trotzdem verdächtig klein; **nicht verifiziert**). Die Diagnose bleibt aber: **je Finding ein HTTP-Call, je Pkg-Kombination gecacht** (`cache`-Map in `advisories.ts:46`).

**c) Image-Vulns sind Zähler, keine Findings (Ist):** `trivyImageScan` (`image-scan.ts:509`) reduziert auf `{high, critical}` und verwirft `VulnerabilityID`, `FixedVersion`, `PkgName`. Es ist **technisch unmöglich**, aus den heutigen Daten einen „dieser Bump fixt CVE X"-Nachweis zu führen — weder für die Soaking-Ausnahme (N3) noch für die KEV-/EPSS-Priorisierung (N1).

**d) Freshness nur Docker Hub + GHCR:** `registry-other` → `'Freshness nur Docker Hub/GHCR — übersprungen'` (`image-scan.ts:361`). Probe-Report: `mcr.microsoft.com/playwright/mcp:v0.0.83` fällt komplett raus (H97/C8, aber kein Update-Check). `quay.io`, `registry.k8s.io`, `gcr.io` sind ebenso blinde Flecken — bei `private-ai-interface` sind das die interessantesten Images.

**e) Pre-Release-Hard-Filter (Ist, N2-relevant):**
- `tagSemantics()` `image-scan.ts:254`: `prerelease = /^-(alpha|beta|rc|dev|edge|snapshot|pre)/i.test(suffix) || suffix.startsWith('+rc')` — Übersehen: `-nightly`, `-canary`, `-next`, `-insiders`, `-v8`-Varianten, `-preview`, `-pre.1`, `-0.20260101`. `pinned`/`floating` werden bei `prerelease=true` auf `false` gesetzt → solche Tags sind dann **weder** Kandidat noch als aktueller Ref registriert; `addRef` (`:666`) macht eine `Pre-Release-Tag (…) — übersprungen`-Note. Ergo: ein Tag **`node:26.0.0-rc.1` in use** wird stillschweigend nie auf Updates geprüft.
- `newestSameMajorTag()` `:418` und `newestExactTag()` `:493` filtern `!c.sem.prerelease` hart.
- NPM-Pinning-Scan: `npmLatest()` `pinning.ts:96–112` liest **nur `dist-tags.latest`**; `prerelease`-Versionen in `package.json` (z.B. `"typescript": "7.1.0-beta"`) sind `semver.valid === true` und gelten damit als **exakt gepinnt** (`:65–71`) — kein Finding, aber auch keine Info „Beta-Kanal, neueres Beta verfügbar".

**f) Soaking/Cooldown existiert nirgends:** Kein `publishedAt`, `last_updated`, kein Datum im `PinFinding` (`pinning.ts:32–42`) oder `ImageFinding` (`image-scan.ts:36–67`). Jeder Fund mit `updateAvailable=true` triggert sofort PR + Telegram (`scan.ts:846`, `image-scan.ts:614–635`).

**g) Rate-Limit-Verhalten:** `ghFetch` (`github.ts:34–40`) wartet **einmal** bei `remaining===0`, Retry via Rekursion (kein Cap, kein Backoff-Exponent): wiederholter 403 → tiefe Rekursion bei langem Lauf. Registry-Calls haben **keinen** Retry; 401/403/404 → sofortige Note (`image-scan.ts:374–376`).

**h) Trivy-Timeout:** `trivyImageScan` 12 min je Image (`:518`), `runTrivy` 15 min je Repo (`scan.ts:681`). Bei 19 Refs sequentiell Lift-laufbar — Use-Case kaputt bei ~40 Refs (Giphy-Abbruch des Cron-Jobs, kein Alert).

### 2.3 Was der Scanner heute **nicht** prüft

| Lücke | Warum relevant für N1–N3 |
|---|---|
| `.nvmrc` fehlt/veraltet | Projektregel „`.nvmrc` Pflicht, bevorzugt `26`" — wird **gar nicht** geprüft, der Scanner selbst hat `26.13.0` (`(.nvmrc)`) |
| Dockerfile-Pin vs. `.nvmrc`-Konsistenz | `Dockerfile:6,14,19` pinnen `node:26.13.0-alpine3.24`, `.nvmrc` `26.13.0` — passt heute; Drift wäre unsichtbar |
| Digest-Pins | Regel „ggf. Digest", Scanner markiert nur (`digestPinned`) und bilanziert nicht |
| `image: audit-scanner:latest` im eigenen Compose | Selbstverstoß gegen Pins-Policy (`docker-compose.yml:8`) — als `latest`-Note vorhanden, aber nicht alarmierend |
| Lockfile-Committed / Lockfile-Drift zu `package.json` | Projektregel, gar nicht geprüft |
| `engines.node` / `.nvmrc` Konsistenz | `package.json` hat `"node": ">=24"` (**floating Major!**) neben `(.nvmrc) 26.13.0` |
| pnpm `pnpm-workspace.yaml`-Only-Repos (kein `package-lock`) | `MANIFEST_MAP` deckt nur `package-lock`/`pnpm-lock`/`yarn.lock` ab — Repo **ohne** einen davon fällt raus |
| Go/Cargo-**Updates** | Nur Report einzeln ohne Auto-Fix, keine Freshness (`fix-pr.ts:115` `supportable`) |
| pip-Pinning | `requirements.txt` mit `>=` ist immer „pinned" für den Pinning-Check, aber das ist Floating per Definition der Projektregel — **nicht** erkannt |
| pyproject / poetry / uv | Nicht unterstützt |

---

## 3. Fremdtool-Abwägung

Ziel dieses Abschnitts ist **nicht** „Renovate übernehmen", sondern „was macht Renovate **besser**, was macht unser Scanner **besser**, und wo ist der Austausch wirtschaftlich sinnvoll". Die **Kern-These**: Der Scanner hat bereits eine Eigenschaft, die Renovate nicht hat: **ein Inventar** über alle Repos mit einem einheitlichen Report und einer Telegram-Nachricht. Renovate läuft **pro Repo** als GitHub App oder self-hosted — d.h. bei 12 Repos 12 Bot-Accounts / 12 PR-Flows / 12 Konfigurations-Schemas. Dependabot analog.

### 3.1 Vergleichstabelle

| Werkzeug | Was es löst | Was es kostet (für **dieses** Setup) | Empfehlung | Begründung |
|---|---|---|---|---|
| **Renovate (self-hosted)** | Dep-Updates inkl. `minimumReleaseAge`, `vulnerabilityAlerts`, `ignoreUnstable`, `followTag`, Docker-Tag-Major-Pinning (`docker`+`docker-compose` Manager), Lockfile-Regen, PR-Erzeugung, `datasource`-basiert (npm/PyPI/Go/Cargo/Docker Hub/GHCR/custom) | Self-hosted: eigener Container, GitHub App o. PAT, Repo-Konfig pro Repo (`renovate.json`), **kein** Cross-Repo-Report, **kein** Telegram-Bündel (nur GitHub-Notifications), eigener Rate-Limit-Budget gegen GitHub (App-Installation-Token), `minimumReleaseAge` erfordert `releaseTimestamp` → bei GHCR-Images **muss** das GHCR-Datasource `created`-Annotation liefern (verifiziert: liefert `org.opencontainers.image.created`, s.u.); Konfig-Aufwand pro Repo: ~20 Zeilen; 12 Repos = **1 M** initial + ~0.5 h/Repo/Jahr Wartung | **Nicht als Ersatz**, aber Renovate-Doku als **Spec-Vorlage** für N3 | Renovate prüft **dieselben** Dinge wie unser Scanner — aber nur pro Repo, nicht aggregiert. Wenn wir Renovate einführen **und** den Scanner behalten, haben wir doppelte PR-Kanäle (`cve-audit/*` vs. `renovate/*`). Wenn wir Renovate **statt** PR-Automatik nehmen, verlieren wir die Telegram-Bündelung und den einen Nacht-Report. **Fazit:** Renovate-Semantik nachbauen (N3), Renovate selbst nicht deployen. |
| **Dependabot** | Updates pro Repo, Security-Alerts, Auto-PR, Docker + docker-compose + npm + pip + go + cargo | GitHub-nativ: `.github/dependabot.yml` pro Repo; **kein** self-hosted Telegram, **kein** Cross-Repo-Report; Konfiguration unterliegt GitHub-Rate-Limit (max. 200 PRs/Tag/Repo); Publisher-Datum-Logik **nicht** konfigurierbar (kein `minimumReleaseAge` — Dependabot hat **keine** Soaking-Option) | **Nicht** | Kein Soaking (N3 nicht abbildbar), kein Pre-Release-Info-Feld (N2 nur als PR, nicht als Report). Kein Nutzen über unser Eigenbau hinaus. |
| **OSV-Scanner (CLI)** | Offline-GO-OSV-Datenbank-Scan, `dir`/`image`/`sbom`-Modi, `--recursive`, `--format=json`, `--config=osv-scanner.toml` mit `ignore`-Blocks inkl. **`reason` + `expires`** (ausgezeichnet für Suppress-Governance) | Eigenes Binary im Container (~80 MB), **parallele** Datenbank (OSV vs. Trivy) → widersprüchliche Findings möglich; kein Advisory-Crosscheck gegen GHSA (OSV **enthält** GHSA als Teilimport, aber ohne `first_patched`-Feld in CLI-Reportform); Re-Scan mit denselben Repos + ein **zweites** Datenschema; Wartung: DB-Update im Volume | **Nicht parallel**, **OSV.dev-API ja** | Wir brauchen das Advisory-Wissen, nicht den zweiten Scanner. Trivy liefert Lockfile-Evidenz + Manifest-Pfad (wichtig für Fix-PR) — das OSV-Scanner-CLI-Report-Format liefert das nicht mit derselben Auflösung. **OSV.dev API** (HTTP, kein Binary) deckt den Crosscheck sauberer ab (siehe §4.1). |
| **Trivy (behalten)** | fs- und image-Scan, Registry-API ohne Daemon, `--severity`, `--vex`, `--sbom-sources`, `--skip-db-update` | Bekannt: DB-Download im Cache, Lock-Contention bei parallelem Scan (`image-scan.ts` hat deshalb sequentiell); `--image-src` default = `docker,containerd,podman,remote` in dieser Reihenfolge → **ohne** Daemon fällt automatisch `remote` an (Bestätigt durch Doku `--image-src podman,containerd`; Quelle: `docs/guide/target/container_image.md`, Context7 `/aquasecurity/trivy`). Aktuelle Version 2026-11-05: **v0.76.2** (Dockerfile pinnen `0.76.1` — Update-Kandidat) | **Behalten, ergänzen um `--vex`/`--sbom`-Optionen** (defer) | Kein Grund zum Wechsel. `--vex`/`--vex repo` könnte Suppress-Governance ersetzen (statt LLM-Triage), aber nur mit Aufwand; LLM-Triage funktioniert heute. |
| **npm audit / `npm audit --package-lock-only` / `@npmcli/audit`-Bulk-Endpoint** | `POST registry.npmjs.org/-/npm/v1/security/advisories/bulk` mit `{"pkg":["version"]}` → **alle** Advisories je Pkg-Version **in einem** Call, inkl. `cvss.score`, `cvss.vectorString`, `cwe[]`, `vulnerable_versions`, `title`, GHSA-URL. **Verifiziert** (s. §10-Belege) | Kein Install nötig; kein Auth; deckt **nur** npm; liefert **kein** `first_patched_version` (nur `vulnerable_versions`-Range) | **Empfehlen** als NPM-spezifischer Advisory-Batch | 1 Call pro Repo statt N Calls pro Finding; für npm die KV-Handvoll-Calls auf `/advisories` ersetzen. `first_patched` müsste aus der `vulnerable_versions`-Range abgeleitet werden — machbar (`semver.minVersion` der Range + höchster `<`-Bound). |
| **deps.dev API** | `GET api.deps.dev/v3/systems/{eco}/packages/{pkg}/versions/{v}` liefert `publishedAt`, `isDefault`, `isDeprecated`, `licenses`, `advisoryKeys[]`, `slsaProvenances[]`, `attestations[]`. **Verifiziert** | Kein Auth, öffentlich; **Rate-Limits** dokumentiert (Google-API, fair use), kein SLA; Pkg-Namen path-encoded (scoped `@scope%2Fname` nötig) | **Bedingt übernehmen** (optional `publishedAt`-Fallback) | Interessant vor allem für den **SLSA/Attestation**-Check als Bonus. `publishedAt` redundant zu npm/PyPI/Docker Hub, aber Abbildabbau weniger Calls. **Kein** Dependabot-Ersatz. |
| **Grype / Syft (Anchore)** | SBOM-basiert (`syft` CycloneDX/SPDX) + `grype` Vulnerability-Match inkl. `epss`, `kev`, `cvss`-Feldern im JSON-Output; `grype db` aus OCI-Image; kann `--from-registry` **ohne** Docker-Daemon | Zweites Binaries-Paar (~100 MB), **dritte** Datenbank (Grype-DB vs. Trivy-DB), redundanter Scan → verdoppelte Laufzeit (19 Images × 2), Grype-DB-Auto-Update-Strategie im Container muss verwaltet werden; PR-Anlage bleibt Eigenbau | **Nicht** jetzt; Argumentation: scannt die **gleichen** OS-Pakete wie Trivy, aber ohne `--vex`/`--sbom-sources`-Parität. Wenn wir EPSS/KEV wollen: **eigene** Anreicherung (§4.2), nicht Grype. **Perspektivisch:** `syft` als SBOM-Erzeuger für Trivy (`--sbom`-Input) um Trivy-DB-Nutzung von Image-Scan zu isolieren. |
| **GitHub Dependency Review / Dependency Graph** | PR-Level-Diff (was kommt **mit diesem PR** neu hinzu), GitHub-natives UI, Alerts in „Security" | Nur bei **PR vorhanden**; nicht für prophylaktische Nachtauswertung; Rate-Limit; Rechte nötig (`dependency-graph: read`); liefert **keine** Cross-Repo-Aggregation | **Nicht** (bzw. nur als PR-Gate in den Ziel-Repos) | Ist Add-on in den Repos, nicht Teil unseres Scanners. Optional in der Roadmap als „nach Merge aktivieren" — aber die Repos haben das schon per GitHub-Settings, wenn der Owner will. |

### 3.2 Wo Eigenbau unschlagbar bleibt (Begründung pro Punkt)

1. **Cross-Repo-Inventar** — 1 Lauf, 1 Report, alle 12 Repos, archivierte hart gefiltert, `--only=…` für Probe. Kein Fremdtool bietet das. Allein die Inventar-Query (`/user/repos?affiliation=owner`, paginiert) ist 22 API-Calls im Probe-Report wert und nicht trivial (Rate-Limit, Tree-API-Fehler, `truncated`-Warnung).
2. **Pins-Policy als *aktiver* Enforcer** — Renovate **pinnt nicht** `^1.2.3` auf `1.2.3`, es *bumped* Ranges. Unser Scanner schreibt exakte Versionen, Lockfile-Regen inklusive. Diese Semantik kauft kein Tool.
3. **Telegram-Bündelung mit Novelty-Dedupe** — „1 Nachricht je Nacht, nur echte Neuigkeiten, Reminder-Sektion zuerst, Image-PRs bewusst ohne Reminder". Renovate/Dependabot pushen pro Repo pro PR Notifications. **Nicht** nachbaubar.
4. **PR-Automatik mit eigener Branch-Konvention + State** — `cve-audit/*-<date>`, max 1 PR/Tag/Repo/Kind, Dedupe über `state.json` + Remote-Reconcile. Renovate kann PRs, aber **ohne** unsere Telegram-Reminder-Kopplung.

### 3.3 Gesamturteil N1

> **Kern behalten, Datenquellen modernisieren.** Konkret prozentual: 60 % des Codes (Inventar, Pins, State, Telegram) unangetastet, 25 % (Advisory-Crosscheck, Report-Schema) ersetzt, 15 % (Image-Scan-Evidenz) erweitert. Kein Fremdtool übernimmt einen Block.

---

## 4. Vulnerability-Check — bessere Quellen & Priorisierung

### 4.1 Advisory-Crosscheck-Lücken (heute)

| Problem | Beleg | Auswirkung |
|---|---|---|
| **`ghPaginate` je Finding** | `scan.ts:405` → `advisories.ts:66` | API-Multiplikator — bei 50 Findings = 50+ Calls; bei 500 Findings = 500+ und ggf. Rate-Limit-Resets (Wartezeiten `github.ts:35–39`) |
| **Case-Insensitive Name-Match, aber nur `==`** | `advisories.ts:78` `v.package.name.toLowerCase() !== pkg.toLowerCase()` | pip-Namen mit `_`/`-`-Normalisierung (`typing_extensions` vs. `typing-extensions`) werden nicht gematcht → trivy-only-Fall |
| **Semver-only-Match** | `advisories.ts:79` `if (ghEco === 'npm' && !semverSatisfies(...))` | **pip/go/cargo** werden **nicht** gefiltert → jeder GHSA mit gleichem Namen landet im Finding, unabhängig von der installierten Version. Im Probe-Report kommt das **nicht** zum Tragen (0 Findings), aber latent |
| **`first_patched_version`** | `advisories.ts:94` `patchedIdentifier()` | Wenn es die API als String liefert, ok; als `{identifier}` auch ok. Aber: manche Advisories haben **mehrere** `vulnerabilities[]`-Einträge; `firstPatched` wird je Eintrag gelesen, `scan.ts:478` nimmt das numerisch größte — das ist eine Heuristik, nicht garantiert das „erste rand-freie" |
| **`trivy-only`-Findings** | `scan.ts:406–422` | Werden als Findings gefährt, haben aber **keine** Advisory-Metadaten → `firstPatched=null` → **kein Fix-PR**, nur `⚠️ keine gepatchte Version` in Telegram. Im heutigen Report: `node:26.13.0` H6, `python:3.15.2-slim-trixie` H54, `pgvector:0.8.7-pg17` H77/C4, `playwright/mcp` H97/C8 — alles **base-OS-Pakete** in Images, die heute nur über `trivy image` (Image-Scan) erkannt werden, **nicht** über den Advisory-Crosscheck (weil Image-Scan und Advisory-Pfad **getrennte** Wege sind). Das ist gut so — aber sie landen nicht in den Findings (siehe parallel-in-Arbeit). |

### 4.2 Bessere Quellen — Empfehlung

**Empfohlene Reihenfolge je Finding-Zeile (neuer Advisory-Layer):**

1. **OSV.dev `querybatch`** (HTTP, kein Auth, 1000 Queries/Request): `POST https://api.osv.dev/v1/querybatch` mit `[{package:{name,ecosystem}, version}]` → `[{vulns:[{id, aliases, modified, published, severity[], database_specific{severity, github_reviewed, ...}}]}]`. **Verifiziert** (Beleg §10). Der Batch-Call ersetzt **pro Repo** N Calls. Für `first_patched`/`fixed:`-Info reicht der Batch-Response **nicht** (kein `affects[].ranges`), das gibt's nur mit dem **per-Vuln**-Detail-Endpoint `POST https://api.osv.dev/v1/query` (dann aber **nur** für die GHSA-IDs, die im Batch als relevant markiert sind — i.d.R. 1–5 je Repo statt je Finding).
2. **npm-Bulk-Advisories** (`registry.npmjs.org/-/npm/v1/security/advisories/bulk`, kein Auth): liefert `severity`, `cvss.score`, `cwe[]`, `title`, `vulnerable_versions` **für alle** Versionen einer Pkg in einem Call. Das ist die **beste** Quelle für die `first_patched`-Ableitung (höchster `<`-Bound der aggregierten Range) und CVSS — ohne GitHub-Auth. **Verifiziert** (`lodash@4.17.15` → 5 Advisories mit `cvss:{score:7.2, vectorString:"CVSS:3.1/..."}`).
3. **GitHub `/advisories`** (heute) **behalten als Fallback** für go/cargo (OSV deckt die ab, aber `first_patched` in GHSA-Form ist direkt indiziert) und als Crosscheck bei Verdacht auf OSV-Lücke.

**Priorisierung (NEU, N1):**

| Quelle | Endpoint | Kosten | Empfehlung |
|---|---|---|---|
| **EPSS (FIRST.org)** | `GET https://api.first.org/data/v1/epss?cve=CVE-1,CVE-2` (bis 100 CVEs/Call) | 1 Call/Repo, kein Auth; liefert `epss`, `percentile`, `date`. **Verifiziert** (Beleg §10) | **Ja** — als Report-Spalte und Telegram-Sortierung (`KEV → EPSS ≥ 0.2 → nächster`). |
| **CISA KEV** | `GET https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` (~1.8 MB, Cache 1×/Tag im Volume) | 1 Call/Tag; liefert `vulnerabilities[].cveID` | **Ja** — hard-flag „in freier Wildbahn ausgenutzt". Kein Suppress, nur Markierung. |
| **CVSS** | aus npm-Bulk (`cvss.score`) bzw. OSV (`severity[].score` als CVSS-Vector) | keine | **Ja** — Report-Spalte. |

**Trade-off EPSS/KEV:** beide erhöhen die Report-Größe (1 Zeile/Image, 1 Zeile/Vuln) und brauchen ein Mapping `VulnerabilityID → CVE-ID` (Trivy liefert `CVE-…` als `VulnerabilityID`, aber **nicht** immer — `GHSA-…` wenn Trivy für npm-Pakete GHSA-IDs verwendet). Bei GHSA-IDs ist `aliases` aus OSV der Mapper. **Achtung:** `trivyImageScan()` (`image-scan.ts:504–507`) **verwirft** die `VulnerabilityID` — für EPSS/KEV muss das JSON-`Results[].Vulnerabilities[]` **aufbewahrt** werden (nicht nur gezählt), sonst geht nichts.

**Base-Image-Scope (NEU, N1):** Der Base-Image-Scan deckt heute **alle** `FROM`-Refs + Compose-`image:` — aber `trivy image` **ist** der Base-Image-Scan. Das „Scope"-Problem ist: Image-Refs werden nur aus Dockerfile/compose gelesen; `mcr.microsoft.com/playwright/mcp` ist ein **Tool-Image**, kein Base. Wenn ein Repo ein `FROM node:26` **hat**, wird die node-Version 6 H-Findings erzeugen, die alle Repos teilen. Hier ist die große Effizienzchance: **gleiche Images mehrfach scannen** (node:26.13.0-alpine3.24 taucht in **5** Repos auf; scannt heute 5×). **Empfehlung:** `trivy image`-Ergebnisse nach `image@digest` deduplizieren (Digest via Registry-HEAD `Docker-Content-Digest`, verifiziert §10) — **spart 4/5 der node-Scans**. **L**.

### 4.3 Konkreter neuer Advisory-Layer (Pseudocode)

```
async function collectAdvisories(repo, findings):
  # 1. Batch pro Repo (OSV)
  queries = findings.map(f => ({package:{name:f.pkg, ecosystem:map(f.eco)}, version:f.version}))
  batch = POST api.osv.dev/v1/querybatch {queries}   # 1 Call
  # 2. Für GHSA-relevante Einträge: Details only (first_patched/cvss)
  details = []
  for v in flatten(batch): if v.id.startsWith("GHSA-"): details.push(POST api.osv.dev/v1/query {package, version})  # max 5
  # 3. npm: Bulk-Advisories (first_patched-Range, CVSS)
  if repo.eco in [npm,pnpm,yarn]: npmBulk = POST registry.npmjs.org/-/npm/v1/security/advisories/bulk
  # 4. CVSS/EPSS/KEV-Annotation
  cves = unique(details.aliases.filter(/^CVE-/))
  epss = GET api.first.org/data/v1/epss?cve=join(cves,",")    # 1 Call, max 100
  kev  = loadKevelFromVolumeCache()                          # 1 Call/Tag
  return annotate(findings, {details, npmBulk, epss, kev})
```

**API-Calls je Repo:** heute ~N (je Finding 1); neu ~4–6 (Batch + bis 5 Details + 1 npm-Bulk + 1 EPSS + 1 KEV aus Cache). Bei 8 Repos: **·** 40–50 statt ~330. **Erwartete Zeitersparnis im Advisory-Block: ~60–80 %** (ungeprüft, aber strukturell garantiert).

---

## 5. BETA-Erkennung (N2)

### 5.1 Prinzip

**Kein Hard-Filter mehr — Info-Klassifikation.** Ziel: „du bist schon auf einem Beta-Kanal" und „es gibt ein neueres Beta" sichtbar machen, ohne PR-Rauschen. Die 3-Tage-Regel (N3) gilt **auch für Betas** — Betas sind nicht schlimmer als RCs, aber sie sind kein Fix-PR-Kandidat.

**Drei Klassen und ihre Semantik:**

| Klasse | Auslöser | Verhalten |
|---|---|---|
| `prerelease-hint` | Ref ist **stable** (`x.y.z` oder `x.y.z-variant`), aber es gibt einen neueren **Pre-Release**-Kandidaten (`-beta`, `-rc`, `-next`, …) im selben Major | **Report-only Zeile** `ℹ️ beta verfügbar: 7.1.0-beta (2d)` — kein Bump-Plan, **kein** PR, kein Telegram-Eintrag, Nur-Telegram wenn es **der einzige** neue Befund ist. |
| `prerelease-current` | Ref steht **selbst schon** auf einem Pre-Release (`node:26.0.0-rc.1`, `typescript@7.1.0-beta`) | Aktuelle Version wird als **“Beta-Kanal"** markiert; Update-Check auf **neuere Pre-Releases im selben Kanal** (gleicher `-<tag>`) — kein Mix `-rc` → `-beta`. |
| `prerelease-exotic` | Suffix-Token ∈ `{nightly, canary, dev, insiders, snapshot, pre, preview, edge}` **oder** Dist-Tag ∈ `{dev, insiders, canary, nightly, next-…}` | **Default aus** (`SHOW_EXOTIC_PRERELEASES=0`), nur Log. |

### 5.2 Design je Ökosystem

**a) npm (Pinning-Scan)**

- **Quelle:** `GET registry.npmjs.org/<pkg>` (heute schon geladen, aber `dist-tags.latest` ist das Einzige, was gelesen wird — `pinning.ts:104`). Erweitern auf:
  - `dist-tags` (Map Tag → Version): `latest`, `next`, `beta`, `rc`, `insiders`, `legacy` usw.
  - `time[<version>]` (Publish-Datum) und `versions[<v>]` (semver-validity).
- **Verifiziert** (§10): `typescript` liefert `{rc: "7.0.1-rc", latest: "7.0.2", beta: "7.1.0-beta", next: "7.1.0-dev.20261107.1", dev: "3.9.4", insiders: "4.6.2-insiders.20220225"}`. `time[<v>]` ist für alle vorhanden, auch Pre-Releases (`7.1.0-beta` → `2026-10-20T16:45:47.402Z`).
- **Kandidaten-Auswahl:** `Object.values(dist-tags).filter(v => semver.prerelease(v) !== null && semver.gt(v, current))`. Beste (höchste) prä-Release-Version. `semver.prerelease("7.1.0-beta") === ["beta"]` (verifiziert).
- **Rauschkontrolle:** `-dev`-Tags (`typescript next: 7.1.0-dev.20261107.1`) fallen wegen `prerelease-exotic` raus. `-insiders.2022…` ebenso. Übrig bleiben `beta`, `rc`, `alpha` — also genau die, die man bewusst akzeptieren will.
- **Report-Spalte:** `Pinning`-Tabelle bekommt `beta-hint`-Spalte (`—` / `7.1.0-beta (2d)`).
- **Pins-PR:** **Nie** Pre-Release als Ziel. Exakte `7.1.0-beta` in `package.json` sind **beide** `semver.valid` (verifiziert) und damit **nicht** floating — der Scanner lässt sie in Ruhe. Ein neues `7.1.0-beta.2` wird nur als Information angezeigt.

**b) Docker / Docker Hub / GHCR**

- **Quelle:** `tags/list` liefert bereits alle Tags inkl. `-rc.1` (`image-scan.ts:366–378`). Diese Liste in `tagSemantics()` **nicht** wegfiltern, sondern klassifizieren.
- **Erweitertes `tagSemantics` (Vorschlag, Interface nur als Ergänzung):**
  ```
  type PrereleaseClass = 'stable' | 'channel' | 'exotic'
  tagSemantics(tag) → {
    …, prerelease: boolean,            // bleibt (Kompat.)
    prereleaseClass: PrereleaseClass,  // NEU: 'channel' | 'exotic'
    channel: string | null,            // NEU: 'beta' | 'rc' | 'alpha'
  }
  ```
  `channel = suffix.match(/^-(alpha|beta|rc|pre)/i)?.[1] ?? null`; `exotic = /^-(nightly|canary|dev|insiders|snapshot|edge|preview|preview)/i || /next/`.
- **Kandidat-Ziel:** `newestSameMajorTag` mit `includePrerelease=true` für die Info-Zeile — Target = höchster Kandidat mit **gleichem** `channel` (wenn `current` schon Pre-Release) oder höchster `channel`-Wert (wenn `current` stable, keine Bump-Empfehlung).
- **`node:26.0.0-rc.1` im `FROM`:** heute **komplett verloren** (`image-scan.ts:666`). Neu: Ref wird als `prerelease-current` erkannt, mit `channel=rc`, und auf `26.0.0-rc.2` (gleicher Channel) geprüft. **Kein** Wechsel in `latest`.
- **`latest`/tagless:** bleibt Skip-With-Note (`image-scan.ts:650,654`), aber wenn Tag `latest` auf ein **Pre-Release**-Digest zeigt? → `trivy image` liefert nur `{}` bei Fehler; `tagSemantics('latest')` → `valid=false`. Kein Change.

**c) PyPI / pip**

- `GET https://pypi.org/pypi/<pkg>/json` → `info.version` + `releases[version][0].upload_time_iso_8601` (**verifiziert**, Beleg §10). `releases[<v>].yanked` → ausschließen.
- Pre-Release: `releases`-Keys mit `-` oder `rcN`/`aN`/`bN`/`devN` (PEP 440). `releases["2.5.0rc1"]` manschetten – die meisten Pakete laden pre-Releases **nicht** nach `info.version` (kein beta-Kanal) → `prerelease-hint` bleibt leer. **Rauschkontrolle:** für PyPI **nur `prerelease-hint`** (kein `-beta`-Kanal-Konzept).

**d) Go / Cargo**

- Go: `GET https://proxy.golang.org/<mod>/@v/list` + `@latest` (nur Release-Tags, keine Pre-Releases → **Beta = n/a**).
- Cargo: `GET https://crates.io/api/v1/crates/<crate>` → `max_stable_version`, `max_version` (Pre-Release-Kanal). `versions[].created_at` (**nicht** verifiziert in dieser Session — **als offene Frage** markiert, aber die Cargo-API ist stabil).

**e) GitHub Releases (nur für die `audit-scanner`-eigene Version? Nein — Drittanbieter nicht relevant)**
`GET /repos/{owner}/{repo}/releases` + `prerelease`-Flag — **nur** sinnvoll für **Tool-Versionen** wie unser Bild `trivy:0.76.x`. Für den Image-Scan **nicht** verwenden: die Docker-Tag-Liste ist das *faktische* Artefakt. `pre`-Flag hat hier Mehrwert, weil ein „Beta-Release" auf GitHub ein *stabiler* Docker-Tag sein kann. **Empfehlung:** als optionale Zusatz-Annotation für unsere eigenen `FROM`-Refs der Form `aquasec/trivy:*` — nicht generisch.

### 5.3 Rauschkontrolle (die wichtigste Regel)

> **Pre-Releases sind immer `info`-Severity und produzieren NIE einen PR.** Das beugt sich gegen das Repo-Rauschen (Payload/Next-RCs dauerhaft in devDeps). Die `prerelease-current`-Erkennung ist **einmalig** pro Repo nützlich („du hast X RC-packages"), danach **stumm**.

- `SHOW_PRERELEASES=info` (Default) | `off` | `exotic-on`.
- Batch-Zeile im Report, **nicht** Telegram. Ausnahme: `prerelease-hint` mit **nicht-exotischem** Kanal und **≥ 3 Tage alt** (N3-Konsistenz) → eine Zeile in 🐳 Images.
- **Stumm bei Security-Fix:** Wenn ein **stable**-Kandidat existiert, wird der **stable**-Kandidat genommen, Pre-Release **nicht** erwähnt.

### 5.4 Telegram-Darstellung

Heute: `🐳 Image-Scan (…): …`. Neu:
```
🐳 Image-Scan (Dockerfile/compose):
*private-ai-interface*:
  • node:26.13.0-alpine3.24 → 26.13.0-alpine3.24 ℹ️ beta: 27.0.0-beta.1 (5d)
  • pgvector/pgvector:0.8.7-pg17 ℹ️ rc: 0.9.0-rc.1 (1d)
```
Nur bei `prerelease-hint` mit `age ≥ 3d`; kein eigener Block, keine Status-Änderung der Hauptzeile.

---

## 6. Soaking / 3-Tage-Regel (N3)

### 6.1 Datenquellen je Ökosystem — verifizierte Belege

| Ökosystem | Quelle | Feld | Verifiziert? | Beleg (Rohauszug) |
|---|---|---|---|---|
| **npm** | `GET registry.npmjs.org/<pkg>` | `time[<version>]` (ISO-8601) | **Ja** | `typescript`: `time["7.1.0-beta"] = "2026-10-20T16:45:47.402Z"`, `time["7.0.2"] = "2026-07-08T15:55:18.431Z"` |
| **Docker Hub** | `GET hub.docker.com/v2/repositories/<repo>/tags/<tag>` | `tag_last_pushed` (ISO) — **nicht** `last_updated` (letzte Pull-Aktivität wäre auch enthalten, aber `tag_last_pushed` ist der Push-Zeitpunkt) | **Ja** | `library/node:26.13.0-alpine3.24` → `"tag_last_pushed":"2026-11-05T20:38:53.674865539Z"`; `pgvector/pgvector:0.8.7-pg17-trixie` → `"tag_last_pushed":"2026-10-31T10:13:39.841668Z"` |
| **Docker Hub (Liste)** | `GET hub.docker.com/v2/repositories/<repo>/tags?page_size=N&ordering=last_updated` | `results[].tag_last_pushed`, `results[].last_updated` | **Ja** | `library/node`: `count=9270`, `next=…page=2` — `ordering=last_updated` **funktioniert** (Top 5 nach Datum) |
| **GHCR** | `GET ghcr.io/v2/<owner>/<repo>/manifests/<tag>` mit OCI-Accept-Header → Manifest-Index `annotations["org.opencontainers.image.created"]` | OCI-Annotation (RFC 3339) | **Ja** (Doku + Beleg) | Für `aquasecurity/trivy:0.76.1`: `"annotations":{"org.opencontainers.image.created":"2026-10-21T10:43:17Z", …}` — **ohne** Docker-Daemon, nur HTTP-Bearer-Token aus `https://ghcr.io/token?scope=repository:…:pull&service=ghcr.io`. **Achtung:** `ghcr.io` liefert `Last-Modified` **nicht** (HEAD response hat nur `docker-content-digest`), aber `created` ist im Manifest. |
| **GHCR: Publish-Datum fehlt** | Wenn ein Image **keine** OCI-Annotation hat (z. B. alte Buildx-Version) → **Fallback:** `HEAD`-Request mit `Docker-Content-Digest`, dann Publish-Datum aus **GitHub Release** (`GET /repos/<owner>/<repo>/releases/tags/<tag>`, `published_at`) — nur wenn Image=GHCR und Repo bekannt. Sonst: **kein Soaking** (fail-open → `eligible`, gut für Betrieb) | — | — |
| **PyPI** | `GET pypi.org/pypi/<pkg>/json` | `releases[<version>][0].upload_time_iso_8601` | **Ja** | `requests`: `"upload_time_iso_8601":"2016-04-29T21:57:23.021820Z"` |
| **Go** | `GET proxy.golang.org/<mod>/@v/<version>.info` | `Time` | **Nein** (nicht verifiziert in dieser Session — **offene Frage** §9) | — |
| **Cargo** | `GET crates.io/api/v1/crates/<crate>/versions` | `created_at` | **Nein** (nicht verifiziert in dieser Session — **offene Frage** §9) | — |
| **deps.dev** (Fallback für **alle** oben) | `GET api.deps.dev/v3/systems/<eco>/packages/<pkg>/versions/<v>` | `publishedAt` | **Ja** | `{"versionKey":{"system":"NPM","name":"lodash","version":"4.17.15"},"publishedAt":"2019-07-16T…","isDefault":false,…}` |

> **Fazit der API-Checks:** Für **alle** Ökosysteme außer Go/Cargo gibt es ein verifiziertes Publish-Datum **ohne Docker-Daemon**. GHCR hat es ebenfalls — via OCI-Annotation, nicht via Registry-API-Feld. Das ist die kritische Erkenntnis für N3.

### 6.2 Warum GHCR-Datum funktioniert, obwohl `tags/list` kein Datum liefert

`GET /v2/<repo>/tags/list` gibt **nur Namen** zurück (`image-scan.ts:366`). Für das Publish-Datum ist ein **zusätzlicher** Call je Kandidat-Tag nötig:
- **Docker Hub:** `GET hub.docker.com/v2/repositories/<repo>/tags/<tag>` → 1 Call/Nacht/Tag (Cache im Volume: `tag → tag_last_pushed` unveränderlich).
- **GHCR:** `GET ghcr.io/v2/<repo>/manifests/<tag>` (Accept OCI-Index) → 1 Call/Tag. Mit `HEAD` statt `GET` fällt das Manifest weg, aber `created` ist dann **nicht** lesbar — also `GET` (Manifest ist klein, ~2 KB).

**Kosten:** 19 Image-Refs im Probe-Report → 19 zusätzliche Calls/Nacht (10–20 ms). **Vernachlässigbar.**

### 6.3 CVE-Ausnahme-Trigger

Es gibt **drei** Wege, einen CVE-Fix zu erkennen — je nach Fund-Typ:

```
A) Paket-Scan (npm/pip/go/cargo)
   Fix, wenn: advisory.first_patched === candidate-version
   UND        advisory.severity ∈ {high, critical}
   Quelle:    advisories.ts › fetchAdvisories().firstPatched
   Achtung:   bei npm-Bulk-Advisories ist `first_patched_version` NICHT im
              Response — Ableitung aus `vulnerable_versions`-Range:
              target = semver.minVersion(range) → Fix-Version ist das
              niedrigste Version ≥ target.

B) Image-Bump (Tag, z. B. node:26.13.0-alpine3.24 → node:26.14.0-alpine3.24)
   Fix, wenn: trivy image für den ZIEL-Ref → fewer H/C als current
   Kosten:    1 zusätzlicher trivy image-Scan je Bump-Kandidat
   Alternativ (billig): Base-OS-Patch-Release-Erkennung
              node 26.13.0 → 26.14.0 = Patch-Sprung → in node ist jedes
              alpine3.24-Tag ein neuer Base-Layer. Aber: node-Release-Patch
              ist kein Base-OS-Patch. → nicht robust. NICHT nutzen.

C) Image-Bump mit Trivy-Evidenz
   Fix, wenn: in den H/C-Findings des AKTUELLEN Images ist mindestens 1
              Finding, dessen `FixedVersion` eine OS-Paket-Version ist, die
              im Ziel-Image-Tag enthalten ist (z. B. `libssl3` >= 3.3.2-r0).
   Quelle:    trivy image JSON `Results[].Vulnerabilities[].FixedVersion`
   Problem:   `FixedVersion` ist paketspezifisch, nicht tag-spezifisch.
              → semantisch unsauber.
```

**Empfehlung:** **A** und **B**. Für **B** den Image-Scan so erweitern, dass er `H/C` **je Ref** aus dem **gleichen** Trivy-JSON lesen kann (heute `trivyImageScan` verwirft die IDs — siehe §4.2 „Trivy discardet IDs"). Ein zusätzlicher `trivy image`-Scan kostet ~30–60 s/Image (12 min-Timeout `:518`), bei 19 Refs = **10–19 min** zusätzlich im Lauf. Das ist **zu teuer**.

**Besseres Verfahren (Empfehlung):**
1. `trivy image <current>` liefert `Results[]` mit `Vulnerabilities[].VulnerabilityID` + `PkgName` + `FixedVersion`.
2. Ableitung: „gibt es ein OS-Patch-Release im Ziel-Tag?" via **Dockerfile-Pin-Analyse** nicht möglich. **Aber:** Wenn `current = node:26.13.0-alpine3.24` und `candidate = node:26.14.0-alpine3.24`, ist das **semver-Major-Minor skipped** (26.13→26.14) — in semver (für node) ist `26.13.0` ein **Minor** (node-Schema: `major.minor.patch`). Ein `26.13.0` → `26.14.0` ist ein node-Minor-Release; mit hoher Wahrscheinlichkeit enthält es Security-Fixes (node-Releases sind im Dezember Patch), aber das ist **keine Garantie**.
   **Verhältnis:** Für einen **strikten** Fix-Nachweis: 1 zusätzlicher `trivy image` je Bump-Kandidat — teuer. Für einen **heuristischen** Fix-Nachweis: im **Report** `cve-exempt (heuristik: minor-release)` markieren und PR trotzdem erstellen, aber **als „CVE-Exempt-Heuristik" geloggt** — wir hatten **nie** eine Bestätigung, ob der CVE wirklich gefixt ist.
3. **Mein Vorschlag:** **Option B strikt** nur dann, wenn `current` und `candidate` die **gleiche** `major.minor` haben und die `patch`-Sektion im **Ziel** fixbar ist → für node ist das `26.13.0` → `26.13.1` (node-patch). **Bei node ist es selten `26.13.0` → `26.13.1`** — node gibt Patch-Releases sporadisch raus; meist `26.13.0` → `26.14.0` (Minor). Für **Base-OS-Pakete** (alpine, debian) ist die relevante Update-Granularität die **`alpine3.24`-Sektion**, nicht die node-Version. Das ist mit dem Image-Tag **nicht** abbildbar.

**Deshalb:** **Empfehlung:** **Option B** durch **Option C+** ersetzen: **Trivy-Report + `Trivy`-GitHub-Releases** vergleichen. Konkret:
```
if current.base === "aquasec/trivy" && candidate == latest-releasetag:
    cve-fix = true   # trivy-Releases sind per Definition Security-Releases
```
Das ist — wie Name sagt — **trivy-spezifisch**. Für **alle anderen** Images:
```
cve-fix = false  # keine CVE-Ausnahme → Soaking greift
```

> **Pragmatischer Kompromiss:** `cve-exempt` **nur** für `aquasec/trivy`-Bumps + **alle** Paket-Scan-Fixes (Option A). Für Base-Images gilt Soaking **immer**. Das ist ehrlich, billig und vermeidet falsche Versprechen an den Menschen.

### 6.4 State/Idempotenz

**Die 3-Tage-Regel braucht KEINEN State.** Sie ist eine reine Funktion `now() - publishedAt` zum Laufzeitpunkt. Ein Tag, der heute 2 Tage alt ist, ist morgen 3 Tage alt → `eligible`. Kein „skip"-Verdacht.

**Was der State **nicht** leistet:** `state.json` ist PR-Dedupe (offene PRs), **nicht** Update-Checkpoint. Er muss **nicht** erweitert werden. Das ist bewusst: fehlerhafte Update-Eligibility soll den **Lauf** nicht verändern, nur den **Report**.

**Was der State **doch** könnte:** Cache für `publishedAt` (unveränderlich nach Publish) und für `latest`-Dist-Tag (ändert sich). **Empfehlung:** **neuer separater** Cache `reports/update-cache.json` (nur Lese-Beschleunigung, kein Skip). Format: `{ "<eco>|<pkg>": {"version": …, "publishedAt": …, "fetchedAt": … } }`. TTL: 24 h. **Ist aber nicht erforderlich** — die Registry-Calls sind billig. **Nur einführen, wenn Laufzeit zum Problem wird.**

**Konsequenz für die bestehende Architektur:** Keine Änderung an `state.ts` für N3. Ein **reiner** Funktionsblock `src/soaking.ts` mit `updateEligibility()` reicht.

### 6.5 Env-Config

| Variable | Default | Bedeutung |
|---|---|---|
| `UPDATE_MIN_AGE_DAYS` | `3` | Mindestalter in **Tagen** (nicht Stunden). `0` = Soaking aus (sofortige Updates). |
| `UPDATE_MIN_AGE_DAYS_DEV` | *(leer = wie `UPDATE_MIN_AGE_DAYS`)* | devDependencies können kürzer (z. B. `1`) — optional. |
| `SHOW_PRERELEASES` | `info` | `info` / `off` / `exotic-on`. |
| `CVE_EXEMPT_HEURISTIC` | `trivy-only` | `all` = alle Minor-Release-Bumps gelten als CVE-Fix (unsicher, nicht empfehlenswert). |

**Semantik `UPDATE_MIN_AGE_DAYS=0`:** kein Datum nötig, sofort `eligible` (kompatibel mit heutigem Verhalten).

### 6.6 Report-Spalte

Neue Spalte in `📌 Unpinned deps`- und `🐳 Images`-Tabellen: **`Age`** mit Wert:
- `3d` (reif, ≥ 3d) → Status `✓ update`
- `2d` (zu jung) → Status `⏳ too young (2d)`
- `3d · CVE` (CVE-Ausnahme) → Status `🔴 CVE-exempt`
- `—` (kein Datum) → Status `unknown-age` + Warnung im Report-Header

### 6.7 Entscheidungsfunktion

```
type Eligibility = 'eligible' | 'too-young' | 'cve-exempt' | 'rejected-variant'

function updateEligibility(
  current: string,                    // aktuell gepinnte Version (z.B. "26.13.0-alpine3.24")
  candidate: string,                  // Kandidat
  publishedAt: string | null,         // ISO-8601, null = unbekannt
  cveFix: boolean,                    // true = Kandidat fixt H/C-CVE
  minAgeDays: number = 3,
  now: Date = new Date(),
): Eligibility {
  // 0. Variant-Gate: OS-Basis-/Variant-Wechsel ist NIE ein Update
  //    (bestehende Infrastruktur in image-scan.ts: variantCompatible)
  if (isVariantChange(current, candidate)) return 'rejected-variant'

  // 1. CVE-Fix-Ausnahme: immer sofort
  if (cveFix) return 'cve-exempt'

  // 2. Soaking
  if (publishedAt === null) return 'eligible'    // fail-open: unbekannt ≠ blockieren
  const ageMs = now.getTime() - Date.parse(publishedAt)
  const ageDays = ageMs / 86_400_000
  if (ageDays >= minAgeDays) return 'eligible'
  return 'too-young'
}
```

**Eigenschaften:**
- **Deterministisch** — kein IO innerhalb der Funktion (nur Testaufruf).
- **Idempotent pro Tag** — gleiche Eingabe = gleiches Ergebnis. Kein „Skip"-State.
- **Fail-open bei unbekanntem Datum** — nie einen Fix blockieren, nur weil die Registry kein Datum liefert.
- **Variant-Gate vor Soaking** — sonst würde `pg17 → pg17-trixie` als „reif" erscheinen und trotzdem blockiert werden; so ist der Grund eindeutig.

**Wichtig:** Die Funktion ist **nicht** identisch mit „Update verfügbar" (`image-scan.ts:614`). `updateAvailable` bleibt bestehen (semantisch „es gibt ein neueres Tag"). Der **neue** Status ist `eligibility` (**darf ein PR erzeugt werden**). Diese Trennung ist die Kern-Design-Entscheidung:
- `updateAvailable = true`, `eligibility = 'too-young'` → **kein** PR, Info im Report.
- `updateAvailable = true`, `eligibility = 'eligible'` → PR.

---

## 7. Risiken & Bugs im Bestand

### 7.1 Sortiert nach Priorität

| P | Bereich | Befund | Beleg | Fixempfehlung | Aufwand |
|---|---|---|---|---|---|
| **P1** | `replaceTag()` | **Substring-Match ohne Tag-Grenze links.** `replaceTag("FROM node:24-alpine AS x", "node:24", "node:24.12.0-alpine")` → `"node:24.12.0-alpine-alpine"`. Der Code `image-scan.ts:837` commentiert explizit „NICHT: weitere Versionssprecher (Zahl/Punkt/-buchstabe?)", prüft aber nur `(?![0-9.])` — der **`-alpine`-Fall** (Buchstaben-Suffix) ist ungeschützt. | `image-scan.ts:833–839`, reproduziert in dieser Session (pure Node-Aufruf) | Regex `(?<![A-Za-z0-9._:/-])<esc>(?![A-Za-z0-9._-])` **oder** besser: nach `parseCompose`/`parseDockerfile` pro Ref ein strukturierter Token-Ersatz (`splitRef` + `bumpTagOnly` auf den Ref-Bereich). **Dringend**, weil der Fix-PR sonst ungültige Image-Refs schreibt (Build bricht nach Merge – GitHub-CI würde den PR als rot markieren, aber der Mensch muss es bemerken) | **S** |
| **P1** | `image-scan.ts:666` (`addRef`) | **Pre-Release-Tags im `FROM` werden komplett übersprungen.** Ein `FROM node:26.0.0-rc.1` wird als `Pre-Release-Tag (…) — übersprungen` markiert und **nie** auf Updates geprüft. Nach N2-Anforderung falsch — maximal die Bump-Empfehlung darf fehlen. | `image-scan.ts:254` + `:666` | Pre-Release **nicht** als `pinned=false` setzen; stattdessen `prerelease=true` beibehalten, aber `freshness-check` mit `channel`-Vergleich ausführen | **S** |
| **P2** | `advisories.ts:79` | **Semver-Filter nur für npm.** Für pip/go/cargo wird jede GHSA mit gleichem Namen eingetragen. Bei go/cargo ist das besonders schlimm: `go.mod`-Modulnamen (`github.com/x/y/v2`) matchen modul-spezifische Advisories nicht. | `advisories.ts:79` und `GH_ECOSYSTEM` `:37–44` | Pro Ökosystem einen passenden Comparator: pip (`packaging.Version` → nicht in JS) **oder** die **Batch-Response von OSV** nutzen (macht den Match). **M** | **M** |
| **P2** | `pinning.ts:96–112` | **Pinning-Check ignoriert Pre-Releases → fälschliche Exaktheit.** `"typescript": "7.1.0-beta"` ist `semver.valid` → **kein Finding**, aber `dist-tags.latest = 7.0.2` **nicht** angeboten. Der Beta-User sieht nichts. | `pinning.ts:65–71` + `:104` | `npmLatest` um `beta/rc`-Tags erweitern und in das `PinFinding` als `betaHint` + `betaPublishedAt` mitführen (N2) | **S** |
| **P2** | `github.ts:34–40` | **Rate-Limit-Wartezeit blockiert den gesamten Lauf, ohne Fortschritt/Alert.** Bei > 5000 Calls/h (8 Repos × ~330 Advisories käme da hin) → 300 s warten, dann rekursiv. Kein Timeout, kein Laufzeit-Cap, kein Telegram-Hinweis. | `github.ts:33–40` | (a) Advisory-Calls durch OSV ersetzen (siehe §4) → 90 % weniger; (b) `Retry-After`-Header berücksichtigen; (c) Rekursion durch `for`-Loop mit max 3 Retries ersetzen | **S** |
| **P2** | `image-scan.ts:509–547` | **`trivy image`-Output verwirft `VulnerabilityID`, `FixedVersion`, `PkgName`.** Nur Zähler → keine EPSS/KEV-Annotation, keine CVE-Ausnahme-Erkennung (N1/N3). | `image-scan.ts:536–545` | JSON-Ergebnis in `ImageFinding.vulns` als **Liste** ergänzen (`vulnIds: string[]`) und Zähler als Summe; API-kompatibel (`high: count`) | **S** |
| **P2** | `image-scan.ts:360–389` | **GHCR-Registry-`token`-Endpoint ohne `scope`-Doku prüft; 403-Beispiel in Session:** `https://ghcr.io/token?scope=repository:mayraost/placeholder-404:pull` → **403**, aber `aquasecurity/trivy` → **200**. Bei privaten GHCR-Images (unsere eigenen) wird also **403** erwartet → `tags/list` scheitert, **kein** `token`-Wiederholung, keine `note`-Unterscheidung privat vs. Rechte fehlt. | `image-scan.ts:350–357` + verifiziert in dieser Session | **Auth**: GHCR nutzt das `GH_TOKEN`-PAT vom GitHub-Konto des Owners. Statt `auth.docker.io`-Flow → **`Authorization: Bearer <GH_TOKEN>`** für GHCR-`/v2/...`. Aktuell schlägt das fehl (403 wie oben). **Nicht dringend** (kein Repo-Image ist auf GHCR), aber latent | **S** |
| **P3** | `image-scan.ts:342–357` | `registryToken` liefert **`''`** (leerer String) wenn `j.token` fehlt → nachfolgender Call mit `Authorization: Bearer ` (leer) → 401. Kein Fallback, kein Diagnose-Log. | `image-scan.ts:349` `return j.token ?? ''` | Bei leerem Token **Glass** `null` zurückgeben (wie aktuell bei `!res.ok`), dann `note: 'Token-Fetch fehlgeschlagen'` | **S** |
| **P3** | `pinning.ts:74–89` | **`findPackageJsonFiles` ignoriert `dist/` aber nicht `.turbo/`, `coverage/`, `build/`, `.svelte-kit/`, `out/`.** Bei Payload/Next-Varianten (`payload` generiert `build/`) sind `package.json` in `build/` Arsenal → **falsche Pinning-Findings**. Insbesondere Yarn-Berry `package.json` in `.yarn/` | `pinning.ts:80` | `node_modules`, `.git`, `.next`, `dist` (heute) + `.turbo`, `coverage`, `build`, `.svelte-kit`, `out`, `.cache` | **S** |
| **P3** | `scan.ts:594–609` | `markDevOnly` liest nur `repoDir/package.json` — bei monorepo (Root `package.json` hat keine devDeps) **werden alle Findings als prod gemeldet**. | `scan.ts:598–606` | `markDevOnly` pro Manifest-Pfad (`f.manifestPath`) — bei `docker/db-mcp/requirements.txt` gibt es kein Pkg-Mapping, aber für `apps/web/package.json` schon | **M** |
| **P3** | `image-scan.ts:509` | **`trivy image` ohne `--skip-db-update`-Abstimmung mit dem fs-Scan** → gleichzeitiges DB-Update bei `trivy fs` (Repo-Scan) und `trivy image` (Repository-Scan) → Contention im `.cache/trivy` → `err` mit `db lock` → Findings fehlen still. (Der fs-Scan läuft **vor** dem Image-Scan, also meistens ok, aber bei 8 Repos parallel nicht garantiert.) | `scan.ts:677–684` + `image-scan.ts:513–518` | `TRIVY_SKIP_UPDATE`-Flag + vorgeschalteter `trivy db`-Warm-Up im `entrypoint.sh` | **S** |
| **P3** | `advisories.ts:46` | **Cache-Leak:** `cache`-Map ist modul-global und wird **nie** geleert. Bei einer langen Session (interaktiv) wächst sie ins Unendliche. Für den Container irrelevant (Prozess endet). Kein Bug, aber Code-Smell. | `advisories.ts:46` | kein Fix nötig, nur Kommentar | — |
| **P3** | `pinning.ts:206` | **`npmLatest`-Cache ist `Map<string,string>` pro **Prozess** — bei mehreren Runs im **gleichen** Prozess (`--only` in Schleife) akkumuliert falsche Daten, wenn zwischen Runs neue Versionen publiziert werden. | `pinning.ts:93` | kein Fix für Cron, nur für Dev | — |
| **P4** | `Dockerfile:23` | `aquasec/trivy:0.76.1` gepinnt — **v0.76.2 existiert** (published 2026-11-05, `prerelease: false`). Der self-scan (`audit-scanner`-Repo) hätte das erkennen müssen; der Image-Scan liest aber nur `Dockerfile`/`compose` und **keine** `COPY --from=aquasec/trivy:0.76.1`-Zeile — nein, `parseInstr` erkennt `--from=` ja (`image-scan.ts:132`). Aber im Probe-Report steht `aquasec/trivy:0.76.2` — es wurde also schon gebumpt (in Arbeit). Also **kein Bug**, nur eine Info. | `Dockerfile:23` | — | — |
| **P4** | `package.json:6` | `"engines": {"node": ">=24"}` — **floating Major**, verstößt gegen die eigene Pins-Policy, die der Scanner erzwingt. `.nvmrc` = `26.13.0` (korrekt). | `package.json:6` | `"node": "26.13.0"` (oder `.nvmrc` dynamisch prüfen). **Selbst-Verstoß**, bei dem der Scanner auch seinen eigenen Repo-Scan bestehen sollte. | **S** |
| **P4** | `docker-compose.yml:8` | `image: audit-scanner:latest` — **floating**, der Scanner **vermisst** das selbst und meldet es als Note („latest — report-only"). | `docker-compose.yml:8` | bewusste Ausnahme dokumentieren (self-build-Image), sonst TODO | — |
| **P4** | Repo-Hygiene | `proxmox-jobs.sqlite3` (+`-shm`, `-wal`) liegt im Repo-Root, `.gitignore` hat `*.sqlite3*` **nicht** (nur `*.sqlite3`). | `.gitignore` + `ls` | `.gitignore` um `*.sqlite3*` ergänzen; Datei prüfen ob getrackt | **S** |

### 7.2 Test-/Verifikations-Lage (N4)

**Vorhanden (Selbsttests ohne Framework):**

| Test | Kommando | Abdeckung | Qualität |
|---|---|---|---|
| `state-test` | `node dist/index.js state-test` (`index.ts:181`) | `parseState` (corrupt/valid), `isKnownFinding`, `upsertEntry`, `ageDays`, `prOpenStatus` gegen echtes Repo | **Gut** für State, aber `prOpenStatus` ist ein **echter** API-Call — Test schlägt bei GH-Ausfall fehl |
| `image-freshness-test` | `node dist/index.js image-freshness-test` (`index.ts:251`) | `tagSemantics`, `newestSameMajorTag`, `newestExactTag`, `strictlyNewer`, `variantDriftTag` mit **statischen** Tag-Listen | **Gut** (kommt parallel in Arbeit) |
| `image-vulns-test` | `node dist/index.js image-vulns-test` (`index.ts:379`) | Novelty-Register, `telegramBody`-Kappung | **Gut** (kommt parallel) |
| `triage-test` | `node dist/index.js triage-test` (`index.ts:122`) | LLM-Triage mit 2 Fake-Findings | **Smoke-Test** — kein Assert auf Ergebnisjustierung, kein Determinismus |

**Nicht** vorhanden:

- **Keine Unit-Tests** für `replaceTag`, `parseInstr`, `parseDockerfile`, `parseCompose`, `splitRef`, `isFloatingSpec`, `semverSatisfies`, `bumpRequirementsTxt`, `applyBumps`, `renderPnpmWorkspaceYaml`. **Das ist die Ursache des P1-ReplaceTag-Bugs** — kein Test hätte den `node:24-alpine`-Fall gefunden.
- **Keine CI** (kein `.github/workflows/*`). Der Code wird per `tsc` gebaut, aber Tests laufen nicht automatisch. Das bedeutet: jeder der 4 Selbsttests ist ein **manueller** Schritt.
- **Keine Regressionstest-Grundlage** — die Selbsttests prüfen Verhalten, aber nicht die JSON-Schema-Form (z.B. dass `ImageVulnFinding` neue Felder hat).
- **Kein Lint/Format** — kein ESLint/Prettier (`package.json:9–16`). TypeScript strict hilft, aber `as`-Casts sind verbreitet.

**Empfehlung (dringlich):** Minimal-CI-Erweiterung mit `node --test` (nativ, Node 26 hat das eingebaut) für die bestehenden Selbsttest-Funktionen als **echte** Assertions, plus `replaceTag`-Regressionstests. **S–M**.

### 7.3 Rate-Limits / Fehlerbehandlung (Detail)

| Stelle | Verhalten | Risiko |
|---|---|---|
| `ghFetch` (`github.ts:34`) | 1× warten bei `remaining==0`, dann rekursiv | Endlos-Rekursion bei dauerhaftem 403; `AbortSignal` fehlt; initial kein `Timeout` auf `fetch` → **hang** möglich |
| `fetchRegistryTags` (`image-scan.ts:373`) | Kein Retry | einmaliger Netzwerk-Hiccup → Image ohne Freshness für diesen Lauf |
| `registryToken` (`image-scan.ts:345`) | Kein Retry | wie oben |
| `npmLatest` (`pinning.ts:102`) | 10 s Timeout, kein Retry | ok für den Cron |
| `trivyImageScan` (`image-scan.ts:522–525`) | 401/403 → „privat", 404 → „unbekannt", sonst generisch | **`trivy` gibt bei Rate-Limit (Docker Hub 429) `429` zurück** — das fällt in den generischen Fehler und wird als „trivy-Fehler" geloggt, aber nicht als Rate-Limit. Möglicher **stiller Verlust** der Image-Vulns |
| `fetchAdvisories` (`advisories.ts:69`) | Bei Fehler → `[]` (leer) und cache | **stiller Verlust**: unbekannte Findings sehen wie „keine CVE" aus |

**Empfehlung P2–P3:** Alle externen Calls in einen gemeinsamen `fetchWithRetry()` mit (a) 10 s Timeout, (b) `Retry-After`-Header, (c) max 2 Retries, (d) `AbortController`; Fehler **sichtbar** im Report (`notes: string[]` statt `[]`). **S**.

---

## 8. Roadmap

### 8.1 Priorisierte Schritte

| # | Schritt | Warum | Aufwand | Dateien |
|---|---|---|---|---|
| **1** | **`replaceTag`-Fix + Regressionstests** | P1-Bug, schreibt sonst kaputte Image-Refs. Tests verhindern Wiederholung. | **S** | `src/image-scan.ts` (nur `replaceTag`), `src/index.ts` (Testfall) |
| **2** | **`updateEligibility()` in `src/soaking.ts` + `publishedAt`-Fetcher** | N3-Kern, rein deterministisch, testbar mit `--as-of`-Fake-Uhr. | **M** | **NEU** `src/soaking.ts`, `src/config.ts`, `src/pinning.ts`, `src/image-scan.ts` |
| **3** | **`publishDates.ts` (npm, Docker Hub, GHCR, PyPI)** | Zulieferung für #2. GHCR via OCI-`created`-Annotation. | **M** | **NEU** `src/publish-dates.ts` |
| **4** | **Pre-Release-Klassifikation (`prerelease-hint`, `prerelease-current`)** | N2. Keine Bumps, nur Report-Info. | **S** | `src/image-scan.ts`, `src/pinning.ts`, `src/scan.ts` (Tabellen) |
| **5** | **Advisory-Layer → OSV.dev `querybatch` + npm-Bulk** | N1, 10× weniger API-Calls, first_patched sauber. | **M** | `src/advisories.ts` (neue Funktion, alte behalten) |
| **6** | **EPSS/KEV-Annotation** | N1, Priorisierung. | **M** | `src/advisories.ts` + `src/scan.ts` (Report-Spalten) |
| **7** | **Trivy-Vuln-IDs aufbewahren** + Base-Image-Dedupe (Digest) | Voraussetzung für #6 und Effizienz. | **S** | `src/image-scan.ts` |
| **8** | **Netzwerk-Retry-Layer** (`fetchWithRetry`, `AbortController`) | P2/P3, Hänger-Robustheit. | **S** | **NEU** `src/fetch-retry.ts` |
| **9** | **`.nvmrc`-Spec-Check + `engines.node` exakt + `*.sqlite3*`-Ignore** | Selbst-Verstoß + Regelkonformität. | **S** | `src/scan.ts` (Self-Audit), `package.json`, `.gitignore` |
| **10** | **CI + `node --test`-Wiring als `npm test`** | N4. Kein externes Framework nötig (Node-26-nativ). | **S** | **NEU** `.github/workflows/ci.yml`, `package.json` |
| **11** | **Trivy-Governance (`--vex repo`) als LLM-Triage-Alternative** | Optional, nur wenn LLM-Triage fehlt. Defer. | **L** | `src/image-scan.ts`, `src/scan.ts`, `Dockerfile` |

### 8.2 Reihenfolge (vektorisiert)

```
Sofort (P1):      1
N3-Kern:          2 → 3
N2-Neben:         4 (nach 2, weil publishedAt gemeinsam genutzt wird)
N1-Advisory:      5 → 7 → 6
Hygiene:          8, 9, 10 (parallel)
Defer:            11
```

### 8.3 Nicht in dieser Roadmap (bewusst raus)

- **Renovate einführen** — siehe §3.1.
- **Grype/Syft** — siehe §3.1.
- **Dependabot-Aktivierung** — nur als PR-Gate in Repos, nicht hier.
- **PyPI-PEP-440-Comparator** — nur nötig, wenn pip-Scope wächst; heute Report-only.
- **Digest-Pin-Enforcement** — schon als Idee im Report, aber nicht N1–N3.

---

## 9. Offene Fragen an den Nutzer

1. **CVE-Ausnahme für Image-Bumps:** Sollen Base-Image-Bumps (node:26.13 → 26.14) **immer** die 3-Tage-Regel durchlaufen (streng, empfohlen), oder soll ein „Minor-Release-Bump = CVE-Fix"-Heuristik greifen (sofort, aber unsauber)? Beides hat Kosten: streng = 3 Tage Wartezeit auf Updates; heuristisch = möglicherweise PR ohne echten Fix-Nachweis. **Empfehlung:** streng, mit Ausnahme für `aquasec/trivy` (Security-Releases).
2. **`UPDATE_MIN_AGE_DAYS` auch für **devDependencies** (1 Tag), oder soll es einen separaten Wert geben? Der Anlass ist die Projektroutine „devDeps dürfen schneller" — aber das erhöht die PR-Frequenz.
3. **`prerelease-hint` für Beta-Kanäle** — soll die Report-Info **auch dann** erscheinen, wenn **nur** ein Beta-Kandidat existiert (und kein stable-Update)? Heute würden wir es zeigen (N2-Anforderung „immer sichtbar"), was aber bei `payload`/`next`-RClern einen Dauer-Info-Eintrag erzeugt. **Empfehlung:** nur wenn `age ≥ minAgeDays` (3 Tage) — sonst Info-Rauschen.
4. **`SHOW_EXOTIC_PRERELEASES=1`** für Repos, die bewusst Nightly nutzen? Das wäre pro-Repo-Konfig (Datei `.cve-audit-prereleases` im Repo) — lohnt der Aufwand?
5. **`trivy`-Datenbank-Update-Strategie** — soll der Scanner die DB **einmal** im Vorlauf (`trivy image --download-db-only`) auf einen Stand bringen, bevor der erste Repo-Scan läuft (mehr Zeit pro Lauf, aber keine Contention), oder bei jedem Repo `--skip-db-update` setzen (weniger Zeit, aber veraltete Daten bei fehlgeschlagenem Vorlauf)?

---

## 10. Anhang: API-Celegenheiten (Rohauszüge)

### 10.1 npm — `time` und `dist-tags`

```bash
$ curl -s https://registry.npmjs.org/typescript | jq '.["dist-tags"]'
{
  "dev": "3.9.4",
  "tag-for-publishing-older-releases": "4.1.6",
  "insiders": "4.6.2-insiders.20220225",
  "rc": "7.0.1-rc",
  "latest": "7.0.2",
  "beta": "7.1.0-beta",
  "next": "7.1.0-dev.20261107.1"
}
# Zeiten:
"beta":  "2026-10-20T16:45:47.402Z"
"latest": "2026-07-08T15:55:18.431Z"
"next":  "2026-11-07T08:11:06.869Z"   # = heute, exotisch
```
→ `dist-tags` ist Voraussetzung für N2; `time[<version>]` ist Publish-Datum für N3.

### 10.2 Docker Hub — `tag_last_pushed`

```bash
$ curl -s https://hub.docker.com/v2/repositories/library/node/tags/26.13.0-alpine3.24
{
  "name": "26.13.0-alpine3.24",
  "tag_last_pushed": "2026-11-05T20:38:53.674865539Z",
  "last_updated":    "2026-11-05T23:40:34.390823Z"
}
$ curl -s 'https://hub.docker.com/v2/repositories/library/node/tags?name=26.13&page_size=3'
{"count": 18, "next": "…page=2&page_size=3", "results":[{"name":"26.13.0-trixie","tag_last_pushed":"2026-11-06T02:40:11.338733Z"}, …]}
```
→ `tag_last_pushed` **ist** das Publish-Datum je Tag. `last_updated` ist die letzte Änderung am Tag (kann `tag_last_pushed` oder Repo-Layer sein — `tag_last_pushed` ist die richtige Wahl).

### 10.3 GHCR — Publish-Datum via OCI-Annotation

```bash
$ TOK=$(curl -s "https://ghcr.io/token?scope=repository:aquasecurity/trivy:pull&service=ghcr.io" | jq -r .token)
$ curl -s -H "Authorization: Bearer $TOK" \
    -H 'Accept: application/vnd.oci.image.index.v1+json' \
    https://ghcr.io/v2/aquasecurity/trivy/manifests/0.76.1 | jq '.annotations'
{
  "org.opencontainers.image.created": "2026-10-21T10:43:17Z",
  "org.opencontainers.image.version": "0.76.1",
  "org.opencontainers.image.revision": "e713f67f…",
  …
}
```
→ **kein Docker-Daemon.** `docker manifest inspect` wäre der CLI-Weg, aber der braucht `docker` installed (nicht im Container) — `curl`+Bearer ist äquivalent.

### 10.4 PyPI — `upload_time_iso_8601`

```bash
$ curl -s https://pypi.org/pypi/requests/json | jq '.releases | to_entries | .[-1]'
{
  "key": "2.34.2",
  "value": [{
    "filename": "requests-2.34.2-py3-none-any.whl",
    "upload_time": "2016-04-29T21:57:23",
    "upload_time_iso_8601": "2016-04-29T21:57:23.021820Z",
    "yanked": false
  }]
}
```
→ `upload_time_iso_8601` direkt nutzbar; `yanked` zur Filterung.

### 10.5 deps.dev — `publishedAt` (Cross-Ecosystem-Fallback)

```bash
$ curl -s https://api.deps.dev/v3/systems/npm/packages/lodash/versions/4.17.15 | jq 'keys'
["versionKey","publishedAt","isDefault","isDeprecated","deprecatedReason","licenses","advisoryKeys","links","slsaProvenances","attestations","registries","relatedProjects"]
```

### 10.6 npm-Bulk-Advisories (CVSS/severity in 1 Call)

```bash
$ curl -s -X POST https://registry.npmjs.org/-/npm/v1/security/advisories/bulk \
  -H 'Content-Type: application/json' \
  -d '{"lodash":["4.17.15"]}' | jq '.["lodash"][0]'
{
  "id": 1106913,
  "url": "https://github.com/advisories/GHSA-35jh-r3h4-6jhm",
  "title": "Command Injection in lodash",
  "severity": "high",
  "vulnerable_versions": "<4.17.21",
  "cwe": ["CWE-77","CWE-94"],
  "cvss": {"score": 7.2, "vectorString": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"}
}
```
→ **kein** `first_patched_version`; Ableitung nötig aus `vulnerable_versions`.

### 10.7 OSV.dev `querybatch` (N1-Kern)

```bash
$ curl -s -X POST https://api.osv.dev/v1/querybatch \
  -H 'Content-Type: application/json' \
  -d '{"queries":[{"package":{"name":"lodash","ecosystem":"npm"},"version":"4.17.15"}]}'
{"results":[{"vulns":[
  {"id":"GHSA-29mw-wpgm-hmr9","modified":"2025-09-29T21:12:31.102523Z"},
  {"id":"GHSA-35jh-r3h4-6jhm","modified":"2026-10-17T02:55:38.085813Z"},
  … 5 Einträge
]}]}
```
→ **1 Call** für ein Pkg; für N Pakete: 1 Call. Details (siehe unten) nur für GHSA-relevante.

```bash
$ curl -s -X POST https://api.osv.dev/v1/query \
  -H 'Content-Type: application/json' \
  -d '{"package":{"name":"lodash","ecosystem":"npm"},"version":"4.17.15"}' | jq '.vulns[0]'
{
  "id": "GHSA-29mw-wpgm-hmr9",
  "aliases": ["CVE-2020-28500"],
  "severity": [{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L"}],
  "database_specific": {
    "cwe_ids": ["CWE-1333","CWE-400"],
    "severity": "MODERATE",
    "github_reviewed": true,
    "nvd_published_at": "2021-02-15T11:15:00Z"
  }
}
```
→ `aliases` mappt GHSA → CVE (für EPSS/KEV); `severity[].score` = CVSS-Vektor.

### 10.8 EPSS (FIRST.org)

```bash
$ curl -s 'https://api.first.org/data/v1/epss?cve=CVE-2020-28500,CVE-2021-23337' | jq '.data'
[
  {"cve":"CVE-2021-23337","epss":"0.213330000","percentile":"0.976170000","date":"2026-11-07"},
  {"cve":"CVE-2020-28500","epss":"0.073360000","percentile":"0.944280000","date":"2026-11-07"}
]
```
→ 1 Call pro Nightrun (max 100 CVEs/call), kein Auth.

### 10.9 CISA KEV

```bash
$ curl -sI https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
HTTP/2 200
content-length: 1832349
```
→ 1.8 MB JSON, Cache sinnvoll.

### 10.10 Renovate `minimumReleaseAge` (Spec-Vorlage für N3)

Quelle: `docs.renovatebot.com/configuration-options/` (abgerufen 2026-11-07), `id="minimumreleaseage"`:

> "Time required before a new release is considered stable. … `minimumReleaseAge` is a feature that requires Renovate to wait for a specified amount of time before suggesting a dependency update. … If `minimumReleaseAge` is set to a time duration and the update has a release timestamp header, then Renovate will check if the set duration has passed. This behaviour can be changed using `minimumReleaseAgeBehaviour`."

Zusätzlich `internalChecksFilter`:
> "`strict`: All pending releases will be filtered. PRs will be skipped unless a non-pending version is available. `flexible`: Similar to `strict`, but in the case where all versions are pending then a PR will be created."

**Bedeutung für uns:** Renovate hat das **Bau-Produkt** der 3-Tage-Regel bereits (strict/flexible). Wir bauen nur `strict` nach. `flexible` (= PR auch bei zu jungen Versionen) **nicht** — das ist ein bewusster Anti-Pattern für uns.

### 10.11 `trivy` Release-Stand

```bash
$ curl -s https://api.github.com/repos/aquasecurity/trivy/releases/latest | jq '{tag_name, published_at, prerelease}'
{"tag_name":"v0.76.2","published_at":"2026-11-05T12:50:25Z","prerelease":false}
```
→ `Dockerfile:23` pinnen `0.76.1` → `0.76.2` ist **S**-Bump (`.76` Minor → kein Major). Der Probe-Report zeigt `aquasec/trivy:0.76.2` in `audit-scanner`-Repo — in Arbeit.

### 10.12 GHCR-Auth-Feinheit (wichtig für P2)

| Endpoint | Ergebnis | Bedeutung |
|---|---|---|
| `https://ghcr.io/token?scope=repository:aquasecurity/trivy:pull&service=ghcr.io` | `200`, Token ~56 Zeichen | public repo, anonymous OK |
| `https://ghcr.io/token?scope=repository:mayraost/placeholder-404:pull&service=ghcr.io` | **`403`** `{"errors":[…]}` | privates/fehlendes Repo, **anonymous nicht erlaubt** |
| `https://ghcr.io/token?scope=repository:mayraost/placeholder-404:pull` (ohne `service`) | `403` | wie oben |

→ **`image-scan.ts:353`** baut `https://ghcr.io/token?scope=…` **ohne `service=ghcr.io`** — der `403` im Test ist primär wegen fehlendem `service`. **Empfehlung:** `service=ghcr.io` **+** `Authorization: Bearer <GH_TOKEN>` für private eigene Images. Also **zwei** Fixes: (a) `service`-Param, (b) Token aus `GH_TOKEN` für private Repos. **Beide in P2.**

---

## Anhang B — Zusammenfassung für den Folge-Subagenten

**Zu **ändern** (Reihenfolge):**
1. `replaceTag()` → Tag-Grenzen; Regressionstests.
2. Neue Datei `src/soaking.ts` mit `updateEligibility()` (exportiert).
3. Neue Datei `src/publish-dates.ts` mit 4 Fetchern (npm, Docker Hub, GHCR, PyPI).
4. `pinning.ts`: `npmLatest` → `npmInfo` (dist-tags + time); `PinFinding` um `betaHint?`, `publishedAt?`, `eligibility?` erweitern.
5. `image-scan.ts`: `tagSemantics` um `prereleaseClass`/`channel`; `addRef` nicht mehr `prerelease` skippen; `ImageFinding` um `vulnIds?`, `publishedAt?`, `eligibility?`, `betaHint?` erweitern.
6. `scan.ts`: Report-Tabellen um `Age`- und `Eligibility`-Spalte erweitern; `updateEligibility` vor `createImagePr`/`createPinsPr` aufrufen (nur `eligible`/`cve-exempt` → PR).
7. `advisories.ts`: neue Funktion `collectAdvisoriesBatch()` (OSV + npm-Bulk + EPSS + KEV) — die alte `fetchAdvisories` **behalten** als Fallback, damit parallele Arbeiten nicht brechen.
8. `config.ts`: `UPDATE_MIN_AGE_DAYS` (Default 3), `SHOW_PRERELEASES` (Default `info`), `CVE_EXEMPT_HEURISTIC` (Default `trivy-only`).
9. `package.json`: `engines.node` exakt (`26.13.0`) + `test`-Script.
10. `.gitignore`: `*.sqlite3*`.
11. Neue Datei `.github/workflows/ci.yml` (falls CI erwünscht).

**Nicht zu ändern:**
- `state.ts`-Schema (für N3 nicht nötig).
- Branch-Schemata `cve-audit/*-<date>`.
- Telegram-Chunking in `telegram.ts`.
- LLM-Triage (außer optionalem §8-Schritt 11).
- Die parallel in Arbeit befindlichen Funktionen in `image-scan.ts` (variantDrift) und `scan.ts`/`state.ts` (Image-Vuln-Findings).

# audit-scanner

![Version](https://img.shields.io/badge/version-1.5.1-blue)
![Node](https://img.shields.io/badge/node-%E2%89%A524%20%2F%2026.13.0-brightgreen)
![Trivy](https://img.shields.io/badge/trivy-0.76.1-informational)
![TypeScript](https://img.shields.io/badge/TypeScript-7.x%2Fstrict-blue)

Nightly CVE-Audit aller Repos im GitHub-Account `mayraost`: Repos werden als
Tarball geladen und mit [Trivy](https://github.com/aquasecurity/trivy)
(fs- und image-scan, nur HIGH/CRITICAL) gescannt, die Treffer gegen die
[GitHub-Advisories-DB](https://github.com/advisories) gematcht und das Ergebnis
an Telegram gemeldet. Optional legt der Scanner automatisch Fix-PRs an — dazu
zählen CVE-Bumps, Docker-Image-Tag-Bumps/Pins und Exact-Pin-PRs für floating
npm-Specifier. Der Scanner läuft als Docker-Compose-App mit internem Busybox-cron —
keine Ports, keine Domain, reiner Batch-Job.

**Funktionen:**

- Inventar aller Owner-Repos (public + private, forks excluded, archivierte
  Repos komplett gefiltert)
- `trivy fs`-Scan je Repo (Tarball, Offline-DB im Volume-Cache)
- Crosscheck gegen GitHub Security Advisories inkl. semver-Match und
  `first_patched_version`
- Image-Scan: Dockerfile- (`FROM`, `COPY/ADD --from`) und Compose-`image:`-Refs,
  Registry-Freshness-Check (Docker Hub/GHCR, same-major)
- Pinning-Enforcement: floating npm-Specifier werden erkannt und gefixt
- Optionale LLM-Triage (suppress entfernt cdv-Meldepflicht bei hoher Konfidenz)
- Persistenter PR-State für tagesübergreifendes Dedupe + tägliche Reminders
- Auto-Fix-PRs (opt-in) für CVE-, Image- und Pins-Befunde
- Report als `report.json`/`report.md`, neuer Tag je Tag-Verzeichnis
- Telegram-Notify (nur bei neuen Findings oder offenen PRs)
- Heartbeat + Docker-HEALTHCHECK (frisch getoucht < 48 h)

## Inhaltsverzeichnis

1. [Übersicht der PR-Kinds](#übersicht-der-pr-kinds)
2. [Wie es funktioniert](#wie-es-funktioniert)
3. [Fix-PR-Details je Ökosystem](#fix-pr-details-je-ökosystem)
4. [Image-Scan](#docker-image-scan-dockerfile--compose)
5. [Pinning-Enforcement](#pinning-enforcement-seit-v150-)
6. [Installation & Setup](#installation--setup)
7. [Konfiguration](#konfiguration)
8. [Usage / CLI](#usage--cli)
9. [Docker / Deployment](#docker--deployment)
10. [Versionierung](#versionierung)
11. [Tests & Sicherheit](#tests--sicherheit)
12. [Lizenz](#lizenz)

## Übersicht der PR-Kinds

Sobald `ENABLE_FIX_PRS=1` gesetzt ist, legt der Scanner bis zu drei PR-Arten
je Repo und Tag an. Allerdings in getrennten Branches — und mit unterschiedlichem
Reminder-Verhalten (CVE/Pins werden täglich erinnert, Images bewusst nicht).

| Kind | Branch-Pattern | Auslöser | Reminder-Verhalten |
| --- | --- | --- | --- |
| `cve` | `cve-audit/fixes-<YYYY-MM-DD>` | fixbares trivy/GHSA-Finding (npm/pip, first_patched vorhanden) | tägliche Telegram-Erinnerung (Tag-Counter), State-Dedupe |
| `image` | `cve-audit/images-<YYYY-MM-DD>` | exakt gepinnter Tag mit neuerer Version im selben Major **oder** floating Major-Tag (Pinning-PR) | kein CVE-Reminder — Image-PRs gelten als kurzlebig, State-Eintrag hat `kind: "image"`, taucht nie in der Reminder-Sektion auf |
| `pins` | `cve-audit/pins-<YYYY-MM-DD>` | floating npm-Specifier in `dependencies`/`devDependencies` (EIN PR je Repo mit allen Manifests) | tägliche Telegram-Erinnerung, State-Eintrag `kind: "pins"` |

## Wie es funktioniert

Pipeline je Nachtlauf (bzw. manueller Trigger):

1. **Inventar**: alle Repos des Owners via `GET /user/repos` (paginiert, public
   + private, **forks excluded**). Archivierte Repos werden seit v1.5.1 beim
   Inventar-Load **komplett gefiltert**: kein Report-Eintrag (JSON/MD), kein
   Telegram-Mention, keine Log-/Skip-Zeile, kein `--only`-Treffer. Andere Skips
   (SKIP_REPOS, `.cve-audit-skip`, kein Manifest) bleiben sichtbar im
   Report-Abschnitt „Nicht gescannt“.
2. **Tarball**: Default-Branch-Head laden → Repo-Tarball entpacken.
3. **Trivy fs**: Offline-DB (Cache im Volume, 1× Laden + inkrementelle Updates),
   Filter auf HIGH/CRITICAL.
4. **Advisories-Crosscheck**: jedes trivy-Finding gegen die
   GitHub-Security-Advisories-DB matchen — semver-basiert; für das
   Fix-PR-Handling zählt `first_patched_version.identifier`.
5. **Dev-Only-Erkennung**: Mitgliedschaft in `devDependencies` (vs.
   `dependencies`) wird aus der `package.json` des gescannten Tarballs geparst
   (`markDevOnly`) und dem LLM-Triage-Prompt als Kontext mitgegeben.
6. **LLM-Triage (optional)**: mit `DEEPINFRA_API_KEY` triagiert ein LLM je
   high/critical-Finding: `remediate` / `suppress` / `investigate` +
   Confidence (0–1) + Begründung. **Suppress wirkt nur bei Confidence ≥ 0.75** —
   solche Findings landen nicht im Fix-PR, sondern in der
   „LLM-suppressed“-Sektion des Reports. Default-Modell
   `zai-org/GLM-5.3-Flash` (DeepInfra, OpenAI-kompatibler Endpoint,
   konfigurierbar via `LLM_MODEL`/`LLM_BASE_URL`). Ohne Key: `LLM disabled`,
   Scanner läuft deterministisch weiter.
7. **State-Dedupe**: persistenter State in `reports/state.json` — je Repo wird
   vor jeder PR-Erstellung der Remote-Status geprüft (`reconcileRepo`:
   offener PR existiert → kein Duplikat, `lastSeen` aktualisiert; geschlossen/
   gemergt → Eintrag entfällt). Corruptes/fehlendes JSON → State startet leer
   und wird aus GitHub rebuilt.
8. **Optional Auto-Fix-PRs**: je nach Befund `cve`-, `image`- oder `pins`-PR
   (Details in den folgenden Abschnitten).
9. **Report + Heartbeat**: `reports/<YYYY-MM-DD>/report.json` und `report.md`;
   `.heartbeat` wird getoucht (HEALTHCHECK akzeptiert Alter < 48 h).
10. **Telegram**: Nachricht nur, wenn **neue Findings** vorliegen **oder**
    offene CVE/Pins-PRs existieren (Reminder-Sektion zuerst, danach nur neue
    Findings; nur Reminders → kompakte Kurznachricht). „Neue Findings“ umfasst
    seit v1.5.2 auch **novel Base-Image-CVEs** (geänderte H/C-Zahl je
    Repo+Image gegenüber `state.json`) — eigene Sektion
    `🛡 Image-Vulns (Base-Image)`. Weder noch → kein Versand, nur Log.
    Image-PRs wurden bewusst ab v1.4.0 **ohne** daily
    Reminder gebaut (kurzlebig). Ohne Telegram-Config wird der Versand still
    übersprungen (Scan läuft trotzdem).

## Fix-PR-Details je Ökosystem

Fix-PRs laufen REST-only (kein `git clone`): Branch ab Default-Branch-Head,
Manifest per `GET→PUT /contents` (BLOB-SHA), PR via `POST /pulls`. Der
Manifest-Ort stammt aus dem Trivy-Evidenzpfad je Finding (auch mehrere
Manifests pro Repo möglich).

### npm-Familie (npm/pnpm/yarn)

- **Direkte Deps**: Bump in allen vier `package.json`-Sektionen
  (`dependencies`, `devDependencies`, `optionalDependencies`,
  `peerDependencies`) im jew. Manifestverzeichnis.
- **Transitive Deps**: über `overrides` in `package.json` bzw. top-level
  `overrides` in `pnpm-workspace.yaml` (pnpm ≥ 12) desselben Verzeichnisses.
- **EXACT-PIN-Regel (seit v1.5.0)**: CVE-Bumps schreiben die **exakte
  gepatchte Version** (`x.y.z`) — keine Range-Erhaltung (`^`/`~` wird nicht
  weitergeführt).
- **Lockfile-Regen** im selben Manifestverzeichnis (tmp-Dir, dann PUT des
  Lockfiles): `npm install --package-lock-only --ignore-scripts`
  (mit `NPM_CONFIG_ALLOW_REMOTE=all`) bzw. pnpm via corepack
  `pnpm install --lockfile-only`. Yarn → manuelle Note (kein Auto-Regen).
- **Downgrade-Guard**: ist die ermittelte `first_patched`-Major kleiner als die
  installierte Major (veraltete/übereignete Advisory-Hits), wird der Bump
  übersprungen — niemals auf kleinere Version downgraden.
- Findings ohne verwertbare `first_patched`-Version → kein PR-Inhalt, erscheint
  im Telegram-Report mit `⚠️ keine gepatchte Version`.

### pip

`requirements.txt`-Zeile `pkg==X` (bzw. `pkg>=X`) wird auf die gepatchte
Version gebumpt, mit Inline-Kommentar:

```
# cve-audit GHSA-xxxx-yyyy: 1.2.0 → 1.4.2
```

### go / cargo / bundled

**Report-only** — kein Auto-Fix. Findings werden gescannt, gematcht und
gemeldet, aber die Manifests werden nicht automatisch gebumpt.

## 🐳 Image-Scan (Dockerfile / compose, seit v1.4.0)

Nach dem Tarball-Entpacken wird je Repo nach Docker-Image-Quellen gefiltert:

- **Dockerfile** (alle Varianten `Dockerfile`, `Dockerfile.<name>`): alle
  `FROM <ref>` inkl. BuildKit-Flags (`--platform=…`) und `COPY/ADD --from=<ref>`
  — Stage-Namen (`AS builder`) und numerische Stage-Indizes werden
  ausgeschlossen. `FROM scratch` / `$VAR`-Refs → Skip mit Note.
- **`docker-compose.yml` / `compose.yaml`**: alle `image:`-Felder (Zeilen-Regex,
  robust gegen Inline-Kommentare/Quotes).

Je Repo dedupliziert (Ref über alle Files gemerged), dann:

1. **`trivy image` ohne Docker-Daemon** — Registry-API wird direkt angetaktet
   (DB teilt denselben Trivy-Cache). Nur HIGH/CRITICAL zählen. Private/404-
   Images → graceful Skip im Report statt Hard-Fail.
2. **Freshness-Check** je Image-Ref: Registry-Tag-Liste (Docker Hub via
   `auth.docker.io`-Token-Flow, GHCR analog; Paginierung bis 2 Seiten) →
   neuester gepinnter Tag **im selben Major** (Variant-Präferenz: passende
   `-alpine`-Varianten bevorzugt). Pre-Releases (`-alpha/-beta/-rc/-dev`)
   ausgeschlossen. Digest-pinned / `latest` / tag-less / `$VAR`-Refs → Skip
   mit Note. Andere Registries (`gcr.io`, `quay.io`, `registry.k8s.io`, …)
   werden von trivy gescannt, aber der Freshness-Check bleibt Docker Hub +
   GHCR vorbehalten.
   **Variant-Regel (token-basiert, seit v1.6.0):** Die Variante wird an `-`
   in Tokens zerlegt; ein Kandidat gilt nur dann als *gleiche* Variante, wenn
   die Tokens des current-Tags Präfix der Kandidaten-Tokens sind und höchstens
   **ein** zusätzlicher Token dabei ist, der ein bekanntes OS-Release
   (`alpine3.24`, `trixie`, `bookworm`, `bullseye`, `noble`, `jammy`, `slim`, …)
   ist. Damit matcht `node:26.13.0-alpine3.24` weiter exakt, `slim` erkennt
   `slim-trixie` als **OS-Basis-Wechsel** — und `pg17` matcht **nicht**
   `pg17-trixie` als Versions-Update. Bewusst restriktiv: lieber kein
   „update verfügbar“ als ein falscher Bump.
   **`variantDrift`-Marker:** Existiert ein semver-identischer Tag mit anderer
   OS-Basis (z. B. `0.8.7-pg17` → `0.8.7-pg17-trixie`), setzt der Scan das
   Feld `variantDrift` (Kandidaten-Tag) am Finding. Das ist **report-only**:
   **kein** Bump-Plan und **kein** PR (Variant-/OS-Wechsel ist ein Risiko,
   keine Update-Empfehlung). `strictlyNewer()` vergleicht ausschließlich den
   Zahlen-Teil und ist bei semver-Gleichheit immer `false`; `newestSameMajor`
   ist per Konstruktion **nie semver-kleiner** als der current-Tag (sonst
   fällt der Report auf `exaktPin` bzw. `—` zurück).
3. **Fix-PR-Policy (v1.5.0)**:
   - **Exakte Tags** (`x.y.z`, z. B. `aquasec/trivy:0.76.1`) mit verfügbarer
     streng neuerer Version im selben Major → Tag-Bump-PR
     (`cve-audit/images-<date>`), `contents`-PUT je Quelldatei.
   - **Floating Major-Tags** (z. B. `node:24-alpine`) → **Pinning-PR**:
     floating → neuester exakter Tag im selben Major mit Variant-Fallback
     (`node:24-alpine` → `node:24.22.2-alpine3.24`).
   - **`latest` / tag-less** → report-only Note (Major-Sprung-Risiko, Pins beim
     Menschen). Digest-pinned refs bleiben Skip (schon reproduzierbar).
4. **Report/Telegram**: Sektion `🐳 Images` je Repo
   (Image | current | newest | Vulns H/C | Status); Image-PRs erscheinen als
   eigene `imagePrs`-Summary-Zeile und als State-Eintrag `kind: "image"`
   (ohne CVE-Reminder).
5. **Base-Image-CVEs als eigene Findings (v1.5.2)**: jedes Image mit
   `high+critical > 0` erscheint als `imageVulnFindings`-Eintrag im Report
   (`repo`, `image`, `sourceFiles`, `high`, `critical`; sortiert nach
   `critical`, `high`, `image`) und als Summary-Zähler
   `Image-Vulns: H<n>/C<n> (n Images)` — auch für **gepinnte + aktuelle**
   Images, für die kein Image-PR möglich ist. Telegram meldet sie in der
   eigenen Sektion `🛡 Image-Vulns (Base-Image)` **nur bei neuen Zahlen**
   (Novelty-Register `imageVulns` in `state.json`: `repo → image →
   "H<h>/C<c>"`; Abweichung oder unbekanntes Image = neu, max. 15 Zeilen).
   Das Register wird erst **nach erfolgreichem** Telegram-Versand
   fortgeschrieben — bei Telegram-Fehler wird erneut gemeldet. Mit
   `ENABLE_FIX_PRS=0` gibt es keinen State: alle Einträge gelten als novel
   (nur Report), kein State-Write. Die 🐳-Sektion filtert weiterhin
   update/floating und zeigt weiter **keine** gepinnten+aktuellen Images.

## 📌 Pinning-Enforcement (seit v1.5.0)

Vorgabe „keine floating versions“: alle npm-Specifier müssen exakt sein
(`x.y.z`), nie `^`, `~`, `>=`, `*`, x/y-Ranges. Der Scanner erzwingt das je
gescanntem Repo:

1. **Detection**: alle `package.json` des Repos (ohne `node_modules`) werden
   geparsed. Floating = `semver.valid(spec) === null`. Gescannt werden
   `dependencies` + `devDependencies` (**PR-Kandidaten in EINEM PR pro
   Repo**) sowie `optionalDependencies` + `peerDependencies` (observed,
   **report-only**). Protocol-/Path-Specs (`workspace:*`, `file:`, `link:`, …)
   gelten nicht als Registry-Specifier → kein Finding.
2. **severity**: `warn` für production-deps, `info` für dev/optional/peer
   (kein CVE — Pinning ist Hygiene, kein Security-Befund). LLM-Triage und
   -Suppress greifen **nicht** für Pins.
3. **npm-Latest-Lookup**: `registry.npmjs.org/<pkg>` → `dist-tags.latest`,
   Cache pro Paket (wenige Lookups je Run).
4. **Pins-PR** (deterministisch, kein LLM): ALLE floating deps eines Repos in
   **einem PR** (`cve-audit/pins-<date>`), alle package.json-Manifests des
   Repos in derselben Branch. Bump auf exakte latest-Version, Downgrade-Guard
   analog CVE-Fix. Major-Sprünge werden im PR-Body mit `⚠️ major jump`
   markiert und sind bewusst vom Menschen zu akzeptieren. Lockfile-Regen im
   Manifestverzeichnis (`npm install --package-lock-only`-Style, pnpm analog
   via corepack `--lockfile-only`); Nested-Manifests ohne Lockfile im selben
   Verzeichnis → manuelle Regen-Note.
5. **Report/Telegram**: Report-Sektion `📌 Unpinned deps (package.json)` je
   Repo (`pkg | current ^1.2.3 | latest exact X.Y.Z | scope | sev | soaking |
   beta`), Summary `unpinned deps: N` + `pinsPrs`-Zähler, Telegram `📌 Unpinned
   deps`-Block + `Pins-PRs diesmal: …`. State-Eintrag `kind: "pins"` (mit Reminder).

## ⏳ Soaking & Beta-Erkennung (seit v1.6.0)

Ziel: **kein Update auf eine frisch publizierte Version** — Schutz gegen
Package-Poisoning (kompromittierte Releases werden typischerweise innerhalb
von Stunden nach Publish entdeckt und zurückgezogen).

**Regel 1 — 3-Tage-Reife.** Ein Update (npm-Pin *und* Image-Tag-Bump) wird erst
angeboten, wenn die **Zielversion** mindestens `UPDATE_MIN_AGE_DAYS` (= 3) Tage
alt ist. Die Prüfung ist **rein deterministisch** (kein State): ein heute
2 Tage alter Kandidat ist morgen 3 Tage alt und wird dann angeboten.

Datenquellen (alle ohne Docker-Daemon, nur HTTP):

| Ökosystem | Quelle | Feld |
|---|---|---|
| npm | `registry.npmjs.org/<pkg>` | `time[<version>]` |
| Docker Hub | `hub.docker.com/v2/repositories/<repo>/tags/<tag>` | `tag_last_pushed` |
| GHCR | `ghcr.io/v2/<repo>/manifests/<tag>` | OCI-Annotation `org.opencontainers.image.created` |
| PyPI | `pypi.org/pypi/<pkg>/json` | `releases[<v>][0].upload_time_iso_8601` |

Unbekanntes Datum (private Registry, fehlende Annotation) → **fail-open**
(Update erlaubt, als „unbekanntes Alter“ markiert), damit nichts still hängt.

**Regel 2 — einzige Ausnahme: belegter CVE-Fix.** Ein HIGH/CRITICAL-*Fix*
umgeht die Wartezeit — Status `cve-exempt`. Bewusst **streng**:

- Paket-Scan: `advisory.firstPatched` entspricht der Zielversion.
- Image-Scan: **nur** Security-Tools (`aquasec/trivy`, `anchore/grype|syft`),
  deren jedes Release Vulnerability-/Signatur-Daten ausliefert.
- Ein Base-Image-Patch-Bump (`node:26.13 → 26.14`) ist **keine** Ausnahme —
  er beweist keinen CVE-Fix.

Status im Report: `✓ reif (5d)` · `⏳ zu jung (2d)` · `🔴 CVE-Fix, sofort` ·
`⛔ Variant-Wechsel — kein Update`.

**Regel 3 — Beta-Hinweis nur für Beta-Pakete.** Ein Pre-Release-Kandidat
(`-beta`, `-rc`, `-alpha`) wird **ausschließlich dann** gemeldet, wenn das Paket
**bereits** auf einem Beta/RC-Kanal liegt — und dann nur im **selben Kanal**
(`rc → rc`, nicht `rc → beta`, nie `stable → beta`). Beta-Updates sind immer
**info-only**: nie Bump-Ziel, nie Pins-PR, nie Image-Bump. Nightly/Canary/
Dev/Insiders (`prerelease-exotic`) sind standardmäßig stumm
(`SHOW_EXOTIC_PRERELEASES=1` zum Zeigen).

Telegram: `ℹ️ Beta/RC-Updates (Paket bereits im Beta-Kanal)` — nur für Kandidaten
mit Soaking-Reife. Zu junge Updates erscheinen im Alert als
`⏳ zu jung (2d) (Report)`, also ohne Handlungsaufforderung.

## Installation & Setup

### Voraussetzungen

- **Node ≥ 24** (lokal; `engines` in package.json). Empfohlen/Pinned:
  Node **26.13.0** (`.nvmrc`, Dockerfile-Basis `node:26.13.0-alpine3.24`).
- Trivy wird im Image **mitgeliefert** (COPY aus
  `aquasec/trivy:0.76.1`) — lokal muss `trivy` im PATH liegen (bzw. via
  `TRIVY_BIN` gesetzt werden).
- **GitHub-PAT**: Fine-grained PAT erstellen (github.com → Settings →
  Developer settings → Fine-grained personal access tokens):
  - Repository access → **alle Owner-Repos** (`mayraost`)
  - **Contents** (read + write, nur bei `ENABLE_FIX_PRS` write)
  - **Metadata** (read, Pflicht)
  - **Pull requests** (read + write, nur wenn `ENABLE_FIX_PRS=1`)
  - Die globalen Advisories-Endpoints brauchen keine Spezial-Permission.
  
  Alternativ klassischer PAT mit Scope `repo` (deckt Lesen, Branches,
  Contents und PRs ab).

### Docker-Compose-Start (Coolify)

Coolify → neue App vom Typ **Docker Compose** auf Basis dieses Repos.
Compose referenziert nur `${VAR}` — Secrets kommen ausschließlich über die
App-Environment (nicht ins Repo committen). Keine Ports, keine Domain, kein
`networks:`-Block. Nach dem Deploy `running:healthy` abwarten und
„test-telegram“ im Container ausführen (siehe [Usage](#usage--cli)).

### Lokale Entwicklung

```sh
npm ci
npm run build            # tsc → dist/
export GH_TOKEN=...      # ODER: gh CLI authed (`gh auth token` wird als Dev-Fallback genutzt)
node dist/index.js inventory
```

Lokal ohne Docker braucht ein voller `scan` zusätzlich `trivy` im PATH.

## Konfiguration

| Variable             | Pflicht       | Default | Bedeutung |
| --- | --- | --- | --- |
| `GH_TOKEN`           | ja (im Container) | — | GitHub-PAT (Bearer für `api.github.com`). Lokaler Dev-Fallback: `gh auth token` der authed gh-CLI, nur wenn `GH_TOKEN` fehlt. |
| `TELEGRAM_BOT_TOKEN` | nein | — | Ohne = kein Telegram-Versand (Scan läuft trotzdem). |
| `TELEGRAM_CHAT_ID`   | nein | — | Ziel-Chat (User-ID oder Group-ID). |
| `TELEGRAM_PARSE_MODE` | nein | *(plain text)* | `MarkdownV2` schaltet Markdown-V2-Modus inkl. korrekter Escapes ein; Default ist bewusst plain text. |
| `ENABLE_FIX_PRS`     | nein | `0` | `1`/`true` = Auto-Fix-PRs (CVE, Image, Pins) anlegen. Aktiviert implizit State + Reminder. |
| `SKIP_REPOS`         | nein | *(leer)* | Kommagetrennte Repo-Namen als Skip-Liste. Default leer = alle Repos scannen (auch `audit-scanner` selbst → self-scan). |
| `CRON_SCHEDULE`      | nein | `0 16 * * *` | Cron in Container-Zeit (TZ=Europe/Berlin → 16:00 Ortszeit, DST-korrect via tzdata). |
| `DEEPINFRA_API_KEY`  | nein | — | LLM-Triage + LLM-PR-Bodies. Ohne = `LLM disabled`, deterministischer Flow. |
| `LLM_MODEL`          | nein | `zai-org/GLM-5.3-Flash` | Modell-ID am OpenAI-kompatiblen Endpoint. |
| `LLM_BASE_URL`       | nein | `https://api.deepinfra.com/v1/openai` | OpenAI-kompatible Basis-URL (andere Provider möglich). |
| `TRIVY_BIN`          | nein | `trivy` | Pfad zum Trivy-Binary. |
| `TRIVY_CACHE_DIR`    | nein | `<WORK_DIR>/.cache/trivy` | Trivy-DB-Cache (im Container im Volume `audit-cache`). |
| `WORK_DIR` / `REPORTS_DIR` | nein | `/app` / `<WORK_DIR>/reports` | Pfad-Konventionen (Container-Setup); Report-Unterverzeichnisse je Tag. |
| `UPDATE_MIN_AGE_DAYS` | nein | `3` | **Soaking** (v1.6.0): Ein Update wird erst angeboten/gepinnt, wenn die Zielversion so viele **Tage** alt ist (Schutz gegen Package-Poisoning). `0` = aus. Alternative **nur** bei belegtem HIGH/CRITICAL-CVE-Fix. |
| `SHOW_EXOTIC_PRERELEASES` | nein | `0` | `1` = Nightly/Canary/Dev/Insiders-Kandidaten zusätzlich im Report zeigen (Default aus, Rauschkontrolle). |

**Item-Level-Skip**: Datei `.cve-audit-skip` im Repo-Root (wird im Inventar
erkannt; Repo erscheint als `skip(repo-file)`). **`SKIP_REPOS`** klammert Repos
per ENV aus. Beide gelten nicht für archivierte Repos — die werden ohnehin
immer komplett gefiltert (`skipped-archived` hard guard).

## Usage / CLI

npm-Scripts:

```sh
npm run build          # tsc
npm run scan           # build + voller Durchlauf (Scan + Telegram + Fix-PRs)
npm run inventory      # Inventarlisting (Repos + erkannte Ökosysteme)
npm run test-telegram  # 1 Config-Testnachricht an Telegram
npm run state-test     # PR-Dedupe-State Selbsttest
npm run image-vulns-test # Image-Vuln-Findings/Novelty-Selbsttest (synthetisch)
npm run image-freshness-test # Image-Tag-Freshness (Variant-Matching) Selbsttest
```

Direkte Kommandos (nach `npm run build`):

```sh
node dist/index.js scan                        # voller Lauf
node dist/index.js scan --only=repo1,repo2     # Probe-Lauf: nur diese Repos,
                                               # Report suffixed als
                                               # report.only-<repos>.md —
                                               # Tages-Report unangetastet
node dist/index.js inventory
node dist/index.js test-telegram
node dist/index.js triage-test  # LLM-Triage mit 2 Fake-Findings (kein Scan/Telegram)
node dist/index.js state-test   # State-Dedupe-Selbsttest (simuliert, Fake-Branch)
node dist/index.js image-vulns-test # Image-Vuln-Novelty-Selbsttest (synthetisch)
node dist/index.js image-freshness-test # Variant-Matching/Freshness (kein Netz)
```

Achtung: `scan` ist ein echter Lauf (Trivy-Downloads, API-Calls, bei
`ENABLE_FIX_PRS=1` echte PRs). Zum Testen ohne Nebenwirkungen nur `inventory`,
`triage-test` oder `state-test` nutzen.

**Manueller Container-Trigger** (laufende App, kein Deploy nötig). Der
Container-Name ändert sich pro Deploy:

```sh
docker ps --format '{{.Names}}' | grep audit-scanner
docker exec -d <container> sh -c 'sh /app/bin/scan-wrapper.sh >> /app/logs/scan.log 2>&1'
```

**Wichtig: Wrapper + Log-Redirect benutzen, nicht `node dist/index.js scan`
roh.** Der Wrapper (`bin/scan-wrapper.sh`) macht Log-Rotate + Heartbeat-Touch;
der Redirect muss **im Container** passieren (`sh -c '… >> …'`), nicht auf dem
Host — bei `docker exec -d` verwirft Docker sonst den Output.

Status/Log nach dem Lauf:

```sh
docker exec <container> tail -50 /app/logs/scan.log
ls -l /app/reports/$(date +%F)/      # neue report.json / report.md
```

Reports liegen unter **`/app/reports/<YYYY-MM-DD>/`** (untagged Drafts in
`report.json`/`report.md`, plus `state.json` und `.heartbeat` direkt unter
`/app/reports/`).

## Docker / Deployment

3-Stage-Dockerfile:

1. **build** (`node:26.13.0-alpine3.24` exakt gepinnt): `npm ci` mit
   BuildKit-Cache-Mount + `tsc`.
2. **deps-prod**: `npm ci --omit=dev` (eigene Stage, weil nur `semver` als
   Runtime-Dep übrig bleibt).
3. **runner**: alpine-Runner mit Trivy-Copy (`COPY --from=aquasec/trivy:0.76.1`),
   `tzdata` für TZ-Auflösung, `dist` + prod-node_modules + `bin/`.

- **HEALTHCHECK** heartbeat-age-basiert: `interval 15m`, Fail wenn
  `.heartbeat` älter als 48 h (`test $(( $(date +%s) - $(stat -c %Y .heartbeat) )) -lt 172800`).
  entrypoint touched den Heartbeat boot-seitig, damit keine False-Fails beim Start.
- **crond als PID 1** — **WICHTIG**: crond läuft als **root**. Busybox-crond
  lädt Crontab-Files nur bei `st_uid == 0` (`crond.c:440, DAEMON_UID`) und
  non-root crond kann Jobs mangels `setgroups` gar nicht ausführen. Deshalb
  ist bewusst **kein `USER node`** im Dockerfile; die Jobs werden per setuid
  vom crond selbst auf `node` demoted. Volume-Pfade gehören trotzdem `node`.
- **Volumes** (`docker-compose.yml`): `audit-reports` → `/app/reports`
  (Report-JSON/MD, `state.json`, `.heartbeat`), `audit-cache` → `/app/.cache`
  (Trivy-DB, nur 1× Laden statt jede Nacht), `audit-logs` → `/app/logs`
  (scan.log + crond.log).
- **Cron-Einbindung**: entrypoint rendert `CRON_SCHEDULE` in
  `/app/crontabs/node` (root-owned, Pflicht) und startet
  `crond -f -l 8 -L logs/crond.log`. Cron-Job ruft `bin/scan-wrapper.sh`
  auf (Log-Rotate > 5 MB → Start-Tail behalten).
- **[skip ci]-Verhalten eigener PR-Commits**: Commits, die über die eigenen
  Fix-PRs landen, dürfen den Scanner nicht triggern — ist im Deploy-Workflow
  durch Commit-Marker sichergestellt, damit keine PR-Recursion entsteht.
- Coolify Typ: Docker-Compose-App, Build aus Repo-Root, **keine Ports /
  keine Domain / kein networks-Block** (implizites Projekt-Default-Netz).

## Versionierung

Kompakte Release-Historie (git history; Version in package.json):

| Version | Änderungen |
| --- | --- |
| v1.1.0 | PR-State (`state.json`) + tägliche CVE-Reminder, State-Dedupe gegen offene PRs |
| v1.4.0 | Image-Scan (Dockerfile/compose, `trivy image` ohne Docker-Daemon, Freshness-Check) — Image-PRs bewusst ohne daily Reminder |
| v1.5.0 | Exact-Pin-Enforcement: CVE-Bumps schreiben exakte Versionen; Pins-PRs (`cve-audit/pins-*`) für floating npm-Specifier; floating Image-Tags → Pinning-PRs |
| v1.5.1 | Archivierte Repos hard-guard: beim Inventar-Load komplett gefiltert (kein Report/Telegram/Log/`--only`-Treffer) |

## Tests & Sicherheit

**Tests / Selbsttests:**

- `state-test` — simuliertes State + PR-Status-Check gegen
  `mayraost/audit-scanner` mit nicht existierendem Fake-Branch (keine echten
  PRs, kein Telegram-Versand).
- `image-vulns-test` — synthetische Report-/State-Objekte: Legacy-`state.json`
  ohne `imageVulns`-Feld parst, Novelty-Regel (erster Lauf / unverändert /
  geänderte H/C-Zahl) und Telegram-🛡-Sektion inkl. 15-Zeilen-Kappung.
- `image-freshness-test` — Image-Tag-Freshness ohne Netzwerk: Variant-
  Token-Matching (`alpine` → `alpine3.24` ja, `pg17` → `pg17-trixie` nein),
  `variantDrift`, `strictlyNewer`-Invariante (semver-gleich = false) und
  „pinned never DOWN into floating“.
- `triage-test` — LLM-Triage mit 2 Fake-Findings (kein Scan, kein Telegram).
- `test-telegram` — 1 Config-Testnachricht (à la Smoke-Test) an den
  konfigurierten Chat.
- TypeScript strict-tsconfig (`strict`, `noUncheckedIndexedAccess`,
  `noFallthroughCasesInSwitch`, `noImplicitOverride`, `NodeNext`/`ES2023`).

**Sicherheitshinweise:**

- Alle Secrets ausschließlich via ENV (Coolify-injectiert) — keine Fallback-
  Secret-Dateien, nichts im Image-Layer, Token **nie** ins Repo committen.
- Telegram-Versand enthält **keine Secrets** — nur Findings, PR-URLs und
  Counters. `GH_TOKEN`/Bot-Token gehen nie in Messages oder Logs.
- `DEEPINFRA_API_KEY` geht nur in den Authorization-Header (niemals loggen).
- **Self-scan Dogfooding**: `SKIP_REPOS` ist default leer — der Scanner scannt
  sein eigenes Repo mit. Das eigene Repo ist exakt gepinnt (package.json,
  `node:26.13.0-alpine3.24`, trivy `0.76.1`) — self-scan muss leer durchlaufen.

## Lizenz

Das Repo ist aktuell **unlicensed/private** (`"private": true` in
package.json, keine LICENSE-Datei). If you fork this repo, add a LICENSE
first to make redistribution licensing explicit.

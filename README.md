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
- Heartbeat + Docker-HEALTHCHECK (frisch getoucht < 26 h)
- Crash-Resilienz (v1.8.1): native V8-Abbrüche (rc 133/134/139) → genau eine
  Wiederholung im Wrapper, solange kein Report geschrieben wurde

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
| `pins` | `cve-audit/pins-<YYYY-MM-DD>` | floating npm-Specifier in `dependencies`/`devDependencies` **oder** Beta-Kanal-Update (`beta → beta`, `beta → stable`) — EIN PR je Repo mit allen Manifests | tägliche Telegram-Erinnerung, State-Eintrag `kind: "pins"` |

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
   `.heartbeat` wird getoucht (HEALTHCHECK akzeptiert Alter < 26 h).
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
   Als Empfehlung stand dort bisher pauschal „Rebuild/Base-Image
   aktualisieren" — seit v1.6.2 ersetzt durch den Digest-Vergleich (Punkt 6).
6. **Digest-Vergleich / beweglicher Tag (v1.6.2)**: je gescanntem Image-Ref
   wird der Manifest-Digest (`Docker-Content-Digest` per HEAD auf
   `/v2/<repo>/manifests/<tag>`; Docker Hub + GHCR mit anonymous Token, MCR
   ohne Auth) geholt und in `reports/digests.json` verglichen
   (`{ "<ref>": { digest, firstSeen, lastSeen, changes[] } }`, 90-Tage-Prune
   für Refs, die nicht mehr im Inventar sind; korruptes JSON → leerer Start).
   Weicht der Digest vom letzten Lauf ab, ist der Tag **beweglich**
   (`digestChanged: true`, `previousDigest` gesetzt). Die Empfehlung im
   Report/Telegram ist entsprechend ehrlich: beweglich → „Tag beweglich,
   Rebuild zieht neuen Digest"; stabil/unbekannt → „Pin auf neueren Tag
   erhöhen (Rebuild hilft nicht)". Die Datei wird nur nach erfolgreichem
   Scan-Lauf geschrieben (wie `state.json`).
7. **Upstream-Release-Check (v1.6.3, `src/release-check.ts`)**: Registry-Tags
   sind **nicht** die Release-Wahrheit. Findet der Freshness-Check keinen
   neueren Registry-Tag (= bisher „aktuell"), wird zusätzlich das neueste
   stabile GitHub-Release des Upstream-Repos abgefragt
   (`GET /repos/<owner>/<repo>/releases?per_page=10`, erster Eintrag ohne
   `prerelease`/`draft`) und per Manifest-HEAD geprüft, ob dieser Release-Tag
   auf der Registry überhaupt publiziert wurde (Manifest 404 → kein Image). Bei
   Bump-Kandidaten entfällt der Check (überflüssig, würde nur API-Calls
   kosten); Fehler brechen den Lauf nie (Feld bleibt `null`, nur Log).
   **Bekannter Fall:** `mcr.microsoft.com/playwright/mcp:v0.0.83` —
   GitHub-Release `microsoft/playwright-mcp` v0.0.84 (31.10.2026) existiert,
   MCR `tags/list` endet bei `v0.0.83`, `manifests/v0.0.84` → 404; das Image
   wurde nie gepusht. Der Report (und die 🐳-Zeile im Telegram-Alert, **ohne**
   eigenen Auslöser) sagt dann
   `ℹ️ Release v0.0.84 existiert, kein Image publiziert` statt „aktuell".
   Das Image→Repo-Mapping ist eine explizite Tabelle `UPSTREAM_REPOS` in
   `src/release-check.ts` (playwright/mcp → microsoft/playwright-mcp,
   aquasec/trivy → aquasecurity/trivy, pgvector/pgvector, searxng/searxng, …);
   Docker-Official-Images (`postgres`, `node`, `python`, `golang`, `alpine`,
   `library/*`) stehen bewusst auf `null` (kein sinnvolles GH-Release). Neue
   Einträge dort nur mit belegtem Upstream-Repo ergänzen. Selbsttest:
   `node dist/index.js release-version-test` (Fake-Releases, kein Netzwerk).

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
   analog CVE-Fix. **Beta-Kanal (seit v1.8.0):** Pakete, die bereits auf
   `-beta`/`-rc` stehen, werden im selben Kanal gebumpt (`beta → beta`) oder
   auf das stabile Release (`beta → stable`); `stable → beta` bleibt verboten.
   Major-Sprünge werden im PR-Body mit `⚠️ major jump`
   markiert und sind bewusst vom Menschen zu akzeptieren.
   **Peer-aware (seit v1.7.2):** deklariert eine andere direkte dep des
   Manifests eine `peerDependencies`-Range für das Paket (Payload verlangt
   `graphql: "^16.8.1"`), wird nicht auf `dist-tags.latest` (17.x) gepinnt,
   sondern auf die höchste Version **innerhalb der Range** (16.14.2); ist keine
   auflösbar, fliegt der Kandidat fail-closed aus dem PR. Grund: der naive
   latest-Pin ließ `npm ci` am 07.11.2026 mit `ERESOLVE` scheitern.
   **Lockfile-Regen fail-closed (seit v1.7.2):** Regen läuft **vor** jedem
   Schreibzugriff und ist mit dem Manifest-PUT alles-oder-nichts. Scheitert er,
   bekommt das betroffene Manifest **keinen** Commit im PR (kein
   `package.json` ohne `package-lock.json`), der PR wird `draft` und trägt
   `⚠️ … NOT applied … Do not merge`. Der Body behauptet
   „Lockfiles regenerated" nur noch, wenn es stimmt. Lockfile-Regen im
   Manifestverzeichnis (`npm install --package-lock-only`-Style, pnpm analog
   via corepack `--lockfile-only`); ohne abdeckendes Lockfile → fail-closed.
   **Commit-Messages ohne `[skip ci]`** (siehe Docker-Abschnitt). Achtung:
   Coolify prüft die **gesamte** Commit-Message (auch den Body) auf den Marker —
   ein Satz wie „kein `[skip ci]`-Marker" im Body überspringt den Deploy
   genauso wie der Marker im Betreff.
5. **Report/Telegram**: Report-Sektion `📌 Unpinned deps (package.json)` je
   Repo (`pkg | current ^1.2.3 | latest exact X.Y.Z | scope | sev | soaking |
   beta-ziel`), Summary `unpinned deps: N` + `pinsPrs`-Zähler, Telegram `📌 Unpinned
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

**Regel 3 — Beta-Kanal nur für Beta-Pakete (seit v1.8.0 mit PR).** Ein
Pre-Release-Kandidat (`-beta`, `-rc`, `-alpha`) wird **ausschließlich dann**
angeboten, wenn das Paket **bereits** auf einem Beta/RC-Kanal liegt. Erlaubt
sind nur zwei Richtungen:

- **beta → beta** — neuestes Beta/RC im **selben** Kanal (`4.0.0-beta.7 →
  4.0.0-beta.9`, `rc → rc`; nie `rc → beta`).
- **beta → stable** — das stabile Release schließt den Kanal ab (`4.0.0-beta.7
  → 4.0.0`). Liegt es über dem neuesten Beta, gewinnt es.

**Nie `stable → beta`:** ein stabil gepinntes Paket (z. B. `payload 3.x`)
bekommt weder Beta-Hinweis noch PR — das wäre Dauerrauschen. Exoten
(Nightly/Canary/Dev/Insiders) sind grundsätzlich kein Auto-Ziel
(`SHOW_EXOTIC_PRERELEASES=1` zeigt sie nur im Report). Beta-Ziele laufen durch
dieselbe 3-Tage-Reife wie alle anderen Updates und landen im normalen
Pins-PR (Commit-Titel/Body kennzeichnen `beta → beta` bzw. `beta → stable`).

Telegram: `ℹ️ Beta/RC-Updates (Paket bereits im Beta-Kanal)` — nur für Kandidaten
mit Soaking-Reife, jeweils mit Ziel und Richtung (`beta → beta` /
`beta → stable`). Das Ziel landet im Pins-PR; zu junge Updates erscheinen im
Alert als `⏳ zu jung (2d) (Report)`, also ohne Handlungsaufforderung.

## 🤖 Renovate als Analyse-Quelle (seit v1.7.0)

Renovate läuft optional als **zweite Meinung** und schließt eine Lücke des
Pinning-Scanners: der findet nur *floating* Specs (`^1.2.3`). Exakt gepinnte
Pakete, für die es eine neuere Version gibt, sieht er per Definition nicht —
Renovate schon.

**Arbeitsteilung (bewusst so):**

| | Renovate | Scanner |
|---|---|---|
| Updates finden | ✅ `--dry-run=lookup` | ✅ floating Specs |
| Soaking (3 Tage) | ✅ `minimumReleaseAge` aus `UPDATE_MIN_AGE_DAYS` | ✅ eigene Logik |
| PR anlegen | ❌ **nie** (`prCreation: never`) | ✅ **allein** |
| Bündelung | — | ✅ ein PR je Repo/Tag |

Es gibt also **einen** PR-Kanal (`cve-audit/pins-<datum>`), keine parallelen
Renovate-Branches. Major-/Breaking-Updates erscheinen nur im Report (`Src:
rnv (major)`) und werden **nie** automatisch gebumpt.

**Installation:** Renovate liegt als separat gepinnte CLI im Image
(`RUN npm i -g renovate@44.222.1 && ln -sf …/dist/renovate.js /usr/local/bin/renovate`),
**nicht** in unserer `package.json` — das Paket ist AGPL-3.0-only und zieht ~124
transitive Dependencies mit, was unsere eigene Pins-Policy ad absurdum führen
würde. Die Stage bringt zusätzlich `git` mit (`--platform=local` arbeitet auf
einem echten Checkout; reines `lookup` ohne Branch-Erzeugung).

Image-Kosten (geschätzt, **keine** Messung): `npm i -g` im Runner legt
`/usr/local/lib/node_modules/renovate` + Deps ab — Renovate nennt sich selbst
mit 15,4 MB entpackt, npm zieht rund 400 MB `node_modules` (u. a. `re2`
inclusive Build 99 MB, `@aws-sdk` 54 MB) abzüglich der Build-Artefakte von
`re2`; netto realistisch **+250 bis +450 MB** auf einem Runner, der heute bei
~300 MB liegt (also grob 2×). Der Bin wird per Symlink nach `/usr/local/bin`
gelegt; `NODE_PATH` ist nicht nötig, weil `dist/renovate.js` seine Deps relativ
zum globalen `node_modules` auflöst. Läuft laut `engines` (`^24.11.0 ||
^26.13.0`) auf der Node-26-Basis.

**Ausgabe-Parsing:** `--log-format=json` gibt es in 44.222.1 nicht; die
JSONL-Ausgabe kommt über Env `LOG_FORMAT=json` + `LOG_LEVEL=debug`. Die
Update-Daten liegen im Log-Objekt `msg: "packageFiles with updates"` unter
`config` (Map manager → `packageFiles[]`), nicht unter `packageFiles`.
`minimumReleaseAge` wird aus `UPDATE_MIN_AGE_DAYS` abgeleitet — eine Regelquelle.
Timeout je Repo 120 s (`RENOVATE_TIMEOUT_MS`); Fehler/Timeout → stiller Fallback
auf den Pinning-Scanner, nie ein Abbruch des Laufs. Einschalten mit
`ENABLE_RENOVATE=1`.

**Lockfile-Pflicht (fail-closed):** Ein PR, der `package.json` ändert, aber das
Lockfile unangetastet lässt, bricht `npm ci`. Deshalb ermittelt
`findCoveringLockfile()` das abdeckende Lockfile — eigenes Verzeichnis oder,
bei Monorepos mit `workspaces`, das Workspace-Root. Findet sich keines oder
schlägt der Regen fehl, wird der Kandidat **gar nicht erst committet** (seit
v1.7.2: Regen vor jedem Schreibzugriff, alles-oder-nichts) statt einen
kaputten PR zu öffnen; der PR wird Draft + `⚠️ NOT applied`. Renovate-Ziele
laufen durch dasselbe Peer-Gate wie floating Pins.

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
| `ENABLE_RENOVATE` | nein | `0` | `1` = Renovate-CLI als **Analyse-Quelle** mitlaufen lassen. Renovate legt **nie** eigene PRs an; seine Vorschläge landen gebündelt im `cve-audit/pins-<datum>`-PR. |
| `RENOVATE_BIN` | nein | `renovate` | Pfad zum Renovate-Binary (im Image global installiert, exakt gepinnt). |
| `RENOVATE_TIMEOUT_MS` | nein | `120000` | Timeout je Repo für den Renovate-Lauf (`--dry-run=lookup`). Timeout/Exit≠0 ⇒ Repo ohne Renovate-Vorschläge, Pinning-Scan läuft weiter. |
| `NODE_OPTIONS` | nein | `--report-on-signal --report-signal=SIGSEGV --report-on-fatalerror --report-directory=/app/logs` | **Crash-Diagnose** (v1.7.7, erweitert v1.8.1): Node schreibt bei SIGSEGV (und seit v1.8.1 auch bei V8-Fatal/OOM) einen Diagnose-Report nach `/app/logs/report.<datum>.<pid>.<seq>.json` (header.event, JS-Heap, native Frames, Env, libuv-Handles). Nur `--report-on-signal` ohne `--report-signal` installiert **keinen** Handler — der Report bleibt dann aus. Leer setzen (`NODE_OPTIONS=`) schaltet die Diagnose ab. |

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
node dist/index.js pinning-test  # Pins-PR-Qualität (Fakes, kein Netz)
node dist/index.js renovate-test # Renovate-Parser + Lockfile-Abdeckung (Fakes)
```

Achtung: `scan` ist ein echter Lauf (Trivy-Downloads, API-Calls, bei
`ENABLE_FIX_PRS=1` echte PRs). Zum Testen ohne Nebenwirkungen nur `inventory`,
`triage-test`, `notify-failure-test` oder `state-test` nutzen.

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

**Fehlschlag-Alarm:** Endet der Scan mit rc ≠ 0, ruft der Wrapper
`node /app/dist/index.js notify-failure --rc <rc> --log /app/logs/scan.log` auf
→ Telegram `⚠️ CVE-Audit FEHLGESCHLAGEN <datum>` mit rc, UTC-Zeitpunkt,
Host/Container und den letzten 15 Log-Zeilen (gekürzt + Token-redigiert).
Ohne `TELEGRAM_*`-ENV wird still übersprungen; ein Sende-Fehler ändert den
Exit-Code des Wrappers **nicht**.

**Versand-Retry (v1.7.6, Vorfall 14.11.2026):** Ein einzelner transienter
`fetch failed` hatte den Alarm komplett verschluckt (ein Versuch, kein Retry,
Merker trotzdem gesetzt). Jetzt: `sendMessageOnce` wird bis zu **3×** versucht
(1 s/3 s/7 s Pause) bei Netz-Fehlern und 5xx; 4xx (Token, Chat-ID, Payload)
bricht sofort ab. `notify-failure` signalisiert einen gescheiterten Versand per
Exit-Code 1 → der Wrapper setzt den Merker erst **nach** Erfolg und der
`EXIT`-trap wiederholt den Versand einmal.

Der Heartbeat wird nur im Erfolgsfall getoucht — blieb der Lauf lang genug aus,
flippt der HEALTHCHECK nach 26 h auf `unhealthy` (Coolify meldet den
Status-Wechsel per Telegram). Rendering-Test offline: `npm run notify-failure-test`;
Trockenlauf ohne Versand: `NOTIFY_FAILURE_DRY_RUN=1 node dist/index.js
notify-failure --rc 1 --log /tmp/x.log`.

**Abbruch-Absicherung (v1.7.5):** Bis v1.7.4 meldete nur der `else`-Zweig einen
Fehlschlag. Starb der Wrapper selbst — OOM-Kill, SIGTERM beim Deploy-Rollover,
SIGKILL nach Timeout — wurde er nie erreicht, der Ausfall blieb still. Jetzt
liegt ein `trap` auf `EXIT HUP INT TERM` im Wrapper: endet er ohne
quittierenden rc-Pfad, geht ein Alarm mit `--reason "… abgebrochen …"` raus
(andere Formulierung als der normale Fehlschlag, weil hier nicht feststeht, ob
überhaupt ein Report geschrieben wurde). Doppelmeldungen verhindert das
Merker-File `logs/.failure-alarm-sent`, das zu Beginn jedes Laufs gelöscht und
von Erfolg **oder** erfolgreich versendetem Fehlschlag-Alarm gesetzt wird
(seit v1.7.6 erst nach dem Versand — ein gescheiterter Versand lässt den
`EXIT`-trap einmal wiederholen).

**Crash-Resilienz (v1.8.1, Vorfälle 14.11./18.11.2026):** Zweimal starb der
Scanner-Prozess **nativ** — `rc=139` (SIGSEGV) bzw. `rc=133` (SIGTRAP,
`Check failed: page_->ContainsLimit(object_address + current_size_)` in einem
V8-Worker-Thread). Beides sind V8-Heap-/GC-Interna, kein JS-Fehler. Am selben
Host crashten im selben Zeitraum auch fremde Prozesse (php/libcrypto mit
General-Protection-Fault, ein weiterer `MainThread` mit Reserved-Bit-Pagefault)
— das Muster spricht für Host-/RAM-Instabilität, nicht für Scanner-Code. Der
Wrapper reagiert darauf:

- rc `133`/`134`/`139` **und** Heartbeat unverändert (Lauf starb vor dem
  Report) → genau **eine** Wiederholung (`RETRY_DELAY_SECONDS`, Default 5 s).
  Idempotent, weil Fix-/Pins-/Image-PRs über den Branch-Namen dedupliziert
  werden (`cve-audit/*-<datum>` → `findOpenPr` → `status 'exists'`).
- Heartbeat schon frisch getoucht (Crash **nach** dem Report) → **keine**
  Wiederholung, sonst gäbe es ein Doppel-Telegram.
- Scheitert auch die Wiederholung, geht der Alarm mit `--reason`
  („nativer V8-Abbruch …“) raus.
- `NODE_OPTIONS` enthält zusätzlich `--report-on-fatalerror` (V8-Fatal/OOM
  läuft nicht über den Signal-Handler; der SIGTRAP-Vorfall hinterliess deshalb
  keinen Diagnose-Report).
- Jeder Lauf loggt `Speicher: RSS-Peak ≈ … MB` (plus Warnung ab 1 GB) — die
  Zeile zeigt beim nächsten Crash, ob Speicherdruck im Spiel war.

**Crash-Rest-Aufräumen (v1.8.1):** Stirbt der Lauf zwischen `createRef` und
`createPr`, bleibt ein `cve-audit/*-<datum>`-Branch **ohne PR** zurück (genau
das passierte am 18.11.2026 in 4 Repos). Beim nächsten Lauf wäre `changed`
false — die Pins stehen ja schon auf dem Branch — und der PR entstünde nie.
Pins-, Fix- und Image-PR-Pfad löschen einen solchen Branch deshalb und setzen
ihn frisch vom aktuellen Base-Head auf; die Pins werden deterministisch neu
angewendet. Ein `deleteRef`-Fehler (≠ 404) meldet den PR als `failed`, statt
still zu überspringen.

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
  `.heartbeat` älter als 26 h (`test $(( $(date +%s) - $(stat -c %Y .heartbeat) )) -lt 93600`).
  Seit v1.7.6 bewusst 26 h statt 48 h: ein einzelner verpasster Nachtlauf
  dreht den Container am Folgetag auf `unhealthy` (Coolify-Status-Wechsel →
  Telegram), statt erst nach zwei Tagen.
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
- **Kein `[skip ci]` in eigenen PR-Commits (seit v1.7.2)**: Commits, die über
  die eigenen Fix-/Pins-/Image-PRs landen, tragen **keinen** Skip-Marker.
  Coolify überspringt bei `[skip ci]`/`[skip cd]` den Auto-Deploy **still** und
  antwortet dem GitHub-Webhook trotzdem `200 OK` — 5 Apps hatten am 07.11.2026
  deshalb keinen Deploy-Record bei komplett grünen Webhooks. Ein Deploy eines
  reinen Pin-Bumps ist unschädlich (kein Verhaltens-Change); Blockieren ist
  schlimmer. Die Rekursionsgefahr (Scanner scannt Scanner) fällt ins Leere, weil
  das Repo derzeit selbst exakt gepinnt ist (self-scan leer).

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
| v1.6.3 | Upstream-Release-Check (Registry-Tags ≠ Release-Wahrheit) |
| v1.7.0 | Renovate als Analyse-Quelle; Lockfile-Regen fail-closed |
| v1.7.1 | Registry-Tag-Präfix beim Release-Check (trivy `v0.76.2` vs `0.76.2`) |
| v1.7.2 | Deploybare Pins-PRs: kein `[skip ci]`, peer-aware Pins, Lockfile alles-oder-nichts + Draft-Warnung, Quay im Release-Check, `pinning-test` |
| v1.7.4 | Fehlschlag-Alarm per Telegram (`notify-failure`) + Tages-Quittung |
| v1.7.5 | `trap`-Absicherung: auch stummer Abbruch (Signal/OOM/Timeout) meldet |
| v1.7.6 | Telegram-Retry (3×, 1 s/3 s/7 s) + Alarm-Merker erst nach Erfolg; HEALTHCHECK 26 h statt 48 h |
| v1.7.7 | Crash-Diagnose: `NODE_OPTIONS=--report-on-signal --report-signal=SIGSEGV` → Diagnose-Report in `/app/logs` |
| v1.8.0 | Beta-Kanal-PRs: Pakete bereits im Beta/RC-Kanal werden im Pins-PR gebumpt (`beta → beta` / `beta → stable`), nie `stable → beta`; Soaking gilt auch für Beta-Ziele |
| v1.8.1 | Crash-Resilienz: Wrapper wiederholt native V8-Abbrüche (rc 133/134/139) genau einmal, solange kein Report geschrieben wurde; `--report-on-fatalerror`; RSS-Peak im Log; Alarm-Hinweis 26 h statt 48 h; Branch-ohne-PR-Crash-Rest wird neu aufgesetzt (Pins/Fix/Image) |

## Tests & Sicherheit

**Tests / Selbsttests:**

- `state-test` — simuliertes State + PR-Status-Check gegen
  `mayraost/audit-scanner` mit nicht existierendem Fake-Branch (keine echten
  PRs, kein Telegram-Versand).
- `soaking-test` — Soaking-Gates + Pre-Release-Klassifikation mit fixer Fake-Uhr.
- `digest-test` — Digest-Cache ohne Netzwerk (Fake-Datei in tmp): korruptes
  `digests.json` → leerer Start, erster Lauf setzt `firstSeen`, gleicher Digest
  → stabil, geänderter Digest → `digestChanged` + `previousDigest`,
  90-Tage-Prune, Empfehlungstexte + Telegram-Zeilenlänge.
- `pinning-test` (v1.7.2/v1.8.0) — Pins-PR-Qualität **offline** (Fake-Registry,
  Fake-GitHub-contents, Fake-Lockfile-Regen): Peer-Konflikt → Ausweichversion
  bzw. fail-closed kein Pin, Regen-Fehler → **kein** Manifest-Commit im PR
  (Draft + `⚠️ NOT applied`), Lockfile-Commit vor Manifest-Commit, keine
  `[skip ci]`-Marker, Image-Tag-Präfix-Flip für Docker Hub/MCR/Quay,
  „kein Image" nur bei belastbarer Probe, Beta-Kanal-Ziele
  (`beta → beta`, `beta → stable`, kein `stable → beta`, Soaking) sowie
  (v1.8.1) `R1` Crash-Rest: Branch ohne offenen PR wird gelöscht, neu
  aufgesetzt und der PR entsteht trotzdem.
- `renovate-test` (v1.7.0) — Renovate-Analyse **offline**: eingebettetes
  JSONL-Fixture in der echten Log-Form (`msg: "packageFiles with updates"`,
  Update-Daten unter `config`) prüft Parser (nur deps mit `updates[]`, höchste
  `newVersion` je dep, `releaseTimestamp`/`ageDays`), kaputten/leeren Output
  (`ok:false` ohne Crash), Major-Guard (`major`/`isBreaking` nie im PR) und die
  Lockfile-Abdeckung: Root-Manifest → `package-lock.json` mit-committet,
  Monorepo-Nested-Manifest → Workspace-Root-Lockfile, kein abdeckendes
  Lockfile → Kandidat fail-closed ausgeschlossen (Draft + `⚠️ NOT applied`),
  Renovate- und Pinning-Kandidat landen im **selben** PR.
- `image-vulns-test` — synthetische Report-/State-Objekte: Legacy-`state.json`
  ohne `imageVulns`-Feld parst, Novelty-Regel (erster Lauf / unverändert /
  geänderte H/C-Zahl) und Telegram-🛡-Sektion inkl. 15-Zeilen-Kappung.
- `image-freshness-test` — Image-Tag-Freshness ohne Netzwerk: Variant-
  Token-Matching (`alpine` → `alpine3.24` ja, `pg17` → `pg17-trixie` nein),
  `variantDrift`, `strictlyNewer`-Invariante (semver-gleich = false) und
  „pinned never DOWN into floating“.
- `triage-test` — LLM-Triage mit 2 Fake-Findings (kein Scan, kein Telegram).
- `wrapper-test` (`sh test/scan-wrapper-test.sh`, Fake-`node`) — Wrapper-Pfade
  ohne echten Scan: Erfolg/Fehlschlag, Alarm genau einmal, Retry-Verhalten bei
  `notify-failure`-Fehlern, SIGTERM-Abbruch mit `--reason`, alter Merker und
  (v1.8.1) native V8-Crashes: rc 133 → genau eine Wiederholung, 133+139 →
  Alarm mit Grund, Crash **nach** dem Report → keine Wiederholung.
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

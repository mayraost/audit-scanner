# audit-scanner

Nightly CVE-Audit aller Repos im GitHub-Account `mayraost`: Die Repos werden als
Tarball geladen, mit [Trivy](https://github.com/aquasecurity/trivy) (fs-scan,
Offline-DB) gescannt, die Treffer gegen die
[GitHub-Advisories-DB](https://github.com/advisories) gematcht und das Ergebnis
an Telegram gemeldet. Optional legt der Scanner automatisch Fix-PRs an (Version-
Bump nur in `package.json` + Lockfile-Regenerations-Hinweis).

Der Scanner läuft als Docker-Compose-App (Coolify) mit internem Busybox-cron —
keine Ports, keine Domain, reiner Batch-Job.

## Was er tut

1. **Inventar**: Alle Repos von `mayraost` via GitHub-API (inkl. private), je
   Repo Manifest-Erkennung (`package.json`, `requirements.txt`, `go.mod`, …).
2. **Scan**: Repo-Tarball laden → `trivy fs` mit gepinnter Offline-DB (DB bleibt
   im Volume-Cache, nur 1× Download / inkrementelle Updates).
3. **Match**: Trivy-Findings gegen GH-Advisories matchen (semver-basiert), nur
   HIGH/CRITICAL zählen fürs Report-„Findings“.
4. **Report**: Telegram-Nachricht (plain text, optional MarkdownV2) mit
   Zusammenfassung + Image-/Cache-Status. Ohne Telegram-Config wird der Versand
   still übersprungen (Scan läuft trotzdem).
5. **Fix-PRs** (opt-in, `ENABLE_FIX_PRS=1`): pro Repo ein Branch
   `cve-audit/fix-<runid>`, Version-Bump betroffener Deps in `package.json`
   (PUT `/contents` mit korrektem Blob-SHA), PR gegen den Default-Branch.
   Bereits offene PRs desselben Branches werden erkannt statt dupliziert.
6. **Heartbeat**: Nach jedem Scan-Lauf wird `/app/reports/.heartbeat`
   getoucht — Docker-HEALTHCHECK akzeptiert Alter < 48 h (Cron-Skip-Toleranz).

## Setup

### 1. GitHub-Token (GH_TOKEN)

Fine-grained PAT oder Classic-PAT erstellen: https://github.com/settings/tokens

**Classic-PAT:** Scope `repo` reicht (lesend fürs Scannen; zusätzlich schreibend
für Fix-PRs — Contents, Refs/Branches, Pull Requests, alles `repo`-gedeckt).

**Fine-grained PAT (empfohlen):** Repository access → alle Repos von
`mayraost`; Permissions: `Contents` (read + write), `Metadata` (read, Pflicht),
`Pull requests` (read + write, nur wenn `ENABLE_FIX_PRS=1`). Die globalen
Advisories-Endpoints brauchen keine Spezial-Permission.

Wichtig: Der Token darf **nie ins Repo/Compose** — er kommt nur als
Umgebungsvariable in Coolify (bzw. lokal in eine nicht-committete `.env`).

### 2. Telegram-Bot (TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID)

1. Bot anlegen via [@BotFather](https://t.me/BotFather) → Token notieren.
2. Eigene Chat-ID ermitteln: dem Bot eine Nachricht schicken, dann
   `https://api.telegram.org/bot<TOKEN>/getUpdates` aufrufen →
   `result[].message.chat.id`.
3. Beide Werte als Coolify-ENV setzen. Test: „test-telegram“ (unten).

### 3. Env-Variablen (Coolify-App-Environment oder lokale `.env`)

| Variable             | Pflicht | Default       | Bedeutung |
| -------------------- | ------- | ------------- | ------- |
| `GH_TOKEN`           | ja      | —             | GitHub-PAT (siehe oben). Container: Pflicht; lokal existiert als Dev-Fallback `gh auth token` der authed gh-CLI. |
| `TELEGRAM_BOT_TOKEN` | nein    | —             | Ohne = kein Telegram-Versand (Scan läuft trotzdem). |
| `TELEGRAM_CHAT_ID`   | nein    | —             | Ziel-Chat (User-ID oder Group-ID). |
| `ENABLE_FIX_PRS`     | nein    | `0`           | `1`/`true` = Auto-Fix-PRs anlegen. |
| `SKIP_REPOS`         | nein    | —             | Kommagetrennte Repo-Namen, z. B. `archive,playground`. |
| `CRON_SCHEDULE`      | nein    | `0 16 * * *`  | Cron in Container-Zeit (TZ=Europe/Berlin → 16:00 Ortszeit). |

Zusätzlich pro Repo deaktivierbar: Datei `.cve-audit-skip` im Repo-Root
(wird im Inventar erkannt, Repo erscheint als `skip(repo-file)`).

## Coolify-Deployment

Coolify → neues Projekt/App vom Typ **Docker Compose** mit Build auf Basis
dieses Repos:

- **Build**: `docker-compose.yml` aus dem Repo; Build-Context = Repo-Root
  (Compose `build:`-Sektion, Multi-Stage-Dockerfile, ~5 min erster Build).
- **Keine Ports / keine Domain / kein networks-Block** — reiner Cron-Job,
  alles Volumes (`audit-reports`, `audit-cache`, `audit-logs`).
- **Env-Variablen**: Tabelle oben — secrets NUR über die Coolify-App-Environment
  (nicht in der Compose-Datei committen; Compose referenziert nur `${VAR}`).
  Alternativ per API: `POST/PATCH /api/v1/applications/{uuid}/envs`.
- **Nach dem Deploy Prüfstream**:
  `get_infrastructure_overview` → Status `running:healthy` (Heartbeat-Check);
  danach „test-telegram“ in Container ausführen:
  `docker exec audit-scanner node dist/index.js test-telegram`.
- **TZ**: Image setzt `TZ=Europe/Berlin` (tzdata enthalten) — Cron-Schedule
  `0 16 * * *` = 16:00 Ortszeit (15:00 bzw. 14:00 UTC je DST).

## Lokal ausführen (ohne Docker)

Voraussetzung: Node ≥ 24, `gh` CLI authed (`gh auth status`) ODER `GH_TOKEN`
gesetzt.

```sh
npm ci
npm run build          # tsc → dist/
node dist/index.js inventory      # Inventarlisting (Repos + Ökosysteme)
node dist/index.js scan           # voller Durchlauf (Scan + Telegram + Fix-PRs)
node dist/index.js test-telegram  # 1 Config-Testnachricht an Telegram
```

Achtung: `scan` ist ein echter Lauf (Trivy-Downloads, API-Calls, bei
`ENABLE_FIX_PRS=1` echte PRs). Zum Testen ohne Nebenwirkungen nur `inventory`
nutzen.

## Sicherheit

- Alle Secrets ausschließlich via ENV (Coolify-injectiert); keine Fallback-
  Secret-Dateien, nichts im Image-Layer.
- Fix-PRs sind opt-in (`ENABLE_FIX_PRS`), fehlen nur Versionsinfo + Hinweis auf
  Lockfile-Regeneration in PR-Description.
- Scanner mutiert Scanner-eigene Repos nie direkt auf Default-Branch — nur via
  PR-Branch.

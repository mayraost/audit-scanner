// Telegram-Notify (Spec §6): sendMessage via Bot-API.
// - Lim 4096/Messagelimit → chunked split('\n\n') bei 4000, 300ms Pause (429-Mitigierung)
// - Retry (v1.7.6): 3 Versuche mit 1s/3s/7s Pause bei Netz-/5xx-Fehlern
//   (4xx = Konfig, kein Retry) — Vorfall 14.11.2026: ein "fetch failed" hat
//   den Fehlschlag-Alarm verschluckt.
// - Default plain text (Spec-Empfehlung: MarkdownV2-Escaping fehleranfällig);
//   MarkdownV2 optional via TELEGRAM_PARSE_MODE=MarkdownV2 inkl. korrekter Escapes.
// - Secrets (GH_TOKEN, Tokens, any payload content) gehen NIE in die Message.
// - Fehlende TELEGRAM_* ENV → Skip mit Log (kein Fail des Scan-Runs).

import {
  TELEGRAM_BOT_TOKEN,
  TELEGRAM_CHAT_ID,
  TELEGRAM_PARSE_MODE,
  log,
  telegramConfigured,
} from './config.js';

function chunk(text: string, size = 4000): string[] {
  const parts: string[] = [];
  let cur = '';
  for (const para of text.split('\n\n')) {
    if (cur && (cur + para).length > size) {
      parts.push(cur);
      cur = '';
    }
    cur += (cur ? '\n\n' : '') + para;
  }
  if (cur) parts.push(cur);
  return parts;
}

/** MarkdownV2-Sonderzeichen laut Bot-API-Doku (alles standesgemäß escapen). */
function escapeMarkdownV2(text: string): string {
  return text.replace(/([_*[\]()~`>#+\-=|{}.!\\])/g, '\\$1');
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** Eine Message auf Telegram. Wirft bei harten Fehlern (misconfiguration). */
async function sendMessageOnce(text: string): Promise<void> {
  const payload: Record<string, unknown> = {
    chat_id: TELEGRAM_CHAT_ID,
    text,
  };
  if (TELEGRAM_PARSE_MODE === 'MarkdownV2') {
    payload.parse_mode = 'MarkdownV2';
  }
  const res = await fetch(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (res.status === 429) {
    const retry = Number(res.headers.get('retry_after') ?? 2);
    await sleep(Math.min(retry * 1000, 10_000));
    const r2 = await fetch(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!r2.ok) throw new Error(`Telegram sendMessage (retry) ${r2.status}: ${await r2.text()}`);
    return;
  }
  if (!res.ok) {
    throw new Error(`Telegram sendMessage ${res.status}: ${(await res.text()).slice(0, 300)}`);
  }
}

/**
 * Netz-/Server-Fehler sind voruebergehend (Vorfall 14.11.2026: ein einzelner
 * "fetch failed" beim Fehlschlag-Alarm hat die Meldung verloren). Deshalb:
 * bis zu drei Versuche mit wachsender Pause. 4xx (Token, Chat-ID, Payload)
 * wird nicht wiederholt — das ist Konfig, kein Zufall.
 */
const PAUSEN_MS = [1000, 3000, 7000];

function istVoruebergehend(err: unknown): boolean {
  const m = err instanceof Error ? err.message : String(err);
  if (/fetch failed|ENOTFOUND|EAI_AGAIN|ECONNRESET|ETIMEDOUT|EPIPE|UND_EPIPE_CLOSED/i.test(m)) {
    return true;
  }
  const status = Number(/Telegram sendMessage (\d{3})/.exec(m)?.[1] ?? 0);
  return status >= 500;
}

async function sendMitWiederholung(text: string): Promise<void> {
  for (let versuch = 0; ; versuch++) {
    try {
      return await sendMessageOnce(text);
    } catch (err) {
      const m = err instanceof Error ? err.message : String(err);
      const pause = PAUSEN_MS[versuch];
      if (!istVoruebergehend(err) || pause === undefined) throw err;
      log(
        `WARN: Telegram-Versand Versuch ${versuch + 1} fehlgeschlagen (${m}) — Wiederholung in ${pause} ms.`
      );
      await sleep(pause);
    }
  }
}

/**
 * Text senden (chunked + geringe Rate). Wenn ENV fehlt: ein Log + OK (scan läuft weiter).
 */
export async function sendTelegramReport(title: string, body: string): Promise<boolean> {
  if (!telegramConfigured()) {
    log(
      'TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID nicht gesetzt — Telegram-Notify wird übersprungen.'
    );
    return false;
  }
  const full = `${title}\n\n${body}`;
  const pieces = chunk(full);
  for (let i = 0; i < pieces.length; i++) {
    const piece = pieces[i] as string;
    const msg = TELEGRAM_PARSE_MODE === 'MarkdownV2' ? escapeMarkdownV2(piece) : piece;
    try {
      await sendMitWiederholung(msg);
    } catch (err) {
      const m = err instanceof Error ? err.message : String(err);
      log(`WARN: Telegram-Senden (chunk ${i + 1}/${pieces.length}) fehlgeschlagen: ${m}`);
      if (i === 0) return false; // nach 3 Versuchen immer noch kaputt → nichts weiter spammen
      // spätere Chunks: weitermachen, Fehler sind transient sequenziell — aber nicht crashen
      continue;
    }
    if (i + 1 < pieces.length) await sleep(300);
  }
  log(`Telegram: ${pieces.length} Nachricht(en) gesendet.`);
  return true;
}

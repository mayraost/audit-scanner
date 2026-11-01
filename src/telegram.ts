// Telegram-Notify (Spec §6): sendMessage via Bot-API.
// - Lim 4096/Messagelimit → chunked split('\n\n') bei 4000, 300ms Pause (429-Mitigierung)
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
      await sendMessageOnce(msg);
    } catch (err) {
      const m = err instanceof Error ? err.message : String(err);
      log(`WARN: Telegram-Senden (chunk ${i + 1}/${pieces.length}) fehlgeschlagen: ${m}`);
      if (i === 0) return false; // kaputte Bot-Config → nichts weiter spammen
      // spätere Chunks: weitermachen, Fehler sind transient sequenziell — aber nicht crashen
      continue;
    }
    if (i + 1 < pieces.length) await sleep(300);
  }
  log(`Telegram: ${pieces.length} Nachricht(en) gesendet.`);
  return true;
}

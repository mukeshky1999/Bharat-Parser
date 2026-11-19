/** Small readers for the case summary. A missing value is reported as null so the screen can say "not recorded". */

/** The backend reports a dossier field as a list, a plain string, or a "Not Found" marker. Returns text to show, or null when nothing was found. */
export function dossierText(v: unknown): string | null {
  if (Array.isArray(v)) {
    const parts = v.map((x) => String(x ?? '').trim()).filter(Boolean);
    return parts.length ? parts.join(', ') : null;
  }
  if (typeof v === 'string') {
    const t = v.trim();
    return !t || /^(not found|none|n\/a)\b/i.test(t) ? null : t;
  }
  return null;
}

/** A device field as text, or null when it is empty or a placeholder. */
export function recorded(v: unknown): string | null {
  if (v === null || v === undefined) return null;
  const t = String(v).trim();
  return !t || /^(n\/a|not recorded|unknown|none)$/i.test(t) ? null : t;
}

export function sizeText(bytes: unknown): string | null {
  const n = Number(bytes);
  if (!Number.isFinite(n) || n <= 0) return null;
  const mb = n / (1024 * 1024);
  const shown = mb >= 1024 ? `${(mb / 1024).toFixed(2)} GB` : `${mb.toFixed(2)} MB`;
  return `${shown} (${n.toLocaleString()} bytes)`;
}

export interface AppActivity { app: string; n: number }

/**
 * Records per app as the profile compiler wrote them, "WhatsApp (12 txns, 40 msgs)". A row of Per_App_Breakdown that
 * carries its own count is used as it is. Apps with no count recorded are left out, not guessed.
 */
export function appActivity(dossier: any): AppActivity[] {
  const out = new Map<string, number>();
  const rows: any[] = Array.isArray(dossier?.Per_App_Breakdown) ? dossier.Per_App_Breakdown
    : Array.isArray(dossier?.Per_App_Breakdown_DF) ? dossier.Per_App_Breakdown_DF : [];
  for (const r of rows) {
    const c = Number(r?.Records ?? r?.Record_Count ?? r?.Count);
    const name = recorded(r?.App_Name ?? r?.Application);
    if (name && Number.isFinite(c) && c > 0) out.set(name, (out.get(name) ?? 0) + c);
  }
  if (out.size === 0) {
    const text = dossierText(dossier?.Active_Financial_Apps) ?? '';
    for (const m of text.matchAll(/([^,()]+?)\s*\((\d+) txns, (\d+) msgs\)/g)) {
      const n = Number(m[2]) + Number(m[3]);
      if (n > 0) out.set(m[1].trim(), n);
    }
  }
  return [...out.entries()].map(([app, n]) => ({ app, n })).sort((a, b) => b.n - a.n).slice(0, 6);
}

export interface Contacted { who: string; calls: number; messages: number }

/** The other party of each loaded call and chat message, counted. Only what is loaded in this session. */
export function mostContacted(
  calls: Array<{ direction?: string; callerNumberOrId?: string; calleeNumberOrId?: string; peerNumberOrId?: string; callerName?: string; calleeName?: string }>,
  chats: Array<{ isFromMe: boolean; senderJid?: string; senderName?: string; recipientJid?: string; recipientName?: string }>,
): Contacted[] {
  const m = new Map<string, Contacted>();
  const bump = (who: string | undefined, kind: 'calls' | 'messages') => {
    const k = (who ?? '').trim();
    if (!k) return;
    const e = m.get(k) ?? { who: k, calls: 0, messages: 0 };
    e[kind] += 1;
    m.set(k, e);
  };
  for (const c of calls) {
    const out = c.direction === 'OUTGOING';
    bump(c.peerNumberOrId || (out ? c.calleeName || c.calleeNumberOrId : c.callerName || c.callerNumberOrId), 'calls');
  }
  for (const c of chats) {
    bump(c.isFromMe ? c.recipientName || c.recipientJid : c.senderName || c.senderJid, 'messages');
  }
  return [...m.values()].sort((a, b) => (b.calls + b.messages) - (a.calls + a.messages)).slice(0, 5);
}

export interface DayCount { day: string; n: number }

/** Records per day (in the chosen time zone, IST = UTC+05:30, or UTC) over the span that has records, newest 60 days at most. Records with no recorded time are left out. */
export function perDay(epochs: number[], offsetMs = 0): DayCount[] {
  const valid = epochs.filter((e) => Number.isFinite(e) && e > 0);
  if (!valid.length) return [];
  const DAY = 86_400_000;
  const dayOf = (e: number) => Math.floor((e + offsetMs) / DAY);
  const counts = new Map<number, number>();
  for (const e of valid) counts.set(dayOf(e), (counts.get(dayOf(e)) ?? 0) + 1);
  const keys = [...counts.keys()];
  const last = Math.max(...keys);
  const first = Math.max(Math.min(...keys), last - 59);
  const out: DayCount[] = [];
  for (let d = first; d <= last; d++) out.push({ day: new Date(d * DAY).toISOString().slice(0, 10), n: counts.get(d) ?? 0 });
  return out;
}

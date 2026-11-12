/**
 * Readings of a run of bytes, for the hex view's data interpreter.
 *
 * A reading says what the bytes WOULD be if read that way. It does not say they are that. A time is shown only when
 * it falls between 2000 and 2100, and is labelled as a reading: any four or eight bytes can look like a time.
 */
export interface Reading {
  label: string;
  /** how many bytes this reading uses, so the grid can mark them */
  bytes: number;
  value: string;
  /** true for a reading that is a point in time */
  isTime?: boolean;
}

const MIN_MS = Date.UTC(2000, 0, 1);
const MAX_MS = Date.UTC(2100, 0, 1);

function iso(ms: number): string | null {
  if (!Number.isFinite(ms) || ms < MIN_MS || ms >= MAX_MS) return null;
  return new Date(ms).toISOString().replace('.000Z', 'Z');
}

function printable(b: Uint8Array): string {
  let out = '';
  for (const x of b) out += x >= 0x20 && x < 0x7f ? String.fromCharCode(x) : '.';
  return out;
}

export function interpret(bytes: Uint8Array): Reading[] {
  const out: Reading[] = [];
  const n = bytes.length;
  if (n === 0) return out;
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const add = (label: string, len: number, f: () => string | null, isTime = false) => {
    if (n < len) return;
    const v = f();
    if (v !== null) out.push({ label, bytes: len, value: v, isTime });
  };

  add('Unsigned 8-bit', 1, () => String(dv.getUint8(0)));
  add('Signed 8-bit', 1, () => String(dv.getInt8(0)));
  add('Unsigned 16-bit, little-endian', 2, () => String(dv.getUint16(0, true)));
  add('Unsigned 16-bit, big-endian', 2, () => String(dv.getUint16(0, false)));
  add('Signed 16-bit, little-endian', 2, () => String(dv.getInt16(0, true)));
  add('Unsigned 32-bit, little-endian', 4, () => String(dv.getUint32(0, true)));
  add('Unsigned 32-bit, big-endian', 4, () => String(dv.getUint32(0, false)));
  add('Signed 32-bit, little-endian', 4, () => String(dv.getInt32(0, true)));
  add('Unsigned 64-bit, little-endian', 8, () => dv.getBigUint64(0, true).toString());
  add('Unsigned 64-bit, big-endian', 8, () => dv.getBigUint64(0, false).toString());
  add('Float 32-bit, little-endian', 4, () => { const f = dv.getFloat32(0, true); return Number.isFinite(f) ? String(f) : null; });
  add('Float 64-bit, little-endian', 8, () => { const f = dv.getFloat64(0, true); return Number.isFinite(f) ? String(f) : null; });

  // readings as a point in time (only when the result is a plausible date)
  add('As Unix seconds (32-bit, little-endian)', 4, () => { const s = iso(dv.getUint32(0, true) * 1000); return s && `${s} UTC`; }, true);
  add('As Unix seconds (32-bit, big-endian)', 4, () => { const s = iso(dv.getUint32(0, false) * 1000); return s && `${s} UTC`; }, true);
  add('As Unix milliseconds (64-bit, little-endian)', 8, () => { const s = iso(Number(dv.getBigUint64(0, true))); return s && `${s} UTC`; }, true);
  add('As Cocoa seconds (64-bit float)', 8, () => { const s = iso(Date.UTC(2001, 0, 1) + dv.getFloat64(0, true) * 1000); return s && `${s} UTC`; }, true);
  add('As Cocoa seconds (32-bit, little-endian)', 4, () => { const s = iso(Date.UTC(2001, 0, 1) + dv.getUint32(0, true) * 1000); return s && `${s} UTC`; }, true);
  add('As WebKit microseconds since 1601 (64-bit)', 8, () => {
    const us = dv.getBigUint64(0, true);
    const s = iso(Number(us / 1000n) - 11644473600000);
    return s && `${s} UTC`;
  }, true);
  add('As Windows FILETIME (64-bit)', 8, () => {
    const t = dv.getBigUint64(0, true);
    const s = iso(Number(t / 10000n) - 11644473600000);
    return s && `${s} UTC`;
  }, true);

  // text
  const take = Math.min(n, 32);
  out.push({ label: `ASCII (first ${take} bytes, non-printable shown as .)`, bytes: take, value: printable(bytes.subarray(0, take)) });
  if (n >= 2) {
    const k = Math.min(n - (n % 2), 32);
    let s = '';
    for (let i = 0; i < k; i += 2) { const c = dv.getUint16(i, true); s += c >= 0x20 && c < 0xd800 ? String.fromCharCode(c) : '.'; }
    out.push({ label: `UTF-16, little-endian (first ${k / 2} characters)`, bytes: k, value: s });
  }
  return out;
}

/** Parses "0x1f4", "1F4" or "500" into an offset, or null when it is not one. */
export function parseOffset(text: string): number | null {
  const t = text.trim();
  if (!t) return null;
  if (/^0x[0-9a-f]+$/i.test(t)) return parseInt(t, 16);
  if (/^[0-9]+$/.test(t)) return parseInt(t, 10);
  if (/^[0-9a-f]+$/i.test(t)) return parseInt(t, 16);
  return null;
}

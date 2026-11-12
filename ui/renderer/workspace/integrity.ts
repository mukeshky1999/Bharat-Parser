/** The integrity line states only what the backend recorded. It never says "verified" on its own. */
export function integrityText(
  integrity: { preSha256: string; postSha256: string; match: boolean | null } | null
): { text: string; tone: 'ok' | 'bad' | 'none'; detail: string } {
  if (!integrity) return { text: 'Integrity: nothing recorded', tone: 'none', detail: 'No source hash has been recorded for this case.' };
  if (integrity.match === true) {
    return { text: 'Source hash recorded · re-hash MATCH', tone: 'ok', detail: `SHA-256 before and after processing: ${integrity.preSha256}` };
  }
  if (integrity.match === false) {
    return { text: 'Re-hash MISMATCH: source changed', tone: 'bad', detail: `Before: ${integrity.preSha256}\nAfter: ${integrity.postSha256}` };
  }
  return { text: 'Source hash recorded · re-hash NOT RECORDED', tone: 'none', detail: `SHA-256 before processing: ${integrity.preSha256}` };
}

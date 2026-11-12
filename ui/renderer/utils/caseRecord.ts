/**
 * Which row of the case store a selected item is, when that can be told from the id the store gave it.
 * Rows are given ids that end in the case-store row number: "<message or transaction id>#<row>", "TX_<row>",
 * "CNT_<row>" and "CALL_<row>". Anything else is not tagged from the card (it is not a row of the case).
 */
export interface CaseRecordRef { table: string; id: number }

export function caseRecordOf(artifactId: string | undefined, itemType?: string): CaseRecordRef | null {
  if (!artifactId) return null;
  const row = (s: string): number | null => (/^\d+$/.test(s) && Number(s) > 0 ? Number(s) : null);
  const prefixed: Array<[RegExp, string]> = [[/^TX_(\d+)$/, 'transactions'], [/^CNT_(\d+)$/, 'contacts'], [/^CALL_(\d+)$/, 'calls']];
  for (const [re, table] of prefixed) {
    const m = re.exec(artifactId);
    if (m) { const n = row(m[1]); return n ? { table, id: n } : null; }
  }
  const m = /#(\d+)$/.exec(artifactId);
  if (m) {
    const n = row(m[1]);
    if (!n) return null;
    if (itemType === 'CHAT_MESSAGE') return { table: 'chats', id: n };
    if (itemType === 'Financial Transaction') return { table: 'transactions', id: n };
  }
  return null;
}

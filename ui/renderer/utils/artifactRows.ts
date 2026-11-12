import { forensicClient } from '../api/forensicClient';

/** Every row of one kind of record in the open case, fetched page by page (never stops at a fixed number). */
export async function fetchAllRows(category: string, signal: AbortSignal): Promise<Array<Record<string, any>>> {
  const out: Array<Record<string, any>> = [];
  const PAGE = 500;
  for (let offset = 0; offset < 1_000_000; offset += PAGE) {
    const res: any = await forensicClient.queryArtifacts(category, undefined, undefined, undefined, undefined, PAGE, offset, undefined, false, signal);
    const rows: Array<Record<string, any>> = Array.isArray(res?.rows) ? res.rows : [];
    out.push(...rows);
    if (rows.length < PAGE) break;
  }
  return out;
}

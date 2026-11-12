import React, { useEffect, useState } from 'react';
import { forensicClient, TagSummary } from '../api/forensicClient';
import type { RecordRef } from './TagControls';

const btn = 'h-8 px-3 rounded border border-slate-700 text-slate-200 hover:bg-slate-800 text-xs disabled:opacity-40';

/**
 * Tag (or untag) many records at once. You choose the records and the tag; the tool applies nothing by itself.
 * The count of records that really changed is reported back, including records that already had the tag and
 * records that could not be found.
 */
export const BulkTagBar: React.FC<{
  picked: RecordRef[];
  pageRecords: RecordRef[];
  onPick: (records: RecordRef[], on: boolean) => void;
  onDone: () => void;
}> = ({ picked, pageRecords, onPick, onDone }) => {
  const [known, setKnown] = useState<TagSummary[]>([]);
  const [tag, setTag] = useState('of_interest');
  const [custom, setCustom] = useState('');
  const [msg, setMsg] = useState('');
  const [busy, setBusy] = useState(false);

  useEffect(() => { void forensicClient.getTags().then((r) => setKnown(r.data?.tags ?? [])); }, []);

  const chosen = (custom.trim() || tag).trim();
  const run = async (apply: boolean) => {
    setBusy(true); setMsg('');
    const res = apply ? await forensicClient.tagRecords(chosen, picked) : await forensicClient.untagRecords(chosen, picked);
    setBusy(false);
    if (res.error || !res.data) { setMsg(res.error ?? 'Not done.'); return; }
    const d = res.data as { applied?: number; already_tagged?: number; missing?: unknown[]; removed?: number };
    setMsg(apply
      ? `${d.applied ?? 0} tagged “${chosen}”, ${d.already_tagged ?? 0} already had it${d.missing?.length ? `, ${d.missing.length} not found` : ''}.`
      : `${d.removed ?? 0} had “${chosen}” removed.`);
    onDone();
  };

  const allOnPage = pageRecords.length > 0 && pageRecords.every((r) => picked.some((p) => p.table === r.table && p.id === r.id));

  return (
    <div className="flex flex-wrap items-center gap-2 mb-2 rounded border border-slate-800 bg-slate-900 p-2" aria-label="Tag many records">
      <label className="text-xs text-slate-300 inline-flex items-center gap-1">
        <input type="checkbox" checked={allOnPage} onChange={(e) => onPick(pageRecords, e.target.checked)} />Select this page
      </label>
      <span className="text-xs text-slate-400">{picked.length} selected</span>
      <select aria-label="Tag to apply" className="h-8 rounded bg-slate-950 border border-slate-700 px-2 text-slate-100 text-xs" value={tag} onChange={(e) => setTag(e.target.value)}>
        {known.filter((t) => t.builtin).map((t) => <option key={t.tag} value={t.tag}>{t.tag}</option>)}
      </select>
      <input aria-label="Or your own tag" placeholder="or your own tag" maxLength={40} value={custom} onChange={(e) => setCustom(e.target.value)}
        className="h-8 w-36 rounded bg-slate-950 border border-slate-700 px-2 text-slate-100 text-xs placeholder-slate-500" />
      <button className={btn} disabled={busy || picked.length === 0 || !chosen} onClick={() => void run(true)}>Tag selected</button>
      <button className={btn} disabled={busy || picked.length === 0 || !chosen} onClick={() => void run(false)}>Remove tag from selected</button>
      {picked.length > 0 && <button className={btn} onClick={() => onPick(picked, false)}>Clear selection</button>}
      {msg && <span className="text-xs text-slate-300" aria-live="polite">{msg}</span>}
    </div>
  );
};

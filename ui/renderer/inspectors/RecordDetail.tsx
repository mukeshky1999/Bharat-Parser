import React, { useCallback, useEffect, useState } from 'react';
import { Tag, X } from 'lucide-react';
import { forensicClient, TagSummary } from '../api/forensicClient';
import { shownValue } from '../utils/recordText';

/**
 * One stored record exactly as the case holds it, with its tags.
 * A value that was not recorded is shown as "not recorded", never as a blank or a default.
 * Tags are the examiner's decisions: nothing here applies one by itself.
 */
export interface RecordRef { table: string; id: number }

const btn = 'h-7 px-2 rounded border border-slate-700 text-slate-200 hover:bg-slate-800 text-xs disabled:opacity-40';

export const TagPills: React.FC<{ tags: string[] }> = ({ tags }) => (
  <>
    {tags.map((t) => (
      <span key={t} className="inline-flex items-center gap-1 rounded-full border border-cyan-700 bg-cyan-950/50 px-2 py-0.5 text-[0.6875rem] text-cyan-200">
        <Tag className="w-3 h-3" aria-hidden="true" />{t}
      </span>
    ))}
  </>
);

interface Props {
  record: RecordRef | null;
  onClose?: () => void;
  /** Called after a tag was applied or removed, so a list behind this panel can refresh. */
  onTagsChanged?: () => void;
}

export const RecordDetail: React.FC<Props> = ({ record, onClose, onTagsChanged }) => {
  const [data, setData] = useState<Record<string, unknown> | null>(null);
  const [tags, setTags] = useState<string[]>([]);
  const [known, setKnown] = useState<TagSummary[]>([]);
  const [custom, setCustom] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    if (!record) { setData(null); setTags([]); return; }
    const res = await forensicClient.getRecord(record.table, record.id);
    setError(res.error ?? '');
    setData(res.data);
    setTags(res.tags);
  }, [record]);

  useEffect(() => { void load(); }, [load]);
  useEffect(() => { void forensicClient.getTags().then((r) => setKnown(r.data?.tags ?? [])); }, [record]);

  if (!record) return null;

  const toggle = async (tag: string, on: boolean) => {
    setBusy(true); setError('');
    const res = on
      ? await forensicClient.tagRecords(tag, [record])
      : await forensicClient.untagRecords(tag, [record]);
    setBusy(false);
    if (res.error) { setError(res.error); return; }
    await load();
    onTagsChanged?.();
  };

  const names = known.filter((t) => t.builtin).map((t) => t.tag);
  const extra = tags.filter((t) => !names.includes(t));

  return (
    <aside className="w-96 shrink-0 border-l border-slate-800 bg-slate-900 overflow-y-auto p-3 text-xs text-slate-200 select-text" aria-label="Record detail">
      <div className="flex items-start justify-between gap-2 mb-2">
        <h2 className="font-semibold text-slate-50">{record.table} #{record.id}</h2>
        {onClose && <button className="p-1 rounded text-slate-400 hover:bg-slate-800" aria-label="Close record" onClick={onClose}><X className="w-4 h-4" /></button>}
      </div>
      {error && <p className="text-rose-300 mb-2">{error}</p>}
      <div className="mb-3">
        <p className="text-slate-400 mb-1">Tags (your decisions; the tool applies none)</p>
        <div className="flex flex-wrap gap-1 mb-2">
          {tags.length === 0 ? <span className="text-slate-500">none</span> : <TagPills tags={tags} />}
        </div>
        <div className="flex flex-wrap gap-1">
          {[...names, ...extra].map((t) => {
            const on = tags.includes(t);
            return (
              <button key={t} disabled={busy} aria-pressed={on} onClick={() => void toggle(t, !on)}
                className={`${btn} ${on ? 'bg-cyan-900 border-cyan-600' : ''}`}>{on ? `Remove ${t}` : `Tag ${t}`}</button>
            );
          })}
        </div>
        <form className="flex gap-1 mt-2" onSubmit={(e) => { e.preventDefault(); if (custom.trim()) { void toggle(custom.trim(), true); setCustom(''); } }}>
          <input aria-label="Your own tag" value={custom} onChange={(e) => setCustom(e.target.value)} placeholder="Your own tag"
            className="h-7 flex-1 rounded bg-slate-950 border border-slate-700 px-2 text-slate-100 placeholder-slate-500" maxLength={40} />
          <button type="submit" className={btn} disabled={busy || !custom.trim()}>Add</button>
        </form>
      </div>
      <table className="w-full table-fixed border-collapse">
        <tbody>
          {data && Object.entries(data).map(([k, v]) => (
            <tr key={k} className="border-t border-slate-800 align-top">
              <th className="text-left font-normal text-slate-400 pr-2 py-1 w-36 break-words">{k}</th>
              <td className={`py-1 break-all ${v === null || v === undefined || v === '' ? 'text-slate-500' : 'text-slate-100'}`}>{shownValue(v)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </aside>
  );
};

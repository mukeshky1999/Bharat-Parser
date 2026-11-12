import React, { useCallback, useEffect, useState } from 'react';
import { Tag } from 'lucide-react';
import { forensicClient, TagSummary } from '../api/forensicClient';
import { useUi } from '../state/uiStore';
import { useLatestRequest } from '../utils/latestRequest';

export interface RecordRef { table: string; id: number }

const btn = 'h-7 px-2 rounded border border-slate-700 text-slate-200 hover:bg-slate-800 text-xs disabled:opacity-40';

export const TagPills: React.FC<{ tags: string[] }> = ({ tags }) => (
  <>
    {tags.map((t) => (
      <span key={t} className="inline-flex items-center gap-1 rounded-full border border-cyan-700 bg-cyan-950/50 px-2 py-0.5 text-[0.75rem] text-cyan-200">
        <Tag className="w-3 h-3" aria-hidden="true" />{t}
      </span>
    ))}
  </>
);

/**
 * The tags on one record and the buttons to apply or remove them. Tags are the examiner's decisions: nothing here
 * applies one by itself. `onLoaded` hands the record's fields to a caller that also wants them.
 */
export const TagControls: React.FC<{
  record: RecordRef;
  onChanged?: () => void;
  onLoaded?: (data: Record<string, unknown> | null, error: string) => void;
}> = ({ record, onChanged, onLoaded }) => {
  const [tags, setTags] = useState<string[]>([]);
  const [known, setKnown] = useState<TagSummary[]>([]);
  const [custom, setCustom] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const bumpTags = useUi((s) => s.bumpTags);

  const latest = useLatestRequest();
  const load = useCallback(async () => {
    const { isCurrent } = latest.begin();             // a reply for a record that is no longer open is dropped
    const res = await forensicClient.getRecord(record.table, record.id);
    if (!isCurrent()) return;
    setError(res.error ?? '');
    setTags(res.tags);
    onLoaded?.(res.data, res.error ?? '');
  }, [record.table, record.id, latest]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => { void load(); }, [load]);
  useEffect(() => {
    let alive = true;
    void forensicClient.getTags().then((r) => { if (alive) setKnown(r.data?.tags ?? []); });
    return () => { alive = false; };
  }, [record.table, record.id]);

  const toggle = async (tag: string, on: boolean) => {
    setBusy(true); setError('');
    const res = on ? await forensicClient.tagRecords(tag, [record]) : await forensicClient.untagRecords(tag, [record]);
    setBusy(false);
    if (res.error) { setError(res.error); return; }
    await load();
    bumpTags();
    onChanged?.();
  };

  const names = known.filter((t) => t.builtin).map((t) => t.tag);
  const extra = tags.filter((t) => !names.includes(t));

  return (
    <div className="text-xs text-slate-200">
      {error && <p className="text-rose-300 mb-2">{error}</p>}
      <p className="text-slate-400 mb-1">Tags (your decisions; the tool applies none)</p>
      <div className="flex flex-wrap gap-1 mb-2">{tags.length === 0 ? <span className="text-slate-500">none</span> : <TagPills tags={tags} />}</div>
      <div className="flex flex-wrap gap-1">
        {[...names, ...extra].map((t) => {
          const on = tags.includes(t);
          return (
            <button key={t} disabled={busy} aria-pressed={on} onClick={() => void toggle(t, !on)} className={`${btn} ${on ? 'bg-cyan-900 border-cyan-600' : ''}`}>
              {on ? `Remove ${t}` : `Tag ${t}`}
            </button>
          );
        })}
      </div>
      <form className="flex gap-1 mt-2" onSubmit={(e) => { e.preventDefault(); if (custom.trim()) { void toggle(custom.trim(), true); setCustom(''); } }}>
        <input aria-label="Your own tag" value={custom} onChange={(e) => setCustom(e.target.value)} placeholder="Your own tag"
          className="h-7 flex-1 rounded bg-slate-950 border border-slate-700 px-2 text-slate-100 placeholder-slate-500" maxLength={40} />
        <button type="submit" className={btn} disabled={busy || !custom.trim()}>Add</button>
      </form>
    </div>
  );
};

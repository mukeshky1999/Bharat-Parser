import React, { useCallback, useEffect, useState } from 'react';
import { forensicClient, TimelineEvent, TimelineGroup, TimelineResult } from '../api/forensicClient';
import { usePreferences } from '../state/preferencesStore';
import { RecordDetail, RecordRef, TagPills } from '../inspectors/RecordDetail';

const GROUPS: Array<{ id: TimelineGroup; label: string; help: string }> = [
  { id: 'fixed', label: 'Placed in time', help: 'The source gave a zone or an absolute time, so the instant is known. Listed in time order. A device clock that was wrong is not corrected.' },
  { id: 'clock_only', label: 'Local clock only', help: 'The source gave a clock reading with no zone. The reading is shown as written; these are not placed in time and not mixed in with the others.' },
  { id: 'no_time', label: 'No time recorded', help: 'The record has no time at all. Listed in the order they were stored.' },
];

const PAGE = 100;
const field = 'h-8 rounded bg-slate-950 border border-slate-700 px-2 text-slate-100 placeholder-slate-500';

function whenText(e: TimelineEvent, tz: 'IST' | 'UTC'): string {
  if (e.utc) return tz === 'IST' && e.ist ? e.ist : `${e.utc} UTC`;
  if (e.local_clock) return `${e.local_clock} (local clock, zone not recorded)`;
  return 'time not recorded';
}

/** Every record that has a time, from every table and device, in one list. Records without a fixed instant are counted apart. */
export const TimelineView: React.FC = () => {
  const tz = usePreferences((s) => s.timeZone);
  const [group, setGroup] = useState<TimelineGroup>('fixed');
  const [from, setFrom] = useState('');
  const [to, setTo] = useState('');
  const [app, setApp] = useState('');
  const [tag, setTag] = useState('');
  const [descending, setDescending] = useState(false);
  const [offset, setOffset] = useState(0);
  const [data, setData] = useState<TimelineResult | null>(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [open, setOpen] = useState<RecordRef | null>(null);

  const load = useCallback(async (off: number) => {
    setBusy(true); setError('');
    const res = await forensicClient.getTimeline({
      group, from: from || undefined, to: to || undefined, application: app.trim() || undefined, tag: tag.trim() || undefined,
      limit: PAGE, offset: off, descending, bucket: group === 'fixed' ? 'day' : undefined,
    });
    setBusy(false);
    if (res.error) { setError(res.error); setData(null); return; }
    setData(res.data);
  }, [group, from, to, app, tag, descending]);

  useEffect(() => { setOffset(0); void load(0); }, [load]);

  const max = Math.max(1, ...(data?.buckets?.items.map((b) => b.count) ?? [1]));
  const help = GROUPS.find((g) => g.id === group)?.help;

  return (
    <div className="flex-1 flex min-w-0 min-h-0">
      <div className="flex-1 overflow-y-auto p-4 select-text min-w-0">
        <div role="tablist" aria-label="Kind of time" className="flex flex-wrap gap-2 mb-2">
          {GROUPS.map((g) => (
            <button key={g.id} role="tab" aria-selected={group === g.id} onClick={() => setGroup(g.id)}
              className={`h-8 px-3 rounded border ${group === g.id ? 'border-cyan-600 bg-slate-800 text-slate-50' : 'border-slate-700 text-slate-300 hover:bg-slate-800'}`}>
              {g.label}{data ? ` (${data.counts[g.id]})` : ''}
            </button>
          ))}
        </div>
        <p className="text-slate-400 text-xs mb-3">{help}</p>
        <div className="flex flex-wrap items-center gap-2 mb-3">
          <label className="text-xs text-slate-400">From <input type="date" aria-label="From date" value={from} onChange={(e) => setFrom(e.target.value)} className={field} /></label>
          <label className="text-xs text-slate-400">To <input type="date" aria-label="To date" value={to} onChange={(e) => setTo(e.target.value)} className={field} /></label>
          <input aria-label="Only this app" value={app} onChange={(e) => setApp(e.target.value)} placeholder="App (optional)" className={`${field} w-32`} />
          <input aria-label="Only records with this tag" value={tag} onChange={(e) => setTag(e.target.value)} placeholder="Tag (optional)" className={`${field} w-32`} />
          {group === 'fixed' && (
            <label className="text-xs text-slate-300 inline-flex items-center gap-1"><input type="checkbox" checked={descending} onChange={(e) => setDescending(e.target.checked)} />Newest first</label>
          )}
        </div>
        {error && <p className="text-rose-300 mb-2">{error}</p>}
        {data && (
          <>
            {data.buckets && data.buckets.items.length > 0 && (
              <figure className="mb-3" aria-label="Records per day">
                <div className="flex items-end gap-px h-16 overflow-x-auto">
                  {data.buckets.items.map((b) => (
                    <div key={b.start} title={`${b.start}: ${b.count}`} className="w-2 shrink-0 bg-cyan-600" style={{ height: `${Math.max(4, (b.count / max) * 100)}%` }} />
                  ))}
                </div>
                <figcaption className="text-[0.6875rem] text-slate-500">
                  Records per day, {data.buckets.items[0].start} to {data.buckets.items[data.buckets.items.length - 1].start}
                  {data.buckets.truncated ? ' (only part of the range is shown)' : ''}. Hover a bar for its count.
                </figcaption>
              </figure>
            )}
            <p className="text-slate-200 mb-1" aria-live="polite">{data.total} record{data.total === 1 ? '' : 's'} in this group.</p>
            <ul className="space-y-1">
              {data.events.map((e) => (
                <li key={`${e.tbl}-${e.id}`}>
                  <button onClick={() => setOpen({ table: e.tbl, id: e.id })}
                    className={`w-full text-left rounded border p-2 hover:bg-slate-800 ${open?.table === e.tbl && open.id === e.id ? 'border-cyan-600 bg-slate-800' : 'border-slate-800 bg-slate-900'}`}>
                    <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-[0.75rem] text-slate-400">
                      <span className="text-slate-100 font-mono">{whenText(e, tz)}</span>
                      <span>{e.kind}</span>
                      <span>{e.application || 'app not recorded'}</span>
                      {e.evidence_item && <span>{e.evidence_item}</span>}
                      {e.tags && e.tags.length > 0 && <TagPills tags={e.tags} />}
                    </div>
                    <div className="text-slate-100 break-words">{e.summary || 'no text recorded'}</div>
                  </button>
                </li>
              ))}
            </ul>
            <div className="flex items-center gap-2 mt-3">
              <button className="h-8 px-3 rounded border border-slate-700 text-slate-200 hover:bg-slate-800 disabled:opacity-40" disabled={busy || offset === 0}
                onClick={() => { const o = Math.max(0, offset - PAGE); setOffset(o); void load(o); }}>Previous</button>
              <span className="text-slate-400 text-xs">{data.events.length ? `${offset + 1}–${offset + data.events.length}` : 'none'}</span>
              <button className="h-8 px-3 rounded border border-slate-700 text-slate-200 hover:bg-slate-800 disabled:opacity-40" disabled={busy || offset + PAGE >= data.total}
                onClick={() => { const o = offset + PAGE; setOffset(o); void load(o); }}>Next</button>
            </div>
          </>
        )}
      </div>
      <RecordDetail record={open} onClose={() => setOpen(null)} onTagsChanged={() => void load(offset)} />
    </div>
  );
};

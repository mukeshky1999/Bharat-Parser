import React, { useMemo, useRef, useState } from 'react';
import { ChevronLeft, ChevronRight, Download, Search } from 'lucide-react';
import { useWorkbenchStore } from '../state/workbenchStore';
import { usePreferences } from '../state/preferencesStore';
import { csvCell, downloadCsv } from '../utils/csv';
import { useTagIndex } from './useTagIndex';
import { TagPills } from '../inspectors/TagControls';
import { caseRecordOf } from '../utils/caseRecord';
import type { ForensicProvenance, TimestampTriplet } from '../../shared/forensic-types';

export interface RecordTableProps {
  title: string;
  category: 'CONTACTS' | 'CALLS';
}

interface Column {
  key: string;
  label: string;
  width: string;
  align?: 'right';
}

interface Row {
  id: string;
  cells: Record<string, string>;
  timestamp?: TimestampTriplet;
  provenance: ForensicProvenance;
  recovered: boolean;
  raw: unknown;
}

const NOT_RECORDED = 'not recorded';
const PAGE_SIZE = 100;

const RECOVERY_TEXT: Record<string, string> = {
  ACTIVE: 'In database',
  WAL_RECOVERED: 'Recovered from log',
  CARVED_UNALLOCATED: 'Carved from free space',
  OS_SPILLOVER: 'System trace',
};

const COLUMNS: Record<RecordTableProps['category'], Column[]> = {
  CONTACTS: [
    { key: 'name', label: 'Name', width: 'minmax(10rem,1.4fr)' },
    { key: 'identifier', label: 'Number or ID', width: 'minmax(10rem,1.2fr)' },
    { key: 'app', label: 'App', width: '7rem' },
    { key: 'status', label: 'Status or bio', width: 'minmax(8rem,1.6fr)' },
    { key: 'recovery', label: 'Source state', width: '10rem' },
  ],
  CALLS: [
    { key: 'time', label: 'Time', width: '12.5rem' },
    { key: 'direction', label: 'Direction', width: '6.5rem' },
    { key: 'from', label: 'From', width: 'minmax(9rem,1fr)' },
    { key: 'to', label: 'To', width: 'minmax(9rem,1fr)' },
    { key: 'duration', label: 'Duration', width: '6rem', align: 'right' },
    { key: 'result', label: 'Result', width: '8rem' },
    { key: 'app', label: 'App', width: '6.5rem' },
    { key: 'recovery', label: 'Source state', width: '10rem' },
  ],
};

const DIRECTION_TEXT: Record<string, string> = { INCOMING: 'Incoming', OUTGOING: 'Outgoing', MISSED: 'Missed', REJECTED: 'Rejected', UNKNOWN: 'Unknown' };

function hasTime(t?: TimestampTriplet): t is TimestampTriplet {
  return !!t && !!t.utcIso && t.epochMs > 0;
}

/** One bar per day (or per month when the data spans more than 90 days): counts of records that have a recorded time. */
function activityBuckets(rows: Row[]): { label: string; n: number }[] {
  const times = rows.filter((r) => hasTime(r.timestamp)).map((r) => r.timestamp!.epochMs);
  if (times.length === 0) return [];
  const span = (Math.max(...times) - Math.min(...times)) / 86_400_000;
  const monthly = span > 90;
  const map = new Map<string, number>();
  for (const t of times) {
    const iso = new Date(t).toISOString();
    const key = monthly ? iso.slice(0, 7) : iso.slice(0, 10);
    map.set(key, (map.get(key) ?? 0) + 1);
  }
  return [...map.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([label, n]) => ({ label, n }));
}

export const RecordTable: React.FC<RecordTableProps> = ({ title, category }) => {
  const contacts = useWorkbenchStore((s) => s.contacts);
  const callLogs = useWorkbenchStore((s) => s.callLogs);
  const setSelectedArtifact = useWorkbenchStore((s) => s.setSelectedArtifact);
  const tz = usePreferences((s) => s.timeZone);
  const [query, setQuery] = useState('');
  const [onlyRecovered, setOnlyRecovered] = useState(false);
  const [page, setPage] = useState(1);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const bodyRef = useRef<HTMLDivElement | null>(null);
  const tagIndex = useTagIndex(category === 'CONTACTS' ? 'contacts' : 'calls');
  const tagsOfRow = (id: string): string[] => { const n = caseRecordOf(id)?.id; return n ? tagIndex[n] ?? [] : []; };
  const allCols = [...COLUMNS[category], { key: 'tags', label: 'Tags', width: '11rem' } as Column];
  const hiddenCols = usePreferences((s) => s.hiddenColumns[category]) ?? [];
  const setPrefs = usePreferences((s) => s.set);
  const allHidden = usePreferences((s) => s.hiddenColumns);
  const cols = allCols.filter((c) => !hiddenCols.includes(c.key));

  const fmtTime = (t?: TimestampTriplet) => (hasTime(t) ? (tz === 'IST' ? t.istFormatted : t.utcIso) : NOT_RECORDED);

  const rows: Row[] = useMemo(() => {
    if (category === 'CONTACTS') {
      return contacts.map((c) => ({
        id: c.id,
        cells: {
          name: c.displayName || NOT_RECORDED,
          identifier: c.identifier || NOT_RECORDED,
          app: c.sourceApp || NOT_RECORDED,
          status: c.bioOrStatus || '',
          recovery: RECOVERY_TEXT[c.provenance?.recoveryState] ?? NOT_RECORDED,
        },
        provenance: c.provenance,
        recovered: !!c.provenance && c.provenance.recoveryState !== 'ACTIVE',
        raw: c,
      }));
    }
    return callLogs.map((c) => ({
      id: c.id,
      cells: {
        direction: DIRECTION_TEXT[c.direction] ?? 'Unknown',
        from: c.callerName ? `${c.callerName} (${c.callerNumberOrId})` : c.callerNumberOrId || NOT_RECORDED,
        to: c.calleeName ? `${c.calleeName} (${c.calleeNumberOrId})` : c.calleeNumberOrId || NOT_RECORDED,
        duration: Number.isFinite(c.durationSeconds) && c.durationSeconds >= 0 ? `${c.durationSeconds}s` : NOT_RECORDED,
        result: c.callResult || NOT_RECORDED,
        app: c.sourceApp || NOT_RECORDED,
        recovery: RECOVERY_TEXT[c.provenance?.recoveryState] ?? NOT_RECORDED,
      },
      timestamp: c.timestamp,
      provenance: c.provenance,
      recovered: !!c.provenance && c.provenance.recoveryState !== 'ACTIVE',
      raw: c,
    }));
  }, [category, contacts, callLogs]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return rows.filter((r) => {
      if (onlyRecovered && !r.recovered) return false;
      if (!q) return true;
      return Object.values(r.cells).some((v) => v.toLowerCase().includes(q));
    });
  }, [rows, query, onlyRecovered]);

  const pages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const safePage = Math.min(page, pages);
  const visible = filtered.slice((safePage - 1) * PAGE_SIZE, safePage * PAGE_SIZE);
  const buckets = useMemo(() => (category === 'CALLS' ? activityBuckets(filtered) : []), [category, filtered]);
  const peak = Math.max(1, ...buckets.map((b) => b.n));
  const untimed = category === 'CALLS' ? filtered.filter((r) => !hasTime(r.timestamp)).length : 0;
  const template = `3.5rem ${cols.map((c) => c.width).join(' ')}`;

  const select = (r: Row) => {
    setSelectedId(r.id);
    void setSelectedArtifact({
      id: r.id,
      provenance: r.provenance,
      timestamp: r.timestamp,
      itemType: category === 'CONTACTS' ? 'Contact' : 'Call record',
      rawData: r.raw,
    });
  };

  const onKey = (e: React.KeyboardEvent) => {
    if (visible.length === 0) return;
    const cur = visible.findIndex((r) => r.id === selectedId);
    let next = cur;
    if (e.key === 'ArrowDown' || e.key === 'j') next = Math.min(visible.length - 1, cur + 1);
    else if (e.key === 'ArrowUp' || e.key === 'k') next = Math.max(0, cur < 0 ? 0 : cur - 1);
    else return;
    e.preventDefault();
    select(visible[next]);
    bodyRef.current?.querySelector<HTMLElement>(`[data-row-id="${CSS.escape(visible[next].id)}"]`)?.scrollIntoView({ block: 'nearest' });
  };

  const exportCsv = () =>
    downloadCsv(`${category.toLowerCase()}.csv`, [
      [...(category === 'CALLS' ? ['Time'] : []), ...allCols.filter((c) => c.key !== 'time').map((c) => c.label)].map(csvCell).join(','),
      ...filtered.map((r) =>
        [...(category === 'CALLS' ? [fmtTime(r.timestamp)] : []), ...allCols.filter((c) => c.key !== 'time').map((c) => (c.key === 'tags' ? tagsOfRow(r.id).join('; ') : r.cells[c.key] ?? ''))].map(csvCell).join(',')
      ),
    ]);

  return (
    <div className="flex-1 flex flex-col min-w-0 min-h-0 bg-slate-950 select-text">
      <div className="shrink-0 flex flex-wrap items-center gap-3 px-4 py-3 border-b border-slate-800">
        <h2 className="text-slate-50 font-semibold mr-2">{title}</h2>
        <label className="relative">
          <span className="sr-only">Filter {title}</span>
          <Search className="w-4 h-4 text-slate-400 absolute left-2.5 top-2" aria-hidden="true" />
          <input value={query} onChange={(e) => { setQuery(e.target.value); setPage(1); }} placeholder="Filter" className="h-8 w-64 pl-8 pr-2 rounded bg-slate-900 border border-slate-700 text-slate-100 placeholder-slate-500" />
        </label>
        <label className="flex items-center gap-2 text-slate-300">
          <input type="checkbox" checked={onlyRecovered} onChange={(e) => { setOnlyRecovered(e.target.checked); setPage(1); }} />
          Only recovered records
        </label>
        <span className="text-slate-400">{filtered.length.toLocaleString()} of {rows.length.toLocaleString()}</span>
        <details className="relative">
          <summary className="h-8 px-3 rounded border border-slate-700 text-slate-200 hover:bg-slate-800 cursor-pointer inline-flex items-center list-none">Columns</summary>
          <div className="absolute z-20 mt-1 w-56 rounded border border-slate-700 bg-slate-900 p-2 shadow-xl">
            {allCols.map((c) => (
              <label key={c.key} className="flex items-center gap-2 py-0.5 text-slate-200">
                <input type="checkbox" checked={!hiddenCols.includes(c.key)} disabled={!hiddenCols.includes(c.key) && cols.length === 1}
                  onChange={(e) => setPrefs({ hiddenColumns: { ...allHidden, [category]: e.target.checked ? hiddenCols.filter((k) => k !== c.key) : [...hiddenCols, c.key] } })} />
                {c.label}
              </label>
            ))}
            <p className="mt-1 text-[0.6875rem] text-slate-400">Hiding a column only changes what is shown. Export keeps every column.</p>
          </div>
        </details>
        <button onClick={exportCsv} disabled={filtered.length === 0} className="ml-auto flex items-center gap-2 h-8 px-3 rounded border border-slate-700 text-slate-200 hover:bg-slate-800 disabled:opacity-40">
          <Download className="w-4 h-4" /> Export CSV
        </button>
      </div>

      {buckets.length > 0 && (
        <figure className="shrink-0 px-4 pt-3 pb-2 border-b border-slate-800" aria-label="Number of calls over time">
          <div className="flex items-end gap-px h-14">
            {buckets.slice(-120).map((b) => (
              <div key={b.label} className="flex-1 min-w-[3px] bg-cyan-500/70 rounded-t-sm" style={{ height: `${Math.max(6, (b.n / peak) * 100)}%` }} title={`${b.label}: ${b.n}`} />
            ))}
          </div>
          <figcaption className="mt-1 flex justify-between text-slate-400 text-[0.75rem]">
            <span>{buckets[0].label}</span>
            <span>Calls per {buckets[0].label.length === 7 ? 'month' : 'day'}{untimed ? ` · ${untimed.toLocaleString()} without a recorded time are not shown` : ''}</span>
            <span>{buckets[buckets.length - 1].label}</span>
          </figcaption>
        </figure>
      )}

      <div ref={bodyRef} tabIndex={0} onKeyDown={onKey} className="flex-1 overflow-auto min-h-0 outline-none" role="grid" aria-label={title} aria-rowcount={filtered.length}>
        <div className="min-w-max">
          <div role="row" className="sticky top-0 z-10 grid items-center gap-x-3 px-3 h-8 bg-slate-900 border-b border-slate-700 text-slate-300 font-medium" style={{ gridTemplateColumns: template }}>
            <span role="columnheader" className="text-right">#</span>
            {cols.map((c) => <span key={c.key} role="columnheader" className={c.align === 'right' ? 'text-right' : ''}>{c.label}</span>)}
          </div>
          {visible.length === 0 ? (
            <div className="p-10 text-center text-slate-400">{rows.length === 0 ? 'No records of this kind were found in the evidence.' : 'No record matches this filter.'}</div>
          ) : (
            visible.map((r, i) => (
              <div
                key={r.id}
                role="row"
                data-row-id={r.id}
                aria-selected={selectedId === r.id}
                onClick={() => select(r)}
                className={`rec-row grid items-center gap-x-3 px-3 border-b border-slate-800/70 cursor-pointer ${selectedId === r.id ? 'bg-slate-800 text-slate-50' : 'hover:bg-slate-900 text-slate-200'}`}
                style={{ gridTemplateColumns: template }}
              >
                <span role="gridcell" className="text-right text-slate-500">{(safePage - 1) * PAGE_SIZE + i + 1}</span>
                {cols.map((c) => {
                  if (c.key === 'tags') {
                    const t = tagsOfRow(r.id);
                    return <span key="tags" role="gridcell" className="flex gap-1 overflow-hidden">{t.length ? <TagPills tags={t} /> : <span className="text-slate-600">none</span>}</span>;
                  }
                  const v = c.key === 'time' ? fmtTime(r.timestamp) : r.cells[c.key] ?? '';
                  return (
                    <span key={c.key} role="gridcell" title={v} className={`truncate ${c.align === 'right' ? 'text-right' : ''} ${v === NOT_RECORDED ? 'text-slate-500 italic' : ''} ${c.key === 'recovery' && r.recovered ? 'text-amber-300' : ''}`}>
                      {v}
                    </span>
                  );
                })}
              </div>
            ))
          )}
        </div>
      </div>

      {pages > 1 && (
        <div className="shrink-0 flex items-center justify-center gap-3 h-10 border-t border-slate-800 bg-slate-900 text-slate-300">
          <button onClick={() => setPage(Math.max(1, safePage - 1))} disabled={safePage === 1} className="p-1 rounded hover:bg-slate-800 disabled:opacity-40" aria-label="Previous page"><ChevronLeft className="w-4 h-4" /></button>
          <span>Page {safePage} of {pages}</span>
          <button onClick={() => setPage(Math.min(pages, safePage + 1))} disabled={safePage === pages} className="p-1 rounded hover:bg-slate-800 disabled:opacity-40" aria-label="Next page"><ChevronRight className="w-4 h-4" /></button>
        </div>
      )}
    </div>
  );
};

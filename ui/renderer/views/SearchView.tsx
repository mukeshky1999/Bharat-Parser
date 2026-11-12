import React, { useCallback, useEffect, useState } from 'react';
import { Search } from 'lucide-react';
import { forensicClient, SearchMode, SearchResult } from '../api/forensicClient';
import { useWorkbenchStore } from '../state/workbenchStore';
import { RecordDetail, RecordRef } from '../inspectors/RecordDetail';
import { BulkTagBar } from '../inspectors/BulkTagBar';
import { SavedFilters } from '../workspace/SavedFilters';

const MODES: Array<{ id: SearchMode; label: string; help: string }> = [
  { id: 'keyword', label: 'Words', help: 'Every word must appear, in any order. Indic scripts work.' },
  { id: 'phrase', label: 'Exact phrase', help: 'The words together, in order.' },
  { id: 'contains', label: 'Contains', help: 'The text anywhere inside a value, including part of a word or number.' },
  { id: 'regex', label: 'Pattern (regex)', help: 'A regular expression. A very large case may be stopped by the time limit; the result then says so.' },
];

const PAGE = 50;
const field = 'h-8 rounded bg-slate-950 border border-slate-700 px-2 text-slate-100 placeholder-slate-500';

/** Looks for a text in every table of the case and lists where it was found. A hit opens the whole record. */
export const SearchView: React.FC = () => {
  const searchQuery = useWorkbenchStore((s) => s.searchQuery);
  const setSearchQuery = useWorkbenchStore((s) => s.setSearchQuery);
  const [text, setText] = useState(searchQuery);
  const [mode, setMode] = useState<SearchMode>('keyword');
  const [app, setApp] = useState('');
  const [offset, setOffset] = useState(0);
  const [result, setResult] = useState<SearchResult | null>(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [open, setOpen] = useState<RecordRef | null>(null);
  const [picked, setPicked] = useState<Record<string, RecordRef>>({});

  const run = useCallback(async (q: string, m: SearchMode, a: string, off: number) => {
    if (!q.trim()) { setResult(null); return; }
    setBusy(true); setError('');
    const res = await forensicClient.searchCase(q.trim(), { mode: m, application: a.trim() || undefined, limit: PAGE, offset: off });
    setBusy(false);
    if (res.error) { setError(res.error); setResult(null); return; }
    setResult(res.data);
  }, []);

  // arriving from the command palette with a text already typed
  useEffect(() => {
    if (searchQuery && searchQuery !== text) { setText(searchQuery); setOffset(0); void run(searchQuery, mode, app, 0); }
  }, [searchQuery]); // eslint-disable-line react-hooks/exhaustive-deps

  const submit = (e: React.FormEvent) => { e.preventDefault(); setOffset(0); setSearchQuery(text); void run(text, mode, app, 0); };
  const go = (off: number) => { setOffset(off); void run(text, mode, app, off); };
  const help = MODES.find((m) => m.id === mode)?.help;

  return (
    <div className="flex-1 flex min-w-0 min-h-0">
      <div className="flex-1 overflow-y-auto p-4 select-text min-w-0">
        <form onSubmit={submit} className="flex flex-wrap items-center gap-2 mb-2" role="search">
          <input aria-label="Text to search for" value={text} onChange={(e) => setText(e.target.value)} placeholder="Words, a number, a VPA, a phrase"
            className={`${field} flex-1 min-w-[16rem]`} />
          <select aria-label="How to match" value={mode} onChange={(e) => setMode(e.target.value as SearchMode)} className={field}>
            {MODES.map((m) => <option key={m.id} value={m.id}>{m.label}</option>)}
          </select>
          <input aria-label="Only this app" value={app} onChange={(e) => setApp(e.target.value)} placeholder="App (optional)" className={`${field} w-36`} />
          <SavedFilters scope="search" current={{ text, mode, app }} isDefault={!text.trim()}
            onApply={(s) => { const t = String(s.text ?? ''); const m = (s.mode as SearchMode) ?? 'keyword'; const a = String(s.app ?? ''); setText(t); setMode(m); setApp(a); setOffset(0); setSearchQuery(t); void run(t, m, a, 0); }} />
          <button type="submit" disabled={busy || !text.trim()} className="h-8 px-3 rounded bg-cyan-600 hover:bg-cyan-500 text-slate-50 inline-flex items-center gap-1.5 disabled:opacity-40">
            <Search className="w-4 h-4" aria-hidden="true" />{busy ? 'Searching…' : 'Search'}
          </button>
        </form>
        <p className="text-slate-400 text-xs mb-3">{help}</p>
        {error && <p className="text-rose-300 mb-2">{error}</p>}
        {result && (
          <>
            <p className="text-slate-200 mb-1" aria-live="polite">
              {result.total_is_exact ? result.total : `at least ${result.total}`} record{result.total === 1 ? '' : 's'} found
              {' '}in {Object.values(result.tables).filter((t) => t.count > 0).length} table(s), {result.elapsed_ms} ms.
            </p>
            {!result.complete && <p className="text-amber-300 mb-2">The search was stopped{result.stopped_reason ? `: ${result.stopped_reason}` : ''}. Records after the stop were not checked, so this list may be incomplete.</p>}
            {result.cells_cut > 0 && <p className="text-amber-300 mb-2">{result.cells_cut} very long value(s) were only partly searched.</p>}
            {(() => {
              const skipped = Object.entries(result.tables).filter(([, t]) => t.skipped);
              if (skipped.length === 0) return null;
              return (
                <p className="text-amber-300 mb-2">
                  {skipped.length} table(s) were not searched in this mode ({skipped.map(([n]) => n).join(', ')}): {skipped[0][1].skipped}
                </p>
              );
            })()}
            <BulkTagBar
              picked={Object.values(picked)}
              pageRecords={result.hits.map((h) => ({ table: h.table, id: h.id }))}
              onPick={(recs, on) => setPicked((cur) => {
                const next = { ...cur };
                for (const r of recs) { if (on) next[`${r.table}-${r.id}`] = r; else delete next[`${r.table}-${r.id}`]; }
                return next;
              })}
              onDone={() => void run(text, mode, app, offset)}
            />
            <ul className="space-y-2">
              {result.hits.map((h) => (
                <li key={`${h.table}-${h.id}`} className="flex items-start gap-2">
                  <input type="checkbox" className="mt-3" aria-label={`Select ${h.table} ${h.id}`} checked={!!picked[`${h.table}-${h.id}`]}
                    onChange={(e) => setPicked((cur) => { const n = { ...cur }; if (e.target.checked) n[`${h.table}-${h.id}`] = { table: h.table, id: h.id }; else delete n[`${h.table}-${h.id}`]; return n; })} />
                  <button onClick={() => setOpen({ table: h.table, id: h.id })}
                    className={`flex-1 min-w-0 text-left rounded border p-2 hover:bg-slate-800 ${open?.table === h.table && open.id === h.id ? 'border-cyan-600 bg-slate-800' : 'border-slate-800 bg-slate-900'}`}>
                    <div className="flex flex-wrap items-center gap-x-3 text-[0.75rem] text-slate-400">
                      <span className="text-slate-200">{h.table} #{h.id}</span>
                      <span>{h.application || 'app not recorded'}</span>
                      <span>{h.time || 'time not recorded'}</span>
                      <span>found in {h.matched_fields.join(', ') || 'field not named'}</span>
                    </div>
                    <div className="text-slate-100 break-words">{h.snippet}</div>
                    <div className="text-[0.6875rem] text-slate-500 break-words">{h.source_file}{h.decoded_by ? ` · decoded by ${h.decoded_by}` : ''}</div>
                  </button>
                </li>
              ))}
            </ul>
            <div className="flex items-center gap-2 mt-3">
              <button className="h-8 px-3 rounded border border-slate-700 text-slate-200 hover:bg-slate-800 disabled:opacity-40" disabled={busy || offset === 0} onClick={() => go(Math.max(0, offset - PAGE))}>Previous</button>
              <span className="text-slate-400 text-xs">{result.hits.length ? `${offset + 1}–${offset + result.hits.length}` : 'no hits'}</span>
              <button className="h-8 px-3 rounded border border-slate-700 text-slate-200 hover:bg-slate-800 disabled:opacity-40" disabled={busy || offset + PAGE >= result.total} onClick={() => go(offset + PAGE)}>Next</button>
            </div>
          </>
        )}
        {!result && !error && <p className="text-slate-500">Nothing searched yet. The search covers every table of the open case, every device.</p>}
      </div>
      <RecordDetail record={open} onClose={() => setOpen(null)} />
    </div>
  );
};

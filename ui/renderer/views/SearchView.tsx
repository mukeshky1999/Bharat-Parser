import React, { useCallback, useEffect, useState } from 'react';
import { Search } from 'lucide-react';
import { forensicClient, SearchMode, SearchResult } from '../api/forensicClient';
import { useWorkbenchStore } from '../state/workbenchStore';
import { RecordDetail, RecordRef } from '../inspectors/RecordDetail';
import { BulkTagBar } from '../inspectors/BulkTagBar';
import { SavedFilters } from '../workspace/SavedFilters';
import { ViewHeader, Button } from '../components/ui';
import { useLatestRequest } from '../utils/latestRequest';

const MODES: Array<{ id: SearchMode; label: string; help: string }> = [
  { id: 'keyword', label: 'Words', help: 'Every word must appear, in any order. Indic scripts work.' },
  { id: 'phrase', label: 'Exact phrase', help: 'The words together, in order.' },
  { id: 'contains', label: 'Contains', help: 'The text anywhere inside a value, including part of a word or number.' },
  { id: 'regex', label: 'Pattern (regex)', help: 'A regular expression. A very large case may be stopped by the time limit; the result then says so.' },
];

const PAGE = 50;
const field = 'h-8 rounded-lg bg-surface border border-line-strong px-2 text-ink placeholder:text-faint';

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

  // The query behind the results on screen. Paging and "refresh after tagging" use this, not the box, which may have been edited.
  const [shown, setShown] = useState<{ q: string; m: SearchMode; a: string } | null>(null);
  const latest = useLatestRequest();

  const run = useCallback(async (q: string, m: SearchMode, a: string, off: number) => {
    const { isCurrent } = latest.begin();            // an older reply must not overwrite a newer one
    if (!q.trim()) { setResult(null); setShown(null); setBusy(false); return; }
    setBusy(true); setError('');
    const res = await forensicClient.searchCase(q.trim(), { mode: m, application: a.trim() || undefined, limit: PAGE, offset: off });
    if (!isCurrent()) return;
    setBusy(false);
    if (res.error) { setError(res.error); setResult(null); setShown(null); return; }
    setResult(res.data);
    setShown({ q, m, a });
  }, [latest]);

  // arriving from the command palette: the text is already in the box, so run it when the view opens, and again when it changes
  useEffect(() => {
    if (searchQuery.trim()) { setText(searchQuery); setOffset(0); void run(searchQuery, mode, app, 0); }
  }, [searchQuery]); // eslint-disable-line react-hooks/exhaustive-deps

  const submit = (e: React.FormEvent) => { e.preventDefault(); setOffset(0); setSearchQuery(text); void run(text, mode, app, 0); };
  const go = (off: number) => { if (!shown) return; setOffset(off); void run(shown.q, shown.m, shown.a, off); };
  const help = MODES.find((m) => m.id === mode)?.help;

  return (
    <div className="flex-1 flex min-w-0 min-h-0 bg-page">
      <div className="flex-1 overflow-y-auto p-4 select-text min-w-0">
        <ViewHeader title="Search records" count={result ? result.total : undefined} />
        <form onSubmit={submit} className="flex flex-wrap items-center gap-2 mb-2" role="search">
          <input aria-label="Text to search for" value={text} onChange={(e) => setText(e.target.value)} placeholder="Words, a number, a VPA, a phrase"
            className={`${field} flex-1 min-w-[16rem]`} />
          <select aria-label="How to match" value={mode} onChange={(e) => setMode(e.target.value as SearchMode)} className={field}>
            {MODES.map((m) => <option key={m.id} value={m.id}>{m.label}</option>)}
          </select>
          <input aria-label="Only this app" value={app} onChange={(e) => setApp(e.target.value)} placeholder="App (optional)" className={`${field} w-36`} />
          <SavedFilters scope="search" current={{ text, mode, app }} isDefault={!text.trim()}
            onApply={(s) => { const t = String(s.text ?? ''); const m = (s.mode as SearchMode) ?? 'keyword'; const a = String(s.app ?? ''); setText(t); setMode(m); setApp(a); setOffset(0); setSearchQuery(t); void run(t, m, a, 0); }} />
          <Button type="submit" variant="primary" disabled={busy || !text.trim()}>
            <Search className="w-4 h-4" aria-hidden="true" />{busy ? 'Searching…' : 'Search'}
          </Button>
        </form>
        <p className="text-muted text-xs mb-3">{help}</p>
        {error && <p className="text-rec mb-2">{error}</p>}
        {result && (
          <>
            <p className="text-ink mb-1" aria-live="polite">
              {result.total_is_exact ? result.total : `at least ${result.total}`} record{result.total === 1 ? '' : 's'} found
              {' '}in {Object.values(result.tables).filter((t) => t.count > 0).length} table(s), {result.elapsed_ms} ms.
            </p>
            {!result.complete && <p className="text-warn mb-2">The search was stopped{result.stopped_reason ? `: ${result.stopped_reason}` : ''}. Records after the stop were not checked, so this list may be incomplete.</p>}
            {result.cells_cut > 0 && <p className="text-warn mb-2">{result.cells_cut} very long value(s) were only partly searched.</p>}
            {(() => {
              const skipped = Object.entries(result.tables).filter(([, t]) => t.skipped);
              if (skipped.length === 0) return null;
              return (
                <p className="text-warn mb-2">
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
              onDone={() => { if (shown) void run(shown.q, shown.m, shown.a, offset); }}
            />
            <ul className="space-y-2">
              {result.hits.map((h) => (
                <li key={`${h.table}-${h.id}`} className="flex items-start gap-2">
                  <input type="checkbox" className="mt-3" aria-label={`Select ${h.table} ${h.id}`} checked={!!picked[`${h.table}-${h.id}`]}
                    onChange={(e) => setPicked((cur) => { const n = { ...cur }; if (e.target.checked) n[`${h.table}-${h.id}`] = { table: h.table, id: h.id }; else delete n[`${h.table}-${h.id}`]; return n; })} />
                  <button onClick={() => setOpen({ table: h.table, id: h.id })}
                    className={`flex-1 min-w-0 text-left rounded-[10px] border p-2 shadow-card hover:bg-hover ${open?.table === h.table && open.id === h.id ? 'border-accent bg-accent-soft' : 'border-line bg-surface'}`}>
                    <div className="flex flex-wrap items-center gap-x-3 text-[0.75rem] text-muted">
                      <span className="text-ink font-medium">{h.table} #{h.id}</span>
                      <span>{h.application || 'app not recorded'}</span>
                      <span>{h.time ? `${h.time}${h.time_basis ? ` (${h.time_basis})` : ''}` : 'time not recorded'}</span>
                      <span>found in {h.matched_fields.join(', ') || 'field not named'}</span>
                    </div>
                    <div className="text-ink break-words">{h.snippet}</div>
                    <div className="text-[0.6875rem] text-faint break-words">{h.source_file}{h.decoded_by ? ` · decoded by ${h.decoded_by}` : ''}</div>
                  </button>
                </li>
              ))}
            </ul>
            <div className="flex items-center gap-2 mt-3">
              <Button disabled={busy || offset === 0} onClick={() => go(Math.max(0, offset - PAGE))}>Previous</Button>
              <span className="text-muted text-xs">{result.hits.length ? `${offset + 1}–${offset + result.hits.length}` : 'no hits'}</span>
              <Button disabled={busy || offset + PAGE >= result.total} onClick={() => go(offset + PAGE)}>Next</Button>
            </div>
          </>
        )}
        {!result && !error && <p className="text-faint">Nothing searched yet. The search covers every table of the open case, every device.</p>}
      </div>
      <RecordDetail record={open} onClose={() => setOpen(null)} />
    </div>
  );
};

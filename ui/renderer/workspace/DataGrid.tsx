import React, { useEffect, useMemo, useRef, useState } from 'react';
import { Download } from 'lucide-react';
import { usePreferences } from '../state/preferencesStore';
import { csvCell, downloadCsv } from '../utils/csv';
import { useTagIndex } from './useTagIndex';
import { TagPills } from '../inspectors/TagControls';
import { Button, Chip, ViewHeader } from '../components/ui';

/**
 * The one table pattern for the money views: a header row, fixed-height rows that are drawn only while they are in
 * view (so a case with tens of thousands of rows stays responsive), keyboard selection, a column chooser that is
 * remembered per table, and a CSV export that always carries every column.
 *
 * Rows arrive already filtered. A cell that has no recorded value should show "not recorded" (use `Unset`), never a
 * dash or a default.
 */
export interface GridColumn<T> {
  key: string;
  label: string;
  /** CSS grid track, for example "8rem" or "minmax(10rem,1fr)" */
  width: string;
  align?: 'right' | 'center';
  cell: (row: T) => React.ReactNode;
  /** The same value as plain text, for the CSV export */
  text: (row: T) => string;
}

export const Unset: React.FC = () => <span className="text-faint italic">not recorded</span>;

interface DataGridProps<T> {
  /** Names this table for the remembered column choice */
  tableId: string;
  title: string;
  columns: GridColumn<T>[];
  rows: T[];
  rowKey: (row: T, index: number) => string;
  selectedKey?: string | null;
  onSelect?: (row: T) => void;
  /** Controls placed in the toolbar, left of the count */
  toolbar?: React.ReactNode;
  /** Shown instead of the table when there are no rows */
  empty: React.ReactNode;
  exportName: string;
  rowHeight?: number;
  rowClass?: (row: T) => string;
  /** Optional: recovery state text for a row that came from deleted or carved data (null for an ordinary row). */
  recoveredOf?: (row: T) => string | null;
  /** Total before filtering, for "n of m" */
  totalBeforeFilter?: number;
  /** Adds a Tags column: the case-store table the rows belong to, and which record id a row is (null when it is not one). */
  tags?: { table: string; idOf: (row: T) => number | null };
}

export function DataGrid<T>({
  tableId, title, columns: baseColumns, rows, rowKey, selectedKey, onSelect, toolbar, empty, exportName, rowHeight = 38, rowClass, recoveredOf, totalBeforeFilter, tags,
}: DataGridProps<T>): React.ReactElement {
  const tagIndex = useTagIndex(tags?.table ?? '');
  const tagsOf = (r: T): string[] => { const id = tags?.idOf(r); return id ? tagIndex[id] ?? [] : []; };
  const columns: GridColumn<T>[] = useMemo(() => (tags ? [{
    key: 'tags', label: 'Tags', width: '11rem',
    cell: (r: T) => { const t = tagsOf(r); return t.length ? <span className="flex gap-1 overflow-hidden"><TagPills tags={t} /></span> : <span className="text-faint">none</span>; },
    text: (r: T) => tagsOf(r).join('; '),
  }, ...baseColumns] : baseColumns), [baseColumns, tags, tagIndex]); // eslint-disable-line react-hooks/exhaustive-deps
  const hidden = usePreferences((s) => s.hiddenColumns[tableId]) ?? [];
  const allHidden = usePreferences((s) => s.hiddenColumns);
  const setPrefs = usePreferences((s) => s.set);
  const shown = columns.filter((c) => !hidden.includes(c.key));
  const template = `3.5rem ${shown.map((c) => c.width).join(' ')}`;

  const ref = useRef<HTMLDivElement | null>(null);
  const headerRef = useRef<HTMLDivElement | null>(null);
  const [scrollTop, setScrollTop] = useState(0);
  const [viewport, setViewport] = useState(600);
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const measure = () => setViewport(el.clientHeight || 600);
    measure();
    const ro = typeof ResizeObserver !== 'undefined' ? new ResizeObserver(measure) : null;
    ro?.observe(el);
    return () => ro?.disconnect();
  }, []);

  const OVERSCAN = 8;
  const start = Math.max(0, Math.floor(scrollTop / rowHeight) - OVERSCAN);
  const end = Math.min(rows.length, Math.ceil((scrollTop + viewport) / rowHeight) + OVERSCAN);
  const visible = useMemo(() => rows.slice(start, end), [rows, start, end]);

  const onKey = (e: React.KeyboardEvent) => {
    if (rows.length === 0 || !onSelect) return;
    const cur = rows.findIndex((r, i) => rowKey(r, i) === selectedKey);
    let next = cur;
    if (e.key === 'ArrowDown' || e.key === 'j') next = Math.min(rows.length - 1, cur + 1);
    else if (e.key === 'ArrowUp' || e.key === 'k') next = Math.max(0, cur < 0 ? 0 : cur - 1);
    else return;
    e.preventDefault();
    onSelect(rows[next]);
    const el = ref.current;
    if (el) {
      // The sticky header sits inside the same scroll box, so a row's top is the header's height plus its place in the list.
      const hh = headerRef.current?.offsetHeight ?? 32;
      const rowTop = hh + next * rowHeight;
      if (rowTop - hh < el.scrollTop) el.scrollTop = next * rowHeight;                       // just below the header
      else if (rowTop + rowHeight > el.scrollTop + el.clientHeight) el.scrollTop = rowTop + rowHeight - el.clientHeight;
    }
  };

  const exportCsv = () =>
    downloadCsv(exportName, [
      columns.map((c) => csvCell(c.label)).join(','),
      ...rows.map((r) => columns.map((c) => csvCell(c.text(r))).join(',')),
    ]);

  const recoveredCount = recoveredOf ? rows.reduce((n, r) => n + (recoveredOf(r) ? 1 : 0), 0) : 0;
  const total = totalBeforeFilter ?? rows.length;

  return (
    <div className="flex-1 flex flex-col min-w-0 min-h-0 bg-page select-text p-4">
      <ViewHeader title={title} count={total} recovered={recoveredCount}
        search={toolbar}
        actions={(
          <>
            <details className="relative">
              <summary className="h-8 px-3 rounded-lg border border-line-strong bg-surface text-ink hover:bg-hover cursor-pointer inline-flex items-center list-none font-medium">Columns</summary>
              <div className="absolute right-0 z-20 mt-1 w-60 rounded-lg border border-line-strong bg-surface p-2 shadow-float">
                {columns.map((c) => (
                  <label key={c.key} className="flex items-center gap-2 py-0.5 text-ink">
                    <input type="checkbox" checked={!hidden.includes(c.key)} disabled={!hidden.includes(c.key) && shown.length === 1}
                      onChange={(e) => setPrefs({ hiddenColumns: { ...allHidden, [tableId]: e.target.checked ? hidden.filter((k) => k !== c.key) : [...hidden, c.key] } })} />
                    {c.label}
                  </label>
                ))}
                <p className="mt-1 text-[0.6875rem] text-muted">Hiding a column only changes what is shown. Export keeps every column.</p>
              </div>
            </details>
            <Button onClick={exportCsv} disabled={rows.length === 0}>
              <Download className="w-4 h-4" aria-hidden="true" /> Export CSV
            </Button>
          </>
        )} />

      <div className="card flex-1 flex flex-col min-h-0 overflow-hidden">
        <div ref={ref} tabIndex={0} onKeyDown={onKey} onScroll={(e) => setScrollTop(e.currentTarget.scrollTop)}
          className="flex-1 overflow-auto min-h-0 outline-none focus-visible:ring-2 focus-visible:ring-accent focus-visible:ring-inset" role="grid" aria-label={title} aria-rowcount={rows.length + 1}>
          {rows.length === 0 ? (
            <div className="p-10 text-center text-muted">{empty}</div>
          ) : (
            <div className="min-w-max">
              <div ref={headerRef} role="row" className="sticky top-0 z-10 grid items-center gap-x-3 px-3 h-9 bg-sunken border-b border-line text-muted text-[0.75rem] font-semibold" style={{ gridTemplateColumns: template }}>
                <span role="columnheader" className="text-right">#</span>
                {shown.map((c) => <span key={c.key} role="columnheader" className={c.align === 'right' ? 'text-right' : c.align === 'center' ? 'text-center' : ''}>{c.label}</span>)}
              </div>
              <div style={{ height: rows.length * rowHeight, position: 'relative' }}>
                <div style={{ transform: `translateY(${start * rowHeight}px)` }}>
                  {visible.map((r, i) => {
                    const idx = start + i;
                    const key = rowKey(r, idx);
                    const sel = selectedKey === key;
                    const rec = recoveredOf?.(r) ?? null;
                    return (
                      <div key={key} role="row" aria-selected={sel} aria-rowindex={idx + 2} onClick={() => onSelect?.(r)}
                        className={`${rec ? 'is-recovered shadow-[inset_3px_0_0_var(--t-rec)]' : ''} grid items-center gap-x-3 px-3 border-b border-line ${onSelect ? 'cursor-pointer' : ''} ${sel ? 'bg-accent-soft text-ink' : 'hover:bg-hover text-ink'} ${rowClass?.(r) ?? ''}`}
                        style={{ gridTemplateColumns: template, height: rowHeight }}>
                        <span role="gridcell" className="text-right text-faint">{idx + 1}</span>
                        {shown.map((c, ci) => (
                          <span key={c.key} role="gridcell" title={c.text(r)} className={`truncate ${c.align === 'right' ? 'text-right' : c.align === 'center' ? 'text-center' : ''}`}>
                            {c.cell(r)}
                            {ci === 0 && rec && <>{' '}<Chip tone="rec">Recovered · {rec}</Chip></>}
                          </span>
                        ))}
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>
          )}
        </div>
        <div className="shrink-0 px-4 py-2 border-t border-line bg-sunken text-muted text-[0.75rem]" aria-live="polite">
          Showing {rows.length.toLocaleString()} of {total.toLocaleString()} row{total === 1 ? '' : 's'}
        </div>
      </div>
    </div>
  );
}

/** A row of mutually exclusive choices (a filter). */
export function Segmented<V extends string>({ label, value, options, onChange }: {
  label: string; value: V; options: Array<{ value: V; label: string; title?: string }>; onChange: (v: V) => void;
}): React.ReactElement {
  return (
    <div role="radiogroup" aria-label={label} className="inline-flex rounded-lg border border-line-strong overflow-hidden bg-surface">
      {options.map((o) => (
        <button key={o.value} role="radio" aria-checked={value === o.value} title={o.title} onClick={() => onChange(o.value)}
          className={`h-8 px-3 border-r border-line last:border-r-0 ${value === o.value ? 'bg-accent-soft text-accent-ink font-semibold' : 'text-muted hover:bg-hover'}`}>
          {o.label}
        </button>
      ))}
    </div>
  );
}

export const FilterInput: React.FC<{ label: string; value: string; onChange: (v: string) => void; placeholder: string; width?: string }> = ({ label, value, onChange, placeholder, width = 'w-64' }) => (
  <label>
    <span className="sr-only">{label}</span>
    <input value={value} onChange={(e) => onChange(e.target.value)} placeholder={placeholder} className={`h-8 ${width} px-2.5 rounded-lg bg-surface border border-line-strong text-ink placeholder:text-faint`} />
  </label>
);

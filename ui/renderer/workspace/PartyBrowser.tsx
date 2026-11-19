import React, { useMemo, useState } from 'react';
import { Search } from 'lucide-react';
import { Button, Chip, RecoveredChip, Segmented } from '../components/ui';
import { useWorkbenchStore, type ActiveTabType } from '../state/workbenchStore';

/**
 * The "by person" layout shared by the UPI ledger, Calls and Crypto wallets.
 * Left: app chips and the people (or IDs) found. Right: that person's records, with a facts strip and links to the
 * other views that hold the same ID. "All rows" shows the existing full view unchanged.
 */

export interface PartyBrowserProps<T> {
  rows: T[];
  appOf: (row: T) => string;
  partyOf: (row: T) => string;
  /** A name only when the evidence has one; otherwise the raw ID is the name. */
  partyLabel: (id: string) => { name: string; note?: string };
  isRecovered: (row: T) => boolean;
  apps: string[];
  idLabel: 'UPI ID' | 'Number' | 'Address';
  unit?: { one: string; many: string };
  listSummary: (rows: T[]) => React.ReactNode;
  facts: (rows: T[]) => Array<[string, React.ReactNode]>;
  alsoFoundIn?: (partyId: string) => Array<{ tab: ActiveTabType; label: string }>;
  renderRows: (rows: T[]) => React.ReactNode;
  renderAll: () => React.ReactNode;
}

const LIST_CAP = 300;
const NOT_RECORDED = 'not recorded';

const initials = (name: string): string =>
  name.replace(/[^A-Za-z ]/g, '').split(/\s+/).filter(Boolean).map((w) => w[0]).join('').slice(0, 2).toUpperCase() || '#';
const shortId = (a: string): string => (a.length > 28 ? `${a.slice(0, 12)}…${a.slice(-6)}` : a);

const Avatar: React.FC<{ name: string; big?: boolean }> = ({ name, big }) => (
  <span aria-hidden="true" className={`${big ? 'w-[34px] h-[34px]' : 'w-8 h-8'} rounded-full grid place-items-center shrink-0 bg-accent-soft text-accent-ink font-semibold text-[0.75rem]`}>{initials(name)}</span>
);

const AppChip: React.FC<{ children: React.ReactNode }> = ({ children }) => (
  <span className="inline-flex text-[0.6875rem] font-semibold px-[7px] py-px rounded-full whitespace-nowrap bg-sunken text-muted border border-line">{children}</span>
);

export function PartyBrowser<T>({
  rows, appOf, partyOf, partyLabel, isRecovered, apps, idLabel, unit = { one: 'record', many: 'records' }, listSummary, facts, alsoFoundIn, renderRows, renderAll,
}: PartyBrowserProps<T>): React.ReactElement {
  const setActiveTab = useWorkbenchStore((s) => s.setActiveTab);
  const [mode, setMode] = useState<'party' | 'all'>('party');
  const [app, setApp] = useState('all');
  const [find, setFind] = useState('');
  const [picked, setPicked] = useState<string | null>(null);

  const modeControl = (
    <div className="flex items-center gap-3 px-4 pt-3 shrink-0">
      <Segmented label="Layout" value={mode} onChange={(v) => setMode(v as 'party' | 'all')}
        options={[{ value: 'party', label: 'By person' }, { value: 'all', label: 'All rows' }]} />
      {mode === 'all' && <span className="text-muted text-[0.75rem]">Switch to "By person" to group rows by {idLabel.toLowerCase()}.</span>}
    </div>
  );

  const appCount = (a: string) => new Set(rows.filter((r) => a === 'all' || appOf(r) === a).map(partyOf)).size;

  const { order, by } = useMemo(() => {
    const q = find.trim().toLowerCase();
    const map = new Map<string, T[]>();
    for (const r of rows) {
      if (app !== 'all' && appOf(r) !== app) continue;
      const p = partyOf(r);
      const list = map.get(p);
      if (list) list.push(r); else map.set(p, [r]);
    }
    let keys = [...map.keys()];
    if (q) keys = keys.filter((p) => p.toLowerCase().includes(q) || partyLabel(p).name.toLowerCase().includes(q));
    keys.sort((a, b) => map.get(b)!.length - map.get(a)!.length);
    return { order: keys, by: map };
  }, [rows, app, find]); // eslint-disable-line react-hooks/exhaustive-deps

  if (mode === 'all' || rows.length === 0) {
    return <div className="flex-1 flex flex-col min-w-0 min-h-0">{modeControl}{renderAll()}</div>;
  }

  const cur = picked && by.has(picked) && order.includes(picked) ? picked : order[0] ?? null;
  const curRows = cur ? by.get(cur)! : [];
  const curLabel = cur ? partyLabel(cur) : null;
  const curApps = [...new Set(curRows.map(appOf))];
  const also = cur && alsoFoundIn ? alsoFoundIn(cur) : [];

  return (
    <div className="flex-1 flex flex-col min-w-0 min-h-0 overflow-auto">
      {modeControl}
      <div className="flex gap-4 flex-wrap items-start p-4">
        <section className="card flex-none w-[330px] max-w-full overflow-hidden flex flex-col" aria-label="People and IDs">
          <div className="px-3 py-2.5 border-b border-line flex flex-col gap-2">
            <div className="flex gap-1.5 flex-wrap">
              {['all', ...apps].map((a) => (
                <button key={a} type="button" aria-pressed={app === a} onClick={() => { setApp(a); setPicked(null); }}
                  className={`rounded-full border px-2.5 py-[3px] text-[0.75rem] font-medium ${app === a ? 'bg-accent-soft text-accent-ink border-accent font-semibold' : 'bg-surface text-muted border-line-strong hover:bg-hover'}`}>
                  {a === 'all' ? 'All' : a} <span className="text-faint">{appCount(a)}</span>
                </button>
              ))}
            </div>
            <label className="relative block">
              <span className="sr-only">Find a name or {idLabel.toLowerCase()}</span>
              <Search className="w-4 h-4 text-faint absolute left-2.5 top-2" aria-hidden="true" />
              <input value={find} onChange={(e) => setFind(e.target.value)} placeholder={`Find a name or ${idLabel.toLowerCase()}`}
                className="h-8 w-full pl-8 pr-2 rounded-lg bg-surface border border-line-strong text-ink placeholder:text-faint" />
            </label>
          </div>
          <div className="max-h-[560px] overflow-auto">
            {order.length === 0 && <p className="p-5 text-center text-muted">No one matches these filters.</p>}
            {order.slice(0, LIST_CAP).map((p) => {
              const xs = by.get(p)!;
              const m = partyLabel(p);
              const rec = xs.filter(isRecovered).length;
              const apps2 = [...new Set(xs.map(appOf))];
              return (
                <button key={p} type="button" aria-current={p === cur} onClick={() => setPicked(p)}
                  className={`flex gap-2.5 w-full text-left px-3 py-2.5 border-b border-line items-start ${p === cur ? 'bg-accent-soft' : 'hover:bg-hover'} ${rec ? 'shadow-[inset_3px_0_0_var(--t-rec)]' : ''}`}>
                  <Avatar name={m.name} />
                  <span className="min-w-0 flex-1 flex flex-col gap-0.5">
                    <b className="font-semibold truncate">{m.name || NOT_RECORDED}</b>
                    {m.name !== p && <span className="font-mono text-muted text-[0.75rem] truncate">{shortId(p)}</span>}
                    <span className="flex gap-1.5 items-center flex-wrap text-[0.75rem] text-muted">
                      {apps2.map((a) => <AppChip key={a}>{a}</AppChip>)}
                      <span>{xs.length.toLocaleString()} {xs.length === 1 ? unit.one : unit.many}</span>
                      {rec > 0 && <RecoveredChip n={rec} label="recovered" />}
                    </span>
                  </span>
                  <span className="text-[0.75rem] text-muted text-right whitespace-nowrap">{listSummary(xs)}</span>
                </button>
              );
            })}
          </div>
          <div className="px-3 py-2 border-t border-line text-[0.75rem] text-muted">
            {order.length.toLocaleString()} shown{order.length > LIST_CAP ? `, first ${LIST_CAP} listed. Use the find box to narrow` : ''}
          </div>
        </section>

        <section className="card flex-[1_1_440px] min-w-0 overflow-hidden" aria-label="Records for the selected person">
          {cur && curLabel ? (
            <>
              <div className="flex gap-3 items-center flex-wrap px-4 py-3 border-b border-line">
                <Avatar name={curLabel.name} big />
                <div className="min-w-0 flex-1">
                  <h2 className="text-base font-semibold truncate">{curLabel.name}</h2>
                  <div className="text-muted text-[0.75rem] flex gap-1.5 flex-wrap items-center">
                    <span>{idLabel}</span><span className="font-mono break-all">{cur}</span>
                    {curApps.map((a) => <AppChip key={a}>{a}</AppChip>)}
                  </div>
                </div>
                {curLabel.note && <Chip>{curLabel.note}</Chip>}
              </div>
              <div className="flex gap-x-5 gap-y-1.5 flex-wrap px-4 py-2 border-b border-line bg-sunken text-[0.75rem] text-muted">
                {facts(curRows).map(([l, v]) => <span key={l}>{l} <b className="text-ink font-semibold">{v}</b></span>)}
              </div>
              {also.length > 0 && (
                <div className="flex gap-2 flex-wrap items-center px-4 py-2 border-b border-line text-[0.75rem] text-muted">
                  <span>Same {idLabel.toLowerCase()} also found in</span>
                  {also.map((a) => <Button key={`${a.tab}-${a.label}`} className="!h-[26px] !px-2.5 text-[0.75rem]" onClick={() => setActiveTab(a.tab)}>{a.label}</Button>)}
                </div>
              )}
              <div className="flex flex-col h-[520px] min-h-0">{renderRows(curRows)}</div>
            </>
          ) : (
            <div className="p-10 text-center text-muted">Nothing selected. Change the app filter or the find box.</div>
          )}
        </section>
      </div>
    </div>
  );
}

import React, { useState } from 'react';
import { ChevronDown, PanelLeftClose, PanelLeftOpen, Search } from 'lucide-react';
import { useWorkbenchStore } from '../state/workbenchStore';
import { useFindings } from '../state/findingsStore';
import { usePreferences } from '../state/preferencesStore';
import { GROUPS, Hue, countKey } from './dataTree';
import { GroupTile, RecoveredChip } from '../components/ui';

const SWATCH: Array<[string, string]> = [['bg-rec', 'Recovered (deleted)'], ['bg-accent', 'Selected']];

export const DataTree: React.FC = () => {
  const activeTab = useWorkbenchStore((s) => s.activeTab);
  const setActiveTab = useWorkbenchStore((s) => s.setActiveTab);
  const addToast = useWorkbenchStore((s) => s.addToast);
  const summary = useWorkbenchStore((s) => s.caseSummary);
  const upi = useWorkbenchStore((s) => s.upiTransactions.length);
  const chats = useWorkbenchStore((s) => s.chats.length);
  const contacts = useWorkbenchStore((s) => s.contacts.length);
  const calls = useWorkbenchStore((s) => s.callLogs.length);
  const findings = useFindings((s) => s.findings.length);
  const collapsed = usePreferences((s) => s.navCollapsed);
  const setPref = usePreferences((s) => s.set);
  const [filter, setFilter] = useState('');
  const [closed, setClosed] = useState<Record<string, boolean>>({});

  const q = filter.trim().toLowerCase();

  /** Total records of a view: the case summary's total; the loaded list only when the summary has no such key. */
  const totals = (tab: string): { n: number | null; rec: number } => {
    if (tab === 'FINDINGS') return { n: findings, rec: 0 };
    const key = countKey(tab as never);
    if (!key) return { n: null, rec: 0 };
    const c = summary?.counts?.[key];
    if (c) return { n: c.total, rec: c.wal_and_carved };
    const loaded: Record<string, number> = { CHATS: chats, CALLS: calls, CONTACTS: contacts, UPI_LEDGER: upi };
    return { n: loaded[tab] ?? null, rec: 0 };
  };

  return (
    <nav aria-label="Data tree" className="h-full flex flex-col bg-surface border-r border-line min-h-0" data-region="stages" tabIndex={-1}>
      {!collapsed && (
        <label className="mx-3 mt-3 mb-1.5 flex items-center gap-2 h-8 px-2.5 border border-line rounded-lg text-muted focus-within:border-accent">
          <Search className="w-4 h-4 shrink-0" aria-hidden="true" />
          <input value={filter} onChange={(e) => setFilter(e.target.value)} placeholder="Filter the tree" aria-label="Filter the data tree"
            className="flex-1 min-w-0 bg-transparent outline-none text-ink placeholder:text-faint" />
        </label>
      )}
      <div className="flex-1 overflow-y-auto px-2 pt-1 pb-3">
        <button
          onClick={() => setActiveTab('SUMMARY')}
          aria-current={activeTab === 'SUMMARY' ? 'page' : undefined}
          title={collapsed ? 'Case overview' : undefined}
          className={`w-full flex items-center gap-2.5 px-2 py-[7px] rounded-lg text-left font-semibold mb-1.5 ${activeTab === 'SUMMARY' ? 'bg-accent-soft text-accent-ink' : 'text-ink hover:bg-hover'}`}
        >
          <GroupTile hue="accent" icon={GROUPS[0].icon} />
          {!collapsed && 'Case overview'}
        </button>

        {GROUPS.filter((g) => g.id !== 'overview').map((g) => {
          const items = g.views.filter((v) => !q || v.label.toLowerCase().includes(q) || g.label.toLowerCase().includes(q));
          if (items.length === 0) return null;
          const isClosed = !!closed[g.id] && !q;
                    return (
            <div key={g.id} className="mt-1">
              <button
                onClick={() => (collapsed ? setActiveTab(g.views[0].tab) : setClosed((c) => ({ ...c, [g.id]: !c[g.id] })))}
                aria-expanded={collapsed ? undefined : !isClosed}
                title={collapsed ? `${g.no}. ${g.label}` : undefined}
                className={`w-full flex items-center gap-2.5 px-2 py-[7px] rounded-lg text-left font-semibold hover:bg-hover`}
              >
                <GroupTile hue={g.hue as Hue} icon={g.icon} />
                {!collapsed && (
                  <>
                    <span className="truncate">{g.label}</span>
                    <ChevronDown className={`w-4 h-4 ml-auto text-faint ${isClosed ? '-rotate-90' : ''}`} aria-hidden="true" />
                  </>
                )}
              </button>
              {!collapsed && !isClosed && (
                <ul className="list-none mt-0.5 mb-1.5 pl-11 m-0">
                  {items.map((v) => {
                    const { n, rec } = totals(v.tab);
                    const on = activeTab === v.tab;
                    return (
                      <li key={v.tab}>
                        <button
                          onClick={() => (v.unavailable
                            ? addToast({ type: 'info', title: `${v.label}: not available yet`, message: v.unavailable })
                            : setActiveTab(v.tab))}
                          aria-current={on ? 'page' : undefined}
                          aria-disabled={v.unavailable ? true : undefined}
                          title={v.unavailable ? 'Not available yet: needs testing on real data' : undefined}
                          className={`w-full flex items-center gap-2 px-2 py-[5px] rounded-md text-left ${
                            v.unavailable ? 'text-faint cursor-not-allowed' :
                            on ? 'bg-accent-soft text-accent-ink font-semibold' : 'text-muted hover:bg-hover'
                          }`}
                        >
                          <span className="truncate">{v.label}</span>
                          {v.unavailable && <span className="text-[0.6875rem] text-faint">not tested</span>}
                          {v.inTesting && <span className="text-[0.6875rem] text-warn bg-warn-soft px-1.5 rounded-full">in testing</span>}
                          {rec > 0 && <span className="ml-auto"><RecoveredChip n={rec} /></span>}
                          {n !== null && n > 0 && <span className={`${rec > 0 ? '' : 'ml-auto'} font-medium ${on ? 'text-accent-ink' : 'text-ink'}`}>{n.toLocaleString()}</span>}
                        </button>
                      </li>
                    );
                  })}
                </ul>
              )}
            </div>
          );
        })}
      </div>
      {!collapsed && (
        <div className="border-t border-line px-3.5 py-2.5 text-[0.75rem] text-muted flex gap-3 flex-wrap">
          {SWATCH.map(([cls, label]) => (
            <span key={label} className="inline-flex items-center gap-1.5"><span className={`w-[9px] h-[9px] rounded-[3px] ${cls}`} aria-hidden="true" />{label}</span>
          ))}
        </div>
      )}
      <button
        onClick={() => setPref({ navCollapsed: !collapsed })}
        className="h-9 shrink-0 flex items-center gap-2 px-3 border-t border-line text-muted hover:bg-hover"
        aria-label={collapsed ? 'Expand data tree' : 'Collapse data tree'}
      >
        {collapsed ? <PanelLeftOpen className="w-4 h-4" /> : <><PanelLeftClose className="w-4 h-4" /><span>Collapse</span></>}
      </button>
    </nav>
  );
};

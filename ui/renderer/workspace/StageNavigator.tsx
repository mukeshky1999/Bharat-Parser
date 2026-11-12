import React from 'react';
import { PanelLeftClose, PanelLeftOpen } from 'lucide-react';
import { useWorkbenchStore } from '../state/workbenchStore';
import { useFindings } from '../state/findingsStore';
import { usePreferences } from '../state/preferencesStore';
import { STAGES, stageForTab, type StageId } from './stages';

interface HasRecovery {
  provenance?: { recoveryState?: string } | null;
}

function recovered(items: HasRecovery[]): number {
  return items.filter((i) => i.provenance && i.provenance.recoveryState && i.provenance.recoveryState !== 'ACTIVE').length;
}

export const StageNavigator: React.FC = () => {
  const activeTab = useWorkbenchStore((s) => s.activeTab);
  const setActiveTab = useWorkbenchStore((s) => s.setActiveTab);
  const addToast = useWorkbenchStore((s) => s.addToast);
  const upi = useWorkbenchStore((s) => s.upiTransactions);
  const chats = useWorkbenchStore((s) => s.chats);
  const contacts = useWorkbenchStore((s) => s.contacts);
  const calls = useWorkbenchStore((s) => s.callLogs);
  const spill = useWorkbenchStore((s) => s.osSpillovers);
  const findings = useFindings((s) => s.findings.length);
  const collapsed = usePreferences((s) => s.navCollapsed);
  const setPref = usePreferences((s) => s.set);

  const current = stageForTab(activeTab);

  const counts: Partial<Record<StageId, { n: number; rec: number }>> = {
    people: { n: contacts.length + calls.length, rec: recovered(contacts as HasRecovery[]) + recovered(calls as HasRecovery[]) },
    money: { n: upi.length, rec: recovered(upi as HasRecovery[]) },
    messages: { n: chats.length + spill.length, rec: recovered(chats as HasRecovery[]) },
    findings: { n: findings, rec: 0 },
  };
  const viewCount = (tab: string): number | null => {
    switch (tab) {
      case 'CONTACTS': return contacts.length;
      case 'CALLS': return calls.length;
      case 'UPI_LEDGER': return upi.length;
      case 'CHATS': return chats.length;
      case 'OS_SPILLOVER': return spill.length;
      case 'FINDINGS': return findings;
      default: return null;
    }
  };

  return (
    <nav aria-label="Investigation stages" className="h-full flex flex-col bg-slate-900 border-r border-slate-800 min-h-0" data-region="stages" tabIndex={-1}>
      <ol className="flex-1 overflow-y-auto py-2">
        {STAGES.map((st) => {
          const isCurrent = st.id === current.id;
          const c = counts[st.id];
          const Icon = st.icon;
          return (
            <li key={st.id}>
              <button
                onClick={() => setActiveTab(st.views[0].tab)}
                aria-current={isCurrent ? 'step' : undefined}
                title={collapsed ? `${st.no}. ${st.label}: ${st.hint}` : undefined}
                className={`w-full flex items-center gap-3 px-3 py-2 text-left border-l-4 ${
                  isCurrent ? 'border-cyan-400 bg-slate-800 text-slate-50' : 'border-transparent text-slate-300 hover:bg-slate-800/60'
                }`}
              >
                <span className={`shrink-0 w-6 h-6 grid place-items-center rounded-full text-[0.75rem] font-semibold border ${isCurrent ? 'border-cyan-400 text-cyan-300' : 'border-slate-600 text-slate-300'}`}>{st.no}</span>
                {!collapsed && (
                  <span className="min-w-0 flex-1">
                    <span className="flex items-center gap-2">
                      <Icon className="w-4 h-4 shrink-0 text-slate-400" aria-hidden="true" />
                      <span className="font-medium truncate">{st.label}</span>
                      {c && c.n > 0 && <span className="ml-auto text-slate-300">{c.n.toLocaleString()}</span>}
                    </span>
                    <span className="block text-[0.75rem] text-slate-400 truncate">
                      {st.hint}{c && c.rec > 0 ? ` · +${c.rec.toLocaleString()} recovered` : ''}
                    </span>
                  </span>
                )}
              </button>
              {!collapsed && isCurrent && st.views.length > 1 && (
                <ul className="ml-12 mr-2 mb-1 border-l border-slate-700">
                  {st.views.map((v) => {
                    const n = viewCount(v.tab);
                    return (
                      <li key={v.tab}>
                        <button
                          onClick={() => (v.unavailable
                            ? addToast({ type: 'info', title: `${v.label}: not available yet`, message: v.unavailable })
                            : setActiveTab(v.tab))}
                          aria-current={activeTab === v.tab ? 'page' : undefined}
                          aria-disabled={v.unavailable ? true : undefined}
                          title={v.unavailable ? 'Not available yet: needs testing on real data' : undefined}
                          className={`w-full flex items-center justify-between gap-2 pl-3 pr-2 py-1 text-left rounded-r ${
                            v.unavailable ? 'text-slate-500 cursor-not-allowed' :
                            activeTab === v.tab ? 'bg-slate-800 text-cyan-300 font-medium' : 'text-slate-300 hover:bg-slate-800/60'
                          }`}
                        >
                          <span className="truncate">{v.label}</span>
                          {v.unavailable && <span className="text-[0.6875rem] text-slate-500">not tested</span>}
                          {n !== null && n > 0 && <span className="text-slate-400">{n.toLocaleString()}</span>}
                        </button>
                      </li>
                    );
                  })}
                </ul>
              )}
            </li>
          );
        })}
      </ol>
      <button
        onClick={() => setPref({ navCollapsed: !collapsed })}
        className="h-9 shrink-0 flex items-center gap-2 px-3 border-t border-slate-800 text-slate-300 hover:bg-slate-800"
        aria-label={collapsed ? 'Expand stage list' : 'Collapse stage list'}
      >
        {collapsed ? <PanelLeftOpen className="w-4 h-4" /> : <><PanelLeftClose className="w-4 h-4" /><span>Collapse</span></>}
      </button>
    </nav>
  );
};

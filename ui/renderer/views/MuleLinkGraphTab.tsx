import React, { useCallback, useEffect, useState } from 'react';
import { RefreshCw } from 'lucide-react';
import { forensicClient } from '../api/forensicClient';
import { useWorkbenchStore } from '../state/workbenchStore';
import { Segmented } from '../workspace/DataGrid';

type Mode = 'network' | 'sankey';
const btn = 'h-8 px-3 rounded border border-slate-700 text-slate-200 hover:bg-slate-800 disabled:opacity-40';

const rupees = (v: unknown) => {
  const n = Number(v);
  return Number.isFinite(n) && v !== null && v !== undefined && v !== '' ? `₹${n.toLocaleString('en-IN')}` : 'not recorded';
};

const Notice: React.FC<{ children: React.ReactNode }> = ({ children }) => (
  <div className="h-full flex items-center justify-center p-8 text-center text-slate-400 max-w-md mx-auto">{children}</div>
);

/**
 * Who paid whom, drawn from the payments in the case. Every link and every pattern here is a lead found by matching
 * recorded values (a VPA, an account, an amount). A lead is a reason to look at the records; it is not a finding,
 * and a role is the tool's suggestion from the flow of money, not a statement about a person.
 */
export const MuleLinkGraphTab: React.FC = () => {
  const store = useWorkbenchStore();
  const [networkHtml, setNetworkHtml] = useState('');
  const [loadingGraph, setLoadingGraph] = useState(true);
  const [alerts, setAlerts] = useState<any[]>([]);
  const [roles, setRoles] = useState<any[]>([]);
  const [mode, setMode] = useState<Mode>('network');
  const [sankeySvg, setSankeySvg] = useState('');
  const [loadingSankey, setLoadingSankey] = useState(false);
  const [chain, setChain] = useState<any | null>(null);
  const [tracing, setTracing] = useState(false);

  const loadSankey = useCallback(async () => {
    setLoadingSankey(true);
    try {
      const svg = await forensicClient.getSankeySvg();
      if (svg) setSankeySvg(svg);
    } catch {
      setSankeySvg('');
    } finally {
      setLoadingSankey(false);
    }
  }, []);

  const loadGraph = useCallback(async () => {
    setLoadingGraph(true);
    try {
      void loadSankey();
      const res = await forensicClient.authFetch(forensicClient.getNetworkHtmlUrl());
      if (res.ok) setNetworkHtml(await res.text());
      const summary = await forensicClient.getCaseSummary();
      if (summary) {
        setAlerts(summary.mule_alerts || []);
        setRoles(summary.syndicate_roles || []);
      }
    } catch {
      setNetworkHtml('');
    } finally {
      setLoadingGraph(false);
    }
  }, [loadSankey]);

  useEffect(() => { void loadGraph(); }, [loadGraph, store.caseManifest]);

  const trace = async () => {
    setTracing(true);
    try {
      const res = await forensicClient.getChargeSheetChain();
      if (res && res.success) setChain(res.chain || res);
    } catch {
      setChain(null);
    } finally {
      setTracing(false);
    }
  };

  const hasData = Boolean(store.caseManifest || store.upiTransactions.length > 0);

  return (
    <div className="flex-1 flex flex-col min-w-0 min-h-0 bg-slate-950 select-text">
      <div className="shrink-0 flex flex-wrap items-center gap-3 px-4 py-3 border-b border-slate-800">
        <h2 className="text-slate-50 font-semibold mr-2">Link graph</h2>
        <Segmented<Mode> label="Drawing" value={mode} onChange={(m) => { setMode(m); if (m === 'sankey' && !sankeySvg) void loadSankey(); }}
          options={[{ value: 'network', label: 'Network' }, { value: 'sankey', label: 'Flow of money' }]} />
        <button className={btn} onClick={() => void trace()} disabled={tracing || !hasData}
          title="The chain of payments the tool built for the whole case when the evidence was read. It is not limited to two accounts.">
          {tracing ? 'Loading…' : 'Show the payment chain for this case'}
        </button>
        <button className={`${btn} ml-auto inline-flex items-center gap-2`} onClick={() => void loadGraph()} aria-label="Redraw the graph">
          <RefreshCw className={`w-4 h-4 ${loadingGraph || loadingSankey ? 'animate-spin' : ''}`} aria-hidden="true" />Redraw
        </button>
      </div>
      <p className="shrink-0 px-4 py-2 border-b border-slate-800 text-slate-400 text-xs">
        Leads, not findings. Links come from matching recorded values; patterns and roles are the tool&rsquo;s suggestions from the flow of money. Open the payments behind a link before relying on it.
      </p>

      <div className="flex-1 flex min-h-0">
        <div className="flex-1 min-w-0 bg-slate-950 relative overflow-hidden flex flex-col">
          {mode === 'network' ? (
            loadingGraph ? <Notice><span role="status">Drawing the graph…</span></Notice>
              : !networkHtml || !hasData ? <Notice>No graph yet. Open evidence that holds payments and the links between accounts are drawn here.</Notice>
                : <iframe srcDoc={networkHtml} title="Link graph" className="w-full h-full border-0" sandbox="allow-scripts allow-same-origin" />
          ) : (
            <div className="h-full overflow-auto p-4">
              {loadingSankey ? <Notice><span role="status">Drawing the flow of money…</span></Notice>
                : sankeySvg ? <div className="w-full max-w-5xl mx-auto overflow-auto rounded border border-slate-800 p-3 bg-slate-950" dangerouslySetInnerHTML={{ __html: sankeySvg }} />
                  : <Notice><div>The flow of money could not be drawn. <button className={`${btn} mt-2`} onClick={() => void loadSankey()}>Try again</button></div></Notice>}
            </div>
          )}
        </div>

        <aside className="w-96 shrink-0 border-l border-slate-800 bg-slate-900 overflow-y-auto p-3 space-y-4 text-xs text-slate-200" aria-label="Patterns, roles and traced path">
          <section>
            <h3 className="font-semibold text-slate-50 mb-1">Patterns the tool noticed ({alerts.length})</h3>
            {alerts.length === 0 ? (
              <p className="text-slate-400">{hasData ? 'None of the patterns the tool looks for was noticed. This does not show there is none.' : 'No evidence is open.'}</p>
            ) : (
              <ul className="space-y-2">
                {alerts.map((a, i) => (
                  <li key={i} className="rounded border border-slate-700 bg-slate-950 p-2">
                    <div className="flex justify-between gap-2 text-slate-100">
                      <span>{a.alert_type || a.type || 'Pattern'}</span>
                      {a.risk_level && <span className="text-slate-400">{String(a.risk_level)}</span>}
                    </div>
                    <p className="text-slate-300 mt-1 break-words">{a.description || a.message || a.details || 'No description recorded.'}</p>
                    {a.vpa && <p className="text-slate-400 mt-1 break-all">Account: {a.vpa}</p>}
                  </li>
                ))}
              </ul>
            )}
          </section>

          <section>
            <h3 className="font-semibold text-slate-50 mb-1">Roles the tool suggested ({roles.length})</h3>
            {roles.length === 0 ? <p className="text-slate-400">No account was given a role.</p> : (
              <ul className="space-y-2">
                {roles.map((r, i) => (
                  <li key={i} className="rounded border border-slate-700 bg-slate-950 p-2">
                    <div className="flex justify-between gap-2">
                      <span className="text-slate-100 break-all">{r.entity || r.vpa || 'account not recorded'}</span>
                      <span className="text-slate-300 shrink-0">{r.role || r.classification || 'role not given'}</span>
                    </div>
                    <div className="text-slate-400 mt-1 flex justify-between">
                      <span>In: {rupees(r.total_inflow ?? r.inflow)}</span><span>Out: {rupees(r.total_outflow ?? r.outflow)}</span>
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </section>

          {chain && (
            <section>
              <h3 className="font-semibold text-slate-50 mb-1">Traced path</h3>
              <div className="rounded border border-slate-700 bg-slate-950 p-2">
                <p className="text-slate-100">{chain.summary || 'Path traced.'}</p>
                <pre className="mt-1 whitespace-pre-wrap break-words text-slate-300">{typeof chain === 'string' ? chain : JSON.stringify(chain, null, 2)}</pre>
              </div>
            </section>
          )}
        </aside>
      </div>
    </div>
  );
};

import React, { useCallback, useEffect, useState } from 'react';
import { RefreshCw } from 'lucide-react';
import { forensicClient } from '../api/forensicClient';
import { useWorkbenchStore } from '../state/workbenchStore';
import { Segmented } from '../workspace/DataGrid';
import { ViewHeader, Button } from '../components/ui';
import { useLatestRequest } from '../utils/latestRequest';

type Mode = 'network' | 'sankey';

const rupees = (v: unknown) => {
  const n = Number(v);
  return Number.isFinite(n) && v !== null && v !== undefined && v !== '' ? `₹${n.toLocaleString('en-IN')}` : 'not recorded';
};

const Notice: React.FC<{ children: React.ReactNode }> = ({ children }) => (
  <div className="h-full flex items-center justify-center p-8 text-center text-muted max-w-md mx-auto">{children}</div>
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

  const latestSankey = useLatestRequest();
  const latestGraph = useLatestRequest();

  const loadSankey = useCallback(async () => {
    const { isCurrent } = latestSankey.begin();
    setLoadingSankey(true);
    setSankeySvg('');                       // the drawing of the previous case or device must not stay if this one fails
    try {
      const svg = await forensicClient.getSankeySvg();
      if (isCurrent() && svg) setSankeySvg(svg);
    } catch {
      if (isCurrent()) setSankeySvg('');
    } finally {
      if (isCurrent()) setLoadingSankey(false);
    }
  }, [latestSankey]);

  const loadGraph = useCallback(async () => {
    const { isCurrent } = latestGraph.begin();
    setLoadingGraph(true);
    setNetworkHtml(''); setAlerts([]); setRoles([]);   // nothing of the earlier drawing stays if this load fails
    try {
      void loadSankey();
      const res = await forensicClient.authFetch(forensicClient.getNetworkHtmlUrl());
      const html = res.ok ? await res.text() : '';
      const summary = await forensicClient.getCaseSummary();
      if (!isCurrent()) return;
      setNetworkHtml(html);
      if (summary) {
        setAlerts(summary.mule_alerts || []);
        setRoles(summary.syndicate_roles || []);
      }
    } catch {
      if (isCurrent()) setNetworkHtml('');
    } finally {
      if (isCurrent()) setLoadingGraph(false);
    }
  }, [loadSankey, latestGraph]);

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
    <div className="flex-1 flex flex-col min-w-0 min-h-0 bg-page select-text p-4">
      <ViewHeader title="Link graph"
        actions={(
          <>
        <Segmented<Mode> label="Drawing" value={mode} onChange={(m) => { setMode(m); if (m === 'sankey' && !sankeySvg) void loadSankey(); }}
          options={[{ value: 'network', label: 'Network' }, { value: 'sankey', label: 'Flow of money' }]} />
        <Button onClick={() => void trace()} disabled={tracing || !hasData}
          title="The chain of payments the tool built for the whole case when the evidence was read. It is not limited to two accounts.">
          {tracing ? 'Loading…' : 'Show the payment chain for this case'}
        </Button>
        <Button onClick={() => void loadGraph()} aria-label="Redraw the graph">
          <RefreshCw className="w-4 h-4" aria-hidden="true" />Redraw
        </Button>
          </>
        )} />
      <p className="shrink-0 card px-4 py-2.5 mb-3 bg-warn-soft text-ink text-xs" role="note">
        Leads, not findings. Links come from matching recorded values; patterns and roles are the tool&rsquo;s suggestions from the flow of money. Open the payments behind a link before relying on it.
      </p>

      <div className="flex-1 flex min-h-0 gap-3">
        <div className="flex-1 min-w-0 card bg-surface relative overflow-hidden flex flex-col">
          {mode === 'network' ? (
            loadingGraph ? <Notice><span role="status">Drawing the graph…</span></Notice>
              : !networkHtml || !hasData ? <Notice>No graph yet. Open evidence that holds payments and the links between accounts are drawn here.</Notice>
                : <iframe srcDoc={networkHtml} title="Link graph" className="w-full h-full border-0" sandbox="allow-scripts" />
          ) : (
            <div className="h-full overflow-auto p-4">
              {loadingSankey ? <Notice><span role="status">Drawing the flow of money…</span></Notice>
                : sankeySvg ? <div className="w-full max-w-5xl mx-auto overflow-auto rounded-lg border border-line p-3 bg-surface" dangerouslySetInnerHTML={{ __html: sankeySvg }} />
                  : <Notice><div>The flow of money could not be drawn. <Button className="mt-2" onClick={() => void loadSankey()}>Try again</Button></div></Notice>}
            </div>
          )}
        </div>

        <aside className="w-96 shrink-0 card overflow-y-auto p-3 space-y-4 text-xs text-ink" aria-label="Patterns, roles and traced path">
          <section>
            <h3 className="font-semibold text-ink mb-1">Patterns the tool noticed ({alerts.length})</h3>
            {alerts.length === 0 ? (
              <p className="text-muted">{hasData ? 'None of the patterns the tool looks for was noticed. This does not show there is none.' : 'No evidence is open.'}</p>
            ) : (
              <ul className="space-y-2">
                {alerts.map((a, i) => (
                  <li key={i} className="rounded-lg border border-line bg-sunken p-2">
                    <div className="flex justify-between gap-2 text-ink">
                      <span>{a.alert_type || a.type || 'Pattern'}</span>
                      {a.risk_level && <span className="text-muted">{String(a.risk_level)}</span>}
                    </div>
                    <p className="text-ink mt-1 break-words">{a.description || a.message || a.details || 'No description recorded.'}</p>
                    {a.vpa && <p className="text-muted mt-1 break-all">Account: {a.vpa}</p>}
                  </li>
                ))}
              </ul>
            )}
          </section>

          <section>
            <h3 className="font-semibold text-ink mb-1">Roles the tool suggested ({roles.length})</h3>
            {roles.length === 0 ? <p className="text-muted">No account was given a role.</p> : (
              <ul className="space-y-2">
                {roles.map((r, i) => (
                  <li key={i} className="rounded-lg border border-line bg-sunken p-2">
                    <div className="flex justify-between gap-2">
                      <span className="text-ink break-all">{r.entity || r.vpa || 'account not recorded'}</span>
                      <span className="text-ink shrink-0">{r.role || r.classification || 'role not given'}</span>
                    </div>
                    <div className="text-muted mt-1 flex justify-between">
                      <span>In: {rupees(r.total_inflow ?? r.inflow)}</span><span>Out: {rupees(r.total_outflow ?? r.outflow)}</span>
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </section>

          {chain && (
            <section>
              <h3 className="font-semibold text-ink mb-1">Traced path</h3>
              <div className="rounded-lg border border-line bg-sunken p-2">
                <p className="text-ink">{chain.summary || 'Path traced.'}</p>
                <pre className="mt-1 whitespace-pre-wrap break-words text-ink">{typeof chain === 'string' ? chain : JSON.stringify(chain, null, 2)}</pre>
              </div>
            </section>
          )}
        </aside>
      </div>
    </div>
  );
};

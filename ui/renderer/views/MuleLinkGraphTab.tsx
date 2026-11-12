import React, { useState, useEffect } from 'react';
import {
  Share2,
  AlertTriangle,
  ShieldAlert,
  ArrowRight,
  Coins,
  Bot,
  Smartphone,
  RefreshCw,
  GitBranch,
  Search,
  ExternalLink,
  Layers,
  ChevronDown
} from 'lucide-react';
import { forensicClient } from '../api/forensicClient';
import { useWorkbenchStore } from '../state/workbenchStore';

export const MuleLinkGraphTab: React.FC = () => {
  const store = useWorkbenchStore();
  const [networkHtml, setNetworkHtml] = useState<string>('');
  const [loadingGraph, setLoadingGraph] = useState<boolean>(true);

  const [muleAlerts, setMuleAlerts] = useState<any[]>([]);
  const [syndicateRoles, setSyndicateRoles] = useState<any[]>([]);

  // View Mode: PyVis Network Graph vs 4-Stage SVG Sankey
  const [viewMode, setViewMode] = useState<'network' | 'sankey'>('network');
  const [sankeySvg, setSankeySvg] = useState<string>('');
  const [loadingSankey, setLoadingSankey] = useState<boolean>(false);

  // Charge sheet chain entity selector state
  const [sourceEntity, setSourceEntity] = useState<string>('');
  const [targetEntity, setTargetEntity] = useState<string>('');
  const [chainResult, setChainResult] = useState<any | null>(null);
  const [tracingChain, setTracingChain] = useState<boolean>(false);

  const fetchSankey = async () => {
    setLoadingSankey(true);
    try {
      const svg = await forensicClient.getSankeySvg();
      if (svg) {
        setSankeySvg(svg);
      }
    } catch {
      // Fallback
    } finally {
      setLoadingSankey(false);
    }
  };

  // 1. Fetch PyVis Network Graph HTML & Summary Alerts
  const fetchGraphAndSummary = async () => {
    setLoadingGraph(true);
    try {
      fetchSankey();
      const res = await forensicClient.authFetch(forensicClient.getNetworkHtmlUrl());
      if (res.ok) {
        const text = await res.text();
        setNetworkHtml(text);
      }

      const summary = await forensicClient.getCaseSummary();
      if (summary) {
        setMuleAlerts(summary.mule_alerts || []);
        setSyndicateRoles(summary.syndicate_roles || []);

        // Prepopulate source and target from syndicate entities if available
        if (summary.syndicate_roles && summary.syndicate_roles.length >= 2) {
          setSourceEntity(summary.syndicate_roles[0].entity || summary.syndicate_roles[0].vpa || '');
          setTargetEntity(summary.syndicate_roles[summary.syndicate_roles.length - 1].entity || summary.syndicate_roles[summary.syndicate_roles.length - 1].vpa || '');
        }
      }
    } catch {
      // Fallback
    } finally {
      setLoadingGraph(false);
    }
  };

  useEffect(() => {
    fetchGraphAndSummary();
  }, [store.caseManifest]);

  // 2. Trace Charge Sheet Chain Call
  const handleTraceSyndicateChain = async () => {
    setTracingChain(true);
    try {
      const res = await forensicClient.getChargeSheetChain();
      if (res && res.success) {
        setChainResult(res.chain || res);
      }
    } catch {
      // Fallback
    } finally {
      setTracingChain(false);
    }
  };

  // Derive unique entities for dropdowns
  const availableEntities = React.useMemo(() => {
    const set = new Set<string>();
    syndicateRoles.forEach((r) => {
      const e = r.entity || r.vpa || r.account || r.name;
      if (e) set.add(String(e));
    });
    store.upiTransactions.forEach((tx) => {
      if (tx.payerVpa) set.add(tx.payerVpa);
      if (tx.payeeVpa) set.add(tx.payeeVpa);
    });
    return Array.from(set);
  }, [syndicateRoles, store.upiTransactions]);

  return (
    <div className="flex-1 flex flex-col bg-[#0b1320] text-slate-100 overflow-hidden select-text font-sans">
      {/* 1. Top Controls Bar: Entity Dropdowns & Trace Button */}
      <div className="h-11 bg-[#090f1d] border-b border-[#1e293b] px-3 flex items-center justify-between shrink-0 select-none text-xs">
        <div className="flex items-center space-x-2">
          <div className="flex items-center space-x-1.5 text-slate-300 font-semibold mr-1">
            <Share2 className="w-4 h-4 text-cyan-400" />
            <span>Syndicate Link Flow:</span>
          </div>

          <div className="flex items-center space-x-2">
            <select
              value={sourceEntity}
              onChange={(e) => setSourceEntity(e.target.value)}
              className="bg-slate-950 border border-slate-700 rounded px-2 py-1 text-slate-200 text-xs font-mono max-w-[180px] truncate focus:outline-none focus:border-cyan-500"
            >
              <option value="">-- Source Entity --</option>
              {availableEntities.map((e) => (
                <option key={`src_${e}`} value={e}>
                  {e}
                </option>
              ))}
            </select>

            <ArrowRight className="w-3.5 h-3.5 text-slate-500" />

            <select
              value={targetEntity}
              onChange={(e) => setTargetEntity(e.target.value)}
              className="bg-slate-950 border border-slate-700 rounded px-2 py-1 text-slate-200 text-xs font-mono max-w-[180px] truncate focus:outline-none focus:border-cyan-500"
            >
              <option value="">-- Target Entity --</option>
              {availableEntities.map((e) => (
                <option key={`tgt_${e}`} value={e}>
                  {e}
                </option>
              ))}
            </select>

            <button
              onClick={handleTraceSyndicateChain}
              disabled={tracingChain}
              className="px-3 py-1 bg-cyan-600 hover:bg-cyan-500 text-white font-bold rounded flex items-center space-x-1 transition-colors cursor-pointer text-xs"
            >
              <GitBranch className="w-3.5 h-3.5" />
              <span>{tracingChain ? 'Tracing...' : 'Trace Syndicate Chain'}</span>
            </button>
          </div>

          {/* Sub-tab Switch: PyVis Network Graph vs 4-Stage SVG Sankey */}
          <div className="flex items-center space-x-1 bg-slate-950 p-0.5 rounded border border-slate-800 ml-3">
            <button
              onClick={() => setViewMode('network')}
              className={`px-2.5 py-1 rounded text-[11px] font-semibold cursor-pointer transition-colors ${
                viewMode === 'network' ? 'bg-cyan-600 text-white shadow-sm' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              PyVis Network Graph
            </button>
            <button
              onClick={() => {
                setViewMode('sankey');
                if (!sankeySvg) fetchSankey();
              }}
              className={`px-2.5 py-1 rounded text-[11px] font-semibold cursor-pointer transition-colors ${
                viewMode === 'sankey' ? 'bg-cyan-600 text-white shadow-sm' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              4-Stage SVG Sankey Money Trail
            </button>
          </div>
        </div>

        {/* Refresh Graph */}
        <button
          onClick={fetchGraphAndSummary}
          className="text-slate-400 hover:text-white p-1 rounded hover:bg-slate-800 transition-colors"
          title="Refresh PyVis & Sankey Visualization"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loadingGraph || loadingSankey ? 'animate-spin text-cyan-400' : ''}`} />
        </button>
      </div>

      {/* 2. Main Split Area: Interactive PyVis / Sankey (Left/Center) + Intelligence Dossier (Right) */}
      <div className="flex-1 flex overflow-hidden">
        {/* Left/Center: Interactive PyVis Network Graph OR 4-Stage SVG Sankey Canvas */}
        <div className="flex-1 bg-[#070b14] relative overflow-hidden flex flex-col">
          {viewMode === 'network' ? (
            loadingGraph ? (
              <div className="h-full flex items-center justify-center text-slate-400 space-x-2">
                <span className="w-3 h-3 border-2 border-cyan-400 border-t-transparent rounded-full animate-spin" />
                <span className="text-xs font-mono">Generating interactive PyVis network graph...</span>
              </div>
            ) : !networkHtml || (!store.caseManifest && store.upiTransactions.length === 0) ? (
              <div className="h-full flex flex-col items-center justify-center text-slate-500 space-y-2 p-8">
                <Share2 className="w-12 h-12 text-slate-700 stroke-[1.5]" />
                <span className="text-sm font-semibold text-slate-400">No Syndicate Graph Loaded</span>
                <p className="text-xs text-slate-600 max-w-sm text-center">
                  Ingest an evidence container to construct an interactive transaction graph and visualize cybercrime syndicate fund movements.
                </p>
              </div>
            ) : (
              <iframe
                srcDoc={networkHtml}
                title="Syndicate Link Graph"
                className="w-full h-full border-0"
                sandbox="allow-scripts allow-same-origin"
              />
            )
          ) : (
            <div className="h-full flex flex-col bg-[#070b14] overflow-auto p-4 items-center justify-center">
              {loadingSankey ? (
                <div className="flex items-center text-slate-400 space-x-2">
                  <span className="w-3 h-3 border-2 border-cyan-400 border-t-transparent rounded-full animate-spin" />
                  <span className="text-xs font-mono">Rendering 4-Stage SVG Sankey Money Trail...</span>
                </div>
              ) : sankeySvg ? (
                <div
                  className="w-full max-w-5xl overflow-auto border border-slate-800 rounded-lg p-3 shadow-2xl bg-[#090d16]"
                  dangerouslySetInnerHTML={{ __html: sankeySvg }}
                />
              ) : (
                <div className="text-center text-slate-500">
                  <p>Unable to load Sankey vector canvas.</p>
                  <button
                    onClick={fetchSankey}
                    className="mt-2 px-3 py-1 bg-cyan-600 text-white rounded text-xs cursor-pointer hover:bg-cyan-500"
                  >
                    Retry Render
                  </button>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Right Intelligence & Alerts Sidebar (width: 380px) */}
        <div className="w-96 bg-[#090f1d] border-l border-[#1e293b] flex flex-col overflow-y-auto p-3 space-y-3 shrink-0 text-xs select-text">
          {/* A. Critical Mule Behavior Alerts */}
          <div className="space-y-2">
            <div className="flex items-center space-x-1.5 text-amber-400 font-bold uppercase tracking-wider text-[11px]">
              <ShieldAlert className="w-4 h-4 text-amber-400" />
              <span>Critical Mule Alerts ({muleAlerts.length})</span>
            </div>

            {muleAlerts.length === 0 ? (
              <div className="p-3 bg-slate-900/60 border border-slate-800 rounded text-slate-500 text-center font-mono">
                {Boolean(store.caseManifest || store.upiTransactions.length > 0) ? 'No abnormal mule layering patterns detected.' : 'Awaiting evidence ingestion...'}
              </div>
            ) : (
              <div className="space-y-1.5">
                {muleAlerts.map((alert, idx) => (
                  <div
                    key={idx}
                    className="p-2.5 rounded bg-amber-950/40 border border-amber-800/80 text-amber-200 space-y-1 font-mono text-[11px]"
                  >
                    <div className="flex items-center justify-between font-bold">
                      <span className="text-amber-300">{alert.alert_type || alert.type || 'MULE_BEHAVIOR'}</span>
                      <span className="text-[10px] px-1 bg-amber-900 rounded text-amber-100">
                        RISK: {alert.risk_level || 'CRITICAL'}
                      </span>
                    </div>
                    <p className="text-slate-300 font-sans leading-tight">
                      {alert.description || alert.message || alert.details || JSON.stringify(alert)}
                    </p>
                    {alert.vpa && (
                      <div className="text-[10px] text-cyan-300 truncate">
                        Target VPA: {alert.vpa}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* B. Syndicate Roles Classification */}
          <div className="space-y-2 pt-2 border-t border-[#1e293b]">
            <div className="flex items-center space-x-1.5 text-cyan-400 font-bold uppercase tracking-wider text-[11px]">
              <Layers className="w-4 h-4 text-cyan-400" />
              <span>Syndicate Roles ({syndicateRoles.length})</span>
            </div>

            {syndicateRoles.length === 0 ? (
              <div className="p-3 bg-slate-900/60 border border-slate-800 rounded text-slate-500 text-center font-mono">
                No syndicate entities classified.
              </div>
            ) : (
              <div className="space-y-1.5">
                {syndicateRoles.map((role, idx) => (
                  <div
                    key={idx}
                    className="p-2 rounded bg-slate-900 border border-slate-800 space-y-0.5 font-mono text-[11px]"
                  >
                    <div className="flex items-center justify-between">
                      <span className="text-slate-100 font-bold truncate max-w-[200px]" title={role.entity || role.vpa || ''}>
                        {role.entity || role.vpa || 'Node'}
                      </span>
                      <span className="text-[10px] px-1.5 py-0.2 rounded font-bold bg-cyan-950 text-cyan-300 border border-cyan-800">
                        {role.role || role.classification || 'Mule Intermediary'}
                      </span>
                    </div>
                    <div className="text-[10px] text-slate-400 flex justify-between">
                      <span>Inflow: ₹{Number(role.total_inflow || role.inflow || 0).toLocaleString()}</span>
                      <span>Outflow: ₹{Number(role.total_outflow || role.outflow || 0).toLocaleString()}</span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* C. Traced Charge Sheet Chain */}
          {chainResult && (
            <div className="space-y-2 pt-2 border-t border-[#1e293b]">
              <div className="flex items-center space-x-1.5 text-emerald-400 font-bold uppercase tracking-wider text-[11px]">
                <GitBranch className="w-4 h-4 text-emerald-400" />
                <span>Traced Charge Sheet Chain</span>
              </div>
              <div className="p-2.5 rounded bg-emerald-950/30 border border-emerald-800/80 font-mono text-[11px] space-y-1">
                <div className="text-emerald-300 font-bold">
                  {chainResult.summary || 'Evidence Chain Constructed'}
                </div>
                <div className="text-slate-300 text-[10px] whitespace-pre-wrap leading-relaxed">
                  {typeof chainResult === 'string' ? chainResult : JSON.stringify(chainResult, null, 2)}
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

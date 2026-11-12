import React, { useEffect, useRef, useState } from 'react';
import { ChevronDown, FileArchive, FolderOpen, Search, Settings } from 'lucide-react';
import { useWorkbenchStore } from '../state/workbenchStore';
import { useUi } from '../state/uiStore';
import { forensicClient, HealthResponse, EvidenceItemSummary } from '../api/forensicClient';
import { integrityText } from './integrity';

interface CaseBarProps {
  onPickFile: () => void;
  onPickFolder: () => void;
}

export const CaseBar: React.FC<CaseBarProps> = ({ onPickFile, onPickFolder }) => {
  const caseManifest = useWorkbenchStore((s) => s.caseManifest);
  const integrity = useWorkbenchStore((s) => s.integrity);
  const open = useUi((s) => s.open);
  const [health, setHealth] = useState<HealthResponse>({ status: 'CHECKING' });
  const [menu, setMenu] = useState(false);
  const menuRef = useRef<HTMLDivElement | null>(null);
  const syncWithBackendCase = useWorkbenchStore((s) => s.syncWithBackendCase);
  const [devices, setDevices] = useState<EvidenceItemSummary[]>([]);
  const [activeDevice, setActiveDevice] = useState('');

  useEffect(() => {
    if (!caseManifest) { setDevices([]); return; }
    let alive = true;
    void forensicClient.getEvidenceItems().then((d) => { if (alive) { setDevices(d); setActiveDevice((cur) => cur || d[d.length - 1]?.item_id || ''); } });
    return () => { alive = false; };
  }, [caseManifest?.caseId, caseManifest?.evidenceFileName]); // eslint-disable-line react-hooks/exhaustive-deps

  const switchDevice = async (id: string) => {
    if (await forensicClient.selectActiveItem(id)) {
      setActiveDevice(id);
      await syncWithBackendCase();
    }
  };

  useEffect(() => {
    let alive = true;
    const tick = async () => {
      const h = await forensicClient.checkHealth();
      if (alive) setHealth(h);
    };
    void tick();
    const id = setInterval(tick, 10000);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, []);

  useEffect(() => {
    if (!menu) return;
    const close = (e: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) setMenu(false);
    };
    const esc = (e: KeyboardEvent) => e.key === 'Escape' && setMenu(false);
    document.addEventListener('mousedown', close);
    document.addEventListener('keydown', esc);
    return () => {
      document.removeEventListener('mousedown', close);
      document.removeEventListener('keydown', esc);
    };
  }, [menu]);

  const online = health.status === 'HEALTHY' || health.status === 'ONLINE';
  const checking = health.status === 'CHECKING';
  const integ = integrityText(integrity);
  const toneClass = integ.tone === 'ok' ? 'text-emerald-300' : integ.tone === 'bad' ? 'text-rose-300 font-semibold' : 'text-slate-300';

  return (
    <header className="h-12 shrink-0 flex items-center gap-4 px-4 bg-slate-900 border-b border-slate-800" data-region="case-bar" tabIndex={-1}>
      <div className="flex items-baseline gap-2 min-w-0">
        <span className="font-semibold text-slate-50 tracking-tight">BharatAnalyzer</span>
        <span className="text-slate-500">/</span>
        <span className="truncate text-slate-200" title={caseManifest?.evidencePath || ''}>
          {caseManifest ? `${caseManifest.caseId} · ${caseManifest.evidenceFileName}` : 'No case open'}
        </span>
      </div>

      <div className={`hidden md:block truncate ${toneClass}`} title={integ.detail} data-testid="integrity-line">
        {integ.text}
      </div>

      <div className="ml-auto flex items-center gap-2">
        {devices.length > 1 && (
          <label className="flex items-center gap-1.5 text-slate-300">
            <span className="hidden lg:inline">Device</span>
            <select aria-label="Device the owner profile and link graph describe" value={activeDevice} onChange={(e) => void switchDevice(e.target.value)}
              className="h-8 rounded bg-slate-950 border border-slate-700 px-2 text-slate-100" title="Records of every device stay in the case; this chooses which device the owner profile, link graph and alerts describe.">
              {devices.map((d) => <option key={d.item_id} value={d.item_id}>{d.label || d.item_id}{d.model && d.model !== 'Not recorded' ? ` (${d.model})` : ''}</option>)}
            </select>
          </label>
        )}
        <span className="flex items-center gap-1.5 text-slate-300" title={`Backend: ${health.status}`}>
          <span className={`w-2 h-2 rounded-full ${online ? 'bg-emerald-400' : checking ? 'bg-slate-500' : 'bg-rose-400'}`} aria-hidden="true" />
          {online ? 'Engine ready' : checking ? 'Engine starting' : 'Engine not reachable'}
        </span>

        <div className="relative" ref={menuRef}>
          <button
            onClick={() => setMenu((m) => !m)}
            aria-haspopup="menu"
            aria-expanded={menu}
            className="flex items-center gap-1 h-8 px-3 rounded bg-cyan-600 text-slate-50 hover:bg-cyan-500 font-medium"
          >
            Open evidence <ChevronDown className="w-4 h-4" />
          </button>
          {menu && (
            <div role="menu" className="absolute right-0 mt-1 w-72 rounded border border-slate-700 bg-slate-900 shadow-xl z-50 py-1">
              <button role="menuitem" className="w-full flex items-center gap-2 px-3 py-2 text-left hover:bg-slate-800" onClick={() => { setMenu(false); onPickFile(); }}>
                <FileArchive className="w-4 h-4 text-slate-300" /> Archive or image file…
              </button>
              <button role="menuitem" className="w-full flex items-center gap-2 px-3 py-2 text-left hover:bg-slate-800" onClick={() => { setMenu(false); onPickFolder(); }}>
                <FolderOpen className="w-4 h-4 text-slate-300" /> Extracted folder…
              </button>
              <button role="menuitem" className="w-full flex items-center gap-2 px-3 py-2 text-left hover:bg-slate-800" onClick={() => { setMenu(false); open('ADD_EXTRACTION'); }}>
                <FolderOpen className="w-4 h-4 text-slate-300" /> More options…
              </button>
            </div>
          )}
        </div>

        <button onClick={() => open('PALETTE')} className="flex items-center gap-2 h-8 px-3 rounded border border-slate-700 text-slate-300 hover:bg-slate-800" title="Search and commands (Ctrl+K)">
          <Search className="w-4 h-4" />
          <span className="hidden lg:inline">Search or jump</span>
          <kbd className="hidden lg:inline text-[0.6875rem] text-slate-400 border border-slate-700 rounded px-1">Ctrl K</kbd>
        </button>
        <button onClick={() => open('SETTINGS')} className="h-8 w-8 grid place-items-center rounded border border-slate-700 text-slate-300 hover:bg-slate-800" aria-label="Display settings" title="Display settings">
          <Settings className="w-4 h-4" />
        </button>
      </div>
    </header>
  );
};

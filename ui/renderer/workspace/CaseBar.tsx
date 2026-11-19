import React, { useEffect, useRef, useState } from 'react';
import { ChevronDown, FileArchive, FolderOpen, Search, Settings } from 'lucide-react';
import { useWorkbenchStore } from '../state/workbenchStore';
import { useUi } from '../state/uiStore';
import { forensicClient, HealthResponse, EvidenceItemSummary } from '../api/forensicClient';
import { integrityText } from './integrity';
import { Button } from '../components/ui';

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
  const pill = integ.tone === 'ok' ? 'bg-ok-soft text-ok' : integ.tone === 'bad' ? 'bg-rec-soft text-rec' : 'bg-sunken text-muted';
  const itemClass = 'w-full flex items-center gap-2 px-3 py-2 text-left text-ink hover:bg-hover';

  return (
    <header className="h-[54px] shrink-0 flex items-center gap-3.5 px-4 bg-surface border-b border-line min-w-0" data-region="case-bar" tabIndex={-1}>
      <div className="flex items-center gap-2 font-bold tracking-tight whitespace-nowrap">
        <span className="w-[26px] h-[26px] rounded-[7px] bg-accent text-on-accent grid place-items-center text-[0.75rem] font-bold" aria-hidden="true">BA</span>
        <span className="hidden sm:inline">BharatAnalyzer</span>
      </div>

      <div className="hidden md:flex flex-col leading-tight min-w-0 pl-3.5 border-l border-line" title={caseManifest?.evidencePath || ''}>
        <b className="font-semibold truncate">{caseManifest ? caseManifest.caseId : 'No case open'}</b>
        <span className="text-[0.75rem] text-muted truncate">{caseManifest ? caseManifest.evidenceFileName : 'Open evidence to begin'}</span>
      </div>

      <span className={`hidden lg:inline-flex items-center gap-1.5 px-2.5 py-[3px] rounded-full text-[0.75rem] font-semibold whitespace-nowrap ${pill}`} title={integ.detail} data-testid="integrity-line">
        <span className="w-[7px] h-[7px] rounded-full bg-current" aria-hidden="true" />
        {integ.text}
      </span>

      <button onClick={() => open('PALETTE')} title="Search and commands (Ctrl+K)"
        className="ml-auto flex-1 max-w-[460px] min-w-0 flex items-center gap-2 h-[34px] px-2.5 border border-line-strong rounded-lg bg-sunken text-muted text-left hover:bg-hover">
        <Search className="w-4 h-4 shrink-0" aria-hidden="true" />
        <span className="flex-1 truncate">Search or jump</span>
        <kbd className="hidden lg:inline font-mono text-[0.6875rem] px-1.5 border border-line-strong rounded bg-surface text-muted">Ctrl K</kbd>
      </button>

      <div className="flex items-center gap-2.5 shrink-0">
        {devices.length > 1 && (
          <label className="flex items-center gap-1.5 text-muted">
            <span className="hidden xl:inline">Device</span>
            <select aria-label="Device the owner profile and link graph describe" value={activeDevice} onChange={(e) => void switchDevice(e.target.value)}
              className="h-8 rounded-lg bg-surface border border-line-strong px-2 text-ink" title="Records of every device stay in the case; this chooses which device the owner profile, link graph and alerts describe.">
              {devices.map((d) => <option key={d.item_id} value={d.item_id}>{d.label || d.item_id}{d.model && d.model !== 'Not recorded' ? ` (${d.model})` : ''}</option>)}
            </select>
          </label>
        )}
        <span className="hidden xl:flex items-center gap-1.5 text-muted" title={`Backend: ${health.status}`}>
          <span className={`w-2 h-2 rounded-full ${online ? 'bg-ok' : checking ? 'bg-faint' : 'bg-rec'}`} aria-hidden="true" />
          {online ? 'Engine ready' : checking ? 'Engine starting' : 'Engine not reachable'}
        </span>

        <div className="relative" ref={menuRef}>
          <Button variant="primary" onClick={() => setMenu((m) => !m)} aria-haspopup="menu" aria-expanded={menu}>
            Open evidence <ChevronDown className="w-4 h-4" />
          </Button>
          {menu && (
            <div role="menu" className="absolute right-0 mt-1 w-72 rounded-[10px] border border-line bg-surface shadow-float z-50 py-1">
              <button role="menuitem" className={itemClass} onClick={() => { setMenu(false); onPickFile(); }}>
                <FileArchive className="w-4 h-4 text-muted" /> Archive or image file…
              </button>
              <button role="menuitem" className={itemClass} onClick={() => { setMenu(false); onPickFolder(); }}>
                <FolderOpen className="w-4 h-4 text-muted" /> Extracted folder…
              </button>
              <button role="menuitem" className={itemClass} onClick={() => { setMenu(false); open('ADD_EXTRACTION'); }}>
                <FolderOpen className="w-4 h-4 text-muted" /> More options…
              </button>
            </div>
          )}
        </div>

        <Button variant="icon" onClick={() => open('SETTINGS')} aria-label="Display settings" title="Display settings">
          <Settings className="w-4 h-4" />
        </Button>
      </div>
    </header>
  );
};

import React, { useCallback, useEffect, useRef } from 'react';
import { PanelRightClose, PanelRightOpen } from 'lucide-react';
import { CaseBar } from './CaseBar';
import { StageNavigator } from './StageNavigator';
import { Workspace } from './Workspace';
import { StatusLine } from './StatusLine';
import { CommandPalette } from './CommandPalette';
import { SettingsDialog } from './SettingsDialog';
import { Toasts } from './Toasts';
import { EvidenceCard, buildPin } from '../inspectors/EvidenceCard';
import { Sec63BsaModal } from '../views/Sec63BsaModal';
import { Sec230BnssModal } from '../views/Sec230BnssModal';
import { Ncrp1930FreezeModal } from '../views/Ncrp1930FreezeModal';
import { AddExtractionModal } from '../views/AddExtractionModal';
import { useWorkbenchStore } from '../state/workbenchStore';
import { useFindings } from '../state/findingsStore';
import { usePreferences, applyPreferences } from '../state/preferencesStore';
import { useUi } from '../state/uiStore';
import { forensicClient } from '../api/forensicClient';
import { STAGES } from './stages';

const REGIONS = ['stages', 'workspace', 'card'];

/** A thin bar between two panes that resizes the pane on its inside edge by dragging or with the arrow keys. */
const Splitter: React.FC<{ label: string; onDelta: (dx: number) => void }> = ({ label, onDelta }) => {
  const last = useRef<number | null>(null);
  return (
    <div
      role="separator"
      aria-orientation="vertical"
      aria-label={label}
      tabIndex={0}
      className="w-1.5 shrink-0 cursor-col-resize bg-slate-800 hover:bg-cyan-700 focus-visible:bg-cyan-600"
      onPointerDown={(e) => { last.current = e.clientX; (e.target as HTMLElement).setPointerCapture(e.pointerId); }}
      onPointerMove={(e) => { if (last.current !== null) { onDelta(e.clientX - last.current); last.current = e.clientX; } }}
      onPointerUp={() => { last.current = null; }}
      onKeyDown={(e) => {
        if (e.key === 'ArrowLeft') { e.preventDefault(); onDelta(-16); }
        if (e.key === 'ArrowRight') { e.preventDefault(); onDelta(16); }
      }}
    />
  );
};

export const AppShell: React.FC = () => {
  const syncWithBackendCase = useWorkbenchStore((s) => s.syncWithBackendCase);
  const addToast = useWorkbenchStore((s) => s.addToast);
  const setActiveTab = useWorkbenchStore((s) => s.setActiveTab);
  const isBsaModalOpen = useWorkbenchStore((s) => s.isBsaModalOpen);
  const setIsBsaModalOpen = useWorkbenchStore((s) => s.setIsBsaModalOpen);
  const upi = useWorkbenchStore((s) => s.upiTransactions);
  const chats = useWorkbenchStore((s) => s.chats);
  const apk = useWorkbenchStore((s) => s.apkFindings);
  const caseId = useWorkbenchStore((s) => s.caseManifest?.caseId);
  const loadFindings = useFindings((s) => s.load);
  const prefs = usePreferences();
  const dialog = useUi((s) => s.dialog);
  const open = useUi((s) => s.open);
  const close = useUi((s) => s.close);

  useEffect(() => { applyPreferences(prefs); }, []); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => { void syncWithBackendCase(); }, [syncWithBackendCase]);
  useEffect(() => { void loadFindings(); }, [loadFindings, caseId]);

  const ingest = useCallback(async (picker: () => Promise<string | null | undefined>, what: string) => {
    try {
      const selected = await picker();
      if (!selected) return;
      const res = await forensicClient.ingestCase(selected);
      if (res && res.success) {
        addToast({ type: 'success', title: 'Evidence opened', message: `Loaded ${what} "${res.case_name || selected}".` });
        await syncWithBackendCase();
        setActiveTab('SUMMARY');
      }
    } catch (e: unknown) {
      addToast({ type: 'error', title: 'Could not open evidence', message: e instanceof Error ? e.message : 'Selection failed' });
    }
  }, [addToast, syncWithBackendCase, setActiveTab]);

  const pickFile = useCallback(() => void ingest(() => forensicClient.pickEvidenceFile(), 'file'), [ingest]);
  const pickFolder = useCallback(() => void ingest(() => forensicClient.pickEvidenceFolder(), 'folder'), [ingest]);

  // Global keys: Ctrl+K palette, Ctrl+B pin, Alt+1..8 stage, F6 next region
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const mod = e.ctrlKey || e.metaKey;
      if (mod && e.key.toLowerCase() === 'k') { e.preventDefault(); open('PALETTE'); return; }
      if (mod && e.key.toLowerCase() === 'b') {
        const sel = useWorkbenchStore.getState().selectedArtifact;
        if (sel) {
          e.preventDefault();
          void useFindings.getState().pin(buildPin(sel, ''));
        }
        return;
      }
      if (e.altKey && /^[1-8]$/.test(e.key)) { e.preventDefault(); setActiveTab(STAGES[Number(e.key) - 1].views[0].tab); return; }
      if (e.key === 'F6') {
        e.preventDefault();
        const els = REGIONS.map((r) => document.querySelector<HTMLElement>(`[data-region="${r}"]`)).filter(Boolean) as HTMLElement[];
        const cur = els.findIndex((el) => el.contains(document.activeElement));
        els[(cur + 1) % els.length]?.focus();
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, setActiveTab]);

  // Optional 20-20-20 reminder
  useEffect(() => {
    if (!prefs.breakReminder) return;
    const id = setInterval(() => addToast({ type: 'info', title: 'Rest your eyes', message: 'Look at something 20 feet away for 20 seconds.' }), 20 * 60 * 1000);
    return () => clearInterval(id);
  }, [prefs.breakReminder, addToast]);

  return (
    <div className="h-screen w-screen flex flex-col bg-slate-950 text-slate-200 overflow-hidden">
      <a href="#main-workspace" className="sr-only focus:not-sr-only focus:absolute focus:z-[200] focus:bg-cyan-600 focus:text-slate-50 focus:px-3 focus:py-1" onClick={(e) => { e.preventDefault(); document.querySelector<HTMLElement>('[data-region="workspace"]')?.focus(); }}>
        Skip to workspace
      </a>
      <CaseBar onPickFile={pickFile} onPickFolder={pickFolder} />

      <div className="flex-1 flex min-h-0">
        <div style={{ width: prefs.navCollapsed ? 56 : prefs.navWidth }} className="shrink-0 min-h-0">
          <StageNavigator />
        </div>
        {!prefs.navCollapsed && <Splitter label="Resize stage list" onDelta={(dx) => prefs.set({ navWidth: prefs.navWidth + dx })} />}

        <div id="main-workspace" className="flex-1 min-w-0 min-h-0"><Workspace /></div>

        {prefs.cardOpen ? (
          <>
            <Splitter label="Resize evidence card" onDelta={(dx) => prefs.set({ cardWidth: prefs.cardWidth - dx })} />
            <aside style={{ width: prefs.cardWidth }} className="shrink-0 min-h-0 bg-slate-900 border-l border-slate-800 relative" aria-label="Evidence card" data-region="card" tabIndex={-1}>
              <button onClick={() => prefs.set({ cardOpen: false })} className="absolute top-2 right-12 z-10 p-1 rounded text-slate-400 hover:text-slate-100 hover:bg-slate-800" aria-label="Hide evidence card">
                <PanelRightClose className="w-4 h-4" />
              </button>
              <EvidenceCard />
            </aside>
          </>
        ) : (
          <button onClick={() => prefs.set({ cardOpen: true })} className="w-9 shrink-0 border-l border-slate-800 bg-slate-900 text-slate-300 hover:bg-slate-800 grid place-items-start justify-items-center pt-3" aria-label="Show evidence card">
            <PanelRightOpen className="w-4 h-4" />
          </button>
        )}
      </div>

      <StatusLine />
      <Toasts />
      <CommandPalette onPickFile={pickFile} onPickFolder={pickFolder} />
      <SettingsDialog />

      <AddExtractionModal isOpen={dialog === 'ADD_EXTRACTION'} onClose={close} />
      <Sec63BsaModal
        isOpen={isBsaModalOpen}
        onClose={() => setIsBsaModalOpen(false)}
        counts={{ upiCount: upi.length, walCount: 0, carvedCount: 0, apkCount: apk.length, remoteCount: 0, chatCount: chats.length }}
      />
      <Sec230BnssModal isOpen={dialog === 'SEC230'} onClose={close} />
      <Ncrp1930FreezeModal isOpen={dialog === 'NCRP'} onClose={close} />
    </div>
  );
};

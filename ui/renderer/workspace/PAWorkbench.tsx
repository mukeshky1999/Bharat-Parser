import React, { useState, useEffect } from 'react';
import {
  AlertCircle,
  AlertTriangle,
  CheckCircle2,
  X
} from 'lucide-react';
import { TopRibbonBar } from './TopRibbonBar';
import { LeftVerticalRail, RailItem } from './LeftVerticalRail';
import { ProjectTreeDock } from './ProjectTreeDock';
import { CenterTabCanvas } from './CenterTabCanvas';
import { PAFieldInspector } from '../inspectors/PAFieldInspector';
import { SyncedHexViewer } from '../inspectors/SyncedHexViewer';
import { Sec63BsaModal } from '../views/Sec63BsaModal';
import { Sec230BnssModal } from '../views/Sec230BnssModal';
import { Ncrp1930FreezeModal } from '../views/Ncrp1930FreezeModal';
import { AddExtractionModal } from '../views/AddExtractionModal';
import { useWorkbenchStore } from '../state/workbenchStore';
import { forensicClient } from '../api/forensicClient';

const ToastNotificationContainer: React.FC = () => {
  const toasts = useWorkbenchStore((state) => state.toasts);
  const dismissToast = useWorkbenchStore((state) => state.dismissToast);

  if (!toasts || toasts.length === 0) return null;

  return (
    <div className="fixed bottom-6 right-6 z-[9999] flex flex-col space-y-2.5 max-w-md pointer-events-none">
      {toasts.map((toast) => {
        const isError = toast.type === 'error';
        const isWarn = toast.type === 'warning';
        const isSuccess = toast.type === 'success';

        return (
          <div
            key={toast.id}
            role="alert"
            className={`pointer-events-auto p-3.5 rounded-lg shadow-2xl border flex items-start space-x-3 text-xs transition-all duration-200 backdrop-blur-md animate-in fade-in slide-in-from-bottom-2 ${
              isError
                ? 'bg-rose-950/95 border-rose-600/80 text-rose-100 shadow-rose-950/50'
                : isWarn
                ? 'bg-amber-950/95 border-amber-600/80 text-amber-100 shadow-amber-950/50'
                : isSuccess
                ? 'bg-emerald-950/95 border-emerald-600/80 text-emerald-100 shadow-emerald-950/50'
                : 'bg-slate-900/95 border-slate-700 text-slate-100 shadow-slate-950/50'
            }`}
          >
            {isError ? (
              <AlertCircle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
            ) : isWarn ? (
              <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
            ) : (
              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
            )}
            <div className="flex-1 pr-1 min-w-0">
              {toast.title && (
                <div className="font-bold text-[11px] mb-0.5 tracking-wide uppercase">
                  {toast.title}
                </div>
              )}
              <div className="text-[11px] leading-relaxed opacity-95 break-words font-mono">
                {toast.message}
              </div>
            </div>
            <button
              onClick={() => dismissToast(toast.id)}
              className="text-slate-400 hover:text-white p-0.5 rounded transition-colors cursor-pointer"
              title="Dismiss Notification"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          </div>
        );
      })}
    </div>
  );
};

export const PAWorkbench: React.FC = () => {
  const {
    upiTransactions,
    chats,
    apkFindings,
    isBsaModalOpen,
    setIsBsaModalOpen,
    syncWithBackendCase,
    setActiveTab,
    addToast
  } = useWorkbenchStore();

  const [activeRailItem, setActiveRailItem] = useState<RailItem>('Analyzed Data');
  const [isAddExtractionModalOpen, setIsAddExtractionModalOpen] = useState(false);
  const [isSec230ModalOpen, setIsSec230ModalOpen] = useState(false);
  const [isNcrpFreezeModalOpen, setIsNcrpFreezeModalOpen] = useState(false);

  useEffect(() => {
    // Check backend case state on boot; if loaded, syncs artifacts; otherwise stays clean
    syncWithBackendCase();
  }, [syncWithBackendCase]);

  const handlePickEvidenceFile = async () => {
    try {
      const selectedPath = await forensicClient.pickEvidenceFile();
      if (selectedPath) {
        const res = await forensicClient.ingestCase(selectedPath);
        if (res && res.success) {
          addToast({
            type: 'success',
            title: 'Evidence Ingested',
            message: `Loaded case "${res.case_name || 'Container'}" successfully.`
          });
          await syncWithBackendCase();
        }
      }
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Error picking evidence file';
      addToast({
        type: 'error',
        title: 'File Selection Failure',
        message: msg
      });
    }
  };

  const handlePickEvidenceFolder = async () => {
    try {
      const selectedPath = await forensicClient.pickEvidenceFolder();
      if (selectedPath) {
        const res = await forensicClient.ingestCase(selectedPath);
        if (res && res.success) {
          addToast({
            type: 'success',
            title: 'Directory Ingested',
            message: `Loaded folder "${res.case_name || 'Dump'}" successfully.`
          });
          await syncWithBackendCase();
        }
      }
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Error picking evidence directory';
      addToast({
        type: 'error',
        title: 'Folder Selection Failure',
        message: msg
      });
    }
  };

  return (
    <div className="h-screen w-screen flex flex-col bg-[#0b1120] text-slate-100 overflow-hidden select-none font-sans">
      {/* Top Application Command Bar */}
      <TopRibbonBar
        onOpenAddExtractionModal={() => setIsAddExtractionModalOpen(true)}
        onPickEvidenceFile={handlePickEvidenceFile}
        onPickEvidenceFolder={handlePickEvidenceFolder}
        onOpenFusionModal={() => setActiveTab('CALL_LOGS')}
        onOpenSec230Modal={() => setIsSec230ModalOpen(true)}
        onOpenNcrpFreezeModal={() => setIsNcrpFreezeModalOpen(true)}
      />

      {/* Main Forensic Shell */}
      <div className="flex-1 flex overflow-hidden">
        {/* Far-Left Vertical Icon Rail */}
        <LeftVerticalRail
          activeRailItem={activeRailItem}
          onSelectRailItem={setActiveRailItem}
        />

        {/* Left Evidence & Intelligence Navigator */}
        <ProjectTreeDock />

        {/* Center Canvas */}
        <CenterTabCanvas onOpenAddExtraction={() => setIsAddExtractionModalOpen(true)} />

        {/* Right Dock: Forensic Provenance & Field Inspector */}
        <PAFieldInspector />
      </div>

      {/* Bottom Collapsible Hex & Raw Payload Inspector */}
      <SyncedHexViewer />

      {/* Global Toast Notification System */}
      <ToastNotificationContainer />

      {/* Modal 1: + Add Extraction / Open Dump */}
      <AddExtractionModal
        isOpen={isAddExtractionModalOpen}
        onClose={() => setIsAddExtractionModalOpen(false)}
      />

      {/* Modal 2: Section 63 BSA (2023) Statutory Certificate Modal */}
      <Sec63BsaModal
        isOpen={isBsaModalOpen}
        onClose={() => setIsBsaModalOpen(false)}
        counts={{
          upiCount: upiTransactions.length || 0,
          walCount: 0,
          carvedCount: 0,
          apkCount: apkFindings.length || 0,
          remoteCount: 0,
          chatCount: chats.length || 0
        }}
      />

      {/* Modal 3: Section 230 BNSS (2023) Defense Disclosure Modal */}
      <Sec230BnssModal
        isOpen={isSec230ModalOpen}
        onClose={() => setIsSec230ModalOpen(false)}
      />

      {/* Modal 4: 1930 NCRP / I4C CFCFRMS Bank Freeze Modal */}
      <Ncrp1930FreezeModal
        isOpen={isNcrpFreezeModalOpen}
        onClose={() => setIsNcrpFreezeModalOpen(false)}
      />
    </div>
  );
};

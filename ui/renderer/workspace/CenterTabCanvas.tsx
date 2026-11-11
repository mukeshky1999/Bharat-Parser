import React, { useState } from 'react';
import { useWorkbenchStore, ActiveTabType } from '../state/workbenchStore';
import { ExtractionSummaryTab } from '../views/ExtractionSummaryTab';
import { PATableWorkspace } from './PATableWorkspace';
import { ChatsMasterWorkspace } from '../views/ChatsMasterWorkspace';
import { UPIMasterLedgerView } from '../views/UPIMasterLedgerView';
import { BankCdrFusionView } from '../views/BankCdrFusionView';
import { SQLiteWizardTab } from '../views/SQLiteWizardTab';
import { MuleLinkGraphTab } from '../views/MuleLinkGraphTab';
import { MaliciousApkView } from '../views/MaliciousApkView';
import { RemoteAccessView } from '../views/RemoteAccessView';
import { OsSpilloverView } from '../views/OsSpilloverView';
import { LocationsMediaView } from '../views/LocationsMediaView';
import { CryptoWalletView } from '../views/CryptoWalletView';
import { FileSystemExplorerTab } from '../views/FileSystemExplorerTab';

interface CenterTabCanvasProps {
  onOpenAddExtraction?: () => void;
}

interface DocumentTab {
  id: ActiveTabType | 'WELCOME';
  title: string;
  count?: number;
  hasDot?: boolean;
}

export const CenterTabCanvas: React.FC<CenterTabCanvasProps> = ({ onOpenAddExtraction }) => {
  const {
    activeTab,
    setActiveTab,
    chats,
    upiTransactions,
    contacts,
    apkFindings,
    setSelectedArtifact,
  } = useWorkbenchStore();

  const handleSelectProvenance = (prov: any) => {
    if (prov) {
      setSelectedArtifact({
        id: `GEN_${prov.byteOffset?.toString(16) || Date.now()}`,
        provenance: prov,
        notes: `Inspected from ${prov.tableName || 'VFS'}`
      });
    }
  };

  const [openTabs, setOpenTabs] = useState<DocumentTab[]>([
    { id: 'SUMMARY', title: 'Case Overview', hasDot: true },
    { id: 'CHATS', title: 'Chats & Social Comms', hasDot: true },
    { id: 'UPI_LEDGER', title: 'UPI & Banking Ledger', hasDot: true },
    { id: 'CONTACTS', title: 'Saved Contacts', hasDot: true },
  ]);

  const handleCloseTab = (tabId: ActiveTabType | 'WELCOME', e: React.MouseEvent) => {
    e.stopPropagation();
    if (openTabs.length <= 1) return;
    const remaining = openTabs.filter((t) => t.id !== tabId);
    setOpenTabs(remaining);
    if (activeTab === tabId) {
      const nextTab = remaining[remaining.length - 1];
      if (nextTab.id !== 'WELCOME') {
        setActiveTab(nextTab.id as ActiveTabType);
      } else {
        setActiveTab('SUMMARY');
      }
    }
  };

  const handleSelectTab = (tabId: ActiveTabType | 'WELCOME') => {
    if (tabId === 'WELCOME') {
      setActiveTab('SUMMARY');
    } else {
      setActiveTab(tabId);
    }
  };

  const getDynamicCount = (tabId: string) => {
    if (tabId === 'CHATS') return chats.length > 0 ? chats.length : undefined;
    if (tabId === 'UPI_LEDGER') return upiTransactions.length > 0 ? upiTransactions.length : undefined;
    if (tabId === 'CONTACTS') return contacts.length > 0 ? contacts.length : undefined;
    return undefined;
  };

  // Ensure active tab is present in tab strip
  const tabIds = openTabs.map((t) => t.id);
  if (!tabIds.includes(activeTab as any) && activeTab) {
    const tabLabels: Record<string, string> = {
      SUMMARY: 'Case Overview',
      CHATS: 'Chats & Social Comms',
      UPI_LEDGER: 'UPI & Banking Ledger',
      CONTACTS: 'Saved Contacts',
      CALL_LOGS: 'Calls Log',
      OS_SPILLOVER: 'OS Spillover',
      LOCATIONS_MEDIA: 'Locations & Media',
      SQLITE_WIZARD: 'SQLite Wizard',
      MULE_GRAPH: 'Syndicate Link Graph',
      MALICIOUS_APKS: 'Mule APKs',
      REMOTE_ACCESS: 'Remote Access',
      CRYPTO: 'Crypto Wallets',
      FILE_SYSTEM: 'VFS Browser',
    };
    setOpenTabs((prev) => [
      ...prev,
      {
        id: activeTab,
        title: tabLabels[activeTab] || activeTab,
        hasDot: true,
      },
    ]);
  }

  return (
    <main className="flex-1 flex flex-col overflow-hidden bg-[#0b1320] text-slate-100">
      {/* Top Document Tab Strip */}
      <div className="h-[36px] bg-[#090f1d] border-b border-[#1e293b] flex items-center px-2 space-x-1 shrink-0 overflow-x-auto text-xs select-none">
        {openTabs.map((tab) => {
          const isActive = activeTab === tab.id;
          const dynamicCount = getDynamicCount(tab.id);

          return (
            <div
              key={tab.id}
              onClick={() => handleSelectTab(tab.id)}
              className={`h-[30px] px-3 rounded-t-md flex items-center space-x-1.5 transition-colors cursor-pointer border-t-2 ${
                isActive
                  ? 'bg-[#111c2e] text-cyan-300 font-bold border-cyan-500 shadow-md'
                  : 'bg-[#0e1726] text-slate-400 hover:bg-[#131f33] hover:text-slate-200 border-transparent'
              }`}
            >
              {tab.hasDot && (
                <span className="w-2 h-2 rounded-full bg-emerald-500 shrink-0 shadow-sm shadow-emerald-500/50" />
              )}
              <span className="truncate max-w-[150px] text-xs">
                {tab.title}
                {dynamicCount !== undefined && ` (${dynamicCount})`}
              </span>
              <button
                onClick={(e) => handleCloseTab(tab.id, e)}
                className="text-slate-500 hover:text-slate-200 ml-1 rounded p-0.5 hover:bg-slate-800"
                title="Close Tab"
              >
                ×
              </button>
            </div>
          );
        })}
      </div>

      {/* Main Tab Workspace Canvas */}
      <div className="flex-1 flex overflow-hidden bg-[#0b1320]">
        {activeTab === 'SUMMARY' && (
          <ExtractionSummaryTab onOpenAddExtractionModal={onOpenAddExtraction} />
        )}
        {activeTab === 'CHATS' && (
          <ChatsMasterWorkspace />
        )}
        {activeTab === 'UPI_LEDGER' && (
          <UPIMasterLedgerView />
        )}
        {activeTab === 'CONTACTS' && (
          <PATableWorkspace title="Contacts & Profiles" category="CONTACTS" />
        )}
        {activeTab === 'CALL_LOGS' && (
          <BankCdrFusionView />
        )}
        {activeTab === 'SQLITE_WIZARD' && (
          <SQLiteWizardTab onSelectRecordProvenance={handleSelectProvenance} />
        )}
        {activeTab === 'MULE_GRAPH' && <MuleLinkGraphTab />}
        {activeTab === 'MALICIOUS_APKS' && (
          <MaliciousApkView findings={apkFindings} onSelectApk={(f) => handleSelectProvenance(f.provenance)} />
        )}
        {activeTab === 'REMOTE_ACCESS' && (
          <RemoteAccessView sessions={[]} onSelectSession={(s) => handleSelectProvenance(s.provenance)} />
        )}
        {activeTab === 'OS_SPILLOVER' && <OsSpilloverView />}
        {activeTab === 'LOCATIONS_MEDIA' && <LocationsMediaView />}
        {activeTab === 'CRYPTO' && (
          <CryptoWalletView onSelectTx={(t) => handleSelectProvenance(t.provenance)} />
        )}
        {activeTab === 'FILE_SYSTEM' && (
          <FileSystemExplorerTab onSelectFileProvenance={handleSelectProvenance} />
        )}
      </div>
    </main>
  );
};

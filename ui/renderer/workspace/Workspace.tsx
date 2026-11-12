import React from 'react';
import { ChevronRight } from 'lucide-react';
import { useWorkbenchStore } from '../state/workbenchStore';
import { stageForTab, viewLabel } from './stages';
import { ExtractionSummaryTab } from '../views/ExtractionSummaryTab';
import { RecordTable } from './RecordTable';
import { ChatsMasterWorkspace } from '../views/ChatsMasterWorkspace';
import { UPIMasterLedgerView } from '../views/UPIMasterLedgerView';
import { BankCdrFusionView } from '../views/BankCdrFusionView';
import { SQLiteWizardTab } from '../views/SQLiteWizardTab';
import { MuleLinkGraphTab } from '../views/MuleLinkGraphTab';
import { OsSpilloverView } from '../views/OsSpilloverView';
import { LocationsMediaView } from '../views/LocationsMediaView';
import { CryptoWalletView } from '../views/CryptoWalletView';
import { FileSystemExplorerTab } from '../views/FileSystemExplorerTab';
import { FindingsView } from '../views/FindingsView';
import { CourtOutputView } from '../views/CourtOutputView';

export const Workspace: React.FC = () => {
  const activeTab = useWorkbenchStore((s) => s.activeTab);
  const setSelectedArtifact = useWorkbenchStore((s) => s.setSelectedArtifact);
  const stage = stageForTab(activeTab);

  const inspect = (prov: any) => {
    if (prov) {
      void setSelectedArtifact({
        id: `${prov.vfsInternalPath || 'file'}#${prov.tableName || ''}#${prov.rowId ?? prov.byteOffset ?? ''}`,
        provenance: prov,
        notes: `Inspected from ${prov.tableName || 'file'}`,
        itemType: 'Database record',
      });
    }
  };

  return (
    <main className="h-full flex flex-col min-w-0 min-h-0 bg-slate-950" data-region="workspace" tabIndex={-1}>
      <div className="h-10 shrink-0 flex items-center gap-2 px-4 border-b border-slate-800 bg-slate-900/60">
        <span className="text-slate-400">Stage {stage.no}</span>
        <ChevronRight className="w-4 h-4 text-slate-600" aria-hidden="true" />
        <span className="text-slate-300">{stage.label}</span>
        <ChevronRight className="w-4 h-4 text-slate-600" aria-hidden="true" />
        <h1 className="text-slate-50 font-semibold">{viewLabel(activeTab)}</h1>
      </div>
      <div className="flex-1 flex overflow-hidden min-h-0">
        {activeTab === 'SUMMARY' && <ExtractionSummaryTab />}
        {activeTab === 'FILE_SYSTEM' && <FileSystemExplorerTab onSelectFileProvenance={inspect} />}
        {activeTab === 'SQLITE_WIZARD' && <SQLiteWizardTab onSelectRecordProvenance={inspect} />}
        {activeTab === 'CONTACTS' && <RecordTable title="Contacts" category="CONTACTS" />}
        {activeTab === 'CALLS' && <RecordTable title="Calls" category="CALLS" />}
        {activeTab === 'UPI_LEDGER' && <UPIMasterLedgerView />}
        {activeTab === 'CALL_LOGS' && <BankCdrFusionView />}
        {activeTab === 'CRYPTO' && <CryptoWalletView onSelectTx={(t) => inspect(t.provenance)} />}
        {activeTab === 'MULE_GRAPH' && <MuleLinkGraphTab />}
        {activeTab === 'CHATS' && <ChatsMasterWorkspace />}
        {activeTab === 'OS_SPILLOVER' && <OsSpilloverView />}
        {activeTab === 'LOCATIONS_MEDIA' && <LocationsMediaView />}
        {activeTab === 'FINDINGS' && <FindingsView />}
        {activeTab === 'COURT_OUTPUT' && <CourtOutputView />}
      </div>
    </main>
  );
};

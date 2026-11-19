import React from 'react';
import { ChevronRight, ArrowLeft } from 'lucide-react';
import { useWorkbenchStore } from '../state/workbenchStore';
import { groupForTab, viewLabel } from './dataTree';
import { Button } from '../components/ui';
import { BankAlertsView } from '../views/BankAlertsView';
import { ExtractionSummaryTab } from '../views/ExtractionSummaryTab';
import { RecordTable } from './RecordTable';
import { ChatsMasterWorkspace } from '../views/ChatsMasterWorkspace';
import { CallsView } from '../views/CallsView';
import { UPIMasterLedgerView } from '../views/UPIMasterLedgerView';
import { BankCdrFusionView } from '../views/BankCdrFusionView';
import { SQLiteWizardTab } from '../views/SQLiteWizardTab';
import { MuleLinkGraphTab } from '../views/MuleLinkGraphTab';
import { OsSpilloverView } from '../views/OsSpilloverView';
import { LocationsMediaView } from '../views/LocationsMediaView';
import { CryptoWalletView } from '../views/CryptoWalletView';
import { FileSystemExplorerTab } from '../views/FileSystemExplorerTab';
import { FindingsView } from '../views/FindingsView';
import { ReportExportView } from '../views/ReportExportView';
import { SearchView } from '../views/SearchView';
import { MediaLibraryView } from '../views/MediaLibraryView';
import { TagsView } from '../views/TagsView';
import { TimelineView } from '../views/TimelineView';

export const Workspace: React.FC = () => {
  const activeTab = useWorkbenchStore((s) => s.activeTab);
  const setSelectedArtifact = useWorkbenchStore((s) => s.setSelectedArtifact);
  const group = groupForTab(activeTab);
  const canGoBack = useWorkbenchStore((s) => s.tabHistory.length > 0);
  const goBack = useWorkbenchStore((s) => s.goBack);

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
    <main className="h-full flex flex-col min-w-0 min-h-0 bg-page" data-region="workspace" tabIndex={-1}>
      <div className="h-11 shrink-0 flex items-center gap-2 px-5 border-b border-line bg-surface text-muted min-w-0">
        {canGoBack && (
          <>
            <Button variant="ghost" onClick={goBack} className="!h-7 !px-2 -ml-2" aria-label="Back to the previous view">
              <ArrowLeft className="w-4 h-4" aria-hidden="true" />Back
            </Button>
            <span className="text-faint" aria-hidden="true">|</span>
          </>
        )}
        {activeTab !== 'SUMMARY' && (
          <>
            <span className="truncate">{group.label}</span>
            <ChevronRight className="w-4 h-4 text-faint shrink-0" aria-hidden="true" />
          </>
        )}
        <h1 className="text-ink font-semibold truncate">{viewLabel(activeTab)}</h1>
      </div>
      <div className="flex-1 flex overflow-hidden min-h-0">
        {activeTab === 'SUMMARY' && <ExtractionSummaryTab />}
        {activeTab === 'FILE_SYSTEM' && <FileSystemExplorerTab onSelectFileProvenance={inspect} />}
        {activeTab === 'SQLITE_WIZARD' && <SQLiteWizardTab onSelectRecordProvenance={inspect} />}
        {activeTab === 'CONTACTS' && <RecordTable title="Contacts" category="CONTACTS" />}
        {activeTab === 'CALLS' && <CallsView />}
        {activeTab === 'UPI_LEDGER' && <UPIMasterLedgerView />}
        {activeTab === 'CALL_LOGS' && <BankCdrFusionView />}
        {activeTab === 'CRYPTO' && <CryptoWalletView onSelectTx={(t) => inspect(t.provenance)} />}
        {activeTab === 'MULE_GRAPH' && <MuleLinkGraphTab />}
        {activeTab === 'CHATS' && <ChatsMasterWorkspace />}
        {activeTab === 'OS_SPILLOVER' && <OsSpilloverView />}
        {activeTab === 'LOCATIONS_MEDIA' && <LocationsMediaView />}
        {activeTab === 'FINDINGS' && <FindingsView />}
        {activeTab === 'REPORT_EXPORT' && <ReportExportView />}
        {activeTab === 'SEARCH' && <SearchView />}
        {activeTab === 'TAGS' && <TagsView />}
        {activeTab === 'MEDIA' && <MediaLibraryView />}
        {activeTab === 'BANK_ALERTS' && <BankAlertsView />}
        {activeTab === 'TIMELINE' && <TimelineView />}
      </div>
    </main>
  );
};

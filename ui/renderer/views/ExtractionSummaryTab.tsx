import React, { useState, useEffect } from 'react';
import {
  FileText,
  Phone,
  MessageSquare,
  Users,
  CreditCard,
  Coins,
  MapPin,
  FolderArchive,
  FolderTree,
  HardDrive,
  PlusCircle,
  AlertCircle,
  Network,
  Database,
  Loader2
} from 'lucide-react';
import {
  DeviceMetadata,
  DualHashResult
} from '../../shared/forensic-types';
import { useWorkbenchStore, ActiveTabType } from '../state/workbenchStore';
import { useUi } from '../state/uiStore';
import { forensicClient, CaseSummaryResponse } from '../api/forensicClient';
import { Panel, PanelHeader } from '../components/Panel';
import { Button } from '../components/Button';
import { Badge } from '../components/Badge';
import { KeyValue } from '../components/KeyValue';
import { KeysNeededCard } from '../inspectors/KeyBrokerPanel';

/** The backend reports a dossier field as a list, a plain string, or a "Not Found" marker. Returns text to show, or null when nothing was found. */
function dossierText(v: unknown): string | null {
  if (Array.isArray(v)) {
    const parts = v.map((x) => String(x ?? '').trim()).filter(Boolean);
    return parts.length ? parts.join(', ') : null;
  }
  if (typeof v === 'string') {
    const t = v.trim();
    return !t || /^(not found|none|n\/a)\b/i.test(t) ? null : t;
  }
  return null;
}

interface ExtractionSummaryTabProps {
  deviceMetadata?: DeviceMetadata;
  dualHashes?: DualHashResult;
}

export const ExtractionSummaryTab: React.FC<ExtractionSummaryTabProps> = ({
  deviceMetadata,
  dualHashes
}) => {
  const {
    setActiveTab,
    caseManifest,
    integrity,
    syncWithBackendCase
  } = useWorkbenchStore();
  const openDialog = useUi((st) => st.open);

  const [backendSummary, setBackendSummary] = useState<CaseSummaryResponse | null>(null);
  const [directPathInput, setDirectPathInput] = useState('');
  const [isIngesting, setIsIngesting] = useState(false);
  const [ingestionPhase, setIngestionPhase] = useState<string>('');
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  useEffect(() => {
    let isMounted = true;
    const fetchSummary = async () => {
      try {
        const data = await forensicClient.getCaseSummary();
        if (isMounted && data) {
          setBackendSummary(data);
        }
      } catch {
        // Fall through
      }
    };
    fetchSummary();
  }, [caseManifest]);

  const isLoaded = Boolean(
    backendSummary?.loaded ||
    caseManifest?.evidenceFileName ||
    dualHashes?.verified
  );

  const handlePickFileAndIngest = async () => {
    setErrorMessage(null);
    try {
      const selectedPath = await forensicClient.pickEvidenceFile();
      if (selectedPath) {
        await startIngestion(selectedPath);
      }
    } catch (err: any) {
      setErrorMessage(err.message || 'File selection failed.');
    }
  };

  const handlePickFolderAndIngest = async () => {
    setErrorMessage(null);
    try {
      const selectedPath = await forensicClient.pickEvidenceFolder();
      if (selectedPath) {
        await startIngestion(selectedPath);
      }
    } catch (err: any) {
      setErrorMessage(err.message || 'Folder selection failed.');
    }
  };

  const handleDirectPathIngest = async () => {
    if (!directPathInput.trim()) return;
    setErrorMessage(null);
    await startIngestion(directPathInput.trim());
  };

  const startIngestion = async (path: string) => {
    setIsIngesting(true);
    setIngestionPhase('Reading the evidence. The engine does not report progress, so no percentage is shown.');
    try {
      const res = await forensicClient.ingestCase(path);
      if (res && res.success) {
        await syncWithBackendCase();
        const data = await forensicClient.getCaseSummary();
        if (data) setBackendSummary(data);
      } else {
        setErrorMessage(res.error || 'Ingestion failed on target evidence.');
      }
    } catch (err: any) {
      setErrorMessage(err.message || 'Error occurred during ingestion pipeline.');
    } finally {
      setIsIngesting(false);
      setIngestionPhase('');
    }
  };

  const meta = deviceMetadata || backendSummary?.device_metadata || {
    model: isLoaded ? (backendSummary?.case_name || 'Active Forensic Evidence') : 'No Evidence Ingested',
    manufacturer: 'Not recorded',
    androidVersion: 'Not recorded',
    buildNumber: 'Not recorded',
    imei1: 'N/A',
    imei2: 'N/A',
    serialNumber: 'Not recorded',
    timezone: 'Not recorded',
    extractionType: 'Not recorded',
    evidenceSourcePath: backendSummary?.evidence_path || 'No file selected',
    hashes: backendSummary?.hashes || {
      md5: 'N/A',
      sha256: 'N/A',
      fileSizeBytes: 0,
      verified: false,
      calculatedAt: 'N/A'
    },
    acquisitionTimestamp: {
      rawValue: 0,
      sourceFormat: 'UNIX_MS',
      utcIso: 'N/A',
      istFormatted: 'N/A',
      epochMs: 0
    }
  };

  const dossier = backendSummary?.owner_dossier || {};
  const perAppBreakdown = dossier.Per_App_Breakdown || dossier.Per_App_Breakdown_DF || [];

  const counts = backendSummary?.counts || {};

  const categories: { title: string; note: string; active: number; recovered: number; icon: React.ElementType; tab: ActiveTabType }[] = [
    { title: 'UPI transactions', note: 'UTRs, VPAs and unconfirmed payment intents', active: counts.upi_all?.active || 0, recovered: counts.upi_all?.wal_and_carved || 0, icon: CreditCard, tab: 'UPI_LEDGER' },
    { title: 'Chats', note: 'Messages from all supported apps', active: counts.chats_all?.active || 0, recovered: counts.chats_all?.wal_and_carved || 0, icon: MessageSquare, tab: 'CHATS' },
    { title: 'Contacts', note: 'Saved contacts and payment beneficiaries', active: counts.contacts_all?.active || 0, recovered: counts.contacts_all?.wal_and_carved || 0, icon: Users, tab: 'CONTACTS' },
    { title: 'Calls', note: 'Cellular and app call records', active: counts.calls_all?.active || 0, recovered: counts.calls_all?.wal_and_carved || 0, icon: Phone, tab: 'CALLS' },
    { title: 'Crypto wallets', note: 'Wallet addresses and exchange orders', active: counts.crypto_all?.active || 0, recovered: counts.crypto_all?.wal_and_carved || 0, icon: Coins, tab: 'CRYPTO' },
    { title: 'System traces', note: 'Notifications and keyboard cache', active: counts.os_spillover_all?.active || counts.os_spillover?.active || 0, recovered: counts.os_spillover_all?.wal_and_carved || 0, icon: AlertCircle, tab: 'OS_SPILLOVER' },
    { title: 'Link graph', note: 'Who paid whom (leads)', active: backendSummary?.mule_alerts?.length || 0, recovered: 0, icon: Network, tab: 'MULE_GRAPH' },
    { title: 'Database inspector', note: 'Raw tables, free pages and cells', active: counts.data_files?.active || 0, recovered: counts.data_files?.wal_and_carved || 0, icon: Database, tab: 'SQLITE_WIZARD' },
    { title: 'Locations and media', note: 'GPS coordinates and media files', active: counts.locations_all?.active || 0, recovered: counts.locations_all?.wal_and_carved || 0, icon: MapPin, tab: 'LOCATIONS_MEDIA' },
    { title: 'Files', note: 'File catalogue of the evidence', active: counts.vfs_files?.active || counts.data_files?.active || 0, recovered: 0, icon: FolderTree, tab: 'FILE_SYSTEM' },
  ];

  const rehash = integrity?.match === true
    ? { tone: 'ok' as const, text: 'Re-hash MATCH' }
    : integrity?.match === false
    ? { tone: 'bad' as const, text: 'Re-hash MISMATCH' }
    : { tone: 'neutral' as const, text: 'Re-hash NOT RECORDED' };

  if (!isLoaded) {
    const sources: { icon: React.ElementType; title: string; text: string; action: string; onClick: () => void }[] = [
      { icon: FolderArchive, title: 'Archive or image file', text: 'A .ufdr, .tar, .zip, .xry, .ofb or .ab file.', action: 'Select file', onClick: handlePickFileAndIngest },
      { icon: FolderTree, title: 'Extracted folder or database', text: 'A folder from a file-system extraction, or a single .sqlite or .db file.', action: 'Select folder', onClick: handlePickFolderAndIngest },
    ];
    return (
      <div className="h-full w-full bg-slate-950 overflow-y-auto p-6">
        <div className="max-w-3xl space-y-4">
          <div>
            <h1 className="text-lg font-semibold text-slate-50">Open evidence</h1>
            <p className="mt-1 text-slate-400">The evidence file is hashed before and after processing. Analysis runs on a working copy; the original is opened read-only.</p>
          </div>

          {isIngesting && (
            <Panel className="p-4" aria-live="polite">
              <div className="flex items-center gap-2 text-slate-100"><Loader2 className="w-4 h-4 animate-spin text-slate-400" /> Reading evidence</div>
              <p className="mt-1 text-slate-400">{ingestionPhase}</p>
            </Panel>
          )}

          {errorMessage && (
            <Panel className="p-3 flex items-start gap-2 border-rose-700" role="alert">
              <AlertCircle className="w-4 h-4 text-rose-300 shrink-0 mt-0.5" />
              <span className="text-rose-200">{errorMessage}</span>
            </Panel>
          )}

          <Panel className="divide-y divide-slate-800">
            {sources.map((s) => (
              <div key={s.title} className="flex items-center gap-4 px-4 py-3">
                <s.icon className="w-4 h-4 text-slate-400 shrink-0" aria-hidden="true" />
                <div className="min-w-0 flex-1">
                  <div className="font-medium text-slate-100">{s.title}</div>
                  <div className="text-slate-400">{s.text}</div>
                </div>
                <Button variant="primary" onClick={s.onClick} disabled={isIngesting}>{s.action}</Button>
              </div>
            ))}
            <div className="px-4 py-3">
              <div className="flex items-center gap-4">
                <HardDrive className="w-4 h-4 text-slate-400 shrink-0" aria-hidden="true" />
                <div className="min-w-0 flex-1">
                  <label htmlFor="direct-path" className="font-medium text-slate-100">Path</label>
                  <div className="text-slate-400">Type or paste the full path to an evidence file or folder.</div>
                </div>
              </div>
              <div className="mt-2 flex gap-2 pl-8">
                <input
                  id="direct-path"
                  type="text"
                  value={directPathInput}
                  onChange={(e) => setDirectPathInput(e.target.value)}
                  onKeyDown={(e) => { if (e.key === 'Enter') void handleDirectPathIngest(); }}
                  placeholder="D:\Cases\2026\evidence.tar"
                  className="h-8 flex-1 min-w-0 px-2 rounded-ctl bg-slate-950 border border-slate-700 text-slate-100 placeholder-slate-500 font-mono"
                />
                <Button onClick={handleDirectPathIngest} disabled={!directPathInput.trim() || isIngesting}>Open</Button>
              </div>
            </div>
          </Panel>

          <p className="text-slate-400">Once evidence is open, the report and facts annexure are prepared in stage 8. Hashes are recorded when the evidence is opened.</p>
        </div>
      </div>
    );
  }

  const fileSize = meta.hashes?.fileSizeBytes
    ? `${(meta.hashes.fileSizeBytes / (1024 * 1024)).toFixed(2)} MB (${meta.hashes.fileSizeBytes.toLocaleString()} bytes)`
    : null;
  const val = (v: unknown): string | null => dossierText(v);

  return (
    <div className="h-full w-full bg-slate-950 overflow-y-auto select-text">
      <div className="p-4 space-y-4 max-w-[1400px]">
        <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
          <Panel>
            <PanelHeader title="Device" actions={meta.extractionType ? <Badge>{meta.extractionType}</Badge> : undefined} />
            <div className="p-4">
              <KeyValue columns={2} items={[
                { label: 'Model', value: meta.model },
                { label: 'Manufacturer', value: meta.manufacturer },
                { label: 'Android version', value: meta.androidVersion },
                { label: 'Serial number', value: meta.serialNumber },
                { label: 'Time zone', value: meta.timezone },
                { label: 'Evidence source', value: meta.evidenceSourcePath, mono: true, wide: true },
              ]} />
            </div>
          </Panel>

          <Panel>
            <PanelHeader title="Hashes and integrity" actions={<Badge tone={rehash.tone}>{rehash.text}</Badge>} />
            <div className="p-4 space-y-4">
              <KeyValue columns={1} items={[
                { label: 'MD5 before processing', value: meta.hashes?.md5, mono: true },
                { label: 'SHA-256 before processing', value: meta.hashes?.sha256, mono: true },
                { label: 'SHA-256 after processing', value: integrity?.postSha256, mono: true },
                { label: 'File size', value: fileSize },
              ]} />
              <div className="flex gap-2 pt-3 border-t border-slate-800">
                <Button variant="primary" onClick={() => setActiveTab('REPORT_EXPORT')} title="Opens the examination report, facts annexure, review package and audit log">
                  <FileText className="w-4 h-4" /> Report and export
                </Button>
                <Button onClick={() => openDialog('ADD_EXTRACTION')}>
                  <PlusCircle className="w-4 h-4 text-slate-400" /> Add another extraction
                </Button>
              </div>
            </div>
          </Panel>
        </div>

        <Panel>
          <PanelHeader title="Records by category" />
          <table className="w-full text-left">
            <thead>
              <tr className="text-slate-400 border-b border-slate-800">
                <th className="py-2 pl-4 font-medium">Category</th>
                <th className="py-2 font-medium hidden md:table-cell">Contents</th>
                <th className="py-2 px-3 font-medium text-right">Records</th>
                <th className="py-2 pr-4 font-medium text-right">Recovered</th>
              </tr>
            </thead>
            <tbody>
              {categories.map((c) => (
                <tr key={c.title} className="border-b border-slate-800/70 last:border-0 hover:bg-slate-800/60">
                  <td className="py-0">
                    <button onClick={() => setActiveTab(c.tab)} className="flex items-center gap-3 w-full h-9 pl-4 text-left text-slate-100 font-medium hover:text-cyan-300">
                      <c.icon className="w-4 h-4 text-slate-400" aria-hidden="true" />{c.title}
                    </button>
                  </td>
                  <td className="text-slate-400 hidden md:table-cell">{c.note}</td>
                  <td className="px-3 text-right text-slate-100">{c.active.toLocaleString()}</td>
                  <td className={`pr-4 text-right ${c.recovered > 0 ? 'text-amber-300' : 'text-slate-500'}`}>{c.recovered.toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Panel>

        <Panel>
          <PanelHeader title="Device owner" actions={<span className="text-slate-400">Taken from the apps' own records</span>} />
          <div className="p-4">
            <KeyValue columns={4} items={[
              { label: 'Primary mobile number', value: val(dossier.Primary_Mobile), mono: true },
              { label: 'Account holder names', value: val(dossier.Account_Holder_Names) },
              { label: 'Email addresses', value: val(dossier.Owner_Emails), mono: true },
              { label: 'UPI VPAs', value: val(dossier.Owner_VPAs_Raw), mono: true },
              { label: 'Linked bank accounts', value: val(dossier.Linked_Bank_Accounts), mono: true },
              { label: 'Financial apps in use', value: val(dossier.Active_Financial_Apps) },
              { label: 'Other mobile numbers', value: val(dossier.Secondary_Mobiles), mono: true },
              { label: 'UPI Circle delegations', value: val(dossier.UPI_Circle_Delegations) },
            ]} />
          </div>

          {perAppBreakdown && perAppBreakdown.length > 0 && (
            <div className="border-t border-slate-800">
              <h3 className="px-4 pt-3 pb-2 font-semibold text-slate-100">Accounts by app</h3>
              <div className="overflow-x-auto">
                <table className="w-full text-left">
                  <thead>
                    <tr className="text-slate-400 border-y border-slate-800">
                      <th className="py-2 pl-4 font-medium">App</th>
                      <th className="py-2 px-3 font-medium">Account</th>
                      <th className="py-2 px-3 font-medium">Holder</th>
                      <th className="py-2 px-3 font-medium">VPA or wallet</th>
                      <th className="py-2 pr-4 font-medium">Source file</th>
                    </tr>
                  </thead>
                  <tbody>
                    {perAppBreakdown.map((row: any, i: number) => (
                      <tr key={i} className="border-b border-slate-800/70 last:border-0 hover:bg-slate-800/60">
                        <td className="py-2 pl-4 text-slate-100 font-medium">{row.App_Name || row.Application || 'App'}</td>
                        <td className="py-2 px-3 font-mono text-slate-200">{row.Account_ID || row.Identifier || 'not recorded'}</td>
                        <td className="py-2 px-3 text-slate-200">{row.Holder_Name || row.Name || 'not recorded'}</td>
                        <td className="py-2 px-3 font-mono text-slate-200">{row.VPA || row.Wallet || '—'}</td>
                        <td className="py-2 pr-4 text-slate-400 truncate max-w-xs" title={row.Source_File}>{row.Source_File || 'not recorded'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </Panel>

        <KeysNeededCard
          refreshKey={backendSummary?.case_id ?? ''}
          onProcessed={async () => {
            await syncWithBackendCase();
            const data = await forensicClient.getCaseSummary();
            if (data) setBackendSummary(data);
          }}
        />
      </div>
    </div>
  );
};

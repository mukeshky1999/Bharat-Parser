import React, { useState, useEffect, useMemo } from 'react';
import { FileText, PlusCircle, Smartphone, ShieldCheck, Pin } from 'lucide-react';
import { DeviceMetadata, DualHashResult } from '../../shared/forensic-types';
import { useWorkbenchStore } from '../state/workbenchStore';
import { useUi } from '../state/uiStore';
import { useFindings } from '../state/findingsStore';
import { forensicClient, CaseSummaryResponse } from '../api/forensicClient';
import { KeysNeededCard } from '../inspectors/KeyBrokerPanel';
import { GROUPS, countKey } from '../workspace/dataTree';
import { integrityText } from '../workspace/integrity';
import { Button, Card, Chip, KeyValue, RecoveredChip, StatTile } from '../components/ui';
import { IntakeCard } from './overview/IntakeCard';
import { ActivityChart } from './overview/ActivityChart';
import { appActivity, dossierText, mostContacted, perDay, recorded, sizeText } from './overview/format';

interface ExtractionSummaryTabProps {
  deviceMetadata?: DeviceMetadata;
  dualHashes?: DualHashResult;
}

const NR = <span className="text-muted">not recorded</span>;
const show = (v: string | null) => (v === null ? NR : v);

export const ExtractionSummaryTab: React.FC<ExtractionSummaryTabProps> = ({
  deviceMetadata,
  dualHashes
}) => {
  const {
    setActiveTab,
    caseManifest,
    integrity,
    syncWithBackendCase,
    caseSummary,
    upiTransactions,
    chats,
    callLogs,
    osSpillovers,
  } = useWorkbenchStore();
  const openDialog = useUi((st) => st.open);
  const findings = useFindings((s) => s.findings);
  const loadFindings = useFindings((s) => s.load);

  // The store's summary is used. A local copy is read only when the store has none yet, or after an ingest here.
  const [fetchedSummary, setFetchedSummary] = useState<CaseSummaryResponse | null>(null);
  const [directPathInput, setDirectPathInput] = useState('');
  const [isIngesting, setIsIngesting] = useState(false);
  const [ingestionPhase, setIngestionPhase] = useState<string>('');
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const backendSummary = caseSummary ?? fetchedSummary;

  useEffect(() => {
    if (caseSummary) return;
    let isMounted = true;
    const fetchSummary = async () => {
      try {
        const data = await forensicClient.getCaseSummary();
        if (isMounted && data) {
          setFetchedSummary(data);
        }
      } catch {
        // Fall through
      }
    };
    fetchSummary();
    return () => { isMounted = false; };
  }, [caseManifest, caseSummary]);

  const isLoaded = Boolean(
    backendSummary?.loaded ||
    caseManifest?.evidenceFileName ||
    dualHashes?.verified
  );

  useEffect(() => {
    if (isLoaded) void loadFindings();
  }, [isLoaded, backendSummary?.case_id, loadFindings]);

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
        if (data) setFetchedSummary(data);
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

  const counts = backendSummary?.counts || {};
  const dossier = backendSummary?.owner_dossier || {};
  const perAppBreakdown: any[] = dossier.Per_App_Breakdown || dossier.Per_App_Breakdown_DF || [];

  const days = useMemo(
    () => perDay([
      ...upiTransactions.map((r) => r.timestamp?.epochMs),
      ...chats.map((r) => r.timestamp?.epochMs),
      ...callLogs.map((r) => r.timestamp?.epochMs),
      ...osSpillovers.map((r) => r.timestamp?.epochMs),
    ]),
    [upiTransactions, chats, callLogs, osSpillovers],
  );
  const loadedWithTime = days.reduce((a, d) => a + d.n, 0);
  const apps = useMemo(() => appActivity(dossier), [dossier]);
  const contacted = useMemo(() => mostContacted(callLogs, chats), [callLogs, chats]);
  const latestFindings = useMemo(
    () => [...findings].sort((a, b) => String(b.pinned_at_utc).localeCompare(String(a.pinned_at_utc))).slice(0, 5),
    [findings],
  );

  if (!isLoaded) {
    return (
      <IntakeCard
        directPathInput={directPathInput}
        onPathChange={setDirectPathInput}
        onPickFile={handlePickFileAndIngest}
        onPickFolder={handlePickFolderAndIngest}
        onPathIngest={handleDirectPathIngest}
        isIngesting={isIngesting}
        ingestionPhase={ingestionPhase}
        errorMessage={errorMessage}
      />
    );
  }

  const meta: any = deviceMetadata || backendSummary?.device_metadata || {};
  const hashes: any = meta.hashes || backendSummary?.hashes || {};
  const model = recorded(meta.model) ?? recorded(backendSummary?.case_name) ?? 'Evidence';
  const extraction = recorded(meta.extractionType);
  const acquired = meta.acquisitionTimestamp && Number(meta.acquisitionTimestamp.epochMs) > 0
    ? recorded(meta.acquisitionTimestamp.istFormatted) : null;
  const integ = integrityText(integrity);
  const integTone = integrity?.match === true ? 'ok' : integrity?.match === false ? 'rec' : 'neutral';
  const integLabel = integrity?.match === true ? 'Re-hash MATCH' : integrity?.match === false ? 'Re-hash MISMATCH' : 'Re-hash NOT RECORDED';
  const owner = dossierText(dossier.Primary_Mobile);

  const tiles = GROUPS.flatMap((g) => g.views.map((v) => ({ g, v, key: countKey(v.tab) })))
    .filter((t): t is typeof t & { key: string } => t.key !== null);
  const total = tiles.reduce((a, t) => a + (counts[t.key]?.total ?? 0), 0);

  const dossierRows: Array<[string, string | null]> = [
    ['Primary mobile number', dossierText(dossier.Primary_Mobile)],
    ['Account holder names', dossierText(dossier.Account_Holder_Names)],
    ['Owner emails', dossierText(dossier.Owner_Emails)],
    ['Owner UPI VPAs', dossierText(dossier.Owner_VPAs_Raw)],
    ['Linked bank accounts', dossierText(dossier.Linked_Bank_Accounts)],
    ['Active financial apps', dossierText(dossier.Active_Financial_Apps)],
    ['Secondary mobiles', dossierText(dossier.Secondary_Mobiles)],
    ['UPI Circle delegations', dossierText(dossier.UPI_Circle_Delegations)],
  ];
  const appMax = Math.max(...apps.map((a) => a.n), 1);
  const contactMax = Math.max(...contacted.map((c) => c.calls + c.messages), 1);

  return (
    <div className="h-full w-full bg-page text-ink overflow-y-auto select-text">
      <div className="p-4 space-y-4 max-w-[1600px] mx-auto">
        <div className="flex items-end gap-3 flex-wrap">
          <div>
            <div className="text-muted font-medium">Case overview</div>
            <h1 className="text-xl font-semibold tracking-tight">{model}{extraction ? ` · ${extraction}` : ''}</h1>
          </div>
          <span className="flex-1" />
          <span className="text-muted">{owner ? `Owner number ${owner}` : 'Owner number not recorded'}</span>
          <Button onClick={() => setActiveTab('REPORT_EXPORT')} title="Opens the examination report, facts annexure, review package and audit log">
            <FileText className="w-4 h-4" aria-hidden="true" />Report and export
          </Button>
          <Button onClick={() => openDialog('ADD_EXTRACTION')}>
            <PlusCircle className="w-4 h-4" aria-hidden="true" />Add secondary extraction
          </Button>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
          <Card className="lg:col-span-7" title={<span className="flex items-center gap-2"><Smartphone className="w-4 h-4 text-muted" aria-hidden="true" />Device</span>} aside="from build.prop and accounts">
            <KeyValue className="md:grid-cols-[max-content_minmax(0,1fr)_max-content_minmax(0,1fr)]" items={[
              ['Model', show(recorded(meta.model))],
              ['Android', show(recorded(meta.androidVersion))],
              ['IMEI 1', meta.imei1 && recorded(meta.imei1) ? <span className="font-mono">{meta.imei1}</span> : NR],
              ['IMEI 2', meta.imei2 && recorded(meta.imei2) ? <span className="font-mono">{meta.imei2}</span> : NR],
              ['Extraction', show(extraction)],
              ['Time zone', show(recorded(meta.timezone))],
              ['Acquired', show(acquired)],
              ['Size', show(sizeText(hashes.fileSizeBytes))],
            ]} />
          </Card>

          <Card className="lg:col-span-5" title={<span className="flex items-center gap-2"><ShieldCheck className="w-4 h-4 text-muted" aria-hidden="true" />Integrity</span>}
            aside={<Chip tone={integTone} title={integ.text}>{integLabel}</Chip>}>
            <KeyValue items={[
              ['MD5 before', <span className="font-mono break-all select-all">{hashes.md5 || 'not recorded'}</span>],
              ['SHA-256 before', <span className="font-mono break-all select-all">{hashes.sha256 || 'not recorded'}</span>],
              ['SHA-256 after', <span className="font-mono break-all select-all">{integrity?.postSha256 || 'not recorded'}</span>],
            ]} />
          </Card>
        </div>

        <div>
          <div className="flex items-center gap-3 mb-2">
            <h2 className="font-semibold">Data in this case</h2>
            <span className="text-muted">{total.toLocaleString()} records · select a tile to open it</span>
          </div>
          <div className="grid gap-3" style={{ gridTemplateColumns: 'repeat(auto-fill, minmax(190px, 1fr))' }}>
            {tiles.map(({ g, v, key }) => {
              const c = counts[key];
              const rec = c?.wal_and_carved ?? 0;
              return (
                <StatTile key={v.tab} hue={g.hue} icon={g.icon} label={v.label}
                  value={(c?.total ?? 0).toLocaleString()}
                  sub={rec > 0 ? <RecoveredChip n={rec} label="recovered" /> : <span>all active</span>}
                  onClick={() => setActiveTab(v.tab)} />
              );
            })}
          </div>
        </div>

        <KeysNeededCard
          refreshKey={backendSummary?.case_id ?? ''}
          onProcessed={async () => {
            await syncWithBackendCase();
            const data = await forensicClient.getCaseSummary();
            if (data) setFetchedSummary(data);
          }}
        />

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
          <Card className="lg:col-span-7" title="Records per day" aside="from loaded records">
            {days.length > 0
              ? (<>
                  <ActivityChart days={days} />
                  <p className="text-muted mt-1.5">{loadedWithTime.toLocaleString()} loaded records with a recorded time, counted by UTC day. Records not loaded yet, or with no recorded time, are not counted.</p>
                </>)
              : <p className="text-muted">No loaded records have a recorded time yet. Open a data view to load its records.</p>}
          </Card>

          <Card className="lg:col-span-5" title="Most active apps" aside="from the apps' own records">
            {apps.length > 0 ? (
              <ul className="space-y-2.5">
                {apps.map((a) => (
                  <li key={a.app}>
                    <div className="flex justify-between"><span>{a.app}</span><span className="text-muted">{a.n.toLocaleString()}</span></div>
                    <div className="h-2 rounded-full bg-sunken mt-1"><div className="h-2 rounded-full bg-accent" style={{ width: `${(a.n / appMax) * 100}%` }} /></div>
                  </li>
                ))}
              </ul>
            ) : <p className="text-muted">No per-app record counts were recorded.</p>}
          </Card>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
          <Card className="lg:col-span-6" title="Most contacted" aside="from loaded calls and chats">
            {contacted.length > 0 ? (
              <ul className="space-y-2.5">
                {contacted.map((c) => (
                  <li key={c.who}>
                    <div className="flex justify-between gap-3">
                      <span className="font-mono truncate" title={c.who}>{c.who}</span>
                      <span className="text-muted whitespace-nowrap">{c.calls} call{c.calls === 1 ? '' : 's'} · {c.messages} message{c.messages === 1 ? '' : 's'}</span>
                    </div>
                    <div className="h-2 rounded-full bg-sunken mt-1"><div className="h-2 rounded-full bg-accent" style={{ width: `${((c.calls + c.messages) / contactMax) * 100}%` }} /></div>
                  </li>
                ))}
              </ul>
            ) : <p className="text-muted">Open Calls or Chats to load them. Only loaded records are counted here.</p>}
          </Card>

          <Card className="lg:col-span-6" title={<span className="flex items-center gap-2"><Pin className="w-4 h-4 text-muted" aria-hidden="true" />Latest pinned findings</span>}
            aside={findings.length > 0 ? <button type="button" className="text-accent-ink font-medium hover:underline" onClick={() => setActiveTab('FINDINGS')}>All {findings.length}</button> : undefined}>
            {latestFindings.length > 0 ? (
              <ul className="divide-y divide-line">
                {latestFindings.map((f) => (
                  <li key={f.id} className="py-1.5 first:pt-0 last:pb-0">
                    <button type="button" className="text-left w-full hover:text-accent-ink" onClick={() => setActiveTab('FINDINGS')}>
                      <span className="font-medium">{f.title || f.record_id}</span>
                      {f.note && <span className="block text-muted truncate">{f.note}</span>}
                    </button>
                  </li>
                ))}
              </ul>
            ) : <p className="text-muted">Nothing pinned yet. Pin a record from its detail panel to keep it here.</p>}
          </Card>
        </div>

        <Card title="Device owner details" aside="compiled from the apps' own records">
          <KeyValue className="md:grid-cols-[max-content_minmax(0,1fr)_max-content_minmax(0,1fr)]"
            items={dossierRows.map(([k, v]) => [k, v === null ? NR : <span className="select-all break-words">{v}</span>])} />
          {perAppBreakdown.length > 0 && (
            <div className="mt-4 pt-4 border-t border-line">
              <h3 className="font-semibold mb-2">By application</h3>
              <div className="overflow-x-auto rounded-lg border border-line">
                <table className="w-full text-left border-collapse">
                  <thead>
                    <tr className="bg-sunken text-muted border-b border-line">
                      <th className="py-2 px-3 font-semibold">Application</th>
                      <th className="py-2 px-3 font-semibold">Account identifier</th>
                      <th className="py-2 px-3 font-semibold">Owner name</th>
                      <th className="py-2 px-3 font-semibold">VPAs / wallets</th>
                      <th className="py-2 px-3 font-semibold">Source file</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-line">
                    {perAppBreakdown.map((row: any, i: number) => (
                      <tr key={i} className="hover:bg-hover">
                        <td className="py-2 px-3 font-semibold">{row.App_Name || row.Application || 'App'}</td>
                        <td className="py-2 px-3 font-mono select-all">{row.Account_ID || row.Identifier || row.Registered_Mobile || 'not recorded'}</td>
                        <td className="py-2 px-3">{row.Holder_Name || row.Name || row.Account_Holder_Name || 'not recorded'}</td>
                        <td className="py-2 px-3 font-mono">{row.VPA || row.Wallet || row.Owner_UPI_ID || 'not recorded'}</td>
                        <td className="py-2 px-3 text-muted truncate max-w-xs">{row.Source_File || 'not recorded'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </Card>
      </div>
    </div>
  );
};

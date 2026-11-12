import React, { useMemo, useState } from 'react';
import { useWorkbenchStore } from '../state/workbenchStore';
import { usePreferences } from '../state/preferencesStore';
import { UnifiedUPITransaction } from '../../shared/forensic-types';
import { formatOffset } from '../utils/csv';
import { DataGrid, FilterInput, GridColumn, Segmented, Unset } from '../workspace/DataGrid';

interface UPIMasterLedgerViewProps {
  transactions?: UnifiedUPITransaction[];
  selectedTxId?: string;
  onSelectTransaction?: (tx: UnifiedUPITransaction) => void;
  globalSearchQuery?: string;
}

type DirectionFilter = 'ALL' | 'DEBIT' | 'CREDIT';
type RecoveryFilter = 'ALL' | 'RECOVERED';
type AmountFilter = 'ANY' | 'BAND_40_50' | 'OVER_1L';

const RECOVERY_TEXT: Record<string, string> = {
  ACTIVE: 'In database',
  WAL_RECOVERED: 'Recovered from log',
  CARVED_UNALLOCATED: 'Carved from free space',
  OS_SPILLOVER: 'System trace',
};

const DIRECTION_TEXT: Record<string, string> = { DEBIT: 'Debit', CREDIT: 'Credit', COLLECT_REQUEST: 'Collect request', GHOST_INTENT: 'Intent, not completed' };
const STATUS_TEXT: Record<string, string> = { SUCCESS: 'Success', FAILED: 'Failed', PENDING: 'Pending', ABANDONED_INTENT: 'Abandoned', UNKNOWN: 'Not established' };

const inr = (n: number) => `₹${n.toLocaleString('en-IN', { minimumFractionDigits: 2 })}`;

/**
 * Payments found in the case, every app and device together. The filters are on recorded facts (direction, where the
 * record was found, amount range, clock mismatch); none of them is a verdict about the payment.
 */
export const UPIMasterLedgerView: React.FC<UPIMasterLedgerViewProps> = ({
  transactions: propTransactions,
  selectedTxId: propSelectedTxId,
  onSelectTransaction,
  globalSearchQuery = '',
}) => {
  const store = useWorkbenchStore();
  const tz = usePreferences((s) => s.timeZone);
  const rawTransactions = propTransactions || store.upiTransactions || [];
  const selectedTxId = propSelectedTxId || store.selectedArtifact?.id;

  const [app, setApp] = useState('ALL');
  const [direction, setDirection] = useState<DirectionFilter>('ALL');
  const [recovery, setRecovery] = useState<RecoveryFilter>('ALL');
  const [amount, setAmount] = useState<AmountFilter>('ANY');
  const [clockOnly, setClockOnly] = useState(false);
  const [query, setQuery] = useState('');

  const appCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const tx of rawTransactions) counts[tx.sourceApp || 'App not recorded'] = (counts[tx.sourceApp || 'App not recorded'] || 0) + 1;
    return counts;
  }, [rawTransactions]);
  const apps = Object.keys(appCounts).sort((a, b) => appCounts[b] - appCounts[a]);

  const rows = useMemo(() => {
    const q = (query || globalSearchQuery).toLowerCase().trim();
    return rawTransactions.filter((tx) => {
      if (app !== 'ALL' && (tx.sourceApp || 'App not recorded') !== app) return false;
      if (direction !== 'ALL' && tx.direction !== direction) return false;
      if (recovery === 'RECOVERED' && tx.provenance?.recoveryState !== 'WAL_RECOVERED' && tx.provenance?.recoveryState !== 'CARVED_UNALLOCATED') return false;
      if (amount === 'BAND_40_50' && !(tx.amountInr >= 40000 && tx.amountInr <= 50000)) return false;
      if (amount === 'OVER_1L' && !(tx.amountInr >= 100000)) return false;
      if (clockOnly && !tx.clockTamperDetected) return false;
      if (!q) return true;
      return [tx.utrNumber, tx.appTransactionId, tx.payerVpa, tx.payeeVpa, tx.accountMask, tx.amountInr?.toString(), tx.sourceApp]
        .some((v) => !!v && String(v).toLowerCase().includes(q));
    });
  }, [rawTransactions, app, direction, recovery, amount, clockOnly, query, globalSearchQuery]);

  const select = (tx: UnifiedUPITransaction) => {
    onSelectTransaction?.(tx);
    void store.setSelectedArtifact({
      id: tx.id || tx.appTransactionId || `TX_${tx.provenance?.byteOffset}`,
      provenance: tx.provenance,
      timestamp: tx.timestamp,
      notes: `INR ${tx.amountInr.toLocaleString('en-IN')} | UTR: ${tx.utrNumber || 'not recorded'} | Payee: ${tx.payeeVpa || 'not recorded'}`,
      itemType: 'Financial Transaction',
      rawData: tx,
    });
  };

  const timeText = (tx: UnifiedUPITransaction): string => {
    const t = tx.timestamp;
    if (t?.utcIso) return tz === 'IST' ? t.istFormatted.substring(0, 19) : t.utcIso.substring(0, 19);
    if (t?.localClock) return `${t.localClock.substring(0, 19)} (zone not recorded)`;
    return 'not recorded';
  };

  const columns: Array<GridColumn<UnifiedUPITransaction>> = [
    { key: 'source', label: 'Where found', width: '11rem', cell: (t) => RECOVERY_TEXT[t.provenance?.recoveryState ?? ''] ?? <Unset />, text: (t) => RECOVERY_TEXT[t.provenance?.recoveryState ?? ''] ?? 'not recorded' },
    {
      key: 'time', label: tz === 'IST' ? 'Time (IST)' : 'Time (UTC)', width: '19rem',
      cell: (t) => {
        const s = timeText(t);
        return <>{s === 'not recorded' ? <Unset /> : s}{t.clockTamperDetected && <span className="ml-1 text-amber-300" title="The device clock differs from the transaction's own sequence token.">clock differs</span>}</>;
      },
      text: (t) => `${timeText(t)}${t.clockTamperDetected ? ' (clock differs)' : ''}`,
    },
    { key: 'utr', label: 'UTR / reference', width: '11rem', cell: (t) => t.utrNumber || <Unset />, text: (t) => t.utrNumber || 'not recorded' },
    { key: 'app', label: 'App', width: '8rem', cell: (t) => t.sourceApp || <Unset />, text: (t) => t.sourceApp || 'not recorded' },
    { key: 'amount', label: 'Amount', width: '9rem', align: 'right', cell: (t) => inr(t.amountInr), text: (t) => String(t.amountInr) },
    { key: 'direction', label: 'Direction', width: '8rem', cell: (t) => DIRECTION_TEXT[t.direction] ?? <span className="text-slate-400" title="The evidence does not establish the direction">Not established</span>, text: (t) => DIRECTION_TEXT[t.direction] ?? 'not established' },
    { key: 'status', label: 'Status', width: '8rem', cell: (t) => (t.status ? STATUS_TEXT[t.status] ?? String(t.status) : <Unset />), text: (t) => (t.status ? STATUS_TEXT[t.status] ?? String(t.status) : 'not recorded') },
    { key: 'payer', label: 'Payer VPA / account', width: 'minmax(10rem,1fr)', cell: (t) => t.payerVpa || t.accountMask || <Unset />, text: (t) => t.payerVpa || t.accountMask || 'not recorded' },
    { key: 'payee', label: 'Payee VPA', width: 'minmax(10rem,1fr)', cell: (t) => t.payeeVpa || <Unset />, text: (t) => t.payeeVpa || 'not recorded' },
    { key: 'sources', label: 'Also found in', width: '10rem', cell: (t) => (t.corroboratedSources || []).join(', ') || <Unset />, text: (t) => (t.corroboratedSources || []).join('; ') || 'not recorded' },
    { key: 'offset', label: 'Byte offset', width: '9rem', cell: (t) => formatOffset(t.provenance?.byteOffset), text: (t) => formatOffset(t.provenance?.byteOffset) },
    { key: 'file', label: 'Source file', width: 'minmax(10rem,1fr)', cell: (t) => t.provenance?.vfsInternalPath || t.provenance?.archivePath || <Unset />, text: (t) => t.provenance?.vfsInternalPath || t.provenance?.archivePath || 'not recorded' },
  ];

  const toolbar = (
    <>
      <FilterInput label="Search payments" value={query} onChange={setQuery} placeholder="UTR, VPA, amount…" />
      <Segmented<DirectionFilter> label="Direction" value={direction} onChange={setDirection}
        options={[{ value: 'ALL', label: 'All' }, { value: 'DEBIT', label: 'Debit' }, { value: 'CREDIT', label: 'Credit' }]} />
      <Segmented<RecoveryFilter> label="Where found" value={recovery} onChange={setRecovery}
        options={[{ value: 'ALL', label: 'Everything' }, { value: 'RECOVERED', label: 'Recovered only', title: 'Recovered from a database log or from free space' }]} />
      <label className="text-slate-300 inline-flex items-center gap-2">Amount
        <select aria-label="Amount range" value={amount} onChange={(e) => setAmount(e.target.value as AmountFilter)} className="h-8 rounded bg-slate-900 border border-slate-700 px-2 text-slate-100">
          <option value="ANY">Any</option>
          <option value="BAND_40_50">₹40,000 to ₹50,000</option>
          <option value="OVER_1L">₹1,00,000 or more</option>
        </select>
      </label>
      <label className="text-slate-300 inline-flex items-center gap-2">
        <input type="checkbox" checked={clockOnly} onChange={(e) => setClockOnly(e.target.checked)} />Clock differs from sequence
      </label>
      {apps.length > 1 && (
        <label className="text-slate-300 inline-flex items-center gap-2">App
          <select aria-label="App" value={app} onChange={(e) => setApp(e.target.value)} className="h-8 rounded bg-slate-900 border border-slate-700 px-2 text-slate-100">
            <option value="ALL">All apps ({rawTransactions.length})</option>
            {apps.map((a) => <option key={a} value={a}>{a} ({appCounts[a]})</option>)}
          </select>
        </label>
      )}
    </>
  );

  return (
    <DataGrid<UnifiedUPITransaction>
      tableId="upi_ledger" title="UPI ledger" columns={columns} rows={rows} totalBeforeFilter={rawTransactions.length}
      rowKey={(t, i) => t.id || t.appTransactionId || `row-${i}`}
      selectedKey={selectedTxId ?? null} onSelect={select} toolbar={toolbar} exportName="upi_ledger.csv"
      empty={rawTransactions.length === 0 ? 'No payments were found in the evidence, or no case is open.' : 'No payment matches these filters.'}
    />
  );
};

import React, { useState, useMemo, useRef, useEffect } from 'react';
import {
  Search,
  Filter,
  AlertTriangle,
  ArrowDownLeft,
  ArrowUpRight,
  ShieldCheck,
  CreditCard,
  Layers,
  Download,
  Flame,
  CheckCircle2,
  Clock,
  FileSpreadsheet
} from 'lucide-react';
import { useWorkbenchStore } from '../state/workbenchStore';
import { UnifiedUPITransaction, RecoveryState } from '../../shared/forensic-types';

interface UPIMasterLedgerViewProps {
  transactions?: UnifiedUPITransaction[];
  selectedTxId?: string;
  onSelectTransaction?: (tx: UnifiedUPITransaction) => void;
  globalSearchQuery?: string;
}

/** CSV cell: escape quotes and neutralise spreadsheet formulas (=,+,-,@) coming from evidence text. */
const csvCell = (v: unknown): string => {
  let t = String(v ?? '');
  if (/^[=+\-@\t\r]/.test(t)) t = `'${t}`;
  return `"${t.replace(/"/g, '""')}"`;
};

const formatOffset = (off?: number): string =>
  typeof off === 'number' && off >= 0 ? `0x${off.toString(16).toUpperCase().padStart(8, '0')}` : 'not recorded';

export const UPIMasterLedgerView: React.FC<UPIMasterLedgerViewProps> = ({
  transactions: propTransactions,
  selectedTxId: propSelectedTxId,
  onSelectTransaction,
  globalSearchQuery = '',
}) => {
  const store = useWorkbenchStore();
  const rawTransactions = propTransactions || store.upiTransactions || [];
  const selectedTxId = propSelectedTxId || store.selectedArtifact?.id;

  const [selectedApp, setSelectedApp] = useState<string>('ALL');
  const [filterType, setFilterType] = useState<'ALL' | 'DEBIT' | 'CREDIT' | 'HIGH_RISK' | 'CARVED'>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');

  // Table Virtualization for large datasets (e.g. 10K+ transactions)
  const ROW_HEIGHT = 38;
  const OVERSCAN = 8;
  const [scrollTop, setScrollTop] = useState(0);
  const [viewportHeight, setViewportHeight] = useState(600);
  const tableContainerRef = useRef<HTMLDivElement | null>(null);

  const handleTableScroll = (e: React.UIEvent<HTMLDivElement>) => {
    setScrollTop(e.currentTarget.scrollTop);
  };

  useEffect(() => {
    if (tableContainerRef.current) {
      setViewportHeight(tableContainerRef.current.clientHeight || 600);
    }
  }, []);

  // 1. Dynamic App Filter Pills (Derived solely from apps found in evidence)
  const appCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const tx of rawTransactions) {
      const app = tx.sourceApp || 'Unknown App';
      counts[app] = (counts[app] || 0) + 1;
    }
    return counts;
  }, [rawTransactions]);

  const availableApps = useMemo(() => {
    return Object.keys(appCounts).sort((a, b) => appCounts[b] - appCounts[a]);
  }, [appCounts]);

  // 2. High-Risk / Structuring Detection Helper
  const isHighRiskOrStructuring = (tx: UnifiedUPITransaction): boolean => {
    if (tx.clockTamperDetected) return true;
    if (tx.direction === 'GHOST_INTENT' || tx.status === 'ABANDONED_INTENT') return true;
    // Structuring / Smurfing detection: near 50k reporting threshold
    if (tx.amountInr >= 40000 && tx.amountInr <= 50000) return true;
    // Round trip amounts
    if (tx.amountInr >= 100000) return true;
    return false;
  };

  // 3. Filtered Transaction Set
  const filtered = useMemo(() => {
    const q = (searchQuery || globalSearchQuery).toLowerCase().trim();

    return rawTransactions.filter((tx) => {
      // Dynamic App Filter
      if (selectedApp !== 'ALL' && tx.sourceApp !== selectedApp) return false;

      // Filter Toggles
      if (filterType === 'DEBIT' && tx.direction !== 'DEBIT') return false;
      if (filterType === 'CREDIT' && tx.direction !== 'CREDIT') return false;
      if (filterType === 'HIGH_RISK' && !isHighRiskOrStructuring(tx)) return false;
      if (
        filterType === 'CARVED' &&
        tx.provenance?.recoveryState !== 'WAL_RECOVERED' &&
        tx.provenance?.recoveryState !== 'CARVED_UNALLOCATED'
      ) {
        return false;
      }

      // Search Query
      if (q) {
        const utrMatch = tx.utrNumber?.toLowerCase().includes(q);
        const appIdMatch = tx.appTransactionId?.toLowerCase().includes(q);
        const payerMatch = tx.payerVpa?.toLowerCase().includes(q);
        const payeeMatch = tx.payeeVpa?.toLowerCase().includes(q);
        const maskMatch = tx.accountMask?.toLowerCase().includes(q);
        const amtMatch = tx.amountInr?.toString().includes(q);
        const offsetMatch = `0x${tx.provenance?.byteOffset?.toString(16)}`.toLowerCase().includes(q);
        return Boolean(utrMatch || appIdMatch || payerMatch || payeeMatch || maskMatch || amtMatch || offsetMatch);
      }

      return true;
    });
  }, [rawTransactions, selectedApp, filterType, searchQuery, globalSearchQuery]);

  // Virtual windowing calculations for UPI grid
  const totalCount = filtered.length;
  const startIndex = Math.max(0, Math.floor(scrollTop / ROW_HEIGHT) - OVERSCAN);
  const endIndex = Math.min(totalCount, Math.ceil((scrollTop + viewportHeight) / ROW_HEIGHT) + OVERSCAN);
  const visibleRows = filtered.slice(startIndex, endIndex);

  // 4. Row Selection Synchronizer
  const handleSelectRow = (tx: UnifiedUPITransaction) => {
    if (onSelectTransaction) {
      onSelectTransaction(tx);
    }
    store.setSelectedArtifact({
      id: tx.id || tx.appTransactionId || `TX_${tx.provenance?.byteOffset}`,
      provenance: tx.provenance,
      notes: `INR ₹${tx.amountInr.toLocaleString('en-IN')} | UTR: ${tx.utrNumber || 'N/A'} | Payee: ${tx.payeeVpa || 'N/A'}`,
      itemType: 'Financial Transaction',
      rawData: tx
    });
  };

  // 5. Working CSV Export Button
  const handleExportCsv = () => {
    if (filtered.length === 0) return;

    const headers = [
      'Index',
      'Transaction_ID',
      'Source_App',
      'Timestamp_IST',
      'UTR_RRN',
      'Amount_INR',
      'Direction',
      'Status',
      'Payer_VPA',
      'Payee_VPA',
      'Account_Mask',
      'Recovery_State',
      'Clock_Tampered',
      'Byte_Offset_Hex',
      'Source_File'
    ];

    const rows = filtered.map((tx, idx) => {
      return [
        idx + 1,
        csvCell(tx.appTransactionId || tx.id || ''),
        csvCell(tx.sourceApp || ''),
        csvCell(tx.timestamp?.istFormatted || ''),
        csvCell(tx.utrNumber || ''),
        tx.amountInr,
        csvCell(tx.direction),
        csvCell(tx.status),
        csvCell(tx.payerVpa || ''),
        csvCell(tx.payeeVpa || ''),
        csvCell(tx.accountMask || ''),
        csvCell(tx.provenance?.recoveryState || 'ACTIVE'),
        tx.clockTamperDetected ? 'YES' : 'NO',
        csvCell(formatOffset(tx.provenance?.byteOffset)),
        csvCell(tx.provenance?.vfsInternalPath || tx.provenance?.archivePath || '')
      ].join(',');
    });

    const csvContent = [headers.join(','), ...rows].join('\r\n');
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.setAttribute('download', `BharatAnalyzer_UPI_Banking_Ledger_${new Date().toISOString().substring(0, 10)}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const renderStateBadge = (state?: RecoveryState) => {
    switch (state) {
      case 'ACTIVE':
        return (
          <span className="text-[0.6875rem] bg-emerald-950/80 text-emerald-300 border border-emerald-600/60 px-1.5 py-0.5 rounded font-mono font-bold">
            ACTIVE
          </span>
        );
      case 'WAL_RECOVERED':
        return (
          <span className="text-[0.6875rem] bg-blue-950/80 text-blue-300 border border-blue-600/60 px-1.5 py-0.5 rounded font-mono font-bold">
            WAL
          </span>
        );
      case 'CARVED_UNALLOCATED':
        return (
          <span className="text-[0.6875rem] bg-amber-950/80 text-amber-300 border border-amber-600/60 px-1.5 py-0.5 rounded font-mono font-bold">
            CARVED
          </span>
        );
      default:
        return (
          <span className="text-[0.6875rem] bg-slate-800 text-slate-300 px-1.5 py-0.5 rounded font-mono">
            {state || 'ACTIVE'}
          </span>
        );
    }
  };

  return (
    <div className="flex-1 flex flex-col bg-slate-900 text-slate-100 overflow-hidden select-text font-sans">
      {/* 1. Dynamic App Filter Ribbon */}
      <div className="h-10 bg-slate-950 border-b border-slate-800 px-3 flex items-center justify-between shrink-0 select-none overflow-x-auto text-xs">
        <div className="flex items-center space-x-1.5 shrink-0">
          <span className="text-slate-400 font-semibold text-[0.6875rem] mr-1 flex items-center gap-1">
            <CreditCard className="w-3.5 h-3.5 text-emerald-400" />
            Apps:
          </span>

          <button
            onClick={() => setSelectedApp('ALL')}
            className={`px-2.5 py-1 rounded text-xs font-medium transition-colors flex items-center gap-1.5 cursor-pointer ${
              selectedApp === 'ALL'
                ? 'bg-cyan-600 text-slate-50 font-bold shadow-sm'
                : 'bg-slate-900 text-slate-300 hover:bg-slate-800 border border-slate-700/60'
            }`}
          >
            <span>All Apps</span>
            <span className="text-[0.6875rem] opacity-80 px-1 bg-black/30 rounded-full font-mono">
              {rawTransactions.length}
            </span>
          </button>

          {availableApps.map((app) => (
            <button
              key={app}
              onClick={() => setSelectedApp(app)}
              className={`px-2.5 py-1 rounded text-xs font-medium transition-colors flex items-center gap-1.5 cursor-pointer ${
                selectedApp === app
                  ? 'bg-cyan-600 text-slate-50 font-bold shadow-sm'
                  : 'bg-slate-900 text-slate-300 hover:bg-slate-800 border border-slate-700/60'
              }`}
            >
              <span>{app}</span>
              <span className="text-[0.6875rem] opacity-80 px-1 bg-black/30 rounded-full font-mono">
                {appCounts[app]}
              </span>
            </button>
          ))}
        </div>

        {/* Global Record Counter */}
        <div className="text-[0.6875rem] text-slate-400 font-mono shrink-0 pl-3 hidden md:block">
          Showing <strong className="text-slate-200">{filtered.length}</strong> of {rawTransactions.length} records
        </div>
      </div>

      {/* 2. Secondary Filter & Action Toolbar */}
      <div className="h-11 bg-slate-900 border-b border-slate-800 px-3 flex items-center justify-between shrink-0 select-none text-xs">
        {/* Filter Toggle Buttons */}
        <div className="flex items-center space-x-1.5">
          <span className="text-slate-400 font-semibold text-[0.6875rem] mr-1 flex items-center gap-1">
            <Filter className="w-3.5 h-3.5 text-slate-400" />
            Filter:
          </span>

          <button
            onClick={() => setFilterType('ALL')}
            className={`px-2.5 py-1 rounded text-xs transition-colors cursor-pointer ${
              filterType === 'ALL'
                ? 'bg-slate-700 text-slate-50 font-bold'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
            }`}
          >
            [All]
          </button>

          <button
            onClick={() => setFilterType('DEBIT')}
            className={`px-2.5 py-1 rounded text-xs transition-colors cursor-pointer flex items-center gap-1 ${
              filterType === 'DEBIT'
                ? 'bg-rose-950 text-rose-300 border border-rose-700 font-bold'
                : 'text-slate-400 hover:text-rose-300 hover:bg-slate-800/60'
            }`}
          >
            <ArrowUpRight className="w-3 h-3 text-rose-400" />
            <span>[DEBIT]</span>
          </button>

          <button
            onClick={() => setFilterType('CREDIT')}
            className={`px-2.5 py-1 rounded text-xs transition-colors cursor-pointer flex items-center gap-1 ${
              filterType === 'CREDIT'
                ? 'bg-emerald-950 text-emerald-300 border border-emerald-700 font-bold'
                : 'text-slate-400 hover:text-emerald-300 hover:bg-slate-800/60'
            }`}
          >
            <ArrowDownLeft className="w-3 h-3 text-emerald-400" />
            <span>[CREDIT]</span>
          </button>

          <button
            onClick={() => setFilterType('HIGH_RISK')}
            className={`px-2.5 py-1 rounded text-xs transition-colors cursor-pointer flex items-center gap-1 ${
              filterType === 'HIGH_RISK'
                ? 'bg-amber-950 text-amber-300 border border-amber-600 font-bold'
                : 'text-slate-400 hover:text-amber-300 hover:bg-slate-800/60'
            }`}
            title="Structuring / Smurfing near ₹50K reporting limits & clock tampered records"
          >
            <Flame className="w-3 h-3 text-amber-400" />
            <span>[High-Risk / Structuring]</span>
          </button>

          <button
            onClick={() => setFilterType('CARVED')}
            className={`px-2.5 py-1 rounded text-xs transition-colors cursor-pointer flex items-center gap-1 ${
              filterType === 'CARVED'
                ? 'bg-purple-950 text-purple-300 border border-purple-700 font-bold'
                : 'text-slate-400 hover:text-purple-300 hover:bg-slate-800/60'
            }`}
            title="Recovered from SQLite WAL frames and unallocated freelist blocks"
          >
            <Layers className="w-3 h-3 text-purple-400" />
            <span>[Carved / WAL Recovered]</span>
          </button>
        </div>

        {/* Right Search Input & CSV Export Button */}
        <div className="flex items-center space-x-2">
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2 top-2.5 pointer-events-none" />
            <input
              type="text"
              placeholder="Search UTR, VPA, Amount, Hex..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-48 sm:w-60 bg-slate-950 border border-slate-700/80 rounded pl-7 pr-2 py-1 text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
            />
          </div>

          <button
            onClick={handleExportCsv}
            className="px-2.5 py-1 bg-emerald-950/80 hover:bg-emerald-900 text-emerald-300 border border-emerald-700/80 rounded font-medium text-xs flex items-center space-x-1.5 transition-colors cursor-pointer"
            title="Download the filtered transactions as CSV"
          >
            <FileSpreadsheet className="w-3.5 h-3.5 text-emerald-400" />
            <span className="hidden sm:inline">Export CSV</span>
          </button>
        </div>
      </div>

      {/* 3. High-Contrast Master Transaction Grid with Virtualization */}
      <div
        ref={tableContainerRef}
        onScroll={handleTableScroll}
        className="flex-1 overflow-auto bg-slate-950 font-mono text-xs"
      >
        {filtered.length === 0 ? (
          <div className="h-full flex flex-col items-center justify-center text-slate-500 space-y-2 p-8">
            <CreditCard className="w-12 h-12 text-slate-700 stroke-[1.5]" />
            <span className="text-sm font-semibold text-slate-400">No Transactions Found</span>
            <p className="text-xs text-slate-600 max-w-sm text-center">
              {rawTransactions.length === 0
                ? 'No evidence dump loaded (HTTP 412 Precondition). Ingest a forensic archive or extracted folder to view UPI & banking records.'
                : 'No transactions match the selected filter criteria. Try selecting [All] or clearing the search query.'}
            </p>
          </div>
        ) : (
          <table className="w-full text-left border-collapse">
            <thead className="bg-slate-900 text-slate-400 text-[0.6875rem] uppercase tracking-wider sticky top-0 border-b border-slate-800 z-10 select-none shadow-sm">
              <tr>
                <th className="py-2.5 px-3 w-10 text-slate-500">#</th>
                <th className="py-2.5 px-3 w-24">State</th>
                <th className="py-2.5 px-3 w-44">Timestamp (IST)</th>
                <th className="py-2.5 px-3 w-32">UTR / RRN</th>
                <th className="py-2.5 px-3 w-28">App</th>
                <th className="py-2.5 px-3 w-32 text-right">Amount (INR)</th>
                <th className="py-2.5 px-3 w-24 text-center">Direction</th>
                <th className="py-2.5 px-3 w-40">Payer VPA / Account</th>
                <th className="py-2.5 px-3 w-44">Payee VPA</th>
                <th className="py-2.5 px-3 w-36">Corroboration</th>
                <th className="py-2.5 px-3 w-28">Byte Offset</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800">
              {startIndex > 0 && (
                <tr style={{ height: `${startIndex * ROW_HEIGHT}px` }}>
                  <td colSpan={11} className="p-0 border-none" />
                </tr>
              )}
              {visibleRows.map((tx, idx) => {
                const actualIndex = startIndex + idx;
                const isSelected = selectedTxId === tx.id || selectedTxId === tx.appTransactionId;
                const hexOffset = formatOffset(tx.provenance?.byteOffset);
                const isDebit = tx.direction === 'DEBIT';
                const dirKnown = tx.direction === 'DEBIT' || tx.direction === 'CREDIT';
                const isHighRisk = isHighRiskOrStructuring(tx);

                return (
                  <tr
                    key={tx.id || actualIndex}
                    onClick={() => handleSelectRow(tx)}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' || e.key === ' ') {
                        e.preventDefault();
                        handleSelectRow(tx);
                      }
                    }}
                    tabIndex={0}
                    aria-selected={isSelected}
                    style={{ height: `${ROW_HEIGHT}px` }}
                    className={`cursor-pointer transition-colors ${
                      isSelected
                        ? 'bg-cyan-950/60 text-slate-100 font-semibold border-l-4 border-cyan-400'
                        : 'hover:bg-slate-900 text-slate-300'
                    }`}
                  >
                    <td className="py-2 px-3 text-slate-500">{actualIndex + 1}</td>
                    <td className="py-2 px-3">{renderStateBadge(tx.provenance?.recoveryState)}</td>
                    <td className="py-2 px-3 text-[0.6875rem] text-slate-300">
                      <div className="flex items-center space-x-1.5">
                        <span>{tx.timestamp?.istFormatted ? tx.timestamp.istFormatted.substring(0, 19) : '-'}</span>
                        {tx.clockTamperDetected && (
                          <span title="Clock Tampering Detected! Device timestamp differs from internal transaction sequence token.">
                            <AlertTriangle className="w-3.5 h-3.5 text-rose-400 shrink-0" />
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="py-2 px-3 text-amber-300 font-semibold">{tx.utrNumber || 'N/A'}</td>
                    <td className="py-2 px-3 text-slate-200">
                      <span className="px-1.5 py-0.5 rounded bg-slate-900 border border-slate-800 text-[0.6875rem]">
                        {tx.sourceApp || 'UPI'}
                      </span>
                    </td>
                    <td className="py-2 px-3 text-right font-bold">
                      <span
                        className={!dirKnown ? 'text-slate-300' : isDebit ? 'text-rose-400' : 'text-emerald-400'}
                      >
                        {dirKnown ? (isDebit ? '-' : '+') : ''}₹{tx.amountInr.toLocaleString('en-IN', { minimumFractionDigits: 2 })}
                      </span>
                    </td>
                    <td className="py-2 px-3 text-center">
                      <span
                        className={`text-[0.6875rem] px-1.5 py-0.5 rounded font-bold font-mono ${
                          !dirKnown
                            ? 'bg-slate-900 text-slate-400 border border-slate-700'
                            : isDebit
                              ? 'bg-rose-950/70 text-rose-300 border border-rose-800/60'
                              : 'bg-emerald-950/70 text-emerald-300 border border-emerald-800/60'
                        }`}
                        title={dirKnown ? undefined : 'Direction not established by the evidence'}
                      >
                        {tx.direction}
                      </span>
                    </td>
                    <td className="py-2 px-3 truncate max-w-[170px]" title={tx.payerVpa || tx.accountMask || ''}>
                      <span className="text-slate-300">{tx.payerVpa || tx.accountMask || '-'}</span>
                    </td>
                    <td className="py-2 px-3 truncate max-w-[180px] text-teal-300" title={tx.payeeVpa || ''}>
                      <span>{tx.payeeVpa || '-'}</span>
                    </td>
                    <td className="py-2 px-3">
                      <div className="flex flex-wrap gap-1">
                        {(tx.corroboratedSources || ['APP_DB']).map((src) => (
                          <span
                            key={src}
                            className="text-[0.6875rem] bg-slate-900 text-slate-400 border border-slate-800 px-1 py-0.2 rounded font-mono"
                          >
                            {src}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td className="py-2 px-3 text-amber-400 text-[0.6875rem] font-mono hover:underline">
                      {hexOffset}
                    </td>
                  </tr>
                );
              })}
              {endIndex < totalCount && (
                <tr style={{ height: `${(totalCount - endIndex) * ROW_HEIGHT}px` }}>
                  <td colSpan={11} className="p-0 border-none" />
                </tr>
              )}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
};

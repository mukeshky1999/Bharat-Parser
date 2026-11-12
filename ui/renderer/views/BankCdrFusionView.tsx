import React, { useState, useRef } from 'react';
import {
  GitMerge,
  Upload,
  FileSpreadsheet,
  Phone,
  CheckCircle2,
  AlertTriangle,
  ArrowRight,
  ShieldCheck,
  Search,
  Filter,
  CreditCard,
  Clock,
  Layers,
  Database,
  PhoneCall
} from 'lucide-react';
import { forensicClient } from '../api/forensicClient';
import { useWorkbenchStore } from '../state/workbenchStore';
import { CallLogsView } from './CallLogsView';

export const BankCdrFusionView: React.FC = () => {
  const store = useWorkbenchStore();
  const [activeSubTab, setActiveSubTab] = useState<'BANK' | 'CDR' | 'CALLS'>('BANK');
  const [loading, setLoading] = useState<boolean>(false);
  const [statusMessage, setStatusMessage] = useState<string>('');

  // Bank Statement Reconciliation State
  const [bankResults, setBankResults] = useState<{
    totalRecords: number;
    matchedCount: number;
    unmatchedBankCount: number;
    rows: any[];
  } | null>(null);
  const [bankFilter, setBankFilter] = useState<'ALL' | 'MATCHED' | 'UNMATCHED'>('ALL');
  const [bankSearch, setBankSearch] = useState<string>('');

  // CDR Temporal Correlation State
  const [cdrResults, setCdrResults] = useState<{
    totalCalls: number;
    correlatedCount: number;
    rows: any[];
  } | null>(null);
  const [cdrFilter, setCdrFilter] = useState<'ALL' | 'PRE_TX' | 'POST_TX'>('ALL');
  const [cdrSearch, setCdrSearch] = useState<string>('');

  const bankFileInputRef = useRef<HTMLInputElement>(null);
  const cdrFileInputRef = useRef<HTMLInputElement>(null);

  // 1. Bank Statement Upload Handler
  const handleBankFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setLoading(true);
    setStatusMessage(`Parsing and reconciling bank statement: ${file.name}...`);

    try {
      const reader = new FileReader();
      reader.onload = async () => {
        const content = reader.result as string;
        const res = await forensicClient.fuseBankStatement(undefined, content, file.name);
        setLoading(false);

        if (res && res.success) {
          setBankResults({
            totalRecords: res.bank_records_count || 0,
            matchedCount: res.matched_count || 0,
            unmatchedBankCount: res.unmatched_bank_count || 0,
            rows: res.reconciliation_rows || []
          });
          setStatusMessage(`Successfully reconciled ${res.bank_records_count} bank statement entries against device ledger.`);
        } else {
          setStatusMessage(res?.message || res?.error || 'Failed to parse bank statement.');
        }
      };
      reader.onerror = () => {
        setLoading(false);
        setStatusMessage('Error reading file from disk.');
      };
      reader.readAsText(file);
    } catch (err: any) {
      setLoading(false);
      setStatusMessage(`Error: ${err?.message || 'Bank reconciliation failure.'}`);
    }
  };

  // 2. Telecom CDR Upload Handler
  const handleCdrFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setLoading(true);
    setStatusMessage(`Parsing and correlating telecom CDR records: ${file.name}...`);

    try {
      const reader = new FileReader();
      reader.onload = async () => {
        const content = reader.result as string;
        const res = await forensicClient.fuseCdr(undefined, content, file.name);
        setLoading(false);

        if (res && res.success) {
          setCdrResults({
            totalCalls: res.cdr_count || 0,
            correlatedCount: res.correlated_transactions_count || 0,
            rows: res.correlation_rows || []
          });
          setStatusMessage(`Successfully correlated ${res.correlated_transactions_count} CDR calls within 15-minute transaction windows.`);
        } else {
          setStatusMessage(res?.message || res?.error || 'Failed to parse telecom CDR records.');
        }
      };
      reader.onerror = () => {
        setLoading(false);
        setStatusMessage('Error reading CDR file from disk.');
      };
      reader.readAsText(file);
    } catch (err: any) {
      setLoading(false);
      setStatusMessage(`Error: ${err?.message || 'CDR correlation failure.'}`);
    }
  };

  // Filter Bank Records
  const filteredBankRows = (bankResults?.rows || []).filter((r) => {
    const status = String(r.Reconciliation_Status || '').toUpperCase();
    if (bankFilter === 'MATCHED' && !status.includes('MATCH')) return false;
    if (bankFilter === 'UNMATCHED' && status.includes('MATCH')) return false;

    if (bankSearch.trim()) {
      const q = bankSearch.toLowerCase();
      const narration = String(r.Narration || r.Description || '').toLowerCase();
      const utr = String(r.UTR || r.Reference_Number || '').toLowerCase();
      const amt = String(r.Amount || r.Debit || r.Credit || '').toLowerCase();
      return narration.includes(q) || utr.includes(q) || amt.includes(q);
    }
    return true;
  });

  // Filter CDR Records
  const filteredCdrRows = (cdrResults?.rows || []).filter((r) => {
    const delta = Number(r.Delta_Seconds || 0);
    if (cdrFilter === 'PRE_TX' && delta >= 0) return false;
    if (cdrFilter === 'POST_TX' && delta < 0) return false;

    if (cdrSearch.trim()) {
      const q = cdrSearch.toLowerCase();
      const caller = String(r.Caller || r.Calling_Number || '').toLowerCase();
      const callee = String(r.Callee || r.Called_Number || '').toLowerCase();
      const txid = String(r.TxID || r.Transaction_ID || '').toLowerCase();
      return caller.includes(q) || callee.includes(q) || txid.includes(q);
    }
    return true;
  });

  const handleRowClick = (item: any, type: string) => {
    store.setSelectedArtifact({
      id: `FUSION_${type}_${Date.now()}`,
      provenance: {
        evidenceId: 'FUSION_EXTERNAL',
        archivePath: 'External Statement / CDR Source',
        vfsInternalPath: item.Source_File || 'fusion_input.csv',
        containerType: 'RAW_CARVED',
        byteOffset: 0,
        byteLength: 128,
        recoveryState: item.Reconciliation_Status === 'MATCHED' ? 'ACTIVE' : 'CARVED_UNALLOCATED',
        rawPayloadHex: ''
      },
      notes: type === 'BANK'
        ? `Bank Statement: ${item.Narration || item.Description || 'Row'} | UTR: ${item.UTR || 'N/A'} | Status: ${item.Reconciliation_Status || 'Parsed'}`
        : `Telecom CDR: ${item.Caller || 'Caller'} -> ${item.Callee || 'Target'} (Delta: ${item.Delta_Seconds}s)`,
      itemType: type === 'BANK' ? 'Bank Reconciliation Record' : 'Telecom CDR Correlation',
      rawData: item
    });
  };

  return (
    <div className="flex-1 flex flex-col bg-slate-900 text-slate-100 overflow-hidden select-text font-sans">
      {/* Hidden File Inputs */}
      <input
        type="file"
        ref={bankFileInputRef}
        onChange={handleBankFileUpload}
        accept=".csv,.xlsx,.xls"
        className="hidden"
      />
      <input
        type="file"
        ref={cdrFileInputRef}
        onChange={handleCdrFileUpload}
        accept=".csv,.xlsx,.xls"
        className="hidden"
      />

      {/* 1. Sub-Tab Switcher & Primary Action Bar */}
      <div className="h-11 bg-slate-950 border-b border-slate-800 px-3 flex items-center justify-between shrink-0 select-none text-xs">
        <div className="flex items-center space-x-1.5">
          <button
            onClick={() => setActiveSubTab('BANK')}
            className={`px-3 py-1.5 rounded-md font-semibold text-xs flex items-center space-x-2 transition-colors cursor-pointer ${
              activeSubTab === 'BANK'
                ? 'bg-cyan-600 text-slate-50 shadow-sm'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
            }`}
          >
            <CreditCard className="w-4 h-4 text-emerald-400" />
            <span>Official Bank Statement Reconciliation</span>
          </button>

          <button
            onClick={() => setActiveSubTab('CDR')}
            className={`px-3 py-1.5 rounded-md font-semibold text-xs flex items-center space-x-2 transition-colors cursor-pointer ${
              activeSubTab === 'CDR'
                ? 'bg-cyan-600 text-slate-50 shadow-sm'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
            }`}
          >
            <Phone className="w-4 h-4 text-blue-400" />
            <span>Telecom CDR Temporal Correlation</span>
          </button>

          <button
            onClick={() => setActiveSubTab('CALLS')}
            className={`px-3 py-1.5 rounded-md font-semibold text-xs flex items-center space-x-2 transition-colors cursor-pointer ${
              activeSubTab === 'CALLS'
                ? 'bg-cyan-600 text-slate-50 shadow-sm'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
            }`}
          >
            <PhoneCall className="w-4 h-4 text-amber-400" />
            <span>Extracted Phone & VoIP Calls ({store.callLogs.length})</span>
          </button>
        </div>

        {/* Upload Action Button */}
        <div className="flex items-center space-x-2">
          {activeSubTab === 'BANK' ? (
            <button
              onClick={() => bankFileInputRef.current?.click()}
              disabled={loading}
              className="px-3 py-1.5 bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-bold rounded flex items-center space-x-1.5 transition-colors cursor-pointer shadow-sm text-xs"
            >
              <Upload className="w-3.5 h-3.5" />
              <span>+ Upload Bank Statement (CSV/XLSX)</span>
            </button>
          ) : activeSubTab === 'CDR' ? (
            <button
              onClick={() => cdrFileInputRef.current?.click()}
              disabled={loading}
              className="px-3 py-1.5 bg-blue-600 hover:bg-blue-500 text-slate-950 font-bold rounded flex items-center space-x-1.5 transition-colors cursor-pointer shadow-sm text-xs"
            >
              <Upload className="w-3.5 h-3.5" />
              <span>+ Upload Telecom CDR (CSV/XLSX)</span>
            </button>
          ) : null}
        </div>
      </div>

      {/* Status Alert Notification */}
      {statusMessage && (
        <div className="bg-slate-900 border-b border-cyan-800/60 px-4 py-1.5 flex items-center justify-between text-xs text-cyan-200 font-mono select-none">
          <div className="flex items-center space-x-2">
            <span className="w-2 h-2 rounded-full bg-cyan-400" />
            <span>{statusMessage}</span>
          </div>
          <button onClick={() => setStatusMessage('')} className="text-slate-400 hover:text-slate-50">
            ×
          </button>
        </div>
      )}

      {/* 2. Main Tab View Canvas */}
      {activeSubTab === 'BANK' ? (
        <div className="flex-1 flex flex-col overflow-hidden">
          {/* Stat Cards Strip */}
          <div className="h-14 bg-slate-900 border-b border-slate-800 px-4 flex items-center justify-between shrink-0 select-none text-xs">
            <div className="flex items-center space-x-6">
              <div>
                <span className="text-[0.6875rem] text-slate-500 uppercase tracking-wider block font-semibold">
                  Total Bank Records
                </span>
                <span className="text-base font-extrabold text-slate-50 font-mono">
                  {bankResults?.totalRecords ?? 0}
                </span>
              </div>

              <div className="h-7 w-[1px] bg-slate-800" />

              <div>
                <span className="text-[0.6875rem] text-emerald-400 uppercase tracking-wider block font-semibold flex items-center gap-1">
                  <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                  Matched by Reference
                </span>
                <span className="text-base font-extrabold text-emerald-400 font-mono">
                  {bankResults?.matchedCount ?? 0}
                </span>
              </div>

              <div className="h-7 w-[1px] bg-slate-800" />

              <div>
                <span className="text-[0.6875rem] text-rose-400 uppercase tracking-wider block font-semibold flex items-center gap-1">
                  <AlertTriangle className="w-3 h-3 text-rose-400" />
                  Not Found on Phone
                </span>
                <span className="text-base font-extrabold text-rose-400 font-mono">
                  {bankResults?.unmatchedBankCount ?? 0}
                </span>
              </div>
            </div>

            {/* Filter Pills & Search */}
            <div className="flex items-center space-x-2">
              <div className="flex items-center bg-slate-900 border border-slate-800 rounded p-0.5 text-xs">
                <button
                  onClick={() => setBankFilter('ALL')}
                  className={`px-2 py-0.5 rounded transition-colors ${
                    bankFilter === 'ALL' ? 'bg-slate-700 text-slate-50 font-bold' : 'text-slate-400'
                  }`}
                >
                  All
                </button>
                <button
                  onClick={() => setBankFilter('MATCHED')}
                  className={`px-2 py-0.5 rounded transition-colors ${
                    bankFilter === 'MATCHED' ? 'bg-emerald-950 text-emerald-300 font-bold border border-emerald-700' : 'text-slate-400'
                  }`}
                >
                  In both
                </button>
                <button
                  onClick={() => setBankFilter('UNMATCHED')}
                  className={`px-2 py-0.5 rounded transition-colors ${
                    bankFilter === 'UNMATCHED' ? 'bg-rose-950 text-rose-300 font-bold border border-rose-700' : 'text-slate-400'
                  }`}
                >
                  Bank only (not found on device)
                </button>
              </div>

              <div className="relative">
                <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2 top-2 pointer-events-none" />
                <input
                  type="text"
                  placeholder="Filter statement..."
                  value={bankSearch}
                  onChange={(e) => setBankSearch(e.target.value)}
                  className="w-44 bg-slate-950 border border-slate-700 rounded pl-7 pr-2 py-1 text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
                />
              </div>
            </div>
          </div>

          {/* Bank Reconciliation Table */}
          <div className="flex-1 overflow-auto bg-slate-950 font-mono text-xs">
            {!bankResults ? (
              <div className="h-full flex flex-col items-center justify-center text-slate-500 space-y-3 p-8">
                <FileSpreadsheet className="w-12 h-12 text-slate-700 stroke-[1.5]" />
                <span className="text-sm font-semibold text-slate-300">
                  No Official Bank Statement Loaded
                </span>
                <p className="text-xs text-slate-500 max-w-md text-center">
                  Upload an official bank statement (CSV or XLSX format from SBI, HDFC, ICICI, Axis, PNB) to run forensic cross-reconciliation against the device's UPI transactions and recover wiped entries.
                </p>
                <button
                  onClick={() => bankFileInputRef.current?.click()}
                  className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-bold rounded flex items-center space-x-1.5 transition-colors cursor-pointer text-xs"
                >
                  <Upload className="w-3.5 h-3.5" />
                  <span>Upload Statement to Begin Reconciliation</span>
                </button>
              </div>
            ) : filteredBankRows.length === 0 ? (
              <div className="h-full flex flex-col items-center justify-center text-slate-500 space-y-2 p-8">
                <span className="text-sm font-semibold text-slate-400">No matching reconciliation rows found</span>
              </div>
            ) : (
              <table className="w-full text-left border-collapse">
                <thead className="bg-slate-900 text-slate-400 text-[0.6875rem] uppercase tracking-wider sticky top-0 border-b border-slate-800 z-10 select-none">
                  <tr>
                    <th className="py-2.5 px-3 w-10 text-slate-500">#</th>
                    <th className="py-2.5 px-3 w-48">Reconciliation Status</th>
                    <th className="py-2.5 px-3 w-40">Statement Date</th>
                    <th className="py-2.5 px-3">Narration / Description</th>
                    <th className="py-2.5 px-3 w-36">UTR / Reference No</th>
                    <th className="py-2.5 px-3 w-32 text-right">Debit / Credit (INR)</th>
                    <th className="py-2.5 px-3 w-36">Phone Evidence Match</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800">
                  {filteredBankRows.map((r, idx) => {
                    const status = String(r.Reconciliation_Status || '').toUpperCase();
                    const isMatched = status.includes('MATCH');
                    const amt = r.Amount || r.Debit || r.Credit || 0;

                    return (
                      <tr
                        key={idx}
                        onClick={() => handleRowClick(r, 'BANK')}
                        className={`cursor-pointer transition-colors ${
                          isMatched
                            ? 'hover:bg-slate-900 text-slate-200'
                            : 'bg-rose-950/20 hover:bg-rose-950/30 text-rose-200 border-l-2 border-rose-500'
                        }`}
                      >
                        <td className="py-2 px-3 text-slate-500">{idx + 1}</td>
                        <td className="py-2 px-3">
                          {isMatched ? (
                            <span className="px-2 py-0.5 rounded text-[0.6875rem] font-bold bg-emerald-950 text-emerald-300 border border-emerald-700/80 flex items-center gap-1 w-fit">
                              <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                              VERIFIED BOTH PHONE & BANK
                            </span>
                          ) : (
                            <span className="px-2 py-0.5 rounded text-[0.6875rem] font-bold bg-rose-950 text-rose-300 border border-rose-700/80 flex items-center gap-1 w-fit">
                              <AlertTriangle className="w-3 h-3 text-rose-400" />
                              IN BANK STATEMENT ONLY (WIPED)
                            </span>
                          )}
                        </td>
                        <td className="py-2 px-3 text-slate-300">{r.Date || r.Timestamp || '-'}</td>
                        <td className="py-2 px-3 text-slate-100 font-sans max-w-sm truncate" title={r.Narration || r.Description || ''}>
                          {r.Narration || r.Description || '-'}
                        </td>
                        <td className="py-2 px-3 text-amber-300 font-semibold">{r.UTR || r.Reference_Number || 'N/A'}</td>
                        <td className="py-2 px-3 text-right font-bold text-slate-100">
                          ₹{Number(amt).toLocaleString('en-IN', { minimumFractionDigits: 2 })}
                        </td>
                        <td className="py-2 px-3 text-cyan-300 font-mono text-[0.6875rem]">
                          {r.Device_Tx_ID || (isMatched ? 'Corroborated in App DB' : 'Not Found in Extracted DB')}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            )}
          </div>
        </div>
      ) : activeSubTab === 'CDR' ? (
        /* CDR Temporal Correlation View */
        <div className="flex-1 flex flex-col overflow-hidden">
          {/* Stat Cards Strip */}
          <div className="h-14 bg-slate-900 border-b border-slate-800 px-4 flex items-center justify-between shrink-0 select-none text-xs">
            <div className="flex items-center space-x-6">
              <div>
                <span className="text-[0.6875rem] text-slate-500 uppercase tracking-wider block font-semibold">
                  Total CDR Calls
                </span>
                <span className="text-base font-extrabold text-slate-50 font-mono">
                  {cdrResults?.totalCalls ?? 0}
                </span>
              </div>

              <div className="h-7 w-[1px] bg-slate-800" />

              <div>
                <span className="text-[0.6875rem] text-blue-400 uppercase tracking-wider block font-semibold flex items-center gap-1">
                  <Phone className="w-3 h-3 text-blue-400" />
                  Correlated Financial Transactions
                </span>
                <span className="text-base font-extrabold text-blue-400 font-mono">
                  {cdrResults?.correlatedCount ?? 0}
                </span>
              </div>
            </div>

            {/* Filter Pills & Search */}
            <div className="flex items-center space-x-2">
              <div className="flex items-center bg-slate-900 border border-slate-800 rounded p-0.5 text-xs">
                <button
                  onClick={() => setCdrFilter('ALL')}
                  className={`px-2 py-0.5 rounded transition-colors ${
                    cdrFilter === 'ALL' ? 'bg-slate-700 text-slate-50 font-bold' : 'text-slate-400'
                  }`}
                >
                  All Calls
                </button>
                <button
                  onClick={() => setCdrFilter('PRE_TX')}
                  className={`px-2 py-0.5 rounded transition-colors ${
                    cdrFilter === 'PRE_TX' ? 'bg-amber-950 text-amber-300 font-bold border border-amber-700' : 'text-slate-400'
                  }`}
                >
                  Pre-Transaction (Lure)
                </button>
                <button
                  onClick={() => setCdrFilter('POST_TX')}
                  className={`px-2 py-0.5 rounded transition-colors ${
                    cdrFilter === 'POST_TX' ? 'bg-emerald-950 text-emerald-300 font-bold border border-emerald-700' : 'text-slate-400'
                  }`}
                >
                  Post-Transaction
                </button>
              </div>

              <div className="relative">
                <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2 top-2 pointer-events-none" />
                <input
                  type="text"
                  placeholder="Filter CDR..."
                  value={cdrSearch}
                  onChange={(e) => setCdrSearch(e.target.value)}
                  className="w-44 bg-slate-950 border border-slate-700 rounded pl-7 pr-2 py-1 text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
                />
              </div>
            </div>
          </div>

          {/* CDR Correlation Table */}
          <div className="flex-1 overflow-auto bg-slate-950 font-mono text-xs">
            {!cdrResults ? (
              <div className="h-full flex flex-col items-center justify-center text-slate-500 space-y-3 p-8">
                <Phone className="w-12 h-12 text-slate-700 stroke-[1.5]" />
                <span className="text-sm font-semibold text-slate-300">
                  No Telecom CDR Data Loaded
                </span>
                <p className="text-xs text-slate-500 max-w-md text-center">
                  Upload official telecom CDR records (CSV format from Airtel, Jio, Vi, BSNL) to correlate cellular calls with UPI, crypto, and remote access events within 15-minute suspect coordination windows.
                </p>
                <button
                  onClick={() => cdrFileInputRef.current?.click()}
                  className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-slate-950 font-bold rounded flex items-center space-x-1.5 transition-colors cursor-pointer text-xs"
                >
                  <Upload className="w-3.5 h-3.5" />
                  <span>Upload Telecom CDR</span>
                </button>
              </div>
            ) : filteredCdrRows.length === 0 ? (
              <div className="h-full flex flex-col items-center justify-center text-slate-500 space-y-2 p-8">
                <span className="text-sm font-semibold text-slate-400">No matching CDR rows found</span>
              </div>
            ) : (
              <table className="w-full text-left border-collapse">
                <thead className="bg-slate-900 text-slate-400 text-[0.6875rem] uppercase tracking-wider sticky top-0 border-b border-slate-800 z-10 select-none">
                  <tr>
                    <th className="py-2.5 px-3 w-10 text-slate-500">#</th>
                    <th className="py-2.5 px-3 w-40">Call Timestamp</th>
                    <th className="py-2.5 px-3 w-40">Caller Phone / ID</th>
                    <th className="py-2.5 px-3 w-40">Callee Phone / Target</th>
                    <th className="py-2.5 px-3 w-28 text-right">Duration</th>
                    <th className="py-2.5 px-3 w-36">Correlated TxID</th>
                    <th className="py-2.5 px-3 w-28 text-center">Delta</th>
                    <th className="py-2.5 px-3">Correlation Role</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800">
                  {filteredCdrRows.map((r, idx) => {
                    const delta = Number(r.Delta_Seconds || 0);
                    const isPreTx = delta < 0;

                    return (
                      <tr
                        key={idx}
                        onClick={() => handleRowClick(r, 'CDR')}
                        className="cursor-pointer hover:bg-slate-900 text-slate-300 transition-colors"
                      >
                        <td className="py-2 px-3 text-slate-500">{idx + 1}</td>
                        <td className="py-2 px-3 text-slate-200">{r.Call_Timestamp || r.Timestamp || '-'}</td>
                        <td className="py-2 px-3 text-amber-300 font-bold">{r.Caller || r.Calling_Number || '-'}</td>
                        <td className="py-2 px-3 text-teal-300 font-bold">{r.Callee || r.Called_Number || '-'}</td>
                        <td className="py-2 px-3 text-right font-mono text-slate-300">
                          {r.Duration_Seconds ? `${r.Duration_Seconds}s` : '-'}
                        </td>
                        <td className="py-2 px-3 text-cyan-300 font-mono text-[0.6875rem]">{r.Correlated_Tx_ID || r.TxID || '-'}</td>
                        <td className="py-2 px-3 text-center">
                          <span
                            className={`px-1.5 py-0.5 rounded text-[0.6875rem] font-bold font-mono ${
                              isPreTx
                                ? 'bg-amber-950 text-amber-300 border border-amber-700/80'
                                : 'bg-emerald-950 text-emerald-300 border border-emerald-700/80'
                            }`}
                          >
                            {delta > 0 ? `+${delta}s` : `${delta}s`}
                          </span>
                        </td>
                        <td className="py-2 px-3 text-slate-200 font-sans text-xs">
                          {r.Insight || (isPreTx ? 'Pre-transaction coordination call' : 'Post-transaction confirmation call')}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            )}
          </div>
        </div>
      ) : (
        /* Device Calls & VoIP Logs Sub-Tab */
        <CallLogsView />
      )}
    </div>
  );
};

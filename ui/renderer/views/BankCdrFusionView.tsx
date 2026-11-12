import React, { useMemo, useRef, useState } from 'react';
import { Upload } from 'lucide-react';
import { forensicClient } from '../api/forensicClient';
import { useWorkbenchStore } from '../state/workbenchStore';
import { CallLogsView } from './CallLogsView';
import { DataGrid, FilterInput, GridColumn, Segmented, Unset } from '../workspace/DataGrid';

type Sub = 'BANK' | 'CDR' | 'CALLS';
type BankFilter = 'ALL' | 'MATCHED' | 'UNMATCHED';
type CdrFilter = 'ALL' | 'BEFORE' | 'AFTER';
type Row = Record<string, any>;

const btn = 'h-8 px-3 rounded border border-slate-700 text-slate-200 hover:bg-slate-800 disabled:opacity-40';
const btnPrimary = 'h-8 px-3 rounded bg-cyan-600 text-slate-50 hover:bg-cyan-500 disabled:opacity-40 inline-flex items-center gap-2';

const asText = (v: unknown): string => (v === null || v === undefined || v === '' ? '' : String(v));
const orUnset = (v: unknown) => (asText(v) ? asText(v) : <Unset />);
const money = (v: unknown) => {
  const n = Number(v);
  return Number.isFinite(n) && asText(v) !== '' ? `₹${n.toLocaleString('en-IN', { minimumFractionDigits: 2 })}` : '';
};

/**
 * Two things you bring in yourself, set beside what the phone holds:
 *  - a bank statement: each line is shown as found on the phone too, or only in the statement;
 *  - call detail records from a telecom provider: each call is shown with its time distance from a payment.
 * A line "only in the statement" means no record was matched on the extracted device; it does not say why. A call close
 * in time to a payment is a lead, not proof the two are related.
 */
export const BankCdrFusionView: React.FC = () => {
  const store = useWorkbenchStore();
  const [sub, setSub] = useState<Sub>('BANK');
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState('');
  const [bank, setBank] = useState<{ total: number; matched: number; unmatched: number; rows: Row[] } | null>(null);
  const [cdr, setCdr] = useState<{ total: number; correlated: number; rows: Row[] } | null>(null);
  const [bankFilter, setBankFilter] = useState<BankFilter>('ALL');
  const [cdrFilter, setCdrFilter] = useState<CdrFilter>('ALL');
  const [bankSearch, setBankSearch] = useState('');
  const [cdrSearch, setCdrSearch] = useState('');
  const [selected, setSelected] = useState<string | null>(null);
  const bankInput = useRef<HTMLInputElement>(null);
  const cdrInput = useRef<HTMLInputElement>(null);

  const readFile = (file: File, onText: (text: string) => Promise<void>) => {
    const reader = new FileReader();
    reader.onload = () => { void onText(String(reader.result)); };
    reader.onerror = () => { setLoading(false); setMessage('The file could not be read.'); };
    reader.readAsText(file);
  };

  const uploadBank = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    e.target.value = '';
    if (!file) return;
    setLoading(true); setMessage(`Reading ${file.name}…`);
    readFile(file, async (content) => {
      const res = await forensicClient.fuseBankStatement(undefined, content, file.name);
      setLoading(false);
      if (res && res.success) {
        setBank({ total: res.bank_records_count || 0, matched: res.matched_count || 0, unmatched: res.unmatched_bank_count || 0, rows: (res.reconciliation_rows || []) as Row[] });
        setMessage(`${res.bank_records_count} statement lines were compared with the payments on the device.`);
      } else setMessage(res?.message || res?.error || 'The statement could not be read.');
    });
  };

  const uploadCdr = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    e.target.value = '';
    if (!file) return;
    setLoading(true); setMessage(`Reading ${file.name}…`);
    readFile(file, async (content) => {
      const res = await forensicClient.fuseCdr(undefined, content, file.name);
      setLoading(false);
      if (res && res.success) {
        setCdr({ total: res.cdr_count || 0, correlated: res.correlated_transactions_count || 0, rows: (res.correlation_rows || []) as Row[] });
        setMessage(`${res.correlated_transactions_count} calls fall within 15 minutes of a payment on the device.`);
      } else setMessage(res?.message || res?.error || 'The call records could not be read.');
    });
  };

  const bankRows = useMemo(() => (bank?.rows ?? []).filter((r) => {
    const matched = String(r.Reconciliation_Status || '').toUpperCase().includes('MATCH');
    if (bankFilter === 'MATCHED' && !matched) return false;
    if (bankFilter === 'UNMATCHED' && matched) return false;
    const q = bankSearch.trim().toLowerCase();
    if (!q) return true;
    return [r.Narration, r.Description, r.UTR, r.Reference_Number, r.Amount, r.Debit, r.Credit].some((v) => asText(v).toLowerCase().includes(q));
  }), [bank, bankFilter, bankSearch]);

  const cdrRows = useMemo(() => (cdr?.rows ?? []).filter((r) => {
    const delta = Number(r.Delta_Seconds);
    if (cdrFilter === 'BEFORE' && !(delta < 0)) return false;
    if (cdrFilter === 'AFTER' && !(delta >= 0)) return false;
    const q = cdrSearch.trim().toLowerCase();
    if (!q) return true;
    return [r.Caller, r.Calling_Number, r.Callee, r.Called_Number, r.TxID, r.Transaction_ID, r.Correlated_Tx_ID].some((v) => asText(v).toLowerCase().includes(q));
  }), [cdr, cdrFilter, cdrSearch]);

  const select = (item: Row, kind: 'BANK' | 'CDR', key: string) => {
    setSelected(key);
    void store.setSelectedArtifact({
      id: `FUSION_${kind}_${key}`,
      provenance: {
        evidenceId: 'FUSION_EXTERNAL', archivePath: 'File supplied by the examiner', vfsInternalPath: item.Source_File || 'supplied file',
        containerType: 'RAW_CARVED', byteOffset: -1, byteLength: 0, recoveryState: 'ACTIVE', rawPayloadHex: '',
      },
      notes: kind === 'BANK'
        ? `Bank statement line: ${item.Narration || item.Description || 'no narration'} | UTR: ${item.UTR || 'not recorded'} | ${item.Reconciliation_Status || 'not compared'}`
        : `Call: ${item.Caller || 'caller not recorded'} to ${item.Callee || 'callee not recorded'} (${item.Delta_Seconds ?? 'time distance not recorded'} s from the payment)`,
      itemType: kind === 'BANK' ? 'Bank statement line' : 'Telecom call record',
      rawData: item,
    });
  };

  const bankColumns: Array<GridColumn<Row>> = [
    { key: 'status', label: 'Compared with the phone', width: '16rem',
      cell: (r) => (String(r.Reconciliation_Status || '').toUpperCase().includes('MATCH')
        ? <span className="text-emerald-300">Found on the phone too</span>
        : <span className="text-amber-300" title="No record on the extracted device was matched to this line. The reason is not known.">Only in the statement</span>),
      text: (r) => (String(r.Reconciliation_Status || '').toUpperCase().includes('MATCH') ? 'Found on the phone too' : 'Only in the statement') },
    { key: 'date', label: 'Statement date', width: '10rem', cell: (r) => orUnset(r.Date || r.Timestamp), text: (r) => asText(r.Date || r.Timestamp) || 'not recorded' },
    { key: 'narration', label: 'Narration', width: 'minmax(14rem,2fr)', cell: (r) => orUnset(r.Narration || r.Description), text: (r) => asText(r.Narration || r.Description) || 'not recorded' },
    { key: 'utr', label: 'UTR / reference', width: '11rem', cell: (r) => orUnset(r.UTR || r.Reference_Number), text: (r) => asText(r.UTR || r.Reference_Number) || 'not recorded' },
    { key: 'amount', label: 'Amount', width: '9rem', align: 'right', cell: (r) => money(r.Amount || r.Debit || r.Credit) || <Unset />, text: (r) => asText(r.Amount || r.Debit || r.Credit) || 'not recorded' },
    { key: 'device', label: 'Phone record', width: '12rem', cell: (r) => orUnset(r.Device_Tx_ID), text: (r) => asText(r.Device_Tx_ID) || 'not recorded' },
  ];

  const cdrColumns: Array<GridColumn<Row>> = [
    { key: 'time', label: 'Call time', width: '11rem', cell: (r) => orUnset(r.Call_Timestamp || r.Timestamp), text: (r) => asText(r.Call_Timestamp || r.Timestamp) || 'not recorded' },
    { key: 'caller', label: 'Caller', width: '11rem', cell: (r) => orUnset(r.Caller || r.Calling_Number), text: (r) => asText(r.Caller || r.Calling_Number) || 'not recorded' },
    { key: 'callee', label: 'Called number', width: '11rem', cell: (r) => orUnset(r.Callee || r.Called_Number), text: (r) => asText(r.Callee || r.Called_Number) || 'not recorded' },
    { key: 'duration', label: 'Duration', width: '7rem', align: 'right', cell: (r) => (asText(r.Duration_Seconds) ? `${r.Duration_Seconds} s` : <Unset />), text: (r) => (asText(r.Duration_Seconds) ? `${r.Duration_Seconds} s` : 'not recorded') },
    { key: 'tx', label: 'Nearby payment', width: '12rem', cell: (r) => orUnset(r.Correlated_Tx_ID || r.TxID), text: (r) => asText(r.Correlated_Tx_ID || r.TxID) || 'not recorded' },
    { key: 'delta', label: 'Time from payment', width: '9rem', align: 'right',
      cell: (r) => (Number.isFinite(Number(r.Delta_Seconds)) && asText(r.Delta_Seconds) !== ''
        ? `${Number(r.Delta_Seconds) > 0 ? '+' : ''}${r.Delta_Seconds} s ${Number(r.Delta_Seconds) < 0 ? '(before)' : '(after)'}` : <Unset />),
      text: (r) => (asText(r.Delta_Seconds) ? `${r.Delta_Seconds} s` : 'not recorded') },
  ];

  const tabBtn = (id: Sub, label: string) => (
    <button key={id} role="tab" aria-selected={sub === id} onClick={() => setSub(id)}
      className={`h-8 px-3 rounded border ${sub === id ? 'border-cyan-600 bg-slate-800 text-slate-50' : 'border-slate-700 text-slate-300 hover:bg-slate-800'}`}>{label}</button>
  );

  return (
    <div className="flex-1 flex flex-col min-w-0 min-h-0 bg-slate-950">
      <input type="file" ref={bankInput} onChange={uploadBank} accept=".csv,.xlsx,.xls" className="hidden" aria-label="Bank statement file" />
      <input type="file" ref={cdrInput} onChange={uploadCdr} accept=".csv,.xlsx,.xls" className="hidden" aria-label="Call records file" />

      <div className="shrink-0 flex flex-wrap items-center gap-2 px-4 py-3 border-b border-slate-800" role="tablist" aria-label="Bank and call records">
        {tabBtn('BANK', 'Bank statement')}
        {tabBtn('CDR', 'Telecom call records')}
        {tabBtn('CALLS', `Calls on the device (${store.callLogs.length})`)}
        <div className="ml-auto flex items-center gap-2">
          {sub === 'BANK' && <button className={btnPrimary} disabled={loading} onClick={() => bankInput.current?.click()}><Upload className="w-4 h-4" aria-hidden="true" />Add a bank statement (CSV or XLSX)</button>}
          {sub === 'CDR' && <button className={btnPrimary} disabled={loading} onClick={() => cdrInput.current?.click()}><Upload className="w-4 h-4" aria-hidden="true" />Add call records (CSV or XLSX)</button>}
        </div>
      </div>

      {message && (
        <div className="shrink-0 px-4 py-2 border-b border-slate-800 text-slate-300 flex items-center justify-between" role="status">
          <span>{message}</span>
          <button className="text-slate-400 hover:text-slate-50" aria-label="Dismiss" onClick={() => setMessage('')}>×</button>
        </div>
      )}

      {sub === 'BANK' && (
        <>
          {bank && (
            <div className="shrink-0 px-4 py-2 border-b border-slate-800 text-slate-300">
              {bank.total} statement line{bank.total === 1 ? '' : 's'} · {bank.matched} found on the phone too · {bank.unmatched} only in the statement
            </div>
          )}
          <DataGrid<Row>
            tableId="fusion_bank" title="Bank statement against the phone" columns={bankColumns} rows={bankRows} totalBeforeFilter={bank?.rows.length}
            rowKey={(_, i) => `b${i}`} selectedKey={selected} onSelect={(r) => select(r, 'BANK', `b${bankRows.indexOf(r)}`)} exportName="bank_statement_comparison.csv"
            toolbar={(
              <>
                <FilterInput label="Filter the statement" value={bankSearch} onChange={setBankSearch} placeholder="Narration, UTR, amount…" />
                <Segmented<BankFilter> label="Show" value={bankFilter} onChange={setBankFilter}
                  options={[{ value: 'ALL', label: 'All lines' }, { value: 'MATCHED', label: 'On the phone too' }, { value: 'UNMATCHED', label: 'Only in the statement' }]} />
              </>
            )}
            empty={!bank
              ? 'No bank statement has been added. Add one to compare each line with the payments found on the device. The statement is a file you supply; the tool does not vouch for it.'
              : 'No line matches this filter.'}
          />
        </>
      )}

      {sub === 'CDR' && (
        <>
          {cdr && (
            <div className="shrink-0 px-4 py-2 border-b border-slate-800 text-slate-300">
              {cdr.total} call{cdr.total === 1 ? '' : 's'} · {cdr.correlated} within 15 minutes of a payment. A call near a payment in time is a lead, not proof the two are related.
            </div>
          )}
          <DataGrid<Row>
            tableId="fusion_cdr" title="Telecom call records against payments" columns={cdrColumns} rows={cdrRows} totalBeforeFilter={cdr?.rows.length}
            rowKey={(_, i) => `c${i}`} selectedKey={selected} onSelect={(r) => select(r, 'CDR', `c${cdrRows.indexOf(r)}`)} exportName="call_records_comparison.csv"
            toolbar={(
              <>
                <FilterInput label="Filter the calls" value={cdrSearch} onChange={setCdrSearch} placeholder="Number or payment…" />
                <Segmented<CdrFilter> label="Show" value={cdrFilter} onChange={setCdrFilter}
                  options={[{ value: 'ALL', label: 'All calls' }, { value: 'BEFORE', label: 'Before the payment' }, { value: 'AFTER', label: 'After the payment' }]} />
              </>
            )}
            empty={!cdr
              ? 'No call records have been added. Add a provider’s call detail records (CSV or XLSX) to see which calls fall within 15 minutes of a payment on the device.'
              : 'No call matches this filter.'}
          />
        </>
      )}

      {sub === 'CALLS' && <CallLogsView />}
    </div>
  );
};

import React, { useEffect, useMemo, useState } from 'react';
import { useWorkbenchStore, parseProvenance } from '../state/workbenchStore';
import { usePreferences } from '../state/preferencesStore';
import { fetchAllRows } from '../utils/artifactRows';
import { DataGrid, FilterInput, GridColumn, Unset } from '../workspace/DataGrid';
import { SavedFilters } from '../workspace/SavedFilters';
import { BANK_ALERTS_NOTICE } from '../workspace/stages';
import { normalizeTimestamp } from '../../shared/forensic-types';

type Row = Record<string, any>;

const CATEGORY_TEXT: Record<string, string> = {
  TX_DEBIT_OUTFLOW: 'Money out (debit)',
  TX_CREDIT_INFLOW: 'Money in (credit)',
  ATM_CASH_WITHDRAWAL: 'Cash withdrawal',
  BENEFICIARY_ADDITION_ALERT: 'New beneficiary added',
  OTP_AUTHENTICATION_CODE: 'One-time code',
  LIEN_HOLD_OR_FREEZE_ALERT: 'Lien, hold or freeze notice',
  UPI_DEVICE_BINDING_OR_MPIN: 'UPI device binding or PIN',
  UPI_AUTOPAY_OR_MANDATE: 'Autopay or mandate',
  FAILED_OR_DECLINED_TX: 'Failed or declined',
  UNCLASSIFIED: 'Not classified',
};

const text = (v: unknown) => (v === null || v === undefined || v === '' ? '' : String(v));
const cell = (v: unknown) => (text(v) ? text(v) : <Unset />);
const money = (v: unknown) => (text(v) && Number.isFinite(Number(v)) ? `₹${Number(v).toLocaleString('en-IN', { minimumFractionDigits: 2 })}` : '');

/**
 * Bank and SMS notices found in the phone's SMS database. IN TESTING: the reader has been run on made-up data only.
 * The kind of notice is the tool's reading of the wording; the sender header is resolved only when the tool recognises it.
 */
export const BankAlertsView: React.FC = () => {
  const manifest = useWorkbenchStore((s) => s.caseManifest);
  const selected = useWorkbenchStore((s) => s.selectedArtifact);
  const setSelectedArtifact = useWorkbenchStore((s) => s.setSelectedArtifact);
  const tz = usePreferences((s) => s.timeZone);
  const [rows, setRows] = useState<Row[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [category, setCategory] = useState('');
  const [query, setQuery] = useState('');

  useEffect(() => {
    if (!manifest) { setRows([]); return; }
    const ctl = new AbortController();
    setLoading(true); setError(''); setRows([]);
    fetchAllRows('bank_alerts', ctl.signal)
      .then((r) => { if (!ctl.signal.aborted) setRows(r); })
      .catch((e) => { if (e?.name !== 'AbortError' && !ctl.signal.aborted) setError(e?.message || 'The alerts could not be loaded.'); })
      .finally(() => { if (!ctl.signal.aborted) setLoading(false); });
    return () => ctl.abort();
  }, [manifest?.caseId, manifest?.evidenceFileName]); // eslint-disable-line react-hooks/exhaustive-deps

  const NONE = '__none__';                                 // an alert with no kind recorded
  const kinds = useMemo(() => Array.from(new Set(rows.map((r) => (r.Category === null || r.Category === undefined || r.Category === '' ? NONE : String(r.Category))))).sort(), [rows]);
  const shown = useMemo(() => {
    const q = query.trim().toLowerCase();
    return rows.filter((r) => {
      if (category === NONE ? !(r.Category === null || r.Category === undefined || r.Category === '') : (category && r.Category !== category)) return false;
      if (!q) return true;
      return Object.values(r).some((v) => v !== null && String(v).toLowerCase().includes(q));
    });
  }, [rows, category, query]);

  const when = (r: Row) => {
    const t = tz === 'IST' ? r.Received_IST : r.Received_UTC;
    return text(t);
  };

  const columns: Array<GridColumn<Row>> = [
    { key: 'time', label: tz === 'IST' ? 'Received (IST)' : 'Received (UTC)', width: '17rem', cell: (r) => cell(when(r)), text: (r) => when(r) || 'not recorded' },
    { key: 'kind', label: 'Kind of notice', width: '14rem', cell: (r) => CATEGORY_TEXT[r.Category] ?? cell(r.Category), text: (r) => CATEGORY_TEXT[r.Category] ?? (text(r.Category) || 'not recorded') },
    { key: 'inst', label: 'Sender', width: '14rem', cell: (r) => (text(r.Institution) ? `${r.Institution} (${text(r.Sender)})` : text(r.Sender) ? `${r.Sender} (institution not resolved)` : <Unset />), text: (r) => [text(r.Institution), text(r.Sender)].filter(Boolean).join(' / ') || 'not recorded' },
    { key: 'amount', label: 'Amount', width: '10rem', align: 'right', cell: (r) => cell(money(r.Amount)), text: (r) => text(r.Amount) || 'not recorded' },
    { key: 'balance', label: 'Balance stated', width: '10rem', align: 'right', cell: (r) => cell(money(r.Balance)), text: (r) => text(r.Balance) || 'not recorded' },
    { key: 'acct', label: 'Account', width: '10rem', cell: (r) => cell(r.Account_Masked), text: (r) => text(r.Account_Masked) || 'not recorded' },
    { key: 'utr', label: 'Reference', width: '12rem', cell: (r) => cell(r.UTR), text: (r) => text(r.UTR) || 'not recorded' },
    { key: 'cp', label: 'Counterparty', width: 'minmax(10rem,1fr)', cell: (r) => cell(r.Counterparty), text: (r) => text(r.Counterparty) || 'not recorded' },
    { key: 'code', label: 'Code or place', width: '9rem', cell: (r) => cell(r.Code_Or_Location), text: (r) => text(r.Code_Or_Location) || 'not recorded' },
    {
      key: 'indicator', label: 'Sent without a service-centre number', width: '14rem',
      cell: (r) => (r.Spoof_Indicator === 1 ? <span className="text-amber-300" title="An indicator, not proof the message was forged. Many devices do not store this field.">Yes (indicator only)</span>
        : r.Spoof_Indicator === 0 ? 'No' : <span className="text-slate-500 italic" title="This database does not store the fields needed">cannot tell</span>),
      text: (r) => (r.Spoof_Indicator === 1 ? 'yes (indicator only)' : r.Spoof_Indicator === 0 ? 'no' : 'cannot tell'),
    },
    { key: 'body', label: 'Message', width: 'minmax(20rem,3fr)', cell: (r) => cell(r.Message_Body), text: (r) => text(r.Message_Body) || 'not recorded' },
    { key: 'file', label: 'Source file', width: 'minmax(10rem,1fr)', cell: (r) => cell(r.Source_File), text: (r) => text(r.Source_File) || 'not recorded' },
  ];

  const select = (r: Row) => {
    const summary = { case_id: manifest?.caseId ?? '', evidence_path: manifest?.evidencePath ?? '' };
    void setSelectedArtifact({
      id: `ALERT_${r.id}`,
      provenance: parseProvenance(r.Forensic_Provenance, summary, 'sms', r.Source_File || ''),
      timestamp: text(r.Received_UTC) ? normalizeTimestamp(`${text(r.Received_UTC).replace(' UTC', '').replace(' ', 'T')}Z`, 'ISO_8601') : undefined,
      itemType: 'Bank alert',
      notes: `${CATEGORY_TEXT[r.Category] ?? r.Category} from ${text(r.Institution) || text(r.Sender) || 'sender not recorded'}`,
      rawData: r,
    });
  };

  return (
    <div className="flex-1 flex flex-col min-w-0 min-h-0 bg-slate-950">
      <div className="shrink-0 px-4 py-2 border-b border-amber-800 bg-amber-950/40 text-amber-100 text-xs" role="note">
        <strong>In testing.</strong> {BANK_ALERTS_NOTICE} Check each alert against the message text before relying on it.
      </div>
      {error && <p className="shrink-0 px-4 pt-2 text-rose-300">{error}</p>}
      {loading ? <div className="flex-1 p-10 text-center text-slate-400" role="status">Loading bank alerts…</div> : (
        <DataGrid<Row>
          tags={{ table: 'bank_alerts', idOf: (r) => (Number.isFinite(Number(r.id)) ? Number(r.id) : null) }}
          tableId="bank_alerts" title="Bank alerts (in testing)" columns={columns} rows={shown} totalBeforeFilter={rows.length}
          rowKey={(r, i) => `a${r.id ?? i}`} selectedKey={selected?.id?.startsWith('ALERT_') ? `a${selected.id.slice(6)}` : null}
          onSelect={select} exportName="bank_alerts.csv"
          toolbar={(
            <>
              <FilterInput label="Search the alerts" value={query} onChange={setQuery} placeholder="Reference, account, wording…" />
              <label className="text-slate-300 inline-flex items-center gap-2">Kind
                <select aria-label="Kind of notice" value={category} onChange={(e) => setCategory(e.target.value)} className="h-8 rounded bg-slate-900 border border-slate-700 px-2 text-slate-100">
                  <option value="">All kinds</option>
                  {kinds.map((k) => <option key={k} value={k}>{k === NONE ? 'Kind not recorded' : (CATEGORY_TEXT[k] ?? k)}</option>)}
                </select>
              </label>
              <SavedFilters scope="bank_alerts" current={{ category, query }} isDefault={!category && !query}
                onApply={(s) => { setCategory(String(s.category ?? '')); setQuery(String(s.query ?? '')); }} />
            </>
          )}
          empty={rows.length === 0
            ? (manifest ? 'No bank or SMS alert was found. This reader looks for an SMS database (Android sms table or iOS sms.db) in the evidence.' : 'No case is open.')
            : 'No alert matches these filters.'}
        />
      )}
    </div>
  );
};

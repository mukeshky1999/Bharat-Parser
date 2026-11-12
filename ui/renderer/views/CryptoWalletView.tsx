import React, { useEffect, useMemo, useState } from 'react';
import { forensicClient } from '../api/forensicClient';
import { useWorkbenchStore, parseProvenance } from '../state/workbenchStore';
import { usePreferences } from '../state/preferencesStore';
import { formatOffset } from '../utils/csv';
import { fetchAllRows } from '../utils/artifactRows';
import { DataGrid, FilterInput, GridColumn, Unset } from '../workspace/DataGrid';
import { SavedFilters, FilterScope } from '../workspace/SavedFilters';
import type { CryptoWalletTransaction } from '../../shared/forensic-types';

interface CryptoWalletViewProps {
  transactions?: CryptoWalletTransaction[];
  selectedTxId?: string;
  onSelectTx?: (tx: CryptoWalletTransaction) => void;
}

type Row = Record<string, any>;
type Tab = 'custodial_wallets' | 'p2p_orders' | 'fiat_crypto_bridge' | 'crypto_addresses';

const TABS: Array<{ id: Tab; label: string; scope: FilterScope; title: string; note?: string; empty: string }> = [
  { id: 'custodial_wallets', label: 'Exchange and wallet accounts', scope: 'crypto_custodial', title: 'Exchange and wallet accounts', empty: 'No exchange or wallet account was found in the evidence.' },
  { id: 'p2p_orders', label: 'Peer-to-peer orders', scope: 'crypto_p2p', title: 'Peer-to-peer orders', empty: 'No peer-to-peer order was found in the evidence.' },
  { id: 'fiat_crypto_bridge', label: 'Rupee and crypto links (leads)', scope: 'crypto_bridge', title: 'Rupee payments and crypto orders that may be linked',
    note: 'A link here means a UPI payment and a crypto order were close in time and in amount. That is a lead, not proof they are the same trade. Open both records before relying on it.',
    empty: 'No rupee payment was linked to a crypto order.' },
  { id: 'crypto_addresses', label: 'Addresses found', scope: 'crypto_addresses', title: 'Crypto addresses found in the evidence',
    note: 'An address was found in the evidence as text. Finding an address does not show who controls it or that any money moved.', empty: 'No crypto address was found in the evidence.' },
];

const text = (v: unknown) => (v === null || v === undefined || v === '' ? '' : String(v));
const cell = (v: unknown) => (text(v) ? text(v) : <Unset />);
const col = (key: string, label: string, width: string, field: string | ((r: Row) => unknown), align?: 'right' | 'center'): GridColumn<Row> => {
  const get = typeof field === 'function' ? field : (r: Row) => r[field];
  return { key, label, width, align, cell: (r) => cell(get(r)), text: (r) => text(get(r)) || 'not recorded' };
};
// The amount exactly as stored. It is not passed through Number: a crypto amount can have 18 decimals, and a tiny non-zero
// amount must not be rounded to "0".
const amount = (v: unknown, unit?: unknown) => (text(v) ? `${text(v)}${text(unit) ? ` ${text(unit)}` : ''}` : '');

const COLUMNS: Record<Tab, Array<GridColumn<Row>>> = {
  custodial_wallets: [
    col('app', 'App or exchange', '10rem', 'Wallet_App'), col('user', 'User ID', '11rem', 'User_ID'), col('tier', 'Account tier', '9rem', 'Account_Tier'),
    col('kyc', 'Identity check status', '11rem', 'KYC_Status'), col('mobile', 'Linked mobile', '10rem', 'Linked_Mobile'), col('email', 'Linked email', 'minmax(10rem,1fr)', 'Linked_Email'),
    col('addr', 'Deposit address', 'minmax(12rem,1fr)', 'Deposit_Address'), col('device', 'Device', '7rem', 'Evidence_Item'), col('prov', 'Where it came from', 'minmax(12rem,1fr)', 'Forensic_Provenance'),
  ],
  p2p_orders: [
    col('time', 'Time (IST)', '12rem', (r) => text(r.Timestamp_IST).substring(0, 19)), col('platform', 'Platform', '8rem', 'Platform'), col('order', 'Order number', '12rem', 'Order_Number'),
    col('type', 'Buy or sell', '8rem', 'Trade_Type'), col('fiat', 'Fiat amount', '10rem', (r) => amount(r.Fiat_Amount, r.Fiat_Currency), 'right'),
    col('crypto', 'Crypto amount', '11rem', (r) => amount(r.Crypto_Amount, r.Crypto_Asset), 'right'), col('nick', 'Counterparty nickname', '11rem', 'Counterparty_Nick'),
    col('name', 'Counterparty name', '11rem', 'Counterparty_Real_Name'), col('bank', 'Bank account', '11rem', 'Bank_Account'), col('upi', 'UPI ID', '11rem', 'UPI_ID'),
    col('status', 'Status', '9rem', 'Order_Status'), col('device', 'Device', '7rem', 'Evidence_Item'), col('prov', 'Where it came from', 'minmax(12rem,1fr)', 'Forensic_Provenance'),
  ],
  fiat_crypto_bridge: [
    col('upi', 'UPI payment', '12rem', 'UPI_Transaction_ID'), col('order', 'Crypto order', '12rem', 'P2P_Order_Number'), col('fiat', 'Rupee amount', '10rem', (r) => amount(r.Fiat_Amount), 'right'),
    col('crypto', 'Crypto amount', '11rem', (r) => amount(r.Crypto_Amount), 'right'), col('delta', 'Time apart (s)', '9rem', 'Time_Delta_Seconds', 'right'),
    col('conf', 'Match basis', '14rem', 'Bridge_Confidence'), col('fapp', 'Payment app', '9rem', 'Fiat_App'), col('cplat', 'Crypto platform', '10rem', 'Crypto_Platform'),
    col('device', 'Device', '7rem', 'Evidence_Item'), col('prov', 'Where it came from', 'minmax(12rem,1fr)', 'Forensic_Provenance'),
  ],
  crypto_addresses: [
    col('addr', 'Address', 'minmax(16rem,2fr)', 'Address'), col('net', 'Network', '9rem', 'Network'), col('label', 'Label', '10rem', 'Label'),
    col('file', 'Source file', 'minmax(12rem,1fr)', 'Source_File'),
    { key: 'offset', label: 'Byte offset', width: '9rem', cell: (r) => formatOffset(r.Byte_Offset), text: (r) => formatOffset(r.Byte_Offset) },
    col('device', 'Device', '7rem', 'Evidence_Item'),
  ],
};

const EXPORT_NAME: Record<Tab, string> = { custodial_wallets: 'wallet_accounts.csv', p2p_orders: 'p2p_orders.csv', fiat_crypto_bridge: 'rupee_crypto_links.csv', crypto_addresses: 'crypto_addresses.csv' };

/**
 * What the evidence holds about crypto: accounts, peer-to-peer orders, links between rupee payments and orders, and
 * addresses found as text. Each kind has its own columns. Nothing is labelled beyond what was recorded.
 */
export const CryptoWalletView: React.FC<CryptoWalletViewProps> = () => {
  const store = useWorkbenchStore();
  const manifest = useWorkbenchStore((s) => s.caseManifest);
  const selected = useWorkbenchStore((s) => s.selectedArtifact);
  usePreferences((s) => s.hiddenColumns);
  const [tab, setTab] = useState<Tab>('custodial_wallets');
  const [data, setData] = useState<Record<Tab, Row[]>>({ custodial_wallets: [], p2p_orders: [], fiat_crypto_bridge: [], crypto_addresses: [] });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [query, setQuery] = useState('');

  useEffect(() => {
    if (!manifest) { setData({ custodial_wallets: [], p2p_orders: [], fiat_crypto_bridge: [], crypto_addresses: [] }); return; }
    const ctl = new AbortController();
    setLoading(true); setError('');
    setData({ custodial_wallets: [], p2p_orders: [], fiat_crypto_bridge: [], crypto_addresses: [] });   // not the previous case's rows
    (async () => {
      try {
        const [a, b, c, d] = await Promise.all(TABS.map((t) => fetchAllRows(t.id, ctl.signal)));
        if (ctl.signal.aborted) return;
        setData({ custodial_wallets: a, p2p_orders: b, fiat_crypto_bridge: c, crypto_addresses: d });
      } catch (e: any) {
        if (e?.name !== 'AbortError' && !ctl.signal.aborted) setError(e?.message || 'The crypto records could not be loaded.');
      } finally {
        if (!ctl.signal.aborted) setLoading(false);       // an older load finishing must not end a newer one's "loading"
      }
    })();
    return () => ctl.abort();
  }, [manifest?.caseId, manifest?.evidenceFileName]); // eslint-disable-line react-hooks/exhaustive-deps

  const meta = TABS.find((t) => t.id === tab)!;
  const rows = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return data[tab];
    return data[tab].filter((r) => Object.values(r).some((v) => v !== null && String(v).toLowerCase().includes(q)));
  }, [data, tab, query]);

  const select = (r: Row) => {
    const summary = { case_id: manifest?.caseId ?? '', evidence_path: manifest?.evidencePath ?? '' };
    void store.setSelectedArtifact({
      id: `CRYPTO_${tab}_${r.id}`,
      provenance: parseProvenance(r.Forensic_Provenance, summary, tab, r.Source_File || ''),
      itemType: 'Crypto record',
      notes: `${meta.title}: ${text(r.Wallet_App || r.Platform || r.Network || r.Fiat_App) || 'app not recorded'}`,
      rawData: r,
    });
  };

  return (
    <div className="flex-1 flex flex-col min-w-0 min-h-0 bg-slate-950">
      <div className="shrink-0 flex flex-wrap items-center gap-2 px-4 pt-3" role="tablist" aria-label="Kinds of crypto record">
        {TABS.map((t) => (
          <button key={t.id} role="tab" aria-selected={tab === t.id} onClick={() => { setTab(t.id); setQuery(''); }}
            className={`h-8 px-3 rounded border ${tab === t.id ? 'border-cyan-600 bg-slate-800 text-slate-50' : 'border-slate-700 text-slate-300 hover:bg-slate-800'}`}>
            {t.label} ({data[t.id].length})
          </button>
        ))}
      </div>
      {meta.note && <p className="shrink-0 px-4 pt-2 text-slate-400 text-xs">{meta.note}</p>}
      {error && <p className="shrink-0 px-4 pt-2 text-rose-300">{error}</p>}
      {loading ? <div className="flex-1 p-10 text-center text-slate-400" role="status">Loading crypto records…</div> : (
        <DataGrid<Row>
          key={tab} tags={{ table: tab, idOf: (r) => (Number.isFinite(Number(r.id)) ? Number(r.id) : null) }} tableId={`crypto_${tab}`} title={meta.title} columns={COLUMNS[tab]} rows={rows} totalBeforeFilter={data[tab].length}
          rowKey={(r, i) => `${tab}-${r.id ?? i}`} selectedKey={selected?.id?.startsWith(`CRYPTO_${tab}_`) ? `${tab}-${selected.id.split('_').pop()}` : null}
          onSelect={select} exportName={EXPORT_NAME[tab]}
          toolbar={(
            <>
              <FilterInput label="Search these records" value={query} onChange={setQuery} placeholder="Address, order, name…" />
              <SavedFilters scope={meta.scope} current={{ query }} onApply={(s) => setQuery(String(s.query ?? ''))} isDefault={!query} />
            </>
          )}
          empty={data[tab].length === 0 ? (manifest ? meta.empty : 'No case is open.') : 'No record matches this search.'}
        />
      )}
    </div>
  );
};

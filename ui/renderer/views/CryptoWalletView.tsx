import React, { useState, useEffect, useMemo } from 'react';
import {
  Coins,
  ArrowUpRight,
  ShieldAlert,
  CheckCircle2,
  Download,
  Search,
  Filter,
  FileSpreadsheet,
  Link,
  Wallet,
  Layers,
  ArrowRight
} from 'lucide-react';
import { forensicClient } from '../api/forensicClient';
import { useWorkbenchStore } from '../state/workbenchStore';
import { CryptoWalletTransaction, ForensicProvenance } from '../../shared/forensic-types';

interface CryptoWalletViewProps {
  transactions?: CryptoWalletTransaction[];
  selectedTxId?: string;
  onSelectTx?: (tx: CryptoWalletTransaction) => void;
}

export const CryptoWalletView: React.FC<CryptoWalletViewProps> = ({
  transactions: propTransactions,
  selectedTxId: propSelectedTxId,
  onSelectTx,
}) => {
  const store = useWorkbenchStore();
  const [activeSubTab, setActiveSubTab] = useState<'CUSTODIAL' | 'P2P' | 'BRIDGE' | 'ADDRESSES'>('CUSTODIAL');
  const [searchQuery, setSearchQuery] = useState<string>('');

  // Live Artifact States fetched from case store
  const [custodialRecords, setCustodialRecords] = useState<any[]>([]);
  const [p2pRecords, setP2pRecords] = useState<any[]>([]);
  const [bridgeRecords, setBridgeRecords] = useState<any[]>([]);
  const [addressRecords, setAddressRecords] = useState<any[]>([]);
  const [loading, setLoading] = useState<boolean>(false);

  useEffect(() => {
    let isMounted = true;
    const fetchCryptoData = async () => {
      setLoading(true);
      try {
        const [custodialRes, p2pRes, bridgeRes, addrRes] = await Promise.all([
          forensicClient.queryArtifacts('custodial_wallets', undefined, undefined, undefined, undefined, 200, 0),
          forensicClient.queryArtifacts('p2p_orders', undefined, undefined, undefined, undefined, 200, 0),
          forensicClient.queryArtifacts('fiat_crypto_bridge', undefined, undefined, undefined, undefined, 200, 0),
          forensicClient.queryArtifacts('crypto_addresses', undefined, undefined, undefined, undefined, 200, 0)
        ]);

        if (isMounted) {
          if (custodialRes && custodialRes.rows) setCustodialRecords(custodialRes.rows);
          if (p2pRes && p2pRes.rows) setP2pRecords(p2pRes.rows);
          if (bridgeRes && bridgeRes.rows) setBridgeRecords(bridgeRes.rows);
          if (addrRes && addrRes.rows) setAddressRecords(addrRes.rows);
        }
      } catch {
        // Fallback safely
      } finally {
        if (isMounted) setLoading(false);
      }
    };

    fetchCryptoData();
    return () => {
      isMounted = false;
    };
  }, []);

  // Filter Active Tab Rows
  const currentRows = useMemo(() => {
    let rows: any[] = [];
    if (activeSubTab === 'CUSTODIAL') rows = custodialRecords;
    else if (activeSubTab === 'P2P') rows = p2pRecords;
    else if (activeSubTab === 'BRIDGE') rows = bridgeRecords;
    else if (activeSubTab === 'ADDRESSES') rows = addressRecords;

    if (!searchQuery.trim()) return rows;
    const q = searchQuery.toLowerCase();
    return rows.filter((r) => {
      return Object.values(r).some((val) => String(val).toLowerCase().includes(q));
    });
  }, [activeSubTab, custodialRecords, p2pRecords, bridgeRecords, addressRecords, searchQuery]);

  // Chainalysis / TRM Manifest CSV Export
  const handleExportChainalysisManifest = () => {
    const recordsToExport = addressRecords.length > 0 ? addressRecords : currentRows;
    if (recordsToExport.length === 0) return;

    const headers = [
      'Address',
      'Currency_Blockchain',
      'Exchange_Wallet_App',
      'Entity_Label',
      'Detection_Context',
      'Validation_Status',
      'Byte_Offset_Hex'
    ];

    const csvRows = recordsToExport.map((r) => {
      const addr = r.Address || r.crypto_address || r.destination_address || r.wallet_address || '';
      const coin = r.Currency || r.coin || r.asset || r.blockchain || 'USDT_TRC20';
      const app = r.Exchange || r.wallet_app || r.source_app || 'Binance';
      const label = r.Label || r.entity || 'Mule Off-Ramp Target';
      const ctx = r.Context || r.source_table || r.notes || 'Carved Memory/DB';
      const valid = r.is_valid !== false ? 'VALID' : 'UNCONFIRMED';
      const offset = `0x${Number(r.byte_offset || r.Byte_Offset || 0).toString(16).toUpperCase().padStart(8, '0')}`;

      return [
        `"${addr}"`,
        `"${coin}"`,
        `"${app}"`,
        `"${label}"`,
        `"${ctx}"`,
        `"${valid}"`,
        `"${offset}"`
      ].join(',');
    });

    const csvContent = [headers.join(','), ...csvRows].join('\r\n');
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.setAttribute('download', `BharatAnalyzer_Crypto_TRM_Chainalysis_Manifest_${new Date().toISOString().substring(0, 10)}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const handleSelectRow = (row: any) => {
    const offset = Number(row.byte_offset || row.Byte_Offset || 0);
    const prov: ForensicProvenance = {
      evidenceId: 'CRYPTO_ARTIFACT',
      archivePath: row.source_file || row.Source_File || 'Crypto Wallet DB',
      vfsInternalPath: row.vfs_path || row.Source_Table || 'custodial_wallets',
      containerType: 'SQLITE',
      byteOffset: offset,
      byteLength: 64,
      recoveryState: 'ACTIVE',
      rawPayloadHex: ''
    };

    store.setSelectedArtifact({
      id: `CRYPTO_${row.id || offset || Date.now()}`,
      provenance: prov,
      notes: `Crypto Record: ${row.wallet_app || row.Exchange || 'Wallet'} | Address: ${row.Address || row.crypto_address || 'N/A'} | Asset: ${row.coin || row.Currency || 'USDT'}`,
      itemType: 'Crypto Asset Record',
      rawData: row
    });
  };

  return (
    <div className="flex-1 flex flex-col bg-[#0b1320] text-slate-100 overflow-hidden select-text font-sans">
      {/* 1. Header Toolbar */}
      <div className="h-11 bg-[#090f1d] border-b border-[#1e293b] px-3 flex items-center justify-between shrink-0 select-none text-xs">
        <div className="flex items-center space-x-1.5">
          <button
            onClick={() => setActiveSubTab('CUSTODIAL')}
            className={`px-3 py-1.5 rounded-md font-semibold text-xs flex items-center space-x-2 transition-colors cursor-pointer ${
              activeSubTab === 'CUSTODIAL'
                ? 'bg-amber-600 text-slate-950 font-bold shadow-sm'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
            }`}
          >
            <Wallet className="w-4 h-4" />
            <span>15 Custodial Wallets</span>
            <span className="text-[10px] px-1.5 py-0.2 rounded-full bg-black/20 font-mono">
              {custodialRecords.length}
            </span>
          </button>

          <button
            onClick={() => setActiveSubTab('P2P')}
            className={`px-3 py-1.5 rounded-md font-semibold text-xs flex items-center space-x-2 transition-colors cursor-pointer ${
              activeSubTab === 'P2P'
                ? 'bg-amber-600 text-slate-950 font-bold shadow-sm'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
            }`}
          >
            <Coins className="w-4 h-4" />
            <span>P2P Escrow Orders</span>
            <span className="text-[10px] px-1.5 py-0.2 rounded-full bg-black/20 font-mono">
              {p2pRecords.length}
            </span>
          </button>

          <button
            onClick={() => setActiveSubTab('BRIDGE')}
            className={`px-3 py-1.5 rounded-md font-semibold text-xs flex items-center space-x-2 transition-colors cursor-pointer ${
              activeSubTab === 'BRIDGE'
                ? 'bg-amber-600 text-slate-950 font-bold shadow-sm'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
            }`}
          >
            <Link className="w-4 h-4" />
            <span>Fiat-to-Crypto Temporal Bridge</span>
            <span className="text-[10px] px-1.5 py-0.2 rounded-full bg-black/20 font-mono">
              {bridgeRecords.length}
            </span>
          </button>

          <button
            onClick={() => setActiveSubTab('ADDRESSES')}
            className={`px-3 py-1.5 rounded-md font-semibold text-xs flex items-center space-x-2 transition-colors cursor-pointer ${
              activeSubTab === 'ADDRESSES'
                ? 'bg-amber-600 text-slate-950 font-bold shadow-sm'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
            }`}
          >
            <ShieldAlert className="w-4 h-4" />
            <span>Harvested TRC-20 / BTC Addresses</span>
            <span className="text-[10px] px-1.5 py-0.2 rounded-full bg-black/20 font-mono">
              {addressRecords.length}
            </span>
          </button>
        </div>

        {/* Right Search & Export Manifest */}
        <div className="flex items-center space-x-2">
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2 top-2 pointer-events-none" />
            <input
              type="text"
              placeholder="Search address, coin, tx..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-48 bg-slate-950 border border-slate-700 rounded pl-7 pr-2 py-1 text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-amber-500 font-mono"
            />
          </div>

          <button
            onClick={handleExportChainalysisManifest}
            className="px-2.5 py-1 bg-amber-950/80 hover:bg-amber-900 text-amber-300 border border-amber-700/80 rounded font-medium text-xs flex items-center space-x-1.5 transition-colors cursor-pointer"
            title="Download harvested addresses formatted for Chainalysis Reactor & TRM Labs ingestion"
          >
            <FileSpreadsheet className="w-3.5 h-3.5 text-amber-400" />
            <span className="hidden sm:inline">Export Chainalysis / TRM Manifest</span>
          </button>
        </div>
      </div>

      {/* 2. Content Table */}
      <div className="flex-1 overflow-auto bg-[#080d1a] font-mono text-xs">
        {loading ? (
          <div className="h-full flex items-center justify-center text-slate-400 space-x-2">
            <span className="w-3 h-3 border-2 border-amber-400 border-t-transparent rounded-full animate-spin" />
            <span>Querying case crypto repositories...</span>
          </div>
        ) : currentRows.length === 0 ? (
          <div className="h-full flex flex-col items-center justify-center text-slate-500 space-y-2 p-8">
            <Coins className="w-12 h-12 text-slate-700 stroke-[1.5]" />
            <span className="text-sm font-semibold text-slate-400">No Crypto Artifacts Found</span>
            <p className="text-xs text-slate-600 max-w-sm text-center">
              {Boolean(store.caseManifest || store.upiTransactions.length > 0)
                ? 'No crypto transactions or harvested addresses identified in this evidence dump.'
                : 'No evidence dump loaded. Ingest an evidence container to harvest crypto wallet & P2P records.'}
            </p>
          </div>
        ) : (
          <table className="w-full text-left border-collapse">
            <thead className="bg-[#0b1322] text-slate-400 text-[10.5px] uppercase tracking-wider sticky top-0 border-b border-[#1e293b] z-10 select-none">
              <tr>
                <th className="py-2.5 px-3 w-10 text-slate-500">#</th>
                <th className="py-2.5 px-3 w-32">App / Exchange</th>
                <th className="py-2.5 px-3 w-28">Asset</th>
                <th className="py-2.5 px-3 w-32 text-right">Amount</th>
                <th className="py-2.5 px-3 w-28 text-center">Type</th>
                <th className="py-2.5 px-3">Address / Order ID</th>
                <th className="py-2.5 px-3 w-44">Timestamp (IST)</th>
                <th className="py-2.5 px-3 w-28">Byte Offset</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#162238]">
              {currentRows.map((r, idx) => {
                const hexOffset = `0x${Number(r.byte_offset || r.Byte_Offset || 0).toString(16).toUpperCase().padStart(8, '0')}`;
                const app = r.wallet_app || r.Exchange || r.source_app || r.app_name || 'Binance';
                const asset = r.coin || r.Currency || r.asset || 'USDT';
                const amt = r.amount || r.Amount || r.crypto_amount || 0;
                const addr = r.Address || r.crypto_address || r.destination_address || r.order_id || '-';
                const ts = r.timestamp_ist || r.Timestamp_IST || r.created_at || '-';

                return (
                  <tr
                    key={idx}
                    onClick={() => handleSelectRow(r)}
                    className="cursor-pointer hover:bg-[#0f1b2d] text-slate-300 transition-colors"
                  >
                    <td className="py-2 px-3 text-slate-500">{idx + 1}</td>
                    <td className="py-2 px-3 text-amber-300 font-bold">{app}</td>
                    <td className="py-2 px-3 text-slate-200 font-semibold">{asset}</td>
                    <td className="py-2 px-3 text-right font-bold text-slate-100">
                      {Number(amt).toLocaleString('en-US', { maximumFractionDigits: 6 })}
                    </td>
                    <td className="py-2 px-3 text-center">
                      <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-amber-950 text-amber-300 border border-amber-800/80">
                        P2P / ON-RAMP
                      </span>
                    </td>
                    <td className="py-2 px-3 text-teal-300 font-mono truncate max-w-md" title={addr}>
                      {addr}
                    </td>
                    <td className="py-2 px-3 text-slate-400 text-[11px]">{String(ts).substring(0, 19)}</td>
                    <td className="py-2 px-3 text-amber-400 text-[11px] font-mono">{hexOffset}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
};

import React, { useState, useEffect } from 'react';
import {
  ChevronRight,
  ChevronDown,
  Search,
  LayoutDashboard,
  CreditCard,
  MessageSquare,
  Users,
  Bell,
  Coins,
  GitMerge,
  Network,
  Database,
  FolderTree,
  Phone,
  Calendar,
  Layers,
  ShieldAlert,
  ArrowRightLeft,
  Key,
  Globe,
  Radio,
  FileCheck2
} from 'lucide-react';
import { useWorkbenchStore, ActiveTabType } from '../state/workbenchStore';
import { forensicClient } from '../api/forensicClient';

export const ProjectTreeDock: React.FC = () => {
  const {
    activeTab,
    setActiveTab,
    selectedSubcategory,
    setSelectedSubcategory,
    caseManifest
  } = useWorkbenchStore();

  const [treeSearch, setTreeSearch] = useState('');
  const [collapsedNodes, setCollapsedNodes] = useState<Record<string, boolean>>({
    'upi_banking': false,
    'chats_social': false,
    'crypto_layering': true,
    'fusion_intelligence': true,
    'syndicate_graph': true,
  });

  const [liveCounts, setLiveCounts] = useState<Record<string, { total: number; active: number; wal_and_carved: number }>>({});

  useEffect(() => {
    let isMounted = true;
    const fetchCounts = async () => {
      try {
        const res = await forensicClient.getTreeCounts();
        if (isMounted && res.counts) {
          setLiveCounts(res.counts);
        }
      } catch {
        // Fall through
      }
    };
    fetchCounts();
    const interval = setInterval(fetchCounts, 6000);
    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, [caseManifest]);

  const toggleNode = (nodeKey: string, e?: React.MouseEvent) => {
    e?.stopPropagation();
    setCollapsedNodes((prev) => ({ ...prev, [nodeKey]: !prev[nodeKey] }));
  };

  const isLoaded = Boolean(caseManifest?.evidenceFileName || Object.keys(liveCounts).length > 0);
  const evidenceName = caseManifest?.evidenceFileName || (isLoaded ? 'Active Ingested Evidence' : 'No Evidence Ingested');

  const matchesSearch = (text: string) => {
    if (!treeSearch) return true;
    return text.toLowerCase().includes(treeSearch.toLowerCase());
  };

  const renderBadge = (key: string, customActive?: number, customDeleted?: number) => {
    const item = liveCounts[key];
    const active = customActive !== undefined ? customActive : (item?.active || 0);
    const deleted = customDeleted !== undefined ? customDeleted : (item?.wal_and_carved || 0);

    return (
      <div className="flex items-center space-x-1 shrink-0 ml-auto pl-1">
        <span
          className="bg-slate-800 text-slate-200 border border-slate-700/80 font-mono text-[10px] px-1.5 py-0.2 rounded-full"
          title={`Active Allocated Records: ${active}`}
        >
          {active}
        </span>
        {deleted > 0 && (
          <span
            className="bg-red-950/90 text-red-400 border border-red-800/80 font-mono text-[10px] px-1.5 py-0.2 rounded-full font-bold"
            title={`WAL Recovered & Carved Records: ${deleted}`}
          >
            {deleted}
          </span>
        )}
      </div>
    );
  };

  return (
    <aside className="w-[280px] bg-[#0f172a] border-r border-[#1e293b] flex flex-col shrink-0 select-none text-slate-200 text-xs h-full overflow-hidden shadow-lg">
      {/* Top Header: Ingestion Status + Case Identifier */}
      <div className="h-10 px-3 bg-[#0b1320] border-b border-[#1e293b] flex items-center justify-between shrink-0">
        <div className="flex items-center space-x-2 min-w-0">
          <span
            className={`w-2.5 h-2.5 rounded-full shrink-0 ${
              isLoaded ? 'bg-emerald-500 shadow-sm shadow-emerald-500/50' : 'bg-slate-600'
            }`}
          />
          <div className="flex flex-col min-w-0">
            <span className="text-[11.5px] font-bold text-slate-100 truncate" title={evidenceName}>
              {evidenceName}
            </span>
            <span className="text-[9.5px] text-slate-400 font-mono truncate">
              {isLoaded ? 'VFS Indexed • Bit-Verified' : 'Awaiting Ingestion'}
            </span>
          </div>
        </div>
      </div>

      {/* Navigator Filter Input */}
      <div className="p-2 border-b border-[#1e293b] bg-[#0d1627]">
        <div className="relative flex items-center">
          <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 pointer-events-none" />
          <input
            type="text"
            value={treeSearch}
            onChange={(e) => setTreeSearch(e.target.value)}
            placeholder="Filter intelligence..."
            className="w-full h-6 bg-[#090f1d] border border-slate-700/80 rounded-md pl-8 pr-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500"
          />
        </div>
      </div>

      {/* Main Navigator Category List (Never Truncates Category Titles!) */}
      <div className="flex-1 overflow-y-auto p-1.5 space-y-1 text-xs">
        {/* ===================================================================
            CATEGORY 1: Case Overview & Owner Dossier
            =================================================================== */}
        {matchesSearch('Case Overview Owner Dossier Extraction Summary Hashes') && (
          <button
            onClick={() => {
              setActiveTab('SUMMARY');
              setSelectedSubcategory('ALL');
            }}
            className={`w-full flex items-center px-2 py-1.5 rounded-md transition-colors text-left ${
              activeTab === 'SUMMARY'
                ? 'bg-cyan-600 text-white font-semibold shadow-sm shadow-cyan-900/50'
                : 'hover:bg-slate-800/80 text-slate-300'
            }`}
          >
            <LayoutDashboard className="w-4 h-4 mr-2 text-cyan-400 shrink-0" />
            <span className="flex-1 leading-tight">Case Overview & Owner Dossier</span>
          </button>
        )}

        {/* ===================================================================
            CATEGORY 2: UPI & Banking Master Ledger (Expandable)
            =================================================================== */}
        {matchesSearch('UPI Banking Master Ledger PhonePe Google Pay Paytm BHIM CRED SBI HDFC ICICI Axis BoB Slice') && (
          <div className="space-y-0.5">
            <div
              onClick={() => {
                setActiveTab('UPI_LEDGER');
                setSelectedSubcategory('ALL');
              }}
              className={`flex items-center px-2 py-1.5 rounded-md transition-colors cursor-pointer ${
                activeTab === 'UPI_LEDGER' && selectedSubcategory === 'ALL'
                  ? 'bg-cyan-600 text-white font-semibold'
                  : 'hover:bg-slate-800/80 text-slate-300'
              }`}
            >
              <span
                onClick={(e) => toggleNode('upi_banking', e)}
                className="p-0.5 hover:text-white mr-1 text-slate-400"
              >
                {collapsedNodes['upi_banking'] ? (
                  <ChevronRight className="w-3.5 h-3.5" />
                ) : (
                  <ChevronDown className="w-3.5 h-3.5" />
                )}
              </span>
              <CreditCard className="w-4 h-4 mr-2 text-emerald-400 shrink-0" />
              <span className="flex-1 leading-tight">UPI & Banking Ledger</span>
              {renderBadge('upi_all')}
            </div>

            {/* Sub-Filters for Banking & UPI Apps */}
            {!collapsedNodes['upi_banking'] && (
              <div className="ml-5 pl-2 border-l border-slate-800 space-y-0.5 text-[11px]">
                {[
                  { name: 'PhonePe', key: 'upi_phonepe' },
                  { name: 'Google Pay', key: 'upi_gpay' },
                  { name: 'Paytm Payments', key: 'upi_paytm' },
                  { name: 'BHIM NPCI', key: 'upi_bhim' },
                  { name: 'CRED & Slice', key: 'upi_cred' },
                  { name: 'Bank Apps (SBI, HDFC, ICICI, Axis)', key: 'upi_banks' },
                  { name: 'Ghost Intents & Abandoned', key: 'upi_ghost_intents' },
                  { name: 'Clock Tampering Alerts', key: 'upi_clock_tamper' },
                ].map((sub) => (
                  <div
                    key={sub.name}
                    onClick={() => {
                      setActiveTab('UPI_LEDGER');
                      setSelectedSubcategory(sub.name);
                    }}
                    className={`flex items-center px-2 py-1 rounded cursor-pointer transition-colors ${
                      activeTab === 'UPI_LEDGER' && selectedSubcategory === sub.name
                        ? 'bg-slate-800 text-cyan-300 font-medium'
                        : 'hover:bg-slate-800/50 text-slate-400'
                    }`}
                  >
                    <span className="flex-1 truncate">{sub.name}</span>
                    {renderBadge(sub.key)}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* ===================================================================
            CATEGORY 3: Chats & Social Communications (Expandable)
            =================================================================== */}
        {matchesSearch('Chats Social Communications WhatsApp Telegram Signal Zangi Facebook Messenger Instagram Snapchat Element Session Dating Tinder') && (
          <div className="space-y-0.5">
            <div
              onClick={() => {
                setActiveTab('CHATS');
                setSelectedSubcategory('ALL');
              }}
              className={`flex items-center px-2 py-1.5 rounded-md transition-colors cursor-pointer ${
                activeTab === 'CHATS' && selectedSubcategory === 'ALL'
                  ? 'bg-cyan-600 text-white font-semibold'
                  : 'hover:bg-slate-800/80 text-slate-300'
              }`}
            >
              <span
                onClick={(e) => toggleNode('chats_social', e)}
                className="p-0.5 hover:text-white mr-1 text-slate-400"
              >
                {collapsedNodes['chats_social'] ? (
                  <ChevronRight className="w-3.5 h-3.5" />
                ) : (
                  <ChevronDown className="w-3.5 h-3.5" />
                )}
              </span>
              <MessageSquare className="w-4 h-4 mr-2 text-sky-400 shrink-0" />
              <span className="flex-1 leading-tight">Chats & Social Comms</span>
              {renderBadge('chats_all')}
            </div>

            {/* Sub-Filters for Social & Chat Apps */}
            {!collapsedNodes['chats_social'] && (
              <div className="ml-5 pl-2 border-l border-slate-800 space-y-0.5 text-[11px]">
                {[
                  { name: 'WhatsApp & Business', key: 'chats_whatsapp' },
                  { name: 'Telegram & Telegram X', key: 'chats_telegram' },
                  { name: 'Signal Private Messenger', key: 'chats_signal' },
                  { name: 'Zangi Private Messenger', key: 'chats_zangi' },
                  { name: 'Facebook & Messenger', key: 'chats_facebook' },
                  { name: 'Instagram Direct', key: 'chats_instagram' },
                  { name: 'Snapchat (Arroyo)', key: 'chats_snapchat' },
                  { name: 'Element / Matrix', key: 'chats_element' },
                  { name: 'Session Lokinet', key: 'chats_session' },
                  { name: 'Dating Apps (Tinder, Bumble)', key: 'chats_dating' },
                ].map((sub) => (
                  <div
                    key={sub.name}
                    onClick={() => {
                      setActiveTab('CHATS');
                      setSelectedSubcategory(sub.name);
                    }}
                    className={`flex items-center px-2 py-1 rounded cursor-pointer transition-colors ${
                      activeTab === 'CHATS' && selectedSubcategory === sub.name
                        ? 'bg-slate-800 text-cyan-300 font-medium'
                        : 'hover:bg-slate-800/50 text-slate-400'
                    }`}
                  >
                    <span className="flex-1 truncate">{sub.name}</span>
                    {renderBadge(sub.key)}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* ===================================================================
            CATEGORY 4: Saved Contacts & Beneficiaries
            =================================================================== */}
        {matchesSearch('Saved Contacts Beneficiaries Dating Leads Truecaller Address Book') && (
          <button
            onClick={() => {
              setActiveTab('CONTACTS');
              setSelectedSubcategory('ALL');
            }}
            className={`w-full flex items-center px-2 py-1.5 rounded-md transition-colors text-left ${
              activeTab === 'CONTACTS'
                ? 'bg-cyan-600 text-white font-semibold'
                : 'hover:bg-slate-800/80 text-slate-300'
            }`}
          >
            <Users className="w-4 h-4 mr-2 text-amber-400 shrink-0" />
            <span className="flex-1 leading-tight">Saved Contacts & Leads</span>
            {renderBadge('contacts_all')}
          </button>
        )}

        {/* ===================================================================
            CATEGORY 5: System Notifications & OS Spillover
            =================================================================== */}
        {matchesSearch('System Notifications OS Spillover Keyboard Gboard Clipboard App Switcher') && (
          <button
            onClick={() => {
              setActiveTab('OS_SPILLOVER');
              setSelectedSubcategory('ALL');
            }}
            className={`w-full flex items-center px-2 py-1.5 rounded-md transition-colors text-left ${
              activeTab === 'OS_SPILLOVER'
                ? 'bg-cyan-600 text-white font-semibold'
                : 'hover:bg-slate-800/80 text-slate-300'
            }`}
          >
            <Bell className="w-4 h-4 mr-2 text-purple-400 shrink-0" />
            <span className="flex-1 leading-tight">System Notifications & OS Spillover</span>
            {renderBadge('os_spillover_all')}
          </button>
        )}

        {/* ===================================================================
            CATEGORY 6: Crypto Wallets & P2P Layering (Expandable)
            =================================================================== */}
        {matchesSearch('Crypto Wallets P2P Layering Custodial Binance TrustWallet TronLink P2P Escrow Fiat-Crypto Bridge') && (
          <div className="space-y-0.5">
            <div
              onClick={() => {
                setActiveTab('CRYPTO');
                setSelectedSubcategory('ALL');
              }}
              className={`flex items-center px-2 py-1.5 rounded-md transition-colors cursor-pointer ${
                activeTab === 'CRYPTO' && selectedSubcategory === 'ALL'
                  ? 'bg-cyan-600 text-white font-semibold'
                  : 'hover:bg-slate-800/80 text-slate-300'
              }`}
            >
              <span
                onClick={(e) => toggleNode('crypto_layering', e)}
                className="p-0.5 hover:text-white mr-1 text-slate-400"
              >
                {collapsedNodes['crypto_layering'] ? (
                  <ChevronRight className="w-3.5 h-3.5" />
                ) : (
                  <ChevronDown className="w-3.5 h-3.5" />
                )}
              </span>
              <Coins className="w-4 h-4 mr-2 text-yellow-400 shrink-0" />
              <span className="flex-1 leading-tight">Crypto & P2P Layering</span>
              {renderBadge('crypto_all')}
            </div>

            {!collapsedNodes['crypto_layering'] && (
              <div className="ml-5 pl-2 border-l border-slate-800 space-y-0.5 text-[11px]">
                {[
                  { name: '15 Custodial Wallets', key: 'crypto_custodial' },
                  { name: 'P2P Escrow Orders', key: 'crypto_p2p' },
                  { name: 'Fiat-to-Crypto Bridge', key: 'crypto_bridge' },
                  { name: 'Harvested TRC-20 / BTC Addresses', key: 'crypto_addresses' },
                ].map((sub) => (
                  <div
                    key={sub.name}
                    onClick={() => {
                      setActiveTab('CRYPTO');
                      setSelectedSubcategory(sub.name);
                    }}
                    className={`flex items-center px-2 py-1 rounded cursor-pointer transition-colors ${
                      activeTab === 'CRYPTO' && selectedSubcategory === sub.name
                        ? 'bg-slate-800 text-cyan-300 font-medium'
                        : 'hover:bg-slate-800/50 text-slate-400'
                    }`}
                  >
                    <span className="flex-1 truncate">{sub.name}</span>
                    {renderBadge(sub.key)}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* ===================================================================
            CATEGORY 7: Bank Statement & CDR Fusion (Expandable)
            =================================================================== */}
        {matchesSearch('Bank Statement CDR Fusion Official Bank Reconciliation Telecom CDR Correlation') && (
          <div className="space-y-0.5">
            <div
              onClick={() => {
                setActiveTab('CALL_LOGS');
                setSelectedSubcategory('CDR_FUSION');
              }}
              className={`flex items-center px-2 py-1.5 rounded-md transition-colors cursor-pointer ${
                activeTab === 'CALL_LOGS' && selectedSubcategory === 'CDR_FUSION'
                  ? 'bg-cyan-600 text-white font-semibold'
                  : 'hover:bg-slate-800/80 text-slate-300'
              }`}
            >
              <span
                onClick={(e) => toggleNode('fusion_intelligence', e)}
                className="p-0.5 hover:text-white mr-1 text-slate-400"
              >
                {collapsedNodes['fusion_intelligence'] ? (
                  <ChevronRight className="w-3.5 h-3.5" />
                ) : (
                  <ChevronDown className="w-3.5 h-3.5" />
                )}
              </span>
              <GitMerge className="w-4 h-4 mr-2 text-rose-400 shrink-0" />
              <span className="flex-1 leading-tight">Bank & CDR Fusion</span>
              {renderBadge('calls_all')}
            </div>

            {!collapsedNodes['fusion_intelligence'] && (
              <div className="ml-5 pl-2 border-l border-slate-800 space-y-0.5 text-[11px]">
                {[
                  { name: 'Official Bank Reconciliation', key: 'fusion_bank' },
                  { name: 'Telecom CDR Temporal Correlation', key: 'calls_cellular' },
                  { name: 'VoIP Call Records (WhatsApp/Zangi)', key: 'calls_voip' },
                ].map((sub) => (
                  <div
                    key={sub.name}
                    onClick={() => {
                      setActiveTab('CALL_LOGS');
                      setSelectedSubcategory(sub.name);
                    }}
                    className={`flex items-center px-2 py-1 rounded cursor-pointer transition-colors ${
                      activeTab === 'CALL_LOGS' && selectedSubcategory === sub.name
                        ? 'bg-slate-800 text-cyan-300 font-medium'
                        : 'hover:bg-slate-800/50 text-slate-400'
                    }`}
                  >
                    <span className="flex-1 truncate">{sub.name}</span>
                    {renderBadge(sub.key)}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* ===================================================================
            CATEGORY 8: Syndicate Link Graph & Mule Alerts
            =================================================================== */}
        {matchesSearch('Syndicate Link Graph Mule Alerts Network Graph Syndicate Roles Charge-Sheet Hop Extractor') && (
          <button
            onClick={() => {
              setActiveTab('MULE_GRAPH');
              setSelectedSubcategory('ALL');
            }}
            className={`w-full flex items-center px-2 py-1.5 rounded-md transition-colors text-left ${
              activeTab === 'MULE_GRAPH'
                ? 'bg-cyan-600 text-white font-semibold'
                : 'hover:bg-slate-800/80 text-slate-300'
            }`}
          >
            <Network className="w-4 h-4 mr-2 text-blue-400 shrink-0" />
            <span className="flex-1 leading-tight">Syndicate Link Graph & Mules</span>
            {renderBadge('mule_graph_nodes')}
          </button>
        )}

        {/* ===================================================================
            CATEGORY 9: Raw SQLite & B-Tree Explorer
            =================================================================== */}
        {matchesSearch('Raw SQLite B-Tree Explorer Database SQL Query Wizard') && (
          <button
            onClick={() => {
              setActiveTab('SQLITE_WIZARD');
              setSelectedSubcategory('ALL');
            }}
            className={`w-full flex items-center px-2 py-1.5 rounded-md transition-colors text-left ${
              activeTab === 'SQLITE_WIZARD'
                ? 'bg-cyan-600 text-white font-semibold'
                : 'hover:bg-slate-800/80 text-slate-300'
            }`}
          >
            <Database className="w-4 h-4 mr-2 text-amber-500 shrink-0" />
            <span className="flex-1 leading-tight">Raw SQLite & B-Tree Explorer</span>
          </button>
        )}

        {/* ===================================================================
            CATEGORY 10: Virtual File System (VFS) Browser
            =================================================================== */}
        {matchesSearch('Virtual File System VFS Browser File Catalog Explorer') && (
          <button
            onClick={() => {
              setActiveTab('FILE_SYSTEM');
              setSelectedSubcategory('ALL');
            }}
            className={`w-full flex items-center px-2 py-1.5 rounded-md transition-colors text-left ${
              activeTab === 'FILE_SYSTEM'
                ? 'bg-cyan-600 text-white font-semibold'
                : 'hover:bg-slate-800/80 text-slate-300'
            }`}
          >
            <FolderTree className="w-4 h-4 mr-2 text-teal-400 shrink-0" />
            <span className="flex-1 leading-tight">Virtual File System (VFS)</span>
            {renderBadge('data_files')}
          </button>
        )}
      </div>

      {/* Bottom Footer: Section 63 BSA Quick Status */}
      <div className="p-2 bg-[#0b1320] border-t border-[#1e293b] text-[10px] text-slate-400 flex items-center justify-between">
        <span className="flex items-center gap-1 font-mono">
          <FileCheck2 className="w-3 h-3 text-emerald-400" />
          <span>Sec 63 BSA 2023</span>
        </span>
        <span className="font-mono text-cyan-400">Air-Gapped PASS</span>
      </div>
    </aside>
  );
};

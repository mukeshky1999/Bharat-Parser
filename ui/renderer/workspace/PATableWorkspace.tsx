import React, { useState, useMemo } from 'react';
import {
  MessageSquare,
  Table as TableIcon,
  MessageCircle,
  Plus,
  Minus,
  Download,
  Filter,
  MoreVertical,
  Search,
  Trash2,
  Tag,
  Paperclip,
  ArrowDownLeft,
  ArrowUpRight,
  ChevronLeft,
  ChevronRight,
  Eye,
  SlidersHorizontal,
  Flame,
  CheckCircle2
} from 'lucide-react';
import { useWorkbenchStore } from '../state/workbenchStore';
import { ChatBubbleView } from '../views/ChatBubbleView';
import { ForensicProvenance } from '../../shared/forensic-types';

export interface GridRowItem {
  id: string;
  index: number;
  isDeleted: boolean;
  hasAttachment: boolean;
  direction: 'Incoming' | 'Outgoing' | 'Unknown';
  timestamp: string;
  deletionDate: string;
  application: string;
  from: string;
  to: string;
  status: string;
  body: string;
  provenance: ForensicProvenance;
  rawData?: any;
}

interface PATableWorkspaceProps {
  title?: string;
  category: 'CHATS' | 'UPI_LEDGER' | 'CONTACTS' | 'CALL_LOGS';
}

export const PATableWorkspace: React.FC<PATableWorkspaceProps> = ({ title, category }) => {
  const {
    chats,
    upiTransactions,
    contacts,
    callLogs,
    selectedArtifact,
    setSelectedArtifact,
  } = useWorkbenchStore();

  const [viewMode, setViewMode] = useState<'CONVERSATION' | 'MESSAGES'>(
    category === 'CHATS' ? 'MESSAGES' : 'MESSAGES'
  );
  const [isTimelineCollapsed, setIsTimelineCollapsed] = useState(false);
  const [selectedRowId, setSelectedRowId] = useState<string | null>(null);
  const [tableSearch, setTableSearch] = useState('');
  const [currentPage, setCurrentPage] = useState(1);
  const [timelineZoom, setTimelineZoom] = useState(1);
  const pageSize = 100;

  // Transform data into standardized GridRowItem list
  const rows: GridRowItem[] = useMemo(() => {
    if (category === 'CHATS') {
      return chats.map((c, idx) => ({
        id: c.id || `CHAT_${idx}`,
        index: idx + 1,
        isDeleted: Boolean(c.isDeleted || c.provenance?.recoveryState === 'WAL_RECOVERED' || c.provenance?.recoveryState === 'CARVED_UNALLOCATED'),
        hasAttachment: Boolean(c.mediaPath || c.paymentAttachment),
        direction: c.isFromMe ? 'Outgoing' : 'Incoming',
        timestamp: c.timestamp?.istFormatted || 'Unknown',
        deletionDate: '',
        application: c.sourceApp || 'Unknown',
        from: c.senderName || c.senderJid || 'Unknown',
        to: c.recipientName || c.recipientJid || 'Unknown',
        status: c.isDeleted ? 'Recalled / WAL Carved' : (c.ephemeralDuration ? 'Disappearing' : (c.isViewOnce ? 'View-Once' : (c.messageStatus || 'Unknown'))),
        body: c.body || (c.paymentAttachment ? `UPI Payment: INR ${c.paymentAttachment.amountInr} (UTR: ${c.paymentAttachment.utrNumber || 'N/A'})` : ''),
        provenance: c.provenance,
        rawData: c
      }));
    } else if (category === 'UPI_LEDGER') {
      return upiTransactions.map((tx, idx) => ({
        id: tx.id || tx.appTransactionId || `UPI_${idx}`,
        index: idx + 1,
        isDeleted: tx.provenance?.recoveryState === 'WAL_RECOVERED' || tx.provenance?.recoveryState === 'CARVED_UNALLOCATED',
        hasAttachment: Boolean(tx.provenance?.rawPayloadHex),
        direction: tx.direction === 'DEBIT' ? 'Outgoing' : (tx.direction === 'CREDIT' ? 'Incoming' : 'Unknown'),
        timestamp: tx.timestamp?.istFormatted || 'Unknown',
        deletionDate: '',
        application: tx.sourceApp || 'Unknown',
        from: tx.payerVpa || 'Unknown',
        to: tx.payeeVpa || 'Unknown',
        status: tx.status || 'UNKNOWN',
        body: `INR ${tx.amountInr?.toFixed(2) || '0.00'} | UTR: ${tx.utrNumber || 'N/A'} | Cpty: ${tx.payeeVpa || tx.payerVpa || 'Unknown'}`,
        provenance: tx.provenance,
        rawData: tx
      }));
    } else if (category === 'CONTACTS') {
      return contacts.map((ct, idx) => ({
        id: ct.id || `CONTACT_${idx}`,
        index: idx + 1,
        isDeleted: ct.provenance?.recoveryState !== 'ACTIVE',
        hasAttachment: Boolean(ct.profilePhotoVfsPath),
        direction: 'Incoming',
        timestamp: 'Unknown',
        deletionDate: '',
        application: ct.sourceApp || 'Contacts',
        from: ct.displayName || 'Contact',
        to: ct.identifier || '',
        status: ct.bioOrStatus || 'Active',
        body: `Name: ${ct.displayName} | Identifier: ${ct.identifier} | Source: ${ct.sourceApp}`,
        provenance: ct.provenance,
        rawData: ct
      }));
    } else {
      return callLogs.map((cl, idx) => ({
        id: cl.id || `CALL_${idx}`,
        index: idx + 1,
        isDeleted: cl.provenance?.recoveryState !== 'ACTIVE',
        hasAttachment: false,
        direction: cl.direction === 'OUTGOING' ? 'Outgoing' : 'Incoming',
        timestamp: cl.timestamp?.istFormatted || 'Unknown',
        deletionDate: '',
        application: cl.sourceApp || 'Cellular',
        from: cl.callerNumberOrId || cl.callerName || 'Unknown',
        to: cl.calleeNumberOrId || cl.calleeName || 'Self',
        status: cl.direction || 'MISSED',
        body: `Duration: ${cl.durationSeconds}s | Type: ${cl.callType}`,
        provenance: cl.provenance,
        rawData: cl
      }));
    }
  }, [category, chats, upiTransactions, contacts, callLogs]);

  // Filter rows
  const filteredRows = useMemo(() => {
    if (!tableSearch.trim()) return rows;
    const q = tableSearch.toLowerCase();
    return rows.filter((r) =>
      r.body.toLowerCase().includes(q) ||
      r.from.toLowerCase().includes(q) ||
      r.to.toLowerCase().includes(q) ||
      r.application.toLowerCase().includes(q) ||
      r.status.toLowerCase().includes(q)
    );
  }, [rows, tableSearch]);

  const totalPages = Math.max(1, Math.ceil(filteredRows.length / pageSize));
  const pagedRows = useMemo(() => {
    const start = (currentPage - 1) * pageSize;
    return filteredRows.slice(start, start + pageSize);
  }, [filteredRows, currentPage, pageSize]);

  const handleRowClick = (row: GridRowItem) => {
    setSelectedRowId(row.id);
    setSelectedArtifact({
      id: row.id,
      provenance: row.provenance,
      notes: row.body,
      itemType: category === 'CHATS' ? 'Instant Message' : (category === 'UPI_LEDGER' ? 'Financial Transaction' : 'Contact'),
      rawData: row.rawData
    });
  };

  // Activity Sparkline data generator
  const sparklineDays = Array.from({ length: 30 }, (_, i) => i + 1);
  const sparklineHeights = [
    12, 18, 25, 40, 15, 8, 22, 65, 80, 45, 30, 20, 15, 55, 90, 70, 40, 25, 35, 60,
    75, 50, 30, 45, 60, 85, 95, 40, 20, 15
  ];

  return (
    <div className="flex-1 flex flex-col bg-[#ffffff] text-[#111827] overflow-hidden select-text">
      {/* 1. Sub-Tab Switcher Bar (Conversation View vs Messages View) */}
      <div className="h-9 bg-[#f1f5f9] border-b border-[#e2e8f0] px-3 flex items-center justify-between shrink-0 select-none">
        <div className="flex items-center space-x-1">
          <button
            onClick={() => setViewMode('CONVERSATION')}
            className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-t text-xs font-semibold transition-colors cursor-pointer ${
              viewMode === 'CONVERSATION'
                ? 'bg-white text-[#0078d4] border-t-2 border-[#0078d4] shadow-sm'
                : 'text-gray-600 hover:text-gray-900'
            }`}
          >
            <MessageCircle className="w-3.5 h-3.5" />
            <span>Conversation View</span>
          </button>

          <button
            onClick={() => setViewMode('MESSAGES')}
            className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-t text-xs font-semibold transition-colors cursor-pointer ${
              viewMode === 'MESSAGES'
                ? 'bg-white text-[#0078d4] border-t-2 border-[#0078d4] shadow-sm'
                : 'text-gray-600 hover:text-gray-900'
            }`}
          >
            <TableIcon className="w-3.5 h-3.5" />
            <span>Messages View</span>
          </button>
        </div>

        <div className="text-[11px] text-slate-500 font-mono">
          BharatAnalyzer Forensic Intelligence Engine
        </div>
      </div>

      {/* Render Conversation View or Messages View */}
      {viewMode === 'CONVERSATION' ? (
        <div className="flex-1 flex overflow-hidden">
          <ChatBubbleView
            messages={chats}
            selectedMessageId={selectedRowId || undefined}
            onSelectMessage={(msg) => {
              setSelectedRowId(msg.id);
              setSelectedArtifact({
                id: msg.id,
                provenance: msg.provenance,
                notes: msg.body,
                itemType: 'Instant Message',
                rawData: msg
              });
            }}
          />
        </div>
      ) : (
        <div className="flex-1 flex flex-col overflow-hidden">
          {/* 2. Collapsible Activity Timeline Sparkline Chart (height: 110px, white background) */}
          {!isTimelineCollapsed && (
            <div className="h-[110px] bg-white border-b border-[#e5e7eb] px-4 py-2 shrink-0 flex flex-col justify-between select-none relative">
              {/* Timeline Header Bar */}
              <div className="flex items-center justify-between text-[11px] text-gray-600">
                <div className="flex items-center space-x-2">
                  <div className="w-4 h-4 rounded bg-cyan-600 text-white flex items-center justify-center font-bold text-[9px] shadow-sm">
                    BA
                  </div>
                  <span className="font-semibold text-gray-800">Timeline Activity (Day of Month)</span>
                </div>

                <div className="flex items-center space-x-1">
                  <button
                    onClick={() => setTimelineZoom((z) => Math.min(3, z + 0.2))}
                    title="Zoom In"
                    className="p-1 hover:bg-gray-100 rounded text-gray-600 cursor-pointer"
                  >
                    <Plus className="w-3 h-3" />
                  </button>
                  <button
                    onClick={() => setTimelineZoom((z) => Math.max(0.5, z - 0.2))}
                    title="Zoom Out"
                    className="p-1 hover:bg-gray-100 rounded text-gray-600 cursor-pointer"
                  >
                    <Minus className="w-3 h-3" />
                  </button>
                  <button
                    onClick={() => setIsTimelineCollapsed(true)}
                    className="text-[10px] text-gray-400 hover:text-gray-700 ml-2 cursor-pointer"
                  >
                    Hide
                  </button>
                </div>
              </div>

              {/* Sparkline Canvas / Line */}
              <div className="h-12 w-full flex items-end relative overflow-hidden my-1">
                <svg className="w-full h-full" preserveAspectRatio="none" viewBox="0 0 600 60">
                  <defs>
                    <linearGradient id="timelineGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#1d70b8" stopOpacity="0.25" />
                      <stop offset="100%" stopColor="#1d70b8" stopOpacity="0.0" />
                    </linearGradient>
                  </defs>
                  {/* Area fill */}
                  <polygon
                    points={`0,60 ${sparklineHeights.map((h, i) => `${(i / (sparklineHeights.length - 1)) * 600},${60 - (h / 100) * 55}`).join(' ')} 600,60`}
                    fill="url(#timelineGrad)"
                  />
                  {/* Polyline line chart */}
                  <polyline
                    fill="none"
                    stroke="#1d70b8"
                    strokeWidth="1.5"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    points={sparklineHeights.map((h, i) => `${(i / (sparklineHeights.length - 1)) * 600},${60 - (h / 100) * 55}`).join(' ')}
                  />
                </svg>
              </div>

              {/* Ruler Day Bar (1 2 3 ... 30) */}
              <div className="flex justify-between text-[9px] text-gray-500 font-mono border-t border-[#f1f5f9] pt-0.5">
                {sparklineDays.map((d) => (
                  <span key={d} className="w-4 text-center">{d}</span>
                ))}
              </div>
            </div>
          )}

          {/* 3. Table Action Toolbar (height: 32px, #f8fafc) */}
          <div className="h-8 bg-[#f8fafc] border-b border-[#e5e7eb] px-3 flex items-center justify-between shrink-0 text-xs select-none">
            <div className="flex items-center space-x-3 text-gray-700">
              <button
                onClick={() => setIsTimelineCollapsed((c) => !c)}
                className="hover:text-blue-600 font-medium text-[11px] cursor-pointer"
              >
                {isTimelineCollapsed ? 'Show Timeline' : 'Hide Timeline'}
              </button>
              <span className="text-gray-300">|</span>
              <button className="flex items-center space-x-1 hover:text-blue-600 text-[11px] cursor-pointer">
                <Download className="w-3 h-3" />
                <span>Export ▾</span>
              </button>
              <button className="flex items-center space-x-1 hover:text-blue-600 text-[11px] cursor-pointer">
                <Filter className="w-3 h-3" />
                <span>Filters ▾</span>
              </button>
              <button className="flex items-center space-x-1 hover:text-blue-600 text-[11px] cursor-pointer">
                <MoreVertical className="w-3 h-3" />
                <span>Actions ▾</span>
              </button>
            </div>

            <div className="relative flex items-center">
              <input
                type="text"
                value={tableSearch}
                onChange={(e) => {
                  setTableSearch(e.target.value);
                  setCurrentPage(1);
                }}
                placeholder="Search..."
                className="w-48 h-5 bg-white border border-[#cbd5e1] rounded pl-2 pr-6 text-xs text-gray-900 placeholder-gray-400 focus:outline-none focus:border-[#0078d4]"
              />
              <Search className="w-3 h-3 text-gray-400 absolute right-1.5 pointer-events-none" />
            </div>
          </div>

          {/* 4. High-Density White Data Grid (rowHeight: 26px, borders #e5e7eb, selected row Sky Blue #8ecae6 / #7cc0f7) */}
          <div className="flex-1 overflow-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead className="bg-[#f1f5f9] text-[#334155] border-b border-[#cbd5e1] sticky top-0 z-10 select-none shadow-sm">
                <tr className="h-[26px]">
                  <th className="w-6 px-1.5 text-center border-r border-[#e2e8f0]">
                    <input type="checkbox" className="rounded" />
                  </th>
                  <th className="w-10 px-1 text-center font-semibold border-r border-[#e2e8f0]">#</th>
                  <th className="w-6 px-1 text-center border-r border-[#e2e8f0]" title="Tag">
                    <Tag className="w-3 h-3 mx-auto text-gray-500" />
                  </th>
                  <th className="w-6 px-1 text-center border-r border-[#e2e8f0]" title="Deleted / Carved">
                    <Trash2 className="w-3 h-3 mx-auto text-red-500" />
                  </th>
                  <th className="w-6 px-1 text-center border-r border-[#e2e8f0]" title="Attachment">
                    <Paperclip className="w-3 h-3 mx-auto text-gray-500" />
                  </th>
                  <th className="w-6 px-1 text-center border-r border-[#e2e8f0]" title="Direction">
                    ⇄
                  </th>
                  <th className="px-2 font-semibold border-r border-[#e2e8f0] w-36">Timestamp</th>
                  <th className="px-2 font-semibold border-r border-[#e2e8f0] w-32">Deletion Date</th>
                  <th className="px-2 font-semibold border-r border-[#e2e8f0] w-32">Application</th>
                  <th className="px-2 font-semibold border-r border-[#e2e8f0] w-40">From</th>
                  <th className="px-2 font-semibold border-r border-[#e2e8f0] w-40">To</th>
                  <th className="px-2 font-semibold border-r border-[#e2e8f0] w-32">Label / Status</th>
                  <th className="px-2 font-semibold">Body / Amount / Counterparty</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#e5e7eb]">
                {pagedRows.map((row) => {
                  const isSelected = selectedRowId === row.id;
                  return (
                    <tr
                      key={row.id}
                      onClick={() => handleRowClick(row)}
                      className={`h-[26px] cursor-pointer transition-colors ${
                        isSelected
                          ? 'bg-[#8ecae6] text-black font-medium'
                          : 'hover:bg-[#f8fafc] text-[#111827]'
                      }`}
                    >
                      <td className="px-1.5 text-center border-r border-[#e5e7eb]">
                        <input
                          type="checkbox"
                          checked={isSelected}
                          onChange={() => {}}
                          className="rounded pointer-events-none"
                        />
                      </td>
                      <td className="px-1 text-center text-gray-500 border-r border-[#e5e7eb] font-mono text-[10.5px]">
                        {row.index}
                      </td>
                      <td className="px-1 text-center border-r border-[#e5e7eb]">
                        <Tag className="w-3 h-3 mx-auto text-gray-300" />
                      </td>
                      <td className="px-1 text-center border-r border-[#e5e7eb]">
                        {row.isDeleted ? (
                          <span title="WAL / Freelist Carved">
                            <Trash2 className="w-3.5 h-3.5 mx-auto text-[#ef4444]" />
                          </span>
                        ) : null}
                      </td>
                      <td className="px-1 text-center border-r border-[#e5e7eb]">
                        {row.hasAttachment ? (
                          <Paperclip className="w-3 h-3 mx-auto text-blue-600" />
                        ) : null}
                      </td>
                      <td className="px-1 text-center border-r border-[#e5e7eb]">
                        {row.direction === 'Outgoing' ? (
                          <span title="Outgoing">
                            <ArrowUpRight className="w-3 h-3 mx-auto text-blue-600" />
                          </span>
                        ) : row.direction === 'Unknown' ? (
                          <span title="Direction not established by the evidence" aria-label="Direction unknown" className="block text-center text-slate-400 font-bold">?</span>
                        ) : (
                          <span title="Incoming">
                            <ArrowDownLeft className="w-3 h-3 mx-auto text-green-600" />
                          </span>
                        )}
                      </td>
                      <td className="px-2 border-r border-[#e5e7eb] font-mono text-[11px] truncate">
                        {row.timestamp}
                      </td>
                      <td className="px-2 border-r border-[#e5e7eb] font-mono text-[11px] text-red-600 truncate">
                        {row.deletionDate}
                      </td>
                      <td className="px-2 border-r border-[#e5e7eb] font-medium truncate">
                        {row.application}
                      </td>
                      <td className="px-2 border-r border-[#e5e7eb] truncate" title={row.from}>
                        {row.from}
                      </td>
                      <td className="px-2 border-r border-[#e5e7eb] truncate" title={row.to}>
                        {row.to}
                      </td>
                      <td className="px-2 border-r border-[#e5e7eb] truncate">
                        <span
                          className={`text-[10px] px-1 py-0.2 rounded font-medium ${
                            row.isDeleted
                              ? 'bg-red-100 text-red-700'
                              : 'bg-blue-50 text-blue-700'
                          }`}
                        >
                          {row.status}
                        </span>
                      </td>
                      <td className="px-2 truncate select-text" title={row.body}>
                        {row.body}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          {/* 5. Bottom Table Footer Bar (height: 24px, #f3f4f6) */}
          <div className="h-6 bg-[#f3f4f6] border-t border-[#e5e7eb] px-3 flex items-center justify-between shrink-0 text-xs text-gray-600 font-mono select-none">
            <div className="flex items-center space-x-4 text-[11px]">
              <span>Total: <strong className="text-gray-900">{filteredRows.length}</strong></span>
              <span>Deduplication: 0</span>
              <span>Items: <strong className="text-gray-900">{Math.min(filteredRows.length, (currentPage - 1) * pageSize + 1)}-{Math.min(filteredRows.length, currentPage * pageSize)}</strong> of {filteredRows.length}</span>
              <span>Selected: <strong className="text-gray-900">{selectedRowId ? 1 : 0}</strong></span>
            </div>

            <div className="flex items-center space-x-2 text-[11px]">
              <button
                disabled={currentPage <= 1}
                onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
                className="px-1.5 py-0.5 rounded border border-[#cbd5e1] bg-white hover:bg-gray-100 disabled:opacity-40 cursor-pointer"
              >
                &lt; Prev
              </button>
              <span>Page {currentPage} of {totalPages}</span>
              <button
                disabled={currentPage >= totalPages}
                onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
                className="px-1.5 py-0.5 rounded border border-[#cbd5e1] bg-white hover:bg-gray-100 disabled:opacity-40 cursor-pointer"
              >
                Next &gt;
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

import React, { useState } from 'react';
import {
  FileCode,
  Languages,
  ChevronDown,
  User,
  Paperclip,
  MapPin,
  Clock,
  ExternalLink,
  Trash2,
  ShieldCheck,
  CheckCircle2,
  Copy,
  AlertTriangle,
  CreditCard,
  Binary,
  Layers,
  ChevronRight
} from 'lucide-react';
import { useWorkbenchStore } from '../state/workbenchStore';
import { ForensicProvenance } from '../../shared/forensic-types';

interface PAFieldInspectorProps {
  provenance?: ForensicProvenance | null;
}

export const PAFieldInspector: React.FC<PAFieldInspectorProps> = (props) => {
  const storeArtifact = useWorkbenchStore((state) => state.selectedArtifact);
  const fetchHexWindowForOffset = useWorkbenchStore((state) => state.fetchHexWindowForOffset);
  const setBottomDockTab = useWorkbenchStore((state) => state.setBottomDockTab);

  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [isCollapsed, setIsCollapsed] = useState(false);

  const prov = props.provenance || storeArtifact?.provenance;
  const rawData = storeArtifact?.rawData || {};
  const notes = storeArtifact?.notes;

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const handleSourceFileClick = () => {
    if (prov) {
      setBottomDockTab('HEX');
      fetchHexWindowForOffset(prov);
    }
  };

  const itemKind =
    storeArtifact?.itemType ||
    (prov?.tableName === 'transactions'
      ? 'UPI Financial Transaction'
      : prov?.tableName === 'contacts'
      ? 'Contact Record'
      : prov?.tableName === 'calls'
      ? 'Call Log CDR'
      : 'Instant Message / Chat');

  if (isCollapsed) {
    return (
      <aside className="w-8 bg-[#0b1320] border-l border-slate-800 flex flex-col items-center py-3 select-none text-slate-400">
        <button
          onClick={() => setIsCollapsed(false)}
          className="p-1 hover:text-white hover:bg-slate-800 rounded transition-colors"
          title="Expand Forensic Provenance Inspector"
        >
          <ChevronRight className="w-4 h-4 rotate-180" />
        </button>
        <span className="text-[10px] uppercase font-mono tracking-widest rotate-90 mt-14 whitespace-nowrap text-slate-400 font-bold">
          Field Inspector
        </span>
      </aside>
    );
  }

  if (!prov && !storeArtifact) {
    return (
      <aside className="w-[340px] bg-[#0d1627] border-l border-slate-800 flex flex-col items-center justify-center p-6 text-center text-slate-400 shrink-0 select-none">
        <div className="w-12 h-12 rounded-full bg-slate-800/80 border border-slate-700 flex items-center justify-center mb-3">
          <FileCode className="w-6 h-6 text-slate-400 stroke-1" />
        </div>
        <span className="text-xs font-bold text-slate-200">No Forensic Artifact Selected</span>
        <span className="text-[11px] text-slate-400 mt-1 max-w-[240px] leading-relaxed">
          Select any record in the workbench grid, chat bubbles, or ledger to inspect bit-for-bit provenance, physical byte offsets, and multi-timezone timestamps.
        </span>
      </aside>
    );
  }

  const hexOffset = prov ? `0x${prov.byteOffset.toString(16).toUpperCase().padStart(8, '0')}` : '0x00066000';
  const vfsPath = prov?.vfsInternalPath || '/data/data/com.whatsapp/databases/msgstore.db';
  const tableName = prov?.tableName || 'messages';
  const byteSize = prov?.byteLength ? `${prov.byteLength} bytes` : '64 bytes';
  const recoveryState = prov?.recoveryState || 'ACTIVE';
  const isDeleted = recoveryState === 'WAL_RECOVERED' || recoveryState === 'CARVED_UNALLOCATED' || rawData?.Is_Deleted || rawData?.Is_Revoked_Deleted;

  const appName = rawData.Application || rawData.Source_App || rawData.sourceApp || 'WhatsApp';
  const senderId = rawData.Sender_Identifier || rawData.Sender_ID || rawData.sender || rawData.senderJid || 'N/A';
  const senderName = rawData.Sender_Name || rawData.Sender_ID || rawData.senderName || 'Subject';
  const recipientId = rawData.Recipient_Identifier || rawData.Recipient_ID || rawData.recipient || rawData.recipientJid || 'N/A';
  const recipientName = rawData.Recipient_Name || rawData.Recipient_ID || rawData.recipientName || 'Counterparty';
  const isFromMe = Boolean(rawData.Direction === 'OUTGOING' || rawData.isFromMe);

  const bodyText =
    rawData.Message_Body ||
    rawData.Message_Text ||
    rawData.body ||
    storeArtifact?.notes ||
    (rawData.Amount ? `Amount: ₹${rawData.Amount} (UTR: ${rawData.Bank_Ref_No || rawData.Transaction_ID})` : 'No payload content');

  const rawTimestamp = rawData.Raw_Timestamp_Value || rawData.Timestamp_Raw || storeArtifact?.timestamp?.rawValue || 'N/A';
  const utcIso = rawData.Timestamp_UTC || storeArtifact?.timestamp?.utcIso || 'N/A';
  const istFormatted = rawData.Timestamp_IST || storeArtifact?.timestamp?.istFormatted || 'N/A';

  return (
    <aside className="w-[340px] bg-[#0d1627] border-l border-slate-800 flex flex-col shrink-0 select-text overflow-y-auto overflow-x-hidden text-xs text-slate-200 shadow-xl">
      {/* Top Header */}
      <div className="h-10 px-3 bg-[#090f1d] border-b border-slate-800 flex items-center justify-between shrink-0 font-semibold text-slate-100">
        <div className="flex items-center space-x-1.5 truncate">
          <span className="text-cyan-400 font-bold">»</span>
          <span className="truncate">{itemKind}</span>
        </div>
        <div className="flex items-center space-x-1 text-[11px] font-normal">
          <button
            onClick={handleSourceFileClick}
            className="flex items-center space-x-1 px-2 py-0.5 bg-cyan-950 text-cyan-300 border border-cyan-700/80 rounded hover:bg-cyan-900 transition-colors cursor-pointer"
            title="Inspect in Hex Viewer"
          >
            <Binary className="w-3 h-3" />
            <span>Hex View</span>
          </button>
          <button
            onClick={() => setIsCollapsed(true)}
            className="p-1 hover:text-white text-slate-400 rounded transition-colors"
            title="Collapse Inspector"
          >
            <ChevronRight className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      <div className="p-3 space-y-4 pr-4">
        {/* ===================================================================
            GROUP 1: Artifact Summary & Parties
            =================================================================== */}
        <div className="space-y-2">
          <div className="text-[10px] font-bold uppercase tracking-wider text-slate-400 flex items-center gap-1.5 pb-1 border-b border-slate-800">
            <Layers className="w-3.5 h-3.5 text-cyan-400" />
            <span>Artifact Summary & Parties</span>
          </div>

          <div className="space-y-1.5 text-[11.5px] leading-snug">
            <div className="flex items-start justify-between gap-2">
              <span className="text-slate-400 font-medium shrink-0">Application:</span>
              <span className="font-semibold text-white text-right break-words">{appName}</span>
            </div>

            <div className="flex items-start justify-between gap-2">
              <span className="text-slate-400 font-medium shrink-0">Direction:</span>
              <span className="font-mono text-cyan-300 text-right">
                {rawData.Direction || (isFromMe ? 'OUTGOING' : 'INCOMING')}
              </span>
            </div>

            <div className="flex items-start justify-between gap-2">
              <span className="text-slate-400 font-medium shrink-0">Sender / Origin:</span>
              <div className="text-right truncate max-w-[190px]">
                <div className="font-semibold text-slate-200 truncate">{senderName}</div>
                <div className="text-[10px] text-slate-400 font-mono truncate">{senderId}</div>
              </div>
            </div>

            <div className="flex items-start justify-between gap-2">
              <span className="text-slate-400 font-medium shrink-0">Recipient / Party:</span>
              <div className="text-right truncate max-w-[190px]">
                <div className="font-semibold text-slate-200 truncate">{recipientName}</div>
                <div className="text-[10px] text-slate-400 font-mono truncate">{recipientId}</div>
              </div>
            </div>

            <div className="flex items-start justify-between gap-2">
              <span className="text-slate-400 font-medium shrink-0">Recovery State:</span>
              <span
                className={`font-mono text-[10.5px] font-bold px-1.5 py-0.2 rounded ${
                  isDeleted
                    ? 'bg-red-950 text-red-300 border border-red-800'
                    : 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                }`}
              >
                {recoveryState}
              </span>
            </div>

            <div className="flex items-start justify-between gap-2">
              <span className="text-slate-400 font-medium shrink-0">Status:</span>
              <span className="font-medium text-slate-200 text-right">
                {rawData.Delivery_Status || rawData.Status || 'COMPLETED'}
              </span>
            </div>
          </div>
        </div>

        {/* ===================================================================
            GROUP 2: Multi-Timezone Timestamps
            =================================================================== */}
        <div className="space-y-2">
          <div className="text-[10px] font-bold uppercase tracking-wider text-slate-400 flex items-center gap-1.5 pb-1 border-b border-slate-800">
            <Clock className="w-3.5 h-3.5 text-emerald-400" />
            <span>Multi-Timezone Timestamps</span>
          </div>

          <div className="space-y-1.5 text-[11px] font-mono leading-snug">
            <div>
              <span className="text-slate-400 font-sans block text-[10px]">Raw Epoch / PhonePe ID:</span>
              <span className="text-slate-300 select-all break-all">{rawTimestamp}</span>
            </div>

            <div>
              <span className="text-slate-400 font-sans block text-[10px]">UTC Timezone (+00:00):</span>
              <span className="text-slate-300 select-all break-all">{utcIso}</span>
            </div>

            <div>
              <span className="text-slate-400 font-sans block text-[10px]">Indian Standard Time (IST +05:30):</span>
              <span className="text-emerald-300 font-bold select-all break-all">{istFormatted}</span>
            </div>
          </div>
        </div>

        {/* ===================================================================
            GROUP 3: Source File & Byte Provenance
            =================================================================== */}
        <div className="space-y-2">
          <div className="text-[10px] font-bold uppercase tracking-wider text-slate-400 flex items-center gap-1.5 pb-1 border-b border-slate-800">
            <Binary className="w-3.5 h-3.5 text-amber-400" />
            <span>Source File & Byte Provenance</span>
          </div>

          <div className="space-y-2 text-[11px] leading-snug">
            <div className="p-2 bg-[#090f1d] border border-slate-800 rounded-lg space-y-1">
              <span className="text-slate-400 text-[10px] block font-sans">Physical Byte Offset:</span>
              <button
                onClick={handleSourceFileClick}
                className="text-amber-400 font-mono font-bold text-xs hover:underline flex items-center gap-1"
                title="Click to jump to physical offset in Hex Inspector"
              >
                <span>{hexOffset}</span>
                <ExternalLink className="w-3 h-3 inline" />
              </button>
            </div>

            <div>
              <span className="text-slate-400 text-[10px] block font-sans">Internal File Path:</span>
              <span className="font-mono text-cyan-300 text-[10.5px] break-all select-all block">
                {vfsPath}
              </span>
            </div>

            <div className="grid grid-cols-2 gap-2 text-[10.5px] font-mono">
              <div>
                <span className="text-slate-400 font-sans block text-[9.5px]">Table / Structure:</span>
                <span className="text-slate-200">{tableName}</span>
              </div>
              <div>
                <span className="text-slate-400 font-sans block text-[9.5px]">Record Span:</span>
                <span className="text-slate-200">{byteSize}</span>
              </div>
            </div>
          </div>
        </div>

        {/* ===================================================================
            GROUP 4: Payload Body & Copier
            =================================================================== */}
        <div className="space-y-2">
          <div className="flex items-center justify-between pb-1 border-b border-slate-800">
            <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400">
              Payload Content
            </span>
            <button
              onClick={() => copyToClipboard(bodyText, 'body')}
              className="flex items-center space-x-1 px-1.5 py-0.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded text-[10px] font-mono transition-colors"
            >
              {copiedKey === 'body' ? (
                <>
                  <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                  <span className="text-emerald-400">Copied</span>
                </>
              ) : (
                <>
                  <Copy className="w-3 h-3 text-slate-400" />
                  <span>Copy</span>
                </>
              )}
            </button>
          </div>

          <div className="p-2.5 bg-[#090f1d] border border-slate-800 rounded-lg text-xs text-slate-200 leading-relaxed max-h-40 overflow-y-auto whitespace-pre-wrap font-sans break-words select-all">
            {bodyText}
          </div>
        </div>
      </div>
    </aside>
  );
};

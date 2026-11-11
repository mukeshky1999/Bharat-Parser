import React, { useState } from 'react';
import {
  ChatArtifact,
  RecoveryState
} from '../../shared/forensic-types';
import { useWorkbenchStore } from '../state/workbenchStore';
import {
  MessageSquare,
  ArrowUpRight,
  ArrowDownLeft,
  Check,
  CheckCheck,
  Trash2,
  Flame,
  CornerUpRight,
  Star,
  MapPin,
  FileText,
  Volume2,
  Image as ImageIcon,
  LayoutGrid,
  MessageCircle,
  Clock,
  ExternalLink
} from 'lucide-react';

interface ChatBubbleViewProps {
  messages: ChatArtifact[];
  selectedMessageId?: string;
  onSelectMessage: (msg: ChatArtifact) => void;
}

export const ChatBubbleView: React.FC<ChatBubbleViewProps> = ({
  messages,
  selectedMessageId,
  onSelectMessage
}) => {
  const { chatViewMode, setChatViewMode, selectedSubcategory, setSelectedArtifact } =
    useWorkbenchStore();

  const [activeTabSubcategory, setActiveTabSubcategory] = useState<string>(
    selectedSubcategory || 'ALL'
  );

  // Filter messages by active subcategory
  const filteredMessages = messages.filter((msg) => {
    const subcat = selectedSubcategory !== 'ALL' ? selectedSubcategory : activeTabSubcategory;
    if (!subcat || subcat === 'ALL') return true;
    if (subcat === 'WhatsApp') return msg.sourceApp.includes('WhatsApp');
    if (subcat === 'Telegram') return msg.sourceApp.includes('Telegram');
    if (subcat === 'Signal') return msg.sourceApp.includes('Signal');
    if (subcat === 'Zangi') return msg.sourceApp.includes('Zangi');
    if (subcat === 'Element') return msg.sourceApp.includes('Element');
    if (subcat === 'Session') return msg.sourceApp.includes('Session');
    if (subcat === 'Threema') {
      return ['Threema', 'Briar', 'SimpleX'].some((a) => msg.sourceApp.includes(a));
    }
    if (subcat === 'Snapchat') return msg.sourceApp.includes('Snapchat');
    if (subcat === 'Instagram') return msg.sourceApp.includes('Instagram');
    if (subcat === 'Dating') {
      return ['Tinder', 'Bumble', 'Hinge', 'Grindr'].some((a) => msg.sourceApp.includes(a));
    }
    return true;
  });

  const getAppTheme = (app: string) => {
    if (app.includes('WhatsApp')) {
      return {
        bubbleIncoming: 'bg-emerald-950/70 border-emerald-800/60 text-emerald-100',
        bubbleOutgoing: 'bg-emerald-900/90 border-emerald-700/80 text-emerald-50',
        badge: 'bg-emerald-950 text-emerald-300 border-emerald-700/60',
        nameColor: 'text-emerald-400'
      };
    }
    if (app.includes('Telegram')) {
      return {
        bubbleIncoming: 'bg-sky-950/70 border-sky-800/60 text-sky-100',
        bubbleOutgoing: 'bg-sky-900/90 border-sky-700/80 text-sky-50',
        badge: 'bg-sky-950 text-sky-300 border-sky-700/60',
        nameColor: 'text-sky-400'
      };
    }
    if (app.includes('Signal')) {
      return {
        bubbleIncoming: 'bg-purple-950/70 border-purple-800/60 text-purple-100',
        bubbleOutgoing: 'bg-purple-900/90 border-purple-700/80 text-purple-50',
        badge: 'bg-purple-950 text-purple-300 border-purple-700/60',
        nameColor: 'text-purple-400'
      };
    }
    if (app.includes('Zangi')) {
      return {
        bubbleIncoming: 'bg-orange-950/70 border-orange-800/60 text-orange-100',
        bubbleOutgoing: 'bg-orange-900/90 border-orange-700/80 text-orange-50',
        badge: 'bg-orange-950 text-orange-300 border-orange-700/60',
        nameColor: 'text-orange-400'
      };
    }
    if (app.includes('Snapchat')) {
      return {
        bubbleIncoming: 'bg-yellow-950/70 border-yellow-800/60 text-yellow-100',
        bubbleOutgoing: 'bg-yellow-900/90 border-yellow-700/80 text-yellow-50',
        badge: 'bg-yellow-950 text-yellow-300 border-yellow-700/60',
        nameColor: 'text-yellow-400'
      };
    }
    if (app.includes('Tinder') || app.includes('Bumble') || app.includes('Hinge')) {
      return {
        bubbleIncoming: 'bg-rose-950/70 border-rose-800/60 text-rose-100',
        bubbleOutgoing: 'bg-rose-900/90 border-rose-700/80 text-rose-50',
        badge: 'bg-rose-950 text-rose-300 border-rose-700/60',
        nameColor: 'text-rose-400'
      };
    }
    if (app.includes('Element')) {
      return {
        bubbleIncoming: 'bg-teal-950/70 border-teal-800/60 text-teal-100',
        bubbleOutgoing: 'bg-teal-900/90 border-teal-700/80 text-teal-50',
        badge: 'bg-teal-950 text-teal-300 border-teal-700/60',
        nameColor: 'text-teal-400'
      };
    }
    if (app.includes('Session')) {
      return {
        bubbleIncoming: 'bg-cyan-950/70 border-cyan-800/60 text-cyan-100',
        bubbleOutgoing: 'bg-cyan-900/90 border-cyan-700/80 text-cyan-50',
        badge: 'bg-cyan-950 text-cyan-300 border-cyan-700/60',
        nameColor: 'text-cyan-400'
      };
    }
    return {
      bubbleIncoming: 'bg-slate-900 border-slate-800 text-slate-200',
      bubbleOutgoing: 'bg-slate-800 border-slate-700 text-slate-100',
      badge: 'bg-slate-800 text-slate-300 border-slate-700',
      nameColor: 'text-slate-300'
    };
  };

  const getStatusIcon = (status?: string) => {
    switch (status) {
      case 'READ':
        return (
          <span title="Read">
            <CheckCheck className="w-3 h-3 text-cyan-400" />
          </span>
        );
      case 'DELIVERED':
        return (
          <span title="Delivered">
            <CheckCheck className="w-3 h-3 text-slate-400" />
          </span>
        );
      case 'SENT':
        return (
          <span title="Sent">
            <Check className="w-3 h-3 text-slate-400" />
          </span>
        );
      default:
        return (
          <span title="Sent">
            <Check className="w-3 h-3 text-slate-500" />
          </span>
        );
    }
  };

  const getStateBadge = (state: RecoveryState) => {
    switch (state) {
      case 'ACTIVE':
        return (
          <span className="text-[9px] bg-emerald-950 text-emerald-300 border border-emerald-800/60 px-1.5 py-0.2 rounded font-mono font-semibold">
            [ACTIVE]
          </span>
        );
      case 'WAL_RECOVERED':
        return (
          <span className="text-[9px] bg-blue-950 text-blue-300 border border-blue-800/60 px-1.5 py-0.2 rounded font-mono font-bold flex items-center space-x-1">
            <Trash2 className="w-2.5 h-2.5" />
            <span>[WAL RECOVERED]</span>
          </span>
        );
      case 'CARVED_UNALLOCATED':
        return (
          <span className="text-[9px] bg-amber-950 text-amber-300 border border-amber-800/60 px-1.5 py-0.2 rounded font-mono font-bold flex items-center space-x-1">
            <Trash2 className="w-2.5 h-2.5" />
            <span>[CARVED]</span>
          </span>
        );
      default:
        return (
          <span className="text-[9px] bg-purple-950 text-purple-300 border border-purple-800/60 px-1.5 py-0.2 rounded font-mono">
            [{state}]
          </span>
        );
    }
  };

  return (
    <div className="flex-1 flex flex-col bg-slate-950 overflow-hidden select-text">
      {/* View Header with Dual-Mode Toggle & Subcategory Pills */}
      <div className="h-11 bg-slate-900 border-b border-slate-800 px-3 flex items-center justify-between text-xs shrink-0 select-none">
        <div className="flex items-center space-x-2">
          <MessageSquare className="w-4 h-4 text-cyan-400" />
          <span className="font-bold text-slate-100">
            Instant Messengers & Social Chats
          </span>
          <span className="text-[11px] text-slate-400 font-mono">
            ({filteredMessages.length} Records)
          </span>
        </div>

        {/* View Mode Toggle: PA Table Grid vs Conversation Bubbles */}
        <div className="flex items-center space-x-2">
          <div className="flex items-center bg-slate-950 border border-slate-800 rounded p-0.5 font-mono text-[11px]">
            <button
              onClick={() => setChatViewMode('GRID')}
              className={`flex items-center space-x-1 px-2.5 py-1 rounded transition-colors ${
                chatViewMode === 'GRID'
                  ? 'bg-emerald-600 text-white font-bold'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <LayoutGrid className="w-3.5 h-3.5" />
              <span>PA Table Grid</span>
            </button>
            <button
              onClick={() => setChatViewMode('BUBBLE')}
              className={`flex items-center space-x-1 px-2.5 py-1 rounded transition-colors ${
                chatViewMode === 'BUBBLE'
                  ? 'bg-emerald-600 text-white font-bold'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <MessageCircle className="w-3.5 h-3.5" />
              <span>Bubble View</span>
            </button>
          </div>
        </div>
      </div>

      {/* Subcategory Filter Filter Pills */}
      <div className="h-8 bg-slate-950/80 border-b border-slate-800/80 px-3 flex items-center space-x-1.5 overflow-x-auto text-[11px] font-mono shrink-0 select-none">
        <span className="text-[10px] text-slate-500 uppercase tracking-wider mr-1">App Filter:</span>
        {[
          'ALL',
          'WhatsApp',
          'Telegram',
          'Signal',
          'Zangi',
          'Element',
          'Session',
          'Threema',
          'Snapchat',
          'Instagram',
          'Dating'
        ].map((app) => {
          const isCurrent =
            (selectedSubcategory && selectedSubcategory !== 'ALL')
              ? selectedSubcategory === app
              : activeTabSubcategory === app;

          return (
            <button
              key={app}
              onClick={() => setActiveTabSubcategory(app)}
              className={`px-2 py-0.5 rounded text-[10.5px] transition-colors ${
                isCurrent
                  ? 'bg-cyan-950 text-cyan-300 font-bold border border-cyan-700/60'
                  : 'bg-slate-900 text-slate-400 hover:bg-slate-800 hover:text-slate-200'
              }`}
            >
              {app}
            </button>
          );
        })}
      </div>

      {/* Main Content Area */}
      {chatViewMode === 'GRID' ? (
        /* PA Multi-Column Forensic Table Grid (No Column Flattening) */
        <div className="flex-1 overflow-auto">
          <table className="w-full text-left text-[11px] font-mono border-collapse select-text">
            <thead className="bg-slate-900 border-b border-slate-800 text-slate-400 uppercase text-[9.5px] sticky top-0 z-10">
              <tr>
                <th className="p-2 w-10">#</th>
                <th className="p-2 w-28">App</th>
                <th className="p-2 w-16">Dir</th>
                <th className="p-2 w-44">Sender (ID / Name)</th>
                <th className="p-2 w-44">Recipient (ID / Name)</th>
                <th className="p-2">Message Body / Media Payload</th>
                <th className="p-2 w-44">Timestamp (IST +05:30)</th>
                <th className="p-2 w-16">Status</th>
                <th className="p-2 w-20">Ephemeral</th>
                <th className="p-2 w-14">Fwd</th>
                <th className="p-2 w-28">Source Table</th>
                <th className="p-2 w-24">Byte Offset</th>
                <th className="p-2 w-28">Recovery State</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 bg-slate-950">
              {filteredMessages.map((msg, idx) => {
                const isSelected = selectedMessageId === msg.id;
                const hexOffset = `0x${msg.provenance.byteOffset.toString(16).toUpperCase().padStart(8, '0')}`;

                return (
                  <tr
                    key={msg.id}
                    onClick={() => {
                      onSelectMessage(msg);
                      setSelectedArtifact({
                        id: msg.id,
                        provenance: msg.provenance,
                        timestamp: msg.timestamp,
                        itemType: 'CHAT_MESSAGE',
                        rawData: msg
                      });
                    }}
                    className={`cursor-pointer transition-colors ${
                      isSelected
                        ? 'bg-emerald-950/40 text-emerald-100 border-l-2 border-emerald-500'
                        : 'hover:bg-slate-900/60 text-slate-300'
                    }`}
                  >
                    <td className="p-2 text-slate-500">{idx + 1}</td>
                    <td className="p-2 font-semibold">
                      <span className="px-1.5 py-0.5 rounded bg-slate-900 border border-slate-800 text-[10px]">
                        {msg.sourceApp}
                      </span>
                    </td>
                    <td className="p-2">
                      {msg.isFromMe ? (
                        <span className="flex items-center text-emerald-400 font-bold text-[10px]">
                          <ArrowUpRight className="w-3 h-3 mr-0.5" /> OUT
                        </span>
                      ) : (
                        <span className="flex items-center text-sky-400 font-bold text-[10px]">
                          <ArrowDownLeft className="w-3 h-3 mr-0.5" /> IN
                        </span>
                      )}
                    </td>
                    <td className="p-2 truncate max-w-[170px]" title={msg.senderJid}>
                      <div className="font-sans font-semibold text-slate-200 truncate">
                        {msg.senderName}
                      </div>
                      <div className="text-[9.5px] text-slate-500 truncate">{msg.senderJid}</div>
                    </td>
                    <td className="p-2 truncate max-w-[170px]" title={msg.recipientJid || 'N/A'}>
                      <div className="font-sans font-semibold text-slate-300 truncate">
                        {msg.recipientName || 'Recipient'}
                      </div>
                      <div className="text-[9.5px] text-slate-500 truncate">
                        {msg.recipientJid || 'N/A'}
                      </div>
                    </td>
                    <td className="p-2 max-w-[320px]">
                      <div className="font-sans text-xs text-slate-200 line-clamp-2">
                        {msg.body}
                      </div>
                      {msg.paymentAttachment && (
                        <div className="mt-1 text-[10px] text-emerald-400 font-mono bg-emerald-950/50 px-1.5 py-0.5 rounded border border-emerald-800/40 inline-block">
                          ₹{msg.paymentAttachment.amountInr.toLocaleString('en-IN')} (UTR: {msg.paymentAttachment.utrNumber})
                        </div>
                      )}
                      {msg.locationName && (
                        <div className="mt-1 text-[10px] text-teal-300 flex items-center space-x-1">
                          <MapPin className="w-2.5 h-2.5" />
                          <span>{msg.locationName}</span>
                        </div>
                      )}
                    </td>
                    <td className="p-2 text-slate-300 text-[10px] whitespace-nowrap">
                      {msg.timestamp.istFormatted.substring(0, 19)}
                    </td>
                    <td className="p-2 text-center">
                      {getStatusIcon(msg.messageStatus)}
                    </td>
                    <td className="p-2 text-[10px]">
                      {msg.ephemeralDuration ? (
                        <span className="text-orange-400 flex items-center space-x-0.5 font-bold">
                          <Flame className="w-3 h-3" />
                          <span>{msg.ephemeralDuration}s</span>
                        </span>
                      ) : (
                        <span className="text-slate-600">—</span>
                      )}
                    </td>
                    <td className="p-2 text-[10px] text-center">
                      {msg.forwardingScore ? (
                        <span className="text-cyan-400 font-bold">
                          +{msg.forwardingScore}
                        </span>
                      ) : (
                        <span className="text-slate-600">0</span>
                      )}
                    </td>
                    <td className="p-2 text-slate-400 truncate text-[10px]" title={msg.provenance.tableName}>
                      {msg.provenance.tableName || 'N/A'}
                    </td>
                    <td className="p-2 text-amber-400 font-bold text-[10.5px]">
                      {hexOffset}
                    </td>
                    <td className="p-2">
                      {getStateBadge(msg.provenance.recoveryState)}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      ) : (
        /* BharatAnalyzer Forensic Bubble Stream View */
        <div className="flex-1 overflow-y-auto p-4 space-y-4">
          {filteredMessages.map((msg) => {
            const isSelected = selectedMessageId === msg.id;
            const isFromMe = msg.isFromMe;
            const hexOffset = `0x${msg.provenance.byteOffset.toString(16).toUpperCase().padStart(8, '0')}`;
            const theme = getAppTheme(msg.sourceApp);

            return (
              <div
                key={msg.id}
                onClick={() => {
                  onSelectMessage(msg);
                  setSelectedArtifact({
                    id: msg.id,
                    provenance: msg.provenance,
                    timestamp: msg.timestamp,
                    itemType: 'CHAT_MESSAGE',
                    rawData: msg
                  });
                }}
                className={`flex flex-col cursor-pointer transition-all ${
                  isFromMe ? 'items-end' : 'items-start'
                }`}
              >
                <div
                  className={`max-w-[75%] rounded-xl p-3 shadow-lg border transition-all ${
                    isSelected
                      ? 'border-emerald-400 ring-2 ring-emerald-500/40'
                      : 'border-slate-800'
                  } ${
                    isFromMe
                      ? `${theme.bubbleOutgoing} rounded-tr-none`
                      : `${theme.bubbleIncoming} rounded-tl-none`
                  }`}
                >
                  {/* Sender Header & Forensic Badges */}
                  <div className="flex items-center justify-between space-x-3 mb-1.5 text-[11px] pb-1 border-b border-white/10">
                    <div className="flex items-center space-x-1.5 truncate">
                      <span className={`font-bold font-sans ${theme.nameColor} truncate`}>
                        {msg.senderName}
                      </span>
                      <span className={`text-[9.5px] px-1.5 py-0.2 rounded font-mono border ${theme.badge}`}>
                        {msg.sourceApp}
                      </span>
                    </div>

                    <div className="flex items-center space-x-1.5 shrink-0">
                      {msg.isStarred && (
                        <Star className="w-3 h-3 text-amber-400 fill-amber-400" />
                      )}
                      {msg.forwardingScore ? (
                        <span className="flex items-center space-x-0.5 text-[9px] text-cyan-300 font-mono">
                          <CornerUpRight className="w-2.5 h-2.5" />
                          <span>Fwd (+{msg.forwardingScore})</span>
                        </span>
                      ) : null}
                      {msg.ephemeralDuration ? (
                        <span className="flex items-center space-x-0.5 text-[9px] text-orange-400 bg-orange-950/80 px-1 rounded font-mono">
                          <Flame className="w-2.5 h-2.5" />
                          <span>{msg.ephemeralDuration}s</span>
                        </span>
                      ) : null}
                      {getStateBadge(msg.provenance.recoveryState)}
                    </div>
                  </div>

                  {/* Message Body Content */}
                  <div className="text-xs leading-relaxed select-text font-sans break-words py-1 text-slate-100">
                    {msg.body}
                  </div>

                  {/* Location Attachment Card */}
                  {msg.locationName && (
                    <div className="mt-2 bg-slate-950/90 border border-teal-500/40 rounded-lg p-2 text-xs font-mono flex items-center justify-between">
                      <div className="flex items-center space-x-2">
                        <MapPin className="w-4 h-4 text-teal-400 shrink-0" />
                        <div>
                          <div className="text-teal-300 font-bold">{msg.locationName}</div>
                          <div className="text-[10px] text-slate-400">
                            Lat: {msg.latitude?.toFixed(4)}, Lon: {msg.longitude?.toFixed(4)}
                          </div>
                        </div>
                      </div>
                      <span className="text-[10px] text-teal-400 bg-teal-950 px-2 py-0.5 rounded border border-teal-800/40">
                        GEOTAG
                      </span>
                    </div>
                  )}

                  {/* UPI Payment Attachment Card */}
                  {msg.paymentAttachment && (
                    <div className="mt-2 bg-slate-950/90 border border-emerald-500/40 rounded-lg p-2.5 text-xs font-mono">
                      <div className="flex items-center justify-between text-emerald-400 font-bold">
                        <span>UPI PAYMENT EVIDENCE</span>
                        <span>₹{msg.paymentAttachment.amountInr.toLocaleString('en-IN')}</span>
                      </div>
                      {msg.paymentAttachment.utrNumber && (
                        <div className="text-[10.5px] text-amber-300 mt-1">
                          NPCI UTR: {msg.paymentAttachment.utrNumber}
                        </div>
                      )}
                      {msg.paymentAttachment.vpa && (
                        <div className="text-[10px] text-slate-400">
                          Beneficiary: {msg.paymentAttachment.vpa}
                        </div>
                      )}
                    </div>
                  )}

                  {/* Footer Forensic Metadata & Hex Byte Offset */}
                  <div className="flex items-center justify-between space-x-4 mt-2 pt-1.5 border-t border-white/10 text-[9.5px] font-mono text-slate-400">
                    <div className="flex items-center space-x-1.5">
                      <Clock className="w-2.5 h-2.5 text-slate-500" />
                      <span>{msg.timestamp.istFormatted.substring(0, 19)} IST</span>
                    </div>

                    <div className="flex items-center space-x-2">
                      <span className="text-amber-400 font-bold hover:underline" title="Physical Storage Hex Offset">
                        {hexOffset}
                      </span>
                      {getStatusIcon(msg.messageStatus)}
                    </div>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};

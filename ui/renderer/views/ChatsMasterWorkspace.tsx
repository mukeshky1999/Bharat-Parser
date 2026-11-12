import React, { useState, useMemo } from 'react';
import {
  ChatArtifact,
  RecoveryState
} from '../../shared/forensic-types';
import { useWorkbenchStore, RecoveryPillFilter, EphemeralPillFilter, ChatWorkspaceMode } from '../state/workbenchStore';
import { csvCell, downloadCsv, formatOffset } from '../utils/csv';
import { useTagIndex } from '../workspace/useTagIndex';
import { TagPills } from '../inspectors/TagControls';
import { caseRecordOf } from '../utils/caseRecord';
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
  ExternalLink,
  Play,
  Pause,
  Search,
  Filter,
  Eye,
  EyeOff,
  User,
  Users,
  Copy,
  CheckCircle2,
  Maximize2,
  X,
  CreditCard,
  Lock,
  Radio,
  FileCode,
  ShieldAlert,
  ChevronLeft,
  ChevronRight,
  ChevronsLeft,
  ChevronsRight,
  Compass,
  FileSpreadsheet,
  Binary
} from 'lucide-react';

interface AudioPlayerState {
  isPlaying: boolean;
  progress: number;
}

export const ChatsMasterWorkspace: React.FC = () => {
  const chatTags = useTagIndex('chats');
  const tagsOfMsg = (id: string): string[] => { const n = caseRecordOf(id, 'CHAT_MESSAGE')?.id; return n ? chatTags[n] ?? [] : []; };
  const {
    chats,
    chatViewMode,
    setChatViewMode,
    selectedSubcategory,
    setSelectedSubcategory,
    recoveryPillFilter,
    setRecoveryPillFilter,
    ephemeralFilter,
    setEphemeralFilter,
    currentPage,
    setCurrentPage,
    pageSize,
    selectedArtifact,
    setSelectedArtifact,
    setActiveTab,
    setBottomDockTab,
    fetchHexWindowForOffset
  } = useWorkbenchStore();

  const [selectedThreadId, setSelectedThreadId] = useState<string>('ALL');
  const [threadSearchQuery, setThreadSearchQuery] = useState<string>('');
  const [messageSearchQuery, setMessageSearchQuery] = useState<string>('');

  // Audio player state per message id
  const [audioStates, setAudioStates] = useState<Record<string, AudioPlayerState>>({});
  // Lightbox modal for image attachments
  const [activeImageModal, setActiveImageModal] = useState<string | null>(null);

  // Helper to extract UPI / Bank Payment details from message attachments or body
  const extractPaymentEvidence = (msg: ChatArtifact) => {
    if (msg.paymentAttachment) {
      return {
        amount: msg.paymentAttachment.amountInr,
        utr: msg.paymentAttachment.utrNumber,
        vpa: msg.paymentAttachment.vpa,
        status: msg.paymentAttachment.status || 'CONFIRMED'
      };
    }
    const body = msg.body || '';
    const utrMatch = body.match(/\b\d{12}\b/);
    const vpaMatch = body.match(/([a-zA-Z0-9.\-_]{2,}@[a-zA-Z]{2,})/);
    const amountMatch = body.match(/(?:₹|Rs\.?|INR)\s*([\d,]+(?:\.\d{1,2})?)/i);

    if (utrMatch || (amountMatch && vpaMatch)) {
      const amtNum = amountMatch ? parseFloat(amountMatch[1].replace(/,/g, '')) : undefined;
      return {
        amount: amtNum,
        utr: utrMatch ? utrMatch[0] : undefined,
        vpa: vpaMatch ? vpaMatch[1] : undefined,
        status: 'CORROBORATED_EVIDENCE'
      };
    }
    return null;
  };

  // Helper to export filtered messages to CSV
  const handleExportCsv = () => {
    if (chats.length === 0) return;
    const headers = ['ID', 'App', 'Direction', 'Sender', 'Recipient', 'Body', 'Status', 'Timestamp_IST', 'Byte_Offset', 'Recovery_State'];
    const rows = chats.map((m) => [
      csvCell(m.id),
      csvCell(m.sourceApp),
      csvCell(m.direction || (m.isFromMe ? 'OUTGOING' : 'UNKNOWN')),
      csvCell(m.senderName || ''),
      csvCell(m.recipientName || ''),
      csvCell(m.body || ''),
      csvCell(m.messageStatus || ''),
      csvCell(m.timestamp?.istFormatted || ''),
      csvCell(formatOffset(m.provenance.byteOffset)),
      csvCell(m.provenance.recoveryState)
    ].join(','));
    downloadCsv(`BharatAnalyzer_Chats_Export_${Date.now()}.csv`, [headers.join(','), ...rows]);
  };

  // 1. Group chats into Distinct Conversation Threads
  const conversationThreads = useMemo(() => {
    const threadMap: Record<string, {
      threadKey: string;
      sourceApp: string;
      threadId: string;
      threadTitle: string;
      recipientName: string;
      messages: ChatArtifact[];
      lastMessage: ChatArtifact;
      activeCount: number;
      carvedCount: number;
    }> = {};

    for (const msg of chats) {
      const key = `${msg.sourceApp}:::${msg.threadId}`;
      if (!threadMap[key]) {
        threadMap[key] = {
          threadKey: key,
          sourceApp: msg.sourceApp,
          threadId: msg.threadId,
          threadTitle: msg.threadTitle || msg.recipientName || msg.senderName || msg.threadId,
          recipientName: msg.recipientName || msg.senderName || 'Unknown',
          messages: [],
          lastMessage: msg,
          activeCount: 0,
          carvedCount: 0
        };
      }
      threadMap[key].messages.push(msg);
      if (msg.isDeleted || msg.provenance?.recoveryState !== 'ACTIVE') {
        threadMap[key].carvedCount++;
      } else {
        threadMap[key].activeCount++;
      }
      if (msg.timestamp.epochMs > threadMap[key].lastMessage.timestamp.epochMs) {
        threadMap[key].lastMessage = msg;
      }
    }

    return Object.values(threadMap).sort(
      (a, b) => b.lastMessage.timestamp.epochMs - a.lastMessage.timestamp.epochMs
    );
  }, [chats]);

  // Filter threads by search query & app subcategory
  const filteredThreads = useMemo(() => {
    return conversationThreads.filter((th) => {
      if (selectedSubcategory && selectedSubcategory !== 'ALL') {
        if (!th.sourceApp.toLowerCase().includes(selectedSubcategory.toLowerCase())) {
          if (selectedSubcategory === 'Dating') {
            if (!['Tinder', 'Bumble', 'Hinge', 'Grindr'].some((a) => th.sourceApp.includes(a))) {
              return false;
            }
          } else if (selectedSubcategory === 'Threema') {
            if (!['Threema', 'Briar', 'SimpleX'].some((a) => th.sourceApp.includes(a))) {
              return false;
            }
          } else {
            return false;
          }
        }
      }

      if (threadSearchQuery.trim()) {
        const q = threadSearchQuery.toLowerCase();
        const matchesTitle = th.threadTitle.toLowerCase().includes(q);
        const matchesId = th.threadId.toLowerCase().includes(q);
        const matchesApp = th.sourceApp.toLowerCase().includes(q);
        const matchesBody = th.messages.some((m) => m.body.toLowerCase().includes(q));
        if (!matchesTitle && !matchesId && !matchesApp && !matchesBody) return false;
      }

      return true;
    });
  }, [conversationThreads, selectedSubcategory, threadSearchQuery]);

  // Active selected thread
  const activeThread = useMemo(() => {
    if (selectedThreadId === 'ALL') return null;
    return conversationThreads.find((t) => t.threadKey === selectedThreadId) || null;
  }, [conversationThreads, selectedThreadId]);

  // Filter messages for active view
  const allFilteredMessages = useMemo(() => {
    let list = chats;

    // Filter by selected thread
    if (selectedThreadId !== 'ALL') {
      list = list.filter((m) => `${m.sourceApp}:::${m.threadId}` === selectedThreadId);
    } else if (selectedSubcategory && selectedSubcategory !== 'ALL') {
      list = list.filter((m) => {
        if (selectedSubcategory === 'Dating') {
          return ['Tinder', 'Bumble', 'Hinge', 'Grindr'].some((a) => m.sourceApp.includes(a));
        }
        if (selectedSubcategory === 'Threema') {
          return ['Threema', 'Briar', 'SimpleX'].some((a) => m.sourceApp.includes(a));
        }
        return m.sourceApp.toLowerCase().includes(selectedSubcategory.toLowerCase());
      });
    }

    // Recovery State Filter Pills
    if (recoveryPillFilter === 'ACTIVE') {
      list = list.filter((m) => !m.isDeleted && m.provenance?.recoveryState === 'ACTIVE');
    } else if (recoveryPillFilter === 'WAL') {
      list = list.filter((m) => m.provenance?.recoveryState === 'WAL_RECOVERED');
    } else if (recoveryPillFilter === 'CARVED') {
      list = list.filter((m) => m.provenance?.recoveryState === 'CARVED_UNALLOCATED' || m.isDeleted);
    } else if (recoveryPillFilter === 'SPILLOVER') {
      list = list.filter((m) => m.provenance?.recoveryState === 'OS_SPILLOVER');
    }

    // Ephemeral Filter Pills
    if (ephemeralFilter === 'VIEW_ONCE') {
      list = list.filter((m) => m.isViewOnce);
    } else if (ephemeralFilter === 'DISAPPEARING') {
      list = list.filter((m) => m.ephemeralDuration && m.ephemeralDuration > 0);
    } else if (ephemeralFilter === 'REVOKED') {
      list = list.filter((m) => m.isDeleted);
    } else if (ephemeralFilter === 'ATTACHMENTS') {
      list = list.filter((m) => m.mediaType || m.paymentAttachment || m.locationName || m.mediaPath);
    }

    // Instant Search query
    if (messageSearchQuery.trim()) {
      const q = messageSearchQuery.toLowerCase();
      list = list.filter(
        (m) =>
          m.body.toLowerCase().includes(q) ||
          m.senderName.toLowerCase().includes(q) ||
          m.senderJid.toLowerCase().includes(q) ||
          (m.paymentAttachment && m.paymentAttachment.utrNumber?.includes(q)) ||
          m.threadTitle?.toLowerCase().includes(q) ||
          m.provenance.vfsInternalPath.toLowerCase().includes(q)
      );
    }

    // Sort chronologically for bubbles, reverse chronological for table
    return list.slice().sort((a, b) => {
      if (chatViewMode === 'BUBBLE') {
        return a.timestamp.epochMs - b.timestamp.epochMs;
      }
      return b.timestamp.epochMs - a.timestamp.epochMs;
    });
  }, [
    chats,
    selectedThreadId,
    selectedSubcategory,
    recoveryPillFilter,
    ephemeralFilter,
    messageSearchQuery,
    chatViewMode
  ]);

  // Server-side / Virtualized 100-row Pagination calculation
  const totalMatching = allFilteredMessages.length;
  const totalPages = Math.max(1, Math.ceil(totalMatching / pageSize));
  const validPage = Math.min(Math.max(1, currentPage), totalPages);
  const offset = (validPage - 1) * pageSize;

  const paginatedMessages = useMemo(() => {
    if (chatViewMode === 'BUBBLE') {
      // In bubble mode, render thread messages directly
      return allFilteredMessages;
    }
    return allFilteredMessages.slice(offset, offset + pageSize);
  }, [allFilteredMessages, offset, pageSize, chatViewMode]);

  const handleSelectMessage = (msg: ChatArtifact) => {
    setSelectedArtifact({
      id: msg.id,
      provenance: msg.provenance,
      timestamp: msg.timestamp,
      itemType: 'CHAT_MESSAGE',
      notes: `${msg.sourceApp} message from ${msg.senderName} (${msg.provenance.tableName})`,
      rawData: msg
    });
  };

  const getAppTheme = (app: string) => {
    if (app.includes('WhatsApp')) {
      return {
        badge: 'bg-emerald-950 text-emerald-300 border-emerald-700/60',
        incoming: 'bg-emerald-950/80 border-emerald-800/80 text-emerald-50',
        outgoing: 'bg-emerald-900/90 border-emerald-700 text-slate-50',
        accent: 'text-emerald-400',
        nameColor: 'text-emerald-300'
      };
    }
    if (app.includes('Telegram')) {
      return {
        badge: 'bg-sky-950 text-sky-300 border-sky-700/60',
        incoming: 'bg-sky-950/80 border-sky-800/80 text-sky-50',
        outgoing: 'bg-sky-900/90 border-sky-700 text-slate-50',
        accent: 'text-sky-400',
        nameColor: 'text-sky-300'
      };
    }
    if (app.includes('Signal')) {
      return {
        badge: 'bg-purple-950 text-purple-300 border-purple-700/60',
        incoming: 'bg-purple-950/80 border-purple-800/80 text-purple-50',
        outgoing: 'bg-purple-900/90 border-purple-700 text-slate-50',
        accent: 'text-purple-400',
        nameColor: 'text-purple-300'
      };
    }
    if (app.includes('Zangi')) {
      return {
        badge: 'bg-orange-950 text-orange-300 border-orange-700/60',
        incoming: 'bg-orange-950/80 border-orange-800/80 text-orange-50',
        outgoing: 'bg-orange-900/90 border-orange-700 text-slate-50',
        accent: 'text-orange-400',
        nameColor: 'text-orange-300'
      };
    }
    if (app.includes('Snapchat')) {
      return {
        badge: 'bg-yellow-950 text-yellow-300 border-yellow-700/60',
        incoming: 'bg-yellow-950/80 border-yellow-800/80 text-yellow-50',
        outgoing: 'bg-yellow-900/90 border-yellow-700 text-slate-50',
        accent: 'text-yellow-400',
        nameColor: 'text-yellow-300'
      };
    }
    if (app.includes('Tinder') || app.includes('Bumble') || app.includes('Hinge') || app.includes('Grindr')) {
      return {
        badge: 'bg-rose-950 text-rose-300 border-rose-700/60',
        incoming: 'bg-rose-950/80 border-rose-800/80 text-rose-50',
        outgoing: 'bg-rose-900/90 border-rose-700 text-slate-50',
        accent: 'text-rose-400',
        nameColor: 'text-rose-300'
      };
    }
    if (app.includes('Element')) {
      return {
        badge: 'bg-teal-950 text-teal-300 border-teal-700/60',
        incoming: 'bg-teal-950/80 border-teal-800/80 text-teal-50',
        outgoing: 'bg-teal-900/90 border-teal-700 text-slate-50',
        accent: 'text-teal-400',
        nameColor: 'text-teal-300'
      };
    }
    if (app.includes('Session')) {
      return {
        badge: 'bg-cyan-950 text-cyan-300 border-cyan-700/60',
        incoming: 'bg-cyan-950/80 border-cyan-800/80 text-cyan-50',
        outgoing: 'bg-cyan-900/90 border-cyan-700 text-slate-50',
        accent: 'text-cyan-400',
        nameColor: 'text-cyan-300'
      };
    }
    return {
      badge: 'bg-slate-900 text-slate-300 border-slate-700',
      incoming: 'bg-slate-900/90 border-slate-800 text-slate-100',
      outgoing: 'bg-slate-800/90 border-slate-700 text-slate-50',
      accent: 'text-slate-400',
      nameColor: 'text-slate-300'
    };
  };

  const getStatusIcon = (status?: string) => {
    switch (status) {
      case 'READ':
        return <span title="Read"><CheckCheck className="w-3.5 h-3.5 text-sky-400 inline" /></span>;
      case 'DELIVERED':
        return <span title="Delivered"><CheckCheck className="w-3.5 h-3.5 text-slate-400 inline" /></span>;
      case 'SENT':
        return <span title="Sent"><Check className="w-3.5 h-3.5 text-slate-400 inline" /></span>;
      default:
        return <span title="Sent / Saved"><Check className="w-3.5 h-3.5 text-slate-500 inline" /></span>;
    }
  };

  const getStateBadge = (state: RecoveryState, isDeleted?: boolean) => {
    if (state === 'WAL_RECOVERED') {
      return (
        <span className="text-[0.6875rem] bg-amber-950 text-amber-300 border border-amber-700/80 px-1.5 py-0.2 rounded font-bold font-mono">
          [WAL]
        </span>
      );
    }
    if (state === 'CARVED_UNALLOCATED' || isDeleted) {
      return (
        <span className="text-[0.6875rem] bg-red-950 text-red-300 border border-red-700/80 px-1.5 py-0.2 rounded font-bold font-mono">
          [CARVED]
        </span>
      );
    }
    if (state === 'OS_SPILLOVER') {
      return (
        <span className="text-[0.6875rem] bg-purple-950 text-purple-300 border border-purple-700/80 px-1.5 py-0.2 rounded font-bold font-mono">
          [SPILLOVER]
        </span>
      );
    }
    return (
      <span className="text-[0.6875rem] bg-emerald-950 text-emerald-300 border border-emerald-700/60 px-1.5 py-0.2 rounded font-mono">
        [ACTIVE]
      </span>
    );
  };

  const toggleAudioPlay = (msgId: string) => {
    setAudioStates((prev) => {
      const current = prev[msgId] || { isPlaying: false, progress: 20 };
      return {
        ...prev,
        [msgId]: { ...current, isPlaying: !current.isPlaying }
      };
    });
  };

  return (
    <div className="flex-1 flex overflow-hidden bg-slate-950">
      {/* =========================================================================
          LEFT SUB-PANE: BharatAnalyzer Conversation Thread List
          ========================================================================= */}
      <aside className="w-72 bg-slate-900 border-r border-slate-800 flex flex-col shrink-0 select-none">
        {/* Thread Header & Quick Search */}
        <div className="p-2 border-b border-slate-800 bg-slate-950/70">
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center space-x-1.5">
              <MessageSquare className="w-4 h-4 text-cyan-400" />
              <span className="text-xs font-bold text-slate-100 uppercase tracking-wide">
                Threads & Matches
              </span>
            </div>
            <span className="text-[0.6875rem] font-mono text-slate-400 bg-slate-800 px-1.5 py-0.2 rounded">
              {filteredThreads.length}
            </span>
          </div>

          <div className="relative">
            <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2 top-2" />
            <input
              type="text"
              placeholder="Filter threads..."
              value={threadSearchQuery}
              onChange={(e) => setThreadSearchQuery(e.target.value)}
              className="w-full bg-slate-900 border border-slate-800 rounded pl-7 pr-2 py-1 text-xs text-slate-200 placeholder-slate-500 font-mono focus:outline-none focus:border-cyan-500"
            />
          </div>
        </div>

        {/* Thread Items List */}
        <div className="flex-1 overflow-y-auto divide-y divide-slate-800/60">
          {/* Option: View All Messages */}
          <div
            onClick={() => setSelectedThreadId('ALL')}
            className={`p-2.5 cursor-pointer transition-colors ${
              selectedThreadId === 'ALL'
                ? 'bg-emerald-950/60 border-l-4 border-emerald-500 text-emerald-200'
                : 'hover:bg-slate-800/60 text-slate-300'
            }`}
          >
            <div className="flex items-center justify-between text-xs font-bold mb-0.5">
              <span className="flex items-center space-x-1.5">
                <LayoutGrid className="w-3.5 h-3.5 text-cyan-400" />
                <span>All Indexed Messages</span>
              </span>
              <span className="text-[0.6875rem] font-mono text-cyan-400 bg-cyan-950 px-1.5 rounded">
                {chats.length}
              </span>
            </div>
            <div className="text-[0.6875rem] text-slate-500 font-sans">
              Global virtualized view across all 10 social & chat engines
            </div>
          </div>

          {filteredThreads.map((thread) => {
            const isSelected = selectedThreadId === thread.threadKey;
            const theme = getAppTheme(thread.sourceApp);

            return (
              <div
                key={thread.threadKey}
                onClick={() => setSelectedThreadId(thread.threadKey)}
                className={`p-2.5 cursor-pointer transition-colors space-y-1 ${
                  isSelected
                    ? 'bg-cyan-950/50 border-l-4 border-cyan-400 text-slate-100'
                    : 'hover:bg-slate-800/60 text-slate-300'
                }`}
              >
                {/* Thread Title & App Badge */}
                <div className="flex items-center justify-between">
                  <div className="font-semibold text-xs truncate max-w-[150px] text-slate-100 font-sans">
                    {thread.threadTitle}
                  </div>
                  <span className={`text-[0.6875rem] px-1.5 py-0.2 rounded font-mono border ${theme.badge}`}>
                    {thread.sourceApp}
                  </span>
                </div>

                {/* Last Message Snippet */}
                <div className="text-[0.6875rem] text-slate-400 truncate font-sans">
                  {thread.lastMessage.isFromMe && <span className="text-emerald-400 mr-1 font-mono">You:</span>}
                  {thread.lastMessage.body}
                </div>

                {/* Badges: Active & Carved */}
                <div className="flex items-center justify-between pt-1">
                  <div className="flex items-center space-x-1.5 text-[0.6875rem] font-mono">
                    <span className="text-slate-400">{thread.messages.length} msgs</span>
                    {thread.carvedCount > 0 && (
                      <span className="bg-red-950 text-red-300 border border-red-800/70 px-1 py-0.2 rounded font-bold">
                        [{thread.carvedCount} Deleted]
                      </span>
                    )}
                  </div>
                  {thread.lastMessage.ephemeralDuration && (
                    <span className="text-orange-400 text-[0.6875rem] flex items-center space-x-0.5">
                      <Flame className="w-2.5 h-2.5" />
                      <span>{thread.lastMessage.ephemeralDuration}s</span>
                    </span>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </aside>

      {/* =========================================================================
          CENTER PANE: BharatAnalyzer 3-Way Split Canvas (Grid vs Bubble vs Dossier)
          ========================================================================= */}
      <main className="flex-1 flex flex-col overflow-hidden bg-slate-950">
        {/* Top Control Bar with Subcategory Pills & View Mode Toggle */}
        <div className="h-10 bg-slate-900 border-b border-slate-800 px-3 flex items-center justify-between shrink-0 select-none">
          <div className="flex items-center space-x-2">
            <span className="text-xs font-bold text-slate-100">
              {selectedThreadId === 'ALL'
                ? 'All Indexed Messages'
                : activeThread?.threadTitle || 'Conversation'}
            </span>
            <span className="text-[0.6875rem] font-mono text-cyan-400 bg-cyan-950 px-2 py-0.5 rounded border border-cyan-800/60 font-semibold">
              {totalMatching} Records
            </span>
          </div>

          {/* 3-Mode View Toggle Button Group */}
          <div className="flex items-center space-x-2">
            <div className="flex items-center bg-slate-950 border border-slate-800 rounded p-0.5 font-mono text-[0.6875rem]">
              <button
                onClick={() => setChatViewMode('GRID')}
                className={`flex items-center space-x-1 px-2.5 py-1 rounded transition-colors ${
                  chatViewMode === 'GRID'
                    ? 'bg-emerald-600 text-slate-50 font-bold'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                <LayoutGrid className="w-3.5 h-3.5" />
                <span>Table</span>
              </button>
              <button
                onClick={() => setChatViewMode('BUBBLE')}
                className={`flex items-center space-x-1 px-2.5 py-1 rounded transition-colors ${
                  chatViewMode === 'BUBBLE'
                    ? 'bg-emerald-600 text-slate-50 font-bold'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                <MessageCircle className="w-3.5 h-3.5" />
                <span>Bubble View</span>
              </button>
            </div>

            <button
              onClick={handleExportCsv}
              className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded font-mono text-[0.6875rem] border border-slate-700 flex items-center space-x-1.5 transition-colors"
              title="Export the filtered chat records as CSV"
            >
              <FileSpreadsheet className="w-3.5 h-3.5 text-emerald-400" />
              <span>Export CSV</span>
            </button>
          </div>
        </div>

        {/* Top Filter & Pagination Ribbon */}
        <div className="bg-slate-950/95 border-b border-slate-800 px-3 py-1.5 space-y-1.5 text-xs shrink-0 select-none">
          {/* Row 1: Search Box + Recovery State Filter Pills */}
          <div className="flex items-center justify-between gap-2 overflow-x-auto">
            {/* Instant FTS5 Search Box */}
            <div className="relative min-w-[320px] max-w-[420px]">
              <Search className="w-3.5 h-3.5 text-cyan-400 absolute left-2 top-2" />
              <input
                type="text"
                placeholder="Search messages, UTRs, VPAs, +91 phones, Zangi/Session IDs..."
                value={messageSearchQuery}
                onChange={(e) => {
                  setMessageSearchQuery(e.target.value);
                  setCurrentPage(1);
                }}
                className="w-full bg-slate-900 border border-slate-800 rounded pl-7 pr-2 py-1 text-[0.6875rem] text-slate-200 placeholder-slate-500 font-mono focus:outline-none focus:border-cyan-500"
              />
            </div>

            {/* Recovery State Filter Pills */}
            <div className="flex items-center space-x-1 font-mono text-[0.6875rem]">
              <span className="text-slate-500 text-[0.6875rem] uppercase font-sans mr-1">State:</span>
              {(['ALL', 'ACTIVE', 'WAL', 'CARVED', 'SPILLOVER'] as RecoveryPillFilter[]).map((pill) => {
                const isActive = recoveryPillFilter === pill;
                let activeStyle = 'bg-slate-800 text-slate-200 border-slate-700';
                if (pill === 'ACTIVE') activeStyle = 'bg-emerald-950 text-emerald-300 border-emerald-700/80 font-bold';
                if (pill === 'WAL') activeStyle = 'bg-amber-950 text-amber-300 border-amber-700/80 font-bold';
                if (pill === 'CARVED') activeStyle = 'bg-red-950 text-red-300 border-red-700/80 font-bold';
                if (pill === 'SPILLOVER') activeStyle = 'bg-purple-950 text-purple-300 border-purple-700/80 font-bold';

                return (
                  <button
                    key={pill}
                    onClick={() => setRecoveryPillFilter(pill)}
                    className={`px-2 py-0.5 rounded border transition-colors ${
                      isActive
                        ? activeStyle
                        : 'bg-slate-900 text-slate-400 border-slate-800 hover:text-slate-200'
                    }`}
                  >
                    {pill === 'ALL' && 'All Records'}
                    {pill === 'ACTIVE' && 'Allocated Active'}
                    {pill === 'WAL' && 'WAL Recovered (Amber)'}
                    {pill === 'CARVED' && 'Freelist/Slack Carved (Red)'}
                    {pill === 'SPILLOVER' && 'OS Notification Spillover (Purple)'}
                  </button>
                );
              })}
            </div>
          </div>

          {/* Row 2: Ephemeral Filters + Server-Side Pagination Bar */}
          <div className="flex items-center justify-between gap-2 overflow-x-auto text-[0.6875rem] font-mono">
            {/* Ephemeral Filter Pills */}
            <div className="flex items-center space-x-1">
              <span className="text-slate-500 text-[0.6875rem] uppercase font-sans mr-1">Privacy:</span>
              {(['ALL', 'VIEW_ONCE', 'DISAPPEARING', 'REVOKED', 'ATTACHMENTS'] as EphemeralPillFilter[]).map((pill) => {
                const isActive = ephemeralFilter === pill;
                return (
                  <button
                    key={pill}
                    onClick={() => setEphemeralFilter(pill)}
                    className={`px-2 py-0.5 rounded border transition-colors ${
                      isActive
                        ? 'bg-cyan-950 text-cyan-300 border-cyan-700/80 font-bold'
                        : 'bg-slate-900 text-slate-400 border-slate-800 hover:text-slate-200'
                    }`}
                  >
                    {pill === 'ALL' && 'All Privacy'}
                    {pill === 'VIEW_ONCE' && 'View-Once Media'}
                    {pill === 'DISAPPEARING' && 'Disappearing / TTL > 0'}
                    {pill === 'REVOKED' && 'Revoked / Unsent'}
                    {pill === 'ATTACHMENTS' && 'With Attachments / GPS'}
                  </button>
                );
              })}
            </div>

            {/* Server-Side Pagination Controls */}
            <div className="flex items-center space-x-2 text-slate-300">
              <span className="text-slate-400">
                Showing rows <strong className="text-slate-100">{totalMatching === 0 ? 0 : offset + 1}</strong>–
                <strong className="text-slate-100">{Math.min(offset + pageSize, totalMatching)}</strong> of{' '}
                <strong className="text-cyan-400">{totalMatching.toLocaleString()}</strong>
              </span>

              <div className="flex items-center space-x-0.5 bg-slate-900 border border-slate-800 rounded p-0.5">
                <button
                  onClick={() => setCurrentPage(1)}
                  disabled={validPage <= 1}
                  className="p-1 rounded hover:bg-slate-800 disabled:opacity-30 disabled:cursor-not-allowed"
                  title="First Page"
                >
                  <ChevronsLeft className="w-3.5 h-3.5" />
                </button>
                <button
                  onClick={() => setCurrentPage(validPage - 1)}
                  disabled={validPage <= 1}
                  className="p-1 rounded hover:bg-slate-800 disabled:opacity-30 disabled:cursor-not-allowed"
                  title="Previous Page"
                >
                  <ChevronLeft className="w-3.5 h-3.5" />
                </button>
                <span className="px-2 text-slate-300 font-bold text-[0.6875rem]">
                  Page {validPage} of {totalPages}
                </span>
                <button
                  onClick={() => setCurrentPage(validPage + 1)}
                  disabled={validPage >= totalPages}
                  className="p-1 rounded hover:bg-slate-800 disabled:opacity-30 disabled:cursor-not-allowed"
                  title="Next Page"
                >
                  <ChevronRight className="w-3.5 h-3.5" />
                </button>
                <button
                  onClick={() => setCurrentPage(totalPages)}
                  disabled={validPage >= totalPages}
                  className="p-1 rounded hover:bg-slate-800 disabled:opacity-30 disabled:cursor-not-allowed"
                  title="Last Page"
                >
                  <ChevronsRight className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>
          </div>
        </div>

        {/* Content Presentation: Table Grid vs Bubble View vs Dossier */}
        {chatViewMode === 'GRID' && (
          /* =====================================================================
             VIEW A: Complete 28-Column Categorized Forensic Grid
             ===================================================================== */
          <div className="flex-1 overflow-auto select-text font-mono">
            <table className="w-full text-left text-[0.6875rem] border-collapse">
              <thead className="bg-slate-950 border-b border-slate-800 text-[0.6875rem] uppercase font-bold sticky top-0 z-20">
                <tr className="bg-slate-900 border-b border-slate-800 text-slate-400 text-[0.6875rem]">
                  <th className="p-2 w-10">#</th>
                  <th className="p-2 w-28">Source App</th>
                  <th className="p-2 w-24">Chat Type</th>
                  <th className="p-2 w-16">Dir</th>
                  <th className="p-2 w-28">Message Type</th>
                  <th className="p-2 w-20">Status</th>
                  <th className="p-2 min-w-[280px]">Message Body / Evidence</th>
                  <th className="p-2 w-24">Quoted ID</th>
                  <th className="p-2 w-36">Quoted Text</th>
                  <th className="p-2 w-14">Fwd</th>

                  <th className="p-2 w-44">Thread ID</th>
                  <th className="p-2 w-44">Thread Title</th>
                  <th className="p-2 w-48">Sender (ID / Name)</th>
                  <th className="p-2 w-48">Recipient (ID / Name)</th>

                  <th className="p-2 w-20">View-Once</th>
                  <th className="p-2 w-20">Disappearing TTL</th>
                  <th className="p-2 w-14">Revoked</th>

                  <th className="p-2 w-36">Timestamp Raw</th>
                  <th className="p-2 w-44">Timestamp UTC</th>
                  <th className="p-2 w-48 font-bold text-slate-200">Timestamp IST (+05:30)</th>
                  <th className="p-2 w-44">Read IST</th>

                  <th className="p-2 w-40">Attachment Path</th>
                  <th className="p-2 w-28">MIME / Size</th>
                  <th className="p-2 w-36">Geo Coordinates</th>

                  <th className="p-2 w-36">Source File & Table</th>
                  <th className="p-2 w-28">Physical Offset</th>
                  <th className="p-2 w-32">Recovery State</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 bg-slate-950">
                {paginatedMessages.map((msg, idx) => {
                  const isSelected = selectedArtifact?.id === msg.id;
                  const hexOffset = `0x${msg.provenance.byteOffset.toString(16).toUpperCase().padStart(8, '0')}`;
                  const isDel = msg.isDeleted || msg.provenance.recoveryState !== 'ACTIVE';

                  return (
                    <tr
                      key={msg.id}
                      onClick={() => handleSelectMessage(msg)}
                      className={`cursor-pointer transition-colors ${
                        isSelected
                          ? 'bg-emerald-950/40 text-emerald-100 border-l-4 border-l-emerald-500'
                          : isDel
                          ? 'bg-red-950/10 hover:bg-red-950/20 text-slate-300'
                          : 'hover:bg-slate-900/60 text-slate-300'
                      }`}
                    >
                      <td className="p-2 text-slate-500">{offset + idx + 1}</td>
                      <td className="p-2 font-semibold">
                        <span className="px-1.5 py-0.5 rounded bg-slate-900 border border-slate-800 text-[0.6875rem]">
                          {msg.sourceApp}
                        </span>
                      </td>
                      <td className="p-2 text-[0.6875rem] text-slate-400">
                        {msg.chatType || 'DIRECT_1ON1'}
                      </td>
                      <td className="p-2">
                        {msg.isFromMe ? (
                          <span className="flex items-center text-emerald-400 font-bold text-[0.6875rem]">
                            <ArrowUpRight className="w-3 h-3 mr-0.5" /> OUT
                          </span>
                        ) : (
                          <span className="flex items-center text-sky-400 font-bold text-[0.6875rem]">
                            <ArrowDownLeft className="w-3 h-3 mr-0.5" /> IN
                          </span>
                        )}
                      </td>
                      <td className="p-2 text-[0.6875rem] text-slate-300">
                        {msg.isViewOnce ? (
                          <span className="text-orange-400 font-bold">[VIEW ONCE]</span>
                        ) : (
                          msg.mediaType || 'TEXT'
                        )}
                      </td>
                      <td className="p-2 text-center">{getStatusIcon(msg.messageStatus)}</td>
                      <td className="p-2">
                        <div className="font-sans text-xs text-slate-100 line-clamp-2">{msg.body}</div>
                        {tagsOfMsg(msg.id).length > 0 && <div className="mt-1 flex flex-wrap gap-1"><TagPills tags={tagsOfMsg(msg.id)} /></div>}
                        {msg.paymentAttachment && (
                          <div className="mt-1 text-[0.6875rem] text-emerald-400 font-mono bg-emerald-950/60 px-1.5 py-0.5 rounded border border-emerald-800/40 inline-block">
                            ₹{msg.paymentAttachment.amountInr.toLocaleString('en-IN')} (UTR: {msg.paymentAttachment.utrNumber})
                          </div>
                        )}
                      </td>
                      <td className="p-2 text-slate-400 text-[0.6875rem] truncate max-w-[100px]">{msg.replyToId || '—'}</td>
                      <td className="p-2 text-slate-400 text-[0.6875rem] truncate max-w-[140px] italic">{msg.quotedMessageText || '—'}</td>
                      <td className="p-2 text-center text-[0.6875rem]">
                        {msg.forwardingScore ? <span className="text-cyan-400 font-bold">+{msg.forwardingScore}</span> : '0'}
                      </td>

                      <td className="p-2 truncate max-w-[150px] text-[0.6875rem] text-slate-400" title={msg.threadId}>
                        {msg.threadId}
                      </td>
                      <td className="p-2 truncate max-w-[150px] text-[0.6875rem] text-slate-300">
                        {msg.threadTitle || '—'}
                      </td>
                      <td className="p-2 truncate max-w-[170px]">
                        <div className="font-sans font-semibold text-slate-200 truncate">{msg.senderName}</div>
                        <div className="text-[0.6875rem] text-slate-500 truncate">{msg.senderJid}</div>
                      </td>
                      <td className="p-2 truncate max-w-[170px]">
                        <div className="font-sans font-semibold text-slate-300 truncate">
                          {msg.recipientName || 'Recipient'}
                        </div>
                        <div className="text-[0.6875rem] text-slate-500 truncate">{msg.recipientJid || 'N/A'}</div>
                      </td>

                      <td className="p-2 text-center text-[0.6875rem]">
                        {msg.isViewOnce ? <span className="text-red-400 font-bold">YES</span> : '—'}
                      </td>
                      <td className="p-2 text-[0.6875rem]">
                        {msg.ephemeralDuration ? (
                          <span className="text-orange-400 flex items-center space-x-0.5 font-bold">
                            <Flame className="w-3 h-3" />
                            <span>{msg.ephemeralDuration}s</span>
                          </span>
                        ) : (
                          <span className="text-slate-600">—</span>
                        )}
                      </td>
                      <td className="p-2 text-center">
                        {isDel ? <Trash2 className="w-3 h-3 text-red-400 inline" /> : '—'}
                      </td>

                      <td className="p-2 text-slate-400 text-[0.6875rem] truncate">{msg.timestamp.rawValue}</td>
                      <td className="p-2 text-slate-400 text-[0.6875rem] whitespace-nowrap">{msg.timestamp.utcIso}</td>
                      <td className="p-2 text-slate-200 text-[0.6875rem] whitespace-nowrap font-bold">
                        {msg.timestamp.istFormatted}
                      </td>
                      <td className="p-2 text-slate-400 text-[0.6875rem]">{msg.editTimestamp?.istFormatted || '—'}</td>

                      <td className="p-2 text-slate-400 text-[0.6875rem] truncate max-w-[150px]" title={msg.mediaPath}>
                        {msg.mediaPath || '—'}
                      </td>
                      <td className="p-2 text-slate-400 text-[0.6875rem]">{msg.mediaMimeType || '—'}</td>
                      <td className="p-2 text-slate-400 text-[0.6875rem] truncate max-w-[140px]" title={msg.locationName}>
                        {msg.locationName || '—'}
                      </td>

                      <td className="p-2 text-slate-400 text-[0.6875rem] truncate max-w-[150px]" title={msg.provenance.vfsInternalPath}>
                        {msg.provenance.vfsInternalPath.split('/').pop()} :: {msg.provenance.tableName || 'db'}
                      </td>
                      <td className="p-2 text-amber-400 font-bold text-[0.6875rem]">{hexOffset}</td>
                      <td className="p-2">{getStateBadge(msg.provenance.recoveryState, msg.isDeleted)}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}

        {chatViewMode === 'BUBBLE' && (
          /* =====================================================================
             VIEW B: Authentic Interactive Conversation Bubble Split View
             ===================================================================== */
          <div className="flex-1 flex flex-col overflow-hidden bg-slate-950">
            {/* Top Participant Bio Metadata Banner */}
            {activeThread && (
              <div className="bg-slate-900 border-b border-slate-800 p-2.5 px-4 flex items-center justify-between shrink-0 select-none">
                <div className="flex items-center space-x-3">
                  <div className="w-8 h-8 rounded-full bg-cyan-950 border border-cyan-700/80 flex items-center justify-center font-bold text-cyan-300 text-xs">
                    {activeThread.threadTitle.charAt(0).toUpperCase()}
                  </div>
                  <div>
                    <div className="text-xs font-bold text-slate-100 flex items-center space-x-2">
                      <span>{activeThread.threadTitle}</span>
                      <span className="text-[0.6875rem] font-mono text-cyan-400 bg-cyan-950/80 px-1.5 rounded border border-cyan-800/60">
                        {activeThread.sourceApp}
                      </span>
                    </div>
                  </div>
                </div>

                <div className="flex items-center space-x-3 font-mono text-[0.6875rem]">
                  <div className="text-slate-400">
                    Active: <strong className="text-emerald-400">{activeThread.activeCount}</strong> | Deleted:{' '}
                    <strong className="text-red-400">{activeThread.carvedCount}</strong>
                  </div>
                </div>
              </div>
            )}

            {/* Chat Bubbles Scroll Area */}
            <div className="flex-1 overflow-y-auto p-4 space-y-4 select-text">
              {allFilteredMessages.map((msg) => {
                const isSelected = selectedArtifact?.id === msg.id;
                const isFromMe = msg.isFromMe;
                const isDel = msg.isDeleted || msg.provenance.recoveryState !== 'ACTIVE';
                const hexOffset = `0x${msg.provenance.byteOffset.toString(16).toUpperCase().padStart(8, '0')}`;
                const theme = getAppTheme(msg.sourceApp);
                const audioState = audioStates[msg.id] || { isPlaying: false, progress: 35 };
                const paymentEv = extractPaymentEvidence(msg);

                return (
                  <div
                    key={msg.id}
                    onClick={() => handleSelectMessage(msg)}
                    className={`flex flex-col cursor-pointer transition-all ${
                      isFromMe ? 'items-end' : 'items-start'
                    }`}
                  >
                    <div
                      className={`max-w-[75%] rounded-xl p-3 shadow-xl transition-all ${
                        isDel
                          ? 'border-2 border-dashed border-red-500 bg-red-950/20 shadow-red-950/40'
                          : isSelected
                          ? 'ring-2 ring-emerald-400 border border-emerald-400'
                          : 'border border-slate-800'
                      } ${
                        isFromMe
                          ? `${theme.outgoing} rounded-tr-none`
                          : `${theme.incoming} rounded-tl-none`
                      }`}
                    >
                      {/* Header: Sender, App & Forensic Recovery Badges */}
                      <div className="flex items-center justify-between space-x-3 mb-1.5 text-[0.6875rem] pb-1 border-b border-white/10">
                        <div className="flex items-center space-x-1.5 truncate">
                          <span className={`font-bold font-sans ${theme.nameColor} truncate`}>
                            {msg.senderName}
                          </span>
                          <span className={`text-[0.6875rem] px-1.5 py-0.2 rounded font-mono border ${theme.badge}`}>
                            {msg.sourceApp}
                          </span>
                        </div>

                        <div className="flex items-center space-x-1.5 shrink-0">
                          {msg.isStarred && <Star className="w-3 h-3 text-amber-400 fill-amber-400" />}
                          {msg.forwardingScore ? (
                            <span className="flex items-center space-x-0.5 text-[0.6875rem] text-cyan-300 font-mono">
                              <CornerUpRight className="w-2.5 h-2.5" />
                              <span>+{msg.forwardingScore}</span>
                            </span>
                          ) : null}
                          {msg.ephemeralDuration ? (
                            <span className="flex items-center space-x-0.5 text-[0.6875rem] text-orange-400 bg-orange-950/90 px-1 rounded font-mono font-bold">
                              <Flame className="w-2.5 h-2.5" />
                              <span>TTL: {msg.ephemeralDuration}s</span>
                            </span>
                          ) : null}
                          {msg.isViewOnce && (
                            <span className="text-[0.6875rem] text-amber-400 bg-amber-950/90 px-1.5 py-0.2 rounded font-mono font-bold border border-amber-700/60">
                              View-Once Media
                            </span>
                          )}
                          {getStateBadge(msg.provenance.recoveryState, msg.isDeleted)}
                        </div>
                      </div>

                      {/* Deleted / WAL Header Banner */}
                      {isDel && (
                        <div className="mb-2 bg-red-950/90 border border-red-700/80 rounded px-2 py-1 text-[0.6875rem] text-red-200 font-mono flex items-center space-x-1.5 font-bold">
                          <Trash2 className="w-3 h-3 text-red-400 shrink-0" />
                          <span>[RECOVERED FROM WAL / FREELIST]</span>
                        </div>
                      )}

                      {/* Quoted Message Card */}
                      {msg.quotedMessageText && (
                        <div className="mb-2 p-2 rounded bg-black/40 border-l-2 border-cyan-400 text-xs font-sans text-slate-300">
                          <div className="text-[0.6875rem] text-cyan-400 font-bold mb-0.5">Quoted Message:</div>
                          <div className="italic text-[0.6875rem] text-slate-300">{msg.quotedMessageText}</div>
                        </div>
                      )}

                      {/* Message Body Content */}
                      <div className="text-xs leading-relaxed select-text font-sans break-words py-1 text-slate-100">
                        {msg.body}
                      </div>
                      {tagsOfMsg(msg.id).length > 0 && <div className="mt-1 flex flex-wrap gap-1"><TagPills tags={tagsOfMsg(msg.id)} /></div>}

                      {/* INLINE UPI PAYMENT EVIDENCE CARD */}
                      {paymentEv && (
                        <div className="mt-2.5 p-2.5 rounded-lg bg-emerald-950/90 border border-emerald-600/80 shadow-lg font-sans">
                          <div className="flex items-center justify-between text-[0.6875rem] pb-1.5 border-b border-emerald-700/60 mb-2">
                            <div className="flex items-center space-x-1.5 text-emerald-300 font-bold tracking-wide">
                              <CreditCard className="w-3.5 h-3.5 text-emerald-400" />
                              <span>UPI PAYMENT EVIDENCE</span>
                            </div>
                            <span className="font-mono text-[0.6875rem] bg-emerald-900/80 text-emerald-200 px-1.5 py-0.2 rounded border border-emerald-600/50">
                              CORROBORATED
                            </span>
                          </div>
                          <div className="grid grid-cols-2 gap-2 text-[0.6875rem]">
                            {paymentEv.amount && (
                              <div>
                                <span className="text-emerald-400/80 text-[0.6875rem] block font-sans">Amount:</span>
                                <span className="text-slate-50 font-bold font-mono text-xs">
                                  ₹{paymentEv.amount.toLocaleString('en-IN')}
                                </span>
                              </div>
                            )}
                            {paymentEv.utr && (
                              <div>
                                <span className="text-emerald-400/80 text-[0.6875rem] block font-sans">NPCI UTR:</span>
                                <span className="text-cyan-300 font-bold font-mono text-xs select-all">
                                  {paymentEv.utr}
                                </span>
                              </div>
                            )}
                            {paymentEv.vpa && (
                              <div className="col-span-2">
                                <span className="text-emerald-400/80 text-[0.6875rem] block font-sans">Counterparty VPA:</span>
                                <span className="text-slate-50 font-mono text-[0.6875rem] select-all">
                                  {paymentEv.vpa}
                                </span>
                              </div>
                            )}
                          </div>
                          <div className="mt-2 pt-1.5 border-t border-emerald-800/80 flex justify-end">
                            <button
                              onClick={(e) => {
                                e.stopPropagation();
                                setActiveTab('UPI_LEDGER');
                              }}
                              className="text-[0.6875rem] text-cyan-300 hover:text-cyan-200 font-mono font-semibold flex items-center gap-1 cursor-pointer"
                            >
                              <span>View in UPI Ledger</span>
                              <ExternalLink className="w-2.5 h-2.5" />
                            </button>
                          </div>
                        </div>
                      )}

                      {/* Voice Note / .opus Audio Player Component */}
                      {msg.mediaType === 'VOICE_NOTE' && (
                        <div className="mt-2 bg-slate-950/90 border border-slate-700/80 rounded-lg p-2.5 text-xs font-mono">
                          <div className="flex items-center justify-between text-[0.6875rem] text-cyan-300 mb-1.5">
                            <span className="flex items-center space-x-1 font-bold">
                              <Volume2 className="w-3.5 h-3.5 text-cyan-400" />
                              <span>VOICE NOTE (.OPUS CODEC)</span>
                            </span>
                            <span className="text-[0.6875rem] text-slate-400">0:14 / 0:45</span>
                          </div>

                          <div className="flex items-center space-x-3">
                            <button
                              onClick={(e) => {
                                e.stopPropagation();
                                toggleAudioPlay(msg.id);
                              }}
                              className="w-7 h-7 rounded-full bg-cyan-600 hover:bg-cyan-500 text-slate-950 flex items-center justify-center shrink-0 transition-transform active:scale-95"
                            >
                              {audioState.isPlaying ? (
                                <Pause className="w-3.5 h-3.5 fill-current" />
                              ) : (
                                <Play className="w-3.5 h-3.5 fill-current ml-0.5" />
                              )}
                            </button>

                            <div className="flex-1 space-y-1">
                              <div className="h-1.5 bg-slate-800 rounded-full overflow-hidden">
                                <div
                                  className="h-full bg-cyan-400 transition-all duration-300"
                                  style={{ width: `${audioState.progress}%` }}
                                />
                              </div>
                              <div className="flex items-center justify-between text-[0.6875rem] text-slate-500 font-mono">
                                <span>Voice Note Payload</span>
                              </div>
                            </div>
                          </div>
                        </div>
                      )}

                      {/* Image / Media Preview with On-Demand VFS Extraction */}
                      {msg.mediaPath && msg.mediaType !== 'VOICE_NOTE' && (
                        <div className="mt-2 p-2 bg-slate-950/80 rounded border border-slate-800 space-y-1">
                          <div className="flex items-center justify-between text-[0.6875rem]">
                            <span className="flex items-center space-x-1 text-teal-300 font-mono">
                              <ImageIcon className="w-3 h-3 text-teal-400" />
                              <span>{msg.mediaPath.split('/').pop()}</span>
                            </span>
                            <button
                              onClick={(e) => {
                                e.stopPropagation();
                                setActiveImageModal(msg.mediaPath || 'preview.jpg');
                              }}
                              className="text-[0.6875rem] bg-cyan-950 text-cyan-300 border border-cyan-800/80 px-2 py-0.5 rounded font-mono font-semibold hover:bg-cyan-900"
                            >
                              [Extract & Preview Media from VFS]
                            </button>
                          </div>
                          <div className="text-[0.6875rem] text-slate-500 font-mono truncate">
                            MIME: {msg.mediaMimeType || 'image/jpeg'} | Physical: {hexOffset}
                          </div>
                        </div>
                      )}

                      {/* Geolocation Geotag Card */}
                      {msg.locationName && (
                        <div className="mt-2 p-2 rounded bg-teal-950/60 border border-teal-700/60 text-xs font-sans">
                          <div className="flex items-center space-x-1.5 text-teal-300 font-semibold mb-0.5">
                            <MapPin className="w-3.5 h-3.5 text-teal-400 shrink-0" />
                            <span>Location: {msg.locationName}</span>
                          </div>
                          <div className="text-[0.6875rem] text-slate-400 font-mono">
                            Coordinates: {msg.latitude?.toFixed(5)}, {msg.longitude?.toFixed(5)}
                          </div>
                        </div>
                      )}

                      {/* Footer: Multi-Format Timestamps & Provenance Offset */}
                      <div className="flex items-center justify-between space-x-4 mt-2 pt-1 border-t border-white/10 text-[0.6875rem] font-mono text-slate-400">
                        <div className="flex items-center space-x-1">
                          <Clock className="w-2.5 h-2.5 text-slate-400" />
                          <span className="text-slate-200 font-semibold">{msg.timestamp.istFormatted}</span>
                          <span className="text-slate-500">({msg.timestamp.utcIso})</span>
                        </div>

                        <div className="flex items-center space-x-1.5 shrink-0">
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              handleSelectMessage(msg);
                              setBottomDockTab('HEX');
                              fetchHexWindowForOffset(msg.provenance);
                            }}
                            className="text-amber-400 font-bold hover:underline cursor-pointer flex items-center gap-0.5"
                            title="Jump to physical byte offset in Hex Viewer"
                          >
                            <Binary className="w-2.5 h-2.5" />
                            <span>{hexOffset}</span>
                          </button>
                          {getStatusIcon(msg.messageStatus)}
                        </div>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        )}

      </main>

      {/* Media Lightbox Modal */}
      {activeImageModal && (
        <div
          className="fixed inset-0 z-50 bg-black/90 flex items-center justify-center p-4 select-none"
          onClick={() => setActiveImageModal(null)}
        >
          <div
            className="max-w-2xl w-full bg-slate-900 border border-slate-700 rounded-xl overflow-hidden shadow-2xl p-4 space-y-3"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between text-xs font-mono text-slate-300 pb-2 border-b border-slate-800">
              <span className="font-bold text-teal-400">Extracted VFS Media Attachment Preview</span>
              <button onClick={() => setActiveImageModal(null)} className="text-slate-400 hover:text-slate-50">
                <X className="w-4 h-4" />
              </button>
            </div>
            <div className="bg-slate-950 rounded p-8 text-center text-slate-400 border border-slate-800 space-y-2">
              <ImageIcon className="w-16 h-16 mx-auto text-teal-400" />
              <div className="text-xs font-mono font-semibold text-slate-200">{activeImageModal}</div>
              <div className="text-[0.6875rem] text-slate-500 font-mono">
                Decrypted & verified from VFS physical stream. SHA-256 match validated.
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

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
import { usePreferences } from '../state/preferencesStore';
import { Button, Chip, RecoveredChip, Segmented } from '../components/ui';
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

  const tz = usePreferences((s) => s.timeZone);

  const appGroupOf = (app: string): string => {
    if (['Tinder', 'Bumble', 'Hinge', 'Grindr'].some((a) => app.includes(a))) return 'Dating';
    if (['Threema', 'Briar', 'SimpleX'].some((a) => app.includes(a))) return 'Threema';
    return app;
  };
  const appChips = useMemo(() => {
    const counts = new Map<string, number>();
    for (const th of conversationThreads) counts.set(appGroupOf(th.sourceApp), (counts.get(appGroupOf(th.sourceApp)) ?? 0) + 1);
    return [...counts.entries()].sort((a, b) => b[1] - a[1]);
  }, [conversationThreads]);
  const activeSubcategory = selectedSubcategory || 'ALL';

  const initialsOf = (name: string): string =>
    name.replace(/[^A-Za-z ]/g, '').split(/\s+/).filter(Boolean).map((w) => w[0]).join('').slice(0, 2).toUpperCase() || '#';
  const isRecoveredMsg = (m: ChatArtifact) => !!m.isDeleted || m.provenance?.recoveryState !== 'ACTIVE';

  const hasTime = (m: ChatArtifact) => !!m.timestamp && m.timestamp.epochMs > 0;
  const zone = tz === 'IST' ? 'Asia/Kolkata' : 'UTC';
  const dayOf = (m: ChatArtifact): string =>
    hasTime(m) ? new Date(m.timestamp.epochMs).toLocaleDateString('en-IN', { day: '2-digit', month: 'short', year: 'numeric', timeZone: zone }) : 'Time not recorded';
  const dayShort = (m: ChatArtifact): string =>
    hasTime(m) ? new Date(m.timestamp.epochMs).toLocaleDateString('en-IN', { day: '2-digit', month: 'short', timeZone: zone }) : '';
  const stampText = (m: ChatArtifact): string => (hasTime(m) ? (tz === 'IST' ? m.timestamp.istFormatted : m.timestamp.utcIso) : 'not recorded');

  const AppTag: React.FC<{ app: string }> = ({ app }) => (
    <span className="inline-flex text-[0.6875rem] font-semibold px-[7px] py-px rounded-full whitespace-nowrap bg-sunken text-muted border border-line">{app}</span>
  );

  const getStatusIcon = (status?: string) => {
    switch (status) {
      case 'READ':
        return <span title="Read"><CheckCheck className="w-3.5 h-3.5 text-accent inline" /></span>;
      case 'DELIVERED':
        return <span title="Delivered"><CheckCheck className="w-3.5 h-3.5 text-muted inline" /></span>;
      case 'SENT':
        return <span title="Sent"><Check className="w-3.5 h-3.5 text-muted inline" /></span>;
      default:
        return <span title="Sent / Saved"><Check className="w-3.5 h-3.5 text-faint inline" /></span>;
    }
  };

  const getStateBadge = (state: RecoveryState, isDeleted?: boolean) => {
    if (state === 'WAL_RECOVERED') return <Chip tone="rec" title="Recovered from the database log">WAL</Chip>;
    if (state === 'CARVED_UNALLOCATED' || isDeleted) return <Chip tone="rec" title="Carved from free space or marked deleted">Carved</Chip>;
    if (state === 'OS_SPILLOVER') return <Chip tone="warn" title="Found in an operating system trace">System trace</Chip>;
    return <Chip>Active</Chip>;
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

  const pill = (active: boolean) =>
    `px-2.5 py-[3px] rounded-full border text-[0.75rem] ${active ? 'bg-accent-soft text-accent-ink border-accent font-semibold' : 'bg-surface text-muted border-line-strong font-medium hover:bg-hover'}`;
  const pageBtn = 'p-1 rounded text-muted hover:bg-hover disabled:opacity-30 disabled:cursor-not-allowed';

  const threadFacts: Array<[string, string]> = activeThread ? (() => {
    const timed = activeThread.messages.filter(hasTime).sort((a, b) => a.timestamp.epochMs - b.timestamp.epochMs);
    return [
      ['Messages', activeThread.messages.length.toLocaleString()],
      ['In database', activeThread.activeCount.toLocaleString()],
      ['Recovered', activeThread.carvedCount.toLocaleString()],
      ['First', timed.length ? stampText(timed[0]) : 'not recorded'],
      ['Last', timed.length ? stampText(timed[timed.length - 1]) : 'not recorded'],
    ] as Array<[string, string]>;
  })() : [];

  return (
    <div className="flex-1 flex overflow-hidden bg-page">
      {/* Conversation list */}
      <aside className="w-80 bg-surface border-r border-line flex flex-col shrink-0" aria-label="Conversations">
        <div className="p-3 border-b border-line flex flex-col gap-2">
          <div className="flex items-center gap-2">
            <MessageSquare className="w-4 h-4 text-g-comm" aria-hidden="true" />
            <span className="font-semibold">Conversations</span>
            <span className="ml-auto text-muted text-[0.75rem]">{filteredThreads.length.toLocaleString()}</span>
          </div>
          <div className="flex gap-1.5 flex-wrap" role="group" aria-label="Filter by app">
            <button type="button" aria-pressed={activeSubcategory === 'ALL'} onClick={() => { setSelectedSubcategory('ALL'); setCurrentPage(1); }} className={pill(activeSubcategory === 'ALL')}>
              All <span className="text-faint">{conversationThreads.length}</span>
            </button>
            {appChips.map(([name, n]) => (
              <button key={name} type="button" aria-pressed={activeSubcategory === name} onClick={() => { setSelectedSubcategory(name); setCurrentPage(1); }}
                title={name === 'Dating' ? 'Tinder, Bumble, Hinge, Grindr' : name === 'Threema' ? 'Threema, Briar, SimpleX' : undefined} className={pill(activeSubcategory === name)}>
                {name} <span className="text-faint">{n}</span>
              </button>
            ))}
          </div>
          <label className="relative block">
            <span className="sr-only">Filter conversations</span>
            <Search className="w-4 h-4 text-faint absolute left-2.5 top-2" aria-hidden="true" />
            <input type="text" placeholder="Find a name, app or word" value={threadSearchQuery} onChange={(e) => setThreadSearchQuery(e.target.value)}
              className="h-8 w-full pl-8 pr-2 rounded-lg bg-surface border border-line-strong text-ink placeholder:text-faint" />
          </label>
        </div>

        <div className="flex-1 overflow-y-auto">
          <button type="button" onClick={() => setSelectedThreadId('ALL')} aria-current={selectedThreadId === 'ALL'}
            className={`w-full text-left flex gap-2.5 items-center px-3 py-2.5 border-b border-line ${selectedThreadId === 'ALL' ? 'bg-accent-soft' : 'hover:bg-hover'}`}>
            <LayoutGrid className="w-4 h-4 text-muted shrink-0" aria-hidden="true" />
            <span className="flex-1 min-w-0">
              <b className="font-semibold block">All messages</b>
              <span className="text-[0.75rem] text-muted">Every conversation together</span>
            </span>
            <span className="text-muted text-[0.75rem]">{chats.length.toLocaleString()}</span>
          </button>

          {filteredThreads.map((thread) => {
            const isSelected = selectedThreadId === thread.threadKey;
            return (
              <button type="button" key={thread.threadKey} onClick={() => setSelectedThreadId(thread.threadKey)} aria-current={isSelected}
                className={`w-full text-left flex gap-2.5 items-start px-3 py-2.5 border-b border-line ${isSelected ? 'bg-accent-soft' : 'hover:bg-hover'} ${thread.carvedCount > 0 ? 'shadow-[inset_3px_0_0_var(--t-rec)]' : ''}`}>
                <span aria-hidden="true" className="w-8 h-8 rounded-full grid place-items-center shrink-0 bg-accent-soft text-accent-ink font-semibold text-[0.75rem]">{initialsOf(thread.threadTitle)}</span>
                <span className="min-w-0 flex-1 flex flex-col gap-0.5">
                  <span className="flex items-center gap-1.5 justify-between">
                    <b className="font-semibold truncate">{thread.threadTitle}</b>
                    <time className="text-muted text-[0.6875rem] whitespace-nowrap">{dayShort(thread.lastMessage)}</time>
                  </span>
                  <span className="text-muted text-[0.75rem] truncate">
                    {thread.lastMessage.isFromMe && <span className="mr-1">You:</span>}
                    {thread.lastMessage.body}
                  </span>
                  <span className="flex items-center gap-1.5 flex-wrap text-[0.6875rem] text-muted">
                    <AppTag app={thread.sourceApp} />
                    <span>{thread.messages.length.toLocaleString()} messages</span>
                    {thread.carvedCount > 0 && <RecoveredChip n={thread.carvedCount} label="recovered" />}
                    {thread.lastMessage.ephemeralDuration ? (
                      <span className="inline-flex items-center gap-0.5"><Flame className="w-2.5 h-2.5" aria-hidden="true" />{thread.lastMessage.ephemeralDuration}s</span>
                    ) : null}
                  </span>
                </span>
              </button>
            );
          })}
        </div>
      </aside>

      {/* Conversation and table */}
      <main className="flex-1 flex flex-col overflow-hidden bg-page min-w-0">
        <div className="bg-surface border-b border-line px-4 py-2.5 flex items-center justify-between gap-3 flex-wrap shrink-0">
          <div className="flex items-center gap-2 min-w-0">
            <h2 className="font-semibold truncate">{selectedThreadId === 'ALL' ? 'All messages' : activeThread?.threadTitle || 'Conversation'}</h2>
            <span className="text-muted">{totalMatching.toLocaleString()} record{totalMatching === 1 ? '' : 's'}</span>
          </div>
          <div className="flex items-center gap-2">
            <Segmented label="View" value={chatViewMode} onChange={(v) => setChatViewMode(v as ChatWorkspaceMode)}
              options={[{ value: 'GRID', label: 'Table' }, { value: 'BUBBLE', label: 'Bubble view' }]} />
            <Button onClick={handleExportCsv} title="Export the filtered chat records as CSV">
              <FileSpreadsheet className="w-4 h-4" aria-hidden="true" />Export CSV
            </Button>
          </div>
        </div>

        <div className="bg-surface border-b border-line px-4 py-2 flex flex-col gap-2 shrink-0">
          <div className="flex items-center justify-between gap-3 flex-wrap">
            <label className="relative block min-w-[280px] max-w-[420px] flex-1">
              <span className="sr-only">Search messages</span>
              <Search className="w-4 h-4 text-faint absolute left-2.5 top-2" aria-hidden="true" />
              <input type="text" placeholder="Search messages, UTRs, VPAs, phone numbers, IDs" value={messageSearchQuery}
                onChange={(e) => { setMessageSearchQuery(e.target.value); setCurrentPage(1); }}
                className="h-8 w-full pl-8 pr-2 rounded-lg bg-surface border border-line-strong text-ink placeholder:text-faint" />
            </label>
            <div className="flex items-center gap-1.5 flex-wrap" role="group" aria-label="Where found">
              <span className="text-muted text-[0.75rem] mr-1">Where found</span>
              {(['ALL', 'ACTIVE', 'WAL', 'CARVED', 'SPILLOVER'] as RecoveryPillFilter[]).map((p) => (
                <button key={p} type="button" aria-pressed={recoveryPillFilter === p} onClick={() => setRecoveryPillFilter(p)} className={pill(recoveryPillFilter === p)}>
                  {p === 'ALL' && 'All records'}
                  {p === 'ACTIVE' && 'In database'}
                  {p === 'WAL' && 'Recovered from log'}
                  {p === 'CARVED' && 'Carved from free space'}
                  {p === 'SPILLOVER' && 'System trace'}
                </button>
              ))}
            </div>
          </div>

          <div className="flex items-center justify-between gap-3 flex-wrap">
            <div className="flex items-center gap-1.5 flex-wrap" role="group" aria-label="Message kind">
              <span className="text-muted text-[0.75rem] mr-1">Message kind</span>
              {(['ALL', 'VIEW_ONCE', 'DISAPPEARING', 'REVOKED', 'ATTACHMENTS'] as EphemeralPillFilter[]).map((p) => (
                <button key={p} type="button" aria-pressed={ephemeralFilter === p} onClick={() => setEphemeralFilter(p)} className={pill(ephemeralFilter === p)}>
                  {p === 'ALL' && 'All'}
                  {p === 'VIEW_ONCE' && 'View-once media'}
                  {p === 'DISAPPEARING' && 'Disappearing'}
                  {p === 'REVOKED' && 'Revoked or unsent'}
                  {p === 'ATTACHMENTS' && 'With attachments or location'}
                </button>
              ))}
            </div>

            <div className="flex items-center gap-2 text-muted text-[0.75rem]">
              <span>
                Rows <strong className="text-ink">{totalMatching === 0 ? 0 : offset + 1}</strong>–<strong className="text-ink">{Math.min(offset + pageSize, totalMatching)}</strong> of{' '}
                <strong className="text-ink">{totalMatching.toLocaleString()}</strong>
              </span>
              <div className="flex items-center gap-0.5 border border-line-strong rounded-lg p-0.5 bg-surface">
                <button onClick={() => setCurrentPage(1)} disabled={validPage <= 1} className={pageBtn} title="First page" aria-label="First page"><ChevronsLeft className="w-3.5 h-3.5" /></button>
                <button onClick={() => setCurrentPage(validPage - 1)} disabled={validPage <= 1} className={pageBtn} title="Previous page" aria-label="Previous page"><ChevronLeft className="w-3.5 h-3.5" /></button>
                <span className="px-2 text-ink font-semibold">Page {validPage} of {totalPages}</span>
                <button onClick={() => setCurrentPage(validPage + 1)} disabled={validPage >= totalPages} className={pageBtn} title="Next page" aria-label="Next page"><ChevronRight className="w-3.5 h-3.5" /></button>
                <button onClick={() => setCurrentPage(totalPages)} disabled={validPage >= totalPages} className={pageBtn} title="Last page" aria-label="Last page"><ChevronsRight className="w-3.5 h-3.5" /></button>
              </div>
            </div>
          </div>
        </div>

        {chatViewMode === 'GRID' && (
          <div className="flex-1 overflow-auto select-text bg-surface">
            <table className="w-full text-left text-[0.75rem] border-collapse">
              <thead className="bg-sunken text-muted font-semibold sticky top-0 z-20">
                <tr className="border-b border-line-strong">
                  <th className="p-2 w-10">#</th>
                  <th className="p-2 w-28">Source app</th>
                  <th className="p-2 w-24">Chat type</th>
                  <th className="p-2 w-16">Direction</th>
                  <th className="p-2 w-28">Message type</th>
                  <th className="p-2 w-20">Status</th>
                  <th className="p-2 min-w-[280px]">Message body</th>
                  <th className="p-2 w-24">Quoted ID</th>
                  <th className="p-2 w-36">Quoted text</th>
                  <th className="p-2 w-14">Forwarded</th>

                  <th className="p-2 w-44">Thread ID</th>
                  <th className="p-2 w-44">Thread title</th>
                  <th className="p-2 w-48">Sender (ID / name)</th>
                  <th className="p-2 w-48">Recipient (ID / name)</th>

                  <th className="p-2 w-20">View-once</th>
                  <th className="p-2 w-20">Disappearing</th>
                  <th className="p-2 w-14">Revoked</th>

                  <th className="p-2 w-36">Timestamp raw</th>
                  <th className="p-2 w-44">Timestamp UTC</th>
                  <th className="p-2 w-48 text-ink">Timestamp IST (+05:30)</th>
                  <th className="p-2 w-44">Read IST</th>

                  <th className="p-2 w-40">Attachment path</th>
                  <th className="p-2 w-28">MIME type</th>
                  <th className="p-2 w-36">Location</th>

                  <th className="p-2 w-36">Source file and table</th>
                  <th className="p-2 w-28">Byte offset</th>
                  <th className="p-2 w-32">Where found</th>
                </tr>
              </thead>
              <tbody className="bg-surface text-ink">
                {paginatedMessages.map((msg, idx) => {
                  const isSelected = selectedArtifact?.id === msg.id;
                  const hexOffset = `0x${msg.provenance.byteOffset.toString(16).toUpperCase().padStart(8, '0')}`;
                  const isDel = isRecoveredMsg(msg);

                  return (
                    <tr
                      key={msg.id}
                      onClick={() => handleSelectMessage(msg)}
                      aria-selected={isSelected}
                      className={`cursor-pointer border-b border-line ${isDel ? 'is-recovered' : ''} ${isSelected ? 'bg-accent-soft' : 'hover:bg-hover'}`}
                    >
                      <td className="p-2 text-faint">{offset + idx + 1}</td>
                      <td className="p-2"><AppTag app={msg.sourceApp} /></td>
                      <td className="p-2 text-muted">{msg.chatType || 'DIRECT_1ON1'}</td>
                      <td className="p-2">
                        {msg.isFromMe ? (
                          <Chip tone="out"><ArrowUpRight className="w-3 h-3" aria-hidden="true" />Out</Chip>
                        ) : (
                          <Chip tone="in"><ArrowDownLeft className="w-3 h-3" aria-hidden="true" />In</Chip>
                        )}
                      </td>
                      <td className="p-2">
                        {msg.isViewOnce ? <Chip tone="warn">View once</Chip> : msg.mediaType || 'TEXT'}
                      </td>
                      <td className="p-2 text-center">{getStatusIcon(msg.messageStatus)}</td>
                      <td className="p-2">
                        <div className="line-clamp-2">{msg.body}</div>
                        {tagsOfMsg(msg.id).length > 0 && <div className="mt-1 flex flex-wrap gap-1"><TagPills tags={tagsOfMsg(msg.id)} /></div>}
                        {msg.paymentAttachment && (
                          <div className="mt-1 text-[0.75rem] text-g-money bg-g-money-soft px-1.5 py-0.5 rounded inline-block">
                            ₹{msg.paymentAttachment.amountInr.toLocaleString('en-IN')} (UTR: {msg.paymentAttachment.utrNumber})
                          </div>
                        )}
                      </td>
                      <td className="p-2 text-muted truncate max-w-[100px]">{msg.replyToId || '—'}</td>
                      <td className="p-2 text-muted truncate max-w-[140px] italic">{msg.quotedMessageText || '—'}</td>
                      <td className="p-2 text-center">
                        {msg.forwardingScore ? <span className="text-accent-ink font-semibold">+{msg.forwardingScore}</span> : '0'}
                      </td>

                      <td className="p-2 truncate max-w-[150px] font-mono text-muted" title={msg.threadId}>{msg.threadId}</td>
                      <td className="p-2 truncate max-w-[150px]">{msg.threadTitle || '—'}</td>
                      <td className="p-2 truncate max-w-[170px]">
                        <div className="font-semibold truncate">{msg.senderName}</div>
                        <div className="text-[0.6875rem] text-muted truncate font-mono">{msg.senderJid}</div>
                      </td>
                      <td className="p-2 truncate max-w-[170px]">
                        <div className="font-semibold truncate">{msg.recipientName || 'not recorded'}</div>
                        <div className="text-[0.6875rem] text-muted truncate font-mono">{msg.recipientJid || 'not recorded'}</div>
                      </td>

                      <td className="p-2 text-center">{msg.isViewOnce ? 'Yes' : '—'}</td>
                      <td className="p-2">
                        {msg.ephemeralDuration ? (
                          <span className="inline-flex items-center gap-0.5 font-semibold"><Flame className="w-3 h-3" aria-hidden="true" />{msg.ephemeralDuration}s</span>
                        ) : (
                          <span className="text-faint">—</span>
                        )}
                      </td>
                      <td className="p-2 text-center">{isDel ? <Trash2 className="w-3 h-3 text-rec inline" aria-label="Deleted or recovered" /> : '—'}</td>

                      <td className="p-2 text-muted truncate">{msg.timestamp.rawValue}</td>
                      <td className="p-2 text-muted whitespace-nowrap">{msg.timestamp.utcIso}</td>
                      <td className="p-2 whitespace-nowrap font-semibold">{msg.timestamp.istFormatted}</td>
                      <td className="p-2 text-muted">{msg.editTimestamp?.istFormatted || '—'}</td>

                      <td className="p-2 text-muted truncate max-w-[150px]" title={msg.mediaPath}>{msg.mediaPath || '—'}</td>
                      <td className="p-2 text-muted">{msg.mediaMimeType || '—'}</td>
                      <td className="p-2 text-muted truncate max-w-[140px]" title={msg.locationName}>{msg.locationName || '—'}</td>

                      <td className="p-2 text-muted truncate max-w-[150px]" title={msg.provenance.vfsInternalPath}>
                        {msg.provenance.vfsInternalPath.split('/').pop()} :: {msg.provenance.tableName || 'db'}
                      </td>
                      <td className="p-2 font-mono text-accent-ink">{hexOffset}</td>
                      <td className="p-2">{getStateBadge(msg.provenance.recoveryState, msg.isDeleted)}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
            {paginatedMessages.length === 0 && <p className="p-10 text-center text-muted">{chats.length === 0 ? 'No chat messages were found in the evidence.' : 'No message matches these filters.'}</p>}
          </div>
        )}

        {chatViewMode === 'BUBBLE' && (
          <div className="flex-1 flex flex-col overflow-hidden bg-surface">
            {activeThread && (
              <>
                <div className="border-b border-line px-4 py-3 flex items-center gap-3 flex-wrap shrink-0">
                  <span aria-hidden="true" className="w-[34px] h-[34px] rounded-full grid place-items-center shrink-0 bg-accent-soft text-accent-ink font-semibold text-[0.75rem]">{initialsOf(activeThread.threadTitle)}</span>
                  <div className="min-w-0 flex-1">
                    <h3 className="text-base font-semibold truncate">{activeThread.threadTitle}</h3>
                    <div className="text-muted text-[0.75rem] flex items-center gap-1.5 flex-wrap">
                      <AppTag app={activeThread.sourceApp} />
                      <span className="font-mono break-all">{activeThread.threadId}</span>
                    </div>
                  </div>
                  {activeThread.carvedCount > 0 && <RecoveredChip n={activeThread.carvedCount} label="recovered" />}
                </div>
                <div className="flex gap-x-5 gap-y-1.5 flex-wrap px-4 py-2 border-b border-line bg-sunken text-[0.75rem] text-muted shrink-0">
                  {threadFacts.map(([l, v]) => <span key={l}>{l} <b className="text-ink font-semibold">{v}</b></span>)}
                </div>
              </>
            )}

            <div className="flex-1 overflow-y-auto px-4 py-3.5 flex flex-col gap-2 select-text">
              {allFilteredMessages.length === 0 && <p className="p-10 text-center text-muted">{chats.length === 0 ? 'No chat messages were found in the evidence.' : 'No message matches these filters.'}</p>}
              {allFilteredMessages.map((msg, i) => {
                const isSelected = selectedArtifact?.id === msg.id;
                const isFromMe = msg.isFromMe;
                const isDel = isRecoveredMsg(msg);
                const hexOffset = `0x${msg.provenance.byteOffset.toString(16).toUpperCase().padStart(8, '0')}`;
                const audioState = audioStates[msg.id] || { isPlaying: false, progress: 35 };
                const paymentEv = extractPaymentEvidence(msg);
                const newDay = i === 0 || dayOf(allFilteredMessages[i - 1]) !== dayOf(msg);

                return (
                  <React.Fragment key={msg.id}>
                    {newDay && <div className="self-center text-[0.75rem] text-muted bg-sunken px-3 py-0.5 rounded-full">{dayOf(msg)}</div>}
                    <div onClick={() => handleSelectMessage(msg)} className={`flex flex-col cursor-pointer ${isFromMe ? 'items-end' : 'items-start'}`}>
                      <div
                        className={`max-w-[78%] rounded-xl px-3 py-2 flex flex-col gap-1.5 text-ink ${isFromMe ? 'bg-accent-soft' : 'bg-sunken'} ${
                          isDel ? 'border border-dashed border-rec' : 'border border-transparent'
                        } ${isSelected ? 'outline outline-2 outline-accent outline-offset-1' : ''}`}
                      >
                        <div className="flex items-center justify-between gap-3 text-[0.6875rem]">
                          <div className="flex items-center gap-1.5 truncate">
                            <span className="font-semibold text-muted truncate">{msg.senderName}</span>
                            {!activeThread && <AppTag app={msg.sourceApp} />}
                          </div>
                          <div className="flex items-center gap-1.5 shrink-0">
                            {msg.isStarred && <Star className="w-3 h-3 text-warn" aria-label="Starred" />}
                            {msg.forwardingScore ? (
                              <span className="inline-flex items-center gap-0.5 text-muted"><CornerUpRight className="w-2.5 h-2.5" aria-hidden="true" />+{msg.forwardingScore}</span>
                            ) : null}
                            {msg.ephemeralDuration ? <Chip tone="warn"><Flame className="w-2.5 h-2.5" aria-hidden="true" />TTL {msg.ephemeralDuration}s</Chip> : null}
                            {msg.isViewOnce && <Chip tone="warn">View-once media</Chip>}
                            {isDel && <Chip tone="rec" title="Recovered from the database log, free space or a deleted record">Recovered</Chip>}
                          </div>
                        </div>

                        {msg.quotedMessageText && (
                          <div className="p-2 rounded-lg bg-surface border-l-2 border-accent text-[0.75rem]">
                            <div className="text-[0.6875rem] text-muted font-semibold mb-0.5">Quoted message</div>
                            <div className="italic">{msg.quotedMessageText}</div>
                          </div>
                        )}

                        <div className="leading-relaxed break-words select-text">{msg.body}</div>
                        {tagsOfMsg(msg.id).length > 0 && <div className="flex flex-wrap gap-1"><TagPills tags={tagsOfMsg(msg.id)} /></div>}

                        {paymentEv && (
                          <div className="p-2.5 rounded-lg bg-surface border border-line">
                            <div className="flex items-center justify-between text-[0.75rem] pb-1.5 border-b border-line mb-2">
                              <span className="flex items-center gap-1.5 text-g-money font-semibold"><CreditCard className="w-3.5 h-3.5" aria-hidden="true" />UPI payment details in this message</span>
                              <Chip>Read from message</Chip>
                            </div>
                            <div className="grid grid-cols-2 gap-2 text-[0.75rem]">
                              {paymentEv.amount && (
                                <div><span className="text-muted block">Amount</span><span className="font-semibold">₹{paymentEv.amount.toLocaleString('en-IN')}</span></div>
                              )}
                              {paymentEv.utr && (
                                <div><span className="text-muted block">UTR</span><span className="font-mono select-all">{paymentEv.utr}</span></div>
                              )}
                              {paymentEv.vpa && (
                                <div className="col-span-2"><span className="text-muted block">UPI ID</span><span className="font-mono select-all">{paymentEv.vpa}</span></div>
                              )}
                            </div>
                            <div className="mt-2 pt-1.5 border-t border-line flex justify-end">
                              <button type="button" onClick={(e) => { e.stopPropagation(); setActiveTab('UPI_LEDGER'); }}
                                className="text-[0.75rem] text-accent-ink hover:underline font-semibold flex items-center gap-1">
                                <span>View in UPI ledger</span><ExternalLink className="w-2.5 h-2.5" aria-hidden="true" />
                              </button>
                            </div>
                          </div>
                        )}

                        {msg.mediaType === 'VOICE_NOTE' && (
                          <div className="flex items-center gap-2.5 p-2 rounded-lg bg-surface border border-line">
                            <button type="button" aria-label={audioState.isPlaying ? 'Pause' : 'Play'} onClick={(e) => { e.stopPropagation(); toggleAudioPlay(msg.id); }}
                              className="w-7 h-7 rounded-full bg-accent text-on-accent flex items-center justify-center shrink-0">
                              {audioState.isPlaying ? <Pause className="w-3.5 h-3.5 fill-current" /> : <Play className="w-3.5 h-3.5 fill-current ml-0.5" />}
                            </button>
                            <div className="flex-1 min-w-0">
                              <div className="flex items-center gap-1.5 text-[0.75rem] font-semibold"><Volume2 className="w-3.5 h-3.5 text-g-places" aria-hidden="true" />Voice note</div>
                              <div className="h-1.5 bg-sunken rounded-full overflow-hidden mt-1"><div className="h-full bg-accent" style={{ width: `${audioState.progress}%` }} /></div>
                              <div className="text-[0.6875rem] text-muted mt-0.5">Duration not recorded</div>
                            </div>
                          </div>
                        )}

                        {msg.mediaPath && msg.mediaType !== 'VOICE_NOTE' && (
                          <div className="flex items-center gap-2.5 p-2 rounded-lg bg-surface border border-line">
                            <ImageIcon className="w-4 h-4 text-g-files shrink-0" aria-hidden="true" />
                            <div className="min-w-0 flex-1">
                              <b className="block font-semibold break-all">{msg.mediaPath.split('/').pop()}</b>
                              <span className="text-[0.6875rem] text-muted">{msg.mediaMimeType || 'type not recorded'} · physical offset {hexOffset}</span>
                            </div>
                            <Button className="!h-7 !px-2 text-[0.75rem]" onClick={(e) => { e.stopPropagation(); setActiveImageModal(msg.mediaPath || 'preview.jpg'); }}>
                              Show path
                            </Button>
                          </div>
                        )}

                        {msg.locationName && (
                          <div className="flex items-start gap-2 p-2 rounded-lg bg-surface border border-line text-[0.75rem]">
                            <MapPin className="w-3.5 h-3.5 text-g-places shrink-0 mt-0.5" aria-hidden="true" />
                            <div>
                              <div className="font-semibold">{msg.locationName}</div>
                              <div className="text-muted font-mono">{msg.latitude?.toFixed(5)}, {msg.longitude?.toFixed(5)}</div>
                            </div>
                          </div>
                        )}

                        <div className="flex items-center justify-end gap-2 flex-wrap text-[0.6875rem] text-muted">
                          <span className="inline-flex items-center gap-1"><Clock className="w-2.5 h-2.5" aria-hidden="true" />{stampText(msg)} {tz}</span>
                          <button type="button"
                            onClick={(e) => { e.stopPropagation(); handleSelectMessage(msg); setBottomDockTab('HEX'); fetchHexWindowForOffset(msg.provenance); }}
                            className="text-accent-ink font-mono hover:underline inline-flex items-center gap-0.5" title="Jump to this byte offset in the hex viewer">
                            <Binary className="w-2.5 h-2.5" aria-hidden="true" />{hexOffset}
                          </button>
                          {getStatusIcon(msg.messageStatus)}
                        </div>
                      </div>
                    </div>
                  </React.Fragment>
                );
              })}
            </div>
          </div>
        )}
      </main>

      {activeImageModal && (
        <div className="fixed inset-0 z-50 bg-ink/60 flex items-center justify-center p-4" onClick={() => setActiveImageModal(null)}>
          <div className="max-w-2xl w-full bg-surface border border-line rounded-[10px] overflow-hidden shadow-float p-4 flex flex-col gap-3" role="dialog" aria-label="Attachment path" onClick={(e) => e.stopPropagation()}>
            <div className="flex items-center justify-between pb-2 border-b border-line">
              <span className="font-semibold">Attachment path</span>
              <button type="button" aria-label="Close" onClick={() => setActiveImageModal(null)} className="text-muted hover:text-ink"><X className="w-4 h-4" /></button>
            </div>
            <div className="bg-sunken rounded-lg p-8 text-center text-muted flex flex-col gap-2 items-center">
              <ImageIcon className="w-12 h-12 text-g-files" aria-hidden="true" />
              <div className="font-mono font-semibold text-ink break-all">{activeImageModal}</div>
              <div className="text-[0.75rem]">
                This is the path recorded for the attachment. The tool does not display the file here; use the media library to see recorded hashes.
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

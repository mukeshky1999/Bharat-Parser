import { create } from 'zustand';
import {
  CaseManifest,
  ChatArtifact,
  CallLogArtifact,
  ContactArtifact,
  OsSpilloverArtifact,
  DualHashResult,
  ForensicProvenance,
  MaliciousApkFinding,
  TimestampTriplet,
  UnifiedUPITransaction,
  VfsNode,
  normalizeTimestamp
} from '../../shared/forensic-types';
import { forensicClient, registerApiToastListener } from '../api/forensicClient';

export type ActiveFilterType = 'ALL' | 'WAL_AND_CARVED_ONLY' | 'CLOCK_TAMPER_ONLY';
export type RecoveryPillFilter = 'ALL' | 'ACTIVE' | 'WAL' | 'CARVED' | 'SPILLOVER';
export type EphemeralPillFilter = 'ALL' | 'VIEW_ONCE' | 'DISAPPEARING' | 'REVOKED' | 'ATTACHMENTS';
export type ChatWorkspaceMode = 'GRID' | 'BUBBLE';
export type BottomDockTabType = 'HEX' | 'DECODED_TREE';

export type ActiveTabType =
  | 'SUMMARY'
  | 'UPI_LEDGER'
  | 'CHATS'
  | 'CALL_LOGS'
  | 'CONTACTS'
  | 'OS_SPILLOVER'
  | 'LOCATIONS_MEDIA'
  | 'MULE_GRAPH'
  | 'CALLS'
  | 'FINDINGS'
  | 'REPORT_EXPORT'
  | 'CRYPTO'
  | 'SQLITE_WIZARD'
  | 'FILE_SYSTEM'
  | 'KEYS'
  | 'SEARCH'
  | 'TIMELINE'
  | 'TAGS'
  | 'MEDIA';

export interface SelectedArtifactState {
  id: string;
  provenance: ForensicProvenance;
  timestamp?: TimestampTriplet;
  embeddedIdTimestamp?: TimestampTriplet;
  clockTamperDetected?: boolean;
  notes?: string;
  itemType?: string;
  rawData?: any;
}

export interface HexWindowData {
  startOffset: number;
  byteCount: number;
  rawHex: string;
  hex_dump?: string;
  ascii_dump?: string;
  fileSize?: number;
  isEof?: boolean;
  targetOffset: number;
  targetLength: number;
  rows: Array<{
    address: number;
    addressHex: string;
    bytes: Array<{ val: number; hex: string; isHighlighted: boolean }>;
    ascii: Array<{ char: string; isHighlighted: boolean }>;
  }>;
}

export interface ToastNotification {
  id: string;
  type: 'error' | 'warning' | 'success' | 'info';
  title?: string;
  message: string;
  statusCode?: number;
  durationMs?: number;
}

export interface WorkbenchStoreState {
  // Case & Forensic Evidence
  caseManifest: CaseManifest | null;
  dualHashes: DualHashResult | null;
  /** What the backend recorded about the source file's integrity. null = nothing recorded. */
  integrity: { preSha256: string; postSha256: string; match: boolean | null } | null;
  vfsTree: VfsNode[];
  totalFilesIndexed: number;

  // Extracted Artifact Ledgers
  upiTransactions: UnifiedUPITransaction[];
  chats: ChatArtifact[];
  callLogs: CallLogArtifact[];
  contacts: ContactArtifact[];
  osSpillovers: OsSpilloverArtifact[];
  apkFindings: MaliciousApkFinding[];

  // Navigation & Filtering
  activeTab: ActiveTabType;
  selectedSubcategory: string;
  activeFilter: ActiveFilterType;
  recoveryPillFilter: RecoveryPillFilter;
  ephemeralFilter: EphemeralPillFilter;
  chatViewMode: ChatWorkspaceMode;
  searchQuery: string;

  // Pagination (100 rows per page)
  currentPage: number;
  pageSize: number;

  // Synchronized Selection & Hex Stream
  selectedArtifact: SelectedArtifactState | null;
  hexWindow: HexWindowData | null;
  isLoadingHex: boolean;
  hexError: string | null;
  bottomDockTab: BottomDockTabType;

  // Actions
  setCaseManifest: (manifest: CaseManifest) => void;
  setDualHashes: (hashes: DualHashResult) => void;
  setVfsTree: (tree: VfsNode[]) => void;
  setUpiTransactions: (txs: UnifiedUPITransaction[]) => void;
  setChats: (chats: ChatArtifact[]) => void;
  setCallLogs: (callLogs: CallLogArtifact[]) => void;
  setContacts: (contacts: ContactArtifact[]) => void;
  setOsSpillovers: (spillovers: OsSpilloverArtifact[]) => void;
  setApkFindings: (findings: MaliciousApkFinding[]) => void;
  setActiveTab: (tab: ActiveTabType) => void;
  setSelectedSubcategory: (subcat: string) => void;
  setActiveFilter: (filter: ActiveFilterType) => void;
  setRecoveryPillFilter: (filter: RecoveryPillFilter) => void;
  setEphemeralFilter: (filter: EphemeralPillFilter) => void;
  setChatViewMode: (mode: ChatWorkspaceMode) => void;
  setSearchQuery: (query: string) => void;
  setCurrentPage: (page: number) => void;
  setPageSize: (size: number) => void;
  setBottomDockTab: (tab: BottomDockTabType) => void;
  setSelectedArtifact: (artifact: SelectedArtifactState | null) => Promise<void>;
  fetchHexWindowForOffset: (provenance: ForensicProvenance) => Promise<void>;
  syncWithBackendCase: () => Promise<void>;

  // Toast notifications
  toasts: ToastNotification[];
  addToast: (toast: Omit<ToastNotification, 'id'>) => string;
  dismissToast: (id: string) => void;
}

// Module-level abort controller to prevent torn reads and race conditions
let activeHexAbortController: AbortController | null = null;


type BackendRow = Record<string, any>;

/** Fetches every row of a category, page by page (the UI must never silently show only page 1). */
async function fetchAllArtifactRows(category: string): Promise<{ rows: BackendRow[] } | null> {
  const PAGE = 500;
  const rows: BackendRow[] = [];
  for (let offset = 0; offset < 1_000_000; offset += PAGE) {
    const res: any = await forensicClient.queryArtifacts(category, undefined, undefined, undefined, undefined, PAGE, offset);
    if (!res || !Array.isArray(res.rows)) break;
    rows.push(...res.rows);
    const total = typeof res.total === 'number' ? res.total : (typeof res.total_count === 'number' ? res.total_count : null);
    if (res.rows.length < PAGE || (total !== null && rows.length >= total)) break;
  }
  return { rows };
}

/** X-13: a transaction time is UTC/IST only when the source fixed the instant; otherwise the clock string is shown as recorded. */
function txTimestamp(r: any): TimestampTriplet {
  if (r.Timestamp_UTC) {
    return { ...normalizeTimestamp(`${String(r.Timestamp_UTC).replace(' ', 'T')} UTC`, 'ISO_8601'), basis: r.Timestamp_Basis || undefined };
  }
  const clock = String(r.Date || '').trim();
  return {
    rawValue: r.Timestamp_Raw ?? r.Date ?? '',
    sourceFormat: 'ISO_8601',
    utcIso: '',
    istFormatted: 'Unknown',
    epochMs: 0,
    localClock: clock || undefined,
    basis: r.Timestamp_Basis || (clock ? 'LOCAL_ZONE_UNKNOWN' : undefined),
  };
}

function mapTxDirection(v: unknown): 'DEBIT' | 'CREDIT' | 'UNKNOWN' {
  const t = String(v ?? '').trim().toUpperCase();
  if (t === 'DEBIT' || t === 'DR') return 'DEBIT';
  if (t === 'CREDIT' || t === 'CR') return 'CREDIT';
  return 'UNKNOWN'; // TRANSFER / empty: direction not established by the evidence
}

function mapTxStatus(v: unknown): 'SUCCESS' | 'FAILED' | 'PENDING' | 'UNKNOWN' {
  const t = String(v ?? '').trim().toUpperCase();
  if (/FAIL|DECLIN|REJECT|CANCEL|EXPIR/.test(t)) return 'FAILED';
  if (/PEND|INITIAT|PROCESS/.test(t)) return 'PENDING';
  if (/^(SUCCESS|SUCCESSFUL|COMPLETED|PAID)$/.test(t)) return 'SUCCESS';
  return 'UNKNOWN';
}

/** Reads table/rowid/offset out of the backend provenance string. Missing parts stay unknown. */
function mapChatDirection(v: unknown): 'INCOMING' | 'OUTGOING' | 'UNKNOWN' {
  const t = String(v ?? '').trim().toUpperCase();
  if (t === 'OUTGOING' || t === 'SENT' || t === 'OUT') return 'OUTGOING';
  if (t === 'INCOMING' || t === 'RECEIVED' || t === 'IN') return 'INCOMING';
  return 'UNKNOWN'; // blank / UNKNOWN: the evidence does not say
}

function mapCallDirection(v: unknown): 'INCOMING' | 'OUTGOING' | 'MISSED' | 'REJECTED' | 'UNKNOWN' {
  const t = String(v ?? '').trim().toUpperCase();
  if (t === 'OUTGOING' || t === 'INCOMING' || t === 'MISSED' || t === 'REJECTED') return t;
  return 'UNKNOWN';
}

function parseProvenance(prov: unknown, summary: any, fallbackTable: string, vfsPath: string): any {
  const text = String(prov ?? '');
  const rowRaw = text.match(/RowID=([^\s:]+)/i)?.[1];
  const row = rowRaw && !/^not$/i.test(rowRaw) ? rowRaw : undefined; // "Not recorded" is not a row id
  const off = text.match(/Offset=(0x[0-9a-f]+|\d+)/i)?.[1];
  const table = text.split('::').map(x => x.trim()).find(x => /^[A-Za-z_][A-Za-z0-9_]*$/.test(x) && !/^(State|Offset)$/i.test(x)) || fallbackTable;
  const upper = text.toUpperCase();
  return {
    evidenceId: summary.case_id || '',
    archivePath: summary.evidence_path || '',
    vfsInternalPath: vfsPath || text.split('::')[1]?.trim() || '',
    containerType: 'SQLITE',
    tableName: table,
    rowId: row,
    byteOffset: off ? (off.toLowerCase().startsWith('0x') ? parseInt(off, 16) : parseInt(off, 10)) : -1, // -1 = not recorded
    byteLength: 0,
    recoveryState: upper.includes('WAL') ? 'WAL_RECOVERED' : (upper.includes('CARVED') || upper.includes('FREELIST') || upper.includes('SLACK') ? 'CARVED_UNALLOCATED' : 'ACTIVE'),
    rawPayloadHex: ''
  };
}

export const useWorkbenchStore = create<WorkbenchStoreState>((set, get) => ({
  caseManifest: null,
  dualHashes: null,
  integrity: null,
  vfsTree: [],
  totalFilesIndexed: 0,

  upiTransactions: [],
  chats: [],
  callLogs: [],
  contacts: [],
  osSpillovers: [],
  apkFindings: [],

  activeTab: 'SUMMARY',
  selectedSubcategory: 'ALL',
  activeFilter: 'ALL',
  recoveryPillFilter: 'ALL',
  ephemeralFilter: 'ALL',
  chatViewMode: 'GRID',
  searchQuery: '',

  currentPage: 1,
  pageSize: 100,

  selectedArtifact: null,
  hexWindow: null,
  isLoadingHex: false,
  hexError: null,
  bottomDockTab: 'HEX',

  toasts: [],
  addToast: (toast) => {
    const id = `toast_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`;
    const newToast: ToastNotification = { ...toast, id };
    set((state) => ({ toasts: [...state.toasts, newToast] }));
    const duration = toast.durationMs ?? (toast.type === 'error' ? 6000 : 4000);
    if (duration > 0) {
      setTimeout(() => {
        get().dismissToast(id);
      }, duration);
    }
    return id;
  },
  dismissToast: (id) => {
    set((state) => ({ toasts: state.toasts.filter((t) => t.id !== id) }));
  },

  setCaseManifest: (manifest) => set({ caseManifest: manifest }),
  setDualHashes: (hashes) => set({ dualHashes: hashes }),
  setVfsTree: (tree) => set({ vfsTree: tree }),
  setUpiTransactions: (txs) => set({ upiTransactions: txs }),
  setChats: (chats) => set({ chats }),
  setCallLogs: (callLogs) => set({ callLogs }),
  setContacts: (contacts) => set({ contacts }),
  setOsSpillovers: (osSpillovers) => set({ osSpillovers }),
  setApkFindings: (findings) => set({ apkFindings: findings }),
  setActiveTab: (tab) => set({ activeTab: tab, selectedSubcategory: 'ALL', currentPage: 1 }),
  setSelectedSubcategory: (subcat) => set({ selectedSubcategory: subcat, currentPage: 1 }),
  setActiveFilter: (filter) => set({ activeFilter: filter, currentPage: 1 }),
  setRecoveryPillFilter: (filter) => set({ recoveryPillFilter: filter, currentPage: 1 }),
  setEphemeralFilter: (filter) => set({ ephemeralFilter: filter, currentPage: 1 }),
  setChatViewMode: (mode) => set({ chatViewMode: mode }),
  setSearchQuery: (query) => set({ searchQuery: query, currentPage: 1 }),
  setCurrentPage: (page) => set({ currentPage: Math.max(1, page) }),
  setPageSize: (size) => set({ pageSize: size, currentPage: 1 }),
  setBottomDockTab: (tab) => set({ bottomDockTab: tab }),

  setSelectedArtifact: async (artifact) => {
    // The raw bytes are fetched when the examiner opens the "Source bytes" tab, not on every selection:
    // reading a file window for each row clicked is slow on a large image and shows an error for rows whose file is not available.
    set({ selectedArtifact: artifact, hexWindow: null, hexError: null });
  },

  fetchHexWindowForOffset: async (provenance: ForensicProvenance) => {
    if (activeHexAbortController) {
      activeHexAbortController.abort();
    }
    activeHexAbortController = new AbortController();
    const currentSignal = activeHexAbortController.signal;

    set({ isLoadingHex: true, hexError: null });

    // byteOffset < 0 means the parser did not record a physical offset: show the file start, highlight nothing.
    const offsetKnown = provenance.byteOffset >= 0;
    const targetOffset = offsetKnown ? provenance.byteOffset : 0;
    const targetLength = offsetKnown ? (provenance.byteLength || 32) : 0;

    // Stream 4KB (4096 bytes) window centered around the physical byte offset
    const windowSize = 4096;
    const startOffset = Math.max(0, Math.floor(targetOffset / 16) * 16 - 256);

    try {
      let rawHex = '';
      let hexDump = '';
      let asciiDump = '';
      let fileSize = 0;
      let isEof = false;

      // Try fetching from backend API via forensicClient
      try {
        const hexRes = await forensicClient.getHexWindow(
          provenance.vfsInternalPath,
          startOffset,
          windowSize,
          currentSignal
        );
        if (hexRes && hexRes.success) {
          rawHex = hexRes.raw_hex || hexRes.hex_dump || hexRes.hex_window?.raw_hex || '';
          hexDump = hexRes.hex_dump || rawHex;
          asciiDump = hexRes.ascii_dump || '';
          fileSize = hexRes.file_size || 0;
          isEof = Boolean(hexRes.is_eof);
        }
      } catch {
        // Fall through
      }

      if (currentSignal.aborted) return;

      // Never fabricate bytes (REVIEW C-04): if the file/offset cannot be read, say so.
      if (!rawHex) {
        set({
          hexWindow: null,
          hexError: 'These bytes could not be read from the evidence file (file missing, offset out of range, or no byte offset recorded).',
          isLoadingHex: false
        });
        return;
      }

      // Parse 16-byte rows for virtualized Hex + ASCII view
      const rows: HexWindowData['rows'] = [];
      const totalBytes = Math.floor(rawHex.length / 2);
      const rowCount = Math.min(256, Math.ceil(totalBytes / 16));

      for (let r = 0; r < rowCount; r++) {
        const rowAddress = startOffset + r * 16;
        const rowAddressHex = rowAddress.toString(16).toUpperCase().padStart(8, '0');
        const rowBytes: Array<{ val: number; hex: string; isHighlighted: boolean }> = [];
        const rowAscii: Array<{ char: string; isHighlighted: boolean }> = [];

        for (let c = 0; c < 16; c++) {
          const byteIdx = r * 16 + c;
          if (byteIdx >= totalBytes) break;

          const currentAddr = rowAddress + c;
          const isHighlighted =
            currentAddr >= targetOffset && currentAddr < targetOffset + targetLength;

          const byteHex = rawHex.substring(byteIdx * 2, byteIdx * 2 + 2) || '00';
          const byteVal = parseInt(byteHex, 16) || 0;
          const char = byteVal >= 32 && byteVal <= 126 ? String.fromCharCode(byteVal) : '.';

          rowBytes.push({ val: byteVal, hex: byteHex.toUpperCase(), isHighlighted });
          rowAscii.push({ char, isHighlighted });
        }

        rows.push({
          address: rowAddress,
          addressHex: rowAddressHex,
          bytes: rowBytes,
          ascii: rowAscii
        });
      }

      if (!currentSignal.aborted) {
        set({
          hexError: null,
          hexWindow: {
            startOffset,
            byteCount: totalBytes,
            rawHex,
            hex_dump: hexDump,
            ascii_dump: asciiDump,
            fileSize,
            isEof,
            targetOffset,
            targetLength,
            rows
          },
          isLoadingHex: false
        });
      }
    } catch {
      if (!currentSignal.aborted) {
        set({ isLoadingHex: false });
      }
    }
  },

  syncWithBackendCase: async () => {
    try {
      const summary = await forensicClient.getCaseSummary();
      if (summary && summary.loaded) {
        set({
          integrity: summary.hashes && summary.hashes.sha256 ? {
            preSha256: String(summary.hashes.sha256),
            postSha256: String(summary.hashes.postIngestionSha256 || ''),
            // the backend only sets integrityMatch after it re-hashed the source: absent = not re-checked
            match: typeof summary.hashes.integrityMatch === 'boolean' ? summary.hashes.integrityMatch : null
          } : null,
          dualHashes: summary.hashes ? {
            md5: summary.hashes.md5 || '',
            sha256: summary.hashes.sha256 || '',
            fileSizeBytes: summary.hashes.fileSizeBytes || 0,
            verified: Boolean(summary.hashes.verified),
            calculatedAt: summary.hashes.calculatedAt || '' // not recorded: never use the time the page was opened
          } : null,
          caseManifest: summary.extractions?.[0] ? {
            caseId: summary.case_id || 'CASE_01',
            caseNumber: summary.case_id || 'CASE_01',
            // Case particulars come from the examiner, never from placeholders (review U-07).
            firNumber: '',
            policeStation: '',
            district: '',
            examinerName: summary.examiner_name || '',
            evidencePath: summary.evidence_path || '',
            evidenceFileName: summary.case_name || 'Evidence Extraction Dump',
            fileSizeBytes: summary.hashes?.fileSizeBytes || 0,
            preIngestionHashes: {
              md5: summary.hashes?.md5 || '',
              sha256: summary.hashes?.sha256 || '',
              calculatedAt: summary.hashes?.calculatedAt || ''
            },
            indexedAt: normalizeTimestamp(Date.now(), 'UNIX_MS'),
            totalFilesIndexed: summary.extractions?.length || 1
          } : null
        });

        // Query real artifacts from backend store
        const [txRes, chatRes, contactRes, callRes] = await Promise.all([
          fetchAllArtifactRows('upi_transactions'),
          fetchAllArtifactRows('chats'),
          fetchAllArtifactRows('contacts'),
          fetchAllArtifactRows('calls')
        ]);

        if (txRes && txRes.rows && txRes.rows.length > 0) {
          set({
            upiTransactions: txRes.rows.map((r: any) => {
              const direction = mapTxDirection(r.Type ?? r.Direction);
              const counterparty = String(r.VPA || r.Counterparty || '');
              const owner = 'Device owner (account not resolved)';
              const hasId = r.Transaction_ID && r.Transaction_ID !== 'N/A';
              return {
                id: hasId ? `${r.Transaction_ID}#${r.id}` : `TX_${r.id}`,
                utrNumber: r.Bank_Ref_No || (hasId ? r.Transaction_ID : '') || '',
                appTransactionId: hasId ? r.Transaction_ID : '',
                sourceApp: r.Application || 'UPI',
                payerVpa: direction === 'DEBIT' ? owner : counterparty,
                payeeVpa: direction === 'CREDIT' ? owner : counterparty,
                accountMask: r.Account || '',
                ifscCode: null,
                amountInr: Number(r.Amount) || 0,
                currency: 'INR',
                direction,
                status: mapTxStatus(r.Status),
                timestamp: txTimestamp(r),
                clockTamperDetected: Boolean(r.Clock_Tamper_Detected),
                corroboratedSources: ['APP_DB'],
                provenance: parseProvenance(r.Forensic_Provenance, summary, 'transactions', r.Source_File || '')
              };
            })
          });
        }

        if (chatRes && chatRes.rows && chatRes.rows.length > 0) {
          set({
            chats: chatRes.rows.map((r: any) => ({
              id: `${r.Message_ID || 'MSG'}#${r.id}`,
              threadId: r.Thread_ID || 'thread',
              threadTitle: r.Thread_Title || r.Recipient_Name || r.Sender_Name || 'Chat',
              chatType: r.Chat_Type || 'DIRECT_1ON1',
              sourceApp: r.Application || 'Chat',
              senderJid: r.Sender_Identifier || '',
              senderName: r.Sender_Name || 'Unknown',
              recipientJid: r.Recipient_Identifier || '',
              recipientName: r.Recipient_Name || 'Unknown',
              body: r.Message_Body || '',
              isFromMe: mapChatDirection(r.Direction) === 'OUTGOING',
              direction: mapChatDirection(r.Direction),
              timestamp: normalizeTimestamp(r.Timestamp_UTC || r.Timestamp_IST || '', 'ISO_8601'),
              messageStatus: r.Delivery_Status || 'Unknown',
              isViewOnce: Boolean(r.Is_View_Once),
              isRevoked: Boolean(r.Is_Revoked_Deleted),
              isDeleted: Boolean(r.Is_Revoked_Deleted),
              provenance: parseProvenance(r.Forensic_Provenance, summary, 'chats', r.Attachment_Path_or_URL || '')
            }))
          });
        }

        if (contactRes && contactRes.rows && contactRes.rows.length > 0) {
          set({
            contacts: contactRes.rows.map((r: any) => ({
              id: `CNT_${r.id}`,
              identifier: r.Phone_Number || r.Identifier || 'N/A',
              displayName: r.Contact_Name || 'Unnamed Contact',
              identifiers: [{ type: 'PHONE', value: r.Phone_Number || r.Identifier || '' }],
              sourceApp: r.Application || 'Contacts',
              isKnownSuspect: false,
              provenance: parseProvenance(r.Forensic_Provenance, summary, 'contacts', r.Source_File || '')
            }))
          });
        }

        if (callRes && callRes.rows && callRes.rows.length > 0) {
          set({
            callLogs: callRes.rows.map((r: any) => ({
              id: `CALL_${r.id}`,
              callType: (r.Call_Type === 'VOIP' || (r.Application && r.Application !== 'Cellular')) ? 'VOIP_APP' : 'CELLULAR_CDR',
              direction: mapCallDirection(r.Direction),
              callerNumberOrId: r.Caller || r.Peer || 'Unknown',
              callerName: r.Peer || '',
              calleeNumberOrId: r.Callee || 'Unknown',
              calleeName: '',
              durationSeconds: r.Duration_Sec || 0,
              callResult: r.Call_Result || 'UNKNOWN',
              timestamp: normalizeTimestamp(r.Timestamp_IST || '', 'ISO_8601'),
              sourceApp: r.Application || 'Phone',
              provenance: parseProvenance(r.Forensic_Provenance, summary, 'calls', r.Source_File || '')
            }))
          });
        }
      } else {
        // Reset to clean empty state when no dump is loaded
        set({
          dualHashes: null,
          integrity: null,
          caseManifest: null,
          upiTransactions: [],
          chats: [],
          contacts: [],
          callLogs: [],
          osSpillovers: []
        });
      }
    } catch (e) {
      console.error('[workbenchStore] Error syncing with backend case:', e);
    }
  }
}));

// Automatically bridge forensic backend HTTP errors to active toast notifications
registerApiToastListener((event) => {
  useWorkbenchStore.getState().addToast({
    type: event.type,
    title: event.title,
    message: event.message,
    statusCode: event.status
  });
});


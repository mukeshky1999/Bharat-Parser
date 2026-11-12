/**
 * Bharat-PA Forensics — Dual HTTP + Electron API Client Bridge
 * Safely wraps Electron IPC and REST API on http://127.0.0.1:8000.
 * Strictly aligned with FastAPI/Pydantic models:
 *   - CaseOpenResponse
 *   - PaginatedRecordsResponse
 *   - HexInspectorResponse
 *   - BenchmarkResponse
 * Explicitly surfaces 409 Conflict, 412 Precondition Failed, 403 Forbidden,
 * and passes AbortSignal across all requests to eliminate state leaks.
 */

export interface TreeCountsResponse {
  success: boolean;
  counts: Record<string, { total: number; active: number; wal_and_carved: number }>;
}

export interface PaginatedRecordsResponse {
  success: boolean;
  category: string;
  table_name: string;
  rows: Record<string, unknown>[];
  total: number;
  limit: number;
  offset: number;
  page: number;
  total_pages: number;
  apps_available: string[];
  execution_time_ms?: number;
}

export interface ChatThreadsResponse {
  success: boolean;
  threads: Record<string, unknown>[];
  count: number;
  thread_id?: string;
  messages?: Record<string, unknown>[];
}

export interface HexInspectorResponse {
  success: boolean;
  file_path: string;
  file_size: number;
  offset: number;
  window_size: number;
  hex_dump: string;
  ascii_dump: string;
  is_eof: boolean;
  target_offset?: number | null;
  target_length?: number | null;
  start_offset?: number | null;
  window_bytes?: number | null;
  sha256?: string | null;
  hex_lines?: Array<{
    address: number;
    addressHex: string;
    bytes: Array<{ val: number; hex: string; isHighlighted: boolean }>;
    ascii: Array<{ char: string; isHighlighted: boolean }>;
  }> | null;
  raw_hex?: string | null;
  // Backward compatibility alias for legacy viewers
  hex_window?: {
    file_path: string;
    byte_offset: number;
    window_size: number;
    raw_hex: string;
    rows?: Array<{
      address: number;
      address_hex: string;
      bytes: Array<{ val: number; hex: string; is_highlighted: boolean }>;
      ascii: Array<{ char: string; is_highlighted: boolean }>;
    }>;
  };
}

// Backward compatible type alias
export type HexWindowResponse = HexInspectorResponse;

export interface CaseOpenResponse {
  success: boolean;
  workspace: string;
  db_path: string;
  case_id: string | null;
  case_name: string | null;
  case_loaded: boolean;
  records_count: number;
  error?: string;
  detail?: string;
  status?: number;
}

export interface BenchmarkResponse {
  success: boolean;
  dump_path: string;
  output_dir: string;
  ledger_path: string;
  report_path: string;
  duration_seconds: number;
  executive_summary: Record<string, unknown>;
  vendor_differential: Record<string, unknown>;
  error?: string;
  detail?: string;
  status?: number;
}

export interface IngestCaseResponse {
  success: boolean;
  case_id?: string | null;
  case_name?: string | null;
  evidence_path?: string | null;
  examiner_name?: string;
  agency_name?: string;
  hashes?: {
    md5?: string;
    sha256?: string;
    fileSizeBytes?: number;
    verified?: boolean;
    calculatedAt?: string;
  };
  owner_dossier?: Record<string, unknown> | null;
  device_metadata?: Record<string, unknown> | null;
  mule_alerts?: unknown[];
  syndicate_roles?: unknown[];
  counts?: Record<string, { total: number; active: number; wal_and_carved: number }>;
  extractions?: unknown[];
  error?: string;
  detail?: string;
  status?: number;
}

export interface CaseStateResponse {
  loaded: boolean;
  case_id?: string | null;
  case_name?: string | null;
  evidence_path?: string | null;
  extractions: any[];
  counts: Record<string, { total: number; active: number; wal_and_carved: number }>;
  owner_dossier?: any | null;
  hashes?: {
    md5?: string;
    sha256?: string;
    fileSizeBytes?: number;
    verified?: boolean;
    calculatedAt?: string;
  };
}

export interface CaseSummaryResponse {
  loaded: boolean;
  case_id?: string | null;
  case_name?: string | null;
  evidence_path?: string | null;
  examiner_name?: string;
  agency_name?: string;
  hashes?: {
    md5?: string;
    sha256?: string;
    fileSizeBytes?: number;
    verified?: boolean;
    calculatedAt?: string;
  };
  owner_dossier?: any | null;
  device_metadata?: any | null;
  mule_alerts?: any[];
  syndicate_roles?: any[];
  counts: Record<string, { total: number; active: number; wal_and_carved: number }>;
  extractions: any[];
}

export interface HealthResponse {
  status: string;
  platform?: string;
  python_version?: string;
  case_loaded?: boolean;
  database_exists?: boolean;
  database_size_bytes?: number;
}

export interface ApiToastEvent {
  status: number;
  title: string;
  message: string;
  type: 'error' | 'warning' | 'info';
}

export interface ChatRedlineResponse {
  success: boolean;
  original_text: string;
  edited_text: string;
  rendered_markup: string;
  tokens: Array<{ token_type: string; text: string }>;
  has_financial_or_crypto_token: boolean;
  error?: string;
  detail?: string;
  status?: number;
}

export interface MuleNetworkResponse {
  success: boolean;
  nodes: Array<{
    id: string;
    entity: string;
    type: string;
    inflow: number;
    outflow: number;
    apps_used?: string[];
    role: string;
  }>;
  edges: Array<{
    source: string;
    target: string;
    amount: number;
    app: string;
    flow: string;
    timestamp?: string;
    txid?: string;
  }>;
  mule_alerts: unknown[];
  syndicate_roles: unknown[];
  sankey_layout: {
    stages: Record<string, Array<{ node_id: string; label: string; x: number; y: number; height: number }>>;
    ribbons: Array<{ source: string; target: string; amount_inr: number; thickness_px: number; path: string }>;
    smurfing_fans: Array<{ target: string; count: number; total_inr: number; badge: string }>;
  };
  error?: string;
  detail?: string;
  status?: number;
}

export interface Sec230BnssResponse {
  success: boolean;
  case_id: string;
  bundle_path: string;
  pocso_withheld_count: number;
  html_viewer_path: string;
  statutory_mandate: string;
  error?: string;
  detail?: string;
  status?: number;
}

export interface NcrpCandidate {
  account_no: string;
  ifsc: string;
  vpa: string;
  is_complainant_victim: boolean;
  volume_inr: number;
  counterparty_name?: string;
}

export interface NcrpFreezeResponse {
  success: boolean;
  csv_path: string;
  csv_content: string;
  sha256: string;
  total_accounts_evaluated: number;
  total_freeze_targets: number;
  total_lien_amount_inr: number;
  safeguards: Array<{
    account_no: string;
    is_victim: boolean;
    is_freeze_locked: boolean;
    freeze_checkbox_disabled: boolean;
    role_badge: string;
  }>;
  portal: string;
  error?: string;
  detail?: string;
  status?: number;
}

export interface OcrAnalyzeResponse {
  success: boolean;
  image_path: string;
  engine_used: string;
  raw_text: string;
  normalized_text: string;
  detected_scripts: string[];
  document_category: string;
  extracted_utrs: string[];
  extracted_pans: string[];
  extracted_ifscs: string[];
  extracted_amounts_inr: number[];
  vpas: string[];
  confidence_score: number;
  error?: string;
  detail?: string;
  status?: number;
}

export type ApiToastListener = (event: ApiToastEvent) => void;

let activeToastListener: ApiToastListener | null = null;

export function registerApiToastListener(listener: ApiToastListener | null): void {
  activeToastListener = listener;
}

export class ForensicApiError extends Error {
  constructor(
    public status: number,
    public detail: string,
    public endpoint: string
  ) {
    super(`Forensic API [${status}] at ${endpoint}: ${detail}`);
    this.name = 'ForensicApiError';
  }
}

const BACKEND_BASE_URL = 'http://127.0.0.1:8000';

class ForensicClient {
  private hasElectron(): boolean {
    return (
      typeof window !== 'undefined' &&
      Boolean((window as unknown as { electronAPI?: unknown }).electronAPI ||
        (window as unknown as { electron?: { ipcRenderer?: unknown } }).electron?.ipcRenderer)
    );
  }

  private notifyHttpError(status: number, detail: string, endpoint: string): void {
    if (!activeToastListener) return;

    if (status === 409) {
      activeToastListener({
        status,
        type: 'error',
        title: '409 Conflict: Operation In Progress',
        message: detail || 'A concurrent ingestion or benchmark pipeline is actively running. Please await completion.'
      });
    } else if (status === 412) {
      activeToastListener({
        status,
        type: 'warning',
        title: '412 Precondition Failed: No Case Loaded',
        message: detail || 'No forensic case is loaded. Ingest evidence or open a case workspace first.'
      });
    } else if (status === 403) {
      activeToastListener({
        status,
        type: 'error',
        title: '403 Forbidden: Sandbox Violation',
        message: detail || 'Access Denied: Target path is outside the active forensic case workspace and evidence container.'
      });
    } else if (status === 404) {
      activeToastListener({
        status,
        type: 'error',
        title: '404 Not Found',
        message: detail || 'Requested evidence container, database, or resource not found.'
      });
    } else if (status >= 500) {
      activeToastListener({
        status,
        type: 'error',
        title: `${status} Internal Forensic Engine Error`,
        message: detail || 'Backend processing failure.'
      });
    }
  }

  private async fetchApi<T>(
    endpoint: string,
    options: RequestInit = {}
  ): Promise<{ data: T | null; error: string | null; status: number }> {
    try {
      const url = `${BACKEND_BASE_URL}${endpoint}`;
      const res = await fetch(url, {
        ...options,
        headers: {
          'Content-Type': 'application/json',
          ...(options.headers || {})
        }
      });

      if (!res.ok) {
        let errorDetail = res.statusText || `HTTP ${res.status}`;
        try {
          const errJson = await res.json();
          if (errJson && errJson.detail) {
            errorDetail = typeof errJson.detail === 'string'
              ? errJson.detail
              : JSON.stringify(errJson.detail);
          }
        } catch {
          // Response body is not JSON
        }

        this.notifyHttpError(res.status, errorDetail, endpoint);
        return { data: null, error: errorDetail, status: res.status };
      }

      const data = (await res.json()) as T;
      return { data, error: null, status: res.status };
    } catch (err: unknown) {
      if (err instanceof Error && err.name === 'AbortError') {
        return { data: null, error: 'Request aborted', status: 0 };
      }
      const msg = err instanceof Error ? err.message : 'Network communication failure';
      return { data: null, error: msg, status: 0 };
    }
  }

  /**
   * Health check for Python FastAPI server on 127.0.0.1:8000.
   */
  public async checkHealth(signal?: AbortSignal): Promise<HealthResponse> {
    try {
      const res = await this.fetchApi<HealthResponse>('/api/health', { signal });
      if (res.data && res.data.status) {
        return res.data;
      }
    } catch {
      // Fall through
    }
    return {
      status: 'DISCONNECTED',
      database_exists: false,
      database_size_bytes: 0
    };
  }

  /**
   * Native Windows File Explorer picker via Electron native dialog or Python backend.
   */
  public async pickEvidenceFile(): Promise<string> {
    try {
      const win = window as unknown as { electronAPI?: { openFileDialog?: () => Promise<string> } };
      if (this.hasElectron() && win.electronAPI?.openFileDialog) {
        const selected = await win.electronAPI.openFileDialog();
        if (selected) return selected;
      }
      const res = await this.fetchApi<{ selected_path: string }>('/api/system/pick-evidence-file', {
        method: 'POST'
      });
      return res.data?.selected_path || '';
    } catch {
      return '';
    }
  }

  /**
   * Native Windows Folder Explorer picker via Electron native dialog or Python backend.
   */
  public async pickEvidenceFolder(): Promise<string> {
    try {
      const win = window as unknown as { electronAPI?: { openFolderDialog?: () => Promise<string> } };
      if (this.hasElectron() && win.electronAPI?.openFolderDialog) {
        const selected = await win.electronAPI.openFolderDialog();
        if (selected) return selected;
      }
      const res = await this.fetchApi<{ selected_path: string }>('/api/system/pick-evidence-folder', {
        method: 'POST'
      });
      return res.data?.selected_path || '';
    } catch {
      return '';
    }
  }

  /**
   * Ingests evidence container / directory through Python 1 TB+ streaming forensic pipeline.
   * Gracefully catches and surfaces 409 Conflict, 403 Forbidden, and 404.
   */
  public async ingestCase(
    evidencePath: string,
    caseId?: string,
    caseName?: string,
    signal?: AbortSignal
  ): Promise<IngestCaseResponse> {
    try {
      const res = await this.fetchApi<IngestCaseResponse>('/api/case/ingest', {
        method: 'POST',
        signal,
        body: JSON.stringify({
          evidence_path: evidencePath,
          case_id: caseId,
          case_name: caseName
        })
      });
      if (res.data && res.data.success) {
        return res.data;
      }
      return {
        success: false,
        status: res.status,
        detail: res.error || 'Ingestion failed on backend',
        error: res.error || 'Ingestion failed on backend'
      };
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Failed to ingest evidence container';
      return { success: false, status: 0, detail: msg, error: msg };
    }
  }

  /**
   * Fetches current case state.
   */
  public async getCaseState(signal?: AbortSignal): Promise<CaseStateResponse> {
    try {
      const res = await this.fetchApi<CaseStateResponse>('/api/case/state', { signal });
      if (res.data) return res.data;
    } catch {
      // Fall through
    }
    return {
      loaded: false,
      case_name: null,
      extractions: [],
      counts: {},
      owner_dossier: null
    };
  }

  /**
   * Fetches active case summary, dossier, mule alerts, hashes, and counts.
   */
  public async getCaseSummary(signal?: AbortSignal): Promise<CaseSummaryResponse> {
    try {
      const res = await this.fetchApi<CaseSummaryResponse>('/api/case/summary', { signal });
      if (res.data) return res.data;
    } catch {
      // Fall through
    }
    return {
      loaded: false,
      case_name: null,
      extractions: [],
      counts: {},
      owner_dossier: null,
      device_metadata: null,
      hashes: {},
      mule_alerts: [],
      syndicate_roles: []
    };
  }

  /**
   * Fetches Physical Analyzer Analyzed Data tree counts (Active vs WAL/Carved).
   */
  public async getTreeCounts(signal?: AbortSignal): Promise<TreeCountsResponse> {
    try {
      const win = window as unknown as { electronAPI?: { getTreeCounts?: () => Promise<TreeCountsResponse['counts']> } };
      if (this.hasElectron() && win.electronAPI?.getTreeCounts) {
        const counts = await win.electronAPI.getTreeCounts();
        if (counts) return { success: true, counts };
      }
      const res = await this.fetchApi<TreeCountsResponse>('/api/case/tree-counts', { signal });
      if (res.data && res.data.success && res.data.counts) {
        return res.data;
      }
    } catch {
      // Fall through
    }

    return {
      success: false,
      counts: {}
    };
  }

  /**
   * Queries paginated virtualized records from SQLite FTS5 backend.
   */
  public async queryArtifacts(
    category: string,
    appFilter?: string,
    recoveryFilter?: string,
    ephemeralFilter?: string,
    searchQuery?: string,
    limit: number = 100,
    offset: number = 0,
    sortCol?: string,
    sortAsc: boolean = false,
    signal?: AbortSignal
  ): Promise<PaginatedRecordsResponse> {
    const params = new URLSearchParams({
      category,
      limit: limit.toString(),
      offset: offset.toString()
    });

    if (searchQuery && searchQuery.trim()) params.append('search_query', searchQuery.trim());
    if (recoveryFilter && recoveryFilter !== 'ALL') params.append('recovery_filter', recoveryFilter);
    if (ephemeralFilter && ephemeralFilter !== 'ALL') params.append('ephemeral_filter', ephemeralFilter);
    if (appFilter && appFilter !== 'ALL') params.append('app_filter', appFilter);
    if (sortCol) params.append('sort_col', sortCol);
    if (sortAsc) params.append('sort_asc', 'true');

    try {
      const res = await this.fetchApi<PaginatedRecordsResponse>(`/api/artifacts/query?${params.toString()}`, {
        signal
      });
      if (res.data && res.data.success) {
        return res.data;
      }
    } catch {
      // Fall through
    }

    const calculatedPage = Math.floor(offset / Math.max(1, limit)) + 1;
    return {
      success: false,
      category,
      table_name: category,
      rows: [],
      total: 0,
      limit,
      offset,
      page: calculatedPage,
      total_pages: 1,
      apps_available: []
    };
  }

  /**
   * Queries paginated virtualized records matching hardened FastAPI /api/case/records endpoint.
   */
  public async getPaginatedRecords(
    category: string,
    page: number = 1,
    pageSize: number = 100,
    search?: string,
    recoveryFilter?: string,
    ephemeralFilter?: string,
    app?: string,
    signal?: AbortSignal
  ): Promise<PaginatedRecordsResponse> {
    const params = new URLSearchParams({
      category,
      page: page.toString(),
      page_size: pageSize.toString()
    });

    if (search && search.trim()) params.append('search', search.trim());
    if (recoveryFilter && recoveryFilter !== 'ALL') params.append('recovery_filter', recoveryFilter);
    if (ephemeralFilter && ephemeralFilter !== 'ALL') params.append('ephemeral_filter', ephemeralFilter);
    if (app && app !== 'ALL') params.append('app', app);

    try {
      const res = await this.fetchApi<PaginatedRecordsResponse>(`/api/case/records?${params.toString()}`, {
        signal
      });
      if (res.data && res.data.success) {
        return res.data;
      }
    } catch {
      // Fall through
    }

    // Fallback to queryArtifacts
    const offset = (page - 1) * pageSize;
    return this.queryArtifacts(category, app, recoveryFilter, ephemeralFilter, search, pageSize, offset, undefined, false, signal);
  }

  /**
   * Returns conversation thread summaries grouped by application or messages for a thread.
   */
  public async getChatThreads(
    app?: string,
    threadId?: string,
    limit: number = 50,
    offset: number = 0,
    signal?: AbortSignal
  ): Promise<ChatThreadsResponse> {
    const params = new URLSearchParams({
      limit: limit.toString(),
      offset: offset.toString()
    });
    if (app && app !== 'ALL') params.append('app', app);
    if (threadId) params.append('thread_id', threadId);

    try {
      const res = await this.fetchApi<ChatThreadsResponse>(`/api/chats/threads?${params.toString()}`, { signal });
      if (res.data && res.data.success) {
        return res.data;
      }
    } catch {
      // Fall through
    }

    return {
      success: false,
      threads: [],
      count: 0
    };
  }

  /**
   * Reconciles external bank statement CSV with active UPI/banking timeline.
   */
  public async fuseBankStatement(
    statementPath?: string,
    csvContent?: string,
    filename?: string,
    signal?: AbortSignal
  ): Promise<{
    success: boolean;
    error?: string;
    message?: string;
    bank_records_count?: number;
    matched_count?: number;
    unmatched_bank_count?: number;
    reconciliation_rows?: unknown[];
  }> {
    try {
      const res = await this.fetchApi<{
        success: boolean;
        message?: string;
        bank_records_count?: number;
        matched_count?: number;
        unmatched_bank_count?: number;
        reconciliation_rows?: unknown[];
      }>('/api/fusion/bank-statement', {
        method: 'POST',
        signal,
        body: JSON.stringify({ statement_path: statementPath, csv_content: csvContent, filename })
      });
      return res.data || { success: false, error: res.error || 'Failed to fuse bank statement' };
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Error fusing bank statement';
      return { success: false, error: msg };
    }
  }

  /**
   * Correlates telecom CDR record CSV with financial transactions.
   */
  public async fuseCdr(
    cdrPath?: string,
    csvContent?: string,
    filename?: string,
    signal?: AbortSignal
  ): Promise<{
    success: boolean;
    error?: string;
    message?: string;
    cdr_count?: number;
    correlated_transactions_count?: number;
    correlation_rows?: unknown[];
  }> {
    try {
      const res = await this.fetchApi<{
        success: boolean;
        message?: string;
        cdr_count?: number;
        correlated_transactions_count?: number;
        correlation_rows?: unknown[];
      }>('/api/fusion/cdr', {
        method: 'POST',
        signal,
        body: JSON.stringify({ cdr_path: cdrPath, csv_content: csvContent, filename })
      });
      return res.data || { success: false, error: res.error || 'Failed to fuse CDR record' };
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Error fusing CDR record';
      return { success: false, error: msg };
    }
  }

  /**
   * Returns standalone PyVis interactive graph HTML.
   */
  public getNetworkHtmlUrl(): string {
    return `${BACKEND_BASE_URL}/api/graph/network-html`;
  }

  /**
   * Returns chargesheet syndicate chain.
   */
  public async getChargeSheetChain(signal?: AbortSignal): Promise<{
    success: boolean;
    chain?: Record<string, unknown>;
    mule_alerts?: unknown[];
    syndicate_roles?: unknown[];
  }> {
    try {
      const res = await this.fetchApi<{
        success: boolean;
        chain?: Record<string, unknown>;
        mule_alerts?: unknown[];
        syndicate_roles?: unknown[];
      }>('/api/graph/charge-sheet-chain', { signal });
      return res.data || { success: false };
    } catch {
      return { success: false };
    }
  }

  /**
   * Deep dumps tables and key-value pairs from any SQLite database.
   */
  public async inspectSqlite(
    dbPath: string,
    tableName?: string,
    limit: number = 100,
    signal?: AbortSignal
  ): Promise<{
    success: boolean;
    error?: string;
    tables: Array<{ table_name: string; row_count: number; columns: string[] }>;
    selected_table?: string;
    rows: Record<string, unknown>[];
    kv_pairs?: unknown[];
  }> {
    try {
      const res = await this.fetchApi<{
        success: boolean;
        tables: Array<{ table_name: string; row_count: number; columns: string[] }>;
        selected_table?: string;
        rows: Record<string, unknown>[];
        kv_pairs?: unknown[];
      }>(
        '/api/sqlite/inspect',
        {
          method: 'POST',
          signal,
          body: JSON.stringify({ db_path: dbPath, table_name: tableName, limit })
        }
      );
      return res.data || { success: false, error: res.error || 'Inspection failed', tables: [], rows: [] };
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Error inspecting SQLite';
      return { success: false, error: msg, tables: [], rows: [] };
    }
  }

  /**
   * Fetches memory-mapped 4KB hex window centered on physical byte offset via hardened /api/case/hex-window.
   * Strictly enforces 412 Precondition Failed validation and 403 sandboxing.
   */
  public async getInspectorHex(
    filePath: string,
    offset: number = 0,
    windowSize: number = 4096,
    signal?: AbortSignal
  ): Promise<HexInspectorResponse> {
    const params = new URLSearchParams({
      file_path: filePath,
      offset: offset.toString(),
      window_size: windowSize.toString()
    });

    try {
      const res = await this.fetchApi<HexInspectorResponse>(`/api/case/hex-window?${params.toString()}`, {
        signal
      });
      if (res.data && res.data.success) {
        return res.data;
      }
    } catch {
      // Fall through
    }

    return {
      success: false,
      file_path: filePath,
      file_size: 0,
      offset,
      window_size: windowSize,
      hex_dump: '',
      ascii_dump: '',
      is_eof: false
    };
  }

  /**
   * Hex window alias directly pointing to hardened /api/case/hex-window endpoint.
   */
  public async getHexWindow(
    filePath: string,
    offset: number,
    windowSize: number = 4096,
    signal?: AbortSignal
  ): Promise<HexInspectorResponse> {
    return this.getInspectorHex(filePath, offset, windowSize, signal);
  }

  /**
   * Returns Section 63(4)(c) BSA statutory certificate URL.
   */
  public getSec63BsaReportUrl(): string {
    return `${BACKEND_BASE_URL}/api/report/sec63-bsa`;
  }

  /**
   * Ingests or opens a dump file / workspace via backend.
   * Matches Pydantic CaseOpenResponse.
   */
  public async openCase(
    workspaceDir: string,
    dbName: string = 'bharat_case_store.db',
    signal?: AbortSignal
  ): Promise<CaseOpenResponse> {
    try {
      const res = await this.fetchApi<CaseOpenResponse>('/api/case/open', {
        method: 'POST',
        signal,
        body: JSON.stringify({ workspace_dir: workspaceDir, db_name: dbName })
      });
      if (res.data && res.data.success) {
        return res.data;
      }
      return {
        success: false,
        workspace: workspaceDir,
        db_path: dbName,
        case_id: null,
        case_name: null,
        case_loaded: false,
        records_count: 0,
        status: res.status,
        detail: res.error || 'Failed to open case workspace',
        error: res.error || 'Failed to open case workspace'
      };
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Failed to open case';
      return {
        success: false,
        workspace: workspaceDir,
        db_path: dbName,
        case_id: null,
        case_name: null,
        case_loaded: false,
        records_count: 0,
        status: 0,
        detail: msg,
        error: msg
      };
    }
  }

  /**
   * Ingests and benchmarks a real evidence dump (.ufdr, .tar, .zip, .xry, directory).
   * Matches Pydantic BenchmarkResponse and surfaces 409 Conflict concurrency lock.
   */
  public async loadDump(
    dumpPath: string,
    signal?: AbortSignal
  ): Promise<BenchmarkResponse> {
    try {
      const res = await this.fetchApi<BenchmarkResponse>('/api/benchmark/run', {
        method: 'POST',
        signal,
        body: JSON.stringify({ dump_path: dumpPath, verbose: true })
      });
      if (res.data && res.data.success) {
        return res.data;
      }
      return {
        success: false,
        dump_path: dumpPath,
        output_dir: '',
        ledger_path: '',
        report_path: '',
        duration_seconds: 0,
        executive_summary: {},
        vendor_differential: {},
        status: res.status,
        detail: res.error || 'Backend benchmark invocation failed',
        error: res.error || 'Backend benchmark invocation failed'
      };
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Error executing benchmark harness';
      return {
        success: false,
        dump_path: dumpPath,
        output_dir: '',
        ledger_path: '',
        report_path: '',
        duration_seconds: 0,
        executive_summary: {},
        vendor_differential: {},
        status: 0,
        detail: msg,
        error: msg
      };
    }
  }

  /**
   * Computes Myers Shortest-Edit-Script diff between original and edited chat messages.
   * Surfaces inline <del> and <ins> markup and financial token classifications.
   */
  public async computeChatRedline(
    originalText: string,
    editedText: string,
    signal?: AbortSignal
  ): Promise<ChatRedlineResponse> {
    try {
      const res = await this.fetchApi<ChatRedlineResponse>('/api/chat-redline', {
        method: 'POST',
        signal,
        body: JSON.stringify({ original_text: originalText, edited_text: editedText })
      });
      if (res.data && res.data.success) {
        return res.data;
      }
      return {
        success: false,
        original_text: originalText,
        edited_text: editedText,
        rendered_markup: editedText,
        tokens: [],
        has_financial_or_crypto_token: false,
        status: res.status,
        error: res.error || 'Failed to compute redline diff',
        detail: res.error || 'Failed to compute redline diff'
      };
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Error in chat redline';
      return {
        success: false,
        original_text: originalText,
        edited_text: editedText,
        rendered_markup: editedText,
        tokens: [],
        has_financial_or_crypto_token: false,
        status: 0,
        error: msg,
        detail: msg
      };
    }
  }

  /**
   * Retrieves structured money laundering graph topology and 5-stage Sankey layout coordinates.
   */
  public async getMuleNetwork(signal?: AbortSignal): Promise<MuleNetworkResponse> {
    try {
      const res = await this.fetchApi<MuleNetworkResponse>('/api/graph/mule-network', {
        method: 'GET',
        signal
      });
      if (res.data && res.data.success) {
        return res.data;
      }
      return {
        success: false,
        nodes: [],
        edges: [],
        mule_alerts: [],
        syndicate_roles: [],
        sankey_layout: { stages: {}, ribbons: [], smurfing_fans: [] },
        status: res.status,
        error: res.error || 'Failed to fetch mule network',
        detail: res.error || 'Failed to fetch mule network'
      };
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Error fetching mule network';
      return {
        success: false,
        nodes: [],
        edges: [],
        mule_alerts: [],
        syndicate_roles: [],
        sankey_layout: { stages: {}, ribbons: [], smurfing_fans: [] },
        status: 0,
        error: msg,
        detail: msg
      };
    }
  }

  /**
   * Retrieves rendered 4-Stage / 5-Stage SVG vector money trail markup.
   */
  public async getSankeySvg(signal?: AbortSignal): Promise<string> {
    try {
      const url = `${BACKEND_BASE_URL}/api/graph/sankey-svg`;
      const res = await fetch(url, { signal });
      if (res.ok) {
        return await res.text();
      }
      return '';
    } catch {
      return '';
    }
  }

  /**
   * Generates Section 230 BNSS statutory defense disclosure bundle with victim PII redaction
   * and judicial notice cards for intimate/POCSO media.
   */
  public async generateSec230BnssPackage(
    caseId: string,
    outputDir?: string,
    anonymize: boolean = true,
    victimName?: string,
    signal?: AbortSignal,
    items?: Array<{ path: string; redaction_tag: string | null }>
  ): Promise<Sec230BnssResponse> {
    try {
      const res = await this.fetchApi<Sec230BnssResponse>('/api/report/sec230-bnss', {
        method: 'POST',
        signal,
        body: JSON.stringify({
          case_id: caseId,
          output_dir: outputDir,
          anonymize_victim_identity: anonymize,
          victim_name: victimName,
          items
        })
      });
      if (res.data && res.data.success) {
        return res.data;
      }
      return {
        success: false,
        case_id: caseId,
        bundle_path: '',
        pocso_withheld_count: 0,
        html_viewer_path: '',
        statutory_mandate: '',
        status: res.status,
        error: res.error || 'Failed to generate Section 230 BNSS bundle',
        detail: res.error || 'Failed to generate Section 230 BNSS bundle'
      };
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Error generating Sec 230 bundle';
      return {
        success: false,
        case_id: caseId,
        bundle_path: '',
        pocso_withheld_count: 0,
        html_viewer_path: '',
        statutory_mandate: '',
        status: 0,
        error: msg,
        detail: msg
      };
    }
  }

  /**
   * Generates 14-column 1930 NCRP bank freeze sheet and enforces Complainant Safeguard Lock.
   */
  /** Media files of the loaded case that can be packaged for a Section 230 disclosure copy. */
  public async getMediaCandidates(
    signal?: AbortSignal
  ): Promise<{ items: Array<{ path: string; vfs_path: string; file_name: string; file_size: number }>; error?: string }> {
    const res = await this.fetchApi<{ items: any[] }>('/api/case/media-candidates', { signal });
    if (res.data) return { items: res.data.items || [] };
    return { items: [], error: res.error || 'Could not list case media' };
  }

  /** Candidate beneficiary accounts derived from the loaded case (never sample data). */
  public async getNcrpCandidates(
    complainantAccount: string,
    signal?: AbortSignal
  ): Promise<{ candidates: NcrpCandidate[]; error?: string }> {
    const res = await this.fetchApi<{ candidates: NcrpCandidate[] }>(
      `/api/report/ncrp-candidates?complainant_account=${encodeURIComponent(complainantAccount)}`,
      { signal }
    );
    if (res.data) return { candidates: res.data.candidates || [] };
    return { candidates: [], error: res.error || 'Could not load candidate accounts' };
  }

  public async exportNcrpFreezePacket(
    candidates: any[] | undefined,
    outputDir: string | undefined,
    complainantAccount: string,
    acknowledgementNo: string,
    signal?: AbortSignal
  ): Promise<NcrpFreezeResponse> {
    try {
      const res = await this.fetchApi<NcrpFreezeResponse>('/api/report/ncrp-freeze', {
        method: 'POST',
        signal,
        body: JSON.stringify({
          candidates,
          output_dir: outputDir,
          complainant_account: complainantAccount,
          acknowledgement_no: acknowledgementNo
        })
      });
      if (res.data && res.data.success) {
        return res.data;
      }
      return {
        success: false,
        csv_path: '',
        csv_content: '',
        sha256: '',
        total_accounts_evaluated: 0,
        total_freeze_targets: 0,
        total_lien_amount_inr: 0,
        safeguards: [],
        portal: '',
        status: res.status,
        error: res.error || 'Failed to export NCRP freeze packet',
        detail: res.error || 'Failed to export NCRP freeze packet'
      };
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Error generating NCRP freeze packet';
      return {
        success: false,
        csv_path: '',
        csv_content: '',
        sha256: '',
        total_accounts_evaluated: 0,
        total_freeze_targets: 0,
        total_lien_amount_inr: 0,
        safeguards: [],
        portal: '',
        status: 0,
        error: msg,
        detail: msg
      };
    }
  }

  /**
   * Performs bilingual Hindi + English OCR analysis on an image file.
   */
  public async analyzeOcr(
    imagePath: string,
    signal?: AbortSignal
  ): Promise<OcrAnalyzeResponse> {
    try {
      const res = await this.fetchApi<OcrAnalyzeResponse>('/api/ocr/analyze', {
        method: 'POST',
        signal,
        body: JSON.stringify({ image_path: imagePath })
      });
      if (res.data && res.data.success) {
        return res.data;
      }
      return {
        success: false,
        image_path: imagePath,
        engine_used: '',
        raw_text: '',
        normalized_text: '',
        detected_scripts: [],
        document_category: '',
        extracted_utrs: [],
        extracted_pans: [],
        extracted_ifscs: [],
        extracted_amounts_inr: [],
        vpas: [],
        confidence_score: 0,
        status: res.status,
        error: res.error || 'Failed to analyze OCR',
        detail: res.error || 'Failed to analyze OCR'
      };
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Error analyzing OCR';
      return {
        success: false,
        image_path: imagePath,
        engine_used: '',
        raw_text: '',
        normalized_text: '',
        detected_scripts: [],
        document_category: '',
        extracted_utrs: [],
        extracted_pans: [],
        extracted_ifscs: [],
        extracted_amounts_inr: [],
        vpas: [],
        confidence_score: 0,
        status: 0,
        error: msg,
        detail: msg
      };
    }
  }
}

export const forensicClient = new ForensicClient();

import { create } from 'zustand';
import { forensicClient } from '../api/forensicClient';

export interface Finding {
  id: number;
  kind: string;
  record_id: string;
  title: string;
  note: string;
  source: Record<string, unknown>;
  pinned_at_utc: string;
}

export interface PinInput {
  kind: string;
  record_id: string;
  title: string;
  note?: string;
  source?: Record<string, unknown>;
}

interface FindingsState {
  findings: Finding[];
  loading: boolean;
  error: string | null;
  load: () => Promise<void>;
  pin: (input: PinInput) => Promise<boolean>;
  unpin: (id: number) => Promise<void>;
  isPinned: (kind: string, recordId: string) => boolean;
}

async function call(endpoint: string, init?: RequestInit): Promise<Finding[]> {
  const res = await forensicClient.authFetch(endpoint, {
    ...init,
    headers: { 'Content-Type': 'application/json', ...(init?.headers || {}) },
  });
  if (!res.ok) {
    let detail = res.statusText || `HTTP ${res.status}`;
    try {
      const j = await res.json();
      if (j && typeof j.detail === 'string') detail = j.detail;
    } catch {
      // body was not JSON
    }
    throw new Error(detail);
  }
  const body = await res.json();
  return Array.isArray(body?.findings) ? (body.findings as Finding[]) : [];
}

export const useFindings = create<FindingsState>((set, get) => ({
  findings: [],
  loading: false,
  error: null,
  load: async () => {
    set({ loading: true, error: null });
    try {
      set({ findings: await call('/api/case/findings'), loading: false });
    } catch (e) {
      set({ loading: false, error: e instanceof Error ? e.message : 'Could not load findings' });
    }
  },
  pin: async (input) => {
    try {
      const findings = await call('/api/case/findings', {
        method: 'POST',
        body: JSON.stringify({ note: '', source: {}, ...input }),
      });
      set({ findings, error: null });
      return true;
    } catch (e) {
      set({ error: e instanceof Error ? e.message : 'Could not pin the record' });
      return false;
    }
  },
  unpin: async (id) => {
    try {
      set({ findings: await call(`/api/case/findings/${id}`, { method: 'DELETE' }), error: null });
    } catch (e) {
      set({ error: e instanceof Error ? e.message : 'Could not remove the finding' });
    }
  },
  isPinned: (kind, recordId) => get().findings.some((f) => f.kind === kind && f.record_id === recordId),
}));

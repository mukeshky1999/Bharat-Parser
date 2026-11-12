import React from 'react';
import { useWorkbenchStore } from '../state/workbenchStore';
import { usePreferences } from '../state/preferencesStore';
import { stageForTab, viewLabel } from './stages';

export const StatusLine: React.FC = () => {
  const activeTab = useWorkbenchStore((s) => s.activeTab);
  const selected = useWorkbenchStore((s) => s.selectedArtifact);
  const upi = useWorkbenchStore((s) => s.upiTransactions.length);
  const chats = useWorkbenchStore((s) => s.chats.length);
  const contacts = useWorkbenchStore((s) => s.contacts.length);
  const calls = useWorkbenchStore((s) => s.callLogs.length);
  const errors = useWorkbenchStore((s) => s.toasts.filter((t) => t.type === 'error').length);
  const tz = usePreferences((s) => s.timeZone);
  const theme = usePreferences((s) => s.theme);
  const setPref = usePreferences((s) => s.set);

  const counts: Record<string, number | null> = { UPI_LEDGER: upi, CHATS: chats, CONTACTS: contacts, CALLS: calls };
  const n = counts[activeTab] ?? null;
  const stage = stageForTab(activeTab);

  return (
    <footer className="h-7 shrink-0 flex items-center gap-4 px-4 text-[0.75rem] text-slate-300 bg-slate-900 border-t border-slate-800" data-region="status" tabIndex={-1}>
      <span>
        {stage.no}. {stage.label} · {viewLabel(activeTab)}
        {n !== null ? ` · ${n.toLocaleString()} record${n === 1 ? '' : 's'}` : ''}
      </span>
      {selected && <span className="truncate text-slate-400">Selected: {selected.itemType || 'record'} {selected.id}</span>}
      <span className="ml-auto flex items-center gap-3">
        {errors > 0 && <span className="text-rose-300">{errors} error{errors === 1 ? '' : 's'} shown</span>}
        <button onClick={() => setPref({ timeZone: tz === 'IST' ? 'UTC' : 'IST' })} className="hover:text-slate-50 underline decoration-dotted" title="Which time zone is shown first">
          Times: {tz}
        </button>
        <span>Theme: {theme}</span>
      </span>
    </footer>
  );
};

import React, { useCallback, useEffect, useState } from 'react';
import { forensicClient, SavedFilter } from '../api/forensicClient';
import { useWorkbenchStore } from '../state/workbenchStore';
import { useLatestRequest } from '../utils/latestRequest';

export type FilterScope = 'upi_ledger' | 'calls' | 'search' | 'timeline' | 'crypto_custodial' | 'crypto_p2p' | 'crypto_bridge' | 'crypto_addresses' | 'bank_alerts';

/**
 * Saves the filter choices on this screen under a name, and applies a saved set again. Saved filters are kept in the
 * case file (not in the browser) because a filter can hold text from the evidence. A filter holds only your choices,
 * never records.
 */
export const SavedFilters: React.FC<{
  scope: FilterScope;
  current: Record<string, string | number | boolean | null>;
  onApply: (state: Record<string, string | number | boolean | null>) => void;
  /** true when nothing is filtered, so there is nothing worth saving */
  isDefault: boolean;
}> = ({ scope, current, onApply, isDefault }) => {
  const [filters, setFilters] = useState<SavedFilter[]>([]);
  const [name, setName] = useState('');
  const [msg, setMsg] = useState('');

  const caseId = useWorkbenchStore((s) => s.caseManifest?.caseId ?? '');   // another case has its own saved filters
  const [loadError, setLoadError] = useState('');
  const latest = useLatestRequest();
  const load = useCallback(async () => {
    const { isCurrent } = latest.begin();
    const res = await forensicClient.getSavedFilters(scope);
    if (!isCurrent()) return;
    if (res.error) { setLoadError(res.error); setFilters([]); return; }
    setLoadError('');
    setFilters(res.data?.filters ?? []);
  }, [scope, latest]);
  useEffect(() => { void load(); }, [load, caseId]);

  const save = async (e: React.FormEvent) => {
    e.preventDefault();
    setMsg('');
    const res = await forensicClient.saveFilter(scope, name, current);
    if (res.error) { setMsg(res.error); return; }
    setMsg(res.data?.replaced ? `Replaced “${res.data.name}”.` : `Saved “${res.data?.name}”.`);
    setName('');
    await load();
  };

  const remove = async (n: string) => {
    const res = await forensicClient.removeSavedFilter(scope, n);
    if (res.error) setMsg(`Could not delete “${n}”: ${res.error}`);
    await load();
  };

  return (
    <details className="relative">
      <summary className="h-8 px-3 rounded border border-line-strong text-ink hover:bg-hover cursor-pointer inline-flex items-center list-none">
        Saved filters{filters.length ? ` (${filters.length})` : ''}
      </summary>
      <div className="absolute z-20 mt-1 w-80 rounded border border-line-strong bg-sunken p-2 shadow-float text-ink">
        {loadError ? <p role="alert" className="text-rec text-xs mb-2">Saved filters could not be read: {loadError}</p>
          : filters.length === 0 ? <p className="text-muted text-xs">No saved filters on this screen yet.</p> : (
          <ul className="mb-2 space-y-1">
            {filters.map((f) => (
              <li key={f.name} className="flex items-center justify-between gap-2">
                <button className="text-left hover:underline truncate" onClick={() => onApply(f.state)} title="Apply this filter">{f.name}</button>
                <button className="text-muted hover:text-rec text-xs" aria-label={`Delete ${f.name}`} onClick={() => void remove(f.name)}>Delete</button>
              </li>
            ))}
          </ul>
        )}
        <form onSubmit={(e) => void save(e)} className="flex gap-1">
          <input aria-label="Name for this filter" value={name} onChange={(e) => setName(e.target.value)} maxLength={60} placeholder="Name this filter"
            className="h-8 flex-1 rounded bg-surface border border-line-strong px-2 text-ink placeholder:text-faint" />
          <button type="submit" disabled={!name.trim() || isDefault} className="h-8 px-3 rounded border border-line-strong hover:bg-hover disabled:opacity-40"
            title={isDefault ? 'Nothing is filtered yet' : undefined}>Save</button>
        </form>
        <p className="mt-1 text-[0.6875rem] text-muted">Kept in this case file. A saved filter holds your choices, not records.{msg ? ` ${msg}` : ''}</p>
      </div>
    </details>
  );
};

import React, { useCallback, useEffect, useRef, useState } from 'react';
import { KeyRound, Plus, Trash2, Play, ShieldCheck } from 'lucide-react';
import { forensicClient, KeyCheckRow, KeysNeeded } from '../api/forensicClient';

/**
 * Keys you hold for encrypted databases.
 *
 * The values live in this component's state only. They are not put in a store, in local storage or in the case file;
 * they are sent once, with the request that processes the device, and cleared afterwards. The tool tries only the
 * keys listed here and the ones found inside the evidence. It does not generate keys or try a word list.
 */
export interface KeyRow { id: number; name: string; value: string }

export const keysFromRows = (rows: KeyRow[]): Record<string, string> => {
  const out: Record<string, string> = {};
  for (const r of rows) {
    const n = r.name.trim();
    if (n && r.value.trim()) out[n] = r.value;
  }
  return out;
};

interface KeyEntryProps {
  rows: KeyRow[];
  onChange: (rows: KeyRow[]) => void;
  disabled?: boolean;
}

const input = 'h-8 bg-surface border border-line-strong rounded px-2 text-xs text-ink placeholder:text-faint focus:outline-none focus:border-accent';

export const KeyEntry: React.FC<KeyEntryProps> = ({ rows, onChange, disabled }) => {
  const [checks, setChecks] = useState<Record<string, KeyCheckRow>>({});
  const nextId = useRef(rows.reduce((m, r) => Math.max(m, r.id), 0) + 1);

  const check = useCallback(async (list: KeyRow[]) => {
    const keys = keysFromRows(list);
    if (!Object.keys(keys).length) { setChecks({}); return; }
    const res = await forensicClient.checkKeys(keys);
    if (res.data) setChecks(Object.fromEntries(res.data.keys.map((k) => [k.name, k])));
  }, []);

  // describe the keys again whenever the set of non-empty rows changes (on leaving a field, not on every key press)
  const update = (id: number, patch: Partial<KeyRow>) => onChange(rows.map((r) => (r.id === id ? { ...r, ...patch } : r)));

  useEffect(() => () => onChange([]), []); // eslint-disable-line react-hooks/exhaustive-deps -- clear typed keys when this goes away

  return (
    <div className="space-y-2">
      {rows.map((r) => {
        const c = checks[r.name.trim()];
        return (
          <div key={r.id} className="space-y-1">
            <div className="flex items-center gap-2">
              <input
                aria-label="Key name" className={`${input} w-40`} placeholder="Name, e.g. app key" value={r.name} disabled={disabled}
                onChange={(e) => update(r.id, { name: e.target.value })} onBlur={() => void check(rows)} autoComplete="off" spellCheck={false}
              />
              <input
                aria-label="Key value" type="password" className={`${input} flex-1 font-mono`} placeholder="Hex, base64 or passphrase" value={r.value} disabled={disabled}
                onChange={(e) => update(r.id, { value: e.target.value })} onBlur={() => void check(rows)} autoComplete="off" spellCheck={false}
              />
              <button type="button" aria-label="Remove this key" className="h-8 px-2 rounded border border-line-strong text-muted hover:bg-hover" disabled={disabled}
                onClick={() => onChange(rows.filter((x) => x.id !== r.id))}>
                <Trash2 className="w-3.5 h-3.5" aria-hidden="true" />
              </button>
            </div>
            {c && (
              <p className={`text-[0.6875rem] ${c.usable ? 'text-muted' : 'text-warn'}`}>
                {c.usable
                  ? <>Will be tried as: {c.readings.map((x) => `${x.how} (${x.fingerprint})`).join(', ')}. The audit log records the name and fingerprint, not the key.</>
                  : null}
                {c.problems.length > 0 && <span className="text-warn"> {c.problems.join(' ')}</span>}
              </p>
            )}
          </div>
        );
      })}
      <button type="button" className="h-8 px-3 rounded border border-line-strong bg-surface hover:bg-hover text-xs text-ink inline-flex items-center gap-1.5" disabled={disabled}
        onClick={() => onChange([...rows, { id: nextId.current++, name: '', value: '' }])}>
        <Plus className="w-3.5 h-3.5" aria-hidden="true" />Add a key
      </button>
    </div>
  );
};

interface KeysNeededCardProps {
  /** Called after a device was processed again, so the caller can reload the case. */
  onProcessed: () => void | Promise<void>;
  /** Changes when the loaded case changes, so the list is read again. */
  refreshKey?: string | number;
}

/** Lists the files that could not be opened for want of a key, and lets you process that device again with keys you hold. */
export const KeysNeededCard: React.FC<KeysNeededCardProps> = ({ onProcessed, refreshKey }) => {
  const [data, setData] = useState<KeysNeeded | null>(null);
  const [rows, setRows] = useState<KeyRow[]>([]);
  const [busy, setBusy] = useState('');
  const [error, setError] = useState('');

  const [loadError, setLoadError] = useState('');

  const load = useCallback(async () => {
    const res = await forensicClient.getCaseKeys();
    if (res.error || !res.data) { setLoadError(res.error || 'No answer from the backend.'); setData(null); return; }
    setLoadError('');
    setData(res.data);
  }, []);
  useEffect(() => { void load(); }, [load, refreshKey]);

  // If it cannot be checked, say so: staying silent would read as "no file needs a key".
  if (loadError) {
    return <p role="alert" className="rounded border border-line-strong bg-warn-soft p-3 text-xs text-warn">
      The tool could not check whether any file in this case is encrypted and unread ({loadError}). Do not take the absence of this notice as meaning every file was read.
    </p>;
  }
  if (!data || data.needed.length === 0) return null;

  const run = async (item: KeysNeeded['needed'][number]) => {
    const keys = keysFromRows(rows);
    if (!item.source_path) { setError('The source of this device is not recorded, so it cannot be processed again from here.'); return; }
    if (!Object.keys(keys).length) { setError('Add at least one key first.'); return; }
    setBusy(item.evidence_item); setError('');
    const res = await forensicClient.ingestCase(item.source_path, undefined, undefined, undefined,
      { mode: 'add', label: item.label ?? '', keys });
    setBusy('');
    if (!res.success) { setError(res.error || 'Processing failed.'); return; }
    setRows([]);                    // typed keys are cleared as soon as they have been used
    await load();
    await onProcessed();
  };

  return (
    <section className="rounded-lg border border-line-strong bg-warn-soft p-4 text-xs text-ink space-y-3" aria-label="Files that need a key">
      <h2 className="flex items-center gap-2 font-semibold text-warn"><KeyRound className="w-4 h-4" aria-hidden="true" />Encrypted databases that were not read</h2>
      <p className="text-muted">
        These files could not be opened because no key was supplied or found in the evidence. Their content is not in the case.
        If you hold a key, add it and process the device again: that device is replaced, its tags are kept where the same record is found again.
      </p>
      {data.needed.map((n) => (
        <div key={n.evidence_item} className="rounded border border-line-strong bg-surface p-3 space-y-2">
          <p className="font-semibold text-ink">{n.evidence_item}{n.label ? `: ${n.label}` : ''}</p>
          <ul className="list-disc pl-5 text-muted break-all">
            {n.files.map((f) => <li key={f.file}><span className="font-mono">{f.file}</span>{f.reason ? ` (${f.reason})` : ''}</li>)}
          </ul>
          <button type="button" disabled={!!busy || !n.source_path}
            className="h-8 px-3 rounded bg-accent text-on-accent hover:brightness-110 font-semibold inline-flex items-center gap-1.5 disabled:opacity-50"
            onClick={() => void run(n)}>
            <Play className="w-3.5 h-3.5" aria-hidden="true" />{busy === n.evidence_item ? 'Processing…' : 'Process this device again with these keys'}
          </button>
        </div>
      ))}
      <div className="rounded border border-line-strong bg-surface p-3 space-y-2">
        <p className="font-semibold text-ink">Keys you hold</p>
        <KeyEntry rows={rows} onChange={setRows} disabled={!!busy} />
      </div>
      {error && <p className="text-rec">{error}</p>}
      <p className="flex items-center gap-1.5 text-muted"><ShieldCheck className="w-3.5 h-3.5" aria-hidden="true" />{data.note}</p>
    </section>
  );
};

import React, { useMemo, useState } from 'react';
import { Copy, Pin, PinOff, X } from 'lucide-react';
import { useWorkbenchStore, SelectedArtifactState } from '../state/workbenchStore';
import { useFindings } from '../state/findingsStore';
import { usePreferences } from '../state/preferencesStore';
import { SyncedHexViewer } from './SyncedHexViewer';
import type { ForensicProvenance, TimestampTriplet } from '../../shared/forensic-types';

type CardTab = 'DETAILS' | 'BYTES' | 'LINKS';

const NOT_RECORDED = 'not recorded';

const HIDDEN_KEYS = new Set(['provenance', 'timestamp', 'embeddedIdTimestamp', 'rawPayloadHex', 'id']);

function words(key: string): string {
  return key.replace(/([a-z0-9])([A-Z])/g, '$1 $2').replace(/_/g, ' ').replace(/^./, (c) => c.toUpperCase());
}

function show(v: unknown): string {
  if (v === null || v === undefined || v === '') return NOT_RECORDED;
  if (typeof v === 'boolean') return v ? 'yes' : 'no';
  if (typeof v === 'object') {
    try {
      const j = JSON.stringify(v);
      return j.length > 400 ? `${j.slice(0, 400)}…` : j;
    } catch {
      return NOT_RECORDED;
    }
  }
  return String(v);
}

function hasTime(t?: TimestampTriplet | null): t is TimestampTriplet {
  return !!t && !!t.utcIso && t.istFormatted !== 'Unknown';
}

function offsetText(p: ForensicProvenance): string {
  return p.byteOffset >= 0 ? `0x${p.byteOffset.toString(16).toUpperCase().padStart(8, '0')}` : NOT_RECORDED;
}

function Row({ k, v, mono }: { k: string; v: string; mono?: boolean }) {
  const missing = v === NOT_RECORDED;
  return (
    <div className="grid grid-cols-[8.5rem_1fr] gap-x-3 py-1 border-b border-slate-800/70 last:border-b-0">
      <dt className="text-slate-400">{k}</dt>
      <dd className={`${missing ? 'text-slate-500 italic' : 'text-slate-100'} ${mono ? 'font-mono' : ''} break-words min-w-0`}>{v}</dd>
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="mb-4">
      <h3 className="text-[0.6875rem] font-semibold uppercase tracking-wider text-slate-400 mb-1">{title}</h3>
      <dl>{children}</dl>
    </section>
  );
}

function kindOf(a: SelectedArtifactState): string {
  return (a.itemType || 'record').toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_|_$/g, '') || 'record';
}

function titleOf(a: SelectedArtifactState): string {
  const r = (a.rawData ?? {}) as Record<string, unknown>;
  const body = (r.body ?? r.Message_Body ?? r.Message_Text) as string | undefined;
  if (typeof body === 'string' && body.trim()) return body.trim().slice(0, 120);
  const amt = r.amountInr ?? r.Amount;
  if (amt !== undefined && amt !== null) return `${a.itemType || 'Transaction'} INR ${String(amt)}`;
  return `${a.itemType || 'Record'} ${a.id}`;
}

/** The finding stored for a record: a pointer to where it came from, plus the examiner's note. */
export function buildPin(a: SelectedArtifactState, note: string) {
  const prov = a.provenance;
  return {
    kind: kindOf(a),
    record_id: a.id,
    title: titleOf(a),
    note,
    source: {
      file: prov?.vfsInternalPath || null,
      table: prov?.tableName || null,
      rowid: prov?.rowId ?? null,
      offset: prov && prov.byteOffset >= 0 ? prov.byteOffset : null,
      recovery_state: prov?.recoveryState || null,
    },
  };
}

function LinksTab({ artifact }: { artifact: SelectedArtifactState }) {
  const upi = useWorkbenchStore((s) => s.upiTransactions);
  const chats = useWorkbenchStore((s) => s.chats);
  const setSelectedArtifact = useWorkbenchStore((s) => s.setSelectedArtifact);
  const raw = (artifact.rawData ?? {}) as Record<string, any>;

  const links = useMemo(() => {
    const out: Array<{ why: string; label: string; open: () => void }> = [];
    const utr = typeof raw.utrNumber === 'string' && raw.utrNumber.length >= 8 ? raw.utrNumber : null;
    const cpty = raw.payeeVpa || raw.payerVpa || null;
    if (!utr && !cpty) return out;
    for (const t of upi) {
      if (t.id === artifact.id) continue;
      const sameUtr = utr && t.utrNumber === utr;
      const sameVpa = cpty && (t.payeeVpa === cpty || t.payerVpa === cpty);
      if (sameUtr || sameVpa) {
        out.push({
          why: sameUtr ? `same UTR ${utr}` : `same VPA ${cpty}`,
          label: `${t.timestamp?.istFormatted || 'time not recorded'}  INR ${t.amountInr ?? NOT_RECORDED}`,
          open: () => void setSelectedArtifact({ id: t.id, provenance: t.provenance, timestamp: t.timestamp, rawData: t, itemType: 'UPI transaction' }),
        });
      }
    }
    if (utr) {
      for (const c of chats) {
        if (typeof c.body === 'string' && c.body.includes(utr)) {
          out.push({
            why: `message text contains UTR ${utr}`,
            label: `${c.sourceApp}  ${c.timestamp?.istFormatted || 'time not recorded'}`,
            open: () => void setSelectedArtifact({ id: c.id, provenance: c.provenance, timestamp: c.timestamp, rawData: c, itemType: 'Chat message' }),
          });
        }
      }
    }
    return out.slice(0, 50);
  }, [raw, artifact.id, upi, chats, setSelectedArtifact]);

  return (
    <div>
      <p className="text-slate-400 mb-3">Records that share this record&apos;s UTR or counterparty VPA, matched exactly. These are leads to check, not proof that the records belong together.</p>
      {links.length === 0 ? (
        <p className="text-slate-500 italic">No exact matches found for this record.</p>
      ) : (
        <ul className="space-y-1">
          {links.map((l, i) => (
            <li key={i}>
              <button onClick={l.open} className="w-full text-left rounded px-2 py-1.5 bg-slate-900 hover:bg-slate-800 border border-slate-800">
                <div className="text-slate-100">{l.label}</div>
                <div className="text-slate-400">{l.why}</div>
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

export const EvidenceCard: React.FC = () => {
  const artifact = useWorkbenchStore((s) => s.selectedArtifact);
  const setSelectedArtifact = useWorkbenchStore((s) => s.setSelectedArtifact);
  const fetchHex = useWorkbenchStore((s) => s.fetchHexWindowForOffset);
  const findings = useFindings();
  const tzMode = usePreferences((s) => s.timeZone);
  const setPref = usePreferences((s) => s.set);
  const [tab, setTab] = useState<CardTab>('DETAILS');
  const [note, setNote] = useState('');
  const [copied, setCopied] = useState(false);

  React.useEffect(() => {
    setNote('');
    setTab('DETAILS');
  }, [artifact?.id]);

  const provForBytes = artifact?.provenance;
  React.useEffect(() => {
    if (tab === 'BYTES' && provForBytes) void fetchHex(provForBytes);
  }, [tab, artifact?.id, provForBytes, fetchHex]);

  if (!artifact) {
    return (
      <div className="h-full flex flex-col items-center justify-center text-center p-6 text-slate-400">
        <p className="text-slate-200 font-medium mb-1">No record selected</p>
        <p className="max-w-[16rem]">Select a row anywhere. Its fields, where it came from in the evidence file, and its raw bytes appear here.</p>
      </div>
    );
  }

  const prov = artifact.provenance;
  const raw = (artifact.rawData ?? {}) as Record<string, unknown>;
  const kind = kindOf(artifact);
  const pinned = findings.findings.find((f) => f.kind === kind && f.record_id === artifact.id);
  const body = (raw.body ?? raw.Message_Body ?? raw.Message_Text) as string | undefined;

  const fields = Object.entries(raw).filter(([k, v]) => !HIDDEN_KEYS.has(k) && k !== 'body' && !(typeof v === 'object' && v !== null && !Array.isArray(v) && 'utcIso' in (v as object)));
  const t = artifact.timestamp;
  const localTime: TimestampTriplet | null | undefined = artifact.timestamp;

  const copyJson = () => {
    try {
      void navigator.clipboard.writeText(JSON.stringify(raw, null, 2));
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      setCopied(false);
    }
  };

  const doPin = () => findings.pin(buildPin(artifact, note));

  const tabs: Array<[CardTab, string]> = [['DETAILS', 'Details'], ['BYTES', 'Source bytes'], ['LINKS', 'Links']];

  return (
    <div className="h-full flex flex-col min-h-0">
      <header className="px-4 pt-3 pb-2 border-b border-slate-800 shrink-0">
        <div className="flex items-start justify-between gap-2">
          <div className="min-w-0">
            <div className="text-slate-400 text-[0.6875rem] uppercase tracking-wider">{artifact.itemType || 'Record'}</div>
            <h2 className="text-slate-50 font-semibold break-words leading-snug">{titleOf(artifact)}</h2>
          </div>
          <button onClick={() => void setSelectedArtifact(null)} className="p-1 rounded text-slate-400 hover:text-slate-100 hover:bg-slate-800" aria-label="Clear selection">
            <X className="w-4 h-4" />
          </button>
        </div>
        <div role="tablist" aria-label="Evidence card sections" className="flex gap-1 mt-2">
          {tabs.map(([id, label]) => (
            <button
              key={id}
              role="tab"
              aria-selected={tab === id}
              onClick={() => setTab(id)}
              className={`px-2.5 py-1 rounded text-[0.75rem] ${tab === id ? 'bg-slate-700 text-slate-50 font-semibold' : 'text-slate-300 hover:bg-slate-800'}`}
            >
              {label}
            </button>
          ))}
        </div>
      </header>

      <div className="flex-1 overflow-y-auto p-4 select-text min-h-0">
        {tab === 'DETAILS' && (
          <>
            {typeof body === 'string' && body && (
              <Section title="Content">
                <pre className="whitespace-pre-wrap break-words font-sans text-slate-100 bg-slate-900 border border-slate-800 rounded p-2 max-h-60 overflow-auto">{body}</pre>
              </Section>
            )}
            <Section title="When">
              {hasTime(t) ? (
                <>
                  <Row k={tzMode === 'IST' ? 'IST' : 'UTC'} v={tzMode === 'IST' ? t.istFormatted : t.utcIso} mono />
                  <Row k={tzMode === 'IST' ? 'UTC' : 'IST'} v={tzMode === 'IST' ? t.utcIso : t.istFormatted} mono />
                  <Row k="Raw value" v={show(t.rawValue)} mono />
                  <Row k="Raw format" v={show(t.sourceFormat)} />
                  <button className="text-cyan-400 hover:underline mt-1" onClick={() => setPref({ timeZone: tzMode === 'IST' ? 'UTC' : 'IST' })}>
                    Show {tzMode === 'IST' ? 'UTC' : 'IST'} first
                  </button>
                </>
              ) : localTime?.localClock ? (
                <>
                  <Row k="Clock time as recorded" v={localTime.localClock} mono />
                  <Row k="Time zone" v="Not recorded (no UTC or IST time is claimed)" />
                  <Row k="Raw value" v={show(localTime.rawValue)} mono />
                </>
              ) : (
                <Row k="Time" v={NOT_RECORDED} />
              )}
            </Section>
            <Section title="Where it came from">
              {prov ? (
                <>
                  <Row k="File" v={show(prov.vfsInternalPath)} mono />
                  <Row k="Container" v={show(prov.containerType)} />
                  <Row k="Table" v={show(prov.tableName)} />
                  <Row k="Row" v={show(prov.rowId)} />
                  <Row k="Page" v={prov.pageNumber ? String(prov.pageNumber) : NOT_RECORDED} />
                  <Row k="Byte offset" v={offsetText(prov)} mono />
                  <Row k="Length" v={prov.byteOffset >= 0 && prov.byteLength > 0 ? `${prov.byteLength} bytes` : NOT_RECORDED} />
                  <Row k="Recovery state" v={show(prov.recoveryState)} />
                </>
              ) : (
                <Row k="Source" v={NOT_RECORDED} />
              )}
            </Section>
            <Section title="Fields">
              {fields.length === 0 ? <Row k="Fields" v={NOT_RECORDED} /> : fields.map(([k, v]) => <Row key={k} k={words(k)} v={show(v)} />)}
            </Section>
          </>
        )}
        {tab === 'BYTES' && (
          <div className="h-[28rem] border border-slate-800 rounded overflow-hidden">
            <SyncedHexViewer embedded />
          </div>
        )}
        {tab === 'LINKS' && <LinksTab artifact={artifact} />}
      </div>

      <footer className="border-t border-slate-800 p-3 shrink-0 bg-slate-900">
        {pinned ? (
          <div className="flex items-center justify-between gap-2">
            <span className="text-emerald-300">Pinned to findings{pinned.note ? `: ${pinned.note}` : ''}</span>
            <button onClick={() => void findings.unpin(pinned.id)} className="flex items-center gap-1 px-2 py-1 rounded border border-slate-700 text-slate-200 hover:bg-slate-800">
              <PinOff className="w-4 h-4" /> Unpin
            </button>
          </div>
        ) : (
          <div className="flex items-end gap-2">
            <label className="flex-1 min-w-0">
              <span className="sr-only">Note for this finding</span>
              <input
                value={note}
                onChange={(e) => setNote(e.target.value)}
                placeholder="Why this matters (optional)"
                className="w-full h-8 px-2 rounded bg-slate-950 border border-slate-700 text-slate-100 placeholder-slate-500"
              />
            </label>
            <button onClick={() => void doPin()} className="flex items-center gap-1 px-3 h-8 rounded bg-cyan-600 text-slate-50 hover:bg-cyan-500 font-medium" title="Pin to findings (Ctrl+B)">
              <Pin className="w-4 h-4" /> Pin
            </button>
            <button onClick={copyJson} className="flex items-center gap-1 px-2 h-8 rounded border border-slate-700 text-slate-200 hover:bg-slate-800" title="Copy the record as JSON">
              <Copy className="w-4 h-4" /> {copied ? 'Copied' : 'Copy'}
            </button>
          </div>
        )}
        {findings.error && <p className="mt-2 text-rose-300">{findings.error}</p>}
      </footer>
    </div>
  );
};

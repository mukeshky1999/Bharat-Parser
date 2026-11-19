import React, { useMemo, useState } from 'react';
import { Banknote, Copy, FileText, MessageSquare, Pin, PinOff, X } from 'lucide-react';
import { Button, Chip, GroupTile, KeyValue, Tabs } from '../components/ui';
import { useWorkbenchStore, SelectedArtifactState } from '../state/workbenchStore';
import { useFindings } from '../state/findingsStore';
import { usePreferences } from '../state/preferencesStore';
import { SyncedHexViewer } from './SyncedHexViewer';
import { TagControls } from './TagControls';
import { caseRecordOf } from '../utils/caseRecord';
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

type Item = [string, React.ReactNode];

function val(v: string, mono?: boolean): React.ReactNode {
  return v === NOT_RECORDED
    ? <span className="text-faint italic">{v}</span>
    : <span className={mono ? 'font-mono text-[0.75rem]' : ''}>{v}</span>;
}

function Section({ title, items, bordered }: { title: string; items: Item[]; bordered?: boolean }) {
  return (
    <section className={bordered ? 'mb-4 border border-line bg-sunken rounded-lg p-3' : 'mb-4'}>
      <h3 className="text-[0.6875rem] font-semibold uppercase tracking-wider text-muted mb-2">{title}</h3>
      <KeyValue items={items} />
    </section>
  );
}

function tileFor(a: SelectedArtifactState) {
  const t = (a.itemType || '').toLowerCase();
  if (/upi|bank|transaction|crypto|wallet/.test(t)) return { hue: 'money' as const, icon: Banknote };
  if (/chat|message|sms|call|contact/.test(t)) return { hue: 'comm' as const, icon: MessageSquare };
  return { hue: 'accent' as const, icon: FileText };
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
    const cpty = raw.counterpartyVpa || raw.payeeVpa || raw.payerVpa || null;
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
      <p className="text-muted mb-3">Records that share this record&apos;s UTR or counterparty VPA, matched exactly. These are leads to check, not proof that the records belong together.</p>
      {links.length === 0 ? (
        <p className="text-faint italic">No exact matches found for this record.</p>
      ) : (
        <ul className="space-y-1">
          {links.map((l, i) => (
            <li key={i}>
              <button onClick={l.open} className="w-full text-left rounded-lg px-2.5 py-1.5 bg-surface hover:bg-hover border border-line">
                <div className="text-ink">{l.label}</div>
                <div className="text-muted">{l.why}</div>
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
      <div className="h-full flex flex-col items-center justify-center text-center p-6 text-muted">
        <p className="text-ink font-medium mb-1">No record selected</p>
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

  const tile = tileFor(artifact);
  const isRecovered = !!prov && prov.recoveryState !== 'ACTIVE';
  const subLine = hasTime(t) ? (tzMode === 'IST' ? t.istFormatted : t.utcIso) : `Record ${artifact.id}`;

  const doPin = () => findings.pin(buildPin(artifact, note));

  const tabs: Array<[CardTab, string]> = [['DETAILS', 'Details'], ['BYTES', 'Source bytes'], ['LINKS', 'Links']];

  return (
    <div className="h-full flex flex-col min-h-0">
      <header className="px-4 pt-3 shrink-0">
        <div className="flex items-start justify-between gap-2">
          <div className="flex items-start gap-2.5 min-w-0">
            <GroupTile hue={tile.hue} icon={tile.icon} size="lg" />
            <div className="min-w-0">
              <div className="text-muted text-[0.6875rem] uppercase tracking-wider">{artifact.itemType || 'Record'}</div>
              <h2 className="text-base font-semibold break-words leading-snug">{titleOf(artifact)}</h2>
              <div className="flex items-center gap-2 mt-1 text-muted text-[0.75rem] flex-wrap">
                <span>{subLine}</span>
                {isRecovered && <Chip tone="rec">Recovered · {show(prov?.recoveryState)}</Chip>}
              </div>
            </div>
          </div>
          <button onClick={() => void setSelectedArtifact(null)} className="p-1 rounded text-muted hover:text-ink hover:bg-hover" aria-label="Clear selection">
            <X className="w-4 h-4" />
          </button>
        </div>
      </header>
      <Tabs label="Evidence card sections" value={tab} onChange={(v) => setTab(v as CardTab)} tabs={tabs.map(([value, label]) => ({ value, label }))} />

      <div className="flex-1 overflow-y-auto p-4 select-text min-h-0">
        {tab === 'DETAILS' && (
          <>
            {typeof body === 'string' && body && (
              <section className="mb-4">
                <h3 className="text-[0.6875rem] font-semibold uppercase tracking-wider text-muted mb-2">Content</h3>
                <pre className="whitespace-pre-wrap break-words font-sans text-ink bg-sunken border border-line rounded-lg p-2.5 max-h-60 overflow-auto">{body}</pre>
              </section>
            )}
            <section className="mb-4">
              <h3 className="text-[0.6875rem] font-semibold uppercase tracking-wider text-muted mb-2">When</h3>
              {hasTime(t) ? (
                <>
                  <KeyValue items={[
                    [tzMode === 'IST' ? 'IST' : 'UTC', val(tzMode === 'IST' ? t.istFormatted : t.utcIso, true)],
                    [tzMode === 'IST' ? 'UTC' : 'IST', val(tzMode === 'IST' ? t.utcIso : t.istFormatted, true)],
                    ['Raw value', val(show(t.rawValue), true)],
                    ['Raw format', val(show(t.sourceFormat))],
                  ]} />
                  <button className="text-accent-ink hover:underline mt-1" onClick={() => setPref({ timeZone: tzMode === 'IST' ? 'UTC' : 'IST' })}>
                    Show {tzMode === 'IST' ? 'UTC' : 'IST'} first
                  </button>
                </>
              ) : localTime?.localClock ? (
                <KeyValue items={[
                  ['Clock time as recorded', val(localTime.localClock, true)],
                  ['Time zone', val('Not recorded (no UTC or IST time is claimed)')],
                  ['Raw value', val(show(localTime.rawValue), true)],
                ]} />
              ) : (
                <KeyValue items={[['Time', val(NOT_RECORDED)]]} />
              )}
            </section>
            {caseRecordOf(artifact.id, artifact.itemType) && (
              <section className="mb-4">
                <h3 className="text-[0.6875rem] font-semibold uppercase tracking-wider text-muted mb-1">Tags</h3>
                <TagControls key={artifact.id} record={caseRecordOf(artifact.id, artifact.itemType)!} />
              </section>
            )}
            <Section title="Fields" items={fields.length === 0 ? [['Fields', val(NOT_RECORDED)]] : fields.map(([k, v]): Item => [words(k), val(show(v))])} />
            <Section title="Where it came from" bordered items={prov ? [
              ['File', val(show(prov.vfsInternalPath), true)],
              ['Container', val(show(prov.containerType))],
              ['Table', val(show(prov.tableName))],
              ['Row', val(show(prov.rowId))],
              ['Page', val(prov.pageNumber ? String(prov.pageNumber) : NOT_RECORDED)],
              ['Byte offset', val(offsetText(prov), true)],
              ['Length', val(prov.byteOffset >= 0 && prov.byteLength > 0 ? `${prov.byteLength} bytes` : NOT_RECORDED)],
              ['Recovery state', val(show(prov.recoveryState))],
            ] : [['Source', val(NOT_RECORDED)]]} />
          </>
        )}
        {tab === 'BYTES' && (
          <div className="h-[28rem] border border-line rounded-lg overflow-hidden">
            <SyncedHexViewer embedded />
          </div>
        )}
        {tab === 'LINKS' && <LinksTab artifact={artifact} />}
      </div>

      <footer className="border-t border-line p-3 shrink-0 bg-sunken">
        {pinned ? (
          <div className="flex items-center justify-between gap-2">
            <span className="text-ok">Pinned to findings{pinned.note ? `: ${pinned.note}` : ''}</span>
            <Button onClick={() => void findings.unpin(pinned.id)}><PinOff className="w-4 h-4" /> Unpin</Button>
          </div>
        ) : (
          <div className="flex items-end gap-2">
            <label className="flex-1 min-w-0">
              <span className="sr-only">Note for this finding</span>
              <input
                value={note}
                onChange={(e) => setNote(e.target.value)}
                placeholder="Why this matters (optional)"
                className="w-full h-8 px-2.5 rounded-lg bg-surface border border-line-strong text-ink placeholder:text-faint"
              />
            </label>
            <Button variant="primary" onClick={() => void doPin()} title="Pin to findings (Ctrl+B)"><Pin className="w-4 h-4" /> Pin</Button>
            <Button onClick={copyJson} title="Copy the record as JSON"><Copy className="w-4 h-4" /> {copied ? 'Copied' : 'Copy'}</Button>
          </div>
        )}
        {findings.error && <p className="mt-2 text-rec">{findings.error}</p>}
      </footer>
    </div>
  );
};

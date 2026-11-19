import React from 'react';
import { useWorkbenchStore } from '../state/workbenchStore';
import { usePreferences } from '../state/preferencesStore';
import { caseRecordOf } from '../utils/caseRecord';
import { DataGrid, GridColumn, Unset } from '../workspace/DataGrid';
import { PartyBrowser } from '../workspace/PartyBrowser';
import { RecordTable } from '../workspace/RecordTable';
import type { CallLogArtifact } from '../../shared/forensic-types';

const NO_NUMBER = 'Number not recorded';
const DIRECTION_TEXT: Record<string, string> = { INCOMING: 'Incoming', OUTGOING: 'Outgoing', MISSED: 'Missed', REJECTED: 'Rejected', UNKNOWN: 'Not recorded' };
const RECOVERY_TEXT: Record<string, string> = { ACTIVE: 'In database', WAL_RECOVERED: 'Recovered from log', CARVED_UNALLOCATED: 'Carved from free space', OS_SPILLOVER: 'System trace' };

const last10 = (v: string): string => v.replace(/\D/g, '').slice(-10);
const hasDuration = (c: CallLogArtifact) => Number.isFinite(c.durationSeconds) && c.durationSeconds >= 0;
const clock = (s: number) => `${String(Math.floor(s / 60)).padStart(2, '0')}:${String(s % 60).padStart(2, '0')}`;
const isRecovered = (c: CallLogArtifact) => !!c.provenance && c.provenance.recoveryState !== 'ACTIVE';

/** The other party as recorded, whatever the direction. */
const partyOf = (c: CallLogArtifact): string =>
  (c.peerNumberOrId || (c.direction === 'OUTGOING' ? c.calleeNumberOrId : c.direction === 'INCOMING' ? c.callerNumberOrId : '') || '').trim() || NO_NUMBER;

/** Calls: grouped by the number on the other end (the default), or the plain table of every call. */
export const CallsView: React.FC = () => {
  const callLogs = useWorkbenchStore((s) => s.callLogs);
  const contacts = useWorkbenchStore((s) => s.contacts);
  const upi = useWorkbenchStore((s) => s.upiTransactions);
  const selected = useWorkbenchStore((s) => s.selectedArtifact);
  const setSelectedArtifact = useWorkbenchStore((s) => s.setSelectedArtifact);
  const tz = usePreferences((s) => s.timeZone);
  usePreferences((s) => s.hiddenColumns);

  const timeText = (c: CallLogArtifact): string => {
    const t = c.timestamp;
    return t?.utcIso && t.epochMs > 0 ? (tz === 'IST' ? t.istFormatted : t.utcIso) : 'not recorded';
  };

  const columns: Array<GridColumn<CallLogArtifact>> = [
    { key: 'time', label: tz === 'IST' ? 'Time (IST)' : 'Time (UTC)', width: '14rem', cell: (c) => (timeText(c) === 'not recorded' ? <Unset /> : timeText(c)), text: timeText },
    { key: 'direction', label: 'Direction', width: '7rem', cell: (c) => DIRECTION_TEXT[c.direction] ?? 'Not recorded', text: (c) => DIRECTION_TEXT[c.direction] ?? 'not recorded' },
    { key: 'duration', label: 'Duration', width: '6rem', align: 'right', cell: (c) => (hasDuration(c) ? clock(c.durationSeconds) : <Unset />), text: (c) => (hasDuration(c) ? `${c.durationSeconds}s` : 'not recorded') },
    { key: 'result', label: 'Result', width: '8rem', cell: (c) => c.callResult || <Unset />, text: (c) => c.callResult || 'not recorded' },
    { key: 'app', label: 'App', width: '8rem', cell: (c) => c.sourceApp || <Unset />, text: (c) => c.sourceApp || 'not recorded' },
    { key: 'recovery', label: 'Source state', width: '11rem', cell: (c) => RECOVERY_TEXT[c.provenance?.recoveryState] ?? <Unset />, text: (c) => RECOVERY_TEXT[c.provenance?.recoveryState] ?? 'not recorded' },
  ];

  const select = (c: CallLogArtifact) => {
    void setSelectedArtifact({ id: c.id, provenance: c.provenance, timestamp: c.timestamp, itemType: 'Call record', rawData: c });
  };

  const grid = (rs: CallLogArtifact[]) => (
    <DataGrid<CallLogArtifact>
      tags={{ table: 'calls', idOf: (c) => caseRecordOf(c.id)?.id ?? null }}
      tableId="calls_by_person" title="Calls" columns={columns} rows={rs} rowKey={(c, i) => c.id || `call-${i}`}
      selectedKey={selected?.id ?? null} onSelect={select} exportName="calls_person.csv" empty="No call was found for this number."
    />
  );

  const partyLabel = (id: string) => {
    const d = last10(id);
    const c = d.length >= 7 ? contacts.find((x) => x.displayName && last10(x.identifier || '') === d) : undefined;
    return c ? { name: c.displayName, note: 'Saved contact' } : { name: id, note: id === NO_NUMBER ? undefined : 'No saved contact for this number' };
  };

  const alsoFoundIn = (id: string) => {
    const d = last10(id);
    if (d.length < 10) return [];
    const n = upi.filter((t) => [t.counterpartyVpa, t.payerVpa, t.payeeVpa].some((v) => !!v && String(v).split('@')[0] === d)).length;
    return n > 0 ? [{ tab: 'UPI_LEDGER' as const, label: `UPI ledger (${n})` }] : [];
  };

  const talk = (rs: CallLogArtifact[]) => rs.filter(hasDuration).reduce((a, c) => a + c.durationSeconds, 0);
  const apps = [...new Set(callLogs.map((c) => c.sourceApp || 'App not recorded'))].sort();
  const stamp = (c: CallLogArtifact) => (c.timestamp?.utcIso && c.timestamp.epochMs > 0 ? c.timestamp.epochMs : 0);

  return (
    <PartyBrowser<CallLogArtifact>
      rows={callLogs} appOf={(c) => c.sourceApp || 'App not recorded'} partyOf={partyOf} partyLabel={partyLabel} isRecovered={isRecovered}
      apps={apps} idLabel="Number" unit={{ one: 'call', many: 'calls' }}
      listSummary={(rs) => <span className="flex flex-col"><b className="text-ink font-semibold">{clock(talk(rs))}</b>talk time</span>}
      facts={(rs) => {
        const timed = rs.filter((c) => stamp(c) > 0).sort((a, b) => stamp(b) - stamp(a));
        return [
          ['Calls', rs.length.toLocaleString()],
          ['Incoming', rs.filter((c) => c.direction === 'INCOMING').length],
          ['Outgoing', rs.filter((c) => c.direction === 'OUTGOING').length],
          ['Missed', rs.filter((c) => c.direction === 'MISSED').length],
          ['Talk time', clock(talk(rs))],
          ['Last', timed.length ? timeText(timed[0]) : 'not recorded'],
        ];
      }}
      alsoFoundIn={alsoFoundIn}
      renderRows={grid}
      renderAll={() => <RecordTable title="Calls" category="CALLS" />}
    />
  );
};

import React, { useMemo, useState } from 'react';
import { useWorkbenchStore } from '../state/workbenchStore';
import { usePreferences } from '../state/preferencesStore';
import { CallLogArtifact, TimestampTriplet } from '../../shared/forensic-types';
import { formatOffset } from '../utils/csv';
import { caseRecordOf } from '../utils/caseRecord';
import { DataGrid, FilterInput, GridColumn, Segmented, Unset } from '../workspace/DataGrid';
import { SavedFilters } from '../workspace/SavedFilters';

type Kind = 'ALL' | 'CELLULAR' | 'VOIP';
type Dir = 'ALL' | 'INCOMING' | 'OUTGOING' | 'MISSED';

const DIRECTION_TEXT: Record<string, string> = { INCOMING: 'Incoming', OUTGOING: 'Outgoing', MISSED: 'Missed', REJECTED: 'Rejected', UNKNOWN: 'Not established' };
const RECOVERY_TEXT: Record<string, string> = { ACTIVE: 'In database', WAL_RECOVERED: 'Recovered from log', CARVED_UNALLOCATED: 'Carved from free space', OS_SPILLOVER: 'System trace' };
const present = (s?: string | null) => (s && s.trim() && s.toLowerCase() !== 'unknown' ? s : '');

const hasTime = (t?: TimestampTriplet) => !!t && !!t.utcIso && t.epochMs > 0;

function duration(c: CallLogArtifact): string {
  const s = c.durationSeconds;
  if (!Number.isFinite(s) || s < 0) return '';
  return `${Math.floor(s / 60)} min ${s % 60} s`;
}

/** Calls found on the device: cellular records and calls made through apps. A value that was not recorded says so. */
export const CallLogsView: React.FC = () => {
  const callLogs = useWorkbenchStore((s) => s.callLogs);
  const selected = useWorkbenchStore((s) => s.selectedArtifact);
  const setSelectedArtifact = useWorkbenchStore((s) => s.setSelectedArtifact);
  const tz = usePreferences((s) => s.timeZone);
  const [kind, setKind] = useState<Kind>('ALL');
  const [dir, setDir] = useState<Dir>('ALL');
  const [query, setQuery] = useState('');

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase();
    return callLogs.filter((c) => {
      if (kind === 'CELLULAR' && c.callType !== 'CELLULAR_CDR') return false;
      if (kind === 'VOIP' && c.callType !== 'VOIP_APP') return false;
      if (dir !== 'ALL' && c.direction !== dir) return false;
      if (!q) return true;
      return [c.callerNumberOrId, c.callerName, c.calleeNumberOrId, c.calleeName, c.sourceApp, c.callResult].some((v) => !!v && String(v).toLowerCase().includes(q));
    });
  }, [callLogs, kind, dir, query]);

  const timeText = (c: CallLogArtifact) => (hasTime(c.timestamp) ? (tz === 'IST' ? c.timestamp.istFormatted.substring(0, 19) : c.timestamp.utcIso.substring(0, 19)) : c.timestamp?.localClock ? `${c.timestamp.localClock.substring(0, 19)} (zone not recorded)` : '');
  const party = (num: string, name?: string) => [present(name), present(num)].filter(Boolean).join(' · ');

  const columns: Array<GridColumn<CallLogArtifact>> = [
    { key: 'time', label: tz === 'IST' ? 'Time (IST)' : 'Time (UTC)', width: '19rem', cell: (c) => timeText(c) || <Unset />, text: (c) => timeText(c) || 'not recorded' },
    { key: 'app', label: 'App', width: '8rem', cell: (c) => present(c.sourceApp) || <Unset />, text: (c) => present(c.sourceApp) || 'not recorded' },
    { key: 'kind', label: 'Kind', width: '8rem', cell: (c) => (c.callType === 'VOIP_APP' ? 'App call' : 'Cellular'), text: (c) => (c.callType === 'VOIP_APP' ? 'App call' : 'Cellular') },
    { key: 'direction', label: 'Direction', width: '8rem', cell: (c) => DIRECTION_TEXT[c.direction] ?? <Unset />, text: (c) => DIRECTION_TEXT[c.direction] ?? 'not recorded' },
    { key: 'from', label: 'From', width: 'minmax(10rem,1fr)', cell: (c) => party(c.callerNumberOrId, c.callerName) || <Unset />, text: (c) => party(c.callerNumberOrId, c.callerName) || 'not recorded' },
    { key: 'to', label: 'To', width: 'minmax(10rem,1fr)', cell: (c) => party(c.calleeNumberOrId, c.calleeName) || <Unset />, text: (c) => party(c.calleeNumberOrId, c.calleeName) || 'not recorded' },
    { key: 'duration', label: 'Duration', width: '8rem', align: 'right', cell: (c) => duration(c) || <Unset />, text: (c) => duration(c) || 'not recorded' },
    { key: 'result', label: 'Result', width: '8rem', cell: (c) => present(c.callResult) || <Unset />, text: (c) => present(c.callResult) || 'not recorded' },
    { key: 'where', label: 'Where found', width: '11rem', cell: (c) => RECOVERY_TEXT[c.provenance?.recoveryState ?? ''] ?? <Unset />, text: (c) => RECOVERY_TEXT[c.provenance?.recoveryState ?? ''] ?? 'not recorded' },
    { key: 'table', label: 'Source table', width: '10rem', cell: (c) => c.provenance?.tableName || <Unset />, text: (c) => c.provenance?.tableName || 'not recorded' },
    { key: 'offset', label: 'Byte offset', width: '9rem', cell: (c) => formatOffset(c.provenance?.byteOffset), text: (c) => formatOffset(c.provenance?.byteOffset) },
  ];

  const state = { kind, dir, query };
  const apply = (s: Partial<typeof state>) => { setKind((s.kind as Kind) ?? 'ALL'); setDir((s.dir as Dir) ?? 'ALL'); setQuery(s.query ?? ''); };

  return (
    <DataGrid<CallLogArtifact>
      tags={{ table: 'calls', idOf: (c) => caseRecordOf(c.id)?.id ?? null }}
      tableId="calls" title="Calls on the device" columns={columns} rows={rows} totalBeforeFilter={callLogs.length}
      rowKey={(c) => c.id} selectedKey={selected?.id ?? null} exportName="calls.csv"
      onSelect={(c) => void setSelectedArtifact({ id: c.id, provenance: c.provenance, timestamp: c.timestamp, itemType: 'Call record', rawData: c })}
      toolbar={(
        <>
          <FilterInput label="Search calls" value={query} onChange={setQuery} placeholder="Number, name, app…" />
          <Segmented<Kind> label="Kind" value={kind} onChange={setKind} options={[{ value: 'ALL', label: 'All' }, { value: 'CELLULAR', label: 'Cellular' }, { value: 'VOIP', label: 'App calls' }]} />
          <Segmented<Dir> label="Direction" value={dir} onChange={setDir} options={[{ value: 'ALL', label: 'Any' }, { value: 'INCOMING', label: 'Incoming' }, { value: 'OUTGOING', label: 'Outgoing' }, { value: 'MISSED', label: 'Missed' }]} />
          <SavedFilters scope="calls" current={state} onApply={apply} isDefault={kind === 'ALL' && dir === 'ALL' && !query} />
        </>
      )}
      empty={callLogs.length === 0 ? 'No calls were found in the evidence, or no case is open.' : 'No call matches these filters.'}
    />
  );
};

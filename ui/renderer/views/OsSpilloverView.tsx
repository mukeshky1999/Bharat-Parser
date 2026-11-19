import React, { useEffect, useMemo, useState } from 'react';
import { useWorkbenchStore, parseProvenance } from '../state/workbenchStore';
import { fetchAllRows } from '../utils/artifactRows';
import { DataGrid, FilterInput, GridColumn, Unset } from '../workspace/DataGrid';

type Row = Record<string, any>;
const recoveredLabel = (v: unknown) => { const u = String(v ?? '').toUpperCase(); return u.includes('WAL') ? 'Recovered from log' : /CARVED|FREELIST|SLACK/.test(u) ? 'Carved from free space' : null; };

const text = (v: unknown) => (v === null || v === undefined || v === '' ? '' : String(v));
const cell = (v: unknown) => (text(v) ? text(v) : <Unset />);

/**
 * Traces the operating system kept outside the apps' own databases (notification logs, keyboard caches, clipboard,
 * app-switcher snapshots, usage history), as the case holds them. Each row is what was recorded; the tool does not
 * rank any row as more valuable than another.
 */
export const OsSpilloverView: React.FC = () => {
  const manifest = useWorkbenchStore((s) => s.caseManifest);
  const selected = useWorkbenchStore((s) => s.selectedArtifact);
  const setSelectedArtifact = useWorkbenchStore((s) => s.setSelectedArtifact);
  const [rows, setRows] = useState<Row[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [query, setQuery] = useState('');

  useEffect(() => {
    if (!manifest) { setRows([]); return; }
    const ctl = new AbortController();
    setLoading(true); setError(''); setRows([]);
    fetchAllRows('os_spillover', ctl.signal)
      .then((r) => { if (!ctl.signal.aborted) setRows(r); })
      .catch((e) => { if (e?.name !== 'AbortError' && !ctl.signal.aborted) setError(e?.message || 'The traces could not be loaded.'); })
      .finally(() => { if (!ctl.signal.aborted) setLoading(false); });
    return () => ctl.abort();
  }, [manifest?.caseId, manifest?.evidenceFileName]); // eslint-disable-line react-hooks/exhaustive-deps

  const shown = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return rows;
    return rows.filter((r) => Object.values(r).some((v) => v !== null && String(v).toLowerCase().includes(q)));
  }, [rows, query]);

  const columns: Array<GridColumn<Row>> = [
    { key: 'time', label: 'Time (IST)', width: '14rem', cell: (r) => cell(text(r.Timestamp_IST).substring(0, 19)), text: (r) => text(r.Timestamp_IST).substring(0, 19) || 'not recorded' },
    { key: 'vector', label: 'Kind of trace', width: '13rem', cell: (r) => cell(r.Vector_Type), text: (r) => text(r.Vector_Type) || 'not recorded' },
    { key: 'pkg', label: 'App package', width: '14rem', cell: (r) => cell(r.Package_Name), text: (r) => text(r.Package_Name) || 'not recorded' },
    { key: 'snippet', label: 'Text recorded', width: 'minmax(20rem,3fr)', cell: (r) => cell(r.Content_Snippet), text: (r) => text(r.Content_Snippet) || 'not recorded' },
    { key: 'entity', label: 'Value found in it', width: '14rem', cell: (r) => cell(r.Extracted_Entity), text: (r) => text(r.Extracted_Entity) || 'not recorded' },
    { key: 'device', label: 'Device', width: '7rem', cell: (r) => cell(r.Evidence_Item), text: (r) => text(r.Evidence_Item) || 'not recorded' },
    { key: 'prov', label: 'Where it came from', width: 'minmax(12rem,1fr)', cell: (r) => cell(r.Forensic_Provenance), text: (r) => text(r.Forensic_Provenance) || 'not recorded' },
  ];

  const select = (r: Row) => {
    const summary = { case_id: manifest?.caseId ?? '', evidence_path: manifest?.evidencePath ?? '' };
    void setSelectedArtifact({
      id: `SPILL_${r.id}`,
      provenance: parseProvenance(r.Forensic_Provenance, summary, 'os_spillover', ''),
      itemType: 'Device trace',
      notes: `${text(r.Vector_Type) || 'Kind of trace not recorded'}${text(r.Package_Name) ? ` · ${text(r.Package_Name)}` : ''}`,
      rawData: r,
    });
  };

  return (
    <div className="flex-1 flex flex-col min-w-0 min-h-0 bg-page p-4 gap-3">
      {error && <p role="alert" className="shrink-0 text-rec">{error} What is listed below may be incomplete.</p>}
      {loading ? <div className="flex-1 p-10 text-center text-muted" role="status">Loading device traces…</div> : (
        <div className="card flex-1 flex flex-col min-h-0 overflow-hidden">
        <DataGrid<Row>
          recoveredOf={(r) => recoveredLabel(r.Forensic_Provenance)}
          tags={{ table: 'os_spillover', idOf: (r) => (Number.isFinite(Number(r.id)) ? Number(r.id) : null) }}
          tableId="os_spillover" title="Device traces outside the apps" columns={columns} rows={shown} totalBeforeFilter={rows.length}
          rowKey={(r, i) => `s${r.id ?? i}`} selectedKey={selected?.id?.startsWith('SPILL_') ? `s${selected.id.slice(6)}` : null}
          onSelect={select} exportName="device_traces.csv"
          toolbar={<FilterInput label="Search the traces" value={query} onChange={setQuery} placeholder="App, text, value…" />}
          empty={rows.length === 0 ? (manifest ? 'No device trace was found in the evidence, or the reader found none.' : 'No case is open.') : 'No trace matches the search.'}
        />
        </div>
      )}
    </div>
  );
};

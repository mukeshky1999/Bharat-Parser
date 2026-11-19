import React, { useState, useEffect } from 'react';
import { Database, Search, RefreshCw, Table as TableIcon, KeyRound } from 'lucide-react';
import { ViewHeader, Card, Button, EmptyState } from '../components/ui';
import { forensicClient } from '../api/forensicClient';
import { useWorkbenchStore } from '../state/workbenchStore';
import { ForensicProvenance } from '../../shared/forensic-types';

interface SQLiteWizardTabProps {
  onSelectRecordProvenance?: (prov: ForensicProvenance) => void;
  initialDbPath?: string;
}

export const SQLiteWizardTab: React.FC<SQLiteWizardTabProps> = ({
  onSelectRecordProvenance,
  initialDbPath
}) => {
  const store = useWorkbenchStore();
  const [selectedDb, setSelectedDb] = useState<string>(initialDbPath || '');
  const [availableDbs, setAvailableDbs] = useState<string[]>([]);
  const [tables, setTables] = useState<Array<{ table_name: string; row_count: number; columns: string[] }>>([]);
  const [selectedTable, setSelectedTable] = useState<string>('');
  const [rows, setRows] = useState<any[]>([]);
  const [kvPairs, setKvPairs] = useState<any[]>([]);
  const [activeSubTab, setActiveSubTab] = useState<'TABLE' | 'KV'>('TABLE');
  const [loading, setLoading] = useState<boolean>(false);
  const [tableSearch, setTableSearch] = useState<string>('');

  // 1. Fetch list of SQLite files from case VFS
  useEffect(() => {
    const fetchDbs = async () => {
      try {
        const res = await forensicClient.queryArtifacts('vfs_files', undefined, undefined, undefined, '.db', 100, 0);
        if (res && res.rows) {
          const dbPaths = res.rows
            .map((r: any) => r.file_path || r.path || r.name || '')
            .filter((p: string) => p.endsWith('.db') || p.endsWith('.sqlite'));
          setAvailableDbs(dbPaths);
          if (!selectedDb && dbPaths.length > 0) {
            setSelectedDb(dbPaths[0]);
          }
        }
      } catch {
        // Fallback
      }
    };
    fetchDbs();
  }, [store.caseManifest]);

  // 2. Inspect selected SQLite DB
  const inspectCurrentDb = async (dbPath: string, table?: string) => {
    if (!dbPath) return;
    setLoading(true);
    try {
      const res = await forensicClient.inspectSqlite(dbPath, table, 100);
      if (res && res.success) {
        setTables(res.tables || []);
        const activeTbl = table || res.selected_table || (res.tables && res.tables[0]?.table_name) || '';
        setSelectedTable(activeTbl);
        setRows(res.rows || []);
        setKvPairs(res.kv_pairs || []);
      }
    } catch {
      // Fallback
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (selectedDb) {
      inspectCurrentDb(selectedDb, selectedTable);
    }
  }, [selectedDb]);

  const handleTableSelect = (tblName: string) => {
    setSelectedTable(tblName);
    inspectCurrentDb(selectedDb, tblName);
  };

  const handleRowClick = (row: any, idx: number) => {
    const rowId = row.rowid || row.id || row._id || idx + 1;
    const prov: ForensicProvenance = {
      evidenceId: store.caseManifest?.caseNumber || store.caseManifest?.caseId || 'SQLITE_CASE',
      archivePath: store.caseManifest?.evidencePath || selectedDb,
      vfsInternalPath: selectedDb,
      containerType: 'SQLITE',
      tableName: selectedTable,
      pageNumber: Math.floor(idx / 32) + 1,
      rowId: rowId,
      byteOffset: idx * 256,
      byteLength: 256,
      recoveryState: 'ACTIVE',
      rawPayloadHex: ''
    };

    store.setSelectedArtifact({
      id: `SQLITE_${selectedTable}_${rowId}`,
      provenance: prov,
      notes: `SQLite Row: ${selectedTable} [RowID: ${rowId}]`,
      itemType: 'SQLite Database Record',
      rawData: row
    });

    if (onSelectRecordProvenance) {
      onSelectRecordProvenance(prov);
    }
  };

  const filteredTables = tables.filter((t) =>
    t.table_name.toLowerCase().includes(tableSearch.toLowerCase())
  );

  const activeColumns = tables.find((t) => t.table_name === selectedTable)?.columns || (rows.length > 0 ? Object.keys(rows[0]) : []);

  return (
    <div className="flex-1 flex flex-col bg-page p-4 min-h-0 overflow-hidden select-text text-xs">
      {/* 1. Header Toolbar */}
      <ViewHeader title="Database inspector"
        actions={(
          <>
          {selectedDb && (
            <span className="text-[0.6875rem] text-muted font-mono truncate max-w-xs" title={selectedDb}>
              ({selectedDb})
            </span>
          )}
          <div className="flex items-center space-x-1">
            <span className="text-muted text-[0.6875rem]">Database:</span>
            <select
              value={selectedDb}
              onChange={(e) => setSelectedDb(e.target.value)}
              className="bg-surface border border-line-strong text-ink text-xs px-2 h-8 rounded-lg max-w-xs truncate focus:outline-none focus:border-accent font-mono"
            >
              {availableDbs.length === 0 ? (
                <option value="">No SQLite DBs found</option>
              ) : (
                availableDbs.map((p) => (
                  <option key={p} value={p}>
                    {p}
                  </option>
                ))
              )}
            </select>
          </div>

          <Button
            variant="icon"
            onClick={() => inspectCurrentDb(selectedDb, selectedTable)}
            title="Refresh Table Inspection"
            aria-label="Refresh table inspection"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'text-accent' : ''}`} />
          </Button>
          </>
        )} />

      {/* 2. Main Two-Column View: Table Navigator (Left) + Table Grid (Right) */}
      <Card className="flex-1 min-h-0 overflow-hidden flex flex-col" bodyClassName="flex-1 min-h-0 flex overflow-hidden px-0 py-0">
        {/* Left: Table Navigator Sidebar */}
        <div className="w-72 bg-surface border-r border-line flex flex-col shrink-0 select-none">
          <div className="p-2 border-b border-line">
            <div className="relative">
              <Search className="w-3.5 h-3.5 text-faint absolute left-2 top-2 pointer-events-none" />
              <input
                type="text"
                placeholder="Search tables..."
                value={tableSearch}
                onChange={(e) => setTableSearch(e.target.value)}
                className="w-full bg-surface border border-line-strong rounded-lg pl-7 pr-2 py-1 text-xs text-ink placeholder:text-faint focus:outline-none focus:border-accent font-mono"
              />
            </div>
          </div>

          <div className="flex-1 overflow-y-auto p-1 space-y-0.5">
            {filteredTables.length === 0 ? (
              <div className="p-4 text-center text-faint text-xs font-mono">
                {tables.length === 0 ? 'No tables found in database' : 'No matching tables'}
              </div>
            ) : (
              filteredTables.map((t) => {
                const isSelected = selectedTable === t.table_name;
                return (
                  <div
                    key={t.table_name}
                    onClick={() => handleTableSelect(t.table_name)}
                    className={`px-2.5 py-1.5 rounded-lg cursor-pointer flex items-center justify-between font-mono text-xs ${
                      isSelected
                        ? 'bg-accent-soft text-accent-ink font-semibold border border-accent'
                        : 'hover:bg-surface text-ink'
                    }`}
                  >
                    <div className="flex items-center space-x-1.5 truncate">
                      <TableIcon className="w-3.5 h-3.5 text-g-files shrink-0" />
                      <span className="truncate">{t.table_name}</span>
                    </div>
                    <span className="text-[0.6875rem] text-faint ml-2 shrink-0">
                      {t.row_count} rows
                    </span>
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* Right: Data View Area */}
        <div className="flex-1 flex flex-col overflow-hidden bg-surface">
          {/* Sub-Tab Header Bar: Table Grid vs Key-Value Pairs */}
          <div className="h-9 bg-surface border-b border-line px-3 flex items-center justify-between shrink-0 select-none text-xs">
            <div className="flex items-center space-x-1">
              <button
                onClick={() => setActiveSubTab('TABLE')}
                className={`px-3 py-1 rounded text-xs font-semibold flex items-center space-x-1.5 cursor-pointer ${
                  activeSubTab === 'TABLE'
                    ? 'bg-accent-soft text-accent-ink'
                    : 'text-muted hover:text-ink'
                }`}
              >
                <TableIcon className="w-3.5 h-3.5" />
                <span>Raw Table Grid ({rows.length})</span>
              </button>

              <button
                onClick={() => setActiveSubTab('KV')}
                className={`px-3 py-1 rounded text-xs font-semibold flex items-center space-x-1.5 cursor-pointer ${
                  activeSubTab === 'KV'
                    ? 'bg-accent-soft text-accent-ink'
                    : 'text-muted hover:text-ink'
                }`}
              >
                <KeyRound className="w-3.5 h-3.5" />
                <span>Key-Value Pairs ({kvPairs.length})</span>
              </button>
            </div>

            <div className="text-[0.6875rem] text-faint font-mono">
              Table: <strong className="text-ink">{selectedTable || 'None'}</strong>
            </div>
          </div>

          {/* Table Data or Key-Value Data */}
          <div className="flex-1 overflow-auto font-mono text-xs">
            {loading ? (
              <div className="h-full flex items-center justify-center text-muted space-x-2" role="status">
                <span>Dumping SQLite table records...</span>
              </div>
            ) : activeSubTab === 'TABLE' ? (
              rows.length === 0 ? (
                <EmptyState icon={Database} hue="files" title="Table is empty">
                  Select another table or database from the sidebar to inspect records.
                </EmptyState>
              ) : (
                <table className="w-full text-left border-collapse">
                  <thead className="bg-surface text-muted text-[0.6875rem] sticky top-0 border-b border-line z-10 select-none">
                    <tr>
                      <th className="py-2 px-2.5 w-10 text-faint">#</th>
                      {activeColumns.map((col) => (
                        <th key={col} className="py-2 px-2.5 truncate max-w-xs">
                          {col}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-line">
                    {rows.map((row, idx) => (
                      <tr
                        key={idx}
                        onClick={() => handleRowClick(row, idx)}
                        className="cursor-pointer hover:bg-surface text-ink"
                      >
                        <td className="py-1.5 px-2.5 text-faint">{idx + 1}</td>
                        {activeColumns.map((col) => {
                          const val = row[col];
                          const strVal = val === null || val === undefined ? '' : String(val);
                          return (
                            <td key={col} className="py-1.5 px-2.5 truncate max-w-xs text-ink" title={strVal}>
                              {strVal}
                            </td>
                          );
                        })}
                      </tr>
                    ))}
                  </tbody>
                </table>
              )
            ) : (
              /* Key-Value Pairs View */
              kvPairs.length === 0 ? (
                <EmptyState icon={KeyRound} hue="files" title="No key-value pairs detected">
                  This table does not follow a key-value or configuration store schema.
                </EmptyState>
              ) : (
                <table className="w-full text-left border-collapse">
                  <thead className="bg-surface text-muted text-[0.6875rem] sticky top-0 border-b border-line z-10 select-none">
                    <tr>
                      <th className="py-2 px-2.5 w-10 text-faint">#</th>
                      <th className="py-2 px-2.5 w-64">Key</th>
                      <th className="py-2 px-2.5">Value (Decoded String / JSON)</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-line">
                    {kvPairs.map((kv, idx) => (
                      <tr
                        key={idx}
                        className="hover:bg-surface text-ink font-mono"
                      >
                        <td className="py-1.5 px-2.5 text-faint">{idx + 1}</td>
                        <td className="py-1.5 px-2.5 text-ink font-semibold break-all">{kv.key || kv.name || '-'}</td>
                        <td className="py-1.5 px-2.5 text-muted break-all">{String(kv.value || kv.val || '')}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )
            )}
          </div>
        </div>
      </Card>
    </div>
  );
};

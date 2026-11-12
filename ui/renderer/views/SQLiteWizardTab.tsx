import React, { useState, useEffect } from 'react';
import {
  Database,
  Layers,
  Search,
  CornerDownRight,
  Cpu,
  Eye,
  RefreshCw,
  Table as TableIcon,
  KeyRound,
  FileCode
} from 'lucide-react';
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
    <div className="flex-1 flex flex-col bg-slate-900 text-slate-100 overflow-hidden select-text font-sans text-xs">
      {/* 1. Header Toolbar */}
      <div className="h-11 bg-slate-950 border-b border-slate-800 px-3 flex items-center justify-between shrink-0 select-none">
        <div className="flex items-center space-x-2">
          <Database className="w-4 h-4 text-indigo-400" />
          <span className="font-bold text-slate-200">
            Raw SQLite B-Tree & Table Inspector
          </span>
          {selectedDb && (
            <span className="text-[0.6875rem] text-slate-400 font-mono truncate max-w-xs" title={selectedDb}>
              ({selectedDb})
            </span>
          )}
        </div>

        {/* Database Selector & Refresh */}
        <div className="flex items-center space-x-2">
          <div className="flex items-center space-x-1">
            <span className="text-slate-400 text-[0.6875rem]">Database:</span>
            <select
              value={selectedDb}
              onChange={(e) => setSelectedDb(e.target.value)}
              className="bg-slate-950 border border-slate-700 text-slate-200 text-xs px-2 py-1 rounded max-w-xs truncate focus:outline-none focus:border-indigo-500 font-mono"
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

          <button
            onClick={() => inspectCurrentDb(selectedDb, selectedTable)}
            className="p-1 text-slate-400 hover:text-slate-50 rounded hover:bg-slate-800"
            title="Refresh Table Inspection"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin text-indigo-400' : ''}`} />
          </button>
        </div>
      </div>

      {/* 2. Main Two-Column View: Table Navigator (Left) + Table Grid (Right) */}
      <div className="flex-1 flex overflow-hidden">
        {/* Left: Table Navigator Sidebar */}
        <div className="w-72 bg-slate-950 border-r border-slate-800 flex flex-col shrink-0 select-none">
          <div className="p-2 border-b border-slate-800">
            <div className="relative">
              <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2 top-2 pointer-events-none" />
              <input
                type="text"
                placeholder="Search tables..."
                value={tableSearch}
                onChange={(e) => setTableSearch(e.target.value)}
                className="w-full bg-slate-950 border border-slate-700 rounded pl-7 pr-2 py-1 text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-indigo-500 font-mono"
              />
            </div>
          </div>

          <div className="flex-1 overflow-y-auto p-1 space-y-0.5">
            {filteredTables.length === 0 ? (
              <div className="p-4 text-center text-slate-500 text-xs font-mono">
                {tables.length === 0 ? 'No tables found in database' : 'No matching tables'}
              </div>
            ) : (
              filteredTables.map((t) => {
                const isSelected = selectedTable === t.table_name;
                return (
                  <div
                    key={t.table_name}
                    onClick={() => handleTableSelect(t.table_name)}
                    className={`px-2.5 py-1.5 rounded cursor-pointer transition-colors flex items-center justify-between font-mono text-xs ${
                      isSelected
                        ? 'bg-indigo-950 text-indigo-200 font-bold border border-indigo-700/80 shadow-sm'
                        : 'hover:bg-slate-900 text-slate-300'
                    }`}
                  >
                    <div className="flex items-center space-x-1.5 truncate">
                      <TableIcon className="w-3.5 h-3.5 text-indigo-400 shrink-0" />
                      <span className="truncate">{t.table_name}</span>
                    </div>
                    <span className="text-[0.6875rem] text-slate-500 ml-2 shrink-0">
                      {t.row_count} rows
                    </span>
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* Right: Data View Area */}
        <div className="flex-1 flex flex-col overflow-hidden bg-slate-950">
          {/* Sub-Tab Header Bar: Table Grid vs Key-Value Pairs */}
          <div className="h-9 bg-slate-950 border-b border-slate-800 px-3 flex items-center justify-between shrink-0 select-none text-xs">
            <div className="flex items-center space-x-1">
              <button
                onClick={() => setActiveSubTab('TABLE')}
                className={`px-3 py-1 rounded text-xs font-semibold flex items-center space-x-1.5 transition-colors cursor-pointer ${
                  activeSubTab === 'TABLE'
                    ? 'bg-indigo-600 text-slate-50 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                <TableIcon className="w-3.5 h-3.5" />
                <span>Raw Table Grid ({rows.length})</span>
              </button>

              <button
                onClick={() => setActiveSubTab('KV')}
                className={`px-3 py-1 rounded text-xs font-semibold flex items-center space-x-1.5 transition-colors cursor-pointer ${
                  activeSubTab === 'KV'
                    ? 'bg-indigo-600 text-slate-50 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                <KeyRound className="w-3.5 h-3.5" />
                <span>Key-Value Pairs ({kvPairs.length})</span>
              </button>
            </div>

            <div className="text-[0.6875rem] text-slate-500 font-mono">
              Table: <strong className="text-slate-300">{selectedTable || 'None'}</strong>
            </div>
          </div>

          {/* Table Data or Key-Value Data */}
          <div className="flex-1 overflow-auto font-mono text-xs">
            {loading ? (
              <div className="h-full flex items-center justify-center text-slate-400 space-x-2">
                <span className="w-3 h-3 border-2 border-indigo-400 border-t-transparent rounded-full animate-spin" />
                <span>Dumping SQLite table records...</span>
              </div>
            ) : activeSubTab === 'TABLE' ? (
              rows.length === 0 ? (
                <div className="h-full flex flex-col items-center justify-center text-slate-500 space-y-2 p-8">
                  <Database className="w-12 h-12 text-slate-700 stroke-[1.5]" />
                  <span className="text-sm font-semibold text-slate-400">Table is Empty</span>
                  <p className="text-xs text-slate-600">Select another table or database from the sidebar to inspect records.</p>
                </div>
              ) : (
                <table className="w-full text-left border-collapse">
                  <thead className="bg-slate-900 text-slate-400 text-[0.6875rem] uppercase tracking-wider sticky top-0 border-b border-slate-800 z-10 select-none">
                    <tr>
                      <th className="py-2 px-2.5 w-10 text-slate-500">#</th>
                      {activeColumns.map((col) => (
                        <th key={col} className="py-2 px-2.5 truncate max-w-xs">
                          {col}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800">
                    {rows.map((row, idx) => (
                      <tr
                        key={idx}
                        onClick={() => handleRowClick(row, idx)}
                        className="cursor-pointer hover:bg-slate-900 text-slate-300 transition-colors"
                      >
                        <td className="py-1.5 px-2.5 text-slate-500">{idx + 1}</td>
                        {activeColumns.map((col) => {
                          const val = row[col];
                          const strVal = val === null || val === undefined ? '' : String(val);
                          return (
                            <td key={col} className="py-1.5 px-2.5 truncate max-w-xs text-slate-200" title={strVal}>
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
                <div className="h-full flex flex-col items-center justify-center text-slate-500 space-y-2 p-8">
                  <KeyRound className="w-12 h-12 text-slate-700 stroke-[1.5]" />
                  <span className="text-sm font-semibold text-slate-400">No Key-Value Pairs Detected</span>
                  <p className="text-xs text-slate-600">This table does not follow a key-value or configuration store schema.</p>
                </div>
              ) : (
                <table className="w-full text-left border-collapse">
                  <thead className="bg-slate-900 text-slate-400 text-[0.6875rem] uppercase tracking-wider sticky top-0 border-b border-slate-800 z-10 select-none">
                    <tr>
                      <th className="py-2 px-2.5 w-10 text-slate-500">#</th>
                      <th className="py-2 px-2.5 w-64">Key</th>
                      <th className="py-2 px-2.5">Value (Decoded String / JSON)</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800">
                    {kvPairs.map((kv, idx) => (
                      <tr
                        key={idx}
                        className="hover:bg-slate-900 text-slate-300 transition-colors font-mono"
                      >
                        <td className="py-1.5 px-2.5 text-slate-500">{idx + 1}</td>
                        <td className="py-1.5 px-2.5 text-amber-300 font-bold break-all">{kv.key || kv.name || '-'}</td>
                        <td className="py-1.5 px-2.5 text-teal-300 break-all">{String(kv.value || kv.val || '')}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

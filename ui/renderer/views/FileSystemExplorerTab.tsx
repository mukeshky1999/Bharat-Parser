import React, { useState, useEffect } from 'react';
import {
  HardDrive,
  Folder,
  File,
  ChevronRight,
  ChevronDown,
  Binary,
  Eye,
  Search,
  Database,
  RefreshCw,
  SlidersHorizontal
} from 'lucide-react';
import { forensicClient } from '../api/forensicClient';
import { useWorkbenchStore } from '../state/workbenchStore';
import { ForensicProvenance } from '../../shared/forensic-types';

interface FileSystemExplorerTabProps {
  onSelectFileProvenance?: (prov: ForensicProvenance) => void;
  onOpenInSqliteWizard?: (filePath: string) => void;
}

export const FileSystemExplorerTab: React.FC<FileSystemExplorerTabProps> = ({
  onSelectFileProvenance,
  onOpenInSqliteWizard
}) => {
  const store = useWorkbenchStore();
  const [files, setFiles] = useState<any[]>([]);
  const [loading, setLoading] = useState<boolean>(false);
  const [selectedPath, setSelectedPath] = useState<string>('');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [filterExt, setFilterExt] = useState<string>('ALL');

  const fetchVfsFiles = async () => {
    setLoading(true);
    try {
      const res = await forensicClient.queryArtifacts('vfs_files', undefined, undefined, undefined, searchQuery, 500, 0);
      if (res && res.rows) {
        setFiles(res.rows);
      }
    } catch {
      // Fallback
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchVfsFiles();
  }, [store.caseManifest]);

  const filteredFiles = files.filter((f) => {
    const path = String(f.file_path || f.path || f.name || '').toLowerCase();
    if (filterExt === 'SQLITE' && !path.endsWith('.db') && !path.endsWith('.sqlite')) return false;
    if (filterExt === 'WAL' && !path.includes('-wal')) return false;
    if (filterExt === 'XML' && !path.endsWith('.xml') && !path.endsWith('.plist')) return false;
    if (filterExt === 'APK' && !path.endsWith('.apk')) return false;

    if (searchQuery.trim()) {
      return path.includes(searchQuery.toLowerCase());
    }
    return true;
  });

  const handleRowClick = (f: any) => {
    const filePath = f.file_path || f.path || f.name || '';
    setSelectedPath(filePath);

    const offset = Number(f.byte_offset || f.offset || 0);
    const size = Number(f.size_bytes || f.size || 0);

    const prov: ForensicProvenance = {
      evidenceId: store.caseManifest?.caseNumber || store.caseManifest?.caseId || 'EVIDENCE_CONTAINER',
      archivePath: store.caseManifest?.evidencePath || filePath,
      vfsInternalPath: filePath,
      containerType: filePath.endsWith('-wal') ? 'SQLITE_WAL' : (filePath.endsWith('.db') || filePath.endsWith('.sqlite') ? 'SQLITE' : 'RAW_CARVED'),
      byteOffset: offset,
      byteLength: Math.min(size, 4096),
      recoveryState: 'ACTIVE',
      rawPayloadHex: ''
    };

    store.setSelectedArtifact({
      id: `VFS_${offset}_${Date.now()}`,
      provenance: prov,
      notes: `VFS File: ${filePath} (${(size / 1024).toFixed(1)} KB)`,
      itemType: 'Virtual File System Node',
      rawData: f
    });

    if (onSelectFileProvenance) {
      onSelectFileProvenance(prov);
    }
  };

  return (
    <div className="flex-1 flex flex-col bg-slate-900 text-slate-100 overflow-hidden select-text font-mono text-xs">
      {/* 1. Header Toolbar */}
      <div className="h-11 bg-slate-950 border-b border-slate-800 px-3 flex items-center justify-between shrink-0 select-none text-xs">
        <div className="flex items-center space-x-2">
          <HardDrive className="w-4 h-4 text-slate-300" />
          <span className="font-semibold text-slate-200">
            Zero-Copy Virtual File System (VFS) Explorer
          </span>
          <span className="text-[0.75rem] text-slate-400 font-mono">
            ({filteredFiles.length} Indexed Nodes)
          </span>
        </div>

        {/* Filters, Search & Refresh */}
        <div className="flex items-center space-x-2">
          <div className="flex items-center bg-slate-900 border border-slate-800 rounded p-0.5 text-xs">
            {['ALL', 'SQLITE', 'WAL', 'XML', 'APK'].map((ext) => (
              <button
                key={ext}
                onClick={() => setFilterExt(ext)}
                className={`px-2 py-0.5 rounded transition-colors ${
                  filterExt === ext ? 'bg-cyan-600 text-slate-50 font-semibold' : 'text-slate-400 hover:text-slate-50'
                }`}
              >
                {ext}
              </button>
            ))}
          </div>

          <div className="relative">
            <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2 top-2 pointer-events-none" />
            <input
              type="text"
              placeholder="Filter file path..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-48 bg-slate-950 border border-slate-700 rounded pl-7 pr-2 py-1 text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
            />
          </div>

          <button
            onClick={fetchVfsFiles}
            className="p-1 text-slate-400 hover:text-slate-50 rounded hover:bg-slate-800"
            title="Refresh VFS Index"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin text-cyan-400' : ''}`} />
          </button>
        </div>
      </div>

      {/* 2. Main VFS File Grid */}
      <div className="flex-1 overflow-auto bg-slate-950">
        {loading ? (
          <div className="h-full flex items-center justify-center text-slate-400 space-x-2">
            <span className="w-3 h-3 border-2 border-cyan-400 border-t-transparent rounded-full animate-spin" />
            <span>Scanning VFS index...</span>
          </div>
        ) : filteredFiles.length === 0 ? (
          <div className="h-full flex flex-col items-center justify-center text-slate-500 space-y-2 p-8">
            <HardDrive className="w-12 h-12 text-slate-700 stroke-[1.5]" />
            <span className="text-sm font-semibold text-slate-400">No VFS Files Found</span>
            <p className="text-xs text-slate-600 max-w-sm text-center">
              {Boolean(store.caseManifest || store.vfsTree.length > 0)
                ? 'No indexed files match the filter query.'
                : 'No evidence dump loaded. Ingest an evidence container to explore its internal virtual file system.'}
            </p>
          </div>
        ) : (
          <table className="w-full text-left border-collapse">
            <thead className="bg-slate-900 text-slate-400 text-[0.75rem] sticky top-0 border-b border-slate-800 z-10 select-none">
              <tr>
                <th className="py-2.5 px-3 w-10 text-slate-500">#</th>
                <th className="py-2.5 px-3">VFS File Path</th>
                <th className="py-2.5 px-3 w-36">Container Type</th>
                <th className="py-2.5 px-3 w-28 text-right">Size</th>
                <th className="py-2.5 px-3 w-32">Archive Offset</th>
                <th className="py-2.5 px-3 w-24 text-center">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800">
              {filteredFiles.map((f, idx) => {
                const filePath = f.file_path || f.path || f.name || '';
                const isSelected = selectedPath === filePath;
                const offset = Number(f.byte_offset || f.offset || 0);
                const size = Number(f.size_bytes || f.size || 0);
                const isDb = filePath.endsWith('.db') || filePath.endsWith('.sqlite');

                return (
                  <tr
                    key={idx}
                    onClick={() => handleRowClick(f)}
                    className={`cursor-pointer transition-colors ${
                      isSelected
                        ? 'bg-slate-800 text-slate-100 font-semibold border-l-4 border-slate-700'
                        : 'hover:bg-slate-900 text-slate-300'
                    }`}
                  >
                    <td className="py-2 px-3 text-slate-500">{idx + 1}</td>
                    <td className="py-2 px-3 text-slate-200 font-mono truncate max-w-md" title={filePath}>
                      {filePath}
                    </td>
                    <td className="py-2 px-3 text-slate-400">
                      {filePath.endsWith('-wal')
                        ? 'SQLite WAL Log'
                        : isDb
                        ? 'SQLite Database'
                        : filePath.endsWith('.xml')
                        ? 'XML Configuration'
                        : filePath.endsWith('.apk')
                        ? 'Android Application'
                        : 'Binary Stream'}
                    </td>
                    <td className="py-2 px-3 text-right text-emerald-400 font-semibold">
                      {(size / 1024).toFixed(1)} KB
                    </td>
                    <td className="py-2 px-3 text-amber-400">
                      0x{offset.toString(16).toUpperCase().padStart(8, '0')}
                    </td>
                    <td className="py-2 px-3 text-center">
                      {isDb && (
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            store.setActiveTab('SQLITE_WIZARD');
                            if (onOpenInSqliteWizard) {
                              onOpenInSqliteWizard(filePath);
                            }
                          }}
                          className="px-2 py-0.5 rounded text-[0.75rem] font-semibold bg-slate-800 text-slate-300 border border-slate-700 hover:bg-slate-800 transition-colors"
                          title="Open in deep SQLite B-Tree Explorer"
                        >
                          Inspect DB
                        </button>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
};

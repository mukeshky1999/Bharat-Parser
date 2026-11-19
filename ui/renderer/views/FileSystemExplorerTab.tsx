import React, { useState, useEffect } from 'react';
import { HardDrive, Search, RefreshCw } from 'lucide-react';
import { ViewHeader, Card, Button, EmptyState } from '../components/ui';
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
    <div className="flex-1 flex flex-col bg-page p-4 min-h-0 overflow-hidden select-text">
      <ViewHeader title="Files" count={filteredFiles.length}
        search={(
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-faint absolute left-2 top-2.5 pointer-events-none" />
            <input
              type="text"
              placeholder="Filter file path..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-48 h-8 bg-surface border border-line-strong rounded-lg pl-7 pr-2 text-ink placeholder:text-faint focus:outline-none focus:border-accent font-mono"
            />
          </div>
        )}
        actions={(
          <>
            <div className="flex items-center bg-surface border border-line-strong rounded-lg p-0.5">
              {['ALL', 'SQLITE', 'WAL', 'XML', 'APK'].map((ext) => (
                <button
                  key={ext}
                  onClick={() => setFilterExt(ext)}
                  className={`px-2 py-0.5 rounded-md ${
                    filterExt === ext ? 'bg-accent-soft text-accent-ink font-semibold' : 'text-muted hover:text-ink'
                  }`}
                >
                  {ext}
                </button>
              ))}
            </div>
            <Button variant="icon" onClick={fetchVfsFiles} title="Refresh VFS Index" aria-label="Refresh the file index">
              <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'text-accent' : ''}`} />
            </Button>
          </>
        )} />

      <Card className="flex-1 min-h-0 overflow-hidden flex flex-col" bodyClassName="flex-1 min-h-0 overflow-auto">
        {loading ? (
          <div className="h-full flex items-center justify-center text-muted" role="status">
            <span>Scanning VFS index...</span>
          </div>
        ) : filteredFiles.length === 0 ? (
          <EmptyState icon={HardDrive} hue="files" title="No VFS files found">
            {Boolean(store.caseManifest || store.vfsTree.length > 0)
              ? 'No indexed files match the filter query.'
              : 'No evidence dump loaded. Ingest an evidence container to explore its internal virtual file system.'}
          </EmptyState>
        ) : (
          <table className="w-full text-left border-collapse text-xs">
            <thead className="bg-sunken text-muted text-[0.6875rem] sticky top-0 border-b border-line z-10 select-none">
              <tr>
                <th className="py-2.5 px-3 w-10 text-faint">#</th>
                <th className="py-2.5 px-3">VFS file path</th>
                <th className="py-2.5 px-3 w-36">Container type</th>
                <th className="py-2.5 px-3 w-28 text-right">Size</th>
                <th className="py-2.5 px-3 w-32">Archive offset</th>
                <th className="py-2.5 px-3 w-24 text-center">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line">
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
                    className={`cursor-pointer ${
                      isSelected
                        ? 'bg-accent-soft text-ink font-semibold border-l-4 border-accent'
                        : 'hover:bg-hover text-ink'
                    }`}
                  >
                    <td className="py-2 px-3 text-faint">{idx + 1}</td>
                    <td className="py-2 px-3 text-ink font-mono truncate max-w-md" title={filePath}>
                      {filePath}
                    </td>
                    <td className="py-2 px-3 text-muted">
                      {filePath.endsWith('-wal')
                        ? 'SQLite WAL log'
                        : isDb
                        ? 'SQLite database'
                        : filePath.endsWith('.xml')
                        ? 'XML configuration'
                        : filePath.endsWith('.apk')
                        ? 'Android application'
                        : 'Binary stream'}
                    </td>
                    <td className="py-2 px-3 text-right text-ink">
                      {(size / 1024).toFixed(1)} KB
                    </td>
                    <td className="py-2 px-3 text-muted font-mono">
                      0x{offset.toString(16).toUpperCase().padStart(8, '0')}
                    </td>
                    <td className="py-2 px-3 text-center">
                      {isDb && (
                        <Button
                          onClick={(e) => {
                            e.stopPropagation();
                            store.setActiveTab('SQLITE_WIZARD');
                            if (onOpenInSqliteWizard) {
                              onOpenInSqliteWizard(filePath);
                            }
                          }}
                          className="!h-6 px-2 text-[0.6875rem]"
                          title="Open in deep SQLite B-Tree Explorer"
                        >
                          Inspect DB
                        </Button>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </Card>
    </div>
  );
};

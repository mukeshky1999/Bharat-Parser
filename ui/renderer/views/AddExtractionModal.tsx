import React, { useState, useRef, useEffect, useCallback } from 'react';
import {
  X,
  FolderOpen,
  FileArchive,
  Folder,
  ShieldCheck,
  CheckCircle2,
  AlertCircle,
  Play
} from 'lucide-react';
import { forensicClient } from '../api/forensicClient';
import { useWorkbenchStore } from '../state/workbenchStore';
import { KeyEntry, KeyRow, keysFromRows } from '../inspectors/KeyBrokerPanel';

interface AddExtractionModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const AddExtractionModal: React.FC<AddExtractionModalProps> = ({ isOpen, onClose }) => {
  const { setActiveTab, syncWithBackendCase } = useWorkbenchStore();

  const [containerPath, setContainerPath] = useState('');
  const [caseId, setCaseId] = useState('');
  const [extractionFormat, setExtractionFormat] = useState<'UFDR' | 'TAR' | 'ZIP' | 'FOLDER' | 'SQLITE'>('TAR');
  const [isProcessing, setIsProcessing] = useState(false);
  const [keyRows, setKeyRows] = useState<KeyRow[]>([]);
  const [feedback, setFeedback] = useState<{ type: 'success' | 'error' | 'info'; message: string } | null>(null);

  const abortControllerRef = useRef<AbortController | null>(null);
  const isMountedRef = useRef(true);

  useEffect(() => {
    isMountedRef.current = true;
    return () => {
      isMountedRef.current = false;
      if (abortControllerRef.current) {
        abortControllerRef.current.abort();
      }
    };
  }, []);

  const handleClose = useCallback(() => {
    if (isProcessing && abortControllerRef.current) {
      abortControllerRef.current.abort();
    }
    setIsProcessing(false);
    onClose();
  }, [isProcessing, onClose]);

  if (!isOpen) return null;

  const handlePickFile = async () => {
    try {
      const selected = await forensicClient.pickEvidenceFile();
      if (selected && isMountedRef.current) {
        setContainerPath(selected);
        const lower = selected.toLowerCase();
        if (lower.endsWith('.ufdr') || lower.endsWith('.ufd')) {
          setExtractionFormat('UFDR');
        } else if (lower.endsWith('.tar') || lower.endsWith('.tar.gz') || lower.endsWith('.tgz')) {
          setExtractionFormat('TAR');
        } else if (lower.endsWith('.zip')) {
          setExtractionFormat('ZIP');
        } else if (lower.endsWith('.db') || lower.endsWith('.sqlite') || lower.endsWith('.sqlite3')) {
          setExtractionFormat('SQLITE');
        }
      }
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Error opening file picker';
      if (isMountedRef.current) {
        setFeedback({ type: 'error', message: msg });
      }
    }
  };

  const handlePickFolder = async () => {
    try {
      const selected = await forensicClient.pickEvidenceFolder();
      if (selected && isMountedRef.current) {
        setContainerPath(selected);
        setExtractionFormat('FOLDER');
      }
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Error opening directory picker';
      if (isMountedRef.current) {
        setFeedback({ type: 'error', message: msg });
      }
    }
  };

  const handleIngestEvidence = async () => {
    if (!containerPath.trim()) {
      setFeedback({ type: 'error', message: 'Please select or enter an evidence container or folder path.' });
      return;
    }

    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
    }
    const controller = new AbortController();
    abortControllerRef.current = controller;

    setIsProcessing(true);
    setFeedback({ type: 'info', message: 'Computing SHA-256 integrity seal and streaming forensic artifacts...' });

    try {
      const res = await forensicClient.ingestCase(
        containerPath.trim(),
        caseId.trim() || undefined,
        undefined,
        controller.signal,
        { keys: keysFromRows(keyRows) }
      );
      setKeyRows([]); // typed keys are cleared as soon as they have been sent

      if (controller.signal.aborted || !isMountedRef.current) return;

      if (res && res.success) {
        setFeedback({
          type: 'success',
          message: `Successfully ingested case "${res.case_name || 'Evidence Dump'}". Pre-ingestion SHA-256 seal computed.`
        });
        await syncWithBackendCase();
        setTimeout(() => {
          if (isMountedRef.current) {
            handleClose();
            setActiveTab('SUMMARY');
          }
        }, 1000);
      } else {
        const detailMsg = res?.detail || res?.error || 'Failed to ingest evidence container';
        let errorPrefix = 'Ingestion Error';
        if (res?.status === 409) {
          errorPrefix = 'Conflict (409)';
        } else if (res?.status === 403) {
          errorPrefix = 'Access Denied (403)';
        } else if (res?.status === 412) {
          errorPrefix = 'Precondition Failed (412)';
        }
        setFeedback({
          type: 'error',
          message: `${errorPrefix}: ${detailMsg}`
        });
      }
    } catch (e: unknown) {
      if (controller.signal.aborted || !isMountedRef.current) return;
      const msg = e instanceof Error ? e.message : 'Error ingesting evidence archive';
      setFeedback({ type: 'error', message: msg });
    } finally {
      if (isMountedRef.current) {
        setIsProcessing(false);
      }
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-[2px] p-4 select-none">
      <div className="bg-slate-800 border border-slate-700 rounded-lg shadow-2xl w-full max-w-lg overflow-hidden text-slate-50 text-xs">
        {/* Modal Header */}
        <div className="h-10 px-4 bg-slate-900 border-b border-slate-700 flex items-center justify-between">
          <div className="flex items-center space-x-2 font-semibold">
            <FileArchive className="w-4 h-4 text-cyan-600" />
            <span>+ Add Extraction — Ingest Evidence Container</span>
          </div>
          <button
            onClick={handleClose}
            className="text-slate-400 hover:text-slate-50 p-1 rounded transition-colors cursor-pointer"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-4 space-y-4">
          {/* Format Radio Selection */}
          <div>
            <label className="block text-[0.6875rem] font-semibold text-slate-300 mb-1.5 uppercase tracking-wide">
              Extraction Container Format
            </label>
            <div className="grid grid-cols-5 gap-1.5">
              {[
                { id: 'TAR', label: 'TAR (.tar)' },
                { id: 'UFDR', label: 'UFDR Archive (.ufdr)' },
                { id: 'ZIP', label: 'ZIP Container' },
                { id: 'SQLITE', label: 'Single SQLite' },
                { id: 'FOLDER', label: 'Raw Folder' },
              ].map((fmt) => (
                <button
                  key={fmt.id}
                  type="button"
                  onClick={() => setExtractionFormat(fmt.id as 'UFDR' | 'TAR' | 'ZIP' | 'FOLDER' | 'SQLITE')}
                  className={`p-2 rounded text-center border transition-colors cursor-pointer text-[0.6875rem] ${
                    extractionFormat === fmt.id
                      ? 'bg-cyan-600 border-cyan-600 text-slate-50 font-semibold'
                      : 'bg-slate-900 border-slate-700 text-slate-300 hover:border-slate-500'
                  }`}
                >
                  {fmt.label}
                </button>
              ))}
            </div>
          </div>

          {/* Path Input with Native File and Folder Dialog Buttons */}
          <div>
            <label className="block text-[0.6875rem] font-semibold text-slate-300 mb-1.5 uppercase tracking-wide">
              Evidence Container / Workspace File Path
            </label>
            <div className="flex items-center space-x-2">
              <input
                type="text"
                value={containerPath}
                onChange={(e) => setContainerPath(e.target.value)}
                placeholder="C:/Evidence/dump.ufdr or /evidence/physical.tar"
                className="flex-1 h-8 bg-slate-900 border border-slate-700 rounded px-3 text-xs text-slate-50 placeholder-slate-500 focus:outline-none focus:border-cyan-600 font-mono"
              />
              <button
                type="button"
                onClick={handlePickFile}
                className="px-2.5 h-8 bg-slate-800 hover:bg-slate-700 border border-slate-600 rounded flex items-center space-x-1 transition-colors cursor-pointer shrink-0"
                title="Open native Windows File Explorer to select archive or database"
              >
                <FolderOpen className="w-3.5 h-3.5 text-sky-400" />
                <span>File</span>
              </button>
              <button
                type="button"
                onClick={handlePickFolder}
                className="px-2.5 h-8 bg-slate-800 hover:bg-slate-700 border border-slate-600 rounded flex items-center space-x-1 transition-colors cursor-pointer shrink-0"
                title="Open native Windows Directory Explorer to select folder"
              >
                <Folder className="w-3.5 h-3.5 text-amber-400" />
                <span>Folder</span>
              </button>
            </div>
          </div>

          {/* Optional Case ID Input */}
          <div>
            <label className="block text-[0.6875rem] font-semibold text-slate-300 mb-1 uppercase tracking-wide">
              Case Reference ID (Optional)
            </label>
            <input
              type="text"
              value={caseId}
              onChange={(e) => setCaseId(e.target.value)}
              placeholder="e.g. 2026-CYB-09 (Auto-generated if left blank)"
              className="w-full h-8 bg-slate-900 border border-slate-700 rounded px-3 text-xs text-slate-50 placeholder-slate-500 focus:outline-none focus:border-cyan-600 font-mono"
            />
          </div>

          {/* Keys for encrypted databases (optional) */}
          <details className="bg-slate-900 border border-slate-700 rounded p-2.5">
            <summary className="cursor-pointer text-[0.6875rem] font-semibold text-slate-300 uppercase tracking-wide">Keys for encrypted databases (optional)</summary>
            <p className="text-[0.6875rem] text-slate-400 my-2">Only keys you list here, and keys stored in the evidence itself, are tried. They are used while this evidence is processed and are not saved.</p>
            <KeyEntry rows={keyRows} onChange={setKeyRows} disabled={isProcessing} />
          </details>

          {/* Forensic Ingestion Info Banner */}
          <div className="bg-slate-900 border border-slate-700 rounded p-2.5 space-y-1 text-[0.6875rem] text-slate-300">
            <span className="text-slate-400 font-semibold block">Supported Forensic Images:</span>
            <p className="text-[0.6875rem] leading-relaxed text-slate-400">
              Universal Forensic Data Report UFDR (<span className="text-slate-300">.ufdr, .ufd</span>), Physical TAR images (<span className="text-slate-300">.tar, .tar.gz</span>), ZIP containers (<span className="text-slate-300">.zip</span>), XRY (<span className="text-slate-300">.xry</span>), Oxygen (<span className="text-slate-300">.ofb</span>), and extracted SQLite databases (<span className="text-slate-300">.db, .sqlite, -wal</span>).
            </p>
          </div>

          {/* Feedback message */}
          {feedback && (
            <div
              className={`p-2.5 rounded border text-xs flex items-center space-x-2 ${
                feedback.type === 'success'
                  ? 'bg-emerald-950/80 border-emerald-600 text-emerald-300'
                  : feedback.type === 'error'
                  ? 'bg-rose-950/80 border-rose-600 text-rose-300'
                  : 'bg-sky-950/80 border-sky-600 text-sky-300'
              }`}
            >
              {feedback.type === 'success' ? (
                <CheckCircle2 className="w-4 h-4 shrink-0" />
              ) : (
                <AlertCircle className="w-4 h-4 shrink-0" />
              )}
              <span>{feedback.message}</span>
            </div>
          )}
        </div>

        {/* Modal Footer */}
        <div className="h-12 px-4 bg-slate-900 border-t border-slate-700 flex items-center justify-between">
          <div className="flex items-center space-x-1.5 text-emerald-400 font-mono text-[0.6875rem]">
            <ShieldCheck className="w-4 h-4" />
            <span>Original evidence is never modified; hashed before and after</span>
          </div>

          <div className="flex items-center space-x-2">
            <button
              type="button"
              onClick={handleClose}
              disabled={isProcessing}
              className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-xs transition-colors cursor-pointer"
            >
              Cancel
            </button>
            <button
              type="button"
              onClick={handleIngestEvidence}
              disabled={isProcessing}
              className="px-4 py-1.5 bg-cyan-600 hover:bg-cyan-600 text-slate-50 font-semibold rounded text-xs shadow transition-colors flex items-center space-x-1.5 cursor-pointer disabled:opacity-50"
            >
              <Play className="w-3.5 h-3.5 fill-current" />
              <span>{isProcessing ? 'Ingesting Pipeline...' : 'Ingest & Open Extraction'}</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

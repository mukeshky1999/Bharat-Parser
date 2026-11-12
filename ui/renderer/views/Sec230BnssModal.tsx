import React, { useEffect, useMemo, useRef, useState } from 'react';
import {
  X,
  ShieldAlert,
  FolderOpen,
  FileText,
  Lock,
  ExternalLink,
  EyeOff,
  AlertTriangle,
  CheckCircle2,
  Loader2
} from 'lucide-react';
import { forensicClient, Sec230BnssResponse } from '../api/forensicClient';
import { useWorkbenchStore } from '../state/workbenchStore';

interface Sec230BnssModalProps {
  isOpen: boolean;
  onClose: () => void;
}

type MediaItem = { path: string; vfs_path: string; file_name: string; file_size: number };

const TAGS: Array<{ value: string; label: string }> = [
  { value: '', label: 'Disclosable' },
  { value: 'CSAM_POCSO', label: 'Withhold — POCSO / CSAM' },
  { value: 'NON_CONSENSUAL_INTIMATE_MEDIA', label: 'Withhold — non-consensual intimate' },
  { value: 'SEXUAL_ASSAULT_FOOTAGE', label: 'Withhold — sexual assault footage' },
  { value: 'UNRELIED_PRIVATE_DATA', label: 'Unrelied private data' },
  { value: 'PROTECTED_VICTIM_IDENTITY', label: 'Protected victim identity' }
];

export const Sec230BnssModal: React.FC<Sec230BnssModalProps> = ({ isOpen, onClose }) => {
  const store = useWorkbenchStore();
  const dialogRef = useRef<HTMLDivElement | null>(null);

  const [caseId, setCaseId] = useState('');
  const [victimName, setVictimName] = useState('');
  const [anonymizeVictim, setAnonymizeVictim] = useState(true);
  const [outputDir, setOutputDir] = useState('');
  const [media, setMedia] = useState<MediaItem[]>([]);
  const [included, setIncluded] = useState<Record<string, boolean>>({});
  const [tags, setTags] = useState<Record<string, string>>({});
  const [loadingMedia, setLoadingMedia] = useState(false);
  const [mediaError, setMediaError] = useState<string | null>(null);
  const [generating, setGenerating] = useState(false);
  const [result, setResult] = useState<Sec230BnssResponse | null>(null);

  useEffect(() => {
    if (!isOpen) return;
    setResult(null);
    if (!caseId && store.caseManifest?.caseId) setCaseId(store.caseManifest.caseId);
    let cancelled = false;
    (async () => {
      setLoadingMedia(true);
      setMediaError(null);
      const r = await forensicClient.getMediaCandidates();
      if (cancelled) return;
      setMedia(r.items);
      setMediaError(r.error ?? null);
      setIncluded({});
      setTags({});
      setLoadingMedia(false);
    })();
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isOpen]);

  useEffect(() => {
    if (!isOpen) return;
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && onClose();
    window.addEventListener('keydown', onKey);
    dialogRef.current?.focus();
    return () => window.removeEventListener('keydown', onKey);
  }, [isOpen, onClose]);

  const chosen = useMemo(() => media.filter((m) => included[m.path]), [media, included]);
  const withheldCount = chosen.filter((m) => tags[m.path] && /CSAM|INTIMATE|ASSAULT/.test(tags[m.path])).length;
  const missing: string[] = [];
  if (!caseId.trim()) missing.push('case reference');
  if (anonymizeVictim && !victimName.trim()) missing.push('victim name to redact');
  if (chosen.length === 0) missing.push('at least one media file');
  const canGenerate = missing.length === 0 && !generating;

  if (!isOpen) return null;

  const handleBrowseDir = async () => {
    try {
      if (window.electronAPI?.openFolderDialog) {
        const folder = await window.electronAPI.openFolderDialog({ title: 'Select Output Directory for Section 230 BNSS Bundle' });
        if (folder) setOutputDir(folder);
      } else {
        const folder = await forensicClient.pickEvidenceFolder();
        if (folder) setOutputDir(folder);
      }
    } catch {
      /* cancelled */
    }
  };

  const handleGenerate = async () => {
    setGenerating(true);
    try {
      const res = await forensicClient.generateSec230BnssPackage(
        caseId.trim(),
        outputDir || undefined,
        anonymizeVictim,
        victimName.trim() || undefined,
        undefined,
        chosen.map((m) => ({ path: m.path, redaction_tag: tags[m.path] || null }))
      );
      setResult(res);
      if (res.success) {
        store.addToast({
          title: 'Section 230 BNSS bundle ready',
          message: `${res.pocso_withheld_count} item(s) withheld and replaced with notice cards.`,
          type: 'success'
        });
      }
    } catch (e: any) {
      setResult({ success: false, error: e?.message || 'Error executing Section 230 packager' } as Sec230BnssResponse);
    } finally {
      setGenerating(false);
    }
  };

  const handleShowInExplorer = async (path: string) => {
    if (window.electronAPI?.showItemInFolder) await window.electronAPI.showItemInFolder(path);
  };

  return (
    <div
      className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4"
      onMouseDown={(e) => e.target === e.currentTarget && onClose()}
    >
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby="s230-title"
        tabIndex={-1}
        className="bg-[#0b1320] border border-cyan-800/60 rounded-xl shadow-2xl w-full max-w-3xl flex flex-col max-h-[90vh] overflow-hidden text-slate-100 font-sans outline-none"
      >
        <div className="px-5 py-4 bg-[#090f1d] border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center space-x-2.5">
            <div className="w-8 h-8 rounded-lg bg-amber-500/20 border border-amber-500/40 flex items-center justify-center text-amber-400">
              <ShieldAlert className="w-4 h-4" aria-hidden="true" />
            </div>
            <div>
              <h2 id="s230-title" className="text-sm font-bold tracking-wide uppercase text-white">
                Section 230 BNSS (2023) — Defence disclosure copy
              </h2>
              <p className="text-[11px] text-slate-400">
                Statutory redaction gate • P. Gopalkrishnan v. State of Kerala (2019) • Sec 72 BNS 2023
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            aria-label="Close dialog"
            className="text-slate-400 hover:text-white p-1.5 rounded hover:bg-slate-800 focus-visible:outline focus-visible:outline-2 focus-visible:outline-cyan-400"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="flex-1 overflow-y-auto p-5 space-y-4 text-xs">
          <div className="p-3 bg-amber-950/30 border border-amber-600/40 rounded-lg text-amber-200/90 space-y-1">
            <div className="font-bold flex items-center gap-1.5 text-amber-300">
              <Lock className="w-3.5 h-3.5 text-amber-400" aria-hidden="true" />
              <span>Examiner classifies each file</span>
            </div>
            <p className="text-[11px] leading-relaxed text-amber-200/80">
              The software cannot recognise sensitive imagery. Mark every file that must be withheld; those are never
              copied into the bundle and are replaced by a notice card. Hashes are computed from the actual file bytes.
            </p>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div>
              <label htmlFor="s230-case" className="block text-slate-300 font-semibold mb-1">
                Case reference <span className="text-rose-400" aria-hidden="true">*</span>
              </label>
              <input
                id="s230-case"
                type="text"
                value={caseId}
                onChange={(e) => setCaseId(e.target.value)}
                className="w-full bg-slate-950 border border-slate-700 rounded px-3 py-2 text-white font-mono text-xs focus:border-cyan-500 focus:outline-none"
              />
            </div>
            <div>
              <label htmlFor="s230-victim" className="block text-slate-300 font-semibold mb-1">
                Victim name to redact {anonymizeVictim && <span className="text-rose-400" aria-hidden="true">*</span>}
              </label>
              <input
                id="s230-victim"
                type="text"
                value={victimName}
                onChange={(e) => setVictimName(e.target.value)}
                className="w-full bg-slate-950 border border-slate-700 rounded px-3 py-2 text-white text-xs focus:border-cyan-500 focus:outline-none"
              />
            </div>
          </div>

          <label className="flex items-center justify-between gap-3 p-3 bg-slate-950/70 border border-slate-800 rounded-lg cursor-pointer">
            <span className="flex items-center space-x-2">
              <EyeOff className="w-4 h-4 text-cyan-400 shrink-0" aria-hidden="true" />
              <span>
                <span className="font-bold text-slate-200 block">Section 72 BNS 2023 victim anonymisation</span>
                <span className="text-[11px] text-slate-400">Replace the victim’s name with [VICTIM_PROTECTED_ID_01] throughout.</span>
              </span>
            </span>
            <input
              type="checkbox"
              checked={anonymizeVictim}
              onChange={(e) => setAnonymizeVictim(e.target.checked)}
              className="w-4 h-4 accent-cyan-500"
            />
          </label>

          <div>
            <div className="flex items-center justify-between mb-1.5">
              <span className="text-slate-300 font-bold uppercase tracking-wider text-[11px]">Case media</span>
              <span className="text-[10px] text-slate-400 font-mono" aria-live="polite">
                {loadingMedia ? 'Loading…' : `${media.length} found · ${chosen.length} selected · ${withheldCount} withheld`}
              </span>
            </div>
            <div className="border border-slate-800 rounded-lg bg-slate-950/80 max-h-64 overflow-y-auto">
              {loadingMedia ? (
                <div className="p-6 flex items-center justify-center gap-2 text-slate-400" role="status">
                  <Loader2 className="w-4 h-4 animate-spin" aria-hidden="true" /> Reading case catalogue…
                </div>
              ) : mediaError ? (
                <div className="p-5 text-center text-amber-300" role="alert">{mediaError}</div>
              ) : media.length === 0 ? (
                <div className="p-6 text-center text-slate-400">
                  <p className="font-semibold text-slate-300">No media files available</p>
                  <p className="mt-1 text-[11px]">
                    Only files present on disk can be packaged. For container evidence (ZIP/TAR/UFDR) media is not
                    extracted during ingestion; extract the needed files into the case workspace first.
                  </p>
                </div>
              ) : (
                <ul className="divide-y divide-slate-800/70">
                  {media.map((m) => (
                    <li key={m.path} className="flex items-center gap-3 px-3 py-2">
                      <input
                        type="checkbox"
                        aria-label={`Include ${m.file_name}`}
                        checked={!!included[m.path]}
                        onChange={(e) => setIncluded((s) => ({ ...s, [m.path]: e.target.checked }))}
                        className="w-3.5 h-3.5 accent-cyan-500"
                      />
                      <div className="flex-1 min-w-0">
                        <div className="text-slate-200 truncate" title={m.vfs_path}>{m.file_name}</div>
                        <div className="text-[10px] text-slate-500 truncate font-mono">{m.vfs_path}</div>
                      </div>
                      <select
                        aria-label={`Classification for ${m.file_name}`}
                        value={tags[m.path] ?? ''}
                        disabled={!included[m.path]}
                        onChange={(e) => setTags((s) => ({ ...s, [m.path]: e.target.value }))}
                        className="bg-slate-900 border border-slate-700 rounded px-2 py-1 text-[11px] disabled:opacity-40"
                      >
                        {TAGS.map((t) => (
                          <option key={t.value} value={t.value}>{t.label}</option>
                        ))}
                      </select>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </div>

          <div>
            <label htmlFor="s230-dir" className="block text-slate-300 font-semibold mb-1">
              Destination directory <span className="text-slate-500 font-normal">(optional)</span>
            </label>
            <div className="flex space-x-2">
              <input
                id="s230-dir"
                type="text"
                value={outputDir}
                onChange={(e) => setOutputDir(e.target.value)}
                className="flex-1 bg-slate-950 border border-slate-700 rounded px-3 py-2 text-white font-mono text-xs focus:border-cyan-500 focus:outline-none"
              />
              <button
                type="button"
                onClick={handleBrowseDir}
                className="px-3 py-2 bg-slate-800 hover:bg-slate-700 border border-slate-600 rounded text-slate-200 flex items-center space-x-1"
              >
                <FolderOpen className="w-3.5 h-3.5" aria-hidden="true" />
                <span>Browse…</span>
              </button>
            </div>
          </div>

          {result && (
            <div
              role={result.success ? 'status' : 'alert'}
              className={`p-4 rounded-lg border space-y-2 ${result.success ? 'bg-emerald-950/30 border-emerald-600/50' : 'bg-rose-950/30 border-rose-600/50'}`}
            >
              <div className="flex items-center justify-between flex-wrap gap-2">
                <span className="font-bold text-white flex items-center gap-1.5">
                  {result.success ? <CheckCircle2 className="w-4 h-4 text-emerald-400" aria-hidden="true" /> : <AlertTriangle className="w-4 h-4 text-rose-400" aria-hidden="true" />}
                  {result.success ? 'Bundle generated' : 'Generation failed'}
                </span>
                {result.success && (
                  <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-500/20 text-amber-300 border border-amber-500/30">
                    {result.pocso_withheld_count} withheld
                  </span>
                )}
              </div>
              {result.success ? (
                <div className="space-y-1 font-mono text-[11px] text-slate-300">
                  <div><strong>Bundle:</strong> <span className="text-slate-400 break-all">{result.bundle_path}</span></div>
                  <div><strong>Dossier:</strong> <span className="text-slate-400 break-all">{result.html_viewer_path}</span></div>
                </div>
              ) : (
                <p className="text-rose-200">{result.error || result.detail}</p>
              )}
              {result.success && result.bundle_path && (
                <button
                  type="button"
                  onClick={() => handleShowInExplorer(result.bundle_path)}
                  className="mt-1 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 border border-slate-600 rounded text-slate-200 text-xs flex items-center space-x-1"
                >
                  <ExternalLink className="w-3.5 h-3.5 text-cyan-400" aria-hidden="true" />
                  <span>Show in Explorer</span>
                </button>
              )}
            </div>
          )}
        </div>

        <div className="px-5 py-3 bg-[#090f1d] border-t border-slate-800 flex items-center justify-between gap-3 flex-wrap">
          <span className="text-[11px] text-slate-500" aria-live="polite">
            {missing.length > 0 ? `Needs: ${missing.join(', ')}` : 'Ready to generate'}
          </span>
          <div className="flex space-x-2">
            <button onClick={onClose} className="px-4 py-2 bg-slate-800 hover:bg-slate-700 rounded text-slate-300">
              Close
            </button>
            <button
              onClick={handleGenerate}
              disabled={!canGenerate}
              className="px-4 py-2 bg-amber-600 hover:bg-amber-500 text-white font-bold rounded shadow-lg shadow-amber-900/30 flex items-center space-x-1.5 disabled:opacity-40 disabled:cursor-not-allowed"
            >
              {generating ? <Loader2 className="w-3.5 h-3.5 animate-spin" aria-hidden="true" /> : <FileText className="w-3.5 h-3.5" aria-hidden="true" />}
              <span>{generating ? 'Compiling…' : 'Generate Section 230 package'}</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

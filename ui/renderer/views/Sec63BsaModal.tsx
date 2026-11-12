import React, { useCallback, useEffect, useRef, useState } from 'react';
import { X, Printer, Download, ShieldCheck, UserCheck, Loader2, AlertTriangle, RefreshCw } from 'lucide-react';
import { forensicClient } from '../api/forensicClient';
import { useWorkbenchStore } from '../state/workbenchStore';

interface Sec63BsaModalProps {
  isOpen: boolean;
  onClose: () => void;
  /** Kept for caller compatibility; the certificate is built by the backend from recorded facts. */
  deviceMetadata?: unknown;
  counts?: unknown;
}

interface OfficerFields {
  examiner_name: string;
  designation: string;
  fsl_lab: string;
  fir_number: string;
  io_name: string;
  police_station: string;
  court_name: string;
}

const EMPTY: OfficerFields = {
  examiner_name: '',
  designation: '',
  fsl_lab: '',
  fir_number: '',
  io_name: '',
  police_station: '',
  court_name: ''
};

const FIELDS: Array<{ key: keyof OfficerFields; label: string; mono?: boolean }> = [
  { key: 'examiner_name', label: 'Examiner name' },
  { key: 'designation', label: 'Examiner designation' },
  { key: 'fsl_lab', label: 'Forensic laboratory' },
  { key: 'fir_number', label: 'FIR number', mono: true },
  { key: 'io_name', label: 'Investigating officer / custodian' },
  { key: 'police_station', label: 'Police station' },
  { key: 'court_name', label: 'Court of competent jurisdiction' }
];

const BACKEND = 'http://127.0.0.1:8000';

export const Sec63BsaModal: React.FC<Sec63BsaModalProps> = ({ isOpen, onClose }) => {
  const store = useWorkbenchStore();
  const dialogRef = useRef<HTMLDivElement | null>(null);
  const [officer, setOfficer] = useState<OfficerFields>(EMPTY);
  const [html, setHtml] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const caseLoaded = !!store.caseManifest;

  const build = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`${BACKEND}/api/report/sec63-bsa`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(officer)
      });
      if (!res.ok) {
        let detail = res.statusText;
        try {
          const j = await res.json();
          if (j?.detail) detail = typeof j.detail === 'string' ? j.detail : JSON.stringify(j.detail);
        } catch {
          /* not JSON */
        }
        throw new Error(detail || `HTTP ${res.status}`);
      }
      setHtml(await res.text());
    } catch (e: any) {
      setHtml('');
      setError(e?.message || 'Could not generate the certificate');
    } finally {
      setLoading(false);
    }
  }, [officer]);

  // Regenerate (debounced) whenever the dialog opens or the examiner edits a field.
  useEffect(() => {
    if (!isOpen || !caseLoaded) return;
    const t = setTimeout(() => void build(), 350);
    return () => clearTimeout(t);
  }, [isOpen, caseLoaded, build]);

  useEffect(() => {
    if (!isOpen) return;
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && onClose();
    window.addEventListener('keydown', onKey);
    dialogRef.current?.focus();
    return () => window.removeEventListener('keydown', onKey);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  const handlePrint = () => {
    const win = window.open('', '_blank');
    if (win) {
      win.document.write(html);
      win.document.close();
      win.print();
    }
  };

  const handleDownloadHtml = () => {
    const blob = new Blob([html], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `Section63_BSA_Certificate_${store.caseManifest?.caseId ?? 'case'}.html`.replace(/[^\w.\-]/g, '_');
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  return (
    <div
      className="fixed inset-0 z-50 bg-black/80 flex items-center justify-center p-4"
      onMouseDown={(e) => e.target === e.currentTarget && onClose()}
    >
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby="sec63-title"
        tabIndex={-1}
        className="bg-[#0b1320] border border-slate-700 rounded-xl w-full max-w-6xl h-[90vh] flex flex-col shadow-2xl overflow-hidden text-slate-100 font-sans outline-none"
      >
        <div className="h-12 bg-[#090f1d] px-4 border-b border-[#1e293b] flex items-center justify-between shrink-0">
          <div className="flex items-center space-x-2 min-w-0">
            <ShieldCheck className="w-5 h-5 text-emerald-400 shrink-0" aria-hidden="true" />
            <h2 id="sec63-title" className="font-bold text-slate-100 text-sm truncate">
              Section 63(4)(c) BSA, 2023 — Certificate of Electronic Evidence
            </h2>
          </div>
          <button
            onClick={onClose}
            aria-label="Close dialog"
            className="text-slate-400 hover:text-white p-1.5 rounded hover:bg-slate-800 focus-visible:outline focus-visible:outline-2 focus-visible:outline-cyan-400"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="flex-1 flex flex-col md:flex-row overflow-hidden">
          <div className="md:w-80 bg-[#080d19] md:border-r border-b md:border-b-0 border-[#1e293b] p-4 overflow-y-auto space-y-3 text-xs shrink-0 max-h-[40vh] md:max-h-none">
            <div className="text-[11px] font-bold text-slate-400 uppercase tracking-wide flex items-center gap-1.5">
              <UserCheck className="w-3.5 h-3.5 text-cyan-400" aria-hidden="true" />
              <span>Examiner &amp; case particulars</span>
            </div>
            <p className="text-[11px] text-slate-400 leading-relaxed">
              Hashes, device details and counts come from the processed case. Fields left empty are printed as
              “Not provided”.
            </p>

            {FIELDS.map((f) => (
              <div key={f.key}>
                <label htmlFor={`s63-${f.key}`} className="text-[11px] text-slate-300 font-semibold">
                  {f.label}
                </label>
                <input
                  id={`s63-${f.key}`}
                  type="text"
                  value={officer[f.key]}
                  onChange={(e) => setOfficer((o) => ({ ...o, [f.key]: e.target.value }))}
                  className={`w-full bg-slate-950 border border-slate-700 text-slate-200 px-2 py-1.5 rounded mt-1 focus:outline-none focus:border-cyan-500 ${f.mono ? 'font-mono' : ''}`}
                />
              </div>
            ))}

            <div className="pt-2 border-t border-slate-800 space-y-2">
              <button
                onClick={handlePrint}
                disabled={!html || loading}
                className="w-full bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-bold py-2 rounded flex items-center justify-center space-x-1.5 text-xs disabled:opacity-40 disabled:cursor-not-allowed"
              >
                <Printer className="w-4 h-4" aria-hidden="true" />
                <span>Print / save as PDF</span>
              </button>
              <button
                onClick={handleDownloadHtml}
                disabled={!html || loading}
                className="w-full bg-slate-800 hover:bg-slate-700 text-slate-200 font-semibold py-2 rounded flex items-center justify-center space-x-1.5 border border-slate-700 text-xs disabled:opacity-40 disabled:cursor-not-allowed"
              >
                <Download className="w-4 h-4 text-sky-400" aria-hidden="true" />
                <span>Download HTML</span>
              </button>
            </div>
          </div>

          <div className="flex-1 bg-slate-200 p-3 overflow-hidden relative min-h-[300px]">
            {!caseLoaded ? (
              <div className="h-full flex flex-col items-center justify-center text-slate-600 text-center gap-1" role="status">
                <p className="font-semibold">No case loaded</p>
                <p className="text-xs">Ingest evidence first. A certificate is never produced from placeholder data.</p>
              </div>
            ) : error ? (
              <div className="h-full flex flex-col items-center justify-center gap-3 text-center" role="alert">
                <div className="flex items-center gap-2 text-rose-700 font-semibold">
                  <AlertTriangle className="w-4 h-4" aria-hidden="true" /> {error}
                </div>
                <button onClick={() => void build()} className="px-3 py-1.5 bg-slate-800 text-white rounded text-xs flex items-center gap-1.5">
                  <RefreshCw className="w-3.5 h-3.5" aria-hidden="true" /> Retry
                </button>
              </div>
            ) : (
              <>
                {loading && (
                  <div className="absolute top-4 right-4 z-10 bg-slate-900/90 text-slate-100 text-xs px-2.5 py-1.5 rounded flex items-center gap-1.5" role="status">
                    <Loader2 className="w-3.5 h-3.5 animate-spin" aria-hidden="true" /> Updating…
                  </div>
                )}
                {/* sandbox="" : the certificate is inert HTML; no scripts, no navigation. */}
                <iframe
                  srcDoc={html}
                  sandbox=""
                  title="Section 63 BSA certificate preview"
                  className="w-full h-full border-0 bg-white rounded shadow"
                />
              </>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

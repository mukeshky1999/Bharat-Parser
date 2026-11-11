import React, { useState } from 'react';
import {
  X,
  ShieldAlert,
  ShieldCheck,
  FolderOpen,
  FileText,
  Lock,
  ExternalLink,
  EyeOff,
  AlertTriangle,
  CheckCircle2
} from 'lucide-react';
import { forensicClient, Sec230BnssResponse } from '../api/forensicClient';
import { useWorkbenchStore } from '../state/workbenchStore';

interface Sec230BnssModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const Sec230BnssModal: React.FC<Sec230BnssModalProps> = ({ isOpen, onClose }) => {
  const store = useWorkbenchStore();

  const [caseId, setCaseId] = useState(store.caseManifest?.evidenceFileName ? `CASE_${store.caseManifest.evidenceFileName}` : 'CASE_2026_CRIME_01');
  const [victimName, setVictimName] = useState('Sunita Sharma (Complainant)');
  const [anonymizeVictim, setAnonymizeVictim] = useState(true);
  const [outputDir, setOutputDir] = useState('');
  const [generating, setGenerating] = useState(false);
  const [result, setResult] = useState<Sec230BnssResponse | null>(null);

  if (!isOpen) return null;

  const handleBrowseDir = async () => {
    try {
      if (typeof window !== 'undefined' && window.electronAPI?.openFolderDialog) {
        const folder = await window.electronAPI.openFolderDialog({ title: 'Select Output Directory for Section 230 BNSS Bundle' });
        if (folder) setOutputDir(folder);
      } else {
        const folder = await forensicClient.pickEvidenceFolder();
        if (folder) setOutputDir(folder);
      }
    } catch {
      // Ignore
    }
  };

  const handleGenerate = async () => {
    setGenerating(true);
    try {
      const res = await forensicClient.generateSec230BnssPackage(
        caseId,
        outputDir || undefined,
        anonymizeVictim,
        victimName
      );
      setResult(res);
      if (res.success) {
        store.addToast({
          title: 'Section 230 BNSS Bundle Ready',
          message: `Generated defense disclosure bundle with ${res.pocso_withheld_count} withheld notice cards.`,
          type: 'success'
        });
      }
    } catch (e: any) {
      store.addToast({
        title: 'Bundle Generation Failed',
        message: e?.message || 'Error executing Section 230 packager',
        type: 'error'
      });
    } finally {
      setGenerating(false);
    }
  };

  const handleShowInExplorer = async (path: string) => {
    if (typeof window !== 'undefined' && window.electronAPI?.showItemInFolder) {
      await window.electronAPI.showItemInFolder(path);
    }
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="bg-[#0b1320] border border-cyan-800/60 rounded-xl shadow-2xl w-full max-w-3xl flex flex-col max-h-[90vh] overflow-hidden text-slate-100 font-sans">
        {/* Header */}
        <div className="px-5 py-4 bg-[#090f1d] border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center space-x-2.5">
            <div className="w-8 h-8 rounded-lg bg-amber-500/20 border border-amber-500/40 flex items-center justify-center text-amber-400">
              <ShieldAlert className="w-4 h-4" />
            </div>
            <div>
              <h2 className="text-sm font-bold tracking-wide uppercase text-white flex items-center gap-2">
                Section 230 BNSS (2023) — Defense Disclosure Copy
              </h2>
              <p className="text-[11px] text-slate-400 font-mono">
                Statutory Redaction Gate • P. Gopalkrishnan v. State of Kerala (2019) • Sec 72 BNS 2023
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-white p-1 rounded hover:bg-slate-800 transition-colors cursor-pointer"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Content Body */}
        <div className="flex-1 overflow-y-auto p-5 space-y-4 text-xs">
          {/* Statutory Mandate Card */}
          <div className="p-3 bg-amber-950/30 border border-amber-600/40 rounded-lg text-amber-200/90 space-y-1">
            <div className="font-bold flex items-center gap-1.5 text-amber-300">
              <Lock className="w-3.5 h-3.5 text-amber-400" />
              <span>Mandatory Judicial Withholding Gate</span>
            </div>
            <p className="text-[11px] leading-relaxed text-amber-200/80">
              Pursuant to the Supreme Court mandate in <em>P. Gopalkrishnan v. State of Kerala (2019)</em> and the POCSO Act 2012,
              sensitive visual media (CSAM / intimate footage) is withheld from duplication in the defense package and replaced with
              official <strong>Statutory Judicial-Inspection Notice Cards</strong>.
            </p>
          </div>

          {/* Form Fields */}
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-slate-400 font-semibold mb-1">Case Reference ID</label>
              <input
                type="text"
                value={caseId}
                onChange={(e) => setCaseId(e.target.value)}
                className="w-full bg-slate-950 border border-slate-700 rounded px-3 py-1.5 text-white font-mono text-xs focus:border-cyan-500 focus:outline-none"
              />
            </div>

            <div>
              <label className="block text-slate-400 font-semibold mb-1">Complainant / Subject Name</label>
              <input
                type="text"
                value={victimName}
                onChange={(e) => setVictimName(e.target.value)}
                className="w-full bg-slate-950 border border-slate-700 rounded px-3 py-1.5 text-white text-xs focus:border-cyan-500 focus:outline-none"
              />
            </div>
          </div>

          {/* Anonymization Toggle */}
          <div className="flex items-center justify-between p-3 bg-slate-950/70 border border-slate-800 rounded-lg">
            <div className="flex items-center space-x-2">
              <EyeOff className="w-4 h-4 text-cyan-400" />
              <div>
                <span className="font-bold text-slate-200 block">Section 72 BNS 2023 Victim Anonymization</span>
                <span className="text-[11px] text-slate-400">
                  Redact victim legal name across all exhibits and replace with [VICTIM_PROTECTED_ID_01]
                </span>
              </div>
            </div>
            <input
              type="checkbox"
              checked={anonymizeVictim}
              onChange={(e) => setAnonymizeVictim(e.target.checked)}
              className="w-4 h-4 accent-cyan-500 cursor-pointer"
            />
          </div>

          {/* Output Directory Picker */}
          <div>
            <label className="block text-slate-400 font-semibold mb-1">Destination Directory (Optional)</label>
            <div className="flex space-x-2">
              <input
                type="text"
                value={outputDir}
                placeholder="Default active case workspace"
                onChange={(e) => setOutputDir(e.target.value)}
                className="flex-1 bg-slate-950 border border-slate-700 rounded px-3 py-1.5 text-white font-mono text-xs focus:border-cyan-500 focus:outline-none"
              />
              <button
                type="button"
                onClick={handleBrowseDir}
                className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 border border-slate-600 rounded text-slate-200 flex items-center space-x-1 cursor-pointer"
              >
                <FolderOpen className="w-3.5 h-3.5" />
                <span>Browse...</span>
              </button>
            </div>
          </div>

          {/* Result Card if generated */}
          {result && (
            <div className={`p-4 rounded-lg border space-y-2 ${result.success ? 'bg-emerald-950/30 border-emerald-600/50' : 'bg-rose-950/30 border-rose-600/50'}`}>
              <div className="flex items-center justify-between">
                <span className="font-bold text-white flex items-center gap-1.5">
                  {result.success ? <CheckCircle2 className="w-4 h-4 text-emerald-400" /> : <AlertTriangle className="w-4 h-4 text-rose-400" />}
                  {result.success ? 'Section 230 BNSS Defense Bundle Generated' : 'Generation Failed'}
                </span>
                <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-500/20 text-amber-300 border border-amber-500/30">
                  {result.pocso_withheld_count} CSAM/Intimate Media Withheld
                </span>
              </div>

              <div className="space-y-1 font-mono text-[11px] text-slate-300">
                <div><strong>Bundle Path:</strong> <span className="text-slate-400 break-all">{result.bundle_path}</span></div>
                <div><strong>Dossier HTML:</strong> <span className="text-slate-400 break-all">{result.html_viewer_path}</span></div>
              </div>

              {result.bundle_path && (
                <button
                  type="button"
                  onClick={() => handleShowInExplorer(result.bundle_path)}
                  className="mt-2 px-3 py-1 bg-slate-800 hover:bg-slate-700 border border-slate-600 rounded text-slate-200 text-xs flex items-center space-x-1 cursor-pointer"
                >
                  <ExternalLink className="w-3.5 h-3.5 text-cyan-400" />
                  <span>Show Bundle in Explorer</span>
                </button>
              )}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-5 py-3 bg-[#090f1d] border-t border-slate-800 flex items-center justify-between">
          <span className="text-[11px] text-slate-500 font-mono">
            Court Admissibility Standard: BSA 2023 / BNSS 2023
          </span>
          <div className="flex space-x-2">
            <button
              onClick={onClose}
              className="px-4 py-1.5 bg-slate-800 hover:bg-slate-700 rounded text-slate-300 cursor-pointer"
            >
              Close
            </button>
            <button
              onClick={handleGenerate}
              disabled={generating}
              className="px-4 py-1.5 bg-gradient-to-r from-amber-600 to-amber-500 hover:from-amber-500 hover:to-amber-400 text-white font-bold rounded shadow-lg shadow-amber-900/30 flex items-center space-x-1.5 cursor-pointer disabled:opacity-50"
            >
              <FileText className="w-3.5 h-3.5" />
              <span>{generating ? 'Compiling Package...' : 'Generate Section 230 Package'}</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

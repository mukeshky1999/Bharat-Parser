import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  X,
  ShieldAlert,
  ShieldCheck,
  FolderOpen,
  FileSpreadsheet,
  Download,
  ExternalLink,
  CheckCircle2,
  Lock,
  Loader2,
  AlertTriangle
} from 'lucide-react';
import { forensicClient, NcrpCandidate, NcrpFreezeResponse } from '../api/forensicClient';
import { useWorkbenchStore } from '../state/workbenchStore';

interface Ncrp1930FreezeModalProps {
  isOpen: boolean;
  onClose: () => void;
}

const UTILITY_HINT = /billdesk|bescom|electricity|irctc|utility|recharge/i;

const isUtility = (c: NcrpCandidate) => UTILITY_HINT.test(c.vpa) || UTILITY_HINT.test(c.account_no);

export const Ncrp1930FreezeModal: React.FC<Ncrp1930FreezeModalProps> = ({ isOpen, onClose }) => {
  const store = useWorkbenchStore();
  const dialogRef = useRef<HTMLDivElement | null>(null);

  const [acknowledgementNo, setAcknowledgementNo] = useState('');
  const [complainantAccount, setComplainantAccount] = useState('');
  const [outputDir, setOutputDir] = useState('');
  const [candidates, setCandidates] = useState<NcrpCandidate[]>([]);
  const [selected, setSelected] = useState<Record<string, boolean>>({});
  const [loading, setLoading] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [exporting, setExporting] = useState(false);
  const [result, setResult] = useState<NcrpFreezeResponse | null>(null);
  const [exportError, setExportError] = useState<string | null>(null);

  // Candidates always come from the loaded case. Reload when the complainant account changes so the
  // victim safeguard lock is applied to the right row.
  const loadCandidates = useCallback(async (account: string) => {
    setLoading(true);
    setLoadError(null);
    const res = await forensicClient.getNcrpCandidates(account.trim());
    setCandidates(res.candidates);
    setLoadError(res.error ?? null);
    setSelected(Object.fromEntries(res.candidates.map((c) => [c.account_no, !c.is_complainant_victim && !isUtility(c)])));
    setLoading(false);
  }, []);

  useEffect(() => {
    if (!isOpen) return;
    setResult(null);
    setExportError(null);
    const t = setTimeout(() => void loadCandidates(complainantAccount), 250);
    return () => clearTimeout(t);
  }, [isOpen, complainantAccount, loadCandidates]);

  // Dialog behaviour: Escape closes, focus moves into the dialog.
  useEffect(() => {
    if (!isOpen) return;
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && onClose();
    window.addEventListener('keydown', onKey);
    dialogRef.current?.focus();
    return () => window.removeEventListener('keydown', onKey);
  }, [isOpen, onClose]);

  const chosen = useMemo(
    () => candidates.filter((c) => selected[c.account_no] && !c.is_complainant_victim),
    [candidates, selected]
  );
  const lienTotal = chosen.reduce((sum, c) => sum + c.volume_inr, 0);
  const missing: string[] = [];
  if (!complainantAccount.trim()) missing.push('complainant source account');
  if (!acknowledgementNo.trim()) missing.push('acknowledgement number');
  if (chosen.length === 0) missing.push('at least one account to freeze');
  const canExport = missing.length === 0 && !exporting;

  if (!isOpen) return null;

  const handleBrowseDir = async () => {
    try {
      if (window.electronAPI?.openFolderDialog) {
        const folder = await window.electronAPI.openFolderDialog({ title: 'Select Output Directory for NCRP 1930 Freeze Packet' });
        if (folder) setOutputDir(folder);
      } else {
        const folder = await forensicClient.pickEvidenceFolder();
        if (folder) setOutputDir(folder);
      }
    } catch {
      /* user cancelled */
    }
  };

  const handleExport = async () => {
    setExporting(true);
    setExportError(null);
    try {
      // Send the full list (so the victim lock is evaluated) but mark unchecked rows as non-targets.
      const payload = candidates.map((c) => ({
        ...c,
        is_complainant_victim: c.is_complainant_victim || c.account_no === complainantAccount.trim(),
        // De-confliction excludes anything utility-like; unchecked rows are simply not sent.
      })).filter((c) => c.is_complainant_victim || selected[c.account_no]);
      const res = await forensicClient.exportNcrpFreezePacket(
        payload,
        outputDir || undefined,
        complainantAccount.trim(),
        acknowledgementNo.trim()
      );
      setResult(res);
      if (res.success) {
        store.addToast({
          title: '1930 NCRP freeze sheet ready',
          message: `${res.total_freeze_targets} account(s) targeted. Complainant safeguard lock active.`,
          type: 'success'
        });
      } else {
        setExportError(res.error || res.detail || 'Export failed');
      }
    } catch (e: any) {
      setExportError(e?.message || 'Error exporting 1930 freeze packet');
    } finally {
      setExporting(false);
    }
  };

  const handleShowInExplorer = async (path: string) => {
    if (window.electronAPI?.showItemInFolder) await window.electronAPI.showItemInFolder(path);
  };

  const handleDownloadCsv = () => {
    if (!result?.csv_content) return;
    const blob = new Blob([result.csv_content], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.setAttribute('download', 'ncrp_1930_bank_freeze_packet.csv');
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
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
        aria-labelledby="ncrp-title"
        tabIndex={-1}
        className="bg-[#0b1320] border border-cyan-800/60 rounded-xl shadow-2xl w-full max-w-4xl flex flex-col max-h-[90vh] overflow-hidden text-slate-100 font-sans outline-none"
      >
        <div className="px-5 py-4 bg-[#090f1d] border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center space-x-2.5">
            <div className="w-8 h-8 rounded-lg bg-rose-500/20 border border-rose-500/40 flex items-center justify-center text-rose-400">
              <ShieldAlert className="w-4 h-4" aria-hidden="true" />
            </div>
            <div>
              <h2 id="ncrp-title" className="text-sm font-bold tracking-wide uppercase text-white">
                1930 NCRP / I4C CFCFRMS — Bank Lien Sheet
              </h2>
              <p className="text-[11px] text-slate-400 font-mono">
                14-column freeze packet • Candidates are derived from this case’s transactions
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            aria-label="Close dialog"
            className="text-slate-400 hover:text-white p-1.5 rounded hover:bg-slate-800 transition-colors focus-visible:outline focus-visible:outline-2 focus-visible:outline-cyan-400"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="flex-1 overflow-y-auto p-5 space-y-4 text-xs">
          <div className="p-3 bg-emerald-950/30 border border-emerald-600/40 rounded-lg text-emerald-200/90 flex items-start space-x-2.5">
            <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" aria-hidden="true" />
            <p className="text-[11px] leading-relaxed text-emerald-200/80">
              <span className="font-bold text-emerald-300">Complainant safeguard.</span> The complainant’s own account is locked
              and can never appear in the freeze list. Utility and biller accounts are unchecked by default.
              Candidates are leads from the phone data — verify each against the bank record before submitting.
            </p>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div>
              <label htmlFor="ncrp-ack" className="block text-slate-300 font-semibold mb-1">
                Acknowledgement number <span className="text-rose-400" aria-hidden="true">*</span>
              </label>
              <input
                id="ncrp-ack"
                type="text"
                value={acknowledgementNo}
                onChange={(e) => setAcknowledgementNo(e.target.value)}
                placeholder="As issued by the NCRP portal"
                className="w-full bg-slate-950 border border-slate-700 rounded px-3 py-2 text-white font-mono text-xs focus:border-cyan-500 focus:outline-none focus-visible:ring-1 focus-visible:ring-cyan-500"
              />
            </div>
            <div>
              <label htmlFor="ncrp-comp" className="block text-slate-300 font-semibold mb-1">
                Complainant source account <span className="text-rose-400" aria-hidden="true">*</span>
              </label>
              <input
                id="ncrp-comp"
                type="text"
                value={complainantAccount}
                onChange={(e) => setComplainantAccount(e.target.value)}
                placeholder="Account number or VPA the victim paid from"
                className="w-full bg-slate-950 border border-slate-700 rounded px-3 py-2 text-white font-mono text-xs focus:border-cyan-500 focus:outline-none focus-visible:ring-1 focus-visible:ring-cyan-500"
              />
            </div>
          </div>

          <div>
            <div className="flex items-center justify-between mb-1.5">
              <span className="text-slate-300 font-bold uppercase tracking-wider text-[11px]">Candidate accounts</span>
              <span className="text-[10px] text-slate-400 font-mono" aria-live="polite">
                {loading ? 'Loading…' : `${candidates.length} found · ${chosen.length} selected`}
              </span>
            </div>

            <div className="border border-slate-800 rounded-lg overflow-hidden bg-slate-950/80">
              {loading ? (
                <div className="p-8 flex items-center justify-center text-slate-400 gap-2" role="status">
                  <Loader2 className="w-4 h-4 animate-spin" aria-hidden="true" /> Reading transactions…
                </div>
              ) : loadError ? (
                <div className="p-6 text-center text-amber-300 flex items-center justify-center gap-2" role="alert">
                  <AlertTriangle className="w-4 h-4" aria-hidden="true" /> {loadError}
                </div>
              ) : candidates.length === 0 ? (
                <div className="p-8 text-center text-slate-400">
                  <p className="font-semibold text-slate-300">No candidate accounts</p>
                  <p className="mt-1 text-[11px]">
                    This case has no successful outgoing transactions. Load a case with transaction data first;
                    nothing is generated from sample accounts.
                  </p>
                </div>
              ) : (
                <table className="w-full text-left border-collapse text-xs">
                  <caption className="sr-only">Freeze candidate accounts</caption>
                  <thead>
                    <tr className="bg-slate-900 border-b border-slate-800 text-slate-400">
                      <th scope="col" className="py-2 px-3 w-10">Lien</th>
                      <th scope="col" className="py-2 px-3 font-semibold">Account / identifier</th>
                      <th scope="col" className="py-2 px-3 font-semibold">IFSC</th>
                      <th scope="col" className="py-2 px-3 font-semibold text-right">Volume (INR)</th>
                      <th scope="col" className="py-2 px-3 font-semibold">Status</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60 font-mono text-[11px]">
                    {candidates.map((c) => {
                      const victim = c.is_complainant_victim || c.account_no === complainantAccount.trim();
                      const util = isUtility(c);
                      return (
                        <tr key={c.account_no} className={victim ? 'bg-emerald-950/10' : util ? 'bg-slate-900/30' : ''}>
                          <td className="py-2 px-3 text-center">
                            {victim ? (
                              <span className="inline-flex text-emerald-400" title="Locked: complainant account">
                                <Lock className="w-3.5 h-3.5" aria-label="Locked: complainant account" />
                              </span>
                            ) : (
                              <input
                                type="checkbox"
                                aria-label={`Freeze ${c.account_no}`}
                                checked={!!selected[c.account_no]}
                                onChange={(e) => setSelected((s) => ({ ...s, [c.account_no]: e.target.checked }))}
                                className="w-3.5 h-3.5 accent-rose-500 cursor-pointer"
                              />
                            )}
                          </td>
                          <td className="py-2 px-3 text-slate-200">
                            <div className="break-all">{c.account_no}</div>
                            {c.vpa && c.vpa !== c.account_no && <div className="text-[10px] text-slate-400">{c.vpa}</div>}
                            {c.counterparty_name && <div className="text-[10px] text-slate-500">{c.counterparty_name}</div>}
                          </td>
                          <td className="py-2 px-3 text-slate-400">{c.ifsc || 'not recorded'}</td>
                          <td className="py-2 px-3 text-amber-300 font-semibold text-right">
                            ₹{c.volume_inr.toLocaleString('en-IN', { minimumFractionDigits: 2 })}
                          </td>
                          <td className="py-2 px-3">
                            {victim ? (
                              <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">
                                COMPLAINANT — DO NOT FREEZE
                              </span>
                            ) : util ? (
                              <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-800 text-slate-400 border border-slate-700">
                                UTILITY / BILLER
                              </span>
                            ) : (
                              <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-500/15 text-rose-300 border border-rose-500/40">
                                CANDIDATE
                              </span>
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

          <div>
            <label htmlFor="ncrp-dir" className="block text-slate-300 font-semibold mb-1">
              Destination directory <span className="text-slate-500 font-normal">(optional, defaults to the case workspace)</span>
            </label>
            <div className="flex space-x-2">
              <input
                id="ncrp-dir"
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

          {exportError && (
            <div role="alert" className="p-3 rounded-lg border border-rose-600/50 bg-rose-950/30 text-rose-200 flex items-start gap-2">
              <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" aria-hidden="true" />
              <span>{exportError}</span>
            </div>
          )}

          {result?.success && (
            <div className="p-4 bg-emerald-950/20 border border-emerald-600/50 rounded-lg space-y-2" role="status">
              <div className="flex items-center justify-between flex-wrap gap-2">
                <span className="font-bold text-white flex items-center gap-1.5">
                  <CheckCircle2 className="w-4 h-4 text-emerald-400" aria-hidden="true" />
                  Freeze packet exported
                </span>
                <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">
                  {result.total_freeze_targets} account(s) targeted
                </span>
              </div>
              <div className="space-y-1 font-mono text-[11px] text-slate-300">
                <div><strong>Lien sum:</strong> <span className="text-amber-400 font-bold">₹{result.total_lien_amount_inr?.toLocaleString('en-IN', { minimumFractionDigits: 2 })}</span></div>
                <div><strong>CSV path:</strong> <span className="text-slate-400 break-all">{result.csv_path}</span></div>
                <div><strong>SHA-256:</strong> <span className="text-cyan-400 break-all">{result.sha256}</span></div>
              </div>
              <div className="pt-2 flex flex-wrap gap-2">
                <button type="button" onClick={handleDownloadCsv} className="px-3 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-white rounded text-xs flex items-center space-x-1 font-bold">
                  <Download className="w-3.5 h-3.5" aria-hidden="true" /><span>Download CSV</span>
                </button>
                {result.csv_path && (
                  <button type="button" onClick={() => handleShowInExplorer(result.csv_path)} className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 border border-slate-600 rounded text-slate-200 text-xs flex items-center space-x-1">
                    <ExternalLink className="w-3.5 h-3.5 text-cyan-400" aria-hidden="true" /><span>Show in Explorer</span>
                  </button>
                )}
              </div>
            </div>
          )}
        </div>

        <div className="px-5 py-3 bg-[#090f1d] border-t border-slate-800 flex items-center justify-between gap-3 flex-wrap">
          <span className="text-[11px] text-slate-500" aria-live="polite">
            {missing.length > 0 ? `Needs: ${missing.join(', ')}` : `Lien total ₹${lienTotal.toLocaleString('en-IN', { minimumFractionDigits: 2 })}`}
          </span>
          <div className="flex space-x-2">
            <button onClick={onClose} className="px-4 py-2 bg-slate-800 hover:bg-slate-700 rounded text-slate-300">
              Close
            </button>
            <button
              onClick={handleExport}
              disabled={!canExport}
              className="px-4 py-2 bg-rose-600 hover:bg-rose-500 text-white font-bold rounded shadow-lg shadow-rose-900/30 flex items-center space-x-1.5 disabled:opacity-40 disabled:cursor-not-allowed"
            >
              {exporting ? <Loader2 className="w-3.5 h-3.5 animate-spin" aria-hidden="true" /> : <FileSpreadsheet className="w-3.5 h-3.5" aria-hidden="true" />}
              <span>{exporting ? 'Exporting…' : 'Export 1930 NCRP sheet'}</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

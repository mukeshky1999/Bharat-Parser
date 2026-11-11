import React, { useState } from 'react';
import {
  X,
  Shield,
  ShieldAlert,
  ShieldCheck,
  FolderOpen,
  FileSpreadsheet,
  Download,
  ExternalLink,
  AlertTriangle,
  CheckCircle2,
  Lock
} from 'lucide-react';
import { forensicClient, NcrpFreezeResponse } from '../api/forensicClient';
import { useWorkbenchStore } from '../state/workbenchStore';

interface Ncrp1930FreezeModalProps {
  isOpen: boolean;
  onClose: () => void;
}

interface CandidateRow {
  account_no: string;
  ifsc: string;
  vpa: string;
  is_complainant_victim: boolean;
  volume_inr: number;
}

export const Ncrp1930FreezeModal: React.FC<Ncrp1930FreezeModalProps> = ({ isOpen, onClose }) => {
  const store = useWorkbenchStore();

  const [acknowledgementNo, setAcknowledgementNo] = useState('1930-2026-NCRP-8821');
  const [complainantAccount, setComplainantAccount] = useState('98765432109876 (HDFC Bank)');
  const [outputDir, setOutputDir] = useState('');
  const [exporting, setExporting] = useState(false);
  const [result, setResult] = useState<NcrpFreezeResponse | null>(null);

  // Pre-loaded candidate accounts
  const [candidates, setCandidates] = useState<CandidateRow[]>([
    {
      account_no: '98765432109876',
      ifsc: 'HDFC0000001',
      vpa: 'victim@okhdfcbank',
      is_complainant_victim: true,
      volume_inr: 250000.0,
    },
    {
      account_no: '987654321012',
      ifsc: 'SBIN0001234',
      vpa: 'mule1@oksbi',
      is_complainant_victim: false,
      volume_inr: 235000.0,
    },
    {
      account_no: 'BESCOM_UTILITY_ESCROW',
      ifsc: 'SBIN0000002',
      vpa: 'bescom.billdesk@icici',
      is_complainant_victim: false,
      volume_inr: 1500.0,
    },
    {
      account_no: '112233445566',
      ifsc: 'ICIC0005678',
      vpa: 'mule2@icici',
      is_complainant_victim: false,
      volume_inr: 220000.0,
    },
  ]);

  if (!isOpen) return null;

  const handleBrowseDir = async () => {
    try {
      if (typeof window !== 'undefined' && window.electronAPI?.openFolderDialog) {
        const folder = await window.electronAPI.openFolderDialog({ title: 'Select Output Directory for NCRP 1930 Freeze Packet' });
        if (folder) setOutputDir(folder);
      } else {
        const folder = await forensicClient.pickEvidenceFolder();
        if (folder) setOutputDir(folder);
      }
    } catch {
      // Ignore
    }
  };

  const handleExport = async () => {
    setExporting(true);
    try {
      const res = await forensicClient.exportNcrpFreezePacket(
        candidates,
        outputDir || undefined
      );
      setResult(res);
      if (res.success) {
        store.addToast({
          title: '1930 NCRP Freeze Sheet Ready',
          message: `De-conflicted ${res.total_freeze_targets} target accounts. Complainant safeguard lock active.`,
          type: 'success'
        });
      }
    } catch (e: any) {
      store.addToast({
        title: 'Export Failed',
        message: e?.message || 'Error exporting 1930 freeze packet',
        type: 'error'
      });
    } finally {
      setExporting(false);
    }
  };

  const handleShowInExplorer = async (path: string) => {
    if (typeof window !== 'undefined' && window.electronAPI?.showItemInFolder) {
      await window.electronAPI.showItemInFolder(path);
    }
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
    <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="bg-[#0b1320] border border-cyan-800/60 rounded-xl shadow-2xl w-full max-w-4xl flex flex-col max-h-[90vh] overflow-hidden text-slate-100 font-sans">
        {/* Header */}
        <div className="px-5 py-4 bg-[#090f1d] border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center space-x-2.5">
            <div className="w-8 h-8 rounded-lg bg-rose-500/20 border border-rose-500/40 flex items-center justify-center text-rose-400">
              <ShieldAlert className="w-4 h-4" />
            </div>
            <div>
              <h2 className="text-sm font-bold tracking-wide uppercase text-white flex items-center gap-2">
                1930 NCRP / I4C CFCFRMS — Golden-Hour Bank Lien Cart
              </h2>
              <p className="text-[11px] text-slate-400 font-mono">
                14-Column Inter-Bank Freeze Packet • Complainant Safeguard Lock
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
          {/* Safeguard Notice Banner */}
          <div className="p-3 bg-emerald-950/30 border border-emerald-600/40 rounded-lg text-emerald-200/90 flex items-start space-x-2.5">
            <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
            <div className="space-y-1">
              <span className="font-bold text-emerald-300 block">Complainant / Victim Safeguard Lock Enforced</span>
              <p className="text-[11px] leading-relaxed text-emerald-200/80">
                To prevent accidental liening of victim assets, accounts flagged as <code>is_complainant_victim = true</code> have their
                freeze checkboxes permanently disabled (<code>freeze_checkbox_disabled = true</code>) and are barred from inclusion
                in the outgoing 14-column NCRP freeze manifest.
              </p>
            </div>
          </div>

          {/* Form Controls */}
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-slate-400 font-semibold mb-1">Acknowledgement Number</label>
              <input
                type="text"
                value={acknowledgementNo}
                onChange={(e) => setAcknowledgementNo(e.target.value)}
                className="w-full bg-slate-950 border border-slate-700 rounded px-3 py-1.5 text-white font-mono text-xs focus:border-cyan-500 focus:outline-none"
              />
            </div>

            <div>
              <label className="block text-slate-400 font-semibold mb-1">Complainant Source Account</label>
              <input
                type="text"
                value={complainantAccount}
                onChange={(e) => setComplainantAccount(e.target.value)}
                className="w-full bg-slate-950 border border-slate-700 rounded px-3 py-1.5 text-white font-mono text-xs focus:border-cyan-500 focus:outline-none"
              />
            </div>
          </div>

          {/* Candidate Accounts Table */}
          <div>
            <div className="flex items-center justify-between mb-1.5">
              <span className="text-slate-300 font-bold uppercase tracking-wider text-[11px]">
                Freeze Candidate Accounts &amp; 3-Tier De-Confliction
              </span>
              <span className="text-[10px] text-slate-400 font-mono">
                {candidates.length} Accounts Monitored
              </span>
            </div>

            <div className="border border-slate-800 rounded-lg overflow-hidden bg-slate-950/80">
              <table className="w-full text-left border-collapse text-xs">
                <thead>
                  <tr className="bg-slate-900 border-b border-slate-800 text-slate-400">
                    <th className="py-2 px-3 w-10">Lien</th>
                    <th className="py-2 px-3 font-semibold">Account / Identifier</th>
                    <th className="py-2 px-3 font-semibold">Bank / IFSC</th>
                    <th className="py-2 px-3 font-semibold">Volume (INR)</th>
                    <th className="py-2 px-3 font-semibold">De-Confliction Role Badge</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 font-mono text-[11px]">
                  {candidates.map((c, idx) => {
                    const isVictim = c.is_complainant_victim;
                    const isUtility = c.vpa.toLowerCase().includes('billdesk') || c.account_no.toLowerCase().includes('bescom');

                    return (
                      <tr key={idx} className={isVictim ? 'bg-emerald-950/10' : isUtility ? 'bg-slate-900/30' : 'bg-rose-950/10'}>
                        <td className="py-2 px-3 text-center">
                          {isVictim ? (
                            <div className="flex items-center justify-center text-emerald-400" title="Safeguard Lock: Cannot Freeze Victim">
                              <Lock className="w-3.5 h-3.5" />
                            </div>
                          ) : (
                            <input
                              type="checkbox"
                              defaultChecked={!isUtility}
                              className="w-3.5 h-3.5 accent-rose-500 cursor-pointer"
                            />
                          )}
                        </td>
                        <td className="py-2 px-3 text-slate-200">
                          <div>{c.account_no}</div>
                          <div className="text-[10px] text-slate-400">{c.vpa}</div>
                        </td>
                        <td className="py-2 px-3 text-slate-300">{c.ifsc}</td>
                        <td className="py-2 px-3 text-amber-300 font-semibold">₹{c.volume_inr.toLocaleString('en-IN', { minimumFractionDigits: 2 })}</td>
                        <td className="py-2 px-3">
                          {isVictim ? (
                            <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">
                              🛡️ VICTIM / COMPLAINANT — DO NOT FREEZE
                            </span>
                          ) : isUtility ? (
                            <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-800 text-slate-400 border border-slate-700">
                              ⚠️ UTILITY / BILLER — EXCLUDED
                            </span>
                          ) : (
                            <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-500/20 text-rose-300 border border-rose-500/40">
                              🚨 LAYER-1 MULE TARGET
                            </span>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>

          {/* Destination Directory */}
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

          {/* Results Summary */}
          {result && (
            <div className="p-4 bg-emerald-950/20 border border-emerald-600/50 rounded-lg space-y-2">
              <div className="flex items-center justify-between">
                <span className="font-bold text-white flex items-center gap-1.5">
                  <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                  <span>14-Column 1930 NCRP Freeze Packet Successfully Exported</span>
                </span>
                <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">
                  {result.total_freeze_targets} Accounts Targeted for Debit Lien
                </span>
              </div>

              <div className="space-y-1 font-mono text-[11px] text-slate-300">
                <div><strong>Lien Sum:</strong> <span className="text-amber-400 font-bold">₹{result.total_lien_amount_inr?.toLocaleString('en-IN', { minimumFractionDigits: 2 })}</span></div>
                <div><strong>CSV Path:</strong> <span className="text-slate-400 break-all">{result.csv_path}</span></div>
                <div><strong>SHA-256 Digest:</strong> <span className="text-cyan-400 break-all">{result.sha256}</span></div>
              </div>

              <div className="pt-2 flex space-x-2">
                <button
                  type="button"
                  onClick={handleDownloadCsv}
                  className="px-3 py-1 bg-cyan-600 hover:bg-cyan-500 text-white rounded text-xs flex items-center space-x-1 cursor-pointer font-bold"
                >
                  <Download className="w-3.5 h-3.5" />
                  <span>Download 14-Column CSV</span>
                </button>
                {result.csv_path && (
                  <button
                    type="button"
                    onClick={() => handleShowInExplorer(result.csv_path)}
                    className="px-3 py-1 bg-slate-800 hover:bg-slate-700 border border-slate-600 rounded text-slate-200 text-xs flex items-center space-x-1 cursor-pointer"
                  >
                    <ExternalLink className="w-3.5 h-3.5 text-cyan-400" />
                    <span>Show in Windows Explorer</span>
                  </button>
                )}
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-5 py-3 bg-[#090f1d] border-t border-slate-800 flex items-center justify-between">
          <span className="text-[11px] text-slate-500 font-mono">
            Portal Rail: I4C NCRP 1930 CFCFRMS Gateway
          </span>
          <div className="flex space-x-2">
            <button
              onClick={onClose}
              className="px-4 py-1.5 bg-slate-800 hover:bg-slate-700 rounded text-slate-300 cursor-pointer"
            >
              Close
            </button>
            <button
              onClick={handleExport}
              disabled={exporting}
              className="px-4 py-1.5 bg-gradient-to-r from-rose-600 to-rose-500 hover:from-rose-500 hover:to-rose-400 text-white font-bold rounded shadow-lg shadow-rose-900/30 flex items-center space-x-1.5 cursor-pointer disabled:opacity-50"
            >
              <FileSpreadsheet className="w-3.5 h-3.5" />
              <span>{exporting ? 'Exporting...' : 'Export 14-Col 1930 NCRP Sheet'}</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

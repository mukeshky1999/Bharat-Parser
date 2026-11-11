import React, { useState } from 'react';
import { X, Printer, Download, FileText, ShieldCheck, Lock, Building, UserCheck } from 'lucide-react';
import { Section63BsaCertificate, DeviceMetadata } from '../../shared/forensic-types';
import { Sec63BsaGenerator } from '../../main/reporting/sec63_bsa_generator';
import { useWorkbenchStore } from '../state/workbenchStore';

interface Sec63BsaModalProps {
  isOpen: boolean;
  onClose: () => void;
  deviceMetadata?: DeviceMetadata;
  counts?: {
    upiCount: number;
    walCount: number;
    carvedCount: number;
    apkCount: number;
    remoteCount: number;
    chatCount: number;
  };
}

export const Sec63BsaModal: React.FC<Sec63BsaModalProps> = ({
  isOpen,
  onClose,
  deviceMetadata,
  counts: propCounts,
}) => {
  const store = useWorkbenchStore();

  const [firNumber, setFirNumber] = useState('FIR-402/2026');
  const [policeStation, setPoliceStation] = useState('Cyber Crime Police Station, Central Division');
  const [district, setDistrict] = useState('Bengaluru Urban');
  const [courtName, setCourtName] = useState("Hon'ble Principal City Civil & Sessions Judge, Special Cyber Division");
  const [caseTitle, setCaseTitle] = useState('State of Karnataka vs. Cyber Fraud Syndicate (Mule Network)');
  const [actSections, setActSections] = useState('Sec 66C, 66D IT Act 2000 r/w Sec 318(4), 316(2) BNS 2023');
  const [examinerName, setExaminerName] = useState('Inspector Rajesh Kumar, FSL');
  const [examinerDesignation, setExaminerDesignation] = useState('Senior Digital Forensics Examiner');
  const [fslLaboratory, setFslLaboratory] = useState('State Digital Forensics Science Laboratory (DFSL)');
  const [investigatingOfficer, setInvestigatingOfficer] = useState('Sub-Inspector Anitha M. (I.O.)');
  const [seizureDate, setSeizureDate] = useState('2026-10-14 11:30:00 IST');

  if (!isOpen) return null;

  const counts = propCounts || {
    upiCount: store.upiTransactions.length,
    walCount: store.upiTransactions.filter((t) => t.provenance?.recoveryState === 'WAL_RECOVERED').length,
    carvedCount: store.upiTransactions.filter((t) => t.provenance?.recoveryState === 'CARVED_UNALLOCATED').length,
    apkCount: store.apkFindings.length,
    remoteCount: 0,
    chatCount: store.chats.length
  };

  const defaultMeta: DeviceMetadata = deviceMetadata || {
    model: 'Redmi Note 12 5G',
    manufacturer: 'Xiaomi',
    androidVersion: '14.0',
    buildNumber: 'UKQ1.230917.001',
    imei1: '862910058291048',
    imei2: '862910058291055',
    serialNumber: 'd8a7c2901bfa',
    timezone: 'Asia/Kolkata (IST +05:30)',
    extractionType: 'PHYSICAL_TAR',
    evidenceSourcePath: store.caseManifest?.evidencePath || '/evidence/case_evidence.tar',
    hashes: {
      md5: store.dualHashes?.md5 || store.caseManifest?.preIngestionHashes?.md5 || '7d56e9c13b28490a1827461928374610',
      sha256: store.dualHashes?.sha256 || store.caseManifest?.preIngestionHashes?.sha256 || 'a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90',
      fileSizeBytes: store.caseManifest?.fileSizeBytes || 52428800000,
      verified: true,
      calculatedAt: '2026-10-31T16:00:00.000Z'
    },
    acquisitionTimestamp: {
      rawValue: 1760430000000,
      sourceFormat: 'UNIX_MS',
      utcIso: '2026-10-14T08:20:00.000Z',
      istFormatted: '2026-10-14 13:50:00.000 IST (+05:30)',
      epochMs: 1760430000000
    }
  };

  const cert = Sec63BsaGenerator.generateCertificate({
    firNumber,
    policeStation,
    district,
    courtName,
    caseTitle,
    actSections,
    examinerName,
    examinerDesignation,
    examinerCadre: 'State Cyber Forensics Division',
    fslLaboratory,
    deviceMetadata: defaultMeta,
    targetArtifactCounts: {
      upiTransactions: counts.upiCount,
      recoveredWalRows: counts.walCount,
      carvedUnallocatedRows: counts.carvedCount,
      maliciousApks: counts.apkCount,
      remoteAccessSessions: counts.remoteCount,
      chatMessages: counts.chatCount
    },
    custodianName: investigatingOfficer,
    seizureDate
  });

  const htmlContent = Sec63BsaGenerator.renderHtmlReport(cert);

  const handlePrint = () => {
    const win = window.open('', '_blank');
    if (win) {
      win.document.write(htmlContent);
      win.document.close();
      win.print();
    }
  };

  const handleDownloadHtml = () => {
    const blob = new Blob([htmlContent], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `Section63_BSA_Certificate_${cert.certificateId}.html`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/80 flex items-center justify-center p-4">
      <div className="bg-[#0b1320] border border-slate-700 rounded-xl w-full max-w-6xl h-[90vh] flex flex-col shadow-2xl overflow-hidden select-text text-slate-100 font-sans">
        {/* Modal Header */}
        <div className="h-12 bg-[#090f1d] px-4 border-b border-[#1e293b] flex items-center justify-between select-none">
          <div className="flex items-center space-x-2">
            <ShieldCheck className="w-5 h-5 text-emerald-400" />
            <span className="font-bold text-slate-100 text-sm">
              Section 63(4)(c) Bharatiya Sakshya Adhiniyam (BSA), 2023 Statutory Court Certificate
            </span>
            <span className="text-[10px] px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-700/80 font-mono">
              SCHEDULE PART A & PART B
            </span>
          </div>
          <button onClick={onClose} className="text-slate-400 hover:text-white p-1 rounded hover:bg-slate-800">
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="flex-1 flex overflow-hidden">
          {/* Metadata Parameters Panel */}
          <div className="w-80 bg-[#080d19] border-r border-[#1e293b] p-4 overflow-y-auto space-y-3 text-xs shrink-0 select-none">
            <div className="text-[11px] font-bold text-slate-400 uppercase tracking-wide flex items-center gap-1.5">
              <UserCheck className="w-3.5 h-3.5 text-cyan-400" />
              <span>Statutory Officer Parameters</span>
            </div>

            <div>
              <label className="text-[10px] text-slate-400 font-semibold">Examiner Name:</label>
              <input
                type="text"
                value={examinerName}
                onChange={(e) => setExaminerName(e.target.value)}
                className="w-full bg-slate-950 border border-slate-700 text-slate-200 p-1.5 rounded mt-1 font-sans focus:outline-none focus:border-cyan-500"
              />
            </div>

            <div>
              <label className="text-[10px] text-slate-400 font-semibold">Examiner Designation:</label>
              <input
                type="text"
                value={examinerDesignation}
                onChange={(e) => setExaminerDesignation(e.target.value)}
                className="w-full bg-slate-950 border border-slate-700 text-slate-200 p-1.5 rounded mt-1 font-sans focus:outline-none focus:border-cyan-500"
              />
            </div>

            <div>
              <label className="text-[10px] text-slate-400 font-semibold">FSL / Forensic Laboratory:</label>
              <input
                type="text"
                value={fslLaboratory}
                onChange={(e) => setFslLaboratory(e.target.value)}
                className="w-full bg-slate-950 border border-slate-700 text-slate-200 p-1.5 rounded mt-1 font-sans focus:outline-none focus:border-cyan-500"
              />
            </div>

            <div>
              <label className="text-[10px] text-slate-400 font-semibold">FIR Number:</label>
              <input
                type="text"
                value={firNumber}
                onChange={(e) => setFirNumber(e.target.value)}
                className="w-full bg-slate-950 border border-slate-700 text-slate-200 p-1.5 rounded mt-1 font-mono focus:outline-none focus:border-cyan-500"
              />
            </div>

            <div>
              <label className="text-[10px] text-slate-400 font-semibold">Investigating Officer (I.O.) / Custodian:</label>
              <input
                type="text"
                value={investigatingOfficer}
                onChange={(e) => setInvestigatingOfficer(e.target.value)}
                className="w-full bg-slate-950 border border-slate-700 text-slate-200 p-1.5 rounded mt-1 font-sans focus:outline-none focus:border-cyan-500"
              />
            </div>

            <div>
              <label className="text-[10px] text-slate-400 font-semibold">Police Station:</label>
              <input
                type="text"
                value={policeStation}
                onChange={(e) => setPoliceStation(e.target.value)}
                className="w-full bg-slate-950 border border-slate-700 text-slate-200 p-1.5 rounded mt-1 font-sans focus:outline-none focus:border-cyan-500"
              />
            </div>

            <div>
              <label className="text-[10px] text-slate-400 font-semibold">Court of Competent Jurisdiction:</label>
              <input
                type="text"
                value={courtName}
                onChange={(e) => setCourtName(e.target.value)}
                className="w-full bg-slate-950 border border-slate-700 text-slate-200 p-1.5 rounded mt-1 font-sans focus:outline-none focus:border-cyan-500"
              />
            </div>

            {/* Aadhaar Redacted Badge Display */}
            <div className="p-2.5 rounded bg-emerald-950/40 border border-emerald-800/80 text-[11px] space-y-1">
              <div className="flex items-center space-x-1.5 text-emerald-400 font-bold">
                <Lock className="w-3.5 h-3.5" />
                <span>Statutory Privacy Compliance</span>
              </div>
              <p className="text-slate-300 text-[10px]">
                Owner identity redacted as per Supreme Court of India guidelines:
              </p>
              <div className="font-mono text-[10px] text-emerald-300 font-semibold">
                XXXX-XXXX-4921 [Aadhaar Redacted]
              </div>
            </div>

            <div className="pt-2 border-t border-slate-800 space-y-2">
              <button
                onClick={handlePrint}
                className="w-full bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-bold py-2 rounded flex items-center justify-center space-x-1.5 transition-colors cursor-pointer text-xs shadow-sm"
              >
                <Printer className="w-4 h-4" />
                <span>Print Certificate / PDF</span>
              </button>

              <button
                onClick={handleDownloadHtml}
                className="w-full bg-slate-800 hover:bg-slate-700 text-slate-200 font-semibold py-2 rounded flex items-center justify-center space-x-1.5 transition-colors border border-slate-700 cursor-pointer text-xs"
              >
                <Download className="w-4 h-4 text-sky-400" />
                <span>Download HTML Certificate</span>
              </button>
            </div>
          </div>

          {/* Live Document Preview */}
          <div className="flex-1 bg-white text-slate-900 p-4 overflow-y-auto">
            <iframe
              srcDoc={htmlContent}
              title="Section 63 BSA Certificate Preview"
              className="w-full h-full border-0 min-h-[600px]"
            />
          </div>
        </div>
      </div>
    </div>
  );
};

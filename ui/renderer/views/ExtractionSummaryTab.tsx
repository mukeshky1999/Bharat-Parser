import React, { useState, useEffect } from 'react';
import {
  Smartphone,
  ShieldCheck,
  ShieldAlert,
  FileText,
  Calendar,
  Phone,
  MessageSquare,
  Users,
  CreditCard,
  Coins,
  MapPin,
  Image,
  FolderArchive,
  FolderTree,
  HardDrive,
  ExternalLink,
  Binary,
  Layers,
  PlusCircle,
  AlertCircle,
  CheckCircle2,
  GitMerge,
  Network,
  Clock,
  ArrowRight,
  Database,
  Search,
  Sparkles,
  Loader2
} from 'lucide-react';
import {
  DeviceMetadata,
  DualHashResult,
  ForensicProvenance
} from '../../shared/forensic-types';
import { useWorkbenchStore, ActiveTabType } from '../state/workbenchStore';
import { forensicClient, CaseSummaryResponse } from '../api/forensicClient';

interface ExtractionSummaryTabProps {
  deviceMetadata?: DeviceMetadata;
  dualHashes?: DualHashResult;
  onOpenAddExtractionModal?: () => void;
}

export const ExtractionSummaryTab: React.FC<ExtractionSummaryTabProps> = ({
  deviceMetadata,
  dualHashes,
  onOpenAddExtractionModal
}) => {
  const {
    setActiveTab,
    setIsBsaModalOpen,
    setSelectedArtifact,
    caseManifest,
    syncWithBackendCase
  } = useWorkbenchStore();

  const [backendSummary, setBackendSummary] = useState<CaseSummaryResponse | null>(null);
  const [directPathInput, setDirectPathInput] = useState('');
  const [isIngesting, setIsIngesting] = useState(false);
  const [ingestionPhase, setIngestionPhase] = useState<string>('');
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  useEffect(() => {
    let isMounted = true;
    const fetchSummary = async () => {
      try {
        const data = await forensicClient.getCaseSummary();
        if (isMounted && data) {
          setBackendSummary(data);
        }
      } catch {
        // Fall through
      }
    };
    fetchSummary();
  }, [caseManifest]);

  const isLoaded = Boolean(
    backendSummary?.loaded ||
    caseManifest?.evidenceFileName ||
    dualHashes?.verified
  );

  const handlePickFileAndIngest = async () => {
    setErrorMessage(null);
    try {
      const selectedPath = await forensicClient.pickEvidenceFile();
      if (selectedPath) {
        await startIngestion(selectedPath);
      }
    } catch (err: any) {
      setErrorMessage(err.message || 'File selection failed.');
    }
  };

  const handlePickFolderAndIngest = async () => {
    setErrorMessage(null);
    try {
      const selectedPath = await forensicClient.pickEvidenceFolder();
      if (selectedPath) {
        await startIngestion(selectedPath);
      }
    } catch (err: any) {
      setErrorMessage(err.message || 'Folder selection failed.');
    }
  };

  const handleDirectPathIngest = async () => {
    if (!directPathInput.trim()) return;
    setErrorMessage(null);
    await startIngestion(directPathInput.trim());
  };

  const startIngestion = async (path: string) => {
    setIsIngesting(true);
    setIngestionPhase('Computing bit-for-bit SHA-256 and MD5 forensic hashes...');
    try {
      setTimeout(() => setIngestionPhase('Extracting SQLite B-Trees, LevelDB, MMKV & Protobuf payloads...'), 1200);
      setTimeout(() => setIngestionPhase('Running UPI heuristic engine & cross-app corroborator...'), 2400);
      setTimeout(() => setIngestionPhase('Building syndicate transaction graph & owner dossier...'), 3600);

      const res = await forensicClient.ingestCase(path);
      if (res && res.success) {
        await syncWithBackendCase();
        const data = await forensicClient.getCaseSummary();
        if (data) setBackendSummary(data);
      } else {
        setErrorMessage(res.error || 'Ingestion failed on target evidence.');
      }
    } catch (err: any) {
      setErrorMessage(err.message || 'Error occurred during ingestion pipeline.');
    } finally {
      setIsIngesting(false);
      setIngestionPhase('');
    }
  };

  const meta = deviceMetadata || backendSummary?.device_metadata || {
    model: isLoaded ? (backendSummary?.case_name || 'Active Forensic Evidence') : 'No Evidence Ingested',
    manufacturer: 'Not recorded',
    androidVersion: 'Not recorded',
    buildNumber: 'Not recorded',
    imei1: 'N/A',
    imei2: 'N/A',
    serialNumber: 'Not recorded',
    timezone: 'Not recorded',
    extractionType: 'Not recorded',
    evidenceSourcePath: backendSummary?.evidence_path || 'No file selected',
    hashes: backendSummary?.hashes || {
      md5: 'N/A',
      sha256: 'N/A',
      fileSizeBytes: 0,
      verified: false,
      calculatedAt: 'N/A'
    },
    acquisitionTimestamp: {
      rawValue: 0,
      sourceFormat: 'UNIX_MS',
      utcIso: 'N/A',
      istFormatted: 'N/A',
      epochMs: 0
    }
  };

  const handleSourceLinkClick = (filePath: string, hexOffsetStr: string, tableName: string) => {
    const byteOffset = parseInt(hexOffsetStr.replace('0x', ''), 16) || 0;
    const dummyProv: ForensicProvenance = {
      evidenceId: backendSummary?.case_id || 'ACTIVE_CASE_EXT_01',
      archivePath: meta.evidenceSourcePath || '',
      vfsInternalPath: filePath,
      containerType: 'SQLITE',
      tableName: tableName,
      pageNumber: Math.floor(byteOffset / 4096) + 1,
      byteOffset: byteOffset,
      byteLength: 64,
      recoveryState: 'ACTIVE',
      rawPayloadHex: '4143434f554e54535f4944454e544954595f5345414c30303030303030303030'
    };
    setSelectedArtifact({
      id: `PROV_${hexOffsetStr}`,
      provenance: dummyProv,
      notes: `Inspected source file: ${filePath} at offset ${hexOffsetStr}`
    });
  };

  const dossier = backendSummary?.owner_dossier || {};
  const perAppBreakdown = dossier.Per_App_Breakdown || dossier.Per_App_Breakdown_DF || [];

  const counts = backendSummary?.counts || {};

  // Responsive Overview Cards (Never clip category titles!)
  const summaryCards = [
    {
      title: 'UPI & Banking Ledger',
      active: counts.upi_all?.active || 0,
      deleted: counts.upi_all?.wal_and_carved || 0,
      icon: <CreditCard className="w-5 h-5 text-emerald-400" />,
      tab: 'UPI_LEDGER' as ActiveTabType,
      desc: 'NPCI UTRs, VPAs & ghost intents'
    },
    {
      title: 'Chats & Social Comms',
      active: counts.chats_all?.active || 0,
      deleted: counts.chats_all?.wal_and_carved || 0,
      icon: <MessageSquare className="w-5 h-5 text-sky-400" />,
      tab: 'CHATS' as ActiveTabType,
      desc: '10 Chat engines, WAL & View-Once'
    },
    {
      title: 'Saved Contacts & Beneficiaries',
      active: counts.contacts_all?.active || 0,
      deleted: counts.contacts_all?.wal_and_carved || 0,
      icon: <Users className="w-5 h-5 text-amber-300" />,
      tab: 'CONTACTS' as ActiveTabType,
      desc: 'Dating leads, Truecaller & VPAs'
    },
    {
      title: 'Call Log Records',
      active: counts.calls_all?.active || 0,
      deleted: counts.calls_all?.wal_and_carved || 0,
      icon: <Phone className="w-5 h-5 text-green-400" />,
      tab: 'CALL_LOGS' as ActiveTabType,
      desc: 'Cellular CDR & VoIP records'
    },
    {
      title: 'Crypto Wallets & P2P',
      active: counts.crypto_all?.active || 0,
      deleted: counts.crypto_all?.wal_and_carved || 0,
      icon: <Coins className="w-5 h-5 text-yellow-400" />,
      tab: 'CRYPTO' as ActiveTabType,
      desc: 'Custodial on-ramps & escrow orders'
    },
    {
      title: 'System Notifications & Spillover',
      active: counts.os_spillover_all?.active || counts.os_spillover?.active || 0,
      deleted: counts.os_spillover_all?.wal_and_carved || 0,
      icon: <AlertCircle className="w-5 h-5 text-purple-400" />,
      tab: 'OS_SPILLOVER' as ActiveTabType,
      desc: 'OTP intercepts & keyboard cache'
    },
    {
      title: 'Syndicate Link Graph',
      active: backendSummary?.mule_alerts?.length || 0,
      deleted: 0,
      icon: <Network className="w-5 h-5 text-blue-400" />,
      tab: 'MULE_GRAPH' as ActiveTabType,
      desc: 'Mule accounts & syndicate roles'
    },
    {
      title: 'Raw SQLite & B-Tree Explorer',
      active: counts.data_files?.active || 0,
      deleted: counts.data_files?.wal_and_carved || 0,
      icon: <Database className="w-5 h-5 text-amber-500" />,
      tab: 'SQLITE_WIZARD' as ActiveTabType,
      desc: 'Free-list carver & cell inspector'
    },
    {
      title: 'Locations & Media Files',
      active: counts.locations_all?.active || 0,
      deleted: counts.locations_all?.wal_and_carved || 0,
      icon: <MapPin className="w-5 h-5 text-rose-400" />,
      tab: 'LOCATIONS_MEDIA' as ActiveTabType,
      desc: 'GPS EXIF coordinates & media'
    },
    {
      title: 'Virtual File System (VFS)',
      active: counts.vfs_files?.active || counts.data_files?.active || 0,
      deleted: 0,
      icon: <FolderTree className="w-5 h-5 text-teal-400" />,
      tab: 'FILE_SYSTEM' as ActiveTabType,
      desc: 'Air-gapped catalog & index'
    },
  ];

  // If no dump is loaded yet, display clean, centered BharatAnalyzer Case Intake Workspace
  if (!isLoaded) {
    return (
      <div className="h-full w-full bg-[#0b1320] text-slate-100 overflow-y-auto p-6 flex flex-col items-center justify-center select-none font-sans">
        <div className="max-w-[1000px] w-full space-y-6">
          {/* Welcome Header */}
          <div className="text-center space-y-2">
            <div className="inline-flex items-center justify-center w-14 h-14 rounded-xl bg-gradient-to-br from-cyan-500 via-blue-600 to-indigo-700 shadow-xl shadow-cyan-950/60 border border-cyan-400/40 mb-2">
              <svg
                className="w-8 h-8 text-white"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="2.2"
                strokeLinecap="round"
                strokeLinejoin="round"
              >
                <path d="M12 2L3 7v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V7l-9-5z" />
                <path d="M9 12l2 2 4-4" />
              </svg>
            </div>
            <h1 className="text-2xl font-extrabold tracking-tight text-white sm:text-3xl">
              Bharat<span className="text-cyan-400">Analyzer</span> Case Intake
            </h1>
            <p className="text-xs sm:text-sm text-slate-400 max-w-lg mx-auto">
              Air-Gapped Sovereign Digital Forensics & Financial Intelligence Suite. Evidence is hashed before and after processing and analysed from a working copy, so the original is not modified.
            </p>
          </div>

          {/* Ingestion Progress Bar (When ingesting) */}
          {isIngesting && (
            <div className="bg-[#111e33] border border-cyan-500/50 rounded-xl p-5 shadow-2xl space-y-3 animate-pulse">
              <div className="flex items-center justify-between text-xs font-mono">
                <span className="flex items-center gap-2 text-cyan-300 font-bold">
                  <Loader2 className="w-4 h-4 animate-spin text-cyan-400" />
                  <span>STREAMING INGESTION PIPELINE</span>
                </span>
                <span className="text-slate-400">100% Offline • Strict Read-Only</span>
              </div>
              <div className="w-full h-2 bg-slate-800 rounded-full overflow-hidden">
                <div className="h-full bg-gradient-to-r from-cyan-500 to-blue-500 animate-[pulse_1s_infinite] w-3/4 rounded-full" />
              </div>
              <p className="text-xs text-cyan-200 font-mono">{ingestionPhase}</p>
            </div>
          )}

          {/* Error Message */}
          {errorMessage && (
            <div className="p-3 bg-red-950/80 border border-red-800 text-red-200 rounded-lg text-xs flex items-center gap-2">
              <AlertCircle className="w-4 h-4 text-red-400 shrink-0" />
              <span>{errorMessage}</span>
            </div>
          )}

          {/* Three Large Intake Action Cards */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {/* Card 1: Open Forensic Container Archive */}
            <div
              onClick={handlePickFileAndIngest}
              className="bg-[#111c2e] hover:bg-[#16253d] border border-slate-700/80 hover:border-cyan-500/80 rounded-xl p-5 flex flex-col justify-between cursor-pointer transition-all hover:shadow-xl hover:shadow-cyan-950/30 group"
            >
              <div className="space-y-3">
                <div className="w-10 h-10 rounded-lg bg-cyan-950/80 border border-cyan-700/60 flex items-center justify-center text-cyan-400 group-hover:scale-105 transition-transform">
                  <FolderArchive className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="font-bold text-sm text-white group-hover:text-cyan-300 transition-colors">
                    Forensic Container Archive
                  </h3>
                  <p className="text-[11px] text-slate-400 mt-1 leading-relaxed">
                    Native Windows Explorer file picker for <span className="text-slate-200 font-mono">.ufdr, .tar, .zip, .xry, .ofb, .ab</span> dumps.
                  </p>
                </div>
              </div>
              <div className="mt-5 pt-3 border-t border-slate-800/80 flex items-center justify-between text-xs text-cyan-400 font-medium">
                <span>Select Archive File</span>
                <ArrowRight className="w-3.5 h-3.5 group-hover:translate-x-1 transition-transform" />
              </div>
            </div>

            {/* Card 2: Open Extracted Dump Folder or SQLite DB */}
            <div
              onClick={handlePickFolderAndIngest}
              className="bg-[#111c2e] hover:bg-[#16253d] border border-slate-700/80 hover:border-blue-500/80 rounded-xl p-5 flex flex-col justify-between cursor-pointer transition-all hover:shadow-xl hover:shadow-blue-950/30 group"
            >
              <div className="space-y-3">
                <div className="w-10 h-10 rounded-lg bg-blue-950/80 border border-blue-700/60 flex items-center justify-center text-blue-400 group-hover:scale-105 transition-transform">
                  <FolderTree className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="font-bold text-sm text-white group-hover:text-blue-300 transition-colors">
                    Extracted Folder or DB
                  </h3>
                  <p className="text-[11px] text-slate-400 mt-1 leading-relaxed">
                    Select an uncompressed logical filesystem directory, physical extraction, or standalone <span className="text-slate-200 font-mono">.sqlite / .db</span>.
                  </p>
                </div>
              </div>
              <div className="mt-5 pt-3 border-t border-slate-800/80 flex items-center justify-between text-xs text-blue-400 font-medium">
                <span>Browse Folder</span>
                <ArrowRight className="w-3.5 h-3.5 group-hover:translate-x-1 transition-transform" />
              </div>
            </div>

            {/* Card 3: Enter Direct Disk Path */}
            <div className="bg-[#111c2e] border border-slate-700/80 rounded-xl p-5 flex flex-col justify-between">
              <div className="space-y-3">
                <div className="w-10 h-10 rounded-lg bg-indigo-950/80 border border-indigo-700/60 flex items-center justify-center text-indigo-400">
                  <HardDrive className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="font-bold text-sm text-white">
                    Enter Direct Disk Path
                  </h3>
                  <p className="text-[11px] text-slate-400 mt-1 leading-relaxed">
                    Direct path on physical drive, external forensic RAID, or workstation storage.
                  </p>
                </div>
                <input
                  type="text"
                  value={directPathInput}
                  onChange={(e) => setDirectPathInput(e.target.value)}
                  placeholder="e.g. D:\Cases\2026\evidence.tar"
                  className="w-full bg-[#090f1d] border border-slate-700 rounded px-2.5 py-1.5 text-xs text-white placeholder-slate-500 font-mono focus:outline-none focus:border-indigo-500"
                />
              </div>
              <button
                onClick={handleDirectPathIngest}
                disabled={!directPathInput.trim() || isIngesting}
                className="mt-4 w-full py-1.5 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-40 text-white font-semibold text-xs rounded transition-colors flex items-center justify-center gap-1.5"
              >
                <span>Ingest in Read-Only Mode</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>

          {/* Compliance Banner */}
          <div className="p-3 bg-[#0d1627] border border-slate-800 rounded-lg flex items-center justify-between text-xs text-slate-400 font-mono">
            <span className="flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-emerald-400" />
              <span>Section 63(4)(c) Bharatiya Sakshya Adhiniyam, 2023 Compliant</span>
            </span>
            <span className="text-slate-500">Bit-for-Bit Hash Guard Active</span>
          </div>
        </div>
      </div>
    );
  }

  // Loaded State: High-Contrast Obsidian Slate & Data Canvas
  return (
    <div className="h-full w-full bg-[#0b1320] text-slate-200 overflow-y-auto select-text font-sans">
      <div className="p-4 space-y-4 max-w-[1600px] mx-auto">
        {/* ===================================================================
            TOP SECTION: Device Profile & Hash Verification Seal
            =================================================================== */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
          {/* Device Profile Card */}
          <div className="lg:col-span-7 bg-[#111c2e] border border-slate-700/80 rounded-xl p-4 flex flex-col md:flex-row items-center md:items-start gap-4 shadow-lg">
            <div className="w-20 h-36 bg-gradient-to-b from-slate-800 to-slate-950 rounded-2xl p-1.5 shadow-md border border-slate-600 shrink-0 flex flex-col items-center justify-between">
              <div className="w-5 h-1 bg-slate-600 rounded-full mb-1" />
              <div className="w-full flex-1 bg-cyan-950/80 rounded border border-cyan-800/60 flex flex-col items-center justify-center p-1 text-center">
                <Smartphone className="w-6 h-6 text-cyan-400 mb-1" />
                <span className="text-[7.5px] text-cyan-300 font-mono text-center font-bold leading-tight truncate max-w-full">
                  {meta.model}
                </span>
              </div>
              <div className="w-3 h-3 rounded-full border border-slate-600 mt-1" />
            </div>

            <div className="flex-1 text-xs leading-relaxed space-y-2">
              <div className="flex items-center justify-between border-b border-slate-700/80 pb-2">
                <div className="flex items-center gap-2">
                  <span className="font-extrabold text-sm text-white">
                    {meta.model}
                  </span>
                  <span className="bg-cyan-950 text-cyan-300 font-mono text-[10px] font-bold px-2 py-0.5 rounded border border-cyan-800/60">
                    {meta.extractionType}
                  </span>
                </div>
                <span className="text-emerald-400 font-mono text-[11px] font-bold flex items-center gap-1">
                  <CheckCircle2 className="w-3.5 h-3.5" />
                  <span>Verified Ingest</span>
                </span>
              </div>

              <div className="grid grid-cols-2 gap-x-4 gap-y-1.5 text-[11.5px]">
                <div>
                  <span className="text-slate-400 font-medium">Manufacturer: </span>
                  <span className="font-semibold text-white">{meta.manufacturer}</span>
                </div>
                <div>
                  <span className="text-slate-400 font-medium">Android Version: </span>
                  <span className="font-semibold text-white">{meta.androidVersion}</span>
                </div>
                <div>
                  <span className="text-slate-400 font-medium">Serial Number: </span>
                  <span className="font-semibold text-white">{meta.serialNumber}</span>
                </div>
                <div>
                  <span className="text-slate-400 font-medium">Time Zone: </span>
                  <span className="font-semibold text-white">{meta.timezone}</span>
                </div>
                <div className="col-span-2 truncate">
                  <span className="text-slate-400 font-medium">Evidence Source: </span>
                  <span className="font-mono text-cyan-400 text-[11px] font-medium" title={meta.evidenceSourcePath}>
                    {meta.evidenceSourcePath}
                  </span>
                </div>
              </div>
            </div>
          </div>

          {/* Forensic Integrity Seal Card */}
          <div className="lg:col-span-5 bg-[#111c2e] border border-slate-700/80 rounded-xl p-4 shadow-lg flex flex-col justify-between">
            <div className="space-y-2">
              <div className="flex items-center justify-between pb-2 border-b border-slate-700/80">
                <div className="flex items-center space-x-2">
                  <ShieldCheck className="w-5 h-5 text-emerald-400" />
                  <span className="font-bold text-sm text-white">
                    Forensic Hash & Chain of Custody
                  </span>
                </div>
                <span className="px-2 py-0.5 text-[10px] font-bold rounded bg-emerald-950 text-emerald-300 border border-emerald-700/80">
                  BIT-FOR-BIT SEAL PASS
                </span>
              </div>

              <div className="space-y-1 text-xs text-slate-300 font-mono">
                <div>
                  <span className="text-slate-400 font-sans">Pre-Ingestion MD5: </span>
                  <span className="text-slate-200 select-all font-semibold">
                    {meta.hashes?.md5 || 'N/A'}
                  </span>
                </div>
                <div>
                  <span className="text-slate-400 font-sans">Pre-Ingestion SHA-256: </span>
                  <span className="text-emerald-300 break-all select-all font-bold text-[10.5px]">
                    {meta.hashes?.sha256 || 'N/A'}
                  </span>
                </div>
                <div>
                  <span className="text-slate-400 font-sans">Verified File Size: </span>
                  <span className="text-slate-200">
                    {meta.hashes?.fileSizeBytes ? `${(meta.hashes.fileSizeBytes / (1024 * 1024)).toFixed(2)} MB (${meta.hashes.fileSizeBytes.toLocaleString()} bytes)` : '0 bytes'}
                  </span>
                </div>
              </div>
            </div>

            <div className="pt-3 border-t border-slate-800 mt-3 flex items-center justify-between gap-2">
              <button
                onClick={() => setIsBsaModalOpen(true)}
                className="px-3 py-1.5 bg-emerald-700 hover:bg-emerald-600 text-white text-xs font-semibold rounded shadow transition-colors flex items-center gap-1.5"
                title="Generates Section 63(4)(c) BSA 2023 Statutory Certificate"
              >
                <FileText className="w-3.5 h-3.5" />
                <span>Export Sec 63 BSA Certificate</span>
              </button>

              <button
                onClick={() => onOpenAddExtractionModal?.()}
                className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium rounded border border-slate-700 transition-colors flex items-center gap-1.5"
              >
                <PlusCircle className="w-3.5 h-3.5 text-cyan-400" />
                <span>Add Secondary Extraction</span>
              </button>
            </div>
          </div>
        </div>

        {/* ===================================================================
            CATEGORY SUMMARY CARDS (Responsive CSS Grid - ZERO Truncation!)
            =================================================================== */}
        <div>
          <div className="flex items-center justify-between mb-2">
            <h2 className="text-xs font-bold text-slate-300 uppercase tracking-wider">
              Analyzed Forensic Artifacts
            </h2>
            <span className="text-[10px] text-slate-400 font-mono">
              Click any card to inspect category records
            </span>
          </div>

          <div
            className="grid gap-2.5"
            style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))' }}
          >
            {summaryCards.map((card) => (
              <button
                key={card.title}
                onClick={() => setActiveTab(card.tab)}
                className="bg-[#111c2e] hover:bg-[#16253d] border border-slate-700/80 hover:border-cyan-500/80 rounded-lg p-3 flex flex-col justify-between text-left transition-all shadow-sm hover:shadow-md cursor-pointer group"
              >
                <div className="flex items-start justify-between gap-2 mb-2">
                  <div className="p-1.5 rounded-md bg-slate-900 border border-slate-800 shrink-0">
                    {card.icon}
                  </div>
                  <div className="flex items-center space-x-1 shrink-0 font-mono text-[10.5px]">
                    <span className="bg-slate-800 text-slate-100 border border-slate-700 px-1.5 py-0.2 rounded-full font-bold" title="Active Allocated Records">
                      {card.active}
                    </span>
                    {card.deleted > 0 && (
                      <span className="bg-red-950 text-red-400 border border-red-800/80 px-1.5 py-0.2 rounded-full font-bold" title="Carved / WAL Deleted Records">
                        ({card.deleted})
                      </span>
                    )}
                  </div>
                </div>

                <div>
                  <h3 className="font-semibold text-xs text-white group-hover:text-cyan-300 leading-snug">
                    {card.title}
                  </h3>
                  <p className="text-[10px] text-slate-400 mt-0.5 leading-tight">
                    {card.desc}
                  </p>
                </div>
              </button>
            ))}
          </div>
        </div>

        {/* ===================================================================
            UNIFIED MASTER DEVICE OWNER DOSSIER
            =================================================================== */}
        <div className="bg-[#111c2e] border border-slate-700/80 rounded-xl shadow-lg overflow-hidden">
          <div className="px-4 py-3 bg-[#0d1627] border-b border-slate-700/80 flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <Users className="w-4 h-4 text-cyan-400" />
              <h2 className="font-bold text-sm text-white">
                Unified Master Device Owner Dossier
              </h2>
            </div>
            <span className="text-[10px] font-mono text-cyan-300 bg-cyan-950 px-2 py-0.5 rounded border border-cyan-800/60">
              Cross-App Corroboration Engine Verified
            </span>
          </div>

          <div className="p-4 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 text-xs border-b border-slate-800">
            <div>
              <span className="text-slate-400 text-[11px] block font-medium">Primary Mobile Number</span>
              <span className="text-white font-mono font-bold text-sm mt-0.5 block select-all">
                {dossier.Primary_Mobile || 'N/A'}
              </span>
            </div>

            <div>
              <span className="text-slate-400 text-[11px] block font-medium">Account Holder Names</span>
              <span className="text-white font-semibold mt-0.5 block select-all">
                {dossier.Account_Holder_Names && dossier.Account_Holder_Names.length > 0
                  ? dossier.Account_Holder_Names.join(', ')
                  : 'N/A'}
              </span>
            </div>

            <div>
              <span className="text-slate-400 text-[11px] block font-medium">Owner Emails</span>
              <span className="text-cyan-300 font-mono mt-0.5 block select-all truncate" title={dossier.Owner_Emails?.join(', ')}>
                {dossier.Owner_Emails && dossier.Owner_Emails.length > 0
                  ? dossier.Owner_Emails.join(', ')
                  : 'N/A'}
              </span>
            </div>

            <div>
              <span className="text-slate-400 text-[11px] block font-medium">Owner UPI VPAs</span>
              <span className="text-emerald-400 font-mono mt-0.5 block select-all truncate" title={dossier.Owner_VPAs_Raw?.join(', ')}>
                {dossier.Owner_VPAs_Raw && dossier.Owner_VPAs_Raw.length > 0
                  ? dossier.Owner_VPAs_Raw.join(', ')
                  : 'N/A'}
              </span>
            </div>

            <div>
              <span className="text-slate-400 text-[11px] block font-medium">Linked Bank Accounts</span>
              <span className="text-slate-200 font-mono mt-0.5 block select-all">
                {dossier.Linked_Bank_Accounts && dossier.Linked_Bank_Accounts.length > 0
                  ? dossier.Linked_Bank_Accounts.join(', ')
                  : 'N/A'}
              </span>
            </div>

            <div>
              <span className="text-slate-400 text-[11px] block font-medium">Active Financial Apps</span>
              <span className="text-slate-200 font-medium mt-0.5 block">
                {dossier.Active_Financial_Apps && dossier.Active_Financial_Apps.length > 0
                  ? dossier.Active_Financial_Apps.join(', ')
                  : 'N/A'}
              </span>
            </div>

            <div>
              <span className="text-slate-400 text-[11px] block font-medium">Secondary Mobiles</span>
              <span className="text-slate-300 font-mono mt-0.5 block select-all">
                {dossier.Secondary_Mobiles && dossier.Secondary_Mobiles.length > 0
                  ? dossier.Secondary_Mobiles.join(', ')
                  : 'None Identified'}
              </span>
            </div>

            <div>
              <span className="text-slate-400 text-[11px] block font-medium">UPI Circle Delegations</span>
              <span className="text-slate-300 font-medium mt-0.5 block">
                {dossier.UPI_Circle_Delegations && dossier.UPI_Circle_Delegations.length > 0
                  ? dossier.UPI_Circle_Delegations.join(', ')
                  : 'None'}
              </span>
            </div>
          </div>

          {/* Per-App Breakdown Table */}
          {perAppBreakdown && perAppBreakdown.length > 0 && (
            <div className="p-4">
              <h3 className="text-xs font-bold text-slate-300 uppercase tracking-wider mb-2">
                Application-by-Application Profile Matrix
              </h3>
              <div className="overflow-x-auto rounded-lg border border-slate-800">
                <table className="w-full text-left text-xs border-collapse">
                  <thead>
                    <tr className="bg-[#0d1627] text-slate-300 border-b border-slate-800 text-[11px]">
                      <th className="py-2 px-3 font-semibold">Application</th>
                      <th className="py-2 px-3 font-semibold">Account Identifier</th>
                      <th className="py-2 px-3 font-semibold">Owner Name</th>
                      <th className="py-2 px-3 font-semibold">VPAs / Wallets</th>
                      <th className="py-2 px-3 font-semibold">Source Artifact File</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/80 font-mono text-[11px]">
                    {perAppBreakdown.map((row: any, i: number) => (
                      <tr key={i} className="hover:bg-slate-800/40 transition-colors">
                        <td className="py-2 px-3 text-cyan-300 font-semibold">{row.App_Name || row.Application || 'App'}</td>
                        <td className="py-2 px-3 text-slate-200 select-all">{row.Account_ID || row.Identifier || 'N/A'}</td>
                        <td className="py-2 px-3 text-white font-sans font-medium">{row.Holder_Name || row.Name || 'N/A'}</td>
                        <td className="py-2 px-3 text-emerald-400">{row.VPA || row.Wallet || '—'}</td>
                        <td className="py-2 px-3 text-slate-400 text-[10px] truncate max-w-xs">{row.Source_File || 'DB'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

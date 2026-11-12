import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { FileText, Download, PackageOpen, ListChecks } from 'lucide-react';
import { forensicClient, AuditSummary, PackageResult, ReportParticulars } from '../api/forensicClient';
import { useWorkbenchStore } from '../state/workbenchStore';
import { useFindings } from '../state/findingsStore';

const FIELDS: Array<[keyof ReportParticulars, string]> = [
  ['case_number', 'Case / reference number'],
  ['agency', 'Agency / laboratory'],
  ['examiner_name', 'Examiner'],
  ['designation', 'Designation'],
  ['requesting_officer', 'Requesting officer'],
];

const DECISIONS: Array<[string, string]> = [
  ['INCLUDE', 'Include the file'],
  ['WITHHOLD_SENSITIVE', 'Withhold: sensitive content'],
  ['WITHHOLD_PRIVILEGED', 'Withhold: privileged or protected'],
  ['WITHHOLD_NOT_RELIED_UPON', 'Withhold: not relied upon'],
];

interface MediaItem { path: string; vfs_path: string; file_name: string; file_size: number }

const saveText = (name: string, text: string, type: string) => {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = document.createElement('a');
  a.href = url;
  a.download = name.replace(/[^\w.\-]/g, '_');
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
};

const Card: React.FC<{ icon: React.ElementType; title: string; children: React.ReactNode }> = ({ icon: Icon, title, children }) => (
  <section className="rounded border border-slate-800 bg-slate-900 p-4">
    <h2 className="flex items-center gap-2 text-slate-50 font-medium mb-3">
      <Icon className="w-5 h-5 text-slate-300" aria-hidden="true" /> {title}
    </h2>
    {children}
  </section>
);

const btn = 'h-8 px-3 rounded border border-slate-700 text-slate-200 hover:bg-slate-800 disabled:opacity-40 disabled:hover:bg-transparent';
const btnPrimary = 'h-8 px-3 rounded bg-cyan-600 text-slate-50 hover:bg-cyan-500 disabled:opacity-40 disabled:hover:bg-cyan-600';

export const ReportExportView: React.FC = () => {
  const caseManifest = useWorkbenchStore((s) => s.caseManifest);
  const integrity = useWorkbenchStore((s) => s.integrity);
  const findingCount = useFindings((s) => s.findings.length);
  const hasCase = !!caseManifest;

  const [particulars, setParticulars] = useState<ReportParticulars>({});
  const [notes, setNotes] = useState('');
  const [html, setHtml] = useState('');
  const [reportError, setReportError] = useState('');
  const [busy, setBusy] = useState('');

  const [media, setMedia] = useState<MediaItem[] | null>(null);
  const [decisions, setDecisions] = useState<Record<string, string>>({});
  const [itemNotes, setItemNotes] = useState<Record<string, string>>({});
  const [maskText, setMaskText] = useState('');
  const [pkg, setPkg] = useState<PackageResult | null>(null);
  const [pkgError, setPkgError] = useState('');

  const [audit, setAudit] = useState<AuditSummary | null>(null);

  const refreshAudit = useCallback(async () => {
    if (!hasCase) return;
    setAudit(await forensicClient.getAuditLog());
  }, [hasCase]);

  useEffect(() => { void refreshAudit(); }, [refreshAudit, caseManifest?.caseId]);

  const fullParticulars = (): ReportParticulars => ({ ...particulars, notes });

  const preview = async () => {
    setBusy('report'); setReportError('');
    const r = await forensicClient.getExaminationReportHtml(fullParticulars());
    setBusy('');
    if (r.error) { setReportError(r.error); setHtml(''); } else setHtml(r.html);
    void refreshAudit();
  };

  const facts = async (format: 'json' | 'csv') => {
    setBusy(format); setReportError('');
    const r = await forensicClient.getCaseFacts(format);
    setBusy('');
    if (r.error) setReportError(r.error);
    else saveText(`case_facts.${format}`, r.text, format === 'csv' ? 'text/csv;charset=utf-8' : 'application/json');
    void refreshAudit();
  };

  const loadMedia = async () => {
    setPkgError(''); setPkg(null);
    const r = await forensicClient.getMediaCandidates();
    if (r.error) setPkgError(r.error);
    setMedia(r.items);
  };

  const undecided = useMemo(() => (media ?? []).filter((m) => !decisions[m.path]).length, [media, decisions]);
  const canBuild = !!media && media.length > 0 && undecided === 0 && busy !== 'pkg';

  const build = async () => {
    if (!media) return;
    setBusy('pkg'); setPkgError(''); setPkg(null);
    const r = await forensicClient.buildReviewPackage(
      media.map((m) => ({ path: m.path, disposition: decisions[m.path], note: itemNotes[m.path] ?? '' })),
      maskText.split('\n').map((t) => t.trim()).filter(Boolean),
    );
    setBusy('');
    if (r.success) setPkg(r); else setPkgError(r.error || 'The package was not built.');
    void refreshAudit();
  };

  return (
    <div className="flex-1 overflow-y-auto p-6 select-text">
      <div className="max-w-4xl mx-auto space-y-4">
        <div>
          <h1 className="text-lg font-semibold text-slate-50 mb-1">Report &amp; export</h1>
          <p className="text-slate-400">
            Everything here is built from what the software recorded for this case. It contains no legal wording and makes no declaration:
            if a court or agency needs a legal form, you prepare and sign it, copying the facts from the annexure.
          </p>
        </div>

        {!hasCase && <p className="rounded border border-amber-700 bg-amber-950 text-amber-300 p-3">Open evidence first (top right). Nothing can be prepared without a case.</p>}
        {hasCase && integrity?.match === false && (
          <p className="rounded border border-rose-700 bg-rose-950 text-rose-300 p-3">
            The evidence hash changed during processing. The report will say MISMATCH; do not rely on this case until that is explained.
          </p>
        )}

        <Card icon={FileText} title="Examination report">
          <p className="text-slate-300 mb-3">Case particulars you type here appear in the report. A field left blank is printed as &ldquo;Not provided&rdquo;. {findingCount} pinned finding{findingCount === 1 ? '' : 's'} will be included.</p>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 mb-3">
            {FIELDS.map(([key, label]) => (
              <label key={key} className="block">
                <span className="text-slate-400">{label}</span>
                <input
                  value={particulars[key] ?? ''}
                  onChange={(e) => setParticulars((p) => ({ ...p, [key]: e.target.value }))}
                  disabled={!hasCase}
                  className="mt-1 w-full h-8 px-2 rounded border border-slate-700 bg-slate-950 text-slate-100"
                />
              </label>
            ))}
            <label className="block md:col-span-2">
              <span className="text-slate-400">Notes from the examiner</span>
              <textarea
                value={notes} onChange={(e) => setNotes(e.target.value)} disabled={!hasCase} rows={3}
                className="mt-1 w-full px-2 py-1 rounded border border-slate-700 bg-slate-950 text-slate-100"
              />
            </label>
          </div>
          <div className="flex flex-wrap gap-2">
            <button className={btnPrimary} onClick={preview} disabled={!hasCase || busy === 'report'}>{busy === 'report' ? 'Building…' : 'Build and preview report'}</button>
            <button className={btn} onClick={() => saveText('examination_report.html', html, 'text/html;charset=utf-8')} disabled={!html}>
              <Download className="inline w-4 h-4 mr-1" aria-hidden="true" />Save as HTML (print to PDF from the browser)
            </button>
          </div>
          {reportError && <p className="mt-3 text-rose-300">{reportError}</p>}
          {html && (
            <iframe title="Examination report preview" sandbox="" srcDoc={html} className="mt-3 w-full h-[32rem] rounded border border-slate-700 bg-white" />
          )}
        </Card>

        <Card icon={ListChecks} title="Facts annexure">
          <p className="text-slate-300 mb-3">The same facts as plain data (hashes, device identifiers as recorded, tool and environment, processing results, limitations) for copying into your lab&apos;s own forms.</p>
          <div className="flex gap-2">
            <button className={btn} onClick={() => facts('json')} disabled={!hasCase || busy === 'json'}><Download className="inline w-4 h-4 mr-1" aria-hidden="true" />JSON</button>
            <button className={btn} onClick={() => facts('csv')} disabled={!hasCase || busy === 'csv'}><Download className="inline w-4 h-4 mr-1" aria-hidden="true" />CSV</button>
          </div>
        </Card>

        <Card icon={PackageOpen} title="Review package">
          <p className="text-slate-300 mb-3">
            A folder with the files you choose, a manifest of hashes and a viewer that opens offline, for a reviewer without this software.
            <strong> Every file needs your decision</strong>; nothing is built until each one has it. Withheld files are not copied, only a card with the name and hashes.
            Masking removes the terms below from names, notes and cards, not from inside the files.
          </p>
          <button className={btn} onClick={loadMedia} disabled={!hasCase}>List media files in this case</button>
          {media && media.length === 0 && <p className="mt-3 text-slate-400">No media files are available on disk for this case.</p>}
          {media && media.length > 0 && (
            <>
              <table className="mt-3 w-full text-left">
                <thead className="text-slate-400">
                  <tr><th className="py-1 pr-2">File</th><th className="pr-2">Decision</th><th>Note</th></tr>
                </thead>
                <tbody>
                  {media.map((m) => (
                    <tr key={m.path} className="border-t border-slate-800 align-top">
                      <td className="py-1 pr-2 break-all text-slate-200">{m.file_name}<div className="text-slate-500">{m.file_size.toLocaleString()} bytes</div></td>
                      <td className="pr-2">
                        <select
                          aria-label={`Decision for ${m.file_name}`}
                          value={decisions[m.path] ?? ''}
                          onChange={(e) => setDecisions((d) => ({ ...d, [m.path]: e.target.value }))}
                          className={`h-8 rounded border bg-slate-950 text-slate-100 px-1 ${decisions[m.path] ? 'border-slate-700' : 'border-amber-600'}`}
                        >
                          <option value="">Choose…</option>
                          {DECISIONS.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
                        </select>
                      </td>
                      <td>
                        <input
                          aria-label={`Note for ${m.file_name}`} value={itemNotes[m.path] ?? ''}
                          onChange={(e) => setItemNotes((n) => ({ ...n, [m.path]: e.target.value }))}
                          className="h-8 w-full px-2 rounded border border-slate-700 bg-slate-950 text-slate-100"
                        />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <label className="block mt-3">
                <span className="text-slate-400">Terms to mask, one per line (for example a person&apos;s name)</span>
                <textarea value={maskText} onChange={(e) => setMaskText(e.target.value)} rows={2} className="mt-1 w-full px-2 py-1 rounded border border-slate-700 bg-slate-950 text-slate-100" />
              </label>
              <div className="mt-3 flex items-center gap-3">
                <button className={btnPrimary} onClick={build} disabled={!canBuild}>Build package</button>
                {undecided > 0 && <span className="text-amber-300">{undecided === 1 ? '1 file still needs' : `${undecided} files still need`} a decision.</span>}
              </div>
            </>
          )}
          {pkgError && <p className="mt-3 text-rose-300">{pkgError}</p>}
          {pkg && (
            <p className="mt-3 text-slate-200 break-all">
              Built: {pkg.included} included, {pkg.withheld} withheld.<br />
              Folder: <span className="font-mono">{pkg.directory}</span><br />
              Merkle root of the originals: <span className="font-mono">{pkg.merkle_root}</span>
            </p>
          )}
        </Card>

        <Card icon={ListChecks} title="Audit log">
          {!audit ? <p className="text-slate-400">{hasCase ? 'Loading…' : 'No case is open.'}</p> : (
            <>
              <p className="mb-2">
                Chain check:{' '}
                <strong className={audit.verified ? 'text-emerald-300' : 'text-rose-300'}>{audit.verified ? 'VERIFIED' : 'FAILED'}</strong>
                {audit.error && <span className="text-rose-300"> ({audit.error})</span>}. {audit.entries.length} entr{audit.entries.length === 1 ? 'y' : 'ies'}.
              </p>
              <p className="mb-3 text-slate-400">
                Head hash: <span className="font-mono break-all text-slate-200">{audit.head_hash || 'none'}</span><br />
                The check shows that no entry was altered or removed from the middle. A person who can rewrite the whole file could recompute it,
                so each report prints the head hash at the time it was made; keep your copies.
              </p>
              <table className="w-full text-left">
                <thead className="text-slate-400"><tr><th className="py-1 pr-2">#</th><th className="pr-2">Time (UTC)</th><th className="pr-2">By</th><th>Action</th></tr></thead>
                <tbody>
                  {audit.entries.slice(-100).map((e) => (
                    <tr key={e.seq} className="border-t border-slate-800">
                      <td className="py-1 pr-2 tabular-nums">{e.seq}</td><td className="pr-2 tabular-nums">{e.ts_utc}</td><td className="pr-2">{e.actor}</td><td>{e.action}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {audit.entries.length > 100 && <p className="mt-2 text-slate-400">Showing the latest 100 of {audit.entries.length}; the full log is in the audit file and in the report.</p>}
            </>
          )}
        </Card>
      </div>
    </div>
  );
};

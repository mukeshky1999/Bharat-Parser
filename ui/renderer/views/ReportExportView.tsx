import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { FileText, Download, PackageOpen, ListChecks } from 'lucide-react';
import { forensicClient, AuditSummary, PackageResult, ReportParticulars } from '../api/forensicClient';
import { useWorkbenchStore } from '../state/workbenchStore';
import { useFindings } from '../state/findingsStore';
import { csvCell } from '../utils/csv';
import { ViewHeader, Card as UiCard, GroupTile, Button } from '../components/ui';
import { ReviewerMarksCard } from './ReviewerMarksCard';
import { ValidationCard } from './ValidationCard';

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
  <UiCard title={<span className="flex items-center gap-2"><GroupTile hue="report" icon={Icon as any} size="sm" />{title}</span>}>
    {children}
  </UiCard>
);

const OPTIONAL_SECTIONS: Array<[string, string]> = [
  ['particulars', 'Case particulars'], ['device', 'Device details'], ['environment', 'Tool and environment'],
  ['counts', 'Records found'], ['findings', 'Pinned findings'], ['tags', 'Tagged records'],
];


export const ReportExportView: React.FC = () => {
  const caseManifest = useWorkbenchStore((s) => s.caseManifest);
  const integrity = useWorkbenchStore((s) => s.integrity);
  const findingCount = useFindings((s) => s.findings.length);
  const hasCase = !!caseManifest;

  const [particulars, setParticulars] = useState<ReportParticulars>({});
  const [included, setIncluded] = useState<Record<string, boolean>>({});
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
  const [ackTagged, setAckTagged] = useState(false);

  const [audit, setAudit] = useState<AuditSummary | null>(null);

  const refreshAudit = useCallback(async () => {
    if (!hasCase) return;
    setAudit(await forensicClient.getAuditLog());
  }, [hasCase]);

  useEffect(() => { void refreshAudit(); }, [refreshAudit, caseManifest?.caseId]);

  const fullParticulars = (): ReportParticulars => ({ ...particulars, notes, sections: OPTIONAL_SECTIONS.filter(([id]) => included[id] !== false).map(([id]) => id) });

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

  const accounts = async () => {
    setBusy('acct'); setReportError('');
    const res = await forensicClient.getAccountsOfInterest();
    setBusy('');
    if (res.error || !res.data) { setReportError(res.error || 'Could not build the sheet'); return; }
    const cols = ['section', 'vpa', 'account', 'names_as_recorded', 'tagged_records', 'record_ids', 'evidence_items', 'applications', 'tags', 'left_out_because'];
    const rows: Array<Record<string, unknown>> = [
      ...res.data.accounts.map((a) => ({ section: 'account of interest', ...a })),
      ...res.data.left_out.map((a) => ({ section: 'left out', ...a })),
    ];
    const csv = [cols, ...rows.map((r) => cols.map((c) => csvCell(r[c])))].map((r) => r.join(',')).join('\r\n');
    saveText('accounts_of_interest.csv', csv, 'text/csv;charset=utf-8');
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
      undefined,
      ackTagged,
    );
    setBusy('');
    if (r.success) setPkg(r); else setPkgError(r.error || 'The package was not built.');
    void refreshAudit();
  };

  return (
    <div className="flex-1 overflow-y-auto p-4 bg-page select-text">
      <div className="max-w-4xl mx-auto space-y-4">
        <div>
          <ViewHeader title="Report and export" />
          <p className="text-muted">
            Everything here is built from what the software recorded for this case. It contains no legal wording and makes no declaration:
            if a court or agency needs a legal form, you prepare and sign it, copying the facts from the annexure.
          </p>
        </div>

        {!hasCase && <p className="card bg-warn-soft text-warn p-3">Open evidence first (top right). Nothing can be prepared without a case.</p>}
        {hasCase && integrity?.match === false && (
          <p className="card bg-rec-soft text-rec p-3">
            The evidence hash changed during processing. The report will say MISMATCH; do not rely on this case until that is explained.
          </p>
        )}

        <Card icon={FileText} title="Examination report">
          <p className="text-ink mb-3">Case particulars you type here appear in the report. A field left blank is printed as &ldquo;Not provided&rdquo;. {findingCount} pinned finding{findingCount === 1 ? '' : 's'} will be included.</p>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 mb-3">
            {FIELDS.map(([key, label]) => (
              <label key={key} className="block">
                <span className="text-muted">{label}</span>
                <input
                  value={particulars[key] ?? ''}
                  onChange={(e) => setParticulars((p) => ({ ...p, [key]: e.target.value }))}
                  disabled={!hasCase}
                  className="mt-1 w-full h-8 px-2 rounded border border-line-strong bg-surface text-ink"
                />
              </label>
            ))}
            <label className="block md:col-span-2">
              <span className="text-muted">Notes from the examiner</span>
              <textarea
                value={notes} onChange={(e) => setNotes(e.target.value)} disabled={!hasCase} rows={3}
                className="mt-1 w-full px-2 py-1 rounded border border-line-strong bg-surface text-ink"
              />
            </label>
          </div>
          <fieldset className="mb-3 rounded-lg border border-line p-3">
            <legend className="px-1 text-ink">Sections in this copy of the report</legend>
            <div className="flex flex-wrap gap-x-4 gap-y-1">
              {OPTIONAL_SECTIONS.map(([id, label]) => (
                <label key={id} className="inline-flex items-center gap-1.5 text-ink">
                  <input type="checkbox" checked={included[id] !== false} disabled={!hasCase} onChange={(e) => setIncluded((cur) => ({ ...cur, [id]: e.target.checked }))} />{label}
                </label>
              ))}
            </div>
            <p className="mt-2 text-muted text-xs">The evidence and hashes, the limitations and the audit log are always included. A section you leave out is named at the end of the report, so a reader knows it exists.</p>
          </fieldset>
          <div className="flex flex-wrap gap-2">
            <Button variant="primary" onClick={preview} disabled={!hasCase || busy === 'report'}>{busy === 'report' ? 'Building…' : 'Build and preview report'}</Button>
            <Button onClick={() => saveText('examination_report.html', html, 'text/html;charset=utf-8')} disabled={!html}>
              <Download className="inline w-4 h-4 mr-1" aria-hidden="true" />Save as HTML (print to PDF from the browser)
            </Button>
          </div>
          {reportError && <p className="mt-3 text-rec">{reportError}</p>}
          {html && (
            <iframe title="Examination report preview" sandbox="" srcDoc={html} className="mt-3 w-full h-[32rem] rounded-lg border border-line-strong bg-white" />
          )}
        </Card>

        <Card icon={ListChecks} title="Facts annexure">
          <p className="text-ink mb-3">The same facts as plain data (hashes, device identifiers as recorded, tool and environment, processing results, limitations) for copying into your lab&apos;s own forms.</p>
          <div className="flex gap-2">
            <Button onClick={() => facts('json')} disabled={!hasCase || busy === 'json'}><Download className="w-4 h-4" aria-hidden="true" />JSON</Button>
            <Button onClick={() => facts('csv')} disabled={!hasCase || busy === 'csv'}><Download className="w-4 h-4" aria-hidden="true" />CSV</Button>
          </div>
          <p className="text-ink mt-3 mb-2">Accounts from payment records you tagged of interest or relied upon. An account that also appears on a record you tagged complainant, excluded or privileged is listed apart, with the reason.</p>
          <Button onClick={accounts} disabled={!hasCase || busy === 'acct'}><Download className="w-4 h-4" aria-hidden="true" />Accounts of interest (CSV)</Button>
        </Card>

        <Card icon={PackageOpen} title="Review package">
          <p className="text-ink mb-3">
            A folder with the files you choose, a manifest of hashes and a viewer that opens offline, for a reviewer without this software.
            <strong> Every file needs your decision</strong>; nothing is built until each one has it. Withheld files are not copied, only a card with the name and hashes.
            Masking removes the terms below from names, notes and cards, not from inside the files.
          </p>
          <Button onClick={loadMedia} disabled={!hasCase}>List media files in this case</Button>
          {media && media.length === 0 && <p className="mt-3 text-muted">No media files are available on disk for this case.</p>}
          {media && media.length > 0 && (
            <>
              <table className="mt-3 w-full text-left">
                <thead className="text-muted">
                  <tr><th className="py-1 pr-2">File</th><th className="pr-2">Decision</th><th>Note</th></tr>
                </thead>
                <tbody>
                  {media.map((m) => (
                    <tr key={m.path} className="border-t border-line align-top">
                      <td className="py-1 pr-2 break-all text-ink">{m.file_name}<div className="text-faint">{m.file_size.toLocaleString()} bytes</div></td>
                      <td className="pr-2">
                        <select
                          aria-label={`Decision for ${m.file_name}`}
                          value={decisions[m.path] ?? ''}
                          onChange={(e) => setDecisions((d) => ({ ...d, [m.path]: e.target.value }))}
                          className={`h-8 rounded border bg-surface text-ink px-1 ${decisions[m.path] ? 'border-line-strong' : 'border-warn'}`}
                        >
                          <option value="">Choose…</option>
                          {DECISIONS.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
                        </select>
                      </td>
                      <td>
                        <input
                          aria-label={`Note for ${m.file_name}`} value={itemNotes[m.path] ?? ''}
                          onChange={(e) => setItemNotes((n) => ({ ...n, [m.path]: e.target.value }))}
                          className="h-8 w-full px-2 rounded border border-line-strong bg-surface text-ink"
                        />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <label className="block mt-3">
                <span className="text-muted">Terms to mask, one per line (for example a person&apos;s name)</span>
                <textarea value={maskText} onChange={(e) => setMaskText(e.target.value)} rows={2} className="mt-1 w-full px-2 py-1 rounded border border-line-strong bg-surface text-ink" />
              </label>
              <div className="mt-3 flex items-center gap-3">
                <Button variant="primary" onClick={build} disabled={!canBuild}>Build package</Button>
                {undecided > 0 && <span className="text-warn">{undecided === 1 ? '1 file still needs' : `${undecided} files still need`} a decision.</span>}
              </div>
            </>
          )}
          {pkgError && <p className="mt-3 text-rec">{pkgError}</p>}
          {pkgError.includes('tagged privileged') && (
            <label className="mt-2 flex items-center gap-2 text-ink">
              <input type="checkbox" checked={ackTagged} onChange={(e) => setAckTagged(e.target.checked)} />
              I have looked at the files named above and still want them included.
            </label>
          )}
          {pkg && (
            <p className="mt-3 text-ink break-all">
              Built: {pkg.included} included, {pkg.withheld} withheld.<br />
              Folder: <span className="font-mono">{pkg.directory}</span><br />
              Merkle root of the originals: <span className="font-mono">{pkg.merkle_root}</span>
            </p>
          )}
        </Card>

        <Card icon={PackageOpen} title="Reviewer's marks">
          <ReviewerMarksCard hasCase={hasCase} />
        </Card>

        <Card icon={ListChecks} title="Validation record">
          <ValidationCard />
        </Card>

        <Card icon={ListChecks} title="Audit log">
          {!audit ? <p className="text-muted">{hasCase ? 'Loading…' : 'No case is open.'}</p> : (
            <>
              <p className="mb-2">
                Chain check:{' '}
                <strong className={audit.verified ? 'text-ok' : 'text-rec'}>{audit.verified ? 'VERIFIED' : 'FAILED'}</strong>
                {audit.error && <span className="text-rec"> ({audit.error})</span>}. {audit.entries.length} entr{audit.entries.length === 1 ? 'y' : 'ies'}.
              </p>
              <p className="mb-3 text-muted">
                Head hash: <span className="font-mono break-all text-ink">{audit.head_hash || 'none'}</span><br />
                The check shows that no entry was altered or removed from the middle. A person who can rewrite the whole file could recompute it,
                so each report prints the head hash at the time it was made; keep your copies.
              </p>
              <table className="w-full text-left">
                <thead className="text-muted"><tr><th className="py-1 pr-2">#</th><th className="pr-2">Time (UTC)</th><th className="pr-2">By</th><th>Action</th></tr></thead>
                <tbody>
                  {audit.entries.slice(-100).map((e) => (
                    <tr key={e.seq} className="border-t border-line">
                      <td className="py-1 pr-2 tabular-nums">{e.seq}</td><td className="pr-2 tabular-nums">{e.ts_utc}</td><td className="pr-2">{e.actor}</td><td>{e.action}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {audit.entries.length > 100 && <p className="mt-2 text-muted">Showing the latest 100 of {audit.entries.length}; the full log is in the audit file and in the report.</p>}
            </>
          )}
        </Card>
      </div>
    </div>
  );
};

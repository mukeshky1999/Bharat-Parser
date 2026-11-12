import React, { useEffect, useState } from 'react';
import { Download, Trash2 } from 'lucide-react';
import { useFindings, Finding } from '../state/findingsStore';
import { useWorkbenchStore } from '../state/workbenchStore';
import { csvCell, downloadCsv, formatOffset } from '../utils/csv';

function srcText(f: Finding): string {
  const s = f.source as Record<string, unknown>;
  const parts = [
    s.file ? String(s.file) : null,
    s.table ? `table ${String(s.table)}` : null,
    s.rowid !== null && s.rowid !== undefined ? `row ${String(s.rowid)}` : null,
    `offset ${formatOffset(typeof s.offset === 'number' ? s.offset : null)}`,
  ].filter(Boolean);
  return parts.join(' · ');
}

export const FindingsView: React.FC = () => {
  const { findings, load, pin, unpin, error } = useFindings();
  const caseManifest = useWorkbenchStore((s) => s.caseManifest);
  const [drafts, setDrafts] = useState<Record<number, string>>({});

  useEffect(() => {
    void load();
  }, [load, caseManifest?.caseId]);

  const saveNote = (f: Finding) =>
    pin({ kind: f.kind, record_id: f.record_id, title: f.title, note: drafts[f.id] ?? f.note, source: f.source });

  const exportCsv = () =>
    downloadCsv('findings.csv', [
      ['Pinned at (UTC)', 'Kind', 'Record', 'Title', 'Note', 'Source'].map(csvCell).join(','),
      ...findings.map((f) => [f.pinned_at_utc, f.kind, f.record_id, f.title, f.note, srcText(f)].map(csvCell).join(',')),
    ]);

  return (
    <div className="flex-1 overflow-y-auto p-6 select-text">
      <div className="max-w-4xl mx-auto">
        <div className="flex items-end justify-between mb-4">
          <div>
            <h1 className="text-lg font-semibold text-slate-50">Pinned findings</h1>
            <p className="text-slate-400">Records you marked as important, with your own notes. Pin from the evidence card on the right (Ctrl+B).</p>
          </div>
          <button
            onClick={exportCsv}
            disabled={findings.length === 0}
            className="flex items-center gap-2 h-8 px-3 rounded border border-slate-700 text-slate-200 hover:bg-slate-800 disabled:opacity-40"
          >
            <Download className="w-4 h-4" /> Export CSV
          </button>
        </div>
        {error && <p className="mb-3 text-rose-300">{error}</p>}
        {findings.length === 0 ? (
          <div className="rounded border border-dashed border-slate-700 p-8 text-center text-slate-400">
            Nothing pinned yet. Open a record in People, Money or Messages and choose Pin.
          </div>
        ) : (
          <ul className="space-y-3">
            {findings.map((f) => (
              <li key={f.id} className="rounded border border-slate-800 bg-slate-900 p-3">
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <div className="text-slate-100 font-medium break-words">{f.title}</div>
                    <div className="text-slate-400 break-words">{srcText(f)}</div>
                    <div className="text-slate-500 text-[0.75rem]">Pinned {f.pinned_at_utc} UTC · {f.kind}</div>
                  </div>
                  <button onClick={() => void unpin(f.id)} className="p-1.5 rounded text-slate-400 hover:text-rose-300 hover:bg-slate-800" aria-label={`Unpin ${f.title}`}>
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
                <label className="block mt-2">
                  <span className="text-slate-400 text-[0.75rem]">Your note</span>
                  <textarea
                    value={drafts[f.id] ?? f.note}
                    onChange={(e) => setDrafts((d) => ({ ...d, [f.id]: e.target.value }))}
                    onBlur={() => (drafts[f.id] !== undefined && drafts[f.id] !== f.note ? void saveNote(f) : undefined)}
                    rows={2}
                    className="mt-1 w-full rounded bg-slate-950 border border-slate-700 text-slate-100 p-2"
                  />
                </label>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
};

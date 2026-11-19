import React, { useEffect, useState } from 'react';
import { Download, Trash2 } from 'lucide-react';
import { useFindings, Finding } from '../state/findingsStore';
import { useWorkbenchStore } from '../state/workbenchStore';
import { ViewHeader, Card, Button, EmptyState } from '../components/ui';
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
    <div className="flex-1 overflow-y-auto p-4 bg-page select-text">
      <div className="max-w-4xl mx-auto">
        <ViewHeader title="Pinned findings" count={findings.length}
          actions={(
            <Button onClick={exportCsv} disabled={findings.length === 0}>
              <Download className="w-4 h-4" /> Export CSV
            </Button>
          )} />
        <p className="text-muted mb-3">Records you marked as important, with your own notes. Pin from the evidence card on the right (Ctrl+B).</p>
        {error && <p className="mb-3 text-rec">{error}</p>}
        {findings.length === 0 ? (
          <Card>
            <EmptyState hue="analysis" title="Nothing pinned yet">
              Open a record in People, Money or Messages and choose Pin.
            </EmptyState>
          </Card>
        ) : (
          <ul className="space-y-3">
            {findings.map((f) => (
              <li key={f.id} className="card p-3">
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <div className="text-ink font-medium break-words">{f.title}</div>
                    <div className="text-muted break-words">{srcText(f)}</div>
                    <div className="text-faint text-[0.75rem]">Pinned {f.pinned_at_utc} UTC · {f.kind}</div>
                  </div>
                  <button onClick={() => void unpin(f.id)} className="p-1.5 rounded-lg text-muted hover:text-rec hover:bg-hover" aria-label={`Unpin ${f.title}`}>
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
                <label className="block mt-2">
                  <span className="text-muted text-[0.75rem]">Your note</span>
                  <textarea
                    value={drafts[f.id] ?? f.note}
                    onChange={(e) => setDrafts((d) => ({ ...d, [f.id]: e.target.value }))}
                    onBlur={() => (drafts[f.id] !== undefined && drafts[f.id] !== f.note ? void saveNote(f) : undefined)}
                    rows={2}
                    className="mt-1 w-full rounded-lg bg-surface border border-line-strong text-ink p-2"
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

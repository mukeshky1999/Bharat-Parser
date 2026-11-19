import React, { useCallback, useEffect, useState } from 'react';
import { forensicClient } from '../api/forensicClient';

interface Mark {
  id: number; Package_Id: string; Reviewer: string | null; Reviewer_Clock: string | null; File_Index: string; File_Name: string | null;
  File_Sha256: string; Label: string | null; Note: string | null; Imported_At_Utc: string;
}

const LABEL_TEXT: Record<string, string> = { relevant: 'Relevant', not_relevant: 'Not relevant', needs_clarification: 'Needs clarification' };

/**
 * The marks a reviewer made on a package and sent back as a file. They are the reviewer's suggestions: they are
 * listed here apart from your tags and never become tags by themselves.
 */
export const ReviewerMarksCard: React.FC<{ hasCase: boolean }> = ({ hasCase }) => {
  const [marks, setMarks] = useState<Mark[]>([]);
  const [note, setNote] = useState('');
  const [msg, setMsg] = useState('');
  const [error, setError] = useState('');

  const load = useCallback(async () => {
    if (!hasCase) { setMarks([]); return; }
    const res = await forensicClient.getReviewerMarks();
    if (res.error) { setError(res.error); return; }
    setMarks((res.data?.marks ?? []) as unknown as Mark[]);
    setNote(res.data?.note ?? '');
  }, [hasCase]);
  useEffect(() => { void load(); }, [load]);

  const pick = async (file: File | undefined) => {
    if (!file) return;
    setMsg(''); setError('');
    const text = await file.text();
    const res = await forensicClient.importReviewerMarks(text);
    if (res.error) { setError(res.error); return; }
    setMsg(`${res.data!.imported} mark(s) imported${res.data!.reviewer ? ` from ${res.data!.reviewer}` : ''}.`);
    await load();
  };

  return (
    <div>
      <p className="text-muted mb-3">
        The reviewer opens the package&rsquo;s index.html, marks the files and saves a marks file. Import it here. It is accepted only if it belongs to a package this case built and every mark matches a file of that package.
      </p>
      <label className="inline-block">
        <span className="sr-only">Reviewer marks file</span>
        <input type="file" accept="application/json,.json" disabled={!hasCase} onChange={(e) => { void pick(e.target.files?.[0]); e.target.value = ''; }}
          className="text-ink file:mr-3 file:h-8 file:px-3 file:rounded file:border file:border-line-strong file:bg-surface file:text-ink" />
      </label>
      {msg && <p className="mt-2 text-ok" aria-live="polite">{msg}</p>}
      {error && <p className="mt-2 text-rec">{error}</p>}
      {marks.length > 0 && (
        <>
          <p className="mt-3 text-muted">{note}</p>
          <table className="mt-2 w-full text-left">
            <thead className="text-muted"><tr><th className="py-1 pr-2">File</th><th className="pr-2">Mark</th><th className="pr-2">Note</th><th className="pr-2">Reviewer (as typed)</th><th>Imported (UTC)</th></tr></thead>
            <tbody>
              {marks.map((m) => (
                <tr key={m.id} className="border-t border-line align-top">
                  <td className="py-1 pr-2 break-all">{m.File_Index} {m.File_Name ?? ''}</td>
                  <td className="pr-2">{m.Label ? LABEL_TEXT[m.Label] ?? m.Label : 'no mark'}</td>
                  <td className="pr-2 break-words">{m.Note ?? ''}</td>
                  <td className="pr-2">{m.Reviewer ?? 'not given'}</td>
                  <td className="tabular-nums">{m.Imported_At_Utc}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
    </div>
  );
};

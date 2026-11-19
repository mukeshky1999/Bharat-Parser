import React, { useState } from 'react';
import { forensicClient } from '../api/forensicClient';

const saveText = (name: string, text: string, type: string) => {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
};

interface Check { id: string; what: string; status: 'PASS' | 'FAIL' | 'ERROR'; expected: unknown; actual: unknown; error?: string }
interface Report { result: string; tally: { PASS: number; FAIL: number; ERROR: number }; generated_utc: string; checks: Check[]; not_covered: string[]; statement: string }

/**
 * Runs the tool's known-answer checks on inputs whose answer is known in advance, and shows expected against actual.
 * It shows the tool gave the expected result on those inputs, on this build, today. It does not show the tool is right
 * on any other input. The open case is not touched.
 */
export const ValidationCard: React.FC = () => {
  const [busy, setBusy] = useState(false);
  const [report, setReport] = useState<Report | null>(null);
  const [html, setHtml] = useState('');
  const [error, setError] = useState('');

  const run = async () => {
    setBusy(true); setError('');
    const res = await forensicClient.runValidation();
    setBusy(false);
    if (res.error || !res.data) { setError(res.error ?? 'The checks could not be run.'); return; }
    setReport(res.data.report as unknown as Report);
    setHtml(res.data.html);
  };

  const ok = report && report.tally.FAIL === 0 && report.tally.ERROR === 0;

  return (
    <div>
      <p className="text-muted mb-3">
        Runs the tool&rsquo;s own checks on small inputs whose answer is known in advance, and lists what was expected against what the tool produced. The open case is not touched.
      </p>
      <div className="flex flex-wrap gap-2">
        <button className="h-8 px-3 rounded-lg bg-accent text-on-accent hover:brightness-110 disabled:opacity-40" onClick={() => void run()} disabled={busy}>{busy ? 'Running…' : 'Run validation checks'}</button>
        <button className="h-8 px-3 rounded border border-line-strong text-ink hover:bg-hover disabled:opacity-40" disabled={!html}
          onClick={() => saveText('validation_record.html', html, 'text/html;charset=utf-8')}>Save the record (HTML)</button>
      </div>
      {error && <p className="mt-3 text-rec">{error}</p>}
      {report && (
        <div className="mt-3">
          <p className={ok ? 'text-ok font-semibold' : 'text-rec font-semibold'} aria-live="polite">
            {report.result}: {report.tally.PASS} passed, {report.tally.FAIL} failed, {report.tally.ERROR} errored.
          </p>
          <p className="text-muted text-xs mb-2">{report.statement}</p>
          <table className="w-full text-left">
            <thead className="text-muted"><tr><th className="py-1 pr-2">Check</th><th className="pr-2">Result</th></tr></thead>
            <tbody>
              {report.checks.map((c) => (
                <tr key={c.id} className="border-t border-line align-top">
                  <td className="py-1 pr-2">{c.id}: {c.what}
                    {c.status !== 'PASS' && <div className="text-xs text-muted break-all">Expected {JSON.stringify(c.expected)}; got {JSON.stringify(c.actual)} {c.error ?? ''}</div>}
                  </td>
                  <td className={c.status === 'PASS' ? 'text-ok' : 'text-rec'}>{c.status}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <p className="mt-2 text-muted text-xs">Not covered: {report.not_covered.join(' ')}</p>
        </div>
      )}
    </div>
  );
};

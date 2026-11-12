import React, { useEffect, useState } from 'react';
import { forensicClient, IngestProgress } from '../api/forensicClient';

/**
 * What the ingest is really doing, read from the server while the request is pending.
 * No overall percentage is shown: the steps differ in cost by amounts the pipeline cannot know. The step's own
 * progress is shown when the pipeline can count it, and "working" when it cannot.
 */
export const IngestProgressPanel: React.FC<{ active: boolean }> = ({ active }) => {
  const [p, setP] = useState<IngestProgress | null>(null);

  useEffect(() => {
    if (!active) return;
    let alive = true;
    const ctl = new AbortController();
    const tick = async () => {
      const r = await forensicClient.getIngestProgress(0, ctl.signal);
      if (alive && r) setP(r);
    };
    void tick();
    const id = setInterval(tick, 700);
    return () => { alive = false; ctl.abort(); clearInterval(id); };
  }, [active]);

  if (!active || !p || p.state === 'idle') return null;

  const pct = p.fraction === null ? null : Math.round(p.fraction * 100);
  const failed = p.processing_log_tail.filter((l) => l.status !== 'OK' && l.status !== 'SUCCESS');

  return (
    <section className="rounded border border-slate-700 bg-slate-900 p-3 text-xs text-slate-200" aria-label="Progress of reading the evidence" aria-live="polite">
      <div className="flex justify-between gap-3">
        <span className="font-semibold text-slate-50">
          {p.state === 'failed' ? 'Stopped' : `Step ${p.stage_index} of ${p.stage_count}`}{p.stage_label ? `: ${p.stage_label}` : ''}
        </span>
        <span className="text-slate-400">{Math.round(p.elapsed_s)} s</span>
      </div>
      <div className="mt-2 h-2 rounded bg-slate-800 overflow-hidden" role="progressbar" aria-label="Progress of this step"
        aria-valuemin={0} aria-valuemax={100} aria-valuenow={pct ?? undefined} aria-valuetext={pct === null ? 'working' : `${pct} percent`}>
        <div className={`h-full bg-cyan-500 ${pct === null ? 'w-1/3' : ''}`} style={pct === null ? undefined : { width: `${pct}%` }} />
      </div>
      <p className="mt-1 text-slate-400">
        {pct === null ? 'Working. This step cannot say how much is left.' : `${p.units_done} of ${p.units_total} ${p.unit}`}
        {p.stage_eta_s !== null && p.stage_eta_s !== undefined ? ` · about ${Math.round(p.stage_eta_s)} s left in this step` : ''}
      </p>
      {p.detail && <p className="mt-1 text-slate-300 break-all">Now: {p.detail}</p>}
      {p.state === 'failed' && p.message && <p className="mt-1 text-rose-300">{p.message}</p>}
      <p className="mt-1 text-slate-400">{p.processing_log_count} entr{p.processing_log_count === 1 ? 'y' : 'ies'} in the processing log{failed.length ? `, ${failed.length} of the last 20 not OK` : ''}.</p>
      {failed.length > 0 && (
        <ul className="mt-1 text-amber-300 break-all">
          {failed.slice(-5).map((l, i) => <li key={i}>{l.file}: {l.status}{l.error ? ` (${l.error})` : ''}</li>)}
        </ul>
      )}
    </section>
  );
};

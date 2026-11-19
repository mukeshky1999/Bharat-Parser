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
    let inFlight = false;                  // a slow reply must not be overtaken by a later request, or progress could run backwards
    const ctl = new AbortController();
    const tick = async () => {
      if (inFlight) return;
      inFlight = true;
      try {
        const r = await forensicClient.getIngestProgress(0, ctl.signal);
        if (alive && r) setP(r);
      } finally {
        inFlight = false;
      }
    };
    void tick();
    const id = setInterval(tick, 700);
    return () => { alive = false; ctl.abort(); clearInterval(id); };
  }, [active]);

  if (!active || !p || p.state === 'idle') return null;

  const pct = p.fraction === null ? null : Math.round(p.fraction * 100);
  const failed = p.processing_log_tail.filter((l) => l.status !== 'OK' && l.status !== 'SUCCESS');

  return (
    <section className="card p-3 text-xs text-ink" aria-label="Progress of reading the evidence" aria-live="polite">
      <div className="flex justify-between gap-3">
        <span className="font-semibold text-ink">
          {p.state === 'failed' ? 'Stopped' : `Step ${p.stage_index} of ${p.stage_count}`}{p.stage_label ? `: ${p.stage_label}` : ''}
        </span>
        <span className="text-muted">{Math.round(p.elapsed_s)} s</span>
      </div>
      <div className="mt-2 h-2 rounded-full bg-sunken overflow-hidden" role="progressbar" aria-label="Progress of this step"
        aria-valuemin={0} aria-valuemax={100} aria-valuenow={pct ?? undefined} aria-valuetext={pct === null ? 'working' : `${pct} percent`}>
        <div className={`h-full bg-accent ${pct === null ? 'w-1/3' : ''}`} style={pct === null ? undefined : { width: `${pct}%` }} />
      </div>
      <p className="mt-1 text-muted">
        {pct === null ? 'Working. This step cannot say how much is left.' : `${p.units_done} of ${p.units_total} ${p.unit}`}
        {p.stage_eta_s !== null && p.stage_eta_s !== undefined ? ` · about ${Math.round(p.stage_eta_s)} s left in this step` : ''}
      </p>
      {p.detail && <p className="mt-1 text-muted break-all">Now: {p.detail}</p>}
      {p.state === 'failed' && p.message && <p className="mt-1 text-rec">{p.message}</p>}
      <p className="mt-1 text-muted">{p.processing_log_count} entr{p.processing_log_count === 1 ? 'y' : 'ies'} in the processing log{failed.length ? `, ${failed.length} of the last 20 not OK` : ''}.</p>
      {failed.length > 0 && (
        <ul className="mt-1 text-warn break-all">
          {failed.slice(-5).map((l, i) => <li key={i}>{l.file}: {l.status}{l.error ? ` (${l.error})` : ''}</li>)}
        </ul>
      )}
    </section>
  );
};

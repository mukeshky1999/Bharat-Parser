import React from 'react';
import type { DayCount } from './format';

const niceMax = (v: number) => {
  const p = Math.pow(10, Math.floor(Math.log10(Math.max(v, 1))));
  for (const m of [1, 2, 5, 10]) if (m * p >= v) return m * p;
  return 10 * p;
};

const shortDay = (iso: string) => new Date(`${iso}T00:00:00Z`).toLocaleDateString('en-IN', { day: 'numeric', month: 'short', timeZone: 'UTC' });

/** Records per day. One scale for the bars, the ticks and the labels. */
export const ActivityChart: React.FC<{ days: DayCount[] }> = ({ days }) => {
  const W = 640, H = 170, L = 38, R = 8, T = 10, B = 26;
  const max = niceMax(Math.max(...days.map((d) => d.n), 1));
  const bw = (W - L - R) / days.length;
  const y = (v: number) => T + (H - T - B) * (1 - v / max);
  const ticks = [0, max / 2, max];
  const labelEvery = Math.max(1, Math.ceil(days.length / 5));
  return (
    <svg viewBox={`0 0 ${W} ${H}`} role="img" className="w-full h-auto"
      aria-label={`Records per day, ${shortDay(days[0].day)} to ${shortDay(days[days.length - 1].day)}, from loaded records`}>
      {ticks.map((t) => (
        <g key={t}>
          <line x1={L} x2={W - R} y1={y(t)} y2={y(t)} className="stroke-line" strokeWidth={1} />
          <text x={L - 6} y={y(t) + 4} textAnchor="end" fontSize={11} className="fill-muted">{Math.round(t).toLocaleString()}</text>
        </g>
      ))}
      {days.map((d, i) => (
        <rect key={d.day} x={L + i * bw + Math.min(2, bw / 4)} y={y(d.n)} width={Math.max(1, bw - Math.min(4, bw / 2))}
          height={Math.max(0, y(0) - y(d.n))} rx={2} className="fill-accent">
          <title>{`${shortDay(d.day)}: ${d.n.toLocaleString()} records`}</title>
        </rect>
      ))}
      {days.map((d, i) => (i % labelEvery === 0 ? (
        <text key={d.day} x={L + i * bw + bw / 2} y={H - 8} textAnchor="middle" fontSize={11} className="fill-muted">{shortDay(d.day)}</text>
      ) : null))}
    </svg>
  );
};

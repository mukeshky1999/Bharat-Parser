import React from 'react';

export type Tone = 'neutral' | 'ok' | 'warn' | 'bad' | 'accent';
const TONE: Record<Tone, string> = {
  neutral: 'text-slate-300 border-slate-700',
  ok: 'text-emerald-300 border-emerald-700',
  warn: 'text-amber-300 border-amber-700',
  bad: 'text-rose-300 border-rose-700',
  accent: 'text-cyan-300 border-cyan-700',
};

/** A small outlined label. Colour is used only for meaning (ok, warn, bad) or the single accent. */
export const Badge: React.FC<{ tone?: Tone; children: React.ReactNode; title?: string; className?: string }> = ({ tone = 'neutral', children, title, className = '' }) => (
  <span title={title} className={`inline-flex items-center h-5 px-1.5 rounded-ctl border text-[0.75rem] font-medium whitespace-nowrap ${TONE[tone]} ${className}`}>{children}</span>
);

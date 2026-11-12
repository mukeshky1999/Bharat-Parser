import React from 'react';
import { AlertCircle, AlertTriangle, CheckCircle2, Info, X } from 'lucide-react';
import { useWorkbenchStore } from '../state/workbenchStore';

const TONE = {
  error: { box: 'bg-rose-950 border-rose-700 text-rose-100', icon: AlertCircle, ic: 'text-rose-300' },
  warning: { box: 'bg-amber-950 border-amber-700 text-amber-100', icon: AlertTriangle, ic: 'text-amber-300' },
  success: { box: 'bg-emerald-950 border-emerald-700 text-emerald-100', icon: CheckCircle2, ic: 'text-emerald-300' },
  info: { box: 'bg-slate-900 border-slate-600 text-slate-100', icon: Info, ic: 'text-cyan-300' },
} as const;

export const Toasts: React.FC = () => {
  const toasts = useWorkbenchStore((s) => s.toasts);
  const dismiss = useWorkbenchStore((s) => s.dismissToast);
  if (!toasts || toasts.length === 0) return null;
  return (
    <div className="fixed bottom-10 right-6 z-[9999] flex flex-col gap-2 max-w-md" aria-live="polite">
      {toasts.map((t) => {
        const tone = TONE[t.type] ?? TONE.info;
        const Icon = tone.icon;
        return (
          <div key={t.id} role={t.type === 'error' ? 'alert' : 'status'} className={`p-3 rounded-ctl-panel border shadow-float flex items-start gap-3 ${tone.box}`}>
            <Icon className={`w-5 h-5 shrink-0 mt-0.5 ${tone.ic}`} aria-hidden="true" />
            <div className="flex-1 min-w-0">
              {t.title && <div className="font-semibold mb-0.5">{t.title}</div>}
              <div className="break-words">{t.message}</div>
            </div>
            <button onClick={() => dismiss(t.id)} className="p-0.5 rounded-ctl text-slate-300 hover:text-slate-50" aria-label="Dismiss message">
              <X className="w-4 h-4" />
            </button>
          </div>
        );
      })}
    </div>
  );
};

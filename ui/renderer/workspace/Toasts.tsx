import React from 'react';
import { AlertCircle, AlertTriangle, CheckCircle2, Info, X } from 'lucide-react';
import { useWorkbenchStore } from '../state/workbenchStore';

const TONE = {
  error: { box: 'bg-rec-soft border-rec text-ink', icon: AlertCircle, ic: 'text-rec' },
  warning: { box: 'bg-warn-soft border-warn text-ink', icon: AlertTriangle, ic: 'text-warn' },
  success: { box: 'bg-ok-soft border-ok text-ink', icon: CheckCircle2, ic: 'text-ok' },
  info: { box: 'bg-surface border-line-strong text-ink', icon: Info, ic: 'text-accent' },
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
          <div key={t.id} role={t.type === 'error' ? 'alert' : 'status'} className={`p-3 rounded-[10px] border shadow-float flex items-start gap-3 ${tone.box}`}>
            <Icon className={`w-5 h-5 shrink-0 mt-0.5 ${tone.ic}`} aria-hidden="true" />
            <div className="flex-1 min-w-0">
              {t.title && <div className="font-semibold mb-0.5">{t.title}</div>}
              <div className="break-words">{t.message}</div>
            </div>
            <button onClick={() => dismiss(t.id)} className="p-0.5 rounded text-muted hover:text-ink" aria-label="Dismiss message">
              <X className="w-4 h-4" />
            </button>
          </div>
        );
      })}
    </div>
  );
};

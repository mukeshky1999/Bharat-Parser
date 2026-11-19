import React from 'react';
import { AlertTriangle } from 'lucide-react';
import { useWorkbenchStore } from '../state/workbenchStore';

/** Shown when a kind of record could not be read from the backend: the lists below may then be incomplete. */
export const LoadErrors: React.FC = () => {
  const errors = useWorkbenchStore((s) => s.loadErrors);
  const kinds = Object.keys(errors || {});
  if (kinds.length === 0) return null;
  return (
    <div role="alert" className="flex items-start gap-2 px-3 py-1.5 bg-warn-soft text-warn border-b border-line text-sm">
      <AlertTriangle className="w-4 h-4 mt-0.5 shrink-0" aria-hidden="true" />
      <span>
        Could not read {kinds.join(', ')} from the case ({kinds.map((k) => errors[k]).join(' ')}). What is shown for {kinds.length === 1 ? 'it' : 'them'} may be
        incomplete, and an empty list does not mean nothing was found.
      </span>
    </div>
  );
};

import React from 'react';
import { FileCheck2, Gavel, Snowflake } from 'lucide-react';
import { useWorkbenchStore } from '../state/workbenchStore';
import { useFindings } from '../state/findingsStore';
import { useUi } from '../state/uiStore';

export const CourtOutputView: React.FC = () => {
  const caseManifest = useWorkbenchStore((s) => s.caseManifest);
  const integrity = useWorkbenchStore((s) => s.integrity);
  const setIsBsaModalOpen = useWorkbenchStore((s) => s.setIsBsaModalOpen);
  const findings = useFindings((s) => s.findings.length);
  const open = useUi((s) => s.open);
  const hasCase = !!caseManifest;

  const outputs = [
    {
      icon: FileCheck2,
      title: 'Section 63 certificate (Bharatiya Sakshya Adhiniyam, 2023)',
      text: 'The certificate that accompanies electronic records offered as evidence. It records the source file, its hashes and the examiner’s particulars. The examiner signs it.',
      action: () => setIsBsaModalOpen(true),
      label: 'Prepare certificate',
    },
    {
      icon: Gavel,
      title: 'Section 230 disclosure bundle (BNSS, 2023)',
      text: 'The documents that must be given to the accused with the police report, assembled from the case.',
      action: () => open('SEC230'),
      label: 'Prepare bundle',
    },
    {
      icon: Snowflake,
      title: 'NCRP 1930 freeze sheet',
      text: 'A list of bank accounts and UPI handles to request a hold on, for submission through the cybercrime portal.',
      action: () => open('NCRP'),
      label: 'Prepare freeze sheet',
    },
  ];

  return (
    <div className="flex-1 overflow-y-auto p-6 select-text">
      <div className="max-w-3xl mx-auto">
        <h1 className="text-lg font-semibold text-slate-50 mb-1">Court output</h1>
        <p className="text-slate-400 mb-4">
          Each output is built from this case&apos;s records. Read it fully before you sign or submit it: the software prepares the paper, the examiner is responsible for what it says.
        </p>
        {!hasCase && <p className="mb-4 rounded border border-amber-700 bg-amber-950 text-amber-300 p-3">Open evidence first (top right). Nothing can be prepared without a case.</p>}
        {hasCase && integrity?.match === false && (
          <p className="mb-4 rounded border border-rose-700 bg-rose-950 text-rose-300 p-3">
            The source file hash changed during processing. Do not issue a certificate for this case until that is explained.
          </p>
        )}
        <ul className="space-y-3">
          {outputs.map((o) => (
            <li key={o.title} className="rounded border border-slate-800 bg-slate-900 p-4 flex items-start gap-4">
              <o.icon className="w-6 h-6 text-slate-300 shrink-0 mt-0.5" aria-hidden="true" />
              <div className="flex-1 min-w-0">
                <h2 className="text-slate-50 font-medium">{o.title}</h2>
                <p className="text-slate-300 mt-1">{o.text}</p>
              </div>
              <button
                onClick={o.action}
                disabled={!hasCase}
                className="shrink-0 h-8 px-3 rounded bg-cyan-600 text-slate-50 hover:bg-cyan-500 disabled:opacity-40 disabled:hover:bg-cyan-600"
              >
                {o.label}
              </button>
            </li>
          ))}
        </ul>
        <p className="mt-4 text-slate-400">
          {findings} pinned finding{findings === 1 ? '' : 's'} in this case. The generators above do not read pinned findings yet; use the Findings stage to export them as a CSV for your annexure.
        </p>
      </div>
    </div>
  );
};

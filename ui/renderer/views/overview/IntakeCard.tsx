import React from 'react';
import { AlertCircle, FolderArchive, FolderTree, HardDrive, Loader2 } from 'lucide-react';
import { Button, Card } from '../../components/ui';

interface IntakeCardProps {
  directPathInput: string;
  onPathChange: (v: string) => void;
  onPickFile: () => void;
  onPickFolder: () => void;
  onPathIngest: () => void;
  isIngesting: boolean;
  ingestionPhase: string;
  errorMessage: string | null;
}

const STEPS = [
  'Open the evidence: a file such as .ufdr, .tar, .zip, .xry, .ofb or .ab, a folder, or a single .sqlite or .db file.',
  'The tool opens it read-only, hashes it before and after, and reads it from a working copy.',
  'Browse the data in the tree on the left. A report and facts annexure can be prepared once evidence is open.',
];

/** The welcome card shown while no evidence is open. */
export const IntakeCard: React.FC<IntakeCardProps> = ({
  directPathInput, onPathChange, onPickFile, onPickFolder, onPathIngest, isIngesting, ingestionPhase, errorMessage,
}) => (
  <div className="h-full w-full bg-page text-ink overflow-y-auto p-6">
    <div className="max-w-[760px] mx-auto space-y-4 pt-6">
      <div>
        <div className="text-muted font-medium">Case overview</div>
        <h1 className="text-xl font-semibold tracking-tight">Open evidence to start a case</h1>
      </div>

      <Card title="Open evidence" aside="Hashes are recorded on opening">
        <ol className="space-y-2.5 mb-4">
          {STEPS.map((s, i) => (
            <li key={i} className="flex gap-3">
              <span className="w-5 h-5 rounded-full bg-accent-soft text-accent-ink grid place-items-center font-semibold shrink-0 text-[0.75rem]">{i + 1}</span>
              <span>{s}</span>
            </li>
          ))}
        </ol>
        <div className="flex flex-wrap gap-2">
          <Button variant="primary" onClick={onPickFile} disabled={isIngesting}><FolderArchive className="w-4 h-4" aria-hidden="true" />Open file</Button>
          <Button onClick={onPickFolder} disabled={isIngesting}><FolderTree className="w-4 h-4" aria-hidden="true" />Open folder</Button>
        </div>
        <div className="mt-4 pt-4 border-t border-line">
          <label htmlFor="intake-path" className="flex items-center gap-2 text-muted font-medium mb-1.5">
            <HardDrive className="w-4 h-4" aria-hidden="true" />Or paste a path
          </label>
          <div className="flex gap-2">
            <input id="intake-path" type="text" value={directPathInput} onChange={(e) => onPathChange(e.target.value)}
              placeholder="e.g. D:\Cases\2026\evidence.tar"
              className="flex-1 h-8 bg-surface border border-line-strong rounded-lg px-2.5 text-ink placeholder:text-faint font-mono focus:outline-none focus:border-accent" />
            <Button variant="secondary" onClick={onPathIngest} disabled={!directPathInput.trim() || isIngesting}>Open read-only</Button>
          </div>
        </div>
      </Card>

      {isIngesting && (
        <Card>
          <div className="flex items-center gap-2 font-semibold"><Loader2 className="w-4 h-4 animate-spin text-accent" aria-hidden="true" />Reading evidence</div>
          <p className="text-muted mt-1.5">{ingestionPhase}</p>
          <p className="text-muted">The original file is opened read-only.</p>
        </Card>
      )}

      {errorMessage && (
        <div role="alert" className="p-3 bg-rec-soft text-rec rounded-[10px] flex items-center gap-2">
          <AlertCircle className="w-4 h-4 shrink-0" aria-hidden="true" />
          <span>{errorMessage}</span>
        </div>
      )}
    </div>
  </div>
);

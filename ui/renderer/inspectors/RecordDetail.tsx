import React, { useState } from 'react';
import { X } from 'lucide-react';
import { shownValue } from '../utils/recordText';
import { TagControls, TagPills, RecordRef } from './TagControls';

export { TagPills };
export type { RecordRef };

/**
 * One stored record exactly as the case holds it, with its tags.
 * A value that was not recorded is shown as "not recorded", never as a blank or a default.
 */
interface Props {
  record: RecordRef | null;
  onClose?: () => void;
  /** Called after a tag was applied or removed, so a list behind this panel can refresh. */
  onTagsChanged?: () => void;
}

export const RecordDetail: React.FC<Props> = ({ record, onClose, onTagsChanged }) => {
  // The fields are kept with the record they belong to, so the panel never shows one record's fields under another's heading.
  const [loaded, setLoaded] = useState<{ table: string; id: number; data: Record<string, unknown> | null } | null>(null);
  if (!record) return null;
  const data = loaded && loaded.table === record.table && loaded.id === record.id ? loaded.data : null;
  return (
    <aside className="w-96 shrink-0 border-l border-line bg-sunken overflow-y-auto p-3 text-xs text-ink select-text" aria-label="Record detail">
      <div className="flex items-start justify-between gap-2 mb-2">
        <h2 className="font-semibold text-ink">{record.table} #{record.id}</h2>
        {onClose && <button className="p-1 rounded text-muted hover:bg-hover" aria-label="Close record" onClick={onClose}><X className="w-4 h-4" /></button>}
      </div>
      <div className="mb-3">
        <TagControls key={`${record.table}-${record.id}`} record={record} onChanged={onTagsChanged} onLoaded={(d) => setLoaded({ table: record.table, id: record.id, data: d })} />
      </div>
      <table className="w-full table-fixed border-collapse">
        <tbody>
          {data && Object.entries(data).map(([k, v]) => (
            <tr key={k} className="border-t border-line align-top">
              <th className="text-left font-normal text-muted pr-2 py-1 w-36 break-words">{k}</th>
              <td className={`py-1 break-all ${v === null || v === undefined || v === '' ? 'text-faint' : 'text-ink'}`}>{shownValue(v)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </aside>
  );
};

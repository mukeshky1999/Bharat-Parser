import { useEffect, useState } from 'react';
import { forensicClient } from '../api/forensicClient';
import { useUi } from '../state/uiStore';
import { useWorkbenchStore } from '../state/workbenchStore';

/**
 * The tags of every tagged record of one case-store table, keyed by record id. It is read again whenever a tag is
 * applied or removed anywhere (`tagsVersion`), so pills on a table never go stale. Only records the examiner tagged
 * appear: the tool never tags.
 */
export function useTagIndex(table: string): Record<number, string[]> {
  const version = useUi((s) => s.tagsVersion);
  const caseId = useWorkbenchStore((s) => s.caseManifest?.caseId);
  const [index, setIndex] = useState<Record<number, string[]>>({});
  useEffect(() => {
    if (!caseId) { setIndex({}); return; }
    let alive = true;
    void forensicClient.getTagIndex(table).then((r) => {
      if (!alive) return;
      const out: Record<number, string[]> = {};
      for (const [k, v] of Object.entries(r.data?.tags ?? {})) out[Number(k)] = v;
      setIndex(out);
    });
    return () => { alive = false; };
  }, [table, version, caseId]);
  return index;
}

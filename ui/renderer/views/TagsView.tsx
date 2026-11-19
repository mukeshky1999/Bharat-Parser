import React, { useCallback, useEffect, useState } from 'react';
import { forensicClient, TagSummary, TaggedRecord } from '../api/forensicClient';
import { RecordDetail, RecordRef } from '../inspectors/RecordDetail';
import { useUi } from '../state/uiStore';
import { ViewHeader, Button } from '../components/ui';
import { useLatestRequest } from '../utils/latestRequest';

const PAGE = 100;

/**
 * The tags you applied and the records under each. A tag is your decision about a record; the tool applies none.
 * A tag whose record could not be found again after the evidence was processed a second time is counted, not listed.
 */
export const TagsView: React.FC = () => {
  const [tags, setTags] = useState<TagSummary[]>([]);
  const [detachedTotal, setDetachedTotal] = useState(0);
  const [current, setCurrent] = useState<string>('');
  const [records, setRecords] = useState<TaggedRecord[]>([]);
  const [recordsTag, setRecordsTag] = useState<string>('');   // the tag the listed records really belong to
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [error, setError] = useState('');
  const [open, setOpen] = useState<RecordRef | null>(null);
  const bumpTags = useUi((s) => s.bumpTags);

  const loadTags = useCallback(async () => {
    const res = await forensicClient.getTags();
    if (res.error) { setError(res.error); return; }
    setError('');
    setTags(res.data?.tags ?? []);
    setDetachedTotal(res.data?.detached_total ?? 0);
  }, []);

  const latest = useLatestRequest();
  const loadRecords = useCallback(async (tag: string, off: number) => {
    const { isCurrent } = latest.begin();
    if (!tag) { setRecords([]); setTotal(0); setRecordsTag(''); return; }
    const res = await forensicClient.getTaggedRecords(tag, { limit: PAGE, offset: off });
    if (!isCurrent()) return;                          // a newer choice has been made
    if (res.error) { setError(res.error); setRecords([]); setTotal(0); setRecordsTag(tag); return; }
    setRecords(res.data?.records ?? []);
    setTotal(res.data?.total ?? 0);
    setRecordsTag(tag);
  }, [latest]);

  useEffect(() => { void loadTags(); }, [loadTags]);
  useEffect(() => { setOffset(0); void loadRecords(current, 0); }, [current, loadRecords]);

  const remove = async (r: TaggedRecord) => {
    if (r.id === null || recordsTag !== current) return;   // only the tag these records were listed under
    const res = await forensicClient.untagRecords(recordsTag, [{ table: r.table, id: r.id }]);
    if (res.error) { setError(res.error); return; }
    await loadTags();
    await loadRecords(current, offset);
    bumpTags();
  };

  const changed = () => { void loadTags(); void loadRecords(current, offset); };

  return (
    <div className="flex-1 flex min-w-0 min-h-0 bg-page">
      <nav className="w-64 shrink-0 border-r border-line bg-surface overflow-y-auto p-3" aria-label="Tags">
        <ul className="space-y-1">
          {tags.map((t) => (
            <li key={t.tag}>
              <button onClick={() => setCurrent(t.tag)} aria-current={current === t.tag}
                className={`w-full text-left rounded-lg border px-2 py-1.5 ${current === t.tag ? 'border-accent bg-accent-soft' : 'border-line hover:bg-hover'}`}>
                <div className="flex justify-between text-ink"><span>{t.tag}</span><span>{t.count}</span></div>
                {t.meaning && <div className="text-[0.6875rem] text-muted">{t.meaning}</div>}
                {t.detached > 0 && <div className="text-[0.6875rem] text-warn">{t.detached} no longer found after reprocessing</div>}
              </button>
            </li>
          ))}
        </ul>
        {detachedTotal > 0 && (
          <p className="mt-3 text-[0.75rem] text-warn">
            {detachedTotal} tag(s) belong to records that were not found again after a device was processed a second time. They are counted here and are not listed.
          </p>
        )}
      </nav>
      <div className="flex-1 overflow-y-auto p-4 select-text min-w-0">
        {error && <p className="text-rec mb-2">{error}</p>}
        {!current ? (
          <p className="text-muted">Choose a tag to see its records. To tag a record, open it from Search, the Timeline or a table and use the tag buttons in the record panel.</p>
        ) : (
          <>
            <ViewHeader title={`${current}${recordsTag === current ? `: ${total} record${total === 1 ? '' : 's'}` : ': loading…'}`} />
            {recordsTag === current && records.length === 0 && !error && <p className="text-faint">No records under this tag.</p>}
            <ul className="space-y-1">
              {(recordsTag === current ? records : []).map((r, i) => (
                <li key={`${r.table}-${r.id}-${i}`} className="card p-2">
                  <div className="flex justify-between gap-2">
                    <button className="text-left min-w-0 flex-1 hover:underline" disabled={r.id === null} onClick={() => r.id !== null && setOpen({ table: r.table, id: r.id })}>
                      <div className="text-[0.75rem] text-muted">{r.table} #{r.id} · {r.evidence_item ?? 'device not recorded'} · tagged {r.tagged_at_utc} UTC</div>
                      <div className="text-ink break-words">{r.summary || 'no text recorded'}</div>
                      {r.note && <div className="text-muted text-xs">Note: {r.note}</div>}
                    </button>
                    <Button className="!h-7 px-2 text-xs self-start" onClick={() => void remove(r)}>Remove tag</Button>
                  </div>
                </li>
              ))}
            </ul>
            <div className="flex items-center gap-2 mt-3">
              <Button disabled={offset === 0}
                onClick={() => { const o = Math.max(0, offset - PAGE); setOffset(o); void loadRecords(current, o); }}>Previous</Button>
              <Button disabled={offset + PAGE >= total}
                onClick={() => { const o = offset + PAGE; setOffset(o); void loadRecords(current, o); }}>Next</Button>
            </div>
          </>
        )}
      </div>
      <RecordDetail record={open} onClose={() => setOpen(null)} onTagsChanged={changed} />
    </div>
  );
};

import React, { useCallback, useEffect, useState } from 'react';
import { Image as ImageIcon, Film } from 'lucide-react';
import { forensicClient, HashSetInfo, MediaItem } from '../api/forensicClient';
import { ViewHeader, Button } from '../components/ui';
import { useLatestRequest } from '../utils/latestRequest';

const PAGE = 48;
const field = 'h-8 rounded-lg bg-surface border border-line-strong px-2 text-ink placeholder:text-faint';
const NR = 'not recorded';

const STATUS_TEXT: Record<MediaItem['status'], string> = {
  OK: 'Read',
  HASHED_ONLY: 'Hashed only',
  NOT_DECODED: 'Could not be decoded',
  UNREADABLE: 'File could not be read',
};

const Thumb: React.FC<{ item: MediaItem }> = ({ item }) => {
  const [url, setUrl] = useState<string | null>(null);
  useEffect(() => {
    if (!item.has_thumbnail) { setUrl(null); return; }
    const ctl = new AbortController();
    let made: string | null = null;
    let cancelled = false;
    void forensicClient.getMediaThumbnail(item.id, ctl.signal)
      .then((u) => {
        if (cancelled) { if (u) URL.revokeObjectURL(u); return; }   // the reply came after this thumbnail was gone: free it
        made = u; setUrl(u);
      })
      .catch(() => { if (!cancelled) setUrl(null); });
    return () => { cancelled = true; ctl.abort(); if (made) URL.revokeObjectURL(made); };
  }, [item.id, item.has_thumbnail]);
  if (url) return <img src={url} alt={`Thumbnail of ${item.file_name ?? 'file'}`} className="w-full h-28 object-cover bg-sunken" />;
  const Icon = item.kind === 'video' ? Film : ImageIcon;
  return <div className="w-full h-28 bg-sunken flex items-center justify-center text-faint"><Icon className="w-8 h-8" aria-label="No thumbnail" /></div>;
};

const HashLists: React.FC<{ onChanged: () => void }> = ({ onChanged }) => {
  const [sets, setSets] = useState<HashSetInfo[]>([]);
  const [name, setName] = useState('');
  const [kind, setKind] = useState<HashSetInfo['kind']>('known_notable');
  const [text, setText] = useState('');
  const [msg, setMsg] = useState('');
  const load = useCallback(async () => { setSets((await forensicClient.getHashSets()).data?.hash_sets ?? []); }, []);
  useEffect(() => { void load(); }, [load]);
  const add = async () => {
    const res = await forensicClient.importHashSet(name.trim(), kind, text);
    if (res.error) { setMsg(res.error); return; }
    setMsg(`${res.data!.entries} value(s) kept, ${res.data!.skipped_lines} line(s) skipped, ${res.data!.matching_files_now} file(s) match now.`);
    setName(''); setText(''); await load(); onChanged();
  };
  const del = async (n: string) => { await forensicClient.removeHashSet(n); await load(); onChanged(); };
  return (
    <details className="card p-3 mb-3">
      <summary className="cursor-pointer text-ink">Hash lists you supplied ({sets.length})</summary>
      <p className="text-xs text-muted mt-2">
        The tool ships no list. A match means a file&rsquo;s MD5 or SHA-256 equals a value in a list you imported; what the list means is yours to say.
      </p>
      <ul className="mt-2 text-xs text-ink space-y-1">
        {sets.map((s) => (
          <li key={s.id} className="flex items-center justify-between gap-2">
            <span>{s.name} · {s.kind === 'known_notable' ? 'known / notable' : 'known / ignorable'} · {s.entries} values{s.skipped_lines ? ` · ${s.skipped_lines} lines skipped` : ''}</span>
            <Button className="!h-7 px-2" onClick={() => void del(s.name)}>Remove</Button>
          </li>
        ))}
      </ul>
      <div className="mt-2 flex flex-wrap gap-2">
        <input aria-label="List name" className={`${field} w-48`} placeholder="List name" value={name} onChange={(e) => setName(e.target.value)} />
        <select aria-label="List kind" className={field} value={kind} onChange={(e) => setKind(e.target.value as HashSetInfo['kind'])}>
          <option value="known_notable">Known / notable</option>
          <option value="known_ignorable">Known / ignorable</option>
        </select>
      </div>
      <textarea aria-label="MD5 or SHA-256 values, one per line" className="mt-2 w-full h-24 rounded bg-surface border border-line-strong p-2 font-mono text-xs text-ink"
        placeholder="MD5 or SHA-256 values, one per line" value={text} onChange={(e) => setText(e.target.value)} />
      <div className="mt-2 flex items-center gap-3">
        <Button disabled={!name.trim() || !text.trim()} onClick={() => void add()}>Import list</Button>
        {msg && <span className="text-xs text-ink" aria-live="polite">{msg}</span>}
      </div>
    </details>
  );
};

const Detail: React.FC<{ item: MediaItem; onOpen: (id: number) => void }> = ({ item, onOpen }) => {
  const [similar, setSimilar] = useState<{ note: string; matches: Array<{ id: number; distance: number; file_name: string | null; identical_bytes: boolean }> } | null>(null);
  const latestSimilar = useLatestRequest();
  useEffect(() => { latestSimilar.cancel(); setSimilar(null); }, [item.id, latestSimilar]);   // nothing found for another image stays
  const rows: Array<[string, string]> = [
    ['File', item.vfs_path], ['Device', item.evidence_item ?? NR], ['Size', item.file_size !== null ? `${item.file_size} bytes` : NR],
    ['SHA-256', item.sha256 ?? NR], ['MD5', item.md5 ?? NR],
    ['Dimensions', item.width && item.height ? `${item.width} × ${item.height}` : NR], ['Format', item.format ?? NR],
    ['Camera', [item.camera_make, item.camera_model].filter(Boolean).join(' ') || NR], ['Software', item.software ?? NR],
    ['Camera clock', item.exif_clock ? `${item.exif_clock} (the camera's own clock; no zone recorded, not converted)` : NR],
    ['GPS', item.gps_lat !== null && item.gps_lon !== null ? `${item.gps_lat}, ${item.gps_lon}` : 'no fix recorded'],
    ['Fingerprint (dHash)', item.dhash ?? NR], ['Status', `${STATUS_TEXT[item.status]}${item.status_detail ? `: ${item.status_detail}` : ''}`],
    ['Decoded by', item.decoded_by ?? NR],
    ['Matches your lists', item.hash_set_matches.length ? item.hash_set_matches.join(', ') : 'none'],
  ];
  return (
    <aside className="w-96 shrink-0 border-l border-line bg-surface overflow-y-auto p-3 text-xs text-ink select-text" aria-label="Media detail">
      <h2 className="font-semibold text-ink mb-2 break-words">{item.file_name ?? item.vfs_path}</h2>
      <table className="w-full border-collapse">
        <tbody>
          {rows.map(([k, v]) => (
            <tr key={k} className="border-t border-line align-top">
              <th className="text-left font-normal text-muted pr-2 py-1 w-32">{k}</th>
              <td className={`py-1 break-all ${v === NR ? 'text-faint' : 'text-ink'}`}>{v}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {item.dhash && (
        <div className="mt-3">
          <Button onClick={async () => {
            const { isCurrent } = latestSimilar.begin();
            const res = await forensicClient.getSimilarMedia(item.id);
            if (isCurrent()) setSimilar(res.data);
          }}>Find look-alike images (a lead)</Button>
          {similar && (
            <div className="mt-2">
              <p className="text-warn">LEAD: {similar.note}</p>
              {similar.matches.length === 0 && <p className="text-muted mt-1">No other image is within the distance.</p>}
              <ul className="mt-1 space-y-1">
                {similar.matches.map((m) => (
                  <li key={m.id}><button className="underline text-accent-ink" onClick={() => onOpen(m.id)}>{m.file_name ?? `#${m.id}`}</button> · {m.distance} bit(s) apart{m.identical_bytes ? ' · identical bytes' : ''}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </aside>
  );
};

/** The images and videos found in the case, with hashes, camera data and lists you supplied. Look-alike results are leads, not findings. */
export const MediaLibraryView: React.FC = () => {
  const [items, setItems] = useState<MediaItem[]>([]);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [kind, setKind] = useState<'' | 'image' | 'video'>('');
  const [status, setStatus] = useState('');
  const [gps, setGps] = useState<'' | 'yes' | 'no'>('');
  const [listFilter, setListFilter] = useState<'' | 'notable' | 'outside'>('');
  const [selected, setSelected] = useState<MediaItem | null>(null);
  const [error, setError] = useState('');
  const [working, setWorking] = useState('');

  const latestList = useLatestRequest();
  const load = useCallback(async (off: number) => {
    const { isCurrent } = latestList.begin();
    const res = await forensicClient.getMedia({
      kind: kind || undefined, status: status || undefined, hasGps: gps === '' ? undefined : gps === 'yes',
      setKind: listFilter === 'notable' ? 'known_notable' : undefined, outsideSets: listFilter === 'outside', limit: PAGE, offset: off,
    });
    if (!isCurrent()) return;
    if (res.error) { setError(res.error); return; }
    const list = res.data?.items ?? [];
    setError(''); setItems(list); setTotal(res.data?.total ?? 0);
    // the open file is shown as the case holds it now (a hash list imported meanwhile may have changed its matches)
    setSelected((prev) => (prev ? (list.find((i) => i.id === prev.id) ?? prev) : prev));
  }, [kind, status, gps, listFilter, latestList]);

  useEffect(() => { setOffset(0); void load(0); }, [load]);

  const analyse = async (redo: boolean) => {
    setWorking('Analysing…'); setError('');
    let done = 0; let remaining = 1; let pillow: string | null = null;
    while (remaining > 0) {
      const res = await forensicClient.analyseMedia({ redo: redo && done === 0, limit: 500 });
      if (res.error || !res.data) { setError(res.error ?? 'Analysis failed.'); break; }
      done += res.data.analysed; remaining = res.data.remaining; pillow = res.data.pillow;
      setWorking(`Analysed ${done} file(s)${remaining ? `, ${remaining} to go…` : ''}`);
      if (res.data.analysed === 0) break;       // nothing moved: do not loop forever
    }
    setWorking(`Analysed ${done} file(s).${pillow ? '' : ' The image library is not installed, so images were hashed only.'}`);
    await load(offset);
  };

  const openById = (id: number) => {
    const hit = items.find((i) => i.id === id);
    if (hit) setSelected(hit);
    else setError('That image is on another page of the list. Clear the filters or go to its page to open it.');
  };

  return (
    <div className="flex-1 flex min-w-0 min-h-0 bg-page">
      <div className="flex-1 overflow-y-auto p-4 select-text min-w-0">
        <ViewHeader title="Media library" count={total} />
        <div className="flex flex-wrap items-center gap-2 mb-3">
          <Button variant="primary" disabled={!!working && working.endsWith('…')} onClick={() => void analyse(false)}>Analyse media files</Button>
          <select aria-label="Kind" className={field} value={kind} onChange={(e) => setKind(e.target.value as typeof kind)}>
            <option value="">Images and videos</option><option value="image">Images</option><option value="video">Videos</option>
          </select>
          <select aria-label="Status" className={field} value={status} onChange={(e) => setStatus(e.target.value)}>
            <option value="">Any status</option>{Object.entries(STATUS_TEXT).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
          </select>
          <select aria-label="Location" className={field} value={gps} onChange={(e) => setGps(e.target.value as typeof gps)}>
            <option value="">With or without GPS</option><option value="yes">With a GPS fix</option><option value="no">Without a GPS fix</option>
          </select>
          <select aria-label="Your lists" className={field} value={listFilter} onChange={(e) => setListFilter(e.target.value as typeof listFilter)}>
            <option value="">Regardless of your lists</option><option value="notable">On a known / notable list</option><option value="outside">On none of your lists</option>
          </select>
        </div>
        {working && <p className="text-ink text-xs mb-2" aria-live="polite">{working}</p>}
        <HashLists onChanged={() => void load(offset)} />
        {error && <p className="text-rec mb-2">{error}</p>}
        <p className="text-ink mb-2">{total} file{total === 1 ? '' : 's'}.{total === 0 ? ' Choose “Analyse media files” to read the images and videos in the case.' : ''}</p>
        <ul className="grid gap-3" style={{ gridTemplateColumns: 'repeat(auto-fill, minmax(11rem, 1fr))' }}>
          {items.map((i) => (
            <li key={i.id}>
              <button onClick={() => setSelected(i)} className={`w-full text-left rounded-[10px] border overflow-hidden shadow-card hover:bg-hover ${selected?.id === i.id ? 'border-accent' : 'border-line'} bg-surface`}>
                <Thumb item={i} />
                <div className="p-2 text-xs">
                  <div className="text-ink truncate">{i.file_name ?? i.vfs_path}</div>
                  <div className="text-muted">{STATUS_TEXT[i.status]}</div>
                  {i.hash_set_matches.length > 0 && <div className="text-warn">On list: {i.hash_set_matches.join(', ')}</div>}
                </div>
              </button>
            </li>
          ))}
        </ul>
        <div className="flex items-center gap-2 mt-3">
          <Button disabled={offset === 0} onClick={() => { const o = Math.max(0, offset - PAGE); setOffset(o); void load(o); }}>Previous</Button>
          <Button disabled={offset + PAGE >= total} onClick={() => { const o = offset + PAGE; setOffset(o); void load(o); }}>Next</Button>
        </div>
      </div>
      {selected && <Detail item={selected} onOpen={openById} />}
    </div>
  );
};

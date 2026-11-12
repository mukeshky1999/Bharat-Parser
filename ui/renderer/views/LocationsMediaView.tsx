import React, { useEffect, useState } from 'react';
import { MapPin, Loader2, AlertTriangle } from 'lucide-react';
import { forensicClient } from '../api/forensicClient';
import { useWorkbenchStore } from '../state/workbenchStore';

type LocationRow = {
  id: number;
  Latitude: number | null;
  Longitude: number | null;
  Geo_Coordinates?: string;
  Place_Name?: string;
  Timestamp_UTC?: string;
  Timestamp_IST?: string;
  Application?: string;
  Forensic_Provenance?: string;
};

/** Location records parsed from the loaded case. Nothing is shown unless the evidence contains it. */
export const LocationsMediaView: React.FC = () => {
  const caseLoaded = useWorkbenchStore((s) => !!s.caseManifest);
  const [rows, setRows] = useState<LocationRow[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!caseLoaded) {
      setRows([]);
      return;
    }
    const ctl = new AbortController();
    (async () => {
      setLoading(true);
      setError(null);
      try {
        const res: any = await forensicClient.queryArtifacts('locations', undefined, undefined, undefined, undefined, 500, 0, undefined, false, ctl.signal);
        setRows(Array.isArray(res?.rows) ? res.rows : []);
      } catch (e: any) {
        if (e?.name !== 'AbortError') setError(e?.message || 'Could not load locations');
      } finally {
        setLoading(false);
      }
    })();
    return () => ctl.abort();
  }, [caseLoaded]);

  return (
    <div className="flex-1 flex flex-col bg-slate-950 overflow-hidden select-text">
      <div className="h-10 bg-slate-900 border-b border-slate-800 px-3 flex items-center justify-between text-xs shrink-0">
        <div className="flex items-center space-x-2">
          <MapPin className="w-4 h-4 text-teal-400" aria-hidden="true" />
          <h2 className="font-bold text-slate-100">Locations &amp; geotags</h2>
          <span className="text-[0.6875rem] text-slate-400 font-mono">({rows.length} records)</span>
        </div>
      </div>

      <div className="flex-1 overflow-auto p-4">
        {!caseLoaded ? (
          <Empty title="No case loaded" body="Ingest evidence to see location records." />
        ) : loading ? (
          <div className="flex items-center justify-center gap-2 text-slate-400 py-12" role="status">
            <Loader2 className="w-4 h-4 animate-spin" aria-hidden="true" /> Loading locations…
          </div>
        ) : error ? (
          <div className="flex items-center justify-center gap-2 text-amber-300 py-12" role="alert">
            <AlertTriangle className="w-4 h-4" aria-hidden="true" /> {error}
          </div>
        ) : rows.length === 0 ? (
          <Empty
            title="No location records"
            body="None of the processed databases contained recognised location data. This does not prove the device had no location history."
          />
        ) : (
          <table className="w-full text-left text-xs border-collapse">
            <caption className="sr-only">Location records</caption>
            <thead>
              <tr className="text-slate-400 border-b border-slate-800">
                <th scope="col" className="py-2 px-3">Time (IST)</th>
                <th scope="col" className="py-2 px-3">Latitude</th>
                <th scope="col" className="py-2 px-3">Longitude</th>
                <th scope="col" className="py-2 px-3">Place</th>
                <th scope="col" className="py-2 px-3">Source</th>
              </tr>
            </thead>
            <tbody className="font-mono text-[0.6875rem] divide-y divide-slate-800/60">
              {rows.map((r) => (
                <tr key={r.id} className="hover:bg-slate-900/60">
                  <td className="py-2 px-3 text-slate-300">{r.Timestamp_IST || r.Timestamp_UTC || 'Unknown'}</td>
                  <td className="py-2 px-3">{r.Latitude ?? '—'}</td>
                  <td className="py-2 px-3">{r.Longitude ?? '—'}</td>
                  <td className="py-2 px-3 text-slate-300">{r.Place_Name || '—'}</td>
                  <td className="py-2 px-3 text-slate-400 truncate max-w-[280px]" title={r.Forensic_Provenance}>
                    {r.Application || 'Unknown'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
};

const Empty: React.FC<{ title: string; body: string }> = ({ title, body }) => (
  <div className="text-center text-slate-400 py-16 max-w-md mx-auto">
    <p className="font-semibold text-slate-200">{title}</p>
    <p className="mt-1 text-xs leading-relaxed">{body}</p>
  </div>
);

import React from 'react';
import { RemoteAccessSession } from '../../shared/forensic-types';
import { Monitor, ArrowDownLeft, ArrowUpRight, Clock, ShieldAlert } from 'lucide-react';

interface RemoteAccessViewProps {
  sessions: RemoteAccessSession[];
  selectedSessionId?: string;
  onSelectSession: (s: RemoteAccessSession) => void;
}

export const RemoteAccessView: React.FC<RemoteAccessViewProps> = ({
  sessions,
  selectedSessionId,
  onSelectSession,
}) => {
  return (
    <div className="flex-1 flex flex-col bg-slate-950 overflow-hidden select-text">
      {/* Header */}
      <div className="h-10 bg-slate-900 border-b border-slate-800 px-3 flex items-center justify-between text-xs shrink-0 select-none">
        <div className="flex items-center space-x-2">
          <Monitor className="w-4 h-4 text-purple-400" />
          <span className="font-bold text-slate-200">
            Remote Access Tool Forensic Logs (AnyDesk / TeamViewer / RustDesk)
          </span>
        </div>
        <div className="text-[11px] text-purple-400 font-mono">
          {sessions.length} Connection Session(s) Found
        </div>
      </div>

      <div className="flex-1 overflow-auto font-mono text-xs">
        <table className="w-full text-left border-collapse">
          <thead className="bg-slate-900/90 text-slate-400 text-[10.5px] uppercase tracking-wider sticky top-0 border-b border-slate-800 z-10 select-none">
            <tr>
              <th className="py-2 px-3 w-12">#</th>
              <th className="py-2 px-3 w-32">Tool</th>
              <th className="py-2 px-3 w-40">Remote Client ID</th>
              <th className="py-2 px-3 w-32">Direction</th>
              <th className="py-2 px-3 w-48">Connected Time (IST)</th>
              <th className="py-2 px-3 w-36">Duration</th>
              <th className="py-2 px-3 w-36">Source IP</th>
              <th className="py-2 px-3 w-28">Byte Offset</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60">
            {sessions.map((s, idx) => {
              const isSelected = selectedSessionId === s.id;
              const hexOffset = `0x${s.provenance.byteOffset.toString(16).toUpperCase().padStart(8, '0')}`;

              return (
                <tr
                  key={s.id}
                  onClick={() => onSelectSession(s)}
                  className={`cursor-pointer transition-colors ${
                    isSelected
                      ? 'bg-purple-950/50 text-slate-100 font-semibold border-l-4 border-purple-500'
                      : 'hover:bg-slate-900/70 text-slate-300'
                  }`}
                >
                  <td className="py-2 px-3 text-slate-500">{idx + 1}</td>
                  <td className="py-2 px-3 text-slate-200 font-bold">{s.tool}</td>
                  <td className="py-2 px-3 text-amber-300 font-bold">{s.remoteClientId}</td>
                  <td className="py-2 px-3">
                    <span className="text-[10px] bg-rose-950 text-rose-300 border border-rose-800 px-1.5 py-0.5 rounded">
                      {s.incoming ? 'INCOMING (VICTIM CONTROLLED)' : 'OUTGOING'}
                    </span>
                  </td>
                  <td className="py-2 px-3 text-emerald-400">{s.connectedAt.istFormatted.substring(0, 19)}</td>
                  <td className="py-2 px-3 text-slate-300">{s.durationSeconds ? `${Math.floor(s.durationSeconds / 60)} min` : 'Active / Abrupt'}</td>
                  <td className="py-2 px-3 text-slate-400">{s.sourceIp || '185.220.101.45 (Tor Exit)'}</td>
                  <td className="py-2 px-3 text-amber-400">{hexOffset}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
};

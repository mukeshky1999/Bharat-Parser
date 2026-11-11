import React from 'react';
import { useWorkbenchStore } from '../state/workbenchStore';
import { CallLogArtifact } from '../../shared/forensic-types';
import { Phone, PhoneIncoming, PhoneOutgoing, PhoneMissed, Clock, ShieldCheck, Database } from 'lucide-react';

export const CallLogsView: React.FC = () => {
  const { callLogs, selectedSubcategory, setSelectedArtifact, selectedArtifact } = useWorkbenchStore();

  const filteredLogs = callLogs.filter((call) => {
    if (!selectedSubcategory || selectedSubcategory === 'ALL') return true;
    if (selectedSubcategory === 'CELLULAR') return call.callType === 'CELLULAR_CDR';
    if (selectedSubcategory === 'VOIP') return call.callType === 'VOIP_APP';
    return true;
  });

  const formatDuration = (seconds: number) => {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${String(mins).padStart(2, '0')}m ${String(secs).padStart(2, '0')}s`;
  };

  const getDirectionBadge = (dir: string) => {
    switch (dir) {
      case 'INCOMING':
        return (
          <span className="flex items-center space-x-1 text-sky-400 font-bold text-[10px]">
            <PhoneIncoming className="w-3 h-3" />
            <span>INCOMING</span>
          </span>
        );
      case 'OUTGOING':
        return (
          <span className="flex items-center space-x-1 text-emerald-400 font-bold text-[10px]">
            <PhoneOutgoing className="w-3 h-3" />
            <span>OUTGOING</span>
          </span>
        );
      case 'MISSED':
        return (
          <span className="flex items-center space-x-1 text-rose-400 font-bold text-[10px]">
            <PhoneMissed className="w-3 h-3" />
            <span>MISSED</span>
          </span>
        );
      default:
        return <span className="text-slate-400 text-[10px]">{dir}</span>;
    }
  };

  return (
    <div className="flex-1 flex flex-col bg-slate-950 overflow-hidden select-text">
      {/* Header */}
      <div className="h-10 bg-slate-900 border-b border-slate-800 px-3 flex items-center justify-between text-xs shrink-0 select-none">
        <div className="flex items-center space-x-2">
          <Phone className="w-4 h-4 text-blue-400" />
          <span className="font-bold text-slate-100">Call Detail Records (CDR) & VoIP Calls</span>
          <span className="text-[11px] text-slate-400 font-mono">({filteredLogs.length} Records)</span>
        </div>
        <div className="text-[10px] text-slate-400 font-mono">
          Strict Forensic Timestamp Normalization (IST +05:30)
        </div>
      </div>

      {/* Grid */}
      <div className="flex-1 overflow-auto">
        <table className="w-full text-left text-[11px] font-mono border-collapse">
          <thead className="bg-slate-900 border-b border-slate-800 text-slate-400 uppercase text-[9.5px] sticky top-0 z-10">
            <tr>
              <th className="p-2 w-10">#</th>
              <th className="p-2 w-28">Channel / App</th>
              <th className="p-2 w-28">Call Type</th>
              <th className="p-2 w-24">Direction</th>
              <th className="p-2 w-48">Caller (Number / ID)</th>
              <th className="p-2 w-48">Callee (Number / ID)</th>
              <th className="p-2 w-24">Duration</th>
              <th className="p-2 w-44">Timestamp (IST +05:30)</th>
              <th className="p-2 w-32">Source Table</th>
              <th className="p-2 w-24">Byte Offset</th>
              <th className="p-2 w-24">State</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60 bg-slate-950">
            {filteredLogs.map((call, idx) => {
              const isSelected = selectedArtifact?.id === call.id;
              const hexOffset = `0x${call.provenance.byteOffset.toString(16).toUpperCase().padStart(8, '0')}`;

              return (
                <tr
                  key={call.id}
                  onClick={() => {
                    setSelectedArtifact({
                      id: call.id,
                      provenance: call.provenance,
                      timestamp: call.timestamp,
                      itemType: 'CALL_LOG',
                      rawData: call
                    });
                  }}
                  className={`cursor-pointer transition-colors ${
                    isSelected
                      ? 'bg-blue-950/40 text-blue-100 border-l-2 border-blue-500'
                      : 'hover:bg-slate-900/60 text-slate-300'
                  }`}
                >
                  <td className="p-2 text-slate-500">{idx + 1}</td>
                  <td className="p-2 font-semibold">
                    <span className="px-1.5 py-0.5 rounded bg-slate-900 border border-slate-800 text-[10px]">
                      {call.sourceApp}
                    </span>
                  </td>
                  <td className="p-2 text-slate-300 text-[10px]">
                    {call.callType}
                  </td>
                  <td className="p-2">
                    {getDirectionBadge(call.direction)}
                  </td>
                  <td className="p-2 font-sans">
                    <div className="font-semibold text-slate-200">{call.callerName || 'Unknown'}</div>
                    <div className="text-[9.5px] font-mono text-slate-500">{call.callerNumberOrId}</div>
                  </td>
                  <td className="p-2 font-sans">
                    <div className="font-semibold text-slate-300">{call.calleeName || 'Target'}</div>
                    <div className="text-[9.5px] font-mono text-slate-500">{call.calleeNumberOrId}</div>
                  </td>
                  <td className="p-2 text-amber-300 font-bold">
                    {formatDuration(call.durationSeconds)}
                  </td>
                  <td className="p-2 text-slate-300 text-[10px] whitespace-nowrap">
                    {call.timestamp.istFormatted.substring(0, 19)}
                  </td>
                  <td className="p-2 text-slate-400 truncate text-[10px]">
                    {call.provenance.tableName || 'N/A'}
                  </td>
                  <td className="p-2 text-amber-400 font-bold text-[10.5px]">
                    {hexOffset}
                  </td>
                  <td className="p-2">
                    <span className="text-[9px] bg-emerald-950 text-emerald-300 border border-emerald-800/60 px-1.5 py-0.2 rounded font-mono">
                      [ACTIVE]
                    </span>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
};

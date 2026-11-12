import React from 'react';
import { useWorkbenchStore } from '../state/workbenchStore';
import { OsSpilloverArtifact } from '../../shared/forensic-types';
import { Bell, Key, Clipboard, Camera, Clock, ShieldAlert, FileText } from 'lucide-react';

export const OsSpilloverView: React.FC = () => {
  const { osSpillovers, setSelectedArtifact, selectedArtifact } = useWorkbenchStore();

  const getCategoryIcon = (category: string) => {
    switch (category) {
      case 'NOTIFICATION_LOG':
        return <Bell className="w-3.5 h-3.5 text-yellow-400" />;
      case 'KEYBOARD_CACHE':
        return <Key className="w-3.5 h-3.5 text-purple-400" />;
      case 'CLIPBOARD':
        return <Clipboard className="w-3.5 h-3.5 text-cyan-400" />;
      case 'APP_SWITCHER_SNAPSHOT':
        return <Camera className="w-3.5 h-3.5 text-rose-400" />;
      case 'TIMELINE_USAGE':
        return <Clock className="w-3.5 h-3.5 text-emerald-400" />;
      default:
        return <FileText className="w-3.5 h-3.5 text-slate-400" />;
    }
  };

  return (
    <div className="flex-1 flex flex-col bg-slate-950 overflow-hidden select-text">
      {/* Header */}
      <div className="h-10 bg-slate-900 border-b border-slate-800 px-3 flex items-center justify-between text-xs shrink-0 select-none">
        <div className="flex items-center space-x-2">
          <ShieldAlert className="w-4 h-4 text-cyan-400" />
          <span className="font-bold text-slate-100">OS-Level Privacy Spillover & Ephemeral Recovery</span>
          <span className="text-[0.6875rem] text-slate-400 font-mono">({osSpillovers.length} Artifacts)</span>
        </div>
        <div className="text-[0.6875rem] text-slate-400 font-mono">
          Notification Logs • Gboard Dictionaries • App Switcher CE Snapshots • UsageStats
        </div>
      </div>

      {/* Grid */}
      <div className="flex-1 overflow-auto">
        <table className="w-full text-left text-[0.6875rem] font-mono border-collapse">
          <thead className="bg-slate-900 border-b border-slate-800 text-slate-400 uppercase text-[0.6875rem] sticky top-0 z-10">
            <tr>
              <th className="p-2 w-10">#</th>
              <th className="p-2 w-48">Spillover Vector</th>
              <th className="p-2 w-48">Target Package / App</th>
              <th className="p-2">Extracted Forensic Value / Snippet</th>
              <th className="p-2 w-64">High-Value Target Indicator</th>
              <th className="p-2 w-44">Timestamp (IST +05:30)</th>
              <th className="p-2 w-24">Byte Offset</th>
              <th className="p-2 w-28">Recovery State</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60 bg-slate-950">
            {osSpillovers.map((spill, idx) => {
              const isSelected = selectedArtifact?.id === spill.id;
              const hexOffset = `0x${spill.provenance.byteOffset.toString(16).toUpperCase().padStart(8, '0')}`;

              return (
                <tr
                  key={spill.id}
                  onClick={() => {
                    setSelectedArtifact({
                      id: spill.id,
                      provenance: spill.provenance,
                      timestamp: spill.timestamp,
                      itemType: 'OS_SPILLOVER',
                      rawData: spill
                    });
                  }}
                  className={`cursor-pointer transition-colors ${
                    isSelected
                      ? 'bg-cyan-950/40 text-cyan-100 border-l-2 border-cyan-500'
                      : 'hover:bg-slate-900/60 text-slate-300'
                  }`}
                >
                  <td className="p-2 text-slate-500">{idx + 1}</td>
                  <td className="p-2">
                    <div className="flex items-center space-x-1.5 font-bold text-slate-200">
                      {getCategoryIcon(spill.category)}
                      <span className="text-[0.6875rem]">{spill.category}</span>
                    </div>
                  </td>
                  <td className="p-2 font-mono text-[0.6875rem] text-slate-400 truncate max-w-[180px]" title={spill.sourceApp}>
                    {spill.sourceApp || 'System'}
                  </td>
                  <td className="p-2 font-sans text-xs text-slate-200 leading-snug">
                    <div className="font-semibold text-slate-100">{spill.title}</div>
                    <div className="text-[0.6875rem] text-slate-400 mt-0.5">{spill.snippet}</div>
                  </td>
                  <td className="p-2">
                    {spill.targetData && (
                      <span className="px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800/60 font-mono text-[0.6875rem] font-bold inline-block">
                        {spill.targetData}
                      </span>
                    )}
                  </td>
                  <td className="p-2 text-slate-300 text-[0.6875rem] whitespace-nowrap">
                    {spill.timestamp.istFormatted.substring(0, 19)}
                  </td>
                  <td className="p-2 text-amber-400 font-bold text-[0.6875rem]">
                    {hexOffset}
                  </td>
                  <td className="p-2">
                    <span className="text-[0.6875rem] bg-purple-950 text-purple-300 border border-purple-800/60 px-1.5 py-0.2 rounded font-mono font-bold">
                      [OS SPILLOVER]
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

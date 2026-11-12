import React from 'react';
import { useWorkbenchStore } from '../state/workbenchStore';
import { ContactArtifact } from '../../shared/forensic-types';
import { Users, Heart, CreditCard, Smartphone, ShieldCheck, MapPin } from 'lucide-react';

export const ContactsView: React.FC = () => {
  const { contacts, selectedSubcategory, setSelectedArtifact, selectedArtifact } = useWorkbenchStore();

  const filteredContacts = contacts.filter((cnt) => {
    if (!selectedSubcategory || selectedSubcategory === 'ALL') return true;
    if (selectedSubcategory === 'DEVICE') return cnt.sourceApp === 'Device' || cnt.sourceApp === 'WhatsApp';
    if (selectedSubcategory === 'DATING') return ['Tinder', 'Bumble', 'Hinge', 'Grindr'].includes(cnt.sourceApp);
    if (selectedSubcategory === 'UPI') return cnt.sourceApp === 'UPI';
    return true;
  });

  return (
    <div className="flex-1 flex flex-col bg-slate-950 overflow-hidden select-text">
      {/* Header */}
      <div className="h-10 bg-slate-900 border-b border-slate-800 px-3 flex items-center justify-between text-xs shrink-0 select-none">
        <div className="flex items-center space-x-2">
          <Users className="w-4 h-4 text-slate-300" />
          <span className="font-semibold text-slate-100">Contacts, Social Profiles & Dating Matches</span>
          <span className="text-[0.75rem] text-slate-400 font-mono">({filteredContacts.length} Entities)</span>
        </div>
        <div className="text-[0.75rem] text-slate-400 font-mono">
          Corroborated Against Device SQLite & Cloud Cache
        </div>
      </div>

      {/* Grid */}
      <div className="flex-1 overflow-auto">
        <table className="w-full text-left text-[0.75rem] font-mono border-collapse">
          <thead className="bg-slate-900 border-b border-slate-800 text-slate-400 text-[0.75rem] sticky top-0 z-10">
            <tr>
              <th className="p-2 w-10">#</th>
              <th className="p-2 w-28">Source App</th>
              <th className="p-2 w-52">Identifier / Account Handle</th>
              <th className="p-2 w-52">Display Name / Profile</th>
              <th className="p-2">Status / Bio / Target Profile Notes</th>
              <th className="p-2 w-48">Dating / Geolocation Attributes</th>
              <th className="p-2 w-32">Source Table</th>
              <th className="p-2 w-24">Byte Offset</th>
              <th className="p-2 w-24">State</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60 bg-slate-950">
            {filteredContacts.map((cnt, idx) => {
              const isSelected = selectedArtifact?.id === cnt.id;
              const hexOffset = `0x${cnt.provenance.byteOffset.toString(16).toUpperCase().padStart(8, '0')}`;

              return (
                <tr
                  key={cnt.id}
                  onClick={() => {
                    setSelectedArtifact({
                      id: cnt.id,
                      provenance: cnt.provenance,
                      timestamp: cnt.lastActive,
                      itemType: 'CONTACT',
                      rawData: cnt
                    });
                  }}
                  className={`cursor-pointer transition-colors ${
                    isSelected
                      ? 'bg-slate-800 text-slate-300 border-l-2 border-cyan-500'
                      : 'hover:bg-slate-900/60 text-slate-300'
                  }`}
                >
                  <td className="p-2 text-slate-500">{idx + 1}</td>
                  <td className="p-2 font-semibold">
                    <span className="px-1.5 py-0.5 rounded bg-slate-900 border border-slate-800 text-[0.75rem]">
                      {cnt.sourceApp}
                    </span>
                  </td>
                  <td className="p-2 font-mono text-cyan-300 font-semibold truncate max-w-[200px]" title={cnt.identifier}>
                    {cnt.identifier}
                  </td>
                  <td className="p-2 font-sans font-semibold text-slate-200">
                    {cnt.displayName}
                  </td>
                  <td className="p-2 font-sans text-xs text-slate-300">
                    {cnt.bioOrStatus || '—'}
                  </td>
                  <td className="p-2">
                    {cnt.datingMetadata ? (
                      <div className="text-[0.75rem] space-y-0.5 font-sans">
                        <div className="text-slate-300 font-semibold flex items-center space-x-1">
                          <Heart className="w-3 h-3 text-slate-300" />
                          <span>Age: {cnt.datingMetadata.age} | {cnt.datingMetadata.gender}</span>
                        </div>
                        <div className="text-slate-400 flex items-center space-x-1">
                          <MapPin className="w-2.5 h-2.5 text-slate-300" />
                          <span>{cnt.datingMetadata.location} ({cnt.datingMetadata.distanceKm} km)</span>
                        </div>
                      </div>
                    ) : (
                      <span className="text-slate-600 font-mono text-[0.75rem]">—</span>
                    )}
                  </td>
                  <td className="p-2 text-slate-400 truncate text-[0.75rem]">
                    {cnt.provenance.tableName || 'N/A'}
                  </td>
                  <td className="p-2 text-amber-400 font-semibold text-[0.75rem]">
                    {hexOffset}
                  </td>
                  <td className="p-2">
                    <span className="text-[0.75rem] bg-emerald-950 text-emerald-300 border border-emerald-800/60 px-1.5 py-0.5 rounded font-mono">
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

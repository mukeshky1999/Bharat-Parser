import React from 'react';
import { useWorkbenchStore } from '../state/workbenchStore';
import { ContactArtifact } from '../../shared/forensic-types';
import { Heart, MapPin } from 'lucide-react';
import { ViewHeader, Card, Chip } from '../components/ui';

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
    <div className="flex-1 flex flex-col bg-page overflow-hidden select-text p-4 min-h-0">
      <ViewHeader title="Contacts, social profiles and dating matches" count={filteredContacts.length}
        actions={<span className="text-[0.75rem] text-muted">Corroborated against device SQLite and cloud cache</span>} />

      <Card className="flex-1 min-h-0 overflow-hidden flex flex-col" bodyClassName="flex-1 min-h-0 overflow-auto">
        <table className="w-full text-left text-[0.75rem] border-collapse">
          <thead className="bg-sunken border-b border-line text-muted text-[0.6875rem] sticky top-0 z-10">
            <tr>
              <th className="p-2 w-10">#</th>
              <th className="p-2 w-28">Source app</th>
              <th className="p-2 w-52">Identifier or account handle</th>
              <th className="p-2 w-52">Display name or profile</th>
              <th className="p-2">Status, bio or profile notes</th>
              <th className="p-2 w-48">Dating and location attributes</th>
              <th className="p-2 w-32">Source table</th>
              <th className="p-2 w-24">Byte offset</th>
              <th className="p-2 w-24">State</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-line bg-surface">
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
                  className={`cursor-pointer ${
                    isSelected
                      ? 'bg-accent-soft text-ink border-l-2 border-accent'
                      : 'hover:bg-hover text-ink'
                  }`}
                >
                  <td className="p-2 text-faint">{idx + 1}</td>
                  <td className="p-2 font-semibold">
                    <Chip tone="neutral">{cnt.sourceApp}</Chip>
                  </td>
                  <td className="p-2 font-mono text-accent-ink font-semibold truncate max-w-[200px]" title={cnt.identifier}>
                    {cnt.identifier}
                  </td>
                  <td className="p-2 font-semibold text-ink">
                    {cnt.displayName}
                  </td>
                  <td className="p-2 text-ink">
                    {cnt.bioOrStatus || '—'}
                  </td>
                  <td className="p-2">
                    {cnt.datingMetadata ? (
                      <div className="text-[0.75rem] space-y-0.5">
                        <div className="text-ink font-semibold flex items-center space-x-1">
                          <Heart className="w-3 h-3 text-muted" />
                          <span>Age: {cnt.datingMetadata.age} | {cnt.datingMetadata.gender}</span>
                        </div>
                        <div className="text-muted flex items-center space-x-1">
                          <MapPin className="w-3 h-3 text-g-places" />
                          <span>{cnt.datingMetadata.location} ({cnt.datingMetadata.distanceKm} km)</span>
                        </div>
                      </div>
                    ) : (
                      <span className="text-faint text-[0.75rem]">—</span>
                    )}
                  </td>
                  <td className="p-2 text-muted truncate text-[0.75rem]">
                    {cnt.provenance.tableName || 'N/A'}
                  </td>
                  <td className="p-2 text-muted font-mono text-[0.75rem]">
                    {hexOffset}
                  </td>
                  <td className="p-2">
                    <Chip tone="ok">[ACTIVE]</Chip>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </Card>
    </div>
  );
};

import React from 'react';
import { useWorkbenchStore } from '../state/workbenchStore';
import { MapPin, Image as ImageIcon, Volume2, FileText, ExternalLink, Calendar, HardDrive } from 'lucide-react';

export const LocationsMediaView: React.FC = () => {
  const { setSelectedArtifact, selectedArtifact } = useWorkbenchStore();

  const mockMedia = [
    {
      id: 'MEDIA_GEO_01',
      title: 'DSC_20261014_142100.JPG (Suspect Cashout Handover Point)',
      type: 'EXIF_IMAGE',
      filePath: '/data/media/0/DCIM/Camera/DSC_20261014_142100.JPG',
      lat: 12.9784,
      lon: 77.6408,
      locationName: 'Indiranagar 100 Feet Road, Bengaluru',
      cameraModel: 'Xiaomi Redmi Note 12 5G (Sunstone)',
      captureTime: '2026-10-14 14:21:00 IST',
      byteOffset: 0x0041a000,
      sizeBytes: 3418200
    },
    {
      id: 'MEDIA_AUDIO_01',
      title: 'PTT-20261014-WA0012.opus (WhatsApp Voice Note: Mule PIN Instruction)',
      type: 'VOICE_NOTE',
      filePath: '/data/media/0/Android/media/com.whatsapp/WhatsApp/Media/WhatsApp Voice Notes/PTT-20261014-WA0012.opus',
      duration: '00:42',
      captureTime: '2026-10-14 14:23:45 IST',
      byteOffset: 0x0078b200,
      sizeBytes: 142800
    },
    {
      id: 'MEDIA_SNAP_01',
      title: '10492_snap.jpg (App Switcher Task Snapshot)',
      type: 'SNAPSHOT_IMAGE',
      filePath: '/data/system_ce/0/snapshots/10492_snap.jpg',
      captureTime: '2026-10-14 14:22:05 IST',
      byteOffset: 0x0001f400,
      sizeBytes: 184200
    },
    {
      id: 'MEDIA_PDF_01',
      title: 'Bank_Statement_Oct2026_MuleLayer1.pdf',
      type: 'DOCUMENT',
      filePath: '/data/media/0/Download/Bank_Statement_Oct2026_MuleLayer1.pdf',
      captureTime: '2026-10-14 14:30:12 IST',
      byteOffset: 0x0091c000,
      sizeBytes: 524100
    }
  ];

  return (
    <div className="flex-1 flex flex-col bg-slate-950 overflow-hidden select-text">
      {/* Header */}
      <div className="h-10 bg-slate-900 border-b border-slate-800 px-3 flex items-center justify-between text-xs shrink-0 select-none">
        <div className="flex items-center space-x-2">
          <MapPin className="w-4 h-4 text-teal-400" />
          <span className="font-bold text-slate-100">Locations, EXIF Geotags & Media Gallery</span>
          <span className="text-[11px] text-slate-400 font-mono">({mockMedia.length} Media Artifacts)</span>
        </div>
        <div className="text-[10px] text-slate-400 font-mono">
          Strict GPS Parsing & Physical Offset Binding
        </div>
      </div>

      {/* Grid */}
      <div className="flex-1 overflow-auto p-4 grid grid-cols-2 gap-4">
        {mockMedia.map((item) => {
          const isSelected = selectedArtifact?.id === item.id;
          const hexOffset = `0x${item.byteOffset.toString(16).toUpperCase().padStart(8, '0')}`;

          return (
            <div
              key={item.id}
              onClick={() => {
                setSelectedArtifact({
                  id: item.id,
                  provenance: {
                    evidenceId: 'REF_EVIDENCE_DUMP_01',
                    archivePath: '/evidence/case_evidence.tar',
                    vfsInternalPath: item.filePath,
                    containerType: 'RAW_CARVED',
                    tableName: item.type,
                    byteOffset: item.byteOffset,
                    byteLength: item.sizeBytes,
                    recoveryState: 'ACTIVE',
                    rawPayloadHex: 'FFD8FFE000104A46494600010101006000600000'
                  },
                  notes: item.title,
                  itemType: item.type,
                  rawData: item
                });
              }}
              className={`rounded-xl border p-4 bg-slate-900/80 cursor-pointer transition-all ${
                isSelected
                  ? 'border-teal-400 ring-2 ring-teal-500/40 bg-teal-950/20'
                  : 'border-slate-800 hover:border-slate-700'
              }`}
            >
              <div className="flex items-center justify-between mb-2 pb-2 border-b border-slate-800">
                <div className="flex items-center space-x-2">
                  {item.type.includes('IMAGE') ? (
                    <ImageIcon className="w-4 h-4 text-teal-400" />
                  ) : item.type.includes('AUDIO') ? (
                    <Volume2 className="w-4 h-4 text-amber-400" />
                  ) : (
                    <FileText className="w-4 h-4 text-blue-400" />
                  )}
                  <span className="text-xs font-bold text-slate-200 truncate max-w-[280px]">
                    {item.title}
                  </span>
                </div>
                <span className="text-[10px] bg-slate-800 text-slate-400 px-2 py-0.5 rounded font-mono">
                  {item.type}
                </span>
              </div>

              {item.lat && (
                <div className="mb-2 bg-slate-950/80 border border-teal-500/30 rounded-lg p-2.5 text-xs">
                  <div className="text-teal-300 font-semibold flex items-center space-x-1.5">
                    <MapPin className="w-3.5 h-3.5 text-teal-400" />
                    <span>{item.locationName}</span>
                  </div>
                  <div className="text-[10.5px] font-mono text-slate-400 mt-1">
                    Latitude: {item.lat.toFixed(6)} | Longitude: {item.lon?.toFixed(6)}
                  </div>
                  <div className="text-[10px] text-slate-500 mt-0.5">
                    Camera: {item.cameraModel}
                  </div>
                </div>
              )}

              {item.duration && (
                <div className="mb-2 bg-slate-950/80 border border-amber-500/30 rounded-lg p-2.5 text-xs flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    <Volume2 className="w-4 h-4 text-amber-400" />
                    <div>
                      <span className="text-amber-300 font-semibold">Opus Voice Note Payload</span>
                      <div className="text-[10px] text-slate-400">Duration: {item.duration}</div>
                    </div>
                  </div>
                  <div className="h-6 w-24 bg-amber-950/50 rounded flex items-center justify-center border border-amber-800/40">
                    <span className="text-[9px] font-mono text-amber-300">WAVEFORM</span>
                  </div>
                </div>
              )}

              <div className="mt-2 text-[10px] font-mono text-slate-400 space-y-1">
                <div className="flex items-center justify-between">
                  <span>Timestamp:</span>
                  <span className="text-slate-300">{item.captureTime}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span>Physical Byte Offset:</span>
                  <span className="text-amber-400 font-bold">{hexOffset}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span>Payload Size:</span>
                  <span className="text-slate-300">{(item.sizeBytes / 1024).toFixed(1)} KB</span>
                </div>
                <div className="truncate text-slate-500 pt-1 border-t border-slate-800">
                  {item.filePath}
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};

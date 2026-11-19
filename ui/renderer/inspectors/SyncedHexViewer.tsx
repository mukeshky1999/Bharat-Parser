import React, { useEffect, useRef, useState, useCallback } from 'react';
import {
  Binary,
  Maximize2,
  Minimize2,
  Navigation,
  Layers,
  Code2,
  ChevronDown,
  ChevronRight,
  Copy,
  Check,
  ChevronUp
} from 'lucide-react';
import { useWorkbenchStore } from '../state/workbenchStore';
import { ForensicProvenance } from '../../shared/forensic-types';
import { DataInterpreter, ByteSelection } from './DataInterpreter';

interface SyncedHexViewerProps {
  provenance?: ForensicProvenance | null;
  /** true when shown inside the evidence card instead of as a bottom dock */
  embedded?: boolean;
}

const ROW_HEIGHT = 22;
const OVERSCAN = 6;

export const SyncedHexViewer: React.FC<SyncedHexViewerProps> = (props) => {
  const storeArtifact = useWorkbenchStore((state) => state.selectedArtifact);
  const hexWindow = useWorkbenchStore((state) => state.hexWindow);
  const isLoadingHex = useWorkbenchStore((state) => state.isLoadingHex);
  const hexError = useWorkbenchStore((state) => state.hexError);
  const bottomDockTab = useWorkbenchStore((state) => state.bottomDockTab);
  const setBottomDockTab = useWorkbenchStore((state) => state.setBottomDockTab);

  const [dockState, setDockState] = useState<'NORMAL' | 'COLLAPSED' | 'EXPANDED'>('NORMAL');
  const [copiedRaw, setCopiedRaw] = useState(false);
  const [scrollTop, setScrollTop] = useState(0);
  const [viewportHeight, setViewportHeight] = useState(200);

  const containerRef = useRef<HTMLDivElement | null>(null);
  const [selection, setSelection] = useState<ByteSelection | null>(null);
  // the bytes of the loaded window as numbers, so they can be read as values
  const flat = React.useMemo(() => {
    const list: number[] = [];
    for (const r of hexWindow?.rows || []) for (const b of r.bytes) list.push(parseInt(b.hex, 16) || 0);
    return Uint8Array.from(list);
  }, [hexWindow]);
  const windowStart = hexWindow?.startOffset ?? 0;
  React.useEffect(() => { setSelection(null); }, [hexWindow]);
  const inSelection = (idx: number) => !!selection && idx >= selection.start && idx < selection.start + selection.len;
  const jumpTo = (fileOffset: number): string | null => {
    const idx = fileOffset - windowStart;
    if (idx < 0 || idx >= flat.length) return `Offset ${fileOffset} is outside the loaded bytes (${windowStart} to ${windowStart + flat.length - 1}).`;
    setSelection({ start: idx, len: 1 });
    if (containerRef.current) containerRef.current.scrollTop = Math.max(0, Math.floor(idx / 16) * ROW_HEIGHT - 40);
    return null;
  };

  const prov = props.provenance || storeArtifact?.provenance;
  const targetOffset = prov && prov.byteOffset >= 0 ? prov.byteOffset : 0;
  const targetLength = prov && prov.byteOffset >= 0 ? prov.byteLength : 0;
  const offsetRecorded = !!prov && prov.byteOffset >= 0;

  const rows = hexWindow?.rows || [];

  // Update container viewport height on resize or dock toggle
  useEffect(() => {
    if (containerRef.current) {
      setViewportHeight(containerRef.current.clientHeight || 200);
    }
  }, [dockState, bottomDockTab]);

  // Mathematical virtual scroll to highlighted target byte offset
  const scrollToHighlighted = useCallback(() => {
    if (!containerRef.current || rows.length === 0) return;
    const targetIdx = rows.findIndex((r) => r.bytes.some((b) => b.isHighlighted));
    if (targetIdx >= 0) {
      const targetScroll = Math.max(0, targetIdx * ROW_HEIGHT - viewportHeight / 2 + ROW_HEIGHT / 2);
      containerRef.current.scrollTo({ top: targetScroll, behavior: 'smooth' });
    }
  }, [rows, viewportHeight]);

  // Auto-scroll on offset change or tab activation
  useEffect(() => {
    if (containerRef.current && bottomDockTab === 'HEX') {
      scrollToHighlighted();
    }
  }, [targetOffset, hexWindow, bottomDockTab, scrollToHighlighted]);

  const handleScroll = (e: React.UIEvent<HTMLDivElement>) => {
    setScrollTop(e.currentTarget.scrollTop);
  };

  const handleCopyRaw = () => {
    const rawContent = JSON.stringify(storeArtifact?.rawData || storeArtifact || {}, null, 2);
    navigator.clipboard.writeText(rawContent);
    setCopiedRaw(true);
    setTimeout(() => setCopiedRaw(false), 2000);
  };

  const getDockHeightClass = () => {
    if (dockState === 'COLLAPSED') return 'h-8';
    if (dockState === 'EXPANDED') return 'h-[340px]';
    return 'h-[210px]';
  };

  // Virtual windowing calculations
  const totalRows = rows.length;
  const totalHeight = totalRows * ROW_HEIGHT;
  const startIndex = Math.max(0, Math.floor(scrollTop / ROW_HEIGHT) - OVERSCAN);
  const endIndex = Math.min(totalRows, Math.ceil((scrollTop + viewportHeight) / ROW_HEIGHT) + OVERSCAN);
  const visibleRows = rows.slice(startIndex, endIndex);
  const offsetY = startIndex * ROW_HEIGHT;

  return (
    <footer
      className={props.embedded
        ? 'bg-sunken flex flex-col h-full min-h-[260px] select-text'
        : `bg-sunken border-t border-line flex flex-col shrink-0 select-text transition-all duration-200 ${getDockHeightClass()}`}
    >
      {/* Hex Toolbar with Dual Tabs */}
      <div className={`${props.embedded ? 'min-h-8 flex-wrap gap-y-1 py-1' : 'h-8'} bg-sunken border-b border-line px-3 flex items-center justify-between text-xs select-none`}>
        <div className="flex items-center space-x-3">
          {/* Tab Switcher */}
          <div className="flex items-center space-x-1 font-mono text-[0.6875rem]">
            <button
              onClick={() => {
                if (dockState === 'COLLAPSED') setDockState('NORMAL');
                setBottomDockTab('HEX');
              }}
              className={`flex items-center space-x-1 px-2.5 py-0.5 rounded transition-colors ${
                bottomDockTab === 'HEX' && dockState !== 'COLLAPSED'
                  ? 'bg-accent-soft text-accent-ink font-bold border border-accent'
                  : 'text-muted hover:text-ink'
              }`}
            >
              <Binary className="w-3.5 h-3.5 text-accent-ink" />
              <span>16-Byte Physical Hex Stream</span>
            </button>
            <button
              onClick={() => {
                if (dockState === 'COLLAPSED') setDockState('NORMAL');
                setBottomDockTab('DECODED_TREE');
              }}
              className={`flex items-center space-x-1 px-2.5 py-0.5 rounded transition-colors ${
                bottomDockTab === 'DECODED_TREE' && dockState !== 'COLLAPSED'
                  ? 'bg-accent-soft text-accent-ink font-bold border border-accent'
                  : 'text-muted hover:text-ink'
              }`}
            >
              <Code2 className="w-3.5 h-3.5 text-accent-ink" />
              <span>Decoded JSON / Protobuf Structure</span>
            </button>
          </div>

          <span className="text-[0.6875rem] text-faint font-mono">
            @ 0x{targetOffset.toString(16).toUpperCase()}
          </span>
          {isLoadingHex && (
            <span className="text-[0.6875rem] text-ok font-mono font-semibold">
              [STREAMING 4KB MMAP CHUNK...]
            </span>
          )}
          {hexWindow?.fileSize ? (
            <span className="text-[0.6875rem] text-faint font-mono hidden lg:inline">
              [FILE: {hexWindow.fileSize.toLocaleString()} B]
            </span>
          ) : null}
          {hexWindow?.isEof && (
            <span className="text-[0.6875rem] text-warn font-mono font-semibold">
              [EOF REACHED]
            </span>
          )}
        </div>

        <div className="flex items-center space-x-4 text-[0.6875rem] font-mono">
          <div className="flex items-center space-x-1 hidden sm:flex">
            <span className="text-faint">Physical Offset:</span>
            <span className="text-warn font-bold">
              {offsetRecorded ? `0x${targetOffset.toString(16).toUpperCase().padStart(8, '0')}` : 'not recorded'}
            </span>
          </div>

          <div className="flex items-center space-x-1 hidden md:flex">
            <span className="text-faint">Target Span:</span>
            <span className="text-ok font-bold">{targetLength} bytes</span>
          </div>

          {bottomDockTab === 'HEX' ? (
            <button
              onClick={scrollToHighlighted}
              className="text-muted hover:text-ink flex items-center space-x-0.5 transition-colors cursor-pointer"
              title="Auto-Scroll to Highlighted Byte Offset"
            >
              <Navigation className="w-3 h-3 text-accent-ink" />
              <span>Auto-Scroll</span>
            </button>
          ) : (
            <button
              onClick={handleCopyRaw}
              className="text-accent-ink hover:underline flex items-center space-x-0.5 font-mono cursor-pointer"
            >
              {copiedRaw ? <Check className="w-3 h-3 text-ok" /> : <Copy className="w-3 h-3" />}
              <span>{copiedRaw ? 'Copied' : 'Copy Payload'}</span>
            </button>
          )}

          {/* Expand / Collapse Controls */}
          <div className="flex items-center space-x-1 border-l border-line pl-2">
            <button
              onClick={() => setDockState(dockState === 'COLLAPSED' ? 'NORMAL' : 'COLLAPSED')}
              className="text-muted hover:text-ink p-0.5 rounded cursor-pointer"
              title={dockState === 'COLLAPSED' ? 'Expand Dock' : 'Collapse Dock'}
            >
              {dockState === 'COLLAPSED' ? (
                <ChevronUp className="w-3.5 h-3.5" />
              ) : (
                <ChevronDown className="w-3.5 h-3.5" />
              )}
            </button>
            <button
              onClick={() => setDockState(dockState === 'EXPANDED' ? 'NORMAL' : 'EXPANDED')}
              className="text-muted hover:text-ink p-0.5 rounded cursor-pointer"
              title={dockState === 'EXPANDED' ? 'Standard Height (210px)' : 'Maximize (340px)'}
            >
              {dockState === 'EXPANDED' ? (
                <Minimize2 className="w-3.5 h-3.5" />
              ) : (
                <Maximize2 className="w-3.5 h-3.5" />
              )}
            </button>
          </div>
        </div>
      </div>

      {/* Main Content Area (Hidden if Collapsed) */}
      {dockState !== 'COLLAPSED' && (
        <div className="flex-1 overflow-hidden flex flex-col">
          {bottomDockTab === 'HEX' ? (
            /* Virtualized 16-Byte Hex + ASCII Stream Grid, with the data interpreter under it */
            <>
            <div
              ref={containerRef}
              onScroll={handleScroll}
              className="flex-1 overflow-auto p-2 font-mono text-[0.6875rem] leading-snug select-text scroll-smooth bg-sunken"
            >
              {rows.length > 0 ? (
                <div style={{ height: totalHeight, position: 'relative' }} className="min-w-full">
                  <div style={{ transform: `translateY(${offsetY}px)`, willChange: 'transform' }}>
                    {visibleRows.map((row, relativeIdx) => {
                      const actualRowIndex = startIndex + relativeIdx;
                      const hasHighlightedByte = row.bytes.some((b) => b.isHighlighted);

                      return (
                        <div
                          key={row.addressHex || actualRowIndex}
                          style={{ height: `${ROW_HEIGHT}px` }}
                          className={`flex items-center space-x-4 px-1.5 rounded transition-colors ${
                            hasHighlightedByte
                              ? 'bg-warn-soft border-l-2 border-warn'
                              : 'hover:bg-hover/60'
                          }`}
                        >
                          {/* 1. Address Column */}
                          <div
                            className={`select-none w-20 shrink-0 font-semibold ${
                              hasHighlightedByte ? 'text-warn font-bold' : 'text-faint'
                            }`}
                          >
                            {row.addressHex}:
                          </div>

                          {/* 2. 16 Hex Bytes (Split into two 8-byte columns) */}
                          <div className="flex items-center space-x-2 shrink-0">
                            <div className="flex items-center space-x-1">
                              {row.bytes.slice(0, 8).map((b, i) => (
                                <span
                                  key={i}
                                  onClick={() => setSelection({ start: actualRowIndex * 16 + i, len: 1 })}
                                  className={`inline-block w-5 text-center transition-all cursor-pointer ${
                                    inSelection(actualRowIndex * 16 + i)
                                      ? 'bg-accent-soft text-accent-ink font-bold rounded-sm'
                                      : b.isHighlighted
                                      ? 'bg-warn text-on-accent font-bold rounded-sm'
                                      : 'text-ink'
                                  }`}
                                >
                                  {b.hex}
                                </span>
                              ))}
                            </div>
                            <span className="text-faint select-none">|</span>
                            <div className="flex items-center space-x-1">
                              {row.bytes.slice(8, 16).map((b, i) => (
                                <span
                                  key={i + 8}
                                  onClick={() => setSelection({ start: actualRowIndex * 16 + i + 8, len: 1 })}
                                  className={`inline-block w-5 text-center transition-all cursor-pointer ${
                                    inSelection(actualRowIndex * 16 + i + 8)
                                      ? 'bg-accent-soft text-accent-ink font-bold rounded-sm'
                                      : b.isHighlighted
                                      ? 'bg-warn text-on-accent font-bold rounded-sm'
                                      : 'text-ink'
                                  }`}
                                >
                                  {b.hex}
                                </span>
                              ))}
                            </div>
                          </div>

                          {/* 3. ASCII Dump Column */}
                          <div className="flex items-center space-x-0.5 pl-3 border-l border-line text-muted shrink-0 select-text">
                            {row.ascii.map((a, i) => (
                              <span
                                key={i}
                                className={`inline-block w-2.5 text-center ${
                                  inSelection(actualRowIndex * 16 + i) ? 'bg-accent-soft text-accent-ink rounded-sm' : a.isHighlighted ? 'bg-warn-soft text-warn font-bold rounded-sm' : ''
                                }`}
                              >
                                {a.char}
                              </span>
                            ))}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              ) : (
                <div role="status" aria-live="polite" className="p-6 text-center font-mono text-xs">
                  {isLoadingHex ? (
                    <span className="text-muted">Reading bytes from evidence file…</span>
                  ) : hexError ? (
                    <span className="text-warn">{hexError}</span>
                  ) : (
                    <span className="text-faint">Select a record to view the bytes it was read from.</span>
                  )}
                </div>
              )}
            </div>
            {rows.length > 0 && <DataInterpreter bytes={flat} windowStart={windowStart} selection={selection} onSelect={setSelection} onJump={jumpTo} />}
            </>
          ) : (
            /* Raw Decoded JSON / Protobuf Tree Tab */
            <div className="flex-1 overflow-y-auto p-3 font-mono text-xs select-text bg-sunken">
              <div className="bg-sunken rounded-lg border border-line p-3 leading-relaxed">
                <div className="text-[0.6875rem] text-accent-ink font-bold mb-2 uppercase tracking-wide flex items-center space-x-2">
                  <Code2 className="w-3.5 h-3.5" />
                  <span>Decoded Artifact Tree & Wire Payload Structure</span>
                </div>
                <pre className="text-ok text-[0.6875rem] font-mono overflow-x-auto whitespace-pre-wrap">
                  {JSON.stringify(
                    storeArtifact?.rawData || {
                      artifact_id: storeArtifact?.id || 'NO_SELECTION',
                      provenance: storeArtifact?.provenance,
                      timestamp: storeArtifact?.timestamp,
                      notes: storeArtifact?.notes,
                      message: 'Select any record in the workbench grid or chat bubbles to view its decoded tree.'
                    },
                    null,
                    2
                  )}
                </pre>
              </div>
            </div>
          )}
        </div>
      )}
    </footer>
  );
};

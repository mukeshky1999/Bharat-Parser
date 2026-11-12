import React, { useMemo, useState } from 'react';
import { interpret, parseOffset } from '../utils/byteInterpreter';

export interface ByteSelection { start: number; len: number }

/**
 * Readings of the bytes you clicked in the hex view. Each reading says what the bytes would be IF read that way; it
 * does not say they are that. Choose a reading to mark exactly the bytes it uses in the grid, or type a file offset
 * to jump to it.
 */
export const DataInterpreter: React.FC<{
  bytes: Uint8Array;
  windowStart: number;
  selection: ByteSelection | null;
  onSelect: (s: ByteSelection | null) => void;
  onJump: (fileOffset: number) => string | null;
}> = ({ bytes, windowStart, selection, onSelect, onJump }) => {
  const [jump, setJump] = useState('');
  const [jumpMsg, setJumpMsg] = useState('');
  const readings = useMemo(
    () => (selection ? interpret(bytes.subarray(selection.start, selection.start + 16)) : []),
    [bytes, selection],
  );

  const go = (e: React.FormEvent) => {
    e.preventDefault();
    const off = parseOffset(jump);
    if (off === null) { setJumpMsg('Not an offset. Use decimal or hex (0x1f4).'); return; }
    setJumpMsg(onJump(off) ?? '');
  };

  return (
    <div className="shrink-0 max-h-56 overflow-y-auto border-t border-slate-800 bg-slate-900 p-2 text-[0.75rem] text-slate-200" aria-label="Data interpreter">
      <form onSubmit={go} className="flex items-center gap-2 mb-2">
        <label className="text-slate-400">Go to file offset
          <input value={jump} onChange={(e) => setJump(e.target.value)} placeholder="0x1f4 or 500" aria-label="File offset"
            className="ml-2 h-7 w-32 rounded bg-slate-950 border border-slate-700 px-2 font-mono text-slate-100 placeholder-slate-500" />
        </label>
        <button type="submit" className="h-7 px-2 rounded border border-slate-700 hover:bg-slate-800">Go</button>
        {jumpMsg && <span className="text-amber-300">{jumpMsg}</span>}
      </form>
      {!selection ? (
        <p className="text-slate-400">Click a byte to see what it and the bytes after it would be if read as numbers, text or a time.</p>
      ) : (
        <>
          <p className="mb-1 text-slate-300">
            From file offset <span className="font-mono">0x{(windowStart + selection.start).toString(16)}</span> ({windowStart + selection.start}),
            {' '}{selection.len} byte{selection.len === 1 ? '' : 's'} marked. These are readings, not findings: any bytes can look like a number or a date.
            {' '}<button className="underline text-cyan-300" onClick={() => onSelect(null)}>Clear</button>
          </p>
          <table className="w-full border-collapse">
            <tbody>
              {readings.map((r) => (
                <tr key={r.label} className="border-t border-slate-800">
                  <td className="py-0.5 pr-2 text-slate-400 w-1/2">
                    <button className="text-left hover:underline" onClick={() => onSelect({ start: selection.start, len: r.bytes })}>{r.label}</button>
                    <span className="text-slate-600"> · {r.bytes} B</span>
                  </td>
                  <td className={`py-0.5 font-mono break-all ${r.isTime ? 'text-amber-200' : 'text-slate-100'}`}>{r.value}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
    </div>
  );
};

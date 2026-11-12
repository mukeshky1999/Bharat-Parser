/** CSV helpers shared by every export. Evidence text is untrusted: it must not become a spreadsheet formula. */

/** Quote a cell, double any quotes, and neutralise a leading = + - @ (or tab/CR) so Excel will not run it. */
export const csvCell = (v: unknown): string => {
  let t = String(v ?? '');
  // A plain negative number stays a number; anything else that starts like a formula is made text.
  if (/^[=+\-@\t\r]/.test(t) && !/^-\d+(\.\d+)?$/.test(t)) t = `'${t}`;
  return `"${t.replace(/"/g, '""')}"`;
};

/** Offset as hex, or "not recorded" when the parser did not know it (it must never print as 0x0). */
export const formatOffset = (off?: number | null): string =>
  typeof off === 'number' && off >= 0 ? `0x${off.toString(16).toUpperCase().padStart(8, '0')}` : 'not recorded';

/** The file's text: a byte-order mark first, so Excel reads it as UTF-8 (Indic text and the rupee sign are otherwise garbled). */
export const csvFileText = (lines: string[]): string => '\uFEFF' + lines.join('\r\n');

/** Save text as a CSV file. A Blob is used because a data: URI cuts the file at the first '#' in the data. */
export const downloadCsv = (fileName: string, lines: string[]): void => {
  const blob = new Blob([csvFileText(lines)], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.setAttribute('download', fileName);
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
};

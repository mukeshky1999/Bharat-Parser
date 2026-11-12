export const NOT_RECORDED = 'not recorded';

/** How a stored value is shown. A value that was not recorded says so; zero and false are values. */
export function shownValue(v: unknown): string {
  if (v === null || v === undefined || v === '') return NOT_RECORDED;
  if (typeof v === 'object') return JSON.stringify(v);
  return String(v);
}

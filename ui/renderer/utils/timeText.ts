import type { TimelineEvent } from '../api/forensicClient';

/** The time of a timeline event as text. Some tables record only the Indian-time instant (no UTC): it is shown in either zone, and UTC mode says so. */
export function whenText(e: Pick<TimelineEvent, 'utc' | 'ist' | 'local_clock'>, tz: 'IST' | 'UTC'): string {
  const utc = e.utc ? (/ UTC$/.test(e.utc) ? e.utc : `${e.utc} UTC`) : '';
  if (tz === 'UTC' && utc) return utc;
  if (e.ist) return tz === 'UTC' ? `${e.ist} (IST only; UTC not recorded)` : e.ist;
  if (utc) return utc;
  if (e.local_clock) return `${e.local_clock} (local clock, zone not recorded)`;
  return 'time not recorded';
}

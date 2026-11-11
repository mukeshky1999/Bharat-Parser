import { TimestampFormat, TimestampTriplet } from '../../shared/forensic-types';

/**
 * Normalizes any forensic timestamp into a dual-timezone TimestampTriplet.
 * IST is strictly UTC+05:30 as mandated by Indian Digital Forensics guidelines.
 */
export function normalizeTimestamp(
  rawVal: string | number,
  format?: TimestampFormat
): TimestampTriplet {
  let detectedFormat: TimestampFormat = format || 'UNIX_MS';
  let epochMs = 0;

  if (typeof rawVal === 'string' && rawVal.startsWith('T') && rawVal.length >= 13) {
    // Check if it's a PhonePe Transaction ID (e.g., T261014142201000...)
    const datePart = rawVal.substring(1, 13);
    if (/^\d{12}$/.test(datePart)) {
      detectedFormat = 'PHONEPE_TXID';
    }
  }

  if (detectedFormat === 'PHONEPE_TXID' && typeof rawVal === 'string') {
    // PhonePe TxID format: T + YY(2) + MM(2) + DD(2) + HH(2) + mm(2) + ss(2)
    const yy = parseInt(rawVal.substring(1, 3), 10);
    const mm = parseInt(rawVal.substring(3, 5), 10) - 1;
    const dd = parseInt(rawVal.substring(5, 7), 10);
    const hh = parseInt(rawVal.substring(7, 9), 10);
    const min = parseInt(rawVal.substring(9, 11), 10);
    const ss = parseInt(rawVal.substring(11, 13), 10);
    const fullYear = 2000 + yy;

    // TxID embedded time is recorded in local IST (UTC+05:30) by PhonePe client
    const istOffsetMs = 5.5 * 60 * 60 * 1000;
    const dateUtcAssumed = new Date(Date.UTC(fullYear, mm, dd, hh, min, ss));
    epochMs = dateUtcAssumed.getTime() - istOffsetMs;
  } else {
    const numericVal = typeof rawVal === 'number' ? rawVal : parseFloat(rawVal);

    if (isNaN(numericVal) || numericVal <= 0) {
      epochMs = 0;
      detectedFormat = format || 'UNIX_MS';
    } else if (!format) {
      // Auto-detect format from magnitude
      if (numericVal > 1000000000000000) {
        // Microseconds or WebKit
        if (numericVal > 11644473600000000) {
          // WebKit timestamp (microseconds since 1601-01-01)
          detectedFormat = 'WEBKIT_US';
          epochMs = Math.floor((numericVal - 11644473600000000) / 1000);
        } else {
          detectedFormat = 'UNIX_US';
          epochMs = Math.floor(numericVal / 1000);
        }
      } else if (numericVal > 100000000000) {
        // Milliseconds (13 digits)
        detectedFormat = 'UNIX_MS';
        epochMs = Math.floor(numericVal);
      } else {
        // Seconds (10 digits)
        detectedFormat = 'UNIX_SEC';
        epochMs = Math.floor(numericVal * 1000);
      }
    } else {
      detectedFormat = format;
      switch (format) {
        case 'UNIX_SEC':
          epochMs = Math.floor(numericVal * 1000);
          break;
        case 'UNIX_MS':
          epochMs = Math.floor(numericVal);
          break;
        case 'UNIX_US':
          epochMs = Math.floor(numericVal / 1000);
          break;
        case 'WEBKIT_US':
          // Microseconds since 1601-01-01
          epochMs = Math.floor((numericVal - 11644473600000000) / 1000);
          break;
        case 'COCOA_SEC':
          // Seconds since 2001-01-01
          epochMs = Math.floor((numericVal + 978307200) * 1000);
          break;
        default:
          epochMs = Math.floor(numericVal);
          break;
      }
    }
  }

  const d = new Date(epochMs);
  const utcIso = isNaN(d.getTime()) ? '1970-01-01T00:00:00.000Z' : d.toISOString();

  // Compute IST (UTC + 05:30)
  const istOffsetMs = 5.5 * 60 * 60 * 1000;
  const istDate = new Date(d.getTime() + istOffsetMs);

  const pad = (n: number, w = 2) => String(n).padStart(w, '0');
  const year = istDate.getUTCFullYear();
  const month = pad(istDate.getUTCMonth() + 1);
  const day = pad(istDate.getUTCDate());
  const hours = pad(istDate.getUTCHours());
  const minutes = pad(istDate.getUTCMinutes());
  const seconds = pad(istDate.getUTCSeconds());
  const millis = pad(istDate.getUTCMilliseconds(), 3);

  const istFormatted = `${year}-${month}-${day} ${hours}:${minutes}:${seconds}.${millis} IST (+05:30)`;

  return {
    rawValue: rawVal,
    sourceFormat: detectedFormat,
    utcIso,
    istFormatted,
    epochMs
  };
}

/**
 * Detects device clock tampering by comparing database row timestamp with
 * embedded timestamp inside PhonePe/GPay Transaction ID.
 * Returns true if discrepancy exceeds tolerance (default 5 minutes).
 */
export function detectClockTampering(
  dbTimestamp: TimestampTriplet,
  embeddedTxIdTimestamp: TimestampTriplet,
  toleranceMs: number = 300000
): boolean {
  if (!dbTimestamp.epochMs || !embeddedTxIdTimestamp.epochMs) return false;
  const diff = Math.abs(dbTimestamp.epochMs - embeddedTxIdTimestamp.epochMs);
  return diff > toleranceMs;
}

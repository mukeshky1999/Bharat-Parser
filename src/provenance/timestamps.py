"""
5-Epoch Forensic Timestamp Normalizer & 5-Column Schema Generator.
Phase 1, Module 1.2, Section 4.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional, Union


COCOA_EPOCH_DIFF_SECONDS = 978307200
WEBKIT_FILETIME_DIFF_SECONDS = 11644473600


@dataclass(slots=True)
class NormalizedTimestampRecord:
    """The 5-Column Forensic Timestamp Record Contract."""
    ts_raw_value: str
    ts_epoch_unit: str
    ts_utc_unix_ns: int
    ts_utc_iso8601: str
    ts_tz_provenance: str


class TimestampNormalizer:
    """Normalizes across 5 mobile clock systems with sub-second preservation."""

    def normalize_timestamp(
        self,
        raw_value: Union[int, float, str],
        epoch_hint: Optional[str] = None,
        source_tz: str = "UTC"
    ) -> NormalizedTimestampRecord:
        """
        Normalizes Unix, Cocoa, WebKit, or ISO string timestamps into the 5-column standard.
        """
        raw_str = str(raw_value)
        dt_res: datetime

        # 1. Explicit or Hinted Conversion
        if epoch_hint == "COCOA_SECONDS":
            val_f = float(raw_value)
            unix_sec = val_f + COCOA_EPOCH_DIFF_SECONDS
            unix_ns = int(unix_sec * 1_000_000_000)
            unit = "COCOA_SECONDS"
            tz_prov = "INTRINSIC_UTC"
            dt_res = datetime.fromtimestamp(unix_sec, tz=timezone.utc)

        elif epoch_hint == "COCOA_NANOSECONDS":
            val_f = float(raw_value)
            unix_sec = (val_f / 1_000_000_000.0) + COCOA_EPOCH_DIFF_SECONDS
            unix_ns = int(val_f + (COCOA_EPOCH_DIFF_SECONDS * 1_000_000_000))
            unit = "COCOA_NANOSECONDS"
            tz_prov = "INTRINSIC_UTC"
            # Accurate integer microsecond extraction
            sec_part = int(val_f // 1_000_000_000) + COCOA_EPOCH_DIFF_SECONDS
            us_part = int((val_f % 1_000_000_000) // 1_000)
            dt_res = datetime.fromtimestamp(sec_part, tz=timezone.utc).replace(microsecond=us_part)

        elif epoch_hint == "WEBKIT_MICROSECONDS":
            val_i = int(float(raw_value))
            total_us = val_i - (WEBKIT_FILETIME_DIFF_SECONDS * 1_000_000)
            sec, us = divmod(total_us, 1_000_000)
            unix_sec = float(sec) + (us / 1_000_000.0)
            unix_ns = int(total_us * 1_000)
            unit = "WEBKIT_MICROSECONDS"
            tz_prov = "INTRINSIC_UTC"
            dt_res = datetime.fromtimestamp(sec, tz=timezone.utc).replace(microsecond=us)

        elif isinstance(raw_value, (int, float)):
            val_f = float(raw_value)
            # Auto-detection based on magnitude:
            # 10^9 to 4*10^9: Unix seconds (roughly 2001 - 2096)
            if 1_000_000_000 <= val_f < 4_000_000_000:
                unix_sec = val_f
                unix_ns = int(val_f * 1_000_000_000)
                unit = "UNIX_SECONDS"
                tz_prov = "INTRINSIC_UTC"
                dt_res = datetime.fromtimestamp(unix_sec, tz=timezone.utc)

            # 10^12 to 4*10^12: Unix milliseconds
            elif 1_000_000_000_000 <= val_f < 4_000_000_000_000:
                unix_sec = val_f / 1_000.0
                unix_ns = int(val_f * 1_000_000)
                unit = "UNIX_MILLISECONDS"
                tz_prov = "INTRINSIC_UTC"
                sec, ms = divmod(int(val_f), 1_000)
                dt_res = datetime.fromtimestamp(sec, tz=timezone.utc).replace(microsecond=ms * 1_000)

            # 10^15 to 4*10^15: Unix microseconds
            elif 1_000_000_000_000_000 <= val_f < 4_000_000_000_000_000:
                unix_sec = val_f / 1_000_000.0
                unix_ns = int(val_f * 1_000)
                unit = "UNIX_MICROSECONDS"
                tz_prov = "INTRINSIC_UTC"
                sec, us = divmod(int(val_f), 1_000_000)
                dt_res = datetime.fromtimestamp(sec, tz=timezone.utc).replace(microsecond=us)

            # 10^18 to 4*10^18: Unix nanoseconds
            elif 1_000_000_000_000_000_000 <= val_f < 4_000_000_000_000_000_000:
                unix_sec = val_f / 1_000_000_000.0
                unix_ns = int(val_f)
                unit = "UNIX_NANOSECONDS"
                tz_prov = "INTRINSIC_UTC"
                sec = int(val_f // 1_000_000_000)
                us = int((val_f % 1_000_000_000) // 1_000)
                dt_res = datetime.fromtimestamp(sec, tz=timezone.utc).replace(microsecond=us)

            else:
                unix_sec = val_f
                unix_ns = int(val_f * 1_000_000_000)
                unit = "UNIX_SECONDS"
                tz_prov = "INTRINSIC_UTC"
                dt_res = datetime.fromtimestamp(unix_sec, tz=timezone.utc)

        else:
            # Parse ISO string
            cleaned = raw_str.replace("Z", "+00:00")
            dt = datetime.fromisoformat(cleaned)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            dt_res = dt.astimezone(timezone.utc)
            unix_sec = dt_res.timestamp()
            unix_ns = int(unix_sec * 1_000_000_000)
            unit = "ISO8601_STRING"
            tz_prov = "INTRINSIC_UTC"

        iso_str = dt_res.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

        return NormalizedTimestampRecord(
            ts_raw_value=raw_str,
            ts_epoch_unit=unit,
            ts_utc_unix_ns=unix_ns,
            ts_utc_iso8601=iso_str,
            ts_tz_provenance=tz_prov,
        )

    def normalize_dos_timestamp(
        self,
        dos_date: int,
        dos_time: int,
        has_zip_extra_field: bool = False,
        utc_seconds: Optional[int] = None
    ) -> NormalizedTimestampRecord:
        """
        Translates legacy MS-DOS 16-bit date/time pairs or utilizes 0x5455 UTC Extra Fields.
        """
        if has_zip_extra_field and utc_seconds is not None:
            rec = self.normalize_timestamp(
                raw_value=utc_seconds,
                epoch_hint="UNIX_SECONDS"
            )
            return NormalizedTimestampRecord(
                ts_raw_value=str(utc_seconds),
                ts_epoch_unit=rec.ts_epoch_unit,
                ts_utc_unix_ns=rec.ts_utc_unix_ns,
                ts_utc_iso8601=rec.ts_utc_iso8601,
                ts_tz_provenance="UTC_ZIP_EXTRA_FIELD"
            )

        year = ((dos_date >> 9) & 0x7F) + 1980
        month = max(1, min(12, (dos_date >> 5) & 0x0F))
        day = max(1, min(31, dos_date & 0x1F))
        hour = min(23, (dos_time >> 11) & 0x1F)
        minute = min(59, (dos_time >> 5) & 0x3F)
        second = min(59, (dos_time & 0x1F) * 2)

        try:
            dt = datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc)
        except ValueError:
            dt = datetime(1980, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

        unix_sec = dt.timestamp()
        unix_ns = int(unix_sec * 1_000_000_000)

        return NormalizedTimestampRecord(
            ts_raw_value=f"DOS_DATE=0x{dos_date:04x},DOS_TIME=0x{dos_time:04x}",
            ts_epoch_unit="ZIP_DOS_LOCAL",
            ts_utc_unix_ns=unix_ns,
            ts_utc_iso8601=dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            ts_tz_provenance="AMBIGUOUS_LOCAL_ZIP_DOS"
        )

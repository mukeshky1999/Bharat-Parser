"""
Dual Timestamp Preservation Engine.
Section 4.7: Stores raw timestamp, epoch type, source timezone, utc_iso8601, and ist_iso8601.
Standardizes timestamps using multi-epoch conversion + IST (+05:30) Court Verification Triplet.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from typing import Any, Optional, Tuple, Union


COCOA_EPOCH_DIFF_SECONDS = 978307200  # Offset between 1970-01-01 and 2001-01-01 in seconds
WEBKIT_FILETIME_DIFF_SECONDS = 11644473600  # Offset between 1601-01-01 and 1970-01-01 in seconds
IST_TIMEZONE = timezone(timedelta(hours=5, minutes=30), name="IST")


@dataclass(slots=True)
class ForensicTimestamp:
    """Forensic Dual Timestamp container satisfying Section 4.7 of Constitution."""
    raw_timestamp: Union[int, float, str]
    epoch_type: str
    source_timezone: str
    utc_iso8601: str
    ist_iso8601: str

    def to_court_triplet(self) -> Tuple[Union[int, float, str], str, str]:
        """Returns the Court Verification Triplet: (raw_timestamp, utc_iso8601, ist_iso8601)."""
        return (self.raw_timestamp, self.utc_iso8601, self.ist_iso8601)

    @classmethod
    def from_unix_seconds(
        cls,
        ts: Union[int, float],
        source_timezone: str = "UTC"
    ) -> ForensicTimestamp:
        """Converts POSIX Unix timestamp in seconds to ForensicTimestamp."""
        dt_utc = datetime.fromtimestamp(float(ts), tz=timezone.utc)
        dt_ist = dt_utc.astimezone(IST_TIMEZONE)
        return cls(
            raw_timestamp=ts,
            epoch_type="UNIX_SECONDS",
            source_timezone=source_timezone,
            utc_iso8601=dt_utc.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            ist_iso8601=dt_ist.isoformat(),
        )

    @classmethod
    def from_unix_milliseconds(
        cls,
        ts_ms: Union[int, float],
        source_timezone: str = "UTC"
    ) -> ForensicTimestamp:
        """Converts Unix epoch in milliseconds to ForensicTimestamp."""
        ts_sec = float(ts_ms) / 1000.0
        dt_utc = datetime.fromtimestamp(ts_sec, tz=timezone.utc)
        dt_ist = dt_utc.astimezone(IST_TIMEZONE)
        return cls(
            raw_timestamp=ts_ms,
            epoch_type="UNIX_MILLISECONDS",
            source_timezone=source_timezone,
            utc_iso8601=dt_utc.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            ist_iso8601=dt_ist.isoformat(),
        )

    @classmethod
    def from_unix_microseconds(
        cls,
        ts_us: Union[int, float],
        source_timezone: str = "UTC"
    ) -> ForensicTimestamp:
        """Converts Unix epoch in microseconds to ForensicTimestamp."""
        ts_sec = float(ts_us) / 1_000_000.0
        dt_utc = datetime.fromtimestamp(ts_sec, tz=timezone.utc)
        dt_ist = dt_utc.astimezone(IST_TIMEZONE)
        return cls(
            raw_timestamp=ts_us,
            epoch_type="UNIX_MICROSECONDS",
            source_timezone=source_timezone,
            utc_iso8601=dt_utc.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            ist_iso8601=dt_ist.isoformat(),
        )

    @classmethod
    def from_cocoa_seconds(
        cls,
        cocoa_sec: Union[int, float],
        source_timezone: str = "UTC"
    ) -> ForensicTimestamp:
        """Converts Apple Cocoa CoreData timestamp (seconds since 2001-01-01) to ForensicTimestamp."""
        unix_sec = float(cocoa_sec) + COCOA_EPOCH_DIFF_SECONDS
        dt_utc = datetime.fromtimestamp(unix_sec, tz=timezone.utc)
        dt_ist = dt_utc.astimezone(IST_TIMEZONE)
        return cls(
            raw_timestamp=cocoa_sec,
            epoch_type="COCOA_CORE_DATA",
            source_timezone=source_timezone,
            utc_iso8601=dt_utc.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            ist_iso8601=dt_ist.isoformat(),
        )

    @classmethod
    def from_webkit_filetime_microseconds(
        cls,
        webkit_us: int,
        source_timezone: str = "UTC"
    ) -> ForensicTimestamp:
        """Converts WebKit / Chrome epoch (microseconds since 1601-01-01) to ForensicTimestamp."""
        unix_sec = (webkit_us / 1_000_000.0) - WEBKIT_FILETIME_DIFF_SECONDS
        dt_utc = datetime.fromtimestamp(unix_sec, tz=timezone.utc)
        dt_ist = dt_utc.astimezone(IST_TIMEZONE)
        return cls(
            raw_timestamp=webkit_us,
            epoch_type="WEBKIT_FILETIME_MICROSECONDS",
            source_timezone=source_timezone,
            utc_iso8601=dt_utc.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            ist_iso8601=dt_ist.isoformat(),
        )

    @classmethod
    def from_windows_filetime_100ns(
        cls,
        filetime_ticks: int,
        source_timezone: str = "UTC"
    ) -> ForensicTimestamp:
        """Converts Windows FILETIME (100ns intervals since 1601-01-01) to ForensicTimestamp."""
        unix_sec = (filetime_ticks / 10_000_000.0) - WEBKIT_FILETIME_DIFF_SECONDS
        dt_utc = datetime.fromtimestamp(unix_sec, tz=timezone.utc)
        dt_ist = dt_utc.astimezone(IST_TIMEZONE)
        return cls(
            raw_timestamp=filetime_ticks,
            epoch_type="WINDOWS_FILETIME_100NS",
            source_timezone=source_timezone,
            utc_iso8601=dt_utc.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            ist_iso8601=dt_ist.isoformat(),
        )

    @classmethod
    def from_iso_string(
        cls,
        iso_str: str,
        source_timezone: str = "UTC"
    ) -> ForensicTimestamp:
        """Parses an ISO 8601 string and standardizes to UTC and IST representations."""
        cleaned = iso_str.replace("Z", "+00:00")
        dt = datetime.fromisoformat(cleaned)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        dt_utc = dt.astimezone(timezone.utc)
        dt_ist = dt_utc.astimezone(IST_TIMEZONE)
        return cls(
            raw_timestamp=iso_str,
            epoch_type="ISO8601_STRING",
            source_timezone=source_timezone,
            utc_iso8601=dt_utc.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            ist_iso8601=dt_ist.isoformat(),
        )


def format_timestamp_triplet(
    raw_val: Union[int, float, str, None],
    epoch_hint: str = "auto"
) -> Tuple[Union[int, float, str, None], str, str]:
    """
    Standardizes timestamps using multi-epoch conversion + IST (+05:30) Court Verification Triplet:
    (Raw_Timestamp_Value, Timestamp_UTC, Timestamp_IST [+05:30]).
    Supports Unix sec/ms/us/ns, Cocoa/CoreData seconds, WebKit microseconds, and Windows FILETIME.
    """
    if raw_val is None or str(raw_val).strip() in ("", "None", "null", "nan", "0", "-1"):
        return (None, "", "")

    norm_epoch = epoch_hint.lower() if epoch_hint else "auto"

    try:
        # Check if string date / ISO format
        if isinstance(raw_val, str) and not raw_val.strip().isdigit() and not raw_val.strip().replace(".", "", 1).isdigit():
            clean_str = raw_val.strip()
            if len(clean_str) >= 19 and clean_str[10] in (" ", "T"):
                iso_candidate = clean_str.replace(" ", "T")
                if not iso_candidate.endswith("Z") and "+" not in iso_candidate[10:]:
                    iso_candidate += "Z"
                ft = ForensicTimestamp.from_iso_string(iso_candidate)
                dt_utc = datetime.fromisoformat(ft.utc_iso8601.replace("Z", "+00:00"))
                dt_ist = dt_utc.astimezone(IST_TIMEZONE)
                return (
                    raw_val,
                    dt_utc.strftime("%Y-%m-%d %H:%M:%S UTC"),
                    dt_ist.strftime("%Y-%m-%d %H:%M:%S IST (+05:30)"),
                )

        num = float(raw_val)

        # Windows FILETIME 100ns (ticks > 116444736000000000) or explicit hint
        if norm_epoch in ("filetime", "windows_filetime") or (norm_epoch == "auto" and num > 116444736000000000):
            unix_sec = (num / 10_000_000.0) - WEBKIT_FILETIME_DIFF_SECONDS
        # WebKit microseconds (> 11644473600000000) or explicit hint
        elif norm_epoch in ("webkit", "chrome") or (norm_epoch == "auto" and num > 11644473600000000):
            unix_sec = (num / 1e6) - WEBKIT_FILETIME_DIFF_SECONDS
        # Unix nanoseconds (> 1e17)
        elif norm_epoch in ("unix_ns", "ns") or (norm_epoch == "auto" and num > 1e17):
            unix_sec = num / 1e9
        # Unix microseconds (> 1e14)
        elif norm_epoch in ("unix_us", "unix_micro", "us") or (norm_epoch == "auto" and num > 1e14):
            unix_sec = num / 1e6
        # Unix milliseconds (> 1e11)
        elif norm_epoch in ("unix_ms", "unix_milli", "ms") or (norm_epoch == "auto" and num > 1e11):
            unix_sec = num / 1000.0
        # Cocoa CoreData seconds (typically between 100000000 and 1500000000)
        elif norm_epoch in ("cocoa", "cocoa_sec"):
            unix_sec = num + COCOA_EPOCH_DIFF_SECONDS
        else:
            unix_sec = num

        dt_utc = datetime.fromtimestamp(unix_sec, tz=timezone.utc)
        dt_ist = dt_utc.astimezone(IST_TIMEZONE)
        return (
            raw_val,
            dt_utc.strftime("%Y-%m-%d %H:%M:%S UTC"),
            dt_ist.strftime("%Y-%m-%d %H:%M:%S IST (+05:30)"),
        )
    except Exception:
        return (raw_val, str(raw_val), str(raw_val))

"""
Audio Waveform Processor & Offline Voice-Note Transcripts Cache (Sub-Engine 9.2C & Section 7).
Computes 64-sample RMS peak envelopes and manages persistence in chat_media_waveforms_and_transcripts_cache.
"""

import json
import math
import os
import sqlite3
import struct
from typing import Optional

from src.chat_reconstructor_and_redline.models import AudioWaveformRecord


class AudioWaveformProcessor:
    """Computes audio peak envelopes and persists transcripts in workstation SQLite cache."""

    SCHEMA_SQL = """
    CREATE TABLE IF NOT EXISTS chat_media_waveforms_and_transcripts_cache (
        audio_cache_uid INTEGER PRIMARY KEY AUTOINCREMENT,
        source_vfs_file_id INTEGER NOT NULL,
        playable_wav_staging_id INTEGER,
        duration_seconds REAL NOT NULL,
        waveform_64_peaks_json TEXT NOT NULL,
        offline_stt_transcript_text TEXT,
        word_timestamps_json TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_audio_waveform_vfs
        ON chat_media_waveforms_and_transcripts_cache(source_vfs_file_id);
    """

    def initialize_cache_db(self, db_path: str) -> None:
        """Creates the audio waveform and transcript cache schema if not present."""
        os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
        conn = sqlite3.connect(db_path)
        try:
            conn.executescript(self.SCHEMA_SQL)
            conn.commit()
        finally:
            conn.close()

    def compute_64_peak_envelope(self, pcm_data: bytes) -> list[float]:
        """Calculates 64-bar normalized RMS peak envelope in [0.05, 1.0]."""
        if not pcm_data:
            return [0.05] * 64

        # Read samples (assuming 16-bit signed PCM or 8-bit unsigned fallback)
        num_samples = len(pcm_data) // 2
        samples: list[float] = []

        if num_samples > 0:
            for i in range(num_samples):
                val = struct.unpack("<h", pcm_data[i * 2 : (i + 1) * 2])[0]
                samples.append(abs(val) / 32768.0)
        else:
            for b in pcm_data:
                samples.append(abs(b - 128) / 128.0)

        total_len = len(samples)
        if total_len == 0:
            return [0.05] * 64

        chunk_size = max(1, total_len // 64)
        raw_peaks: list[float] = []

        for i in range(64):
            start = i * chunk_size
            end = min(total_len, (i + 1) * chunk_size) if i < 63 else total_len
            slice_samples = samples[start:end]
            if slice_samples:
                mean_sq = sum(s * s for s in slice_samples) / len(slice_samples)
                rms = math.sqrt(mean_sq)
                raw_peaks.append(rms)
            else:
                raw_peaks.append(0.05)

        # Normalize peaks to [0.05, 1.0]
        max_p = max(raw_peaks) if raw_peaks else 0.05
        normalized: list[float] = []
        for p in raw_peaks:
            if max_p > 0.001:
                scaled = p / max_p
            else:
                scaled = 0.05
            clamped = max(0.05, min(1.0, round(scaled, 4)))
            normalized.append(clamped)

        return normalized

    def save_waveform_record(self, db_path: str, record: AudioWaveformRecord) -> int:
        """Persists a waveform and speech transcript record into SQLite cache."""
        conn = sqlite3.connect(db_path)
        try:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO chat_media_waveforms_and_transcripts_cache (
                    source_vfs_file_id,
                    playable_wav_staging_id,
                    duration_seconds,
                    waveform_64_peaks_json,
                    offline_stt_transcript_text,
                    word_timestamps_json
                ) VALUES (?, ?, ?, ?, ?, ?);
                """,
                (
                    record.source_vfs_file_id,
                    record.playable_wav_staging_id,
                    record.duration_seconds,
                    json.dumps(record.waveform_64_peaks),
                    record.offline_stt_transcript_text,
                    json.dumps(record.word_timestamps),
                ),
            )
            conn.commit()
            return cur.lastrowid or 0
        finally:
            conn.close()

    def get_waveform_record_by_file_id(
        self, db_path: str, file_id: int
    ) -> Optional[AudioWaveformRecord]:
        """Retrieves cached waveform and speech transcript by source VFS file ID."""
        conn = sqlite3.connect(db_path)
        try:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT
                    audio_cache_uid,
                    source_vfs_file_id,
                    playable_wav_staging_id,
                    duration_seconds,
                    waveform_64_peaks_json,
                    offline_stt_transcript_text,
                    word_timestamps_json
                FROM chat_media_waveforms_and_transcripts_cache
                WHERE source_vfs_file_id = ?
                ORDER BY audio_cache_uid DESC
                LIMIT 1;
                """,
                (file_id,),
            )
            row = cur.fetchone()
            if not row:
                return None

            peaks = json.loads(row[4]) if row[4] else []
            timestamps = json.loads(row[6]) if row[6] else []

            return AudioWaveformRecord(
                audio_cache_uid=row[0],
                source_vfs_file_id=row[1],
                playable_wav_staging_id=row[2],
                duration_seconds=float(row[3]),
                waveform_64_peaks=peaks,
                offline_stt_transcript_text=row[5],
                word_timestamps=timestamps,
            )
        finally:
            conn.close()

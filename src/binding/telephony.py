"""
Sub-Engine 3.2A: Physical SIM & eSIM Historical Ledger Decoder.
Extracts active and historical/ejected SIM cards from telephony.db (siminfo)
and iOS CellularUsage.db / CommCenter artifacts.
Adheres strictly to AGENTS.md Forensic Invariants and Section 3 of Module 3.2 Spec.
"""

from src.core.sqlite_uri import ro_uri
from pathlib import Path
import sqlite3
from typing import List, Optional, Union

from src.binding.models import (
    DeviceSIMCardHistoryRecord,
    SeizureSlotState,
    SIMFormFactor,
)
from src.core.enums import ResidualConfidence


class TelephonyProviderDecoder:
    """Decodes historical and active SIM/eSIM cards from Android and iOS telephony stores."""

    def decode_telephony_db(
        self,
        db_path: Union[str, Path],
        os_platform: str = "ANDROID",
    ) -> List[DeviceSIMCardHistoryRecord]:
        """
        Parses Android /data/user_de/0/com.android.providers.telephony/databases/telephony.db.
        Extracts all rows from the 'siminfo' table, identifying active slots (0, 1)
        and historical ejected SIM cards (sim_id == -1).
        """
        target = Path(db_path)
        if not target.exists():
            return []

        records: List[DeviceSIMCardHistoryRecord] = []
        conn = sqlite3.connect(ro_uri(target.resolve()), uri=True)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        try:
            # Check if siminfo table exists
            cur.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='siminfo';"
            )
            table_row = cur.fetchone()
            if table_row is None:
                conn.close()
                return []

            cur.execute("SELECT * FROM siminfo ORDER BY _id ASC;")
            rows = cur.fetchall()

            for row in rows:
                col_keys = row.keys()

                # Extract sub_id (_id)
                sub_id: Optional[int] = row["_id"] if "_id" in col_keys else None

                # Extract ICCID
                iccid: Optional[str] = None
                if "icc_id" in col_keys and row["icc_id"] is not None:
                    iccid = str(row["icc_id"]).strip()

                # Determine slot state
                slot_index: Optional[int] = None
                if "sim_id" in col_keys and row["sim_id"] is not None:
                    slot_index = int(row["sim_id"])
                elif "sim_slot_index" in col_keys and row["sim_slot_index"] is not None:
                    slot_index = int(row["sim_slot_index"])

                if slot_index == -1:
                    seizure_state = SeizureSlotState.EJECTED_HISTORICAL_SIM.value
                elif slot_index == 0:
                    seizure_state = SeizureSlotState.ACTIVE_SLOT_1.value
                elif slot_index == 1:
                    seizure_state = SeizureSlotState.ACTIVE_SLOT_2.value
                elif slot_index is not None and slot_index > 1:
                    seizure_state = f"ACTIVE_SLOT_{slot_index + 1}"
                else:
                    seizure_state = SeizureSlotState.EJECTED_HISTORICAL_SIM.value

                # Carrier & Display Name
                display_name: Optional[str] = None
                if "display_name" in col_keys and row["display_name"]:
                    display_name = str(row["display_name"]).strip()
                elif "carrier_name" in col_keys and row["carrier_name"]:
                    display_name = str(row["carrier_name"]).strip()

                # Phone Number
                phone_num: Optional[str] = None
                if "number" in col_keys and row["number"]:
                    phone_num = str(row["number"]).strip()

                # MCC / MNC
                mcc = row["mcc"] if "mcc" in col_keys else None
                mnc = row["mnc"] if "mnc" in col_keys else None
                mcc_mnc_code: Optional[str] = None
                if mcc is not None and mnc is not None:
                    mcc_mnc_code = f"{mcc}-{mnc}"

                # IMSI
                imsi: Optional[str] = None
                if "imsi" in col_keys and row["imsi"]:
                    imsi = str(row["imsi"]).strip()
                elif mcc_mnc_code and sub_id is not None:
                    clean_mcc_mnc = mcc_mnc_code.replace("-", "")
                    imsi = f"{clean_mcc_mnc}{sub_id:09d}"

                # Form Factor
                is_embedded: int = 0
                if "is_embedded" in col_keys and row["is_embedded"] is not None:
                    is_embedded = int(row["is_embedded"])
                form_factor = (
                    SIMFormFactor.EMBEDDED_ESIM.value
                    if is_embedded == 1
                    else SIMFormFactor.PHYSICAL_SIM.value
                )

                record = DeviceSIMCardHistoryRecord(
                    os_platform=os_platform,
                    android_sub_id=sub_id,
                    iccid_20_digit=iccid,
                    imsi_number=imsi,
                    msisdn_phone_number=phone_num,
                    carrier_display_name=display_name,
                    mcc_mnc_code=mcc_mnc_code,
                    sim_form_factor=form_factor,
                    seizure_slot_state=seizure_state,
                    recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
                    first_observed_utc_iso=None,
                    last_observed_utc_iso=None,
                )
                records.append(record)

        finally:
            conn.close()

        return records

    def decode_ios_cellular_usage_db(
        self,
        db_path: Union[str, Path],
    ) -> List[DeviceSIMCardHistoryRecord]:
        """
        Parses iOS /private/var/wireless/Library/Databases/CellularUsage.db
        for historical subscriber info records.
        """
        target = Path(db_path)
        if not target.exists():
            return []

        records: List[DeviceSIMCardHistoryRecord] = []
        conn = sqlite3.connect(ro_uri(target.resolve()), uri=True)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        try:
            cur.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name IN ('subscriber_info', 'subscriber_mdn');"
            )
            tables = [r["name"] for r in cur.fetchall()]
            if not tables:
                conn.close()
                return []

            target_table = "subscriber_info" if "subscriber_info" in tables else tables[0]
            cur.execute(f"SELECT * FROM {target_table};")
            rows = cur.fetchall()

            for row in rows:
                col_keys = row.keys()
                sub_id_str = str(row["subscriber_id"]) if "subscriber_id" in col_keys else None
                mdn = str(row["mdn"]) if "mdn" in col_keys and row["mdn"] else None

                record = DeviceSIMCardHistoryRecord(
                    os_platform="IOS",
                    android_sub_id=None,
                    iccid_20_digit=sub_id_str,
                    imsi_number=None,
                    msisdn_phone_number=mdn,
                    carrier_display_name=None,
                    mcc_mnc_code=None,
                    sim_form_factor=SIMFormFactor.PHYSICAL_SIM.value,
                    seizure_slot_state=SeizureSlotState.ACTIVE_SLOT_1.value,
                    recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
                )
                records.append(record)

        finally:
            conn.close()

        return records

"""
Sub-Engine 6.4C: Indian Railways (IRCTC, Where is My Train, UTS) & Aviation (DigiYatra) Decoders.
Decodes passenger manifests, offline cell-tower train tracking, and IATA BCBP airport boarding passes.
Complies with Section 5 of Phase 6 Module 6.4 Specification and AGENTS.md Constitution.
"""

import json
import logging
import os
from pathlib import Path
import sqlite3
from typing import Any, Dict, List, Optional

from src.core.enums import ForensicGroup, ResidualConfidence
from src.hyperlocal_travel.models import (
    TravelModality,
    MobilityTravelRecord,
    decode_iata_bcbp,
)

logger = logging.getLogger(__name__)


class IntercityTravelDecoder:
    """Decoder for Indian Railways, DigiYatra aviation, and inter-city travel platforms."""

    def parse_where_is_my_train(
        self,
        wimt_data: Dict[str, Any],
        source_vfs_file_id: int = 1102,
    ) -> MobilityTravelRecord:
        """Parses Where is My Train offline cell-tower mode and search records."""
        train_no = str(wimt_data.get("train_number") or "")
        train_name = str(wimt_data.get("train_name") or "")
        from_stn = str(wimt_data.get("from_station") or "ORIGIN")
        to_stn = str(wimt_data.get("to_station") or "DEST")

        is_inside_train = bool(wimt_data.get("inside_train_cell_mode", False))
        status = "CELL_TOWER_INSIDE_TRAIN_ACTIVE" if is_inside_train else "SEARCHED_STATUS"

        dep_iso = str(wimt_data.get("departure_utc_iso") or "1970-01-01T00:00:00.000000Z")
        arr_iso = wimt_data.get("arrival_utc_iso")

        coach_berth = wimt_data.get("coach_berth") or (f"Train: {train_name}" if train_name else None)

        return MobilityTravelRecord(
            source_app_name="Where is My Train",
            travel_modality=TravelModality.TRAIN_CELL_TOWER_TRACKED_WIMT,
            booking_id_or_pnr=wimt_data.get("pnr"),
            trip_status=status,
            origin_station_or_pickup_addr=from_stn,
            dest_station_or_dropoff_addr=to_stn,
            vehicle_plate_or_train_flight_no=train_no,
            seat_coach_or_room_assignment=coach_berth,
            start_or_departure_utc_iso=dep_iso,
            end_or_arrival_utc_iso=arr_iso,
            recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
            forensic_group=ForensicGroup.G13_HYPERLOCAL_DELIVERY_RIDE_TRAVEL,
        )

    def parse_digiyatra_boarding_pass(
        self,
        bcbp_string: str,
        source_vfs_file_id: int = 1102,
    ) -> MobilityTravelRecord:
        """Parses a DigiYatra IATA BCBP boarding pass string into a MobilityTravelRecord."""
        parsed = decode_iata_bcbp(bcbp_string)

        pax = parsed.get("passenger_name", "")
        pnr = parsed.get("pnr", "")
        orig = parsed.get("origin_iata", "ORIG")
        dest = parsed.get("dest_iata", "DEST")
        airline = parsed.get("airline_code", "")
        flight_num = parsed.get("flight_number", "")
        flight_full = f"{airline} {flight_num}".strip()
        seat = parsed.get("seat_number", "")

        return MobilityTravelRecord(
            source_app_name="DigiYatra",
            travel_modality=TravelModality.FLIGHT_DIGIYATRA_OR_OTA,
            booking_id_or_pnr=pnr,
            trip_status="COMPLETED",
            origin_station_or_pickup_addr=orig,
            dest_station_or_dropoff_addr=dest,
            vehicle_plate_or_train_flight_no=flight_full,
            seat_coach_or_room_assignment=f"Seat {seat}".strip() if seat else None,
            passengers_or_guest_rider_json=json.dumps({"passenger_name": pax}) if pax else None,
            start_or_departure_utc_iso="1970-01-01T00:00:00.000000Z",
            recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
            forensic_group=ForensicGroup.G13_HYPERLOCAL_DELIVERY_RIDE_TRAVEL,
        )

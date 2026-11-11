"""
Sub-Engine 6.4B: Indian Ride-Hailing, Auto/Bike-Taxi & ONDC Mobility Decoders.
Extracts trip histories, driver RTO vehicle registration plates, third-party guest bookings,
and unpacks Google Encoded Polylines into coordinate waypoints.
Complies with Section 4 of Phase 6 Module 6.4 Specification and AGENTS.md Constitution.
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
    decode_google_encoded_polyline,
)

logger = logging.getLogger(__name__)


class MobilityRideDecoder:
    """Decoder for Uber, Ola, Rapido, Namma Yatri, InDrive, and BluSmart ride-hailing apps."""

    def parse_ride_trip(
        self,
        trip_data: Dict[str, Any],
        source_vfs_file_id: int = 1102,
    ) -> MobilityTravelRecord:
        """Parses a ride-hailing trip object, automatically decoding route_polyline if present."""
        source_app = str(trip_data.get("source_app_name") or trip_data.get("app") or "RideApp")
        mod_str = str(trip_data.get("travel_modality", "CAB_OR_AUTO_RIDE")).upper()

        if "BIKE" in mod_str or "2W" in mod_str or "RAPIDO_BIKE" in mod_str:
            modality = TravelModality.BIKE_TAXI_2W
        else:
            modality = TravelModality.CAB_OR_AUTO_RIDE

        poly_str = trip_data.get("route_polyline") or trip_data.get("polyline")
        waypoints_json = None
        if poly_str:
            coords = decode_google_encoded_polyline(str(poly_str))
            waypoints_json = json.dumps(coords) if coords else None

        pickup_addr = str(trip_data.get("origin_station_or_pickup_addr") or trip_data.get("pickup_address") or "")
        dropoff_addr = str(trip_data.get("dest_station_or_dropoff_addr") or trip_data.get("dropoff_address") or "")

        return MobilityTravelRecord(
            source_app_name=source_app,
            travel_modality=modality,
            booking_id_or_pnr=trip_data.get("booking_id_or_pnr") or trip_data.get("trip_id"),
            trip_status=str(trip_data.get("trip_status", "COMPLETED")),
            origin_station_or_pickup_addr=pickup_addr,
            origin_lat_lon_json=trip_data.get("origin_lat_lon_json"),
            dest_station_or_dropoff_addr=dropoff_addr,
            dest_lat_lon_json=trip_data.get("dest_lat_lon_json"),
            decoded_route_waypoints_json=waypoints_json,
            vehicle_plate_or_train_flight_no=trip_data.get("vehicle_plate_or_train_flight_no") or trip_data.get("vehicle_plate"),
            seat_coach_or_room_assignment=trip_data.get("seat_coach_or_room_assignment") or trip_data.get("vehicle_description"),
            passengers_or_guest_rider_json=trip_data.get("passengers_or_guest_rider_json"),
            start_or_departure_utc_iso=str(trip_data.get("start_or_departure_utc_iso") or "1970-01-01T00:00:00.000000Z"),
            end_or_arrival_utc_iso=trip_data.get("end_or_arrival_utc_iso"),
            recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
            forensic_group=ForensicGroup.G13_HYPERLOCAL_DELIVERY_RIDE_TRAVEL,
        )

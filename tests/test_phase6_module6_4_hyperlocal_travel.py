"""
Test Suite: Phase 6, Module 6.4 — Indian Hyper-Local Delivery, Quick-Commerce,
Ride-Hailing, Inter-City Travel & Dating/Matrimonial App Forensics.
Covers:
  - Sub-Engine 6.4A: Hyper-Local Saved Address Book, Hideout Extraction & Alternate Phone Detection.
  - Sub-Engine 6.4B: Ride-Hailing Routes & Bitwise Google Encoded Polyline ZigZag Unpacker.
  - Sub-Engine 6.4C: Indian Railways (Where is My Train / IRCTC) & DigiYatra IATA BCBP Boarding Pass Decoder.
  - Sub-Engine 6.4D: Dating & Matrimonial Forensics (Tinder / Bumble / Shaadi.com), Passport Spoofing & Handoffs.
  - Sub-Engine 6.4E: Master SQLite Export (5 Tables).
Complies with Phase 6 Module 6.4 Specification and AGENTS.md Constitution.
"""

import json
import os
from pathlib import Path
import sqlite3
import pytest

from src.core.enums import (
    ForensicGroup,
    ResidualConfidence,
    EvidentiaryExistence,
    EvidentiaryAccess,
    EvidentiaryStorage,
)
from src.hyperlocal_travel.models import (
    HyperlocalOrderCategory,
    TravelModality,
    DatingPlatform,
    DatingProfileRole,
    SavedAddressRecord,
    HyperlocalOrderRecord,
    MobilityTravelRecord,
    DatingProfileMatchRecord,
    DatingMessageRecord,
    decode_google_encoded_polyline,
    decode_iata_bcbp,
    extract_chat_handoffs,
)
from src.hyperlocal_travel.delivery_decoder import HyperlocalDeliveryDecoder
from src.hyperlocal_travel.mobility_decoder import MobilityRideDecoder
from src.hyperlocal_travel.travel_decoder import IntercityTravelDecoder
from src.hyperlocal_travel.dating_decoder import DatingMatrimonialDecoder
from src.hyperlocal_travel.engine import HyperlocalTravelDatingEngine


# ---------------------------------------------------------------------------
# Test 1: Blinkit / Swiggy Exact Flat/Door & Alternate Receiver Phone Test
# ---------------------------------------------------------------------------

def test_blinkit_swiggy_flat_hideout_and_alternate_phone():
    """
    Test 1: Acceptance Test 1 from Spec Section 8.1.
    Verifies that Sub-Engine 6.4A extracts micro-location flat details,
    delivery instructions, PIN code, pinned GPS coordinates,
    and detects an alternate receiver phone number (9811223344 != primary 9988776655).
    """
    decoder = HyperlocalDeliveryDecoder()

    raw_address = {
        "source_app": "Blinkit",
        "label": "HOME",
        "flat_no": "Flat 902, Tower C",
        "society": "Gaur City 2",
        "city_state": "Greater Noida West, Uttar Pradesh",
        "pincode": "201009",
        "latitude": 28.6189,
        "longitude": 77.4285,
        "instructions": "Don't ring bell, call on alternate number",
        "recipient_name": "Vikram Singh",
        "receiver_phone": "9811223344",
        "timestamp_iso": "2025-11-05T13:20:00.000000Z",
    }

    primary_sim_msisdn = "9988776655"

    rec = decoder.parse_saved_address(
        raw_address,
        primary_sim_msisdn=primary_sim_msisdn,
        app_instance_id=1,
        source_vfs_file_id=1101,
    )

    assert rec.source_app_name == "Blinkit"
    assert rec.flat_floor_tower_building == "Flat 902, Tower C"
    assert rec.street_locality_landmark == "Gaur City 2"
    assert rec.pincode_6_digit == "201009"
    assert rec.pinned_lat_wgs84 == 28.6189
    assert rec.pinned_lon_wgs84 == 77.4285
    assert rec.recipient_contact_phone == "9811223344"
    assert rec.is_alternate_or_third_party_phone == 1
    assert rec.gate_code_or_instructions == "Don't ring bell, call on alternate number"


# ---------------------------------------------------------------------------
# Test 2: Uber / Ola Google Encoded Polyline Bitwise Unpacker Test
# ---------------------------------------------------------------------------

def test_uber_ola_google_encoded_polyline_bitwise_unpacker():
    """
    Test 2: Acceptance Test 2 from Spec Section 8.2.
    Verifies that the bitwise ZigZag unpacker decodes the standard
    Google Encoded Polyline string '_p~iF~ps|U_ulLnnqC_mqNvxq`@'
    into exact coordinate pairs:
      [(38.5, -120.2), (40.7, -120.95), (43.252, -126.453)]
    """
    poly_str = "_p~iF~ps|U_ulLnnqC_mqNvxq`@"
    waypoints = decode_google_encoded_polyline(poly_str)

    assert len(waypoints) == 3
    assert waypoints[0] == (38.5, -120.2)
    assert waypoints[1] == (40.7, -120.95)
    assert waypoints[2] == (43.252, -126.453)


# ---------------------------------------------------------------------------
# Test 3: Where is My Train Cell-Tower Mode & DigiYatra IATA BCBP Test
# ---------------------------------------------------------------------------

def test_where_is_my_train_cell_tower_and_digiyatra_bcbp():
    """
    Test 3: Acceptance Test 3 from Spec Section 8.3.
    Verifies that Sub-Engine 6.4C parses:
      1. Where is My Train cell-tower mode record for Train 12559 (BSB -> NDLS)
      2. DigiYatra IATA BCBP boarding pass string:
         'M1SHARMA/RAHUL        EAB12CD VNSDEL 6E 2042 309Y014A0045 100'
    """
    travel_decoder = IntercityTravelDecoder()

    # 1. Where is My Train record
    wimt_data = {
        "train_number": "12559",
        "train_name": "Shiv Ganga Express",
        "from_station": "BSB",
        "to_station": "NDLS",
        "inside_train_cell_mode": 1,
        "coach_berth": "Coach B2, Berth 44 LB",
        "departure_utc_iso": "2025-11-05T13:20:00.000000Z",
        "arrival_utc_iso": "2025-11-06T00:30:00.000000Z",
    }
    train_rec = travel_decoder.parse_where_is_my_train(wimt_data, source_vfs_file_id=1102)

    assert train_rec.travel_modality == TravelModality.TRAIN_CELL_TOWER_TRACKED_WIMT
    assert train_rec.vehicle_plate_or_train_flight_no == "12559"
    assert train_rec.origin_station_or_pickup_addr == "BSB"
    assert train_rec.dest_station_or_dropoff_addr == "NDLS"
    assert train_rec.trip_status == "CELL_TOWER_INSIDE_TRAIN_ACTIVE"

    # 2. DigiYatra IATA BCBP Boarding Pass
    bcbp_str = "M1SHARMA/RAHUL        EAB12CD VNSDEL 6E 2042 309Y014A0045 100"
    bcbp_parsed = decode_iata_bcbp(bcbp_str)

    assert bcbp_parsed["passenger_name"] == "SHARMA/RAHUL"
    assert bcbp_parsed["pnr"] == "AB12CD"
    assert bcbp_parsed["origin_iata"] == "VNS"
    assert bcbp_parsed["dest_iata"] == "DEL"
    assert bcbp_parsed["airline_code"] == "6E"
    assert bcbp_parsed["flight_number"] == "2042"
    assert bcbp_parsed["julian_date"] == 309
    assert bcbp_parsed["seat_number"] == "014A"


# ---------------------------------------------------------------------------
# Test 4: Tinder Unmatched -wal Recovery, Passport Spoof & WhatsApp Handoff
# ---------------------------------------------------------------------------

def test_tinder_unmatched_wal_recovery_passport_spoof_and_whatsapp_handoff():
    """
    Test 4: Acceptance Test 4 from Spec Section 8.4.
    Verifies that Sub-Engine 6.4D:
      1. Detects Tinder Passport location spoofing (Noida actual GPS vs London virtual).
      2. Recovers deleted/unmatched profile from -wal / cache (was_unmatched_or_deleted = 1).
      3. Automatically extracts WhatsApp handoff phone number '9876543210' from chat text.
    """
    dating_decoder = DatingMatrimonialDecoder()

    # 1. Profile with Passport active: actual GPS in Noida (28.5355, 77.3910) vs London (51.5072, -0.1276)
    owner_profile_data = {
        "platform": DatingPlatform.TINDER,
        "native_user_id": "672901abcf89012345678901",
        "display_name": "Rahul",
        "actual_lat": 28.5355,
        "actual_lon": 77.3910,
        "passport_city": "London",
        "passport_lat": 51.5072,
        "passport_lon": -0.1276,
        "is_passport_active": 1,
    }
    profile_rec = dating_decoder.parse_profile_record(owner_profile_data, source_vfs_file_id=1103)

    assert profile_rec.is_dating_location_spoofed == 1
    assert "London" in str(profile_rec.displayed_passport_city_lat_lon)

    # 2. Deleted / unmatched match record recovered from -wal
    unmatched_peer_data = {
        "platform": DatingPlatform.TINDER,
        "native_user_id": "552901abcf89012345678902",
        "display_name": "Elena",
        "recovered_from_wal_or_freelist": 1,
        "matched_iso": "2025-11-05T13:20:00.000000Z",
    }
    peer_rec = dating_decoder.parse_profile_record(unmatched_peer_data, source_vfs_file_id=1103)
    assert peer_rec.was_unmatched_or_deleted == 1
    assert peer_rec.profile_role == DatingProfileRole.UNMATCHED_OR_BLOCKED_RECOVERED

    # 3. Chat message with off-platform handoff
    chat_data = {
        "platform": DatingPlatform.TINDER,
        "peer_uid": 1,
        "direction": "INCOMING_RECEIVED",
        "message_text": "Hey handsome, I'm rarely here. Text me on WhatsApp 9876543210!",
        "sent_iso": "2025-11-05T13:25:00.000000Z",
    }
    msg_rec = dating_decoder.parse_chat_message(chat_data, source_vfs_file_id=1103)

    assert msg_rec.extracted_handoff_phone_or_handle == "9876543210"


# ---------------------------------------------------------------------------
# Test 5: Hyperlocal, Travel & Dating Master SQLite Export Validation
# ---------------------------------------------------------------------------

def test_hyperlocal_travel_master_sqlite_export():
    """
    Test 5: Master Export Validation.
    Verifies that HyperlocalTravelDatingEngine populates all five tables in
    indian_hyperlocal_travel_and_dating_engine.sqlite.
    """
    export_db_path = Path("./.workspace_tmp/indian_hyperlocal_travel_and_dating_engine.sqlite")
    if export_db_path.exists():
        export_db_path.unlink()

    sample_addresses = [
        SavedAddressRecord(
            source_app_name="Blinkit",
            app_instance_id=1,
            source_vfs_file_id=1101,
            flat_floor_tower_building="Flat 902, Tower C",
            street_locality_landmark="Gaur City 2",
            pincode_6_digit="201009",
            pinned_lat_wgs84=28.6189,
            pinned_lon_wgs84=77.4285,
            recipient_name="Vikram Singh",
            recipient_contact_phone="9811223344",
            is_alternate_or_third_party_phone=1,
        )
    ]

    sample_orders = [
        HyperlocalOrderRecord(
            source_app_name="Swiggy Genie",
            order_category=HyperlocalOrderCategory.INTRACITY_P2P_PARCEL_COURIER,
            native_order_id="GENIE-884912",
            order_status="DELIVERED_COMPLETED",
            pickup_or_store_name_addr="Tower A, Noida Sector 62",
            pickup_sender_name_phone="Amit (9811001100)",
            dropoff_full_address="Flat 401, Greater Noida",
            dropoff_receiver_name_phone="Rohit (9822002200)",
            ordered_utc_iso="2025-11-05T13:20:00.000000Z",
        )
    ]

    sample_mobility = [
        MobilityTravelRecord(
            source_app_name="Uber",
            travel_modality=TravelModality.CAB_OR_AUTO_RIDE,
            booking_id_or_pnr="UBER-TRIP-990",
            trip_status="COMPLETED",
            origin_station_or_pickup_addr="Connaught Place, New Delhi",
            dest_station_or_dropoff_addr="Cyber Hub, Gurugram",
            vehicle_plate_or_train_flight_no="DL-1R-TC-4821",
            start_or_departure_utc_iso="2025-11-05T13:20:00.000000Z",
        )
    ]

    sample_profiles = [
        DatingProfileMatchRecord(
            platform_name=DatingPlatform.TINDER,
            app_instance_id=1,
            profile_role=DatingProfileRole.UNMATCHED_OR_BLOCKED_RECOVERED,
            native_user_or_matrimony_id="672901abcf89012345678901",
            display_name_and_age="Elena, 26",
            was_unmatched_or_deleted=1,
        )
    ]

    sample_messages = [
        DatingMessageRecord(
            platform_name=DatingPlatform.TINDER,
            dating_peer_uid=1,
            source_vfs_file_id=1103,
            direction="INCOMING_RECEIVED",
            message_text_or_prompt="Text me on WhatsApp 9876543210!",
            extracted_handoff_phone_or_handle="9876543210",
            sent_utc_ns=1762349100000000000,
            sent_utc_iso="2025-11-05T13:25:00.000000Z",
        )
    ]

    engine = HyperlocalTravelDatingEngine()
    engine.export_to_sqlite(
        saved_addresses=sample_addresses,
        hyperlocal_orders=sample_orders,
        mobility_travel=sample_mobility,
        dating_profiles=sample_profiles,
        dating_messages=sample_messages,
        output_db_path=str(export_db_path),
    )

    assert export_db_path.exists()
    conn = sqlite3.connect(export_db_path)
    cur = conn.cursor()

    cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = {r[0] for r in cur.fetchall()}
    assert "hyperlocal_saved_addresses_and_hideouts" in tables
    assert "hyperlocal_orders_and_parcel_drops_ledger" in tables
    assert "mobility_rides_and_intercity_travel_ledger" in tables
    assert "dating_and_matrimonial_profiles_and_matches" in tables
    assert "dating_and_matrimonial_messages_ledger" in tables

    cur.execute("SELECT COUNT(*) FROM hyperlocal_saved_addresses_and_hideouts")
    assert cur.fetchone()[0] == 1

    cur.execute("SELECT COUNT(*) FROM hyperlocal_orders_and_parcel_drops_ledger")
    assert cur.fetchone()[0] == 1

    cur.execute("SELECT COUNT(*) FROM mobility_rides_and_intercity_travel_ledger")
    assert cur.fetchone()[0] == 1

    cur.execute("SELECT COUNT(*) FROM dating_and_matrimonial_profiles_and_matches")
    assert cur.fetchone()[0] == 1

    cur.execute("SELECT COUNT(*) FROM dating_and_matrimonial_messages_ledger")
    assert cur.fetchone()[0] == 1

    conn.close()

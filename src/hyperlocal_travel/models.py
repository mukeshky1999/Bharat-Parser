"""
Data models, canonical enums, and mathematical decoders for Hyper-Local, Mobility & Dating Forensics.
Covers saved addresses, courier parcel drops, ride-hailing polyline unpacker, DigiYatra IATA BCBP, and dating personas.
Complies with Section 7 of Phase 6 Module 6.4 Specification and AGENTS.md Constitution.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, unique
import re
from typing import Any, Dict, List, Optional, Tuple

from src.core.enums import (
    ForensicGroup,
    ResidualConfidence,
    EvidentiaryExistence,
    EvidentiaryAccess,
    EvidentiaryStorage,
)


@unique
class HyperlocalOrderCategory(str, Enum):
    """Classification of food, quick-commerce, and P2P parcel courier orders."""
    FOOD_DELIVERY = "FOOD_DELIVERY"
    QUICK_COMMERCE_10MIN = "QUICK_COMMERCE_10MIN"
    ECOMMERCE_PACKAGE = "ECOMMERCE_PACKAGE"
    INTRACITY_P2P_PARCEL_COURIER = "INTRACITY_P2P_PARCEL_COURIER"


@unique
class TravelModality(str, Enum):
    """Classification of urban mobility and inter-city travel modalities."""
    CAB_OR_AUTO_RIDE = "CAB_OR_AUTO_RIDE"
    BIKE_TAXI_2W = "BIKE_TAXI_2W"
    TRAIN_RESERVED_IRCTC = "TRAIN_RESERVED_IRCTC"
    TRAIN_CELL_TOWER_TRACKED_WIMT = "TRAIN_CELL_TOWER_TRACKED_WIMT"
    TRAIN_UNRESERVED_UTS = "TRAIN_UNRESERVED_UTS"
    FLIGHT_DIGIYATRA_OR_OTA = "FLIGHT_DIGIYATRA_OR_OTA"
    INTERCITY_BUS = "INTERCITY_BUS"
    HOTEL_STAY_CHECKIN = "HOTEL_STAY_CHECKIN"


@unique
class DatingPlatform(str, Enum):
    """Supported dating and matrimonial platforms."""
    TINDER = "TINDER"
    BUMBLE = "BUMBLE"
    HINGE = "HINGE"
    GRINDR = "GRINDR"
    HAPPN = "HAPPN"
    AISLE = "AISLE"
    TRULYMADLY = "TRULYMADLY"
    QUACKQUACK = "QUACKQUACK"
    OKCUPID = "OKCUPID"
    SCHMOOZE = "SCHMOOZE"
    SHAADI_COM = "SHAADI_COM"
    BHARAT_MATRIMONY = "BHARAT_MATRIMONY"
    JEEVANSATHI = "JEEVANSATHI"


@unique
class DatingProfileRole(str, Enum):
    """Role and recovery classification of dating/matrimonial personas."""
    LOCAL_DEVICE_OWNER_PERSONA = "LOCAL_DEVICE_OWNER_PERSONA"
    ACTIVE_MATCH = "ACTIVE_MATCH"
    UNMATCHED_OR_BLOCKED_RECOVERED = "UNMATCHED_OR_BLOCKED_RECOVERED"
    CROSSED_PATHS_PROXIMITY_PEER = "CROSSED_PATHS_PROXIMITY_PEER"
    UNLOCKED_MATRIMONIAL_CONTACT = "UNLOCKED_MATRIMONIAL_CONTACT"


def decode_google_encoded_polyline(poly_str: str) -> List[Tuple[float, float]]:
    """
    Decodes an ASCII Google Encoded Polyline into a list of (latitude, longitude) tuples.
    Uses bitwise 5-bit shifting and ZigZag sign reconstruction.
    """
    waypoints: List[Tuple[float, float]] = []
    if not poly_str:
        return waypoints

    index = 0
    current_lat = 0
    current_lon = 0
    poly_len = len(poly_str)

    while index < poly_len:
        # 1. Decode Latitude Delta
        shift = 0
        result = 0
        while index < poly_len:
            c = poly_str[index]
            index += 1
            b = ord(c) - 63
            result |= (b & 0x1F) << shift
            shift += 5
            if not (b & 0x20):
                break

        delta_lat = ~(result >> 1) if (result & 1) else (result >> 1)
        current_lat += delta_lat

        # 2. Decode Longitude Delta
        shift = 0
        result = 0
        while index < poly_len:
            c = poly_str[index]
            index += 1
            b = ord(c) - 63
            result |= (b & 0x1F) << shift
            shift += 5
            if not (b & 0x20):
                break

        delta_lon = ~(result >> 1) if (result & 1) else (result >> 1)
        current_lon += delta_lon

        # Divide by 100,000.0 (Polyline5)
        lat = round(current_lat / 100_000.0, 6)
        lon = round(current_lon / 100_000.0, 6)
        waypoints.append((lat, lon))

    return waypoints


def decode_iata_bcbp(bcbp_str: str) -> Dict[str, Any]:
    """
    Parses an IATA Resolution 792 Barcoded Boarding Pass (BCBP) string.
    Example: 'M1SHARMA/RAHUL        EAB12CD VNSDEL 6E 2042 309Y014A0045 100'
    """
    result: Dict[str, Any] = {
        "raw_bcbp": bcbp_str,
        "passenger_name": "",
        "pnr": "",
        "origin_iata": "",
        "dest_iata": "",
        "airline_code": "",
        "flight_number": "",
        "julian_date": 0,
        "seat_number": "",
    }
    if not bcbp_str or len(bcbp_str) < 30:
        return result

    # Robust regex matching IATA Resolution 792 BCBP format
    pattern = r"M[1-9]([A-Za-z0-9/\s]{20})E([A-Za-z0-9\s]{6,7})\s*([A-Za-z]{3})([A-Za-z]{3})\s*([A-Za-z0-9]{2,3})\s*([0-9]{1,5})\s*([0-9]{3})([A-Za-z])([0-9A-Za-z]{3,4})"
    m = re.search(pattern, bcbp_str)
    if m:
        result["passenger_name"] = m.group(1).strip()
        result["pnr"] = m.group(2).strip()
        result["origin_iata"] = m.group(3).strip()
        result["dest_iata"] = m.group(4).strip()
        result["airline_code"] = m.group(5).strip()
        result["flight_number"] = m.group(6).strip()
        raw_julian = m.group(7).strip()
        result["julian_date"] = int(raw_julian) if raw_julian.isdigit() else 0
        result["seat_number"] = m.group(9).strip()
        return result

    # Fallback fixed-width indexing
    try:
        result["passenger_name"] = bcbp_str[2:22].strip()
        result["pnr"] = bcbp_str[23:30].strip()
        result["origin_iata"] = bcbp_str[30:33].strip()
        result["dest_iata"] = bcbp_str[33:36].strip()
        result["airline_code"] = bcbp_str[36:40].strip()
        result["flight_number"] = bcbp_str[40:45].strip()
        raw_julian = bcbp_str[45:48].strip()
        result["julian_date"] = int(raw_julian) if raw_julian.isdigit() else 0
        result["seat_number"] = bcbp_str[49:53].strip()
    except Exception as exc:
        result["parse_error"] = str(exc)

    return result


def extract_chat_handoffs(text: str) -> Optional[str]:
    """
    Scans message text for off-platform handoff vectors:
    10-digit Indian phone numbers, WhatsApp, Telegram, or crypto addresses.
    """
    if not text:
        return None

    # 1. 10-digit Indian mobile number: [6-9]\d{9} (with optional +91 or 0 prefix)
    phone_match = re.search(r"(?:(?:\+?91[\-\s]?)?|0)?([6-9]\d{9})\b", text)
    if phone_match:
        return phone_match.group(1)

    # 2. WhatsApp / Telegram / Instagram handle
    handle_match = re.search(r"(?:whatsapp|tele|insta|ig|tg|snap)[\s:@\-]*([A-Za-z0-9_\.]{4,30})\b", text, re.IGNORECASE)
    if handle_match:
        return handle_match.group(1)

    # 3. TRC-20 USDT / EVM crypto address
    crypto_match = re.search(r"\b(T[A-Za-z1-9]{33}|0x[a-fA-F0-9]{40})\b", text)
    if crypto_match:
        return crypto_match.group(1)

    return None


@dataclass
class SavedAddressRecord:
    """Model for Table 1: hyperlocal_saved_addresses_and_hideouts."""
    source_app_name: str = ""
    app_instance_id: int = 1
    source_vfs_file_id: int = 0
    recovery_classification: ResidualConfidence = ResidualConfidence.ORIGINAL_RECORD
    address_label_tag: Optional[str] = None
    flat_floor_tower_building: Optional[str] = None
    street_locality_landmark: str = ""
    city_and_state: Optional[str] = None
    pincode_6_digit: Optional[str] = None
    pinned_lat_wgs84: Optional[float] = None
    pinned_lon_wgs84: Optional[float] = None
    gate_code_or_instructions: Optional[str] = None
    recipient_name: Optional[str] = None
    recipient_contact_phone: Optional[str] = None
    is_alternate_or_third_party_phone: int = 0
    first_or_last_used_utc_iso: Optional[str] = None
    forensic_group: ForensicGroup = ForensicGroup.G13_HYPERLOCAL_DELIVERY_RIDE_TRAVEL
    hideout_addr_uid: Optional[int] = None


@dataclass
class HyperlocalOrderRecord:
    """Model for Table 2: hyperlocal_orders_and_parcel_drops_ledger."""
    source_app_name: str = ""
    order_category: HyperlocalOrderCategory = HyperlocalOrderCategory.FOOD_DELIVERY
    native_order_id: str = ""
    order_status: str = "DELIVERED_COMPLETED"
    pickup_or_store_name_addr: Optional[str] = None
    pickup_sender_name_phone: Optional[str] = None
    dropoff_full_address: str = ""
    dropoff_receiver_name_phone: Optional[str] = None
    dropoff_lat_lon_json: Optional[str] = None
    items_or_parcel_type_json: Optional[str] = None
    amount_inr_decimal: Optional[float] = None
    payment_mode_and_utr: Optional[str] = None
    rider_name_phone_and_plate: Optional[str] = None
    ordered_utc_iso: str = ""
    delivered_utc_iso: Optional[str] = None
    recovery_classification: ResidualConfidence = ResidualConfidence.ORIGINAL_RECORD
    forensic_group: ForensicGroup = ForensicGroup.G13_HYPERLOCAL_DELIVERY_RIDE_TRAVEL
    order_record_uid: Optional[int] = None


@dataclass
class MobilityTravelRecord:
    """Model for Table 3: mobility_rides_and_intercity_travel_ledger."""
    source_app_name: str = ""
    travel_modality: TravelModality = TravelModality.CAB_OR_AUTO_RIDE
    booking_id_or_pnr: Optional[str] = None
    trip_status: str = "COMPLETED"
    origin_station_or_pickup_addr: str = ""
    origin_lat_lon_json: Optional[str] = None
    dest_station_or_dropoff_addr: str = ""
    dest_lat_lon_json: Optional[str] = None
    decoded_route_waypoints_json: Optional[str] = None
    vehicle_plate_or_train_flight_no: Optional[str] = None
    seat_coach_or_room_assignment: Optional[str] = None
    passengers_or_guest_rider_json: Optional[str] = None
    start_or_departure_utc_iso: str = ""
    end_or_arrival_utc_iso: Optional[str] = None
    recovery_classification: ResidualConfidence = ResidualConfidence.ORIGINAL_RECORD
    forensic_group: ForensicGroup = ForensicGroup.G13_HYPERLOCAL_DELIVERY_RIDE_TRAVEL
    travel_record_uid: Optional[int] = None


@dataclass
class DatingProfileMatchRecord:
    """Model for Table 4: dating_and_matrimonial_profiles_and_matches."""
    platform_name: DatingPlatform = DatingPlatform.TINDER
    app_instance_id: int = 1
    profile_role: DatingProfileRole = DatingProfileRole.ACTIVE_MATCH
    native_user_or_matrimony_id: str = ""
    display_name_and_age: Optional[str] = None
    unlocked_phone_or_social_handles: Optional[str] = None
    kyc_trust_score_or_kundli_json: Optional[str] = None
    actual_gps_or_crossing_lat_lon: Optional[str] = None
    displayed_passport_city_lat_lon: Optional[str] = None
    is_dating_location_spoofed: int = 0
    was_unmatched_or_deleted: int = 0
    cached_photo_paths_json: Optional[str] = None
    matched_or_crossed_utc_iso: Optional[str] = None
    recovery_classification: ResidualConfidence = ResidualConfidence.ORIGINAL_RECORD
    forensic_group: ForensicGroup = ForensicGroup.G07_MAINSTREAM_AND_MODDED_CHATS
    dating_peer_uid: Optional[int] = None


@dataclass
class DatingMessageRecord:
    """Model for Table 5: dating_and_matrimonial_messages_ledger."""
    platform_name: DatingPlatform = DatingPlatform.TINDER
    dating_peer_uid: int = 0
    source_vfs_file_id: int = 0
    recovery_classification: ResidualConfidence = ResidualConfidence.ORIGINAL_RECORD
    direction: str = "UNKNOWN"
    message_text_or_prompt: Optional[str] = None
    media_or_shared_pin_json: Optional[str] = None
    extracted_handoff_phone_or_handle: Optional[str] = None
    sent_utc_ns: int = 0
    sent_utc_iso: str = ""
    forensic_group: ForensicGroup = ForensicGroup.G07_MAINSTREAM_AND_MODDED_CHATS
    dating_msg_uid: Optional[int] = None

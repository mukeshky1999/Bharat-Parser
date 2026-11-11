"""
Sub-Engine 6.4E: Unified Hyper-Local, Travel & Dating Master Database Engine.
Orchestrates forensic export into indian_hyperlocal_travel_and_dating_engine.sqlite across 5 tables.
Complies with Section 7 of Phase 6 Module 6.4 Specification and AGENTS.md Constitution.
"""

import logging
import os
from pathlib import Path
import sqlite3
from typing import List, Optional

from src.core.enums import ForensicGroup
from src.hyperlocal_travel.models import (
    SavedAddressRecord,
    HyperlocalOrderRecord,
    MobilityTravelRecord,
    DatingProfileMatchRecord,
    DatingMessageRecord,
)

logger = logging.getLogger(__name__)


class HyperlocalTravelDatingEngine:
    """Master database and export engine for Module 6.4."""

    def init_database(self, db_path: str) -> None:
        """Initializes the SQLite schema with the 5 canonical tables."""
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()

        # Table 1: hyperlocal_saved_addresses_and_hideouts
        cur.execute("""
            CREATE TABLE IF NOT EXISTS hyperlocal_saved_addresses_and_hideouts (
                hideout_addr_uid INTEGER PRIMARY KEY AUTOINCREMENT,
                source_app_name TEXT NOT NULL,
                app_instance_id INTEGER NOT NULL,
                source_vfs_file_id INTEGER NOT NULL,
                recovery_classification TEXT NOT NULL,
                address_label_tag TEXT,
                flat_floor_tower_building TEXT,
                street_locality_landmark TEXT NOT NULL,
                city_and_state TEXT,
                pincode_6_digit TEXT,
                pinned_lat_wgs84 REAL,
                pinned_lon_wgs84 REAL,
                gate_code_or_instructions TEXT,
                recipient_name TEXT,
                recipient_contact_phone TEXT,
                is_alternate_or_third_party_phone INTEGER DEFAULT 0,
                first_or_last_used_utc_iso TEXT,
                forensic_group TEXT NOT NULL
            )
        """)

        # Table 2: hyperlocal_orders_and_parcel_drops_ledger
        cur.execute("""
            CREATE TABLE IF NOT EXISTS hyperlocal_orders_and_parcel_drops_ledger (
                order_record_uid INTEGER PRIMARY KEY AUTOINCREMENT,
                source_app_name TEXT NOT NULL,
                order_category TEXT NOT NULL,
                native_order_id TEXT NOT NULL,
                order_status TEXT NOT NULL,
                pickup_or_store_name_addr TEXT,
                pickup_sender_name_phone TEXT,
                dropoff_full_address TEXT NOT NULL,
                dropoff_receiver_name_phone TEXT,
                dropoff_lat_lon_json TEXT,
                items_or_parcel_type_json TEXT,
                amount_inr_decimal REAL,
                payment_mode_and_utr TEXT,
                rider_name_phone_and_plate TEXT,
                ordered_utc_iso TEXT NOT NULL,
                delivered_utc_iso TEXT,
                recovery_classification TEXT NOT NULL,
                forensic_group TEXT NOT NULL
            )
        """)

        # Table 3: mobility_rides_and_intercity_travel_ledger
        cur.execute("""
            CREATE TABLE IF NOT EXISTS mobility_rides_and_intercity_travel_ledger (
                travel_record_uid INTEGER PRIMARY KEY AUTOINCREMENT,
                source_app_name TEXT NOT NULL,
                travel_modality TEXT NOT NULL,
                booking_id_or_pnr TEXT,
                trip_status TEXT NOT NULL,
                origin_station_or_pickup_addr TEXT NOT NULL,
                origin_lat_lon_json TEXT,
                dest_station_or_dropoff_addr TEXT NOT NULL,
                dest_lat_lon_json TEXT,
                decoded_route_waypoints_json TEXT,
                vehicle_plate_or_train_flight_no TEXT,
                seat_coach_or_room_assignment TEXT,
                passengers_or_guest_rider_json TEXT,
                start_or_departure_utc_iso TEXT NOT NULL,
                end_or_arrival_utc_iso TEXT,
                recovery_classification TEXT NOT NULL,
                forensic_group TEXT NOT NULL
            )
        """)

        # Table 4: dating_and_matrimonial_profiles_and_matches
        cur.execute("""
            CREATE TABLE IF NOT EXISTS dating_and_matrimonial_profiles_and_matches (
                dating_peer_uid INTEGER PRIMARY KEY AUTOINCREMENT,
                platform_name TEXT NOT NULL,
                app_instance_id INTEGER NOT NULL,
                profile_role TEXT NOT NULL,
                native_user_or_matrimony_id TEXT NOT NULL,
                display_name_and_age TEXT,
                unlocked_phone_or_social_handles TEXT,
                kyc_trust_score_or_kundli_json TEXT,
                actual_gps_or_crossing_lat_lon TEXT,
                displayed_passport_city_lat_lon TEXT,
                is_dating_location_spoofed INTEGER DEFAULT 0,
                was_unmatched_or_deleted INTEGER DEFAULT 0,
                cached_photo_paths_json TEXT,
                matched_or_crossed_utc_iso TEXT,
                recovery_classification TEXT NOT NULL,
                forensic_group TEXT NOT NULL
            )
        """)

        # Table 5: dating_and_matrimonial_messages_ledger
        cur.execute("""
            CREATE TABLE IF NOT EXISTS dating_and_matrimonial_messages_ledger (
                dating_msg_uid INTEGER PRIMARY KEY AUTOINCREMENT,
                platform_name TEXT NOT NULL,
                dating_peer_uid INTEGER NOT NULL,
                source_vfs_file_id INTEGER NOT NULL,
                recovery_classification TEXT NOT NULL,
                direction TEXT NOT NULL,
                message_text_or_prompt TEXT,
                media_or_shared_pin_json TEXT,
                extracted_handoff_phone_or_handle TEXT,
                sent_utc_ns INTEGER NOT NULL,
                sent_utc_iso TEXT NOT NULL,
                forensic_group TEXT NOT NULL
            )
        """)

        # Indexes
        cur.execute("CREATE INDEX IF NOT EXISTS idx_hideout_phone ON hyperlocal_saved_addresses_and_hideouts(recipient_contact_phone)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_hideout_pincode ON hyperlocal_saved_addresses_and_hideouts(pincode_6_digit)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_mobility_plate ON mobility_rides_and_intercity_travel_ledger(vehicle_plate_or_train_flight_no)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_dating_handoff ON dating_and_matrimonial_messages_ledger(extracted_handoff_phone_or_handle)")

        conn.commit()
        conn.close()

    def export_to_sqlite(
        self,
        saved_addresses: Optional[List[SavedAddressRecord]] = None,
        hyperlocal_orders: Optional[List[HyperlocalOrderRecord]] = None,
        mobility_travel: Optional[List[MobilityTravelRecord]] = None,
        dating_profiles: Optional[List[DatingProfileMatchRecord]] = None,
        dating_messages: Optional[List[DatingMessageRecord]] = None,
        output_db_path: str = "./.workspace_tmp/indian_hyperlocal_travel_and_dating_engine.sqlite",
    ) -> None:
        """Populates the 5 tables in the case database with extracted records."""
        out_path = Path(output_db_path)
        out_path.parent.mkdir(parents=True, exist_ok=True)

        self.init_database(output_db_path)

        conn = sqlite3.connect(output_db_path)
        cur = conn.cursor()

        if saved_addresses:
            for s in saved_addresses:
                cur.execute(
                    """
                    INSERT INTO hyperlocal_saved_addresses_and_hideouts (
                        source_app_name,
                        app_instance_id,
                        source_vfs_file_id,
                        recovery_classification,
                        address_label_tag,
                        flat_floor_tower_building,
                        street_locality_landmark,
                        city_and_state,
                        pincode_6_digit,
                        pinned_lat_wgs84,
                        pinned_lon_wgs84,
                        gate_code_or_instructions,
                        recipient_name,
                        recipient_contact_phone,
                        is_alternate_or_third_party_phone,
                        first_or_last_used_utc_iso,
                        forensic_group
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        s.source_app_name,
                        s.app_instance_id,
                        s.source_vfs_file_id,
                        str(s.recovery_classification.value if hasattr(s.recovery_classification, "value") else s.recovery_classification),
                        s.address_label_tag,
                        s.flat_floor_tower_building,
                        s.street_locality_landmark,
                        s.city_and_state,
                        s.pincode_6_digit,
                        s.pinned_lat_wgs84,
                        s.pinned_lon_wgs84,
                        s.gate_code_or_instructions,
                        s.recipient_name,
                        s.recipient_contact_phone,
                        s.is_alternate_or_third_party_phone,
                        s.first_or_last_used_utc_iso,
                        str(s.forensic_group.value if hasattr(s.forensic_group, "value") else s.forensic_group),
                    ),
                )

        if hyperlocal_orders:
            for o in hyperlocal_orders:
                cur.execute(
                    """
                    INSERT INTO hyperlocal_orders_and_parcel_drops_ledger (
                        source_app_name,
                        order_category,
                        native_order_id,
                        order_status,
                        pickup_or_store_name_addr,
                        pickup_sender_name_phone,
                        dropoff_full_address,
                        dropoff_receiver_name_phone,
                        dropoff_lat_lon_json,
                        items_or_parcel_type_json,
                        amount_inr_decimal,
                        payment_mode_and_utr,
                        rider_name_phone_and_plate,
                        ordered_utc_iso,
                        delivered_utc_iso,
                        recovery_classification,
                        forensic_group
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        o.source_app_name,
                        str(o.order_category.value if hasattr(o.order_category, "value") else o.order_category),
                        o.native_order_id,
                        o.order_status,
                        o.pickup_or_store_name_addr,
                        o.pickup_sender_name_phone,
                        o.dropoff_full_address,
                        o.dropoff_receiver_name_phone,
                        o.dropoff_lat_lon_json,
                        o.items_or_parcel_type_json,
                        o.amount_inr_decimal,
                        o.payment_mode_and_utr,
                        o.rider_name_phone_and_plate,
                        o.ordered_utc_iso,
                        o.delivered_utc_iso,
                        str(o.recovery_classification.value if hasattr(o.recovery_classification, "value") else o.recovery_classification),
                        str(o.forensic_group.value if hasattr(o.forensic_group, "value") else o.forensic_group),
                    ),
                )

        if mobility_travel:
            for m in mobility_travel:
                cur.execute(
                    """
                    INSERT INTO mobility_rides_and_intercity_travel_ledger (
                        source_app_name,
                        travel_modality,
                        booking_id_or_pnr,
                        trip_status,
                        origin_station_or_pickup_addr,
                        origin_lat_lon_json,
                        dest_station_or_dropoff_addr,
                        dest_lat_lon_json,
                        decoded_route_waypoints_json,
                        vehicle_plate_or_train_flight_no,
                        seat_coach_or_room_assignment,
                        passengers_or_guest_rider_json,
                        start_or_departure_utc_iso,
                        end_or_arrival_utc_iso,
                        recovery_classification,
                        forensic_group
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        m.source_app_name,
                        str(m.travel_modality.value if hasattr(m.travel_modality, "value") else m.travel_modality),
                        m.booking_id_or_pnr,
                        m.trip_status,
                        m.origin_station_or_pickup_addr,
                        m.origin_lat_lon_json,
                        m.dest_station_or_dropoff_addr,
                        m.dest_lat_lon_json,
                        m.decoded_route_waypoints_json,
                        m.vehicle_plate_or_train_flight_no,
                        m.seat_coach_or_room_assignment,
                        m.passengers_or_guest_rider_json,
                        m.start_or_departure_utc_iso,
                        m.end_or_arrival_utc_iso,
                        str(m.recovery_classification.value if hasattr(m.recovery_classification, "value") else m.recovery_classification),
                        str(m.forensic_group.value if hasattr(m.forensic_group, "value") else m.forensic_group),
                    ),
                )

        if dating_profiles:
            for d in dating_profiles:
                cur.execute(
                    """
                    INSERT INTO dating_and_matrimonial_profiles_and_matches (
                        platform_name,
                        app_instance_id,
                        profile_role,
                        native_user_or_matrimony_id,
                        display_name_and_age,
                        unlocked_phone_or_social_handles,
                        kyc_trust_score_or_kundli_json,
                        actual_gps_or_crossing_lat_lon,
                        displayed_passport_city_lat_lon,
                        is_dating_location_spoofed,
                        was_unmatched_or_deleted,
                        cached_photo_paths_json,
                        matched_or_crossed_utc_iso,
                        recovery_classification,
                        forensic_group
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        str(d.platform_name.value if hasattr(d.platform_name, "value") else d.platform_name),
                        d.app_instance_id,
                        str(d.profile_role.value if hasattr(d.profile_role, "value") else d.profile_role),
                        d.native_user_or_matrimony_id,
                        d.display_name_and_age,
                        d.unlocked_phone_or_social_handles,
                        d.kyc_trust_score_or_kundli_json,
                        d.actual_gps_or_crossing_lat_lon,
                        d.displayed_passport_city_lat_lon,
                        d.is_dating_location_spoofed,
                        d.was_unmatched_or_deleted,
                        d.cached_photo_paths_json,
                        d.matched_or_crossed_utc_iso,
                        str(d.recovery_classification.value if hasattr(d.recovery_classification, "value") else d.recovery_classification),
                        str(d.forensic_group.value if hasattr(d.forensic_group, "value") else d.forensic_group),
                    ),
                )

        if dating_messages:
            for msg in dating_messages:
                cur.execute(
                    """
                    INSERT INTO dating_and_matrimonial_messages_ledger (
                        platform_name,
                        dating_peer_uid,
                        source_vfs_file_id,
                        recovery_classification,
                        direction,
                        message_text_or_prompt,
                        media_or_shared_pin_json,
                        extracted_handoff_phone_or_handle,
                        sent_utc_ns,
                        sent_utc_iso,
                        forensic_group
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        str(msg.platform_name.value if hasattr(msg.platform_name, "value") else msg.platform_name),
                        msg.dating_peer_uid,
                        msg.source_vfs_file_id,
                        str(msg.recovery_classification.value if hasattr(msg.recovery_classification, "value") else msg.recovery_classification),
                        msg.direction,
                        msg.message_text_or_prompt,
                        msg.media_or_shared_pin_json,
                        msg.extracted_handoff_phone_or_handle,
                        msg.sent_utc_ns,
                        msg.sent_utc_iso,
                        str(msg.forensic_group.value if hasattr(msg.forensic_group, "value") else msg.forensic_group),
                    ),
                )

        conn.commit()
        conn.close()

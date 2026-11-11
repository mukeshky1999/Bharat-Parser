"""
Sub-Engine 6.4A: Indian Hyper-Local Food, Quick-Commerce & P2P Parcel Courier Decoders.
Extracts micro-location flat/floor hideouts, delivery gate instructions, PIN codes,
alternate receiver phone attribution, and intra-city P2P courier drops (Swiggy Genie, Porter, Borzo).
Complies with Section 3 of Phase 6 Module 6.4 Specification and AGENTS.md Constitution.
"""

import json
import logging
import os
from pathlib import Path
import sqlite3
from typing import Any, Dict, List, Optional

from src.core.enums import ForensicGroup, ResidualConfidence
from src.hyperlocal_travel.models import (
    HyperlocalOrderCategory,
    SavedAddressRecord,
    HyperlocalOrderRecord,
)

logger = logging.getLogger(__name__)


class HyperlocalDeliveryDecoder:
    """Decoder for Indian food delivery, quick-commerce, and P2P parcel courier apps."""

    def parse_saved_address(
        self,
        raw_address: Dict[str, Any],
        primary_sim_msisdn: Optional[str] = None,
        app_instance_id: int = 1,
        source_vfs_file_id: int = 1101,
    ) -> SavedAddressRecord:
        """
        Parses a single saved address dictionary (from SQLite, MMKV, or app_webview cache):
        Flags is_alternate_or_third_party_phone = 1 if receiver_phone != primary_sim_msisdn.
        """
        source_app = str(raw_address.get("source_app") or raw_address.get("app_name") or "HyperlocalApp")
        label = raw_address.get("label") or raw_address.get("address_label_tag") or raw_address.get("type")
        flat_no = raw_address.get("flat_no") or raw_address.get("flat_floor_tower_building") or raw_address.get("house_no")
        society = raw_address.get("society") or raw_address.get("street_locality_landmark") or raw_address.get("street") or ""
        city_state = raw_address.get("city_state") or raw_address.get("city_and_state") or raw_address.get("city")
        pincode = str(raw_address.get("pincode") or raw_address.get("pincode_6_digit") or raw_address.get("zip") or "")
        pincode_clean = pincode.strip()[:6] if pincode else None

        lat = raw_address.get("latitude") or raw_address.get("pinned_lat_wgs84") or raw_address.get("lat")
        lon = raw_address.get("longitude") or raw_address.get("pinned_lon_wgs84") or raw_address.get("lon") or raw_address.get("lng")

        instructions = raw_address.get("instructions") or raw_address.get("gate_code_or_instructions") or raw_address.get("delivery_instructions")
        recipient = raw_address.get("recipient_name") or raw_address.get("name") or raw_address.get("contact_name")
        phone = raw_address.get("receiver_phone") or raw_address.get("recipient_contact_phone") or raw_address.get("contact_number")

        phone_clean = str(phone).strip() if phone else None
        is_alternate = 0

        if phone_clean and primary_sim_msisdn:
            p1 = phone_clean[-10:]
            p2 = str(primary_sim_msisdn)[-10:]
            if p1 != p2:
                is_alternate = 1

        ts_iso = raw_address.get("timestamp_iso") or raw_address.get("first_or_last_used_utc_iso")

        return SavedAddressRecord(
            source_app_name=source_app,
            app_instance_id=app_instance_id,
            source_vfs_file_id=source_vfs_file_id,
            recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
            address_label_tag=str(label) if label else None,
            flat_floor_tower_building=str(flat_no) if flat_no else None,
            street_locality_landmark=str(society),
            city_and_state=str(city_state) if city_state else None,
            pincode_6_digit=pincode_clean,
            pinned_lat_wgs84=float(lat) if lat is not None else None,
            pinned_lon_wgs84=float(lon) if lon is not None else None,
            gate_code_or_instructions=str(instructions) if instructions else None,
            recipient_name=str(recipient) if recipient else None,
            recipient_contact_phone=phone_clean,
            is_alternate_or_third_party_phone=is_alternate,
            first_or_last_used_utc_iso=str(ts_iso) if ts_iso else None,
            forensic_group=ForensicGroup.G13_HYPERLOCAL_DELIVERY_RIDE_TRAVEL,
        )

    def parse_order_record(
        self,
        order_data: Dict[str, Any],
        source_vfs_file_id: int = 1101,
    ) -> HyperlocalOrderRecord:
        """Parses food, grocery, or P2P courier order (Swiggy Genie, Porter, Borzo)."""
        app_name = str(order_data.get("source_app_name") or order_data.get("app") or "DeliveryApp")
        cat_str = str(order_data.get("order_category", "FOOD_DELIVERY")).upper()

        if "GENIE" in cat_str or "PARCEL" in cat_str or "PORTER" in cat_str:
            cat = HyperlocalOrderCategory.INTRACITY_P2P_PARCEL_COURIER
        elif "QUICK" in cat_str or "10MIN" in cat_str or "INSTAMART" in cat_str or "ZEPTO" in cat_str or "BLINKIT" in cat_str:
            cat = HyperlocalOrderCategory.QUICK_COMMERCE_10MIN
        elif "ECOMMERCE" in cat_str or "FLIPKART" in cat_str or "AMAZON" in cat_str:
            cat = HyperlocalOrderCategory.ECOMMERCE_PACKAGE
        else:
            cat = HyperlocalOrderCategory.FOOD_DELIVERY

        return HyperlocalOrderRecord(
            source_app_name=app_name,
            order_category=cat,
            native_order_id=str(order_data.get("native_order_id") or order_data.get("order_id") or "ORDER-UNKNOWN"),
            order_status=str(order_data.get("order_status", "DELIVERED_COMPLETED")),
            pickup_or_store_name_addr=order_data.get("pickup_or_store_name_addr"),
            pickup_sender_name_phone=order_data.get("pickup_sender_name_phone"),
            dropoff_full_address=str(order_data.get("dropoff_full_address") or order_data.get("delivery_address") or ""),
            dropoff_receiver_name_phone=order_data.get("dropoff_receiver_name_phone"),
            dropoff_lat_lon_json=order_data.get("dropoff_lat_lon_json"),
            items_or_parcel_type_json=order_data.get("items_or_parcel_type_json"),
            amount_inr_decimal=float(order_data["amount_inr_decimal"]) if order_data.get("amount_inr_decimal") is not None else None,
            payment_mode_and_utr=order_data.get("payment_mode_and_utr"),
            rider_name_phone_and_plate=order_data.get("rider_name_phone_and_plate"),
            ordered_utc_iso=str(order_data.get("ordered_utc_iso") or "1970-01-01T00:00:00.000000Z"),
            delivered_utc_iso=order_data.get("delivered_utc_iso"),
            recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
            forensic_group=ForensicGroup.G13_HYPERLOCAL_DELIVERY_RIDE_TRAVEL,
        )

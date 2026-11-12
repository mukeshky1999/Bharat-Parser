"""
Sub-Engine 4.2B: Binance, Bybit & Global P2P Exchange Deep Decoder.
Processes MMKV Layer-1 (active) & Layer-2 (superseded history) stores,
decompressed HTTP/WebView caches, P2P escrow order JSONs, in-order chat extraction,
triangulation fraud detection, and off-chain Binance Pay vs on-chain transfers.
"""

from datetime import datetime, timezone
import json
import logging
import os
import re
import struct
from typing import Any, Dict, List, Optional, Tuple
import zlib

from src.core.enums import (
    ForensicGroup,
    ResidualConfidence,
    EvidentiaryState,
    EvidentiaryExistence,
    EvidentiaryAccess,
    EvidentiaryStorage,
)
from src.core.timestamps import ForensicTimestamp
from src.cex.models import (
    CEXAccountProfileRecord,
    CEXComplianceTier,
    CEXP2PChatMessageRecord,
    CEXP2PEscrowOrderRecord,
    CEXP2POrderStatus,
    CEXP2PTradeDirection,
    CEXTransferCategory,
    CEXTransferRecord,
)

logger = logging.getLogger(__name__)

INDIAN_MOBILE_REGEX = re.compile(r"\b[6-9]\d{9}\b")
NPCI_12_DIGIT_UTR_REGEX = re.compile(r"\b\d{12}\b")
VPA_REGEX = re.compile(r"\b[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}\b(?!\.[a-zA-Z0-9])")


def _key_tokens(name: str) -> set:
    """Lower-case word tokens of a key: 'kycRealName' -> {'kyc','real','name'}, 'guid' -> {'guid'}."""
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", str(name))
    return {t for t in re.split(r"[^a-z0-9]+", spaced.lower()) if t}


def _is_user_id_key(name: str) -> bool:
    t = _key_tokens(name)
    if t & {"device", "guid", "session", "push", "app", "install"}:
        return False
    return "uid" in t or "userid" in t or ("user" in t and "id" in t)


def _is_kyc_name_key(name: str) -> bool:
    t = _key_tokens(name)
    if t & {"user", "nick", "file", "device", "app", "host", "display"} and "kyc" not in t and "real" not in t:
        return False
    return "realname" in t or ("real" in t and "name" in t) or ("full" in t and "name" in t) or ("kyc" in t and "name" in t)


def _ts_iso(raw: Any) -> str:
    """UTC ISO string from a seconds or milliseconds epoch; '' when absent or unreadable (never the analysis time)."""
    try:
        v = float(raw)
    except (TypeError, ValueError):
        return ""
    if v <= 0:
        return ""
    try:
        if v > 10_000_000_000:
            return ForensicTimestamp.from_unix_milliseconds(int(v)).utc_iso8601
        return ForensicTimestamp.from_unix_seconds(int(v)).utc_iso8601
    except (ValueError, OverflowError, OSError):
        return ""


def _to_float(raw: Any) -> float:
    try:
        return float(raw)
    except (TypeError, ValueError):
        return 0.0


def decode_varint(data: bytes, offset: int) -> Tuple[int, int]:
    """Decodes variable-length integer (LEB128) and returns (val, bytes_consumed)."""
    res = 0
    shift = 0
    idx = offset
    while idx < len(data):
        b = data[idx]
        res |= (b & 0x7F) << shift
        idx += 1
        if not (b & 0x80):
            break
        shift += 7
    return res, idx - offset


class BinanceDecoder:
    """Decoder for Binance, Bybit, and Global P2P exchange artifacts."""

    def __init__(self) -> None:
        self.supported_exchanges = ("Binance", "Bybit", "KuCoin", "MEXC", "Bitget")

    def decode_sandbox(
        self,
        mmkv_path: Optional[str] = None,
        cache_path: Optional[str] = None,
        db_path: Optional[str] = None,
        source_vfs_file_id: int = 0,
    ) -> Dict[str, Any]:
        """
        Parses Binance MMKV, WebView caches, and SQLite databases.
        Returns dict with 'accounts', 'p2p_orders', 'chat_messages', 'transfers'.
        """
        accounts: List[CEXAccountProfileRecord] = []
        orders: List[CEXP2PEscrowOrderRecord] = []
        chats: List[CEXP2PChatMessageRecord] = []
        transfers: List[CEXTransferRecord] = []

        if mmkv_path and os.path.exists(mmkv_path):
            mmkv_accs = self._parse_mmkv_accounts(mmkv_path, source_vfs_file_id)
            accounts.extend(mmkv_accs)

        if cache_path and os.path.exists(cache_path):
            cache_orders, cache_transfers = self._parse_cache_file(cache_path, source_vfs_file_id)
            orders.extend(cache_orders)
            transfers.extend(cache_transfers)

        return {
            "accounts": accounts,
            "p2p_orders": orders,
            "chat_messages": chats,
            "transfers": transfers,
        }

    def _parse_mmkv_accounts(
        self, mmkv_path: str, source_vfs_file_id: int
    ) -> List[CEXAccountProfileRecord]:
        """Parses MMKV file, extracting Layer-1 (active) and Layer-2 (superseded) UIDs."""
        accounts: List[CEXAccountProfileRecord] = []
        try:
            with open(mmkv_path, "rb") as fh:
                raw = fh.read()
        except Exception as exc:
            logger.warning("could not read MMKV %s: %s", mmkv_path, exc)
            return accounts

        if len(raw) < 4:
            return accounts

        payload_len = struct.unpack_from("<I", raw, 0)[0]
        offset = 4
        limit = min(len(raw), 4 + payload_len)

        # Collect raw key-value history preserving append order
        history: List[Tuple[str, bytes]] = []
        while offset < limit:
            try:
                k_len, consumed_k = decode_varint(raw, offset)
                offset += consumed_k
                if offset + k_len > limit:
                    break
                key = raw[offset : offset + k_len].decode("utf-8", errors="ignore")
                offset += k_len

                v_len, consumed_v = decode_varint(raw, offset)
                offset += consumed_v
                if offset + v_len > limit:
                    break
                val_bytes = raw[offset : offset + v_len]
                offset += v_len

                history.append((key, val_bytes))
            except Exception:
                break

        # Discover all userIds in order
        user_ids: List[str] = []
        kyc_name_val: Optional[str] = None

        for k, v in history:
            # Whole-word key match: "guid" is not a user id and "userName"/"nickName" is not a KYC name.
            if _is_user_id_key(k):
                val_str = self._extract_clean_string(v)
                if val_str:
                    if val_str in user_ids:
                        user_ids.remove(val_str)  # written again later: the LAST write decides which is active
                    user_ids.append(val_str)
            elif _is_kyc_name_key(k):
                kyc_name_val = self._extract_clean_string(v) or kyc_name_val

        if not user_ids:
            return accounts

        # Last userId is active (Layer 1), prior are superseded historical (Layer 2)
        active_uid = user_ids[-1]
        for uid in user_ids:
            is_active = (uid == active_uid)
            rec_class = (
                ResidualConfidence.ORIGINAL_RECORD
                if is_active
                else ResidualConfidence.HISTORICAL_COMMITTED_RECORD
            )
            storage_type = (
                EvidentiaryStorage.LIVE_RECORD
                if is_active
                else EvidentiaryStorage.MMKV_OR_SLACK
            )

            ev_state = EvidentiaryState(
                existence=EvidentiaryExistence.OBSERVED,
                access=EvidentiaryAccess.PLAINTEXT,
                storage_layer=storage_type,
                provenance_pointer=f"{mmkv_path}::userId::{uid}",
                forensic_group=ForensicGroup.G06_CRYPTO_EXCHANGES_AND_SEEDS,
            )

            acc_rec = CEXAccountProfileRecord(
                exchange_name="Binance",
                fiu_ind_compliance_tier=CEXComplianceTier.GLOBAL_FIU_REGISTERED_VASP,
                source_vfs_file_id=source_vfs_file_id,
                recovery_classification=rec_class,
                cex_user_uid=uid,
                kyc_verified_full_name=kyc_name_val if is_active else None,
                evidentiary_state=ev_state,
            )
            accounts.append(acc_rec)

        return accounts

    def _extract_clean_string(self, raw_bytes: bytes) -> str:
        """Extracts printable string from raw or length-prefixed bytes."""
        if not raw_bytes:
            return ""
        try:
            # Check for inner length prefix
            first_byte = raw_bytes[0]
            if first_byte < len(raw_bytes):
                candidate = raw_bytes[1 : 1 + first_byte].decode("utf-8", errors="ignore")
                if candidate.isprintable():
                    return candidate
            full = raw_bytes.decode("utf-8", errors="ignore")
            # Extract printable portion
            printable = "".join(c for c in full if c.isprintable()).strip()
            return printable
        except Exception:
            return ""

    def _parse_cache_file(
        self, cache_path: str, source_vfs_file_id: int
    ) -> Tuple[List[CEXP2PEscrowOrderRecord], List[CEXTransferRecord]]:
        """Parses compressed or raw HTTP cache files for P2P order JSONs."""
        orders: List[CEXP2PEscrowOrderRecord] = []
        transfers: List[CEXTransferRecord] = []

        try:
            with open(cache_path, "rb") as fh:
                content = fh.read()
        except Exception as exc:
            logger.warning("could not read cache %s: %s", cache_path, exc)
            return orders, transfers

        decompressed_data = content
        # Attempt zlib decompression
        try:
            decompressed_data = zlib.decompress(content)
        except Exception:
            try:
                decompressed_data = zlib.decompress(content, zlib.MAX_WBITS | 16)
            except Exception:
                decompressed_data = content

        try:
            text = decompressed_data.decode("utf-8", errors="ignore")
            json_obj = json.loads(text)
        except Exception:
            # Fallback regex search for JSON inside body
            m = re.search(r"\{.*\}", decompressed_data.decode("utf-8", errors="ignore"), re.S)
            if not m:
                return orders, transfers
            try:
                json_obj = json.loads(m.group(0))
            except Exception as exc:
                logger.warning("cache %s holds no parseable JSON: %s", cache_path, exc)
                return orders, transfers

        data = json_obj.get("data", json_obj) if isinstance(json_obj, dict) else json_obj
        if isinstance(data, list):
            items = data
        else:
            items = [data]

        for item in items:
            if not isinstance(item, dict):
                continue
            order_no = item.get("orderNumber") or item.get("orderId")
            if order_no:
                # A missing tradeType/orderStatus is unknown, not a completed purchase (review R-18).
                t_type = str(item.get("tradeType") or "").upper()
                dir_enum = (
                    CEXP2PTradeDirection.BUY_CRYPTO_PAID_FIAT if t_type == "BUY"
                    else CEXP2PTradeDirection.SELL_CRYPTO_RECEIVED_FIAT if t_type == "SELL"
                    else CEXP2PTradeDirection.UNKNOWN
                )
                status_raw = item.get("orderStatus")
                if status_raw is None:
                    stat_enum = CEXP2POrderStatus.UNKNOWN
                elif status_raw in [4, "COMPLETED"]:
                    stat_enum = CEXP2POrderStatus.COMPLETED_RELEASED
                elif status_raw in [2, "CANCELLED", "CANCELLED_BY_SYSTEM"]:
                    stat_enum = CEXP2POrderStatus.CANCELLED
                elif status_raw in [5, "APPEALING", "IN_APPEAL"]:
                    stat_enum = CEXP2POrderStatus.APPEAL_DISPUTED
                elif str(status_raw).upper() in {"TRADING", "BUYER_PAYED", "DISTRIBUTING", "PENDING"}:
                    stat_enum = CEXP2POrderStatus.IN_ESCROW_PENDING
                else:
                    # An unlisted code is not "in escrow". (The numeric codes above are unverified against a real export.)
                    stat_enum = CEXP2POrderStatus.UNKNOWN

                asset = str(item.get("asset") or "")          # absent = not recorded, never USDT by default
                qty = _to_float(item.get("amount") or item.get("notifyTokenAmount"))
                fiat_curr = str(item.get("fiatUnit") or "")   # absent = not recorded, never INR by default
                total_fiat = _to_float(item.get("totalPrice"))
                rate = _to_float(item.get("unitPrice")) if item.get("unitPrice") else None

                seller_nick = item.get("sellerNickname")
                seller_uid = item.get("sellerUserNo")
                seller_name = item.get("sellerRealName")

                buyer_nick = item.get("buyerNickname")
                buyer_uid = item.get("buyerUserNo")
                buyer_name = item.get("buyerRealName")

                counter_nick = seller_nick if t_type == "BUY" else (buyer_nick if t_type == "SELL" else None)
                counter_uid = seller_uid if t_type == "BUY" else (buyer_uid if t_type == "SELL" else None)
                counter_name = seller_name if t_type == "BUY" else (buyer_name if t_type == "SELL" else None)

                # Extract counterparty payment method
                pay_method = item.get("payMethod")
                if not isinstance(pay_method, dict):
                    pay_method = {}
                rail = pay_method.get("tradeMethodName") or None   # absent = not recorded, never "UPI" by default
                fields = pay_method.get("fields")
                if not isinstance(fields, dict):
                    fields = {}
                vpa = fields.get("upiId") or fields.get("vpa") or fields.get("accountNo")

                iso_created = _ts_iso(item.get("createTime"))  # "" = not recorded; never the time of analysis

                ev_state = EvidentiaryState(
                    existence=EvidentiaryExistence.OBSERVED,
                    access=EvidentiaryAccess.PLAINTEXT,
                    storage_layer=EvidentiaryStorage.LIVE_RECORD,
                    provenance_pointer=f"{cache_path}::p2p_order::{order_no}",
                    forensic_group=ForensicGroup.G06_CRYPTO_EXCHANGES_AND_SEEDS,
                )

                order_rec = CEXP2PEscrowOrderRecord(
                    exchange_name="Binance P2P",
                    source_vfs_file_id=source_vfs_file_id,
                    p2p_order_number=str(order_no),
                    trade_direction=dir_enum,
                    order_status=stat_enum,
                    crypto_asset=asset,
                    crypto_quantity_decimal=qty,
                    fiat_currency=fiat_curr,
                    fiat_total_amount=total_fiat,
                    unit_exchange_rate=rate,
                    counterparty_cex_uid_nick=f"{counter_uid} ({counter_nick})" if counter_uid else counter_nick,
                    counterparty_verified_kyc_name=counter_name,
                    fiat_payment_rail=rail,
                    counterparty_vpa_or_bank_ifsc=vpa,
                    order_created_utc_iso=iso_created,
                    evidentiary_state=ev_state,
                )
                orders.append(order_rec)

        return orders, transfers

    def parse_chat_message(
        self,
        order_number: str,
        sender_uid: str,
        sender_nick: str,
        message_text: str,
        timestamp_ms: int = 0,
        source_vfs_file_id: int = 0,
    ) -> CEXP2PChatMessageRecord:
        """Parses a P2P escrow chat message and extracts phone numbers and UTRs via regex."""
        extracted_tokens: List[str] = []

        # Find 10-digit mobile phone numbers
        phones = INDIAN_MOBILE_REGEX.findall(message_text)
        extracted_tokens.extend(phones)

        # Find 12-digit UTR numbers
        utrs = NPCI_12_DIGIT_UTR_REGEX.findall(message_text)
        extracted_tokens.extend(utrs)

        # Find VPAs
        vpas = VPA_REGEX.findall(message_text)
        extracted_tokens.extend(vpas)

        extracted_summary = ", ".join(dict.fromkeys(extracted_tokens)) if extracted_tokens else None

        if timestamp_ms > 10_000_000_000:
            ts_iso = ForensicTimestamp.from_unix_milliseconds(timestamp_ms).utc_iso8601
        elif timestamp_ms > 0:
            ts_iso = ForensicTimestamp.from_unix_seconds(timestamp_ms).utc_iso8601
        else:
            ts_iso = ""  # not recorded: never substitute the time of analysis

        ev_state = EvidentiaryState(
            existence=EvidentiaryExistence.OBSERVED,
            access=EvidentiaryAccess.PLAINTEXT,
            storage_layer=EvidentiaryStorage.LIVE_RECORD,
            provenance_pointer=f"chat::{order_number}::{sender_uid}",
            forensic_group=ForensicGroup.G06_CRYPTO_EXCHANGES_AND_SEEDS,
        )

        return CEXP2PChatMessageRecord(
            p2p_order_number=order_number,
            exchange_name="Binance P2P",
            sender_uid_and_nickname=f"{sender_uid} ({sender_nick})",
            message_type="TEXT",
            message_text_or_image_url=message_text,
            extracted_phone_utr_or_vpa=extracted_summary,
            sent_utc_iso=ts_iso,
            evidentiary_state=ev_state,
        )

    def evaluate_third_party_triangulation(
        self,
        cex_owner_kyc_name: str,
        phase3_payer_cbs_name: str,
    ) -> bool:
        """
        Returns True when the two names do NOT match. That is a LEAD for the examiner to check, not proof of
        third-party payment: initials, name order, "Mohd"/"Mohammed" and middle names all produce a mismatch.
        Returns False both when the names match and when either name is missing (cannot tell).
        """
        if not cex_owner_kyc_name or not phase3_payer_cbs_name:
            return False

        def normalize_name(n: str) -> str:
            cleaned = re.sub(r"\b(mr|mrs|ms|dr|shri|smt)\b", "", n, flags=re.I)
            cleaned = re.sub(r"[^a-zA-Z\s]", "", cleaned)
            return " ".join(cleaned.lower().split())

        norm_cex = normalize_name(cex_owner_kyc_name)
        norm_payer = normalize_name(phase3_payer_cbs_name)

        # Check exact or token subset match
        if norm_cex == norm_payer:
            return False

        cex_tokens = set(norm_cex.split())
        payer_tokens = set(norm_payer.split())

        # If names share significant tokens, consider them matching
        if cex_tokens and payer_tokens and (cex_tokens.issubset(payer_tokens) or payer_tokens.issubset(cex_tokens)):
            return False

        # Names differ: a lead worth checking, not a finding
        return True

    def parse_transfer_record(
        self,
        transfer_dict: Dict[str, Any],
        is_offchain_pay: bool = False,
        local_web3_lookup: Optional[Dict[str, int]] = None,
        source_vfs_file_id: int = 0,
    ) -> CEXTransferRecord:
        """
        Parses on-chain withdrawals or off-chain Binance Pay transfers,
        linking on-chain addresses to local Web3 self-custody wallets if matched.
        """
        lookup = local_web3_lookup or {}

        if is_offchain_pay:
            order_id = str(transfer_dict.get("orderId") or transfer_dict.get("id") or "")
            receiver_uid = str(transfer_dict.get("receiverUid") or "")
            amt = _to_float(transfer_dict.get("amount"))
            asset = str(transfer_dict.get("currency") or "")
            ts_iso = _ts_iso(transfer_dict.get("transactionTime"))

            ev_state = EvidentiaryState(
                existence=EvidentiaryExistence.OBSERVED,
                access=EvidentiaryAccess.PLAINTEXT,
                storage_layer=EvidentiaryStorage.LIVE_RECORD,
                provenance_pointer=f"binance_pay::{order_id}",
                forensic_group=ForensicGroup.G06_CRYPTO_EXCHANGES_AND_SEEDS,
            )

            return CEXTransferRecord(
                exchange_name="Binance",
                source_vfs_file_id=source_vfs_file_id,
                transfer_category=CEXTransferCategory.OFFCHAIN_BINANCE_PAY_OR_UID_TRANSFER,
                asset_or_currency=asset,
                network_or_rail="BINANCE_PAY_INTERNAL",
                amount_decimal=amt,
                txid_or_internal_pay_order_id=order_id,
                destination_wallet_or_peer_uid=receiver_uid,
                transfer_utc_iso=ts_iso,
                evidentiary_state=ev_state,
            )
        else:
            txid = str(transfer_dict.get("txId") or transfer_dict.get("hash") or "")
            address = str(transfer_dict.get("address") or "")
            amt = _to_float(transfer_dict.get("amount"))
            asset = str(transfer_dict.get("asset") or "")
            raw_network = str(transfer_dict.get("network") or "").upper()   # absent = not recorded, never TRON by default

            network_str = "TRC20" if raw_network in ["TRX", "TRON", "TRC20"] else raw_network
            ts_iso = _ts_iso(transfer_dict.get("applyTime"))

            matched_web3_uid = lookup.get(address)
            if matched_web3_uid is None and address.lower().startswith("0x"):
                # EVM addresses are case-insensitive (checksum casing is only a typo guard)
                matched_web3_uid = {k.lower(): v for k, v in lookup.items()}.get(address.lower())

            ev_state = EvidentiaryState(
                existence=EvidentiaryExistence.OBSERVED,
                access=EvidentiaryAccess.PLAINTEXT,
                storage_layer=EvidentiaryStorage.LIVE_RECORD,
                provenance_pointer=f"onchain::{txid}",
                forensic_group=ForensicGroup.G06_CRYPTO_EXCHANGES_AND_SEEDS,
            )

            return CEXTransferRecord(
                exchange_name="Binance",
                source_vfs_file_id=source_vfs_file_id,
                transfer_category=CEXTransferCategory.ONCHAIN_CRYPTO_WITHDRAWAL,
                asset_or_currency=asset,
                network_or_rail=network_str,
                amount_decimal=amt,
                txid_or_internal_pay_order_id=txid,
                destination_wallet_or_peer_uid=address,
                matches_local_web3_wallet_uid=matched_web3_uid,
                transfer_utc_iso=ts_iso,
                evidentiary_state=ev_state,
            )

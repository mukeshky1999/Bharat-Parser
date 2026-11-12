"""
Decoupled Plugin Manifest Architecture & App Signature Registry.
Supports 42+ Indian UPI, Banking, Wallet, and Crypto applications
across both Android and iOS platforms.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class AppPlugin:
    app_name: str
    category: str  # 'fiat' or 'crypto'
    bundle_ids: List[str] = field(default_factory=list)
    android_pkgs: List[str] = field(default_factory=list)
    aliases: List[str] = field(default_factory=list)
    preferred_tables: List[str] = field(default_factory=list)
    amount_cols: List[str] = field(default_factory=list)
    date_cols: List[str] = field(default_factory=list)
    counterparty_cols: List[str] = field(default_factory=list)
    txid_cols: List[str] = field(default_factory=list)
    status_cols: List[str] = field(default_factory=list)
    blob_cols: List[str] = field(default_factory=list)
    amount_divisor: float = 1.0
    json_amount_divisor: float = 1.0
    timestamp_epoch: str = "auto"


BUILTIN_MANIFESTS: List[Dict[str, Any]] = [
    # 1. PhonePe
    {
        "app_name": "PhonePe",
        "category": "fiat",
        "bundle_ids": ["com.phonepe.PhonePeApp", "com.phonepe.iosapp", "group.com.phonepe", "com.phonepe.business"],
        "android_pkgs": ["com.phonepe.app", "com.phonepe.app.beta", "com.phonepe.app.preprod", "com.phonepe.app.business"],
        "aliases": ["phonepe"],
        "preferred_tables": [
            "ZTRANSACTIONENTITY", "TRANSACTION_HISTORY", "transaction_history",
            "ZTRANSACTION", "transactions", "P2P_TRANSACTIONS", "workflow_table",
            "statement_transaction", "upi_transactions", "rkstorage", "catalystLocalStorage"
        ],
        "amount_cols": ["ZAMOUNT", "AMOUNT", "amount", "z_amount", "txnamount", "amount_in_paise", "amountInPaise"],
        "date_cols": ["ZCREATEDAT", "ZDATE", "DATE", "timestamp", "created_at", "updated_at", "creationTime"],
        "counterparty_cols": ["ZPAYEENAME", "ZCOUNTERPARTY", "counterparty", "payee", "ZPAYEEVPA", "payee_vpa", "payer_vpa", "merchant_name"],
        "txid_cols": ["ZTRANSACTIONID", "ZTRANSACTIONREFERENCEID", "transaction_id", "txn_id", "utr", "bank_ref_no"],
        "status_cols": ["ZSTATUS", "STATUS", "status", "state", "transaction_status"],
        "blob_cols": ["ZDATA", "ZDETAILS", "data", "payload", "value", "transaction_data"],
        "amount_divisor": 100.0,
        "json_amount_divisor": 100.0,
        "timestamp_epoch": "auto"
    },
    # 2. Google Pay (Tez)
    {
        "app_name": "Google Pay",
        "category": "fiat",
        "bundle_ids": ["com.google.Tez", "com.google.ios.pay", "com.google.pay", "group.com.google.Tez", "com.google.paisa"],
        "android_pkgs": ["com.google.android.apps.nbu.paisa.user", "com.google.android.apps.nbu.paisa.merchant", "com.google.android.apps.walletnfcrel"],
        "aliases": ["google pay", "gpay", "tez", "paisa", "nbu.paisa"],
        "preferred_tables": [
            "transactions", "txn_history", "upi_transactions", "tez_transactions",
            "feed_items", "sync_entities", "purchase_orders", "payment_transactions",
            "ZTRANSACTION", "ZFEEDITEM", "money_transfer", "vpa_records"
        ],
        "amount_cols": ["amount", "total_amount", "txn_amount", "amount_minor", "amount_micros", "ZAMOUNT"],
        "date_cols": ["timestamp", "created_at", "txn_time", "time_created", "last_modified_timestamp", "ZTIMESTAMP"],
        "counterparty_cols": ["counterparty", "payee_vpa", "receiver_vpa", "counterparty_id", "counterparty_name", "title", "ZCOUNTERPARTY"],
        "txid_cols": ["transaction_id", "txn_id", "upi_txn_id", "reference_id", "utr", "ZTRANSACTIONID"],
        "status_cols": ["status", "txn_status", "state", "ZSTATUS"],
        "blob_cols": ["payload", "blob", "item", "feed_payload", "sync_payload", "proto_bytes", "data", "ZPAYLOAD"],
        "amount_divisor": 100.0,
        "json_amount_divisor": 100.0,
        "timestamp_epoch": "unix_ms"
    },
    # 3. Paytm
    {
        "app_name": "Paytm",
        "category": "fiat",
        "bundle_ids": ["net.one97.paytm", "group.net.one97.paytm", "com.paytm.business"],
        "android_pkgs": ["net.one97.paytm", "net.one97.paytm.business", "com.paytm.merchants"],
        "aliases": ["paytm", "one97"],
        "preferred_tables": [
            "payments", "paytm_payments", "transactions", "passbook_entries",
            "order_history", "upi_transactions", "wallet_transactions",
            "ZTRANSACTION", "ZPASSBOOKENTRY", "rkstorage"
        ],
        "amount_cols": ["txn_amount", "amount", "amt", "paid_amount", "ZAMOUNT"],
        "date_cols": ["txn_date", "created_at", "timestamp", "txn_time", "ZDATE", "ZCREATEDAT"],
        "counterparty_cols": ["payee_vpa", "counterparty", "heading", "narration", "merchant_name", "ZPAYEE"],
        "txid_cols": ["txn_id", "order_id", "transaction_id", "utr", "rrn", "ZTXNID"],
        "status_cols": ["txn_status", "status", "order_status", "ZSTATUS"],
        "blob_cols": ["payload", "data", "response_data", "value"],
        "amount_divisor": 1.0,
        "json_amount_divisor": 1.0,
        "timestamp_epoch": "auto"
    },
    # 4. BHIM UPI
    {
        "app_name": "BHIM UPI",
        "category": "fiat",
        "bundle_ids": ["in.org.npci.upiapp", "group.in.org.npci.upiapp", "com.npci.bhim"],
        "android_pkgs": ["in.org.npci.upiapp"],
        "aliases": ["bhim", "npci"],
        "preferred_tables": ["transactions", "tx_history", "upi_transactions", "pending_transactions", "rkstorage", "ZTRANSACTION"],
        "amount_cols": ["amount", "txn_amount", "transfer_amount", "ZAMOUNT"],
        "date_cols": ["timestamp", "date", "created_at", "txn_time", "ZDATE"],
        "counterparty_cols": ["payee_vpa", "vpa", "counterparty", "beneficiary_name", "payer_vpa"],
        "txid_cols": ["txn_id", "transaction_id", "rrn", "utr"],
        "status_cols": ["status", "state", "txn_status"],
        "blob_cols": ["payload", "data", "value"],
        "amount_divisor": 1.0,
        "timestamp_epoch": "auto"
    },
    # 5. CRED
    {
        "app_name": "CRED",
        "category": "fiat",
        "bundle_ids": ["com.dreamplug.spend", "com.dreamplug.cred", "group.com.dreamplug"],
        "android_pkgs": ["com.dreamplug.androidapp", "com.dreamplug.android", "com.dreamplug.spend"],
        "aliases": ["cred", "dreamplug"],
        "preferred_tables": ["transactions", "payments", "card_payments", "upi_transactions", "cashflow_transactions", "ZTRANSACTION"],
        "amount_cols": ["amount", "total_amount", "bill_amount", "txn_amount"],
        "date_cols": ["timestamp", "created_at", "date", "txn_date"],
        "counterparty_cols": ["merchant", "counterparty", "payee", "payee_vpa", "title"],
        "txid_cols": ["transaction_id", "txn_id", "payment_id", "utr", "rrn"],
        "status_cols": ["status", "payment_status", "state"],
        "blob_cols": ["data", "payload", "metadata"],
        "amount_divisor": 1.0,
        "timestamp_epoch": "auto"
    },
    # 6. Amazon Pay / Amazon Shopping
    {
        "app_name": "Amazon Pay",
        "category": "fiat",
        "bundle_ids": ["com.amazon.Amazon", "com.amazon.AmazonIN", "com.amazon.mp3", "group.com.amazon"],
        "android_pkgs": ["in.amazon.mShop.android.shopping", "com.amazon.mShop.android.shopping"],
        "aliases": ["amazon", "amazonpay", "mshop"],
        "preferred_tables": ["transactions", "payments", "order_history", "apay_transactions", "upi_transactions"],
        "amount_cols": ["amount", "total_amount", "paid_amount", "txn_amount"],
        "date_cols": ["timestamp", "order_date", "created_at", "date"],
        "counterparty_cols": ["merchant", "seller", "payee", "payee_vpa", "counterparty"],
        "txid_cols": ["order_id", "txn_id", "payment_id", "utr"],
        "status_cols": ["status", "order_status"],
        "blob_cols": ["payload", "data", "value"],
        "amount_divisor": 1.0,
        "timestamp_epoch": "auto"
    },
    # 7. WhatsApp & WhatsApp Business (WhatsApp Pay)
    {
        "app_name": "WhatsApp",
        "category": "fiat",
        "bundle_ids": ["net.whatsapp.WhatsApp", "net.whatsapp.WhatsAppSMB", "group.net.whatsapp.WhatsApp.shared"],
        "android_pkgs": ["com.whatsapp", "com.whatsapp.w4b"],
        "aliases": ["whatsapp"],
        "preferred_tables": ["pay_transaction", "pay_transactions", "transactions", "message_payment", "ZWAPAYMENTTRANSACTION", "message", "message_view", "messages", "ZWAMESSAGE"],
        "amount_cols": ["amount_1000", "amount", "ZAMOUNT1000", "ZAMOUNT"],
        "date_cols": ["timestamp", "init_timestamp", "received_timestamp", "ZTIMESTAMP", "ZMESSAGEDATE"],
        "counterparty_cols": ["remote_jid", "key_remote_jid", "sender_jid", "receiver_jid", "ZFROMJID", "ZTOJID"],
        "txid_cols": ["id", "key_id", "bank_transaction_id", "_id", "ZTRANSACTIONID", "ZSTANZAID"],
        "status_cols": ["status", "ZSTATUS", "message_type"],
        "blob_cols": ["future_data", "metadata", "data", "ZMETADATA"],
        "amount_divisor": 1000.0,
        "timestamp_epoch": "auto"
    },
    # 8. Super.money (Flipkart UPI)
    {
        "app_name": "Super.money",
        "category": "fiat",
        "bundle_ids": ["money.super.app", "com.supermoney.ios"],
        "android_pkgs": ["money.super.payments", "com.supermoney"],
        "aliases": ["super.money", "supermoney"],
        "preferred_tables": ["transactions", "upi_transactions", "payments", "rkstorage"],
        "amount_cols": ["amount", "txn_amount"],
        "date_cols": ["timestamp", "created_at", "date"],
        "counterparty_cols": ["payee_vpa", "counterparty", "merchant_name"],
        "txid_cols": ["txn_id", "utr", "rrn", "transaction_id"],
        "status_cols": ["status"],
        "blob_cols": ["data", "payload", "value"],
        "amount_divisor": 1.0,
        "timestamp_epoch": "auto"
    },
    # 9. Navi UPI
    {
        "app_name": "Navi",
        "category": "fiat",
        "bundle_ids": ["com.naviapp", "group.com.naviapp"],
        "android_pkgs": ["com.naviapp"],
        "aliases": ["navi"],
        "preferred_tables": ["transactions", "upi_transactions", "payment_history", "rkstorage"],
        "amount_cols": ["amount", "txn_amount"],
        "date_cols": ["timestamp", "date", "created_at"],
        "counterparty_cols": ["payee_name", "vpa", "payee_vpa", "counterparty"],
        "txid_cols": ["txn_id", "utr", "rrn", "transaction_id"],
        "status_cols": ["status"],
        "blob_cols": ["data", "payload", "value"],
        "amount_divisor": 1.0,
        "timestamp_epoch": "auto"
    },
    # 10. Jupiter Money
    {
        "app_name": "Jupiter",
        "category": "fiat",
        "bundle_ids": ["money.jupiter.ios", "space.amica.jupiter"],
        "android_pkgs": ["money.jupiter", "space.amica.jupiter"],
        "aliases": ["jupiter"],
        "preferred_tables": ["transactions", "upi_transactions", "account_statement", "rkstorage"],
        "amount_cols": ["amount", "txn_amount"],
        "date_cols": ["timestamp", "created_at", "txn_date"],
        "counterparty_cols": ["payee_vpa", "counterparty", "merchant", "narration"],
        "txid_cols": ["txn_id", "utr", "rrn", "transaction_id"],
        "status_cols": ["status"],
        "blob_cols": ["data", "payload", "value"],
        "amount_divisor": 1.0,
        "timestamp_epoch": "auto"
    },
    # 11. Fi Money (EpiFi)
    {
        "app_name": "Fi Money",
        "category": "fiat",
        "bundle_ids": ["com.epifi.fi", "money.fi.app"],
        "android_pkgs": ["com.epifi.paisa", "money.fi.app"],
        "aliases": ["epifi", "fimoney"],
        "preferred_tables": ["transactions", "upi_transactions", "ledger_entries"],
        "amount_cols": ["amount", "txn_amount"],
        "date_cols": ["timestamp", "created_at", "date"],
        "counterparty_cols": ["counterparty", "payee_vpa", "merchant_name", "narration"],
        "txid_cols": ["txn_id", "utr", "transaction_id"],
        "status_cols": ["status"],
        "blob_cols": ["data", "payload"],
        "amount_divisor": 1.0,
        "timestamp_epoch": "auto"
    },
    # 12. Slice
    {
        "app_name": "Slice",
        "category": "fiat",
        "bundle_ids": ["com.slicepay.Slice", "group.com.slicepay.Slice"],
        "android_pkgs": ["indwin.c3.shareapp", "com.slicepay.Slice", "com.slicepay"],
        "aliases": ["slice", "slicepay", "indwin"],
        "preferred_tables": ["transactions", "passbook", "upi_transactions", "rkstorage"],
        "amount_cols": ["amount", "total_amount", "txn_amount"],
        "date_cols": ["timestamp", "created_at", "date"],
        "counterparty_cols": ["merchant_name", "payee", "payee_vpa", "counterparty"],
        "txid_cols": ["transaction_id", "txn_id", "utr"],
        "status_cols": ["status"],
        "blob_cols": ["data", "payload", "value"],
        "amount_divisor": 1.0,
        "timestamp_epoch": "auto"
    },
    # 13. MobiKwik
    {
        "app_name": "MobiKwik",
        "category": "fiat",
        "bundle_ids": ["com.mobikwik", "com.mobikwik.ios", "group.com.mobikwik"],
        "android_pkgs": ["com.mobikwik_new", "com.mobikwik.android"],
        "aliases": ["mobikwik"],
        "preferred_tables": ["transactions", "history", "wallet_history", "upi_transactions"],
        "amount_cols": ["amount", "txnamount", "txn_amount"],
        "date_cols": ["date", "time", "timestamp", "created_at"],
        "counterparty_cols": ["payee", "counterparty", "merchant", "payee_vpa"],
        "txid_cols": ["txnid", "orderid", "utr", "transaction_id"],
        "status_cols": ["status"],
        "blob_cols": ["data", "payload"],
        "amount_divisor": 1.0,
        "timestamp_epoch": "auto"
    },
    # 14. Freecharge
    {
        "app_name": "Freecharge",
        "category": "fiat",
        "bundle_ids": ["com.freecharge.ios", "com.freecharge", "group.com.freecharge"],
        "android_pkgs": ["com.freecharge.android", "com.freecharge"],
        "aliases": ["freecharge"],
        "preferred_tables": ["transactions", "wallet_transactions", "upi_transactions"],
        "amount_cols": ["amount", "total", "txn_amount"],
        "date_cols": ["created_at", "timestamp", "date"],
        "counterparty_cols": ["payee", "counterparty", "payee_vpa"],
        "txid_cols": ["txn_id", "transaction_id", "utr"],
        "status_cols": ["status"],
        "blob_cols": ["data", "payload"],
        "amount_divisor": 1.0,
        "timestamp_epoch": "auto"
    },
    # 15. Airtel Thanks (Airtel Payments Bank)
    {
        "app_name": "Airtel Thanks",
        "category": "fiat",
        "bundle_ids": ["com.airtel.myairtel", "group.com.airtel.myairtel"],
        "android_pkgs": ["com.myairtelapp", "com.airtel.thanks"],
        "aliases": ["airtel", "myairtel"],
        "preferred_tables": ["transactions", "payment_history", "upi_transactions", "rkstorage"],
        "amount_cols": ["amount", "txn_amount"],
        "date_cols": ["timestamp", "date", "created_at"],
        "counterparty_cols": ["payee", "counterparty", "payee_vpa", "narration"],
        "txid_cols": ["transaction_id", "ref_id", "utr", "txn_id"],
        "status_cols": ["status"],
        "blob_cols": ["data", "payload", "value"],
        "amount_divisor": 1.0,
        "timestamp_epoch": "auto"
    },
    # 16. JioFinance / MyJio (Jio Payments Bank)
    {
        "app_name": "JioFinance",
        "category": "fiat",
        "bundle_ids": ["com.jio.finance", "com.ril.jio.paymentsbank", "group.com.jio.finance", "com.jio.myjio"],
        "android_pkgs": ["com.jio.finance", "com.ril.jio.paymentsbank", "com.jio.myjio", "com.jio.jiopay"],
        "aliases": ["jiofinance", "jiopay", "paymentsbank", "myjio"],
        "preferred_tables": ["transactions", "upi_history", "payment_transactions", "rkstorage"],
        "amount_cols": ["amount", "txn_amount"],
        "date_cols": ["timestamp", "date", "created_at"],
        "counterparty_cols": ["counterparty", "payee_vpa", "payee"],
        "txid_cols": ["transaction_id", "rrn", "utr", "txn_id"],
        "status_cols": ["status"],
        "blob_cols": ["data", "payload", "value"],
        "amount_divisor": 1.0,
        "timestamp_epoch": "auto"
    },
    # 17. BharatPe
    {
        "app_name": "BharatPe",
        "category": "fiat",
        "bundle_ids": ["com.bharatpe", "group.com.bharatpe", "com.bharatpe.ios"],
        "android_pkgs": ["com.bharatpe.app", "com.bharatpe.merchant"],
        "aliases": ["bharatpe"],
        "preferred_tables": ["transactions", "settlements", "upi_transactions", "rkstorage"],
        "amount_cols": ["amount", "settlement_amount", "txn_amount"],
        "date_cols": ["timestamp", "date", "created_at"],
        "counterparty_cols": ["payer_name", "payer_vpa", "counterparty", "payee_vpa"],
        "txid_cols": ["txn_id", "rrn", "utr", "transaction_id"],
        "status_cols": ["status"],
        "blob_cols": ["data", "payload", "value"],
        "amount_divisor": 1.0,
        "timestamp_epoch": "auto"
    },
    # 18. FamPay / FamApp
    {
        "app_name": "FamPay",
        "category": "fiat",
        "bundle_ids": ["com.fampay.in", "in.fampay.app"],
        "android_pkgs": ["com.fampay.in"],
        "aliases": ["fampay", "famapp"],
        "preferred_tables": ["transactions", "upi_transactions", "passbook", "rkstorage"],
        "amount_cols": ["amount", "txn_amount"],
        "date_cols": ["timestamp", "created_at", "date"],
        "counterparty_cols": ["payee_vpa", "counterparty", "title", "payee"],
        "txid_cols": ["txn_id", "utr", "transaction_id"],
        "status_cols": ["status"],
        "blob_cols": ["data", "payload", "value"],
        "amount_divisor": 1.0,
        "timestamp_epoch": "auto"
    },
    # 19. Bajaj Finserv
    {
        "app_name": "Bajaj Finserv",
        "category": "fiat",
        "bundle_ids": ["com.bajajfinserv.in", "org.bajajfinserv.app"],
        "android_pkgs": ["org.altruist.BajajExperia", "com.bajajfinserv.upi"],
        "aliases": ["bajaj", "bajajexperia", "bajajfinserv"],
        "preferred_tables": ["transactions", "upi_transactions", "payment_history", "rkstorage"],
        "amount_cols": ["amount", "txn_amount"],
        "date_cols": ["timestamp", "date", "created_at"],
        "counterparty_cols": ["payee_vpa", "counterparty", "payee_name"],
        "txid_cols": ["txn_id", "utr", "rrn", "transaction_id"],
        "status_cols": ["status"],
        "blob_cols": ["data", "payload", "value"],
        "amount_divisor": 1.0,
        "timestamp_epoch": "auto"
    },
    # 20. Tata Neu
    {
        "app_name": "Tata Neu",
        "category": "fiat",
        "bundle_ids": ["com.tatadigital.tcp", "com.tatadigital.neu"],
        "android_pkgs": ["com.tatadigital.tcp"],
        "aliases": ["tataneu", "tatadigital"],
        "preferred_tables": ["transactions", "upi_transactions", "payments", "rkstorage"],
        "amount_cols": ["amount", "txn_amount"],
        "date_cols": ["timestamp", "date", "created_at"],
        "counterparty_cols": ["payee_vpa", "counterparty", "merchant_name"],
        "txid_cols": ["txn_id", "utr", "order_id"],
        "status_cols": ["status"],
        "blob_cols": ["data", "payload", "value"],
        "amount_divisor": 1.0,
        "timestamp_epoch": "auto"
    },
    # 21. Samsung Pay / Samsung Wallet
    {
        "app_name": "Samsung Wallet",
        "category": "fiat",
        "bundle_ids": [],
        "android_pkgs": ["com.samsung.android.spay", "com.samsung.android.spaymini"],
        "aliases": ["spay", "samsungpay"],
        "preferred_tables": ["transactions", "upi_transactions", "history", "payment_history"],
        "amount_cols": ["amount", "txn_amount"],
        "date_cols": ["timestamp", "date", "created_at"],
        "counterparty_cols": ["payee_vpa", "counterparty", "merchant_name"],
        "txid_cols": ["txn_id", "utr", "rrn", "transaction_id"],
        "status_cols": ["status"],
        "blob_cols": ["data", "payload"],
        "amount_divisor": 1.0,
        "timestamp_epoch": "auto"
    },
    # 22. YONO SBI & YONO Lite SBI
    {
        "app_name": "YONO SBI",
        "category": "fiat",
        "bundle_ids": ["com.sbi.yono", "com.sbi.yono.lite", "group.com.sbi.yono", "com.sbi.lotusintouch"],
        "android_pkgs": ["com.sbi.lotusintouch", "com.sbi.yono", "com.sbi.SBIFreedomPlus", "com.sbi.upi"],
        "aliases": ["yono", "lotusintouch", "sbifreedom", "bhim sbi pay"],
        "preferred_tables": ["transactions", "m_passbook", "account_transactions", "upi_transactions", "passbook"],
        "amount_cols": ["txn_amount", "amount", "trans_amount", "debit_amount", "credit_amount"],
        "date_cols": ["txn_date", "post_date", "date", "value_date", "timestamp"],
        "counterparty_cols": ["narration", "desc", "description", "counterparty", "payee_vpa", "particulars"],
        "txid_cols": ["ref_no", "journal_no", "txn_id", "utr", "rrn"],
        "status_cols": ["status", "txn_status"],
        "blob_cols": ["data", "payload"],
        "amount_divisor": 1.0,
        "timestamp_epoch": "auto"
    },
    # 23. iMobile Pay (ICICI Bank)
    {
        "app_name": "iMobile (ICICI)",
        "category": "fiat",
        "bundle_ids": ["com.icicibank.imobile", "com.icicibank.pockets"],
        "android_pkgs": ["com.csam.icici.bank.imobile", "com.icicibank.pockets"],
        "aliases": ["imobile", "icici"],
        "preferred_tables": ["transactions", "account_statement", "upi_transactions", "recent_transactions"],
        "amount_cols": ["amount", "txn_amount", "trans_amount"],
        "date_cols": ["txn_date", "value_date", "date", "timestamp"],
        "counterparty_cols": ["remarks", "particulars", "payee", "payee_vpa", "narration"],
        "txid_cols": ["reference_id", "cheque_no", "utr", "rrn", "txn_id"],
        "status_cols": ["status"],
        "blob_cols": ["data", "payload"],
        "amount_divisor": 1.0,
        "timestamp_epoch": "auto"
    },
    # 24. HDFC Bank MobileBanking & PayZapp
    {
        "app_name": "HDFC & PayZapp",
        "category": "fiat",
        "bundle_ids": ["com.hdfcbank.payzapp", "com.hdfcbank.mobilebanking", "com.hdfcbank.now"],
        "android_pkgs": ["com.hdfcbank.payzapp", "com.snapwork.hdfc", "com.hdfcbank.android.now"],
        "aliases": ["payzapp", "hdfcbank", "snapwork.hdfc"],
        "preferred_tables": ["transactions", "statement", "upi_transactions", "passbook", "rkstorage"],
        "amount_cols": ["amount", "txn_amount", "withdrawal_amt", "deposit_amt"],
        "date_cols": ["date", "timestamp", "txn_date", "value_date"],
        "counterparty_cols": ["narration", "payee_name", "payee_vpa", "counterparty", "description"],
        "txid_cols": ["ref_id", "transaction_id", "utr", "rrn", "chq_ref_no"],
        "status_cols": ["status"],
        "blob_cols": ["data", "payload", "value"],
        "amount_divisor": 1.0,
        "timestamp_epoch": "auto"
    },
    # 25. Axis Mobile
    {
        "app_name": "Axis Mobile",
        "category": "fiat",
        "bundle_ids": ["com.axisbank.mobilebanking", "com.axis.mobile"],
        "android_pkgs": ["com.axis.mobile", "com.axis.netbanking"],
        "aliases": ["axismobile", "axis.mobile", "axisbank"],
        "preferred_tables": ["transactions", "account_statement", "upi_transactions", "mini_statement"],
        "amount_cols": ["amount", "txn_amount"],
        "date_cols": ["txn_date", "date", "timestamp"],
        "counterparty_cols": ["particulars", "narration", "payee_vpa", "counterparty"],
        "txid_cols": ["utr", "rrn", "txn_id", "reference_id"],
        "status_cols": ["status"],
        "blob_cols": ["data", "payload"],
        "amount_divisor": 1.0,
        "timestamp_epoch": "auto"
    },
    # 26. Kotak 811
    {
        "app_name": "Kotak 811",
        "category": "fiat",
        "bundle_ids": ["com.kotak.mobilebanking", "com.kotak.bank"],
        "android_pkgs": ["com.msf.kbank.mobile", "com.kotak.neo"],
        "aliases": ["kotak", "kbank"],
        "preferred_tables": ["transactions", "account_activity", "upi_transactions", "statement"],
        "amount_cols": ["amount", "txn_amount"],
        "date_cols": ["txn_date", "date", "timestamp"],
        "counterparty_cols": ["description", "payee", "payee_vpa", "narration"],
        "txid_cols": ["ref_num", "txn_id", "utr", "rrn"],
        "status_cols": ["status"],
        "blob_cols": ["data", "payload"],
        "amount_divisor": 1.0,
        "timestamp_epoch": "auto"
    },
    # 27. bob World (Bank of Baroda)
    {
        "app_name": "bob World (BoB)",
        "category": "fiat",
        "bundle_ids": ["com.bankofbaroda.mconnect", "in.co.bankofbaroda.mpassbook"],
        "android_pkgs": ["com.bankofbaroda.mconnect", "com.baroda.mpassbook", "com.bankofbaroda.upi"],
        "aliases": ["bankofbaroda", "bobworld", "mconnect"],
        "preferred_tables": ["transactions", "passbook", "m_passbook", "upi_transactions", "account_statement"],
        "amount_cols": ["amount", "txn_amount", "tran_amt"],
        "date_cols": ["txn_date", "tran_date", "date", "timestamp"],
        "counterparty_cols": ["narration", "particulars", "remarks", "payee_vpa"],
        "txid_cols": ["tran_id", "txn_id", "utr", "rrn", "ref_no"],
        "status_cols": ["status"],
        "blob_cols": ["data", "payload"],
        "amount_divisor": 1.0,
        "timestamp_epoch": "auto"
    },
    # 28. PNB One (Punjab National Bank)
    {
        "app_name": "PNB One",
        "category": "fiat",
        "bundle_ids": ["com.pnb.pnbone", "in.co.pnb.mpassbook"],
        "android_pkgs": ["com.Version1", "com.pnb.mPassbook", "com.fss.pnbpsp"],
        "aliases": ["pnbone", "pnbpsp", "pnb.mpassbook"],
        "preferred_tables": ["transactions", "passbook", "statement", "upi_transactions"],
        "amount_cols": ["amount", "txn_amount", "tran_amount"],
        "date_cols": ["txn_date", "date", "timestamp"],
        "counterparty_cols": ["narration", "particulars", "remarks", "payee_vpa"],
        "txid_cols": ["txn_id", "utr", "rrn", "ref_no"],
        "status_cols": ["status"],
        "blob_cols": ["data", "payload"],
        "amount_divisor": 1.0,
        "timestamp_epoch": "auto"
    },
    # 29. Canara ai1 (Canara Bank)
    {
        "app_name": "Canara ai1",
        "category": "fiat",
        "bundle_ids": ["com.canarabank.mobility", "com.canarabank.ai1"],
        "android_pkgs": ["com.canarabank.mobility", "com.canarabank.epassbook"],
        "aliases": ["canarabank", "canaraai1"],
        "preferred_tables": ["transactions", "passbook", "epassbook", "upi_transactions"],
        "amount_cols": ["amount", "txn_amount"],
        "date_cols": ["txn_date", "date", "timestamp"],
        "counterparty_cols": ["narration", "particulars", "payee_vpa", "description"],
        "txid_cols": ["txn_id", "utr", "rrn", "ref_no"],
        "status_cols": ["status"],
        "blob_cols": ["data", "payload"],
        "amount_divisor": 1.0,
        "timestamp_epoch": "auto"
    },
    # 30. Vyom (Union Bank of India)
    {
        "app_name": "Union Bank Vyom",
        "category": "fiat",
        "bundle_ids": ["com.infrasofttech.uboi", "com.unionbank.vyom"],
        "android_pkgs": ["com.infrasoft.uboi", "com.unionbank.ecommerce.mobile.android"],
        "aliases": ["uboi", "unionbank", "vyom"],
        "preferred_tables": ["transactions", "passbook", "m_passbook", "upi_transactions"],
        "amount_cols": ["amount", "txn_amount"],
        "date_cols": ["txn_date", "date", "timestamp"],
        "counterparty_cols": ["narration", "particulars", "remarks", "payee_vpa"],
        "txid_cols": ["txn_id", "utr", "rrn", "ref_no"],
        "status_cols": ["status"],
        "blob_cols": ["data", "payload"],
        "amount_divisor": 1.0,
        "timestamp_epoch": "auto"
    },
    # 31. IDFC FIRST Bank
    {
        "app_name": "IDFC FIRST Bank",
        "category": "fiat",
        "bundle_ids": ["com.idfcbank.mobileBanking", "com.idfcfirstbank.optimus"],
        "android_pkgs": ["com.idfcfirstbank.optimus", "com.idfcbank.mobileBanking"],
        "aliases": ["idfcfirst", "idfcbank"],
        "preferred_tables": ["transactions", "statement", "upi_transactions", "rkstorage"],
        "amount_cols": ["amount", "txn_amount"],
        "date_cols": ["timestamp", "txn_date", "date"],
        "counterparty_cols": ["narration", "payee_vpa", "counterparty", "merchant"],
        "txid_cols": ["txn_id", "utr", "rrn", "reference_id"],
        "status_cols": ["status"],
        "blob_cols": ["data", "payload", "value"],
        "amount_divisor": 1.0,
        "timestamp_epoch": "auto"
    },
    # 32. IndusMobile (IndusInd Bank)
    {
        "app_name": "IndusMobile",
        "category": "fiat",
        "bundle_ids": ["com.indusind.indusmobile", "com.indusind.indie"],
        "android_pkgs": ["com.indusind.indusmobile", "com.indusind.indie"],
        "aliases": ["indusind", "indusmobile"],
        "preferred_tables": ["transactions", "statement", "upi_transactions"],
        "amount_cols": ["amount", "txn_amount"],
        "date_cols": ["txn_date", "date", "timestamp"],
        "counterparty_cols": ["narration", "payee_vpa", "particulars"],
        "txid_cols": ["txn_id", "utr", "rrn"],
        "status_cols": ["status"],
        "blob_cols": ["data", "payload"],
        "amount_divisor": 1.0,
        "timestamp_epoch": "auto"
    },
    # 33. FedMobile (Federal Bank)
    {
        "app_name": "FedMobile",
        "category": "fiat",
        "bundle_ids": ["com.federalbank.fedmobile"],
        "android_pkgs": ["com.fedmobile"],
        "aliases": ["fedmobile", "federalbank"],
        "preferred_tables": ["transactions", "passbook", "upi_transactions"],
        "amount_cols": ["amount", "txn_amount"],
        "date_cols": ["txn_date", "date", "timestamp"],
        "counterparty_cols": ["narration", "particulars", "payee_vpa"],
        "txid_cols": ["txn_id", "utr", "rrn"],
        "status_cols": ["status"],
        "blob_cols": ["data", "payload"],
        "amount_divisor": 1.0,
        "timestamp_epoch": "auto"
    },
    # 34. IRIS by YES BANK
    {
        "app_name": "YES BANK (IRIS)",
        "category": "fiat",
        "bundle_ids": ["in.irisbyyes.app", "com.yesbank.yesmobile"],
        "android_pkgs": ["in.irisbyyes.app", "com.yesbank", "com.YesBank"],
        "aliases": ["irisbyyes", "yesbank"],
        "preferred_tables": ["transactions", "upi_transactions", "statement", "rkstorage"],
        "amount_cols": ["amount", "txn_amount"],
        "date_cols": ["txn_date", "date", "timestamp"],
        "counterparty_cols": ["narration", "payee_vpa", "counterparty"],
        "txid_cols": ["txn_id", "utr", "rrn"],
        "status_cols": ["status"],
        "blob_cols": ["data", "payload", "value"],
        "amount_divisor": 1.0,
        "timestamp_epoch": "auto"
    },
    # 35. IndOASIS (Indian Bank) & Cent Mobile & BOI Mobile & IPPB
    {
        "app_name": "PSU Mobile Banking (IndOASIS/BOI/Cent/IPPB)",
        "category": "fiat",
        "bundle_ids": ["in.indianbank.indoasis", "com.boi.mobile", "com.ippb.mobile"],
        "android_pkgs": [
            "com.IndianBank.IndOASIS", "com.snapwork.IDBI", "com.boi.ua.android",
            "com.infrasofttech.CentralBank", "com.lcode.ucobank", "com.iob.iobmobile",
            "com.ippb.app", "com.dop.dakpay"
        ],
        "aliases": ["indoasis", "centralbank", "ucobank", "ippb", "dakpay"],
        "preferred_tables": ["transactions", "passbook", "m_passbook", "statement", "upi_transactions"],
        "amount_cols": ["amount", "txn_amount", "tran_amt"],
        "date_cols": ["txn_date", "date", "timestamp"],
        "counterparty_cols": ["narration", "particulars", "remarks", "payee_vpa"],
        "txid_cols": ["txn_id", "utr", "rrn", "ref_no"],
        "status_cols": ["status"],
        "blob_cols": ["data", "payload"],
        "amount_divisor": 1.0,
        "timestamp_epoch": "auto"
    },
    # 36. Telegram
    {
        "app_name": "Telegram",
        "category": "fiat",
        "bundle_ids": ["ph.telegra.Telegra", "org.telegram.Telegram-iOS", "group.ph.telegra.Telegra"],
        "android_pkgs": ["org.telegram.messenger", "org.telegram.messenger.web", "org.telegram.plus"],
        "aliases": ["telegram"],
        "preferred_tables": ["messages_v2", "messages", "chats", "users"],
        "amount_cols": [],
        "date_cols": ["date"],
        "counterparty_cols": ["uid", "from_id", "peer_id", "name"],
        "txid_cols": ["mid", "id"],
        "status_cols": ["out", "read_state"],
        "blob_cols": ["data", "bytes"],
        "amount_divisor": 1.0,
        "timestamp_epoch": "unix_s"
    },
    # 37. Binance
    {
        "app_name": "Binance",
        "category": "crypto",
        "bundle_ids": ["com.binance.BinanceApp", "com.binance.dev", "com.czzhao.binance"],
        "android_pkgs": ["com.binance.dev", "com.binance.us"],
        "aliases": ["binance"],
        "preferred_tables": ["orders", "p2p_orders", "c2c_orders"],
        "amount_cols": ["fiat_amount", "amount", "total"],
        "date_cols": ["create_time", "timestamp"],
        "counterparty_cols": ["nick_name", "merchant"],
        "txid_cols": ["order_no", "order_id"],
        "status_cols": ["order_status", "status"],
        "blob_cols": ["data", "payload"],
        "amount_divisor": 1.0,
        "timestamp_epoch": "unix_ms"
    },
    # 38. Bybit
    {
        "app_name": "Bybit",
        "category": "crypto",
        "bundle_ids": ["com.bybit.Bybit", "com.bybit.app"],
        "android_pkgs": ["com.bybit.app"],
        "aliases": ["bybit"],
        "preferred_tables": ["orders", "p2p_trade"],
        "amount_cols": ["amount", "fiat_amount"],
        "date_cols": ["created_at", "timestamp"],
        "counterparty_cols": ["counterparty", "target_name"],
        "txid_cols": ["order_id", "serial_no"],
        "status_cols": ["status"],
        "blob_cols": [],
        "amount_divisor": 1.0,
        "timestamp_epoch": "unix_ms"
    },
    # 39. KuCoin
    {
        "app_name": "KuCoin",
        "category": "crypto",
        "bundle_ids": ["com.kucoin.KuCoin"],
        "android_pkgs": ["com.kubi.kucoin"],
        "aliases": ["kucoin"],
        "preferred_tables": ["orders", "p2p"],
        "amount_cols": ["amount", "fiat_amount"],
        "date_cols": ["created_at", "time"],
        "counterparty_cols": ["merchant_name", "user_name"],
        "txid_cols": ["order_id"],
        "status_cols": ["status"],
        "blob_cols": [],
        "amount_divisor": 1.0,
        "timestamp_epoch": "unix_ms"
    },
    # 40. Trust Wallet
    {
        "app_name": "Trust Wallet",
        "category": "crypto",
        "bundle_ids": ["com.sixdays.trust"],
        "android_pkgs": ["com.wallet.crypto.trustapp"],
        "aliases": ["trustwallet", "trustapp"],
        "preferred_tables": ["transactions", "wallet_history"],
        "amount_cols": ["amount", "value"],
        "date_cols": ["timestamp", "date"],
        "counterparty_cols": ["to_address", "from_address"],
        "txid_cols": ["tx_hash", "hash"],
        "status_cols": ["status"],
        "blob_cols": [],
        "amount_divisor": 1.0,
        "timestamp_epoch": "unix_s"
    },
    # 41. CoinDCX
    {
        "app_name": "CoinDCX",
        "category": "crypto",
        "bundle_ids": ["com.coindcx.CoinDCX", "com.coindcx.btc"],
        "android_pkgs": ["com.coindcx", "com.coindcx.btc"],
        "aliases": ["coindcx"],
        "preferred_tables": ["orders", "transactions", "inr_transactions"],
        "amount_cols": ["inr_amount", "amount", "total"],
        "date_cols": ["created_at", "timestamp"],
        "counterparty_cols": ["merchant", "counterparty"],
        "txid_cols": ["order_id", "id"],
        "status_cols": ["status"],
        "blob_cols": [],
        "amount_divisor": 1.0,
        "timestamp_epoch": "auto"
    },
    # 42. WazirX & CoinSwitch & Mudrex & ZebPay
    {
        "app_name": "Indian Crypto Exchanges (WazirX/CoinSwitch/ZebPay)",
        "category": "crypto",
        "bundle_ids": ["com.wrx.wazirx", "com.coinswitch.kuber", "com.zebpay.alkaloid"],
        "android_pkgs": ["com.wrx.offline", "com.wazirx.wazirx", "com.coinswitch.kuber", "zebpay.Application", "com.mudrex.app"],
        "aliases": ["wazirx", "coinswitch", "zebpay", "mudrex"],
        "preferred_tables": ["p2p_orders", "trades", "orders", "transactions"],
        "amount_cols": ["amount", "total", "fiat_amount", "inr_amount"],
        "date_cols": ["time", "created_at", "timestamp"],
        "counterparty_cols": ["peer_name", "counterparty", "merchant"],
        "txid_cols": ["order_id", "tx_id"],
        "status_cols": ["status"],
        "blob_cols": [],
        "amount_divisor": 1.0,
        "timestamp_epoch": "auto"
    },
]

# Custodial Wallet signatures and plugin integration
try:
    from parsers.custodial_wallet_parser import WALLET_SIGNATURES
except ImportError:
    WALLET_SIGNATURES = {}

CUSTODIAL_WALLETS = WALLET_SIGNATURES

PLUGINS: Dict[str, Dict[str, Any]] = {}
for name, sig in WALLET_SIGNATURES.items():
    PLUGINS[name] = {
        "category": "CUSTODIAL_WALLET",
        "tier": sig.get("tier", 3),
        "package_android": sig.get("package_android"),
        "bundle_ios": sig.get("bundle_ios"),
        "db_patterns": sig.get("db_patterns", []),
    }
    BUILTIN_MANIFESTS.append({
        "app_name": name,
        "category": "crypto",
        "bundle_ids": [sig["bundle_ios"]] if sig.get("bundle_ios") else [],
        "android_pkgs": [sig["package_android"]] if sig.get("package_android") else [],
        "aliases": [name.lower(), name.lower().replace(" ", "")],
        "preferred_tables": (
            sig.get("tx_tables", [])
            + sig.get("address_tables", [])
            + sig.get("holdings_tables", [])
            + sig.get("kyc_tables", [])
        ),
        "amount_cols": ["amount", "native_amount"],
        "date_cols": ["created_at", "timestamp", "created", "date"],
        "counterparty_cols": ["to_address", "from_address", "address"],
        "txid_cols": ["id", "network_hash", "tx_hash"],
        "status_cols": ["status"],
        "blob_cols": [],
        "amount_divisor": 1.0,
        "timestamp_epoch": "auto",
    })

# =============================================================================
# CHAT, PRIVACY, SOCIAL & DATING APP MANIFESTS (PHASE 6 & 7)
# =============================================================================
BUILTIN_MANIFESTS.extend([
    # 1. WhatsApp & WhatsApp Business
    {
        "app_name": "WhatsApp",
        "category": "chat",
        "bundle_ids": ["net.whatsapp.WhatsApp", "net.whatsapp.WhatsAppSMB", "group.net.whatsapp.WhatsApp.shared"],
        "android_pkgs": ["com.whatsapp", "com.whatsapp.w4b"],
        "aliases": ["whatsapp", "whatsapp business", "wa", "w4b"],
        "preferred_tables": [
            "message", "chat", "jid", "message_media", "message_location",
            "message_quoted", "message_ephemeral", "receipt_user", "call_log",
            "ZWAMESSAGE", "ZWACHATSESSION", "ZWAMEDIAITEM"
        ],
        "amount_cols": [],
        "date_cols": ["timestamp", "ZMESSAGEDATE"],
        "counterparty_cols": ["chat_jid", "sender_jid", "ZCONTACTJID"],
        "txid_cols": ["_id", "Z_PK", "key_id"],
        "status_cols": ["status"],
        "blob_cols": ["message_content"],
        "amount_divisor": 1.0,
        "timestamp_epoch": "auto"
    },
    # 2. Telegram & Telegram X
    {
        "app_name": "Telegram",
        "category": "chat",
        "bundle_ids": ["ph.telegra.Telegra", "org.telegram.Telegram"],
        "android_pkgs": ["org.telegram.messenger", "org.telegram.plus", "org.thunderdog.challegram"],
        "aliases": ["telegram", "telegram x", "tg", "challegram"],
        "preferred_tables": [
            "messages_v2", "users", "chats", "enc_chats", "dialogs", "messages"
        ],
        "amount_cols": [],
        "date_cols": ["date"],
        "counterparty_cols": ["uid", "peer_id"],
        "txid_cols": ["mid", "id"],
        "status_cols": ["read_state", "send_state"],
        "blob_cols": ["data", "replydata"],
        "amount_divisor": 1.0,
        "timestamp_epoch": "unix_sec"
    },
    # 3. Signal Private Messenger
    {
        "app_name": "Signal",
        "category": "privacy",
        "bundle_ids": ["org.whispersystems.signal", "group.org.whispersystems.signal"],
        "android_pkgs": ["org.thoughtcrime.securesms"],
        "aliases": ["signal", "securesms"],
        "preferred_tables": [
            "message", "mms", "sms", "recipient", "part", "thread",
            "model_TSInteraction", "model_TSThread"
        ],
        "amount_cols": [],
        "date_cols": ["date_sent", "date_received", "timestamp"],
        "counterparty_cols": ["recipient_id", "authorId", "phone"],
        "txid_cols": ["_id", "uniqueId"],
        "status_cols": ["type"],
        "blob_cols": [],
        "amount_divisor": 1.0,
        "timestamp_epoch": "unix_ms"
    },
    # 4. Zangi Private Messenger
    {
        "app_name": "Zangi",
        "category": "privacy",
        "bundle_ids": ["com.beint.zangi"],
        "android_pkgs": ["com.beint.zangi"],
        "aliases": ["zangi", "zangi private messenger"],
        "preferred_tables": [
            "messages", "chat_messages", "calls", "ZMESSAGE", "ZCONVERSATION", "ZCONTACT", "ZCALL"
        ],
        "amount_cols": [],
        "date_cols": ["timestamp", "created_at", "ZDATE"],
        "counterparty_cols": ["sender_id", "receiver_id", "from_zangi_number", "to_zangi_number", "ZZANGINUMBER"],
        "txid_cols": ["msg_id", "ZMESSAGEID"],
        "status_cols": ["status"],
        "blob_cols": [],
        "amount_divisor": 1.0,
        "timestamp_epoch": "auto"
    },
    # 5. Element / Matrix Messenger
    {
        "app_name": "Element",
        "category": "privacy",
        "bundle_ids": ["im.vector.app", "im.vector.alpha"],
        "android_pkgs": ["im.vector.app", "im.vector.alpha"],
        "aliases": ["element", "matrix", "vector", "riot"],
        "preferred_tables": [
            "events", "timeline_events", "roomevents", "crypto_store"
        ],
        "amount_cols": [],
        "date_cols": ["origin_server_ts"],
        "counterparty_cols": ["sender", "room_id"],
        "txid_cols": ["event_id"],
        "status_cols": [],
        "blob_cols": ["event_json_payload", "content"],
        "amount_divisor": 1.0,
        "timestamp_epoch": "unix_ms"
    },
    # 6. Session Messenger
    {
        "app_name": "Session",
        "category": "privacy",
        "bundle_ids": ["com.loki-project.loki-messenger"],
        "android_pkgs": ["network.loki.messenger"],
        "aliases": ["session", "loki", "oxen"],
        "preferred_tables": [
            "messages", "sms", "mms", "contacts", "loki_user_display_name_database", "loki_open_group_chat"
        ],
        "amount_cols": [],
        "date_cols": ["date_sent", "date_received", "date"],
        "counterparty_cols": ["address", "thread_id"],
        "txid_cols": ["id"],
        "status_cols": ["type"],
        "blob_cols": [],
        "amount_divisor": 1.0,
        "timestamp_epoch": "unix_ms"
    },
    # 7. Threema / Briar / SimpleX
    {
        "app_name": "Threema",
        "category": "privacy",
        "bundle_ids": ["ch.threema.app"],
        "android_pkgs": ["ch.threema.app", "org.briarproject.briar.android", "chat.simplex.app"],
        "aliases": ["threema", "briar", "simplex", "simplex chat"],
        "preferred_tables": [
            "message", "contact", "messages", "connections"
        ],
        "amount_cols": [],
        "date_cols": ["created_at", "posted_at"],
        "counterparty_cols": ["identity", "chat_id"],
        "txid_cols": ["id", "message_id"],
        "status_cols": [],
        "blob_cols": [],
        "amount_divisor": 1.0,
        "timestamp_epoch": "unix_ms"
    },
    # 8. Snapchat
    {
        "app_name": "Snapchat",
        "category": "social",
        "bundle_ids": ["com.toyopagroup.picaboo"],
        "android_pkgs": ["com.snapchat.android"],
        "aliases": ["snapchat", "snap", "arroyo"],
        "preferred_tables": [
            "conversation_message", "Friend", "Feed", "snap_tag_table"
        ],
        "amount_cols": [],
        "date_cols": ["creation_timestamp", "read_timestamp", "addedTimestamp"],
        "counterparty_cols": ["sender_id", "client_conversation_id", "username"],
        "txid_cols": ["server_message_id", "_id"],
        "status_cols": ["content_type"],
        "blob_cols": ["message_content"],
        "amount_divisor": 1.0,
        "timestamp_epoch": "unix_ms"
    },
    # 9. Instagram Direct
    {
        "app_name": "Instagram",
        "category": "social",
        "bundle_ids": ["com.burbn.instagram"],
        "android_pkgs": ["com.instagram.android"],
        "aliases": ["instagram", "ig", "direct"],
        "preferred_tables": [
            "messages", "threads", "users"
        ],
        "amount_cols": [],
        "date_cols": ["timestamp"],
        "counterparty_cols": ["user_id", "thread_key", "thread_id"],
        "txid_cols": ["item_id", "_id"],
        "status_cols": ["message_type"],
        "blob_cols": ["message"],
        "amount_divisor": 1.0,
        "timestamp_epoch": "auto"
    },
    # 10. Dating Apps (Tinder, Bumble, Hinge, Grindr)
    {
        "app_name": "Dating Apps",
        "category": "dating",
        "bundle_ids": ["com.cardify.tinder", "com.mosocial.Bumble", "co.hinge.app"],
        "android_pkgs": ["com.tinder", "com.bumble.app", "co.hinge.app", "com.grindrapp.android"],
        "aliases": ["dating apps", "dating", "tinder", "bumble", "hinge", "grindr"],
        "preferred_tables": [
            "message_view", "messages", "chat_message", "chat_messages", "matches", "connections", "match_view", "profiles"
        ],
        "amount_cols": [],
        "date_cols": ["sent_date", "created_timestamp", "timestamp"],
        "counterparty_cols": ["from_id", "sender_id", "sender", "match_id"],
        "txid_cols": ["id", "message_id"],
        "status_cols": [],
        "blob_cols": [],
        "amount_divisor": 1.0,
        "timestamp_epoch": "auto"
    }
])

try:
    from parsers.social_interaction_comms_parsers import SOCIAL_INTERACTION_MANIFESTS
    BUILTIN_MANIFESTS.extend(SOCIAL_INTERACTION_MANIFESTS)
except Exception:
    pass




class PluginRegistry:
    """Manages built-in manifests and dynamically ingested plugins."""

    def __init__(self, custom_plugin_dir: Optional[str] = None):
        self._plugins: Dict[str, AppPlugin] = {}
        self._load_builtins()
        if custom_plugin_dir and os.path.isdir(custom_plugin_dir):
            self.load_directory(custom_plugin_dir)

    def _load_builtins(self) -> None:
        for m in BUILTIN_MANIFESTS:
            plugin = AppPlugin(**m)
            self._plugins[plugin.app_name] = plugin

    def load_directory(self, plugin_dir: str) -> int:
        count = 0
        for root, _, files in os.walk(plugin_dir):
            for f in files:
                full_path = os.path.join(root, f)
                if f.endswith(".json"):
                    try:
                        with open(full_path, "r", encoding="utf-8") as jf:
                            data = json.load(jf)
                            if isinstance(data, list):
                                for item in data:
                                    p = AppPlugin(**item)
                                    self._plugins[p.app_name] = p
                                    count += 1
                            elif isinstance(data, dict):
                                p = AppPlugin(**data)
                                self._plugins[p.app_name] = p
                                count += 1
                    except Exception:
                        continue
                elif f.endswith((".yaml", ".yml")):
                    try:
                        import yaml  # type: ignore
                        with open(full_path, "r", encoding="utf-8") as yf:
                            data = yaml.safe_load(yf)
                            if isinstance(data, list):
                                for item in data:
                                    p = AppPlugin(**item)
                                    self._plugins[p.app_name] = p
                                    count += 1
                            elif isinstance(data, dict):
                                p = AppPlugin(**data)
                                self._plugins[p.app_name] = p
                                count += 1
                    except Exception:
                        continue
        return count

    def get_plugin(self, app_name: str) -> Optional[AppPlugin]:
        if app_name in self._plugins:
            return self._plugins[app_name]
        norm = str(app_name).strip().lower()
        for k, p in self._plugins.items():
            if (
                k.lower() == norm
                or norm in [a.lower() for a in p.aliases]
                or norm in [pkg.lower() for pkg in p.android_pkgs]
                or norm in [b.lower() for b in p.bundle_ids]
            ):
                return p
        return None

    def all_plugins(self) -> List[AppPlugin]:
        return list(self._plugins.values())

    def match_path(
        self,
        clean_path: str,
        target_uuids: Optional[List[str]] = None,
        candidate_plugin: Optional[AppPlugin] = None,
    ) -> Optional[AppPlugin]:
        if not clean_path or not isinstance(clean_path, str):
            return None
        path_lower = clean_path.replace("\\", "/").lower()

        if target_uuids and candidate_plugin:
            for u in target_uuids:
                u_low = u.lower()
                if f"/{u_low}/" in path_lower or path_lower.startswith(f"{u_low}/"):
                    return candidate_plugin

        plugins_to_check = [candidate_plugin] if candidate_plugin else list(self._plugins.values())

        for plugin in plugins_to_check:
            if plugin is None:
                continue
            for pkg in plugin.android_pkgs:
                pkg_low = pkg.lower()
                if (
                    f"/{pkg_low}/" in path_lower
                    or path_lower.startswith(f"{pkg_low}/")
                    or f"/{pkg_low}-" in path_lower
                ):
                    return plugin

            for b in plugin.bundle_ids:
                b_low = b.lower()
                if (
                    f"appdomain-{b_low}" in path_lower
                    or f"appdomaingroup-{b_low}" in path_lower
                    or f"/{b_low}/" in path_lower
                    or path_lower.startswith(f"{b_low}/")
                ):
                    return plugin

            for alias in plugin.aliases:
                al_low = alias.lower()
                if f"/{al_low}/" in path_lower or path_lower.startswith(f"{al_low}/"):
                    return plugin

        return None
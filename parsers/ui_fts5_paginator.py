"""
1 TB+ SQLite FTS5 Paginated Case Store & Query Engine: CaseUIPaginatorStore
Provides sub-10ms virtualized pagination, full-text FTS5 queries, live PA tree counts,
conversation thread grouping, and mmap physical byte offset hex streaming.
"""

from __future__ import annotations

import gc
import json
import mmap
import os
import re
import sqlite3
from typing import Any, Dict, List, Optional, Tuple, Union

import pandas as pd

from parsers.enterprise_1tb_chat_and_container_engine import CHAT_COLUMNS
from parsers.freelist_carver import STANDARD_TX_COLUMNS

# Target App Groupings for PA Analyzed Data Tree
TARGET_CHAT_APPS = {
    'whatsapp': 'WhatsApp',
    'telegram': 'Telegram',
    'snapchat': 'Snapchat',
    'signal': 'Signal',
    'zangi': 'Zangi',
    'element': 'Element (Matrix)',
    'session': 'Session',
    'instagram': 'Instagram Direct',
    'dating': 'Dating Apps (Tinder / Bumble / Hinge / Grindr)',
}

DATING_KEYWORDS = ('tinder', 'bumble', 'hinge', 'grindr', 'okcupid', 'badoo', 'happn')


def adapt_legacy_chat_frame(df: pd.DataFrame) -> pd.DataFrame:
    """
    Maps the 37-column messenger-parser schema onto the canonical 28-column chats table so
    Telegram/Signal/Snapchat/... rows keep their body, sender and application (C-11).
    Frames already in the canonical schema pass through unchanged.
    """
    if 'Message_Text' not in df.columns or 'Message_Body' in df.columns:
        return df
    out = pd.DataFrame(index=df.index)

    def col(name: str) -> pd.Series:
        return df[name] if name in df.columns else pd.Series([''] * len(df), index=df.index)

    out['Application'] = col('Source_App')
    out['Message_ID'] = col('Artifact_ID')
    for src, dst in [
        ('Thread_ID', 'Thread_ID'), ('Chat_Type', 'Chat_Type'), ('Direction', 'Direction'),
        ('Message_Type', 'Message_Type'), ('Status', 'Delivery_Status'), ('Message_Text', 'Message_Body'),
        ('Quoted_Message_Text', 'Quoted_Text'), ('Thread_Title', 'Thread_Title'),
        ('Sender_Name', 'Sender_Name'), ('Sender_ID', 'Sender_Identifier'),
        ('Recipient_Name', 'Recipient_Name'), ('Recipient_ID', 'Recipient_Identifier'),
        ('Timestamp_Raw', 'Raw_Timestamp_Value'), ('Timestamp_UTC', 'Timestamp_UTC'),
        ('Timestamp_IST', 'Timestamp_IST'), ('Attachment_Path', 'Attachment_Path_or_URL'),
        ('Forwarding_Score', 'Forwarding_Score'),
    ]:
        out[dst] = col(src)
    out['Is_View_Once'] = col('Is_Ephemeral')
    out['Disappearing_TTL_Sec'] = col('Ephemeral_Duration_Seconds')
    out['Is_Revoked_Deleted'] = col('Is_Deleted')
    out['Attachment_MIME_Size'] = (col('Attachment_MIME').astype(str) + ' ' + col('Attachment_Size').astype(str)).str.strip()
    lat, lon = col('Latitude').astype(str), col('Longitude').astype(str)
    out['Geo_Coordinates'] = (lat + ', ' + lon).where(lat.str.strip().ne('') & lat.ne('nan') & lat.ne('None'), '')
    prov = (
        col('Source_File').astype(str) + ' :: ' + col('Source_Table').astype(str)
        + ' :: RowID=' + col('Row_ID').astype(str)
    )
    rec = col('Recovery_Method').astype(str)
    prov = prov + ' :: State=' + rec.where(rec.str.strip().ne(''), 'Allocated B-Tree')
    out['Forensic_Provenance'] = prov
    if 'Decoded_By' in df.columns:
        out['Decoded_By'] = df['Decoded_By']
    return out


ALLOWED_TABLES = frozenset({
    'chats', 'transactions', 'contacts', 'calls', 'locations', 'os_spillover',
    'notifications', 'custodial_wallets', 'p2p_orders', 'fiat_crypto_bridge',
    'crypto_addresses', 'vfs_files',
})


class CaseUIPaginatorStore:
    """
    On-disk high-throughput SQLite + FTS5 Paginated Data Store for 1 TB+ dumps.
    Zero-OOM streaming ingestion with memory mapped I/O and sub-10ms UI pagination.
    """

    def __init__(self, case_workspace: str, db_name: str = 'case_ui_store.db') -> None:
        self.case_workspace = case_workspace
        self.last_dropped_columns: Dict[str, List[str]] = {}
        os.makedirs(self.case_workspace, exist_ok=True)
        self.db_path = os.path.join(self.case_workspace, db_name)
        self._init_database_schema()

    def _get_connection(self) -> sqlite3.Connection:
        """Opens a connection with WAL mode and memory-mapped cache optimizations."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute("PRAGMA temp_store=MEMORY;")
        conn.execute("PRAGMA mmap_size=268435456;")  # 256 MB memory map
        conn.execute("PRAGMA cache_size=-64000;")     # 64 MB page cache
        return conn

    def _init_database_schema(self) -> None:
        """Initializes normalized tables, FTS5 virtual tables, indexes, and triggers."""
        conn = self._get_connection()
        try:
            cur = conn.cursor()
            cur.executescript("""
                -- 1. CHATS TABLE (28-Column PA Categorized Schema) + FTS5
                CREATE TABLE IF NOT EXISTS chats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    Application TEXT,
                    Message_ID TEXT,
                    Thread_ID TEXT,
                    Chat_Type TEXT,
                    Direction TEXT,
                    Message_Type TEXT,
                    Delivery_Status TEXT,
                    Message_Body TEXT,
                    Quoted_Message_ID TEXT,
                    Quoted_Text TEXT,
                    Forwarding_Score INTEGER DEFAULT 0,
                    Thread_Title TEXT,
                    Sender_Name TEXT,
                    Sender_Identifier TEXT,
                    Recipient_Name TEXT,
                    Recipient_Identifier TEXT,
                    Participant_Bio_Meta TEXT,
                    Is_View_Once INTEGER DEFAULT 0,
                    Disappearing_TTL_Sec INTEGER DEFAULT 0,
                    Is_Revoked_Deleted INTEGER DEFAULT 0,
                    Raw_Timestamp_Value TEXT,
                    Timestamp_UTC TEXT,
                    Timestamp_IST TEXT,
                    Read_Timestamp_IST TEXT,
                    Attachment_Path_or_URL TEXT,
                    Attachment_MIME_Size TEXT,
                    Geo_Coordinates TEXT,
                    Forensic_Provenance TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_chats_app ON chats(Application);
                CREATE INDEX IF NOT EXISTS idx_chats_thread ON chats(Thread_ID);
                CREATE INDEX IF NOT EXISTS idx_chats_ts_ist ON chats(Timestamp_IST);
                CREATE INDEX IF NOT EXISTS idx_chats_prov ON chats(Forensic_Provenance);
                CREATE INDEX IF NOT EXISTS idx_chats_revoked ON chats(Is_Revoked_Deleted);

                CREATE VIRTUAL TABLE IF NOT EXISTS chats_fts USING fts5(
                    Message_Body,
                    Sender_Name,
                    Sender_Identifier,
                    Recipient_Name,
                    Recipient_Identifier,
                    Thread_Title,
                    Participant_Bio_Meta,
                    Forensic_Provenance,
                    content='chats',
                    content_rowid='id'
                );

                CREATE TRIGGER IF NOT EXISTS trg_chats_ai AFTER INSERT ON chats BEGIN
                    INSERT INTO chats_fts(rowid, Message_Body, Sender_Name, Sender_Identifier, Recipient_Name, Recipient_Identifier, Thread_Title, Participant_Bio_Meta, Forensic_Provenance)
                    VALUES (new.id, new.Message_Body, new.Sender_Name, new.Sender_Identifier, new.Recipient_Name, new.Recipient_Identifier, new.Thread_Title, new.Participant_Bio_Meta, new.Forensic_Provenance);
                END;
                CREATE TRIGGER IF NOT EXISTS trg_chats_ad AFTER DELETE ON chats BEGIN
                    INSERT INTO chats_fts(chats_fts, rowid, Message_Body, Sender_Name, Sender_Identifier, Recipient_Name, Recipient_Identifier, Thread_Title, Participant_Bio_Meta, Forensic_Provenance)
                    VALUES ('delete', old.id, old.Message_Body, old.Sender_Name, old.Sender_Identifier, old.Recipient_Name, old.Recipient_Identifier, old.Thread_Title, old.Participant_Bio_Meta, old.Forensic_Provenance);
                END;

                -- 2. TRANSACTIONS TABLE + FTS5
                CREATE TABLE IF NOT EXISTS transactions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    Date TEXT,
                    Transaction_ID TEXT,
                    Amount REAL,
                    Counterparty TEXT,
                    Status TEXT,
                    Type TEXT,
                    Account TEXT,
                    VPA TEXT,
                    Bank_Ref_No TEXT,
                    Application TEXT,
                    Source_File TEXT,
                    Clock_Tamper_Detected INTEGER DEFAULT 0,
                    Direction TEXT,
                    Forensic_Provenance TEXT,
                    Timestamp_IST TEXT,
                    Possible_Link TEXT,
                    Timestamp_Raw TEXT,
                    Timestamp_UTC TEXT,
                    Timestamp_Basis TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_tx_app ON transactions(Application);
                CREATE INDEX IF NOT EXISTS idx_tx_cparty ON transactions(Counterparty);
                CREATE INDEX IF NOT EXISTS idx_tx_txid ON transactions(Transaction_ID);
                CREATE INDEX IF NOT EXISTS idx_tx_ts_ist ON transactions(Timestamp_IST);

                CREATE VIRTUAL TABLE IF NOT EXISTS transactions_fts USING fts5(
                    Counterparty,
                    Transaction_ID,
                    VPA,
                    Account,
                    Bank_Ref_No,
                    Application,
                    Forensic_Provenance,
                    content='transactions',
                    content_rowid='id'
                );

                CREATE TRIGGER IF NOT EXISTS trg_tx_ai AFTER INSERT ON transactions BEGIN
                    INSERT INTO transactions_fts(rowid, Counterparty, Transaction_ID, VPA, Account, Bank_Ref_No, Application, Forensic_Provenance)
                    VALUES (new.id, new.Counterparty, new.Transaction_ID, new.VPA, new.Account, new.Bank_Ref_No, new.Application, new.Forensic_Provenance);
                END;
                CREATE TRIGGER IF NOT EXISTS trg_tx_ad AFTER DELETE ON transactions BEGIN
                    INSERT INTO transactions_fts(transactions_fts, rowid, Counterparty, Transaction_ID, VPA, Account, Bank_Ref_No, Application, Forensic_Provenance)
                    VALUES ('delete', old.id, old.Counterparty, old.Transaction_ID, old.VPA, old.Account, old.Bank_Ref_No, old.Application, old.Forensic_Provenance);
                END;

                -- 3. CONTACTS TABLE + FTS5
                CREATE TABLE IF NOT EXISTS contacts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    Contact_Name TEXT,
                    Phone_Number TEXT,
                    Identifier TEXT,
                    Application TEXT,
                    Email TEXT,
                    Account_ID TEXT,
                    Source_File TEXT,
                    Forensic_Provenance TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_contacts_app ON contacts(Application);
                CREATE INDEX IF NOT EXISTS idx_contacts_ident ON contacts(Identifier);

                CREATE VIRTUAL TABLE IF NOT EXISTS contacts_fts USING fts5(
                    Contact_Name,
                    Phone_Number,
                    Identifier,
                    Application,
                    Email,
                    Forensic_Provenance,
                    content='contacts',
                    content_rowid='id'
                );

                CREATE TRIGGER IF NOT EXISTS trg_contacts_ai AFTER INSERT ON contacts BEGIN
                    INSERT INTO contacts_fts(rowid, Contact_Name, Phone_Number, Identifier, Application, Email, Forensic_Provenance)
                    VALUES (new.id, new.Contact_Name, new.Phone_Number, new.Identifier, new.Application, new.Email, new.Forensic_Provenance);
                END;

                -- 4. CALL LOGS TABLE + FTS5
                CREATE TABLE IF NOT EXISTS calls (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    Peer TEXT,
                    Duration_Sec INTEGER DEFAULT 0,
                    Call_Type TEXT,
                    Direction TEXT,
                    Call_Result TEXT,
                    Timestamp_UTC TEXT,
                    Timestamp_IST TEXT,
                    Application TEXT,
                    Forensic_Provenance TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_calls_peer ON calls(Peer);
                CREATE INDEX IF NOT EXISTS idx_calls_ts_ist ON calls(Timestamp_IST);

                CREATE VIRTUAL TABLE IF NOT EXISTS calls_fts USING fts5(
                    Peer,
                    Call_Type,
                    Direction,
                    Call_Result,
                    Application,
                    Forensic_Provenance,
                    content='calls',
                    content_rowid='id'
                );

                CREATE TRIGGER IF NOT EXISTS trg_calls_ai AFTER INSERT ON calls BEGIN
                    INSERT INTO calls_fts(rowid, Peer, Call_Type, Direction, Call_Result, Application, Forensic_Provenance)
                    VALUES (new.id, new.Peer, new.Call_Type, new.Direction, new.Call_Result, new.Application, new.Forensic_Provenance);
                END;

                -- 5. LOCATIONS TABLE + FTS5
                CREATE TABLE IF NOT EXISTS locations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    Latitude REAL,
                    Longitude REAL,
                    Geo_Coordinates TEXT,
                    Place_Name TEXT,
                    Timestamp_UTC TEXT,
                    Timestamp_IST TEXT,
                    Application TEXT,
                    Forensic_Provenance TEXT
                );

                CREATE VIRTUAL TABLE IF NOT EXISTS locations_fts USING fts5(
                    Geo_Coordinates,
                    Place_Name,
                    Application,
                    Forensic_Provenance,
                    content='locations',
                    content_rowid='id'
                );

                CREATE TRIGGER IF NOT EXISTS trg_locations_ai AFTER INSERT ON locations BEGIN
                    INSERT INTO locations_fts(rowid, Geo_Coordinates, Place_Name, Application, Forensic_Provenance)
                    VALUES (new.id, new.Geo_Coordinates, new.Place_Name, new.Application, new.Forensic_Provenance);
                END;

                -- 6. OS SPILLOVER TABLE + FTS5
                CREATE TABLE IF NOT EXISTS os_spillover (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    Vector_Type TEXT,
                    Package_Name TEXT,
                    Content_Snippet TEXT,
                    Extracted_Entity TEXT,
                    Timestamp_IST TEXT,
                    Forensic_Provenance TEXT
                );

                CREATE VIRTUAL TABLE IF NOT EXISTS os_spillover_fts USING fts5(
                    Vector_Type,
                    Package_Name,
                    Content_Snippet,
                    Extracted_Entity,
                    Forensic_Provenance,
                    content='os_spillover',
                    content_rowid='id'
                );

                CREATE TRIGGER IF NOT EXISTS trg_spillover_ai AFTER INSERT ON os_spillover BEGIN
                    INSERT INTO os_spillover_fts(rowid, Vector_Type, Package_Name, Content_Snippet, Extracted_Entity, Forensic_Provenance)
                    VALUES (new.id, new.Vector_Type, new.Package_Name, new.Content_Snippet, new.Extracted_Entity, new.Forensic_Provenance);
                END;

                -- 7. NOTIFICATIONS TABLE
                CREATE TABLE IF NOT EXISTS notifications (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    Package_Name TEXT,
                    Title TEXT,
                    Text TEXT,
                    Timestamp_IST TEXT,
                    Forensic_Provenance TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_notifs_pkg ON notifications(Package_Name);

                -- 8. CUSTODIAL WALLETS TABLE
                CREATE TABLE IF NOT EXISTS custodial_wallets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    Wallet_App TEXT,
                    User_ID TEXT,
                    Account_Tier TEXT,
                    KYC_Status TEXT,
                    Linked_Mobile TEXT,
                    Linked_Email TEXT,
                    Deposit_Address TEXT,
                    Forensic_Provenance TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_custodial_app ON custodial_wallets(Wallet_App);

                -- 9. P2P ORDERS TABLE
                CREATE TABLE IF NOT EXISTS p2p_orders (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    Platform TEXT,
                    Order_Number TEXT,
                    Trade_Type TEXT,
                    Fiat_Amount REAL,
                    Crypto_Amount REAL,
                    Fiat_Currency TEXT,
                    Crypto_Asset TEXT,
                    Counterparty_Nick TEXT,
                    Counterparty_Real_Name TEXT,
                    Bank_Account TEXT,
                    UPI_ID TEXT,
                    Order_Status TEXT,
                    Timestamp_IST TEXT,
                    Forensic_Provenance TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_p2p_platform ON p2p_orders(Platform);
                CREATE INDEX IF NOT EXISTS idx_p2p_order ON p2p_orders(Order_Number);

                -- 10. FIAT CRYPTO BRIDGE TABLE
                CREATE TABLE IF NOT EXISTS fiat_crypto_bridge (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    UPI_Transaction_ID TEXT,
                    P2P_Order_Number TEXT,
                    Fiat_Amount REAL,
                    Crypto_Amount REAL,
                    Time_Delta_Seconds INTEGER,
                    Bridge_Confidence REAL,
                    Fiat_App TEXT,
                    Crypto_Platform TEXT,
                    Forensic_Provenance TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_bridge_tx ON fiat_crypto_bridge(UPI_Transaction_ID);

                -- 11. CRYPTO ADDRESSES TABLE
                CREATE TABLE IF NOT EXISTS crypto_addresses (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    Address TEXT,
                    Network TEXT,
                    Label TEXT,
                    Source_File TEXT,
                    Byte_Offset INTEGER,
                    Forensic_Provenance TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_crypto_addr ON crypto_addresses(Address);

                -- 12. VFS FILES TABLE
                CREATE TABLE IF NOT EXISTS vfs_files (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    vfs_path TEXT,
                    container_format TEXT,
                    file_name TEXT,
                    file_size INTEGER,
                    archive_offset INTEGER,
                    is_materialized INTEGER DEFAULT 0,
                    local_disk_path TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_vfs_catalog_path ON vfs_files(vfs_path);
                CREATE INDEX IF NOT EXISTS idx_vfs_catalog_name ON vfs_files(file_name);
            """)

            # Case databases created before X-13 lack the transaction time columns: add them.
            have = {r[1] for r in cur.execute("PRAGMA table_info(transactions)")}
            for col in ("Timestamp_Raw", "Timestamp_UTC", "Timestamp_Basis"):
                if col not in have:
                    cur.execute(f"ALTER TABLE transactions ADD COLUMN {col} TEXT")

            # Phase 5B.2: every record says which evidence item (device) it came from.
            for tbl in sorted(ALLOWED_TABLES):
                tbl_cols = {r[1] for r in cur.execute(f"PRAGMA table_info({tbl})")}
                if "Evidence_Item" not in tbl_cols:
                    cur.execute(f"ALTER TABLE {tbl} ADD COLUMN Evidence_Item TEXT")
                # Phase 5B.4: every record says which decoder produced it.
                if "Decoded_By" not in tbl_cols:
                    cur.execute(f"ALTER TABLE {tbl} ADD COLUMN Decoded_By TEXT")
                if tbl in ("chats", "transactions"):
                    cur.execute(f"CREATE INDEX IF NOT EXISTS idx_{tbl}_evidence_item ON {tbl}(Evidence_Item)")

            # Phase 5B.4: one row per file the tool looked at, with what became of it.
            cur.executescript("""
                CREATE TABLE IF NOT EXISTS coverage (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    Evidence_Item TEXT,
                    File TEXT,
                    Size_Bytes INTEGER,
                    Kind TEXT,
                    Outcome TEXT,
                    Reason TEXT,
                    Decoded_By TEXT,
                    Records TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_coverage_item ON coverage(Evidence_Item, Outcome);
            """)
            from parsers.case_tags import SCHEMA as _TAGS_SCHEMA      # Phase 5B.6
            cur.executescript(_TAGS_SCHEMA)
            from parsers.case_media import SCHEMA as _MEDIA_SCHEMA    # Phase 5B.8
            cur.executescript(_MEDIA_SCHEMA)
            from parsers.case_filters import SCHEMA as _FILTERS_SCHEMA    # Phase 5C saved filters
            cur.executescript(_FILTERS_SCHEMA)
            conn.commit()
        finally:
            conn.close()

    # ==========================================================================
    # PARSER TRANSPARENCY (5B.4) AND SEARCH (5B.5)
    # ==========================================================================

    def add_coverage(self, evidence_item: str, rows: List[Dict[str, Any]]) -> int:
        """Stores the coverage rows of one evidence item (replacing any stored earlier for the same item)."""
        conn = self._get_connection()
        try:
            conn.execute("DELETE FROM coverage WHERE Evidence_Item = ?", (evidence_item,))
            conn.executemany(
                "INSERT INTO coverage(Evidence_Item, File, Size_Bytes, Kind, Outcome, Reason, Decoded_By, Records) VALUES (?,?,?,?,?,?,?,?)",
                [(evidence_item, r.get("file"), r.get("size_bytes"), r.get("kind"), r.get("outcome"), r.get("reason"),
                  r.get("decoded_by"), json.dumps(r.get("records") or {}, sort_keys=True)) for r in rows],
            )
            conn.commit()
            return len(rows)
        finally:
            conn.close()

    def get_coverage(self, evidence_item: Optional[str] = None) -> List[Dict[str, Any]]:
        conn = self._get_connection()
        try:
            sql = "SELECT * FROM coverage" + (" WHERE Evidence_Item = ?" if evidence_item else "") + " ORDER BY id"
            out = []
            for r in conn.execute(sql, (evidence_item,) if evidence_item else ()):
                d = dict(r)
                try:
                    d["Records"] = json.loads(d.get("Records") or "{}")
                except ValueError:
                    d["Records"] = {}
                out.append(d)
            return out
        finally:
            conn.close()

    def decoder_summary(self, evidence_item: Optional[str] = None) -> List[Dict[str, Any]]:
        """For every decoder named in Decoded_By: how many records of each table it produced."""
        conn = self._get_connection()
        try:
            present = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            agg: Dict[str, Dict[str, int]] = {}
            for tbl in sorted(ALLOWED_TABLES):
                if tbl not in present or tbl == 'vfs_files':
                    continue
                sql = f"SELECT Decoded_By, COUNT(*) FROM {tbl}" + (" WHERE Evidence_Item = ?" if evidence_item else "") + " GROUP BY Decoded_By"
                for by, n in conn.execute(sql, (evidence_item,) if evidence_item else ()):
                    agg.setdefault(by or "", {})[tbl] = n
            return [{"decoded_by": k or None, "records": v, "total": sum(v.values())} for k, v in sorted(agg.items(), key=lambda kv: -sum(kv[1].values()))]
        finally:
            conn.close()

    def search(self, query: str, **kw: Any) -> Dict[str, Any]:
        """Search every table (see parsers.case_search). Read-only."""
        from parsers.case_search import search_case
        conn = self._get_connection()
        try:
            return search_case(conn, query, allowed_tables=ALLOWED_TABLES, **kw)
        finally:
            conn.close()

    def timeline(self, **kw: Any) -> Dict[str, Any]:
        """Phase 5B.7: events of every table that has a time (see parsers.case_timeline). Read-only."""
        from parsers.case_timeline import timeline
        conn = self._get_connection()
        try:
            return timeline(conn, **kw)
        finally:
            conn.close()

    # Phase 5B.6: tags
    def tag_records(self, tag: str, records: List[Any], note: str = "") -> Dict[str, Any]:
        from parsers import case_tags
        conn = self._get_connection()
        try:
            return case_tags.apply_tag(conn, tag, [(t, i) for t, i in records], ALLOWED_TABLES, note)
        finally:
            conn.close()

    def untag_records(self, tag: str, records: List[Any]) -> Dict[str, Any]:
        from parsers import case_tags
        conn = self._get_connection()
        try:
            return case_tags.remove_tag(conn, tag, [(t, i) for t, i in records])
        finally:
            conn.close()

    def list_tags(self, evidence_item: Optional[str] = None) -> Dict[str, Any]:
        from parsers import case_tags
        conn = self._get_connection()
        try:
            return case_tags.list_tags(conn, evidence_item)
        finally:
            conn.close()

    def tagged_records(self, tag: str, **kw: Any) -> Dict[str, Any]:
        from parsers import case_tags
        conn = self._get_connection()
        try:
            return case_tags.tagged_records(conn, tag, ALLOWED_TABLES, **kw)
        finally:
            conn.close()

    def reattach_tags(self, item_id: str) -> Dict[str, int]:
        from parsers import case_tags
        conn = self._get_connection()
        try:
            return case_tags.reattach(conn, item_id, ALLOWED_TABLES)
        finally:
            conn.close()

    def get_record(self, table: str, record_id: int) -> Optional[Dict[str, Any]]:
        """One whole record as stored. Missing values stay None."""
        tbl = table.lower().strip()
        if tbl not in ALLOWED_TABLES:
            raise ValueError(f"Not a table of the case store: {table}")
        conn = self._get_connection()
        try:
            r = conn.execute(f"SELECT * FROM {tbl} WHERE id = ?", (record_id,)).fetchone()
            return dict(r) if r else None
        finally:
            conn.close()

    def record_tags(self, table: str, record_id: int) -> List[str]:
        """The tags on one record (detached tags are not included)."""
        from parsers import case_tags
        conn = self._get_connection()
        try:
            return case_tags.tags_for(conn, table.lower().strip(), [record_id]).get(record_id, [])
        finally:
            conn.close()

    def delete_evidence_item(self, item_id: str) -> Dict[str, int]:
        """Removes every record of one evidence item (used when that item is processed again). Other items are untouched."""
        removed: Dict[str, int] = {}
        conn = self._get_connection()
        try:
            from parsers import case_tags
            case_tags.snapshot_item(conn, item_id)       # tags are kept; reattach_tags places them again afterwards
            existing = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            for tbl in sorted(ALLOWED_TABLES):
                cur = conn.execute(f"DELETE FROM {tbl} WHERE Evidence_Item = ?", (item_id,))
                removed[tbl] = cur.rowcount
                if removed[tbl] and f"{tbl}_fts" in existing:
                    # chats and transactions have a delete trigger; the others do not, so rebuild their index
                    conn.execute(f"INSERT INTO {tbl}_fts({tbl}_fts) VALUES('rebuild')")
            conn.execute("DELETE FROM coverage WHERE Evidence_Item = ?", (item_id,))
            if "media_items" in existing:
                conn.execute("DELETE FROM media_items WHERE Evidence_Item = ?", (item_id,))      # hash lists are case-level and stay
            conn.commit()
        finally:
            conn.close()
        return removed

    # ==========================================================================
    # STREAMING CHUNKED INGESTION
    # ==========================================================================

    def ingest_dataframe_chunked(
        self,
        table_name: str,
        df: pd.DataFrame,
        chunk_size: int = 5000,
        evidence_item: Optional[str] = None,
    ) -> int:
        """
        Streams parsed DataFrames to disk in chunks of chunk_size and immediately
        triggers garbage collection to prevent memory exhaustion on 1 TB+ images.
        Returns total rows inserted.
        """
        if df is None or df.empty:
            return 0

        target_table = table_name.lower().strip()
        allowed_tables = {
            'chats', 'transactions', 'contacts', 'calls', 'locations', 'os_spillover',
            'notifications', 'custodial_wallets', 'p2p_orders', 'fiat_crypto_bridge',
            'crypto_addresses', 'vfs_files'
        }
        if target_table not in allowed_tables:
            raise ValueError(f"Target table '{table_name}' is not in allowed set: {allowed_tables}")

        conn = self._get_connection()
        total_inserted = 0

        try:
            # Discover matching columns
            cur = conn.cursor()
            cur.execute(f"PRAGMA table_info({target_table})")
            db_cols = [r['name'] for r in cur.fetchall() if r['name'] != 'id']

            if target_table == 'chats':
                df = adapt_legacy_chat_frame(df)
            if evidence_item:
                df = df.copy()
                df['Evidence_Item'] = evidence_item

            common_cols = [c for c in db_cols if c in df.columns]
            # C-11: never drop data silently. Columns the store cannot hold are reported.
            dropped = [
                c for c in df.columns
                if c not in db_cols and c != 'id' and df[c].notna().any()
                and df[c].astype(str).str.strip().ne('').any()
            ]
            self.last_dropped_columns[target_table] = dropped
            if not common_cols:
                return 0

            placeholders = ','.join(['?'] * len(common_cols))
            col_list_str = ','.join(f'"{c}"' for c in common_cols)
            insert_sql = f'INSERT INTO {target_table} ({col_list_str}) VALUES ({placeholders})'

            num_rows = len(df)
            for i in range(0, num_rows, chunk_size):
                chunk = df.iloc[i : i + chunk_size]

                # Convert values to standard SQLite primitive types
                rows_to_insert = []
                for row in chunk[common_cols].itertuples(index=False, name=None):
                    cleaned_row = []
                    for val in row:
                        if pd.isna(val) or val is None:
                            cleaned_row.append(None)
                        elif isinstance(val, bool):
                            cleaned_row.append(1 if val else 0)
                        elif isinstance(val, (int, float, str, bytes)):
                            cleaned_row.append(val)
                        else:
                            cleaned_row.append(str(val))
                    rows_to_insert.append(tuple(cleaned_row))

                conn.executemany(insert_sql, rows_to_insert)
                conn.commit()
                total_inserted += len(rows_to_insert)

                del rows_to_insert
                del chunk
                gc.collect()

            return total_inserted
        finally:
            conn.close()

    # ==========================================================================
    # FAST UI QUERY ENDPOINTS
    # ==========================================================================

    def get_project_tree_counts(self) -> Dict[str, Dict[str, int]]:
        """
        Returns live (total, active, wal_and_carved) counts for every node in the
        the case evidence tree.
        """
        conn = self._get_connection()
        try:
            cur = conn.cursor()
            res: Dict[str, Dict[str, int]] = {}

            # Helper for counting table rows by condition
            def _calc_counts(table: str, app_pattern: Optional[str] = None, extra_where: str = '') -> Dict[str, int]:
                where_clauses = []
                params = []
                if app_pattern:
                    where_clauses.append("Application LIKE ?")
                    params.append(f"%{app_pattern}%")
                if extra_where:
                    where_clauses.append(extra_where)

                base_where = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""

                # Total count
                cur.execute(f"SELECT COUNT(*) AS cnt FROM {table} {base_where}", params)
                total = cur.fetchone()['cnt'] or 0

                # WAL and Carved count
                wal_where_clause = "Forensic_Provenance LIKE '%:: State=WAL%' OR Forensic_Provenance LIKE '%:: State=CARVED%' OR Forensic_Provenance LIKE '%:: State=FREELIST%' OR Forensic_Provenance LIKE '%:: State=SLACK%' OR Forensic_Provenance LIKE '%:: State=Unallocated%'"
                if table == 'chats':
                    wal_where_clause += " OR Is_Revoked_Deleted = 1"

                cur_wal_clauses = list(where_clauses) + [f"({wal_where_clause})"]
                wal_full_where = f"WHERE {' AND '.join(cur_wal_clauses)}"
                cur.execute(f"SELECT COUNT(*) AS cnt FROM {table} {wal_full_where}", params)
                wal_carved = cur.fetchone()['cnt'] or 0

                active = max(0, total - wal_carved)
                return {'total': total, 'active': active, 'wal_and_carved': wal_carved}

            # 1. CHATS
            res['chats_all'] = _calc_counts('chats')
            res['chats_whatsapp'] = _calc_counts('chats', 'whatsapp')
            res['chats_telegram'] = _calc_counts('chats', 'telegram')
            res['chats_snapchat'] = _calc_counts('chats', 'snapchat')
            res['chats_signal'] = _calc_counts('chats', 'signal')
            res['chats_zangi'] = _calc_counts('chats', 'zangi')
            res['chats_element'] = _calc_counts('chats', 'element')
            res['chats_session'] = _calc_counts('chats', 'session')
            res['chats_instagram'] = _calc_counts('chats', 'instagram')

            # Dating apps aggregated
            dating_where = " OR ".join([f"Application LIKE '%{k}%'" for k in DATING_KEYWORDS])
            res['chats_dating'] = _calc_counts('chats', extra_where=f"({dating_where})")

            # 2. CALL LOGS
            res['calls_all'] = _calc_counts('calls')
            res['calls_cellular'] = _calc_counts('calls', extra_where="Call_Type = 'CELLULAR_CDR' OR Call_Type LIKE '%CDR%'")
            res['calls_voip'] = _calc_counts('calls', extra_where="Call_Type = 'VOIP_APP' OR Call_Type LIKE '%VOIP%'")

            # 3. CONTACTS & DATING
            res['contacts_all'] = _calc_counts('contacts')
            res['contacts_saved'] = _calc_counts('contacts', extra_where="Application NOT LIKE '%Tinder%' AND Application NOT LIKE '%Bumble%' AND Application NOT LIKE '%UPI%'")
            res['contacts_dating'] = _calc_counts('contacts', extra_where="Application LIKE '%Tinder%' OR Application LIKE '%Bumble%' OR Application LIKE '%Hinge%' OR Application LIKE '%Grindr%'")
            res['contacts_upi'] = _calc_counts('contacts', extra_where="Application LIKE '%UPI%' OR Application LIKE '%PhonePe%' OR Application LIKE '%GPay%' OR Application LIKE '%Paytm%'")

            # 4. UPI & BANKING LEDGER
            res['upi_all'] = _calc_counts('transactions')
            res['upi_phonepe'] = _calc_counts('transactions', 'phonepe')
            res['upi_gpay'] = _calc_counts('transactions', 'google')
            res['upi_paytm'] = _calc_counts('transactions', 'paytm')
            res['upi_bhim'] = _calc_counts('transactions', 'bhim')
            res['upi_cred'] = _calc_counts('transactions', 'cred')
            res['upi_banks'] = _calc_counts('transactions', extra_where="Application LIKE '%Bank%' OR Application LIKE '%HDFC%' OR Application LIKE '%SBI%' OR Application LIKE '%ICICI%' OR Application LIKE '%Axis%'")
            res['upi_ghost_intents'] = _calc_counts('transactions', extra_where="Direction = 'GHOST_INTENT' OR Status = 'ABANDONED_INTENT'")
            res['upi_clock_tamper'] = _calc_counts('transactions', extra_where="Clock_Tamper_Detected = 1")

            # 5. CRYPTO & CYBERCRIME & SPILLOVER
            res['crypto_all'] = _calc_counts('transactions', extra_where="Application LIKE '%Crypto%' OR Application LIKE '%Binance%' OR Application LIKE '%WazirX%' OR Application LIKE '%CoinDCX%'")
            res['crypto_custodial'] = _calc_counts('transactions', extra_where="Type = 'CRYPTO_DEPOSIT' OR Type = 'CRYPTO_WITHDRAWAL'")
            res['crypto_p2p'] = _calc_counts('transactions', extra_where="Type = 'P2P_ESCROW' OR Type = 'P2P_TRADE'")
            res['crypto_bridge'] = _calc_counts('transactions', extra_where="Status = 'FIAT_TO_CRYPTO_BRIDGED'")

            res['os_spillover_all'] = _calc_counts('os_spillover')
            res['os_notifications'] = _calc_counts('os_spillover', extra_where="Vector_Type LIKE '%Notification%'")
            res['os_keyboard'] = _calc_counts('os_spillover', extra_where="Vector_Type LIKE '%Keyboard%' OR Vector_Type LIKE '%Gboard%'")
            res['os_clipboard'] = _calc_counts('os_spillover', extra_where="Vector_Type LIKE '%Clipboard%'")
            res['os_switcher'] = _calc_counts('os_spillover', extra_where="Vector_Type LIKE '%Switcher%' OR Vector_Type LIKE '%Snapshot%'")
            res['os_usagestats'] = _calc_counts('os_spillover', extra_where="Vector_Type LIKE '%UsageStats%'")

            res['locations_all'] = _calc_counts('locations')

            return res
        finally:
            conn.close()

    def get_chat_threads_summary(
        self,
        app_filter: Optional[str] = None,
        search_query: Optional[str] = None,
        recovery_filter: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> pd.DataFrame:
        """
        Returns grouped conversation threads for the PA Left Sub-Pane Thread List:
        Application, Thread_ID, Thread_Title, Chat_Type, Participant_Identifier,
        Participant_Bio_Meta, Total_Messages, Deleted_Carved_Count, Last_Timestamp_IST.
        """
        conn = self._get_connection()
        try:
            where_clauses: List[str] = []
            params: List[Any] = []

            if app_filter and app_filter != 'ALL':
                if app_filter.lower() == 'dating':
                    d_clauses = " OR ".join([f"Application LIKE '%{k}%'" for k in DATING_KEYWORDS])
                    where_clauses.append(f"({d_clauses})")
                else:
                    where_clauses.append("Application LIKE ?")
                    params.append(f"%{app_filter}%")

            if search_query and isinstance(search_query, str) and search_query.strip():
                # Search via FTS5
                where_clauses.append(
                    "chats.id IN (SELECT rowid FROM chats_fts WHERE chats_fts MATCH ?)"
                )
                params.append(search_query.strip())

            if recovery_filter and recovery_filter != 'ALL':
                if recovery_filter == 'WAL_AND_CARVED_ONLY':
                    where_clauses.append(
                        "(Forensic_Provenance LIKE '%:: State=WAL%' OR Forensic_Provenance LIKE '%:: State=CARVED%' OR Forensic_Provenance LIKE '%:: State=FREELIST%' OR Is_Revoked_Deleted = 1)"
                    )
                elif recovery_filter == 'ACTIVE':
                    where_clauses.append(
                        "(COALESCE(Forensic_Provenance, '') NOT LIKE '%:: State=WAL%' AND COALESCE(Forensic_Provenance, '') NOT LIKE '%:: State=CARVED%' AND COALESCE(Forensic_Provenance, '') NOT LIKE '%:: State=FREELIST%' AND Is_Revoked_Deleted = 0)"
                    )

            base_where = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""

            query = f"""
                SELECT
                    Application,
                    Thread_ID,
                    COALESCE(MAX(Thread_Title), MAX(Recipient_Name), MAX(Sender_Name), Thread_ID) AS Thread_Title,
                    MAX(Chat_Type) AS Chat_Type,
                    COALESCE(MAX(Recipient_Identifier), MAX(Sender_Identifier), '') AS Participant_Identifier,
                    COALESCE(MAX(Participant_Bio_Meta), '') AS Participant_Bio_Meta,
                    COUNT(*) AS Total_Messages,
                    SUM(CASE WHEN (Forensic_Provenance LIKE '%:: State=WAL%' OR Forensic_Provenance LIKE '%:: State=CARVED%' OR Forensic_Provenance LIKE '%:: State=FREELIST%' OR Is_Revoked_Deleted = 1) THEN 1 ELSE 0 END) AS Deleted_Carved_Count,
                    MAX(Timestamp_IST) AS Last_Timestamp_IST
                FROM chats
                {base_where}
                GROUP BY Application, Thread_ID
                ORDER BY Last_Timestamp_IST DESC
                LIMIT ? OFFSET ?
            """
            params.extend([max(1, limit), max(0, offset)])
            df_threads = pd.read_sql_query(query, conn, params=params)
            return df_threads
            return df_threads
        finally:
            conn.close()

    def get_paginated_rows(
        self,
        table_name: str,
        filters: Optional[Dict[str, Any]] = None,
        search_query: str = '',
        sort_col: str = 'Timestamp_IST',
        sort_asc: bool = False,
        limit: int = 100,
        offset: int = 0,
    ) -> Tuple[pd.DataFrame, int]:
        """
        Executes sub-10ms FTS5 + indexed WHERE queries and returns (page_df, total_matching_rows).
        Zero DataFrame duplication in memory.
        """
        target_table = table_name.lower().strip()
        category_map = {
            'upi_transactions': 'transactions',
            'transactions': 'transactions',
            'chats': 'chats',
            'contacts': 'contacts',
            'calls': 'calls',
            'locations': 'locations',
            'os_spillover': 'os_spillover',
            'notifications': 'notifications',
            'custodial_wallets': 'custodial_wallets',
            'p2p_orders': 'p2p_orders',
            'fiat_crypto_bridge': 'fiat_crypto_bridge',
            'crypto_addresses': 'crypto_addresses',
            'vfs_files': 'vfs_files',
        }
        target_table = category_map.get(target_table, target_table)
        allowed = {
            'chats', 'transactions', 'contacts', 'calls', 'locations', 'os_spillover',
            'notifications', 'custodial_wallets', 'p2p_orders', 'fiat_crypto_bridge',
            'crypto_addresses', 'vfs_files'
        }
        if target_table not in allowed:
            raise ValueError(f"Table '{table_name}' is not supported for pagination.")

        conn = self._get_connection()
        try:
            where_clauses: List[str] = []
            params: List[Any] = []

            # 1. Full-Text Search via FTS5 or LIKE
            if search_query and isinstance(search_query, str) and search_query.strip():
                clean_q = search_query.strip()
                if target_table in {'chats', 'transactions', 'contacts', 'calls', 'locations', 'os_spillover'}:
                    fts_table = f"{target_table}_fts"
                    safe_q = clean_q.replace('"', '""')
                    terms = safe_q.split()
                    if len(terms) == 1:
                        formatted_match = f'"{terms[0]}"*'
                    else:
                        formatted_match = " ".join(f'"{t}"*' for t in terms)

                    where_clauses.append(
                        f"{target_table}.id IN (SELECT rowid FROM {fts_table} WHERE {fts_table} MATCH ?)"
                    )
                    params.append(formatted_match)
                else:
                    cur = conn.cursor()
                    cur.execute(f"PRAGMA table_info({target_table})")
                    text_cols = [r['name'] for r in cur.fetchall() if r['type'] == 'TEXT']
                    if text_cols:
                        like_clauses = [f'"{col}" LIKE ?' for col in text_cols]
                        where_clauses.append(f"({' OR '.join(like_clauses)})")
                        params.extend([f"%{clean_q}%"] * len(text_cols))

            # 2. Key-Value Filters
            if filters:
                for k, v in filters.items():
                    if v is None or v == '' or v == 'ALL':
                        continue

                    # Special filter keys
                    if k == 'app_filter':
                        if str(v).lower() == 'dating':
                            d_clauses = " OR ".join([f"Application LIKE '%{kw}%'" for kw in DATING_KEYWORDS])
                            where_clauses.append(f"({d_clauses})")
                        else:
                            where_clauses.append("Application LIKE ?")
                            params.append(f"%{v}%")

                    elif k == 'recovery_filter':
                        if v == 'WAL_AND_CARVED_ONLY' or v == 'CARVED':
                            where_clauses.append(
                                "(Forensic_Provenance LIKE '%:: State=WAL%' OR Forensic_Provenance LIKE '%:: State=CARVED%' OR Forensic_Provenance LIKE '%:: State=FREELIST%' OR Is_Revoked_Deleted = 1)"
                            )
                        elif v == 'ACTIVE':
                            where_clauses.append(
                                "(COALESCE(Forensic_Provenance, '') NOT LIKE '%:: State=WAL%' AND COALESCE(Forensic_Provenance, '') NOT LIKE '%:: State=CARVED%' AND COALESCE(Forensic_Provenance, '') NOT LIKE '%:: State=FREELIST%' AND Is_Revoked_Deleted = 0)"
                            )
                        elif v == 'OS_SPILLOVER':
                            where_clauses.append("Forensic_Provenance LIKE '%OS_SPILLOVER%'")

                    elif k == 'ephemeral_filter':
                        if v == 'VIEW_ONCE':
                            where_clauses.append("Is_View_Once = 1")
                        elif v == 'DISAPPEARING':
                            where_clauses.append("Disappearing_TTL_Sec > 0")
                        elif v == 'REVOKED':
                            where_clauses.append("Is_Revoked_Deleted = 1")
                        elif v == 'MEDIA_OR_GPS':
                            where_clauses.append("(Attachment_Path_or_URL != '' OR Geo_Coordinates != '')")

                    elif k == 'evidence_item':
                        where_clauses.append("Evidence_Item = ?")
                        params.append(str(v))

                    elif k == 'thread_id':
                        where_clauses.append("Thread_ID = ?")
                        params.append(str(v))

                    elif k == 'clock_tamper_only' and v is True:
                        where_clauses.append("Clock_Tamper_Detected = 1")

                    elif isinstance(v, (int, float)):
                        where_clauses.append(f'"{k}" = ?')
                        params.append(v)
                    elif isinstance(v, str):
                        where_clauses.append(f'"{k}" LIKE ?')
                        params.append(f"%{v}%")

            where_str = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""

            # Check sort column validity
            cur = conn.cursor()
            cur.execute(f"PRAGMA table_info({target_table})")
            valid_cols = {r['name'] for r in cur.fetchall()}
            if sort_col not in valid_cols:
                sort_col = 'id'

            order_dir = 'ASC' if sort_asc else 'DESC'

            # 3. Total Matching Count (Optimized)
            count_sql = f"SELECT COUNT(*) AS total FROM {target_table} {where_str}"
            cur.execute(count_sql, params)
            total_rows = cur.fetchone()['total'] or 0

            # 4. Paginated Slice Query
            page_sql = f"""
                SELECT * FROM {target_table}
                {where_str}
                ORDER BY "{sort_col}" {order_dir}
                LIMIT ? OFFSET ?
            """
            slice_params = list(params) + [max(1, limit), max(0, offset)]
            df_page = pd.read_sql_query(page_sql, conn, params=slice_params)

            return df_page, total_rows
        finally:
            conn.close()

    get_paginated_records = get_paginated_rows

    # ==========================================================================
    # SYNCHRONIZED MMAP HEX WINDOW STREAMER
    # ==========================================================================

    def read_provenance_hex_window(
        self,
        provenance_str: Optional[str] = None,
        window_bytes: int = 4096,
        file_path: Optional[str] = None,
        byte_offset: Optional[int] = None,
        window_size: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Parses Forensic_Provenance string or direct file_path/byte_offset, opens the underlying file with
        mmap.ACCESS_READ, reads the 4096-byte window around Byte_Offset, and returns
        formatted 16-byte Hex + ASCII lines with target byte span highlighted.
        """
        if window_size is not None:
            window_bytes = window_size

        empty_res: Dict[str, Any] = {
            'file_path': file_path or '',
            'target_offset': byte_offset or 0,
            'target_length': 32,
            'start_offset': byte_offset or 0,
            'window_bytes': 0,
            'hex_lines': [],
            'raw_hex': '',
            'provenance_parsed': {},
        }

        # Handle direct file_path & byte_offset call
        if not provenance_str and file_path:
            provenance_str = f"{file_path} :: Offset={byte_offset or 0}"

        if not provenance_str or not isinstance(provenance_str, str):
            return empty_res

        # Parse Provenance pattern:
        # e.g. "msgstore.db :: Table=message :: RowID=42 :: Page_2 :: Offset=0x00066000 :: State=WAL_RECOVERED"
        # or "D:/Cases/.../cache4.db :: Page_1 :: Offset=0x000412A0 :: State=CARVED_FREELIST"
        prov_parsed: Dict[str, Any] = {
            'raw_string': provenance_str,
            'file_path': '',
            'table_name': '',
            'row_id': '',
            'page_number': 0,
            'byte_offset': 0,
            'byte_length': 32,
            'recovery_state': 'ACTIVE',
        }

        # 1. Extract physical byte offset (0x... or decimal)
        m_off = re.search(r'Offset\s*=\s*(0x[0-9a-fA-F]+|\d+)', provenance_str, re.IGNORECASE)
        if m_off:
            raw_off = m_off.group(1)
            prov_parsed['byte_offset'] = int(raw_off, 16) if raw_off.lower().startswith('0x') else int(raw_off)

        # 2. Extract Page number
        m_pg = re.search(r'Page(?:_|\s+)(\d+)', provenance_str, re.IGNORECASE)
        if m_pg:
            prov_parsed['page_number'] = int(m_pg.group(1))

        # 3. Extract Table name
        m_tbl = re.search(r'Table(?:=|\s+)([A-Za-z0-9_]+)', provenance_str, re.IGNORECASE)
        if m_tbl:
            prov_parsed['table_name'] = m_tbl.group(1)

        # 4. Extract Row ID
        m_row = re.search(r'Row(?:ID)?(?:=|\s+)(\d+)', provenance_str, re.IGNORECASE)
        if m_row:
            prov_parsed['row_id'] = m_row.group(1)

        # 5. Extract Recovery State
        m_st = re.search(r'(?:State|Recovery)(?:=|\s+)([A-Za-z0-9_]+)', provenance_str, re.IGNORECASE)
        if m_st:
            prov_parsed['recovery_state'] = m_st.group(1)

        # 6. Extract File path (first segment before '::')
        parts = [p.strip() for p in provenance_str.split('::')]
        if parts:
            prov_parsed['file_path'] = parts[0]

        target_offset = prov_parsed['byte_offset']
        target_length = prov_parsed['byte_length']
        file_path = prov_parsed['file_path']

        # Determine 4KB window boundary aligned to 16 bytes
        pre_roll = min(256, (window_bytes // 4 // 16) * 16)
        start_offset = max(0, (target_offset // 16) * 16 - pre_roll)
        raw_bytes = b''

        # If file exists on disk, open with mmap.ACCESS_READ
        candidate_paths = [
            file_path,
            os.path.join(self.case_workspace, file_path),
            os.path.join(self.case_workspace, os.path.basename(file_path)),
        ]
        resolved_file = next((p for p in candidate_paths if p and os.path.isfile(p)), None)

        if resolved_file:
            try:
                fsize = os.path.getsize(resolved_file)
                if fsize > 0:
                    read_len = min(window_bytes, fsize - start_offset) if start_offset < fsize else 0
                    if read_len > 0:
                        with open(resolved_file, 'rb') as f:
                            with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                                raw_bytes = mm[start_offset : start_offset + read_len]
            except Exception:
                raw_bytes = b''

        # Never synthesise bytes: if the real bytes cannot be read, say so.
        if not raw_bytes:
            if not resolved_file:
                reason = f"File not found: {file_path}"
            elif start_offset >= os.path.getsize(resolved_file):
                reason = (f"Offset {target_offset} is beyond end of file "
                          f"({os.path.getsize(resolved_file)} bytes)")
            else:
                reason = "File could not be read"
            empty_res.update({
                'file_path': resolved_file or file_path,
                'target_offset': target_offset,
                'start_offset': start_offset,
                'provenance_parsed': prov_parsed,
                'error': reason,
            })
            return empty_res

        # Format 16-byte Hex + ASCII lines
        hex_lines = []
        total_len = len(raw_bytes)
        row_count = (total_len + 15) // 16

        for r in range(row_count):
            row_addr = start_offset + (r * 16)
            row_slice = raw_bytes[r * 16 : min((r + 1) * 16, total_len)]

            bytes_info = []
            ascii_info = []

            for c, b_val in enumerate(row_slice):
                cur_addr = row_addr + c
                is_hi = (target_offset <= cur_addr < target_offset + target_length)
                hex_str = f"{b_val:02X}"
                char_str = chr(b_val) if 32 <= b_val <= 126 else '.'

                bytes_info.append({'val': b_val, 'hex': hex_str, 'isHighlighted': is_hi})
                ascii_info.append({'char': char_str, 'isHighlighted': is_hi})

            hex_lines.append({
                'address': row_addr,
                'addressHex': f"{row_addr:08X}",
                'bytes': bytes_info,
                'ascii': ascii_info,
            })

        return {
            'file_path': resolved_file or file_path,
            'target_offset': target_offset,
            'target_length': target_length,
            'start_offset': start_offset,
            'window_bytes': len(raw_bytes),
            'hex_lines': hex_lines,
            'raw_hex': raw_bytes.hex(),
            'provenance_parsed': prov_parsed,
        }

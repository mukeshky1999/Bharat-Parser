"""UPI Forensic Intelligence Suite - Parsers Package Initializer."""

import re

_SAFE_TABLE = re.compile(r"^[A-Za-z0-9_]+$")


def quote_sqlite_identifier(name: str) -> str:
    """Double-quote a SQLite identifier with internal escaping."""
    return '"' + str(name).replace('"', '""') + '"'


def is_safe_sqlite_table_name(name: str) -> bool:
    """Return True if the name contains only alphanumeric characters and underscores."""
    return bool(_SAFE_TABLE.match(str(name or "")))


try:
    from .account_profiler import extract_account_profile
except ImportError:
    pass

try:
    from .app_overrides import (
        SCHEMA_OVERRIDES,
        extract_from_blob,
        find_in_json,
        get_app_override,
        normalize_timestamp_value,
        parse_indian_financial_text,
        try_decompress_blob,
    )
except ImportError:
    pass

try:
    from .corroboration_engine import (
        harvest_corroboration_signals,
        is_background_corroboration_file,
        reconcile_and_enrich_artifacts,
    )
except ImportError:
    pass

try:
    from .corrupt_db_carver import (
        carve_corrupted_sqlite_file,
        run_regression_fault_simulation,
    )
except ImportError:
    pass

try:
    from .crypto_address_validator import (
        harvest_blockchain_addresses_from_bytes,
        validate_eip55_checksum,
    )
except ImportError:
    pass

try:
    from .crypto_p2p_parser import parse_crypto_p2p_artifacts
except ImportError:
    pass

try:
    from .custodial_wallet_parser import (
        WALLET_SIGNATURES,
        BaseWalletParser,
        CoinbaseParser,
        CryptoComParser,
        BitgetParser,
        MexcParser,
        build_address_manifest,
        compute_risk_badge,
        detect_chain_from_address,
        dispatch_custodial_wallet,
        get_wallet_signature,
        is_custodial_wallet_app,
    )
except ImportError:
    pass

try:
    from .wallet_provenance import WalletProvenance
except ImportError:
    pass

try:
    from .wallet_deleted_recovery import recover_deleted_wallet_records
except ImportError:
    pass

try:
    from .deep_sqlite import deep_parse, dump_sqlite_tables
except ImportError:
    pass

try:
    from .fiat_crypto_bridge import align_fiat_to_crypto, align_bank_to_custodial_onramp
except ImportError:
    pass

try:
    from .freelist_carver import (
        KNOWN_UPI_SUFFIXES,
        carve_sqlite_freelists,
        decode_record_payload,
        read_varint,
    )
except ImportError:
    pass

try:
    from .graph_intelligence import (
        audit_shared_vault_write,
        build_transaction_graph,
        classify_syndicate_roles,
        cross_case_correlation,
        detect_mule_behavior,
        extract_charge_sheet_chain,
        fuse_multi_source_graph,
        generate_pyvis_network_html,
    )
except ImportError:
    pass

try:
    from .heuristic_engine import parse_database_artifacts
except ImportError:
    pass

try:
    from .keychain_decryptor import (
        CaseKeyring,
        attempt_sqlcipher_decryption,
        attempt_sqlcipher_open,
        extract_app_keys_and_decrypt,
    )
except ImportError:
    pass

try:
    from .leveldb_parser import carve_leveldb_directory
except ImportError:
    pass

try:
    from .multi_source_fusion import (
        correlate_cdr_with_transactions,
        parse_bank_statement,
        parse_cdr_record,
        reconcile_bank_statement_with_device,
    )
except ImportError:
    pass

try:
    from .npci_storage_carver import (
        NPCI_TXID_REGEX,
        carve_non_sqlite_store,
        parse_npci_upi_uri,
    )
except ImportError:
    pass

try:
    from .plugin_loader import AppPlugin, PluginRegistry
except ImportError:
    pass

try:
    from .protobuf_decoder import (
        ProtobufSchemaSynthesizer,
        decode_protobuf_stream,
        extract_financials_from_protobuf,
        infer_protobuf_schema,
    )
except ImportError:
    pass

try:
    from .vpa_harvester import (
        clean_and_validate_vpa,
        harvest_entities_from_file,
        harvest_ifsc_from_file,
        is_valid_indian_mobile,
        resolve_ifsc_bank,
        resolve_vpa_attribution,
    )
except ImportError:
    pass

try:
    from .wal_rollback_analyzer import analyze_wal_revisions, parse_wal_file
except ImportError:
    pass

try:
    from .zero_knowledge_miner import inspect_unindexed_database
except ImportError:
    pass

_CANDIDATE_ALL = [
    "extract_account_profile",
    "SCHEMA_OVERRIDES",
    "extract_from_blob",
    "find_in_json",
    "get_app_override",
    "normalize_timestamp_value",
    "parse_indian_financial_text",
    "try_decompress_blob",
    "harvest_corroboration_signals",
    "is_background_corroboration_file",
    "reconcile_and_enrich_artifacts",
    "carve_corrupted_sqlite_file",
    "run_regression_fault_simulation",
    "carve_sqlite_freelists",
    "decode_record_payload",
    "read_varint",
    "KNOWN_UPI_SUFFIXES",
    "audit_shared_vault_write",
    "build_transaction_graph",
    "fuse_multi_source_graph",
    "classify_syndicate_roles",
    "extract_charge_sheet_chain",
    "detect_mule_behavior",
    "generate_pyvis_network_html",
    "cross_case_correlation",
    "parse_database_artifacts",
    "extract_app_keys_and_decrypt",
    "attempt_sqlcipher_decryption",
    "carve_leveldb_directory",
    "carve_non_sqlite_store",
    "parse_npci_upi_uri",
    "NPCI_TXID_REGEX",
    "decode_protobuf_stream",
    "extract_financials_from_protobuf",
    "infer_protobuf_schema",
    "ProtobufSchemaSynthesizer",
    "harvest_entities_from_file",
    "resolve_vpa_attribution",
    "clean_and_validate_vpa",
    "harvest_ifsc_from_file",
    "is_valid_indian_mobile",
    "resolve_ifsc_bank",
    "harvest_blockchain_addresses_from_bytes",
    "validate_eip55_checksum",
    "parse_crypto_p2p_artifacts",
    "align_fiat_to_crypto",
    "align_bank_to_custodial_onramp",
    "WALLET_SIGNATURES",
    "BaseWalletParser",
    "CoinbaseParser",
    "CryptoComParser",
    "BitgetParser",
    "MexcParser",
    "build_address_manifest",
    "compute_risk_badge",
    "detect_chain_from_address",
    "dispatch_custodial_wallet",
    "get_wallet_signature",
    "is_custodial_wallet_app",
    "WalletProvenance",
    "recover_deleted_wallet_records",
    "deep_parse",
    "dump_sqlite_tables",
    "CaseKeyring",
    "attempt_sqlcipher_open",
    "quote_sqlite_identifier",
    "is_safe_sqlite_table_name",
    "AppPlugin",
    "PluginRegistry",
    "inspect_unindexed_database",
    "analyze_wal_revisions",
    "parse_wal_file",
    "parse_bank_statement",
    "parse_cdr_record",
    "reconcile_bank_statement_with_device",
    "correlate_cdr_with_transactions",
]

__all__ = [name for name in _CANDIDATE_ALL if name in globals()]

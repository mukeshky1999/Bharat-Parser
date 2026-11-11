"""
Package initialization for Phase 4, Module 4.4:
Cross-System BIP-39 Seed Hunter, HD Derivation & Rupee-to-Crypto Correlator Engine.
"""

from src.seedhunter.models import (
    SecretType,
    BlockchainNetwork,
    LaunderingPattern,
    RecoveredSeedRecord,
    HDDerivedAddressRecord,
    LaunderingChainRecord,
    Phase3UPIPayment,
    Phase4P2POrder,
    Phase4CryptoWithdrawal,
)
from src.seedhunter.seed_hunter import (
    validate_bip39_mnemonic,
    validate_monero_seed,
    decode_wif_private_key,
    validate_raw_hex_privkey,
    scan_text_for_crypto_secrets,
)
from src.seedhunter.hd_derivator import (
    derive_master_seed_bip39,
    derive_hd_address,
    derive_all_standard_addresses,
)
from src.seedhunter.vault_unwrapper import (
    unwrap_web3_keystore_v3,
    unwrap_metamask_vault,
)
from src.seedhunter.correlator import (
    RupeeToCryptoCorrelator,
)
from src.seedhunter.engine import (
    SeedHunterCorrelatorEngine,
)

__all__ = [
    "SecretType",
    "BlockchainNetwork",
    "LaunderingPattern",
    "RecoveredSeedRecord",
    "HDDerivedAddressRecord",
    "LaunderingChainRecord",
    "Phase3UPIPayment",
    "Phase4P2POrder",
    "Phase4CryptoWithdrawal",
    "validate_bip39_mnemonic",
    "validate_monero_seed",
    "decode_wif_private_key",
    "validate_raw_hex_privkey",
    "scan_text_for_crypto_secrets",
    "derive_master_seed_bip39",
    "derive_hd_address",
    "derive_all_standard_addresses",
    "unwrap_web3_keystore_v3",
    "unwrap_metamask_vault",
    "RupeeToCryptoCorrelator",
    "SeedHunterCorrelatorEngine",
]

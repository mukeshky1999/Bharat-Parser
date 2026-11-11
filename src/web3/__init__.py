"""
Web3 Self-Custody Wallets Forensic Engine.
Phase 4, Module 4.1.
"""

from src.web3.models import (
    BlockchainNetwork,
    Web3AccountControlMode,
    Web3CrossChainSwapRecord,
    Web3TransactionRecord,
    Web3TxOperationType,
    Web3WalletAccountRecord,
)
from src.web3.address_utils import (
    base58check_to_hex41,
    format_bigint_decimal,
    hex41_to_base58check,
)
from src.web3.tronlink import TronLinkDecoder
from src.web3.metamask import MetaMaskDecoder
from src.web3.trustwallet import TrustWalletDecoder
from src.web3.cakewallet import CakeWalletDecoder
from src.web3.ledgerlive import LedgerLiveDecoder
from src.web3.engine import Web3SelfCustodyWalletsEngine

__all__ = [
    "BlockchainNetwork",
    "Web3AccountControlMode",
    "Web3CrossChainSwapRecord",
    "Web3TransactionRecord",
    "Web3TxOperationType",
    "Web3WalletAccountRecord",
    "base58check_to_hex41",
    "format_bigint_decimal",
    "hex41_to_base58check",
    "TronLinkDecoder",
    "MetaMaskDecoder",
    "TrustWalletDecoder",
    "CakeWalletDecoder",
    "LedgerLiveDecoder",
    "Web3SelfCustodyWalletsEngine",
]

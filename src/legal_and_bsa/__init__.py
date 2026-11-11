"""
Phase 8, Module 8.3: Indian Legal Compliance, Hash Manifests & Section 63 BSA Statutory Certificates.
"""

from src.legal_and_bsa.models import (
    HashTier,
    StatutoryRegimeMode,
    ImmutabilityStatus,
    DeponentDetails,
    DeviceMetadata,
    ForensicExpertDetails,
    WorkstationEnvironment,
    IntegrityAuditDisclosure,
    EvidentiaryHashManifestItem,
    Section63BsaCertificateRecord,
    ChainOfCustodyEntry,
)
from src.legal_and_bsa.hash_manifest import HierarchicalHashManifestManager
from src.legal_and_bsa.bsa_certificate_generator import Section63BsaCertificateGenerator
from src.legal_and_bsa.chain_of_custody import (
    MerkleChainOfCustodyLedger,
    ChainOfCustodyTamperException,
)
from src.legal_and_bsa.engine import LegalComplianceAndBsaEngine

__all__ = [
    "HashTier",
    "StatutoryRegimeMode",
    "ImmutabilityStatus",
    "DeponentDetails",
    "DeviceMetadata",
    "ForensicExpertDetails",
    "WorkstationEnvironment",
    "IntegrityAuditDisclosure",
    "EvidentiaryHashManifestItem",
    "Section63BsaCertificateRecord",
    "ChainOfCustodyEntry",
    "HierarchicalHashManifestManager",
    "Section63BsaCertificateGenerator",
    "MerkleChainOfCustodyLedger",
    "ChainOfCustodyTamperException",
    "LegalComplianceAndBsaEngine",
]

"""
Sub-Engine 8.1A: Constrained Disjoint-Set Union (DSU) Entity Resolver.
Resolves fragmented observations across Phases 1 through 7 into unified Master Entity Profiles.
Enforces Two-Tier Key Hierarchy: only Tier 1 Hard Unique Keys trigger automated node merging.
Prevents false-positive transitive merging on soft attribute keys.
Adheres strictly to AGENTS.md Forensic Invariants and Section 3 of Module 8.1 Specification.
"""

import json
import re
from typing import Any, Dict, List, Set

from src.entity_and_timeline.models import (
    AtomicObservation,
    EntityClassification,
    MasterEntityProfile,
)


class ConstrainedEntityResolver:
    """Deterministic entity resolver implementing constrained DSU over Tier 1 Hard Keys."""

    def __init__(self):
        self._next_uid = 1

    def normalize_hard_key(self, raw_key: str) -> str:
        """Normalizes a Tier 1 Hard Unique Key to canonical format."""
        k = raw_key.strip()
        lower_k = k.lower()

        # 1. Phone number normalization (domestic tail-10)
        if lower_k.startswith("phone:") or lower_k.startswith("phone_tail10:"):
            digits = re.sub(r"\D", "", k)
            if len(digits) >= 10:
                tail10 = digits[-10:]
                return f"phone_tail10:{tail10}"
            return lower_k

        # 2. VPA Handle (lowercase)
        if lower_k.startswith("vpa:"):
            return lower_k

        # 3. WhatsApp JID / LID
        if lower_k.startswith("wa_lid:") or lower_k.startswith("wa_jid:"):
            return lower_k

        # 4. PAN Number
        if lower_k.startswith("pan:"):
            return lower_k

        # 5. CEX User ID
        if lower_k.startswith("cex:"):
            return lower_k

        # 6. Crypto Wallet Address
        if lower_k.startswith("crypto:"):
            return lower_k

        # 7. Bank Account + IFSC
        if lower_k.startswith("bank:"):
            return lower_k

        return lower_k

    def resolve_entities(
        self, observations: List[AtomicObservation]
    ) -> List[MasterEntityProfile]:
        """Executes constrained DSU union-find over Tier 1 Hard Keys only."""
        if not observations:
            return []

        n = len(observations)
        parent = list(range(n))

        def find(i: int) -> int:
            path = []
            while parent[i] != i:
                path.append(i)
                i = parent[i]
            for node in path:
                parent[node] = i
            return i

        def union(i: int, j: int):
            root_i = find(i)
            root_j = find(j)
            if root_i != root_j:
                parent[root_i] = root_j

        # Normalize hard keys for every observation
        norm_obs_keys: List[Set[str]] = []
        for obs in observations:
            n_keys = {self.normalize_hard_key(k) for k in obs.hard_keys if k}
            norm_obs_keys.append(n_keys)

        # Build index mapping canonical hard key -> list of observation indices
        key_to_indices: Dict[str, List[int]] = {}
        for idx, keys in enumerate(norm_obs_keys):
            for k in keys:
                key_to_indices.setdefault(k, []).append(idx)

        # Merge observations sharing at least one Tier 1 Hard Key
        merge_proofs: Dict[int, List[str]] = {i: [] for i in range(n)}
        for k, idx_list in key_to_indices.items():
            if len(idx_list) > 1:
                first = idx_list[0]
                for other in idx_list[1:]:
                    if find(first) != find(other):
                        proof = f"Hard key '{k}' merged obs '{observations[first].observation_id}' with '{observations[other].observation_id}'"
                        merge_proofs[first].append(proof)
                        merge_proofs[other].append(proof)
                        union(first, other)

        # Group observations by their component root
        components: Dict[int, List[int]] = {}
        for idx in range(n):
            root = find(idx)
            components.setdefault(root, []).append(idx)

        # Build MasterEntityProfiles
        master_profiles: List[MasterEntityProfile] = []
        for root_idx, member_indices in sorted(components.items()):
            all_keys: Set[str] = set()
            all_names: Dict[str, str] = {}
            proof_list: List[str] = []
            cbs_name = None
            kyc_name = None
            contact_name = None
            wa_push = None
            fallback_name = None

            for m_idx in member_indices:
                obs = observations[m_idx]
                all_keys.update(norm_obs_keys[m_idx])
                proof_list.extend(merge_proofs[m_idx])
                if obs.handoff_proof:
                    proof_list.append(obs.handoff_proof)

                # Collect names and attributes
                if obs.observed_name:
                    all_names[obs.source_table_record or f"obs_{m_idx}"] = obs.observed_name
                    if fallback_name is None:
                        fallback_name = obs.observed_name

                    # Recognize verified KYC / CEX / PAN name sources
                    has_pan = any(k.startswith("pan:") for k in norm_obs_keys[m_idx])
                    is_kyc_src = (
                        has_pan
                        or obs.source_phase_module in ("PHASE_7_MOD_7_4", "PHASE_4_MOD_4_2", "PHASE_3_MOD_3_3")
                        or "kyc" in (obs.source_table_record or "").lower()
                        or "p2p" in (obs.source_table_record or "").lower()
                    )
                    if is_kyc_src and obs.observed_name.isupper():
                        kyc_name = obs.observed_name

                soft = obs.soft_attributes or {}
                if "cbs_kyc_name" in soft:
                    cbs_name = soft["cbs_kyc_name"]
                if "kyc_name" in soft:
                    kyc_name = soft["kyc_name"]
                if "display_name" in soft:
                    contact_name = soft["display_name"]
                if "wa_push_name" in soft:
                    wa_push = soft["wa_push_name"]

            # Determine prioritized canonical display name:
            # Priority: UIDAI / Bank CBS KYC -> CEX / PAN KYC -> Local Contact -> WA Push -> Fallback
            canonical_name = (
                cbs_name
                or kyc_name
                or contact_name
                or wa_push
                or fallback_name
                or "Unknown Actor"
            )

            # Categorize keys for JSON columns
            phones = [k.replace("phone_tail10:", "+91") for k in all_keys if "phone" in k]
            messaging = [k for k in all_keys if k.startswith(("wa_", "tg_", "sig_", "session:", "zangi:"))]
            bank_vpas = [k for k in all_keys if k.startswith(("vpa:", "bank:"))]
            crypto = [k for k in all_keys if k.startswith(("crypto:", "cex:"))]
            kyc_docs = [k for k in all_keys if k.startswith(("pan:", "aadhaar:", "passport:"))]

            profile = MasterEntityProfile(
                entity_master_uid=self._next_uid,
                entity_classification=EntityClassification.EXTERNAL_PERSON_ACTOR.value,
                canonical_display_name=canonical_name,
                all_observed_names_json=json.dumps(all_names),
                tier1_hard_keys_json=json.dumps(sorted(all_keys)),
                phones_e164_json=json.dumps(phones) if phones else None,
                messaging_handles_json=json.dumps(messaging) if messaging else None,
                bank_accounts_and_vpas_json=json.dumps(bank_vpas) if bank_vpas else None,
                crypto_addresses_and_uids_json=json.dumps(crypto) if crypto else None,
                kyc_documents_and_biometrics_json=json.dumps(kyc_docs) if kyc_docs else None,
                linked_locations_and_addresses_json=None,
                risk_and_typology_flags_json=None,
                deterministic_merge_proof_json=json.dumps(sorted(set(proof_list))),
                tier1_hard_keys=all_keys,
                deterministic_merge_proof=sorted(set(proof_list)),
                all_observed_names=all_names,
            )
            self._next_uid += 1
            master_profiles.append(profile)

        return master_profiles

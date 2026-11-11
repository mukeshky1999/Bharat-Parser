"""
Nodal Agency Freeze Sheets & Section 94 BNSS Requisition Drafter (Sub-Engine 8.4B).
Generates Golden-Hour NCRP 1930 / CEX freeze packets and auto-groups leads into statutory legal notices.
"""

from collections import defaultdict
import csv
from datetime import datetime
import hashlib
import json
import os
from typing import Any, Optional

from src.dossier_and_exhibits.models import (
    CryptoFreezeEntry,
    MuleTransactionEntry,
    NodalAgencyTarget,
    NodalFreezePacketRecord,
    RecipientNodalCategory,
    Section94BnssRequisitionRecord,
)


class NodalFreezeExporter:
    """Exports standardized Golden-Hour bank lien and crypto freeze sheets."""

    @staticmethod
    def _compute_sha256(path: str) -> str:
        ctx = hashlib.sha256()
        with open(path, "rb") as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                ctx.update(chunk)
        return ctx.hexdigest().lower()

    def export_ncrp_1930_bank_freeze_packet(
        self, transactions: list[MuleTransactionEntry], output_dir: str
    ) -> tuple[str, str, NodalFreezePacketRecord]:
        """Exports 14-column I4C NCRP / 1930 CFCFRMS bank freeze and lien packet."""
        os.makedirs(output_dir, exist_ok=True)
        csv_path = os.path.join(output_dir, "ncrp_1930_bank_freeze_packet.csv")

        header = [
            "S_No",
            "Transaction_Layer",
            "Payment_Rail",
            "UTR_or_RRN_12_Digit",
            "Transaction_Timestamp_IST",
            "Transaction_Amount_INR",
            "Payer_Account_or_VPA",
            "Beneficiary_Bank_Name",
            "Beneficiary_Account_Number",
            "Beneficiary_IFSC_11_Char",
            "Beneficiary_UPI_VPA",
            "Beneficiary_Verified_CBS_Name",
            "Linked_Mobile_Number_E164",
            "Forensic_Source_Artifact_and_SHA256",
        ]

        total_fiat = 0.0
        unique_accounts = set()
        unique_utrs = set()

        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(header)
            for t in transactions:
                writer.writerow(
                    [
                        t.s_no,
                        t.transaction_layer,
                        t.payment_rail,
                        t.utr_or_rrn_12_digit,
                        t.transaction_timestamp_ist,
                        f"{t.transaction_amount_inr:.2f}",
                        t.payer_account_or_vpa,
                        t.beneficiary_bank_name,
                        t.beneficiary_account_number,
                        t.beneficiary_ifsc_11_char,
                        t.beneficiary_upi_vpa,
                        t.beneficiary_verified_cbs_name,
                        t.linked_mobile_number_e164,
                        t.forensic_source_artifact_and_sha256,
                    ]
                )
                total_fiat += t.transaction_amount_inr
                if t.beneficiary_account_number:
                    unique_accounts.add(t.beneficiary_account_number)
                elif t.beneficiary_upi_vpa:
                    unique_accounts.add(t.beneficiary_upi_vpa)
                if t.utr_or_rrn_12_digit:
                    unique_utrs.add(t.utr_or_rrn_12_digit)

        sha256_hex = self._compute_sha256(csv_path)
        now_ist = datetime.now().strftime("%Y-%m-%d %H:%M:%S IST (+05:30)")

        record = NodalFreezePacketRecord(
            target_agency_or_portal=NodalAgencyTarget.I4C_NCRP_1930_CFCFRMS_BANK_LIEN,
            total_accounts_or_wallets_count=len(unique_accounts),
            total_utrs_or_txids_count=len(unique_utrs),
            total_disputed_fiat_inr=round(total_fiat, 2),
            total_disputed_crypto_summary=None,
            exported_csv_xlsx_path=csv_path,
            exported_file_sha256=sha256_hex,
            generated_at_ist_iso=now_ist,
        )

        return csv_path, sha256_hex, record

    def export_fiu_and_cex_crypto_freeze_packet(
        self, entries: list[CryptoFreezeEntry], output_dir: str
    ) -> tuple[str, str, NodalFreezePacketRecord]:
        """Exports CEX account and Tether USDT on-chain freeze sheets."""
        os.makedirs(output_dir, exist_ok=True)
        csv_path = os.path.join(output_dir, "fiu_ind_and_cex_crypto_freeze_packet.csv")

        header = [
            "Category",
            "Exchange_or_Network",
            "Target_Identifier",
            "KYC_Name_or_Control",
            "Balance_Summary",
            "Associated_TxIDs_or_Orders",
            "Requested_Action",
        ]

        unique_wallets = set()
        all_txids = set()
        crypto_sums = []

        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(header)
            for e in entries:
                writer.writerow(
                    [
                        e.category,
                        e.exchange_or_network,
                        e.target_identifier,
                        e.kyc_name_or_control,
                        e.fiat_or_token_balance,
                        "; ".join(e.associated_txids_or_orders),
                        e.requested_action,
                    ]
                )
                unique_wallets.add(e.target_identifier)
                for tx in e.associated_txids_or_orders:
                    all_txids.add(tx)
                if e.fiat_or_token_balance:
                    crypto_sums.append(e.fiat_or_token_balance)

        sha256_hex = self._compute_sha256(csv_path)
        now_ist = datetime.now().strftime("%Y-%m-%d %H:%M:%S IST (+05:30)")

        summary = ", ".join(crypto_sums) if crypto_sums else "Multiple Crypto Assets"
        record = NodalFreezePacketRecord(
            target_agency_or_portal=NodalAgencyTarget.FIU_IND_AND_CEX_LERP_FREEZE,
            total_accounts_or_wallets_count=len(unique_wallets),
            total_utrs_or_txids_count=len(all_txids),
            total_disputed_fiat_inr=0.0,
            total_disputed_crypto_summary=summary,
            exported_csv_xlsx_path=csv_path,
            exported_file_sha256=sha256_hex,
            generated_at_ist_iso=now_ist,
        )

        return csv_path, sha256_hex, record


class Section94BnssRequisitionDrafter:
    """Auto-groups discovered intelligence and drafts statutory notices under Section 94 BNSS, 2023."""

    BANK_IFSC_MAP = {
        "SBIN": "State Bank of India",
        "HDFC": "HDFC Bank Ltd.",
        "ICIC": "ICICI Bank Ltd.",
        "PUNB": "Punjab National Bank",
        "BARB": "Bank of Baroda",
        "UTIB": "Axis Bank Ltd.",
        "KKBK": "Kotak Mahindra Bank Ltd.",
        "CNRB": "Canara Bank",
        "UBIN": "Union Bank of India",
        "IDFB": "IDFC FIRST Bank Ltd.",
        "YESB": "Yes Bank Ltd.",
        "INDB": "IndusInd Bank Ltd.",
    }

    def resolve_organization(self, lead: dict[str, Any]) -> str:
        """Resolves target recipient organization name from IFSC, category, or declared name."""
        if lead.get("organization"):
            return lead["organization"]

        if lead.get("ifsc") and len(lead["ifsc"]) >= 4:
            pfx = lead["ifsc"][:4].upper()
            if pfx in self.BANK_IFSC_MAP:
                return self.BANK_IFSC_MAP[pfx]

        cat = lead.get("category")
        if cat == "TELECOM_TSP_NODAL":
            if "405-86" in str(lead.get("cell_tower_id", "")) or str(lead.get("msisdn", "")).startswith("+919"):
                return "Reliance Jio Infocomm Ltd."
            return "Telecom Service Provider"
        if cat == "CRYPTO_CEX_OR_SWAP_COMPLIANCE":
            return "Centralized Exchange Compliance"
        if cat == "HYPERLOCAL_DELIVERY_OR_RIDE_NODAL":
            return "Hyperlocal Service Provider"

        return "Nodal Intermediary"

    def resolve_category(self, lead: dict[str, Any]) -> RecipientNodalCategory:
        """Determines the RecipientNodalCategory enum from lead details."""
        raw_cat = lead.get("category", "")
        if raw_cat == "TELECOM_TSP_NODAL":
            return RecipientNodalCategory.TELECOM_TSP_NODAL
        if raw_cat == "BANK_NODAL_OFFICER" or lead.get("ifsc") or lead.get("account_number"):
            return RecipientNodalCategory.BANK_NODAL_OFFICER
        if raw_cat == "CRYPTO_CEX_OR_SWAP_COMPLIANCE" or lead.get("uid"):
            return RecipientNodalCategory.CRYPTO_CEX_OR_SWAP_COMPLIANCE
        if raw_cat == "HYPERLOCAL_DELIVERY_OR_RIDE_NODAL" or lead.get("order_id"):
            return RecipientNodalCategory.HYPERLOCAL_DELIVERY_OR_RIDE_NODAL
        return RecipientNodalCategory.SOCIAL_OR_MESSAGING_INTERMEDIARY

    def generate_section_94_requisitions(
        self,
        discovered_leads: list[dict[str, Any]],
        case_info: dict[str, Any],
        output_dir: str,
    ) -> list[Section94BnssRequisitionRecord]:
        """Groups discovered leads by organization and renders ready-to-sign statutory notices."""
        os.makedirs(output_dir, exist_ok=True)
        grouped_leads: dict[str, list[dict[str, Any]]] = defaultdict(list)

        for lead in discovered_leads:
            org_name = self.resolve_organization(lead)
            grouped_leads[org_name].append(lead)

        requisitions: list[Section94BnssRequisitionRecord] = []
        now_ist = datetime.now().strftime("%Y-%m-%d %H:%M:%S IST (+05:30)")

        for org_name, items in grouped_leads.items():
            nodal_cat = self.resolve_category(items[0])

            # Compile target identifiers
            identifiers: list[str] = []
            for itm in items:
                for k in ("account_number", "utr", "msisdn", "imei", "cell_tower_id", "order_id", "uid", "vpa"):
                    if itm.get(k):
                        identifiers.append(f"{k}: {itm[k]}")

            # Specific checklist based on recipient category
            if nodal_cat == RecipientNodalCategory.BANK_NODAL_OFFICER:
                checklist = (
                    "Account Opening Form (AOF), KYC Documents (Aadhaar/PAN), Registered Mobile Number, "
                    "Certified CBS Statement with Counterparty Details, Login IP/Device Logs, and Sec 63 BSA Certificate"
                )
            elif nodal_cat == RecipientNodalCategory.TELECOM_TSP_NODAL:
                checklist = (
                    "Customer Application Form (CAF), CDR (Call Detail Records), IPDR (IP Detail Records), "
                    "Cell Tower Dump, IMEI History, and Sec 63 BSA Certificate"
                )
            elif nodal_cat == RecipientNodalCategory.CRYPTO_CEX_OR_SWAP_COMPLIANCE:
                checklist = (
                    "Complete KYC dossier, P2P Counterparty UIDs, Linked Bank/UPI VPAs, "
                    "On-Chain Deposit/Withdrawal Addresses, Access IP/Device Logs, and Sec 63 BSA Certificate"
                )
            elif nodal_cat == RecipientNodalCategory.HYPERLOCAL_DELIVERY_OR_RIDE_NODAL:
                checklist = (
                    "Delivery Rider Particulars, Delivery GPS Geolocation Coordinates, Payer Account / Payment UTR, "
                    "Registered Mobile, Device ID & Login IP Logs"
                )
            else:
                checklist = (
                    "Basic Subscriber Information (BSI), Registration MSISDN & Email, Access IP Logs, "
                    "Linked Device Identifiers, and Sec 63 BSA Certificate"
                )

            safe_name = "".join(c if c.isalnum() else "_" for c in org_name)[:30]
            doc_path = os.path.join(output_dir, f"Section94_Notice_{safe_name}.txt")

            notice_text = (
                "================================================================================\n"
                "OFFICE OF THE INVESTIGATING OFFICER / CYBER CRIME INVESTIGATION CELL\n"
                "NOTICE UNDER SECTION 94 OF THE BHARATIYA NAGARIK SURAKSHA SANHITA (BNSS), 2023\n"
                "[Corresponding to erstwhile Section 91 of the Code of Criminal Procedure, 1973]\n"
                "================================================================================\n\n"
                f"To:\n"
                f"The Nodal / Law Enforcement Liaison Officer,\n"
                f"{org_name}\n\n"
                f"From:\n"
                f"{case_info.get('io_name', 'Investigating Officer')},\n"
                f"{case_info.get('police_station', 'Cyber Crime PS')}, {case_info.get('district', '')}\n\n"
                f"Case Reference: {case_info.get('fir_number', 'N/A')}\n"
                f"Sections of Law: {case_info.get('sections_of_law', 'Sections 318(4) BNS, 2023 r/w 66D IT Act')}\n"
                f"Date of Notice: {now_ist}\n\n"
                "SUBJECT: URGENT REQUISITION FOR PRODUCTION OF ELECTRONIC RECORDS AND DATA UNDER SECTION 94 BNSS, 2023\n\n"
                "Sir / Madam,\n\n"
                f"Whereas the investigation of the above-referenced criminal case is being carried out by the undersigned, "
                f"and it has been revealed during forensic extraction that the electronic records and identifiers listed below "
                f"pertain to your organization and are necessary and desirable for the purposes of the ongoing investigation:\n\n"
                "TARGET IDENTIFIERS:\n"
            )

            for ident in identifiers:
                notice_text += f" - {ident}\n"

            notice_text += (
                f"\nRECORDS REQUIRED TO BE PRODUCED:\n"
                f"{checklist}\n\n"
                "MANDATE & COMPLIANCE TIMELINE:\n"
                "You are hereby legally required under Section 94 of the Bharatiya Nagarik Suraksha Sanhita (BNSS), 2023 "
                "to produce and furnish the aforesaid electronic records and documents within 48 hours of receipt of this notice. "
                "The records must be certified in accordance with Section 63(4)(c) of the Bharatiya Sakshya Adhiniyam, 2023.\n\n"
                f"Investigating Officer: ___________________________\n"
                f"Name: {case_info.get('io_name', 'Investigating Officer')}\n"
                f"Police Station: {case_info.get('police_station', 'Cyber Crime PS')}\n"
            )

            with open(doc_path, "w", encoding="utf-8") as f:
                f.write(notice_text)

            record = Section94BnssRequisitionRecord(
                recipient_nodal_category=nodal_cat,
                recipient_organization_name=org_name,
                target_identifiers_json=json.dumps(identifiers),
                requested_records_checklist=checklist,
                rendered_notice_doc_path=doc_path,
            )
            requisitions.append(record)

        return requisitions

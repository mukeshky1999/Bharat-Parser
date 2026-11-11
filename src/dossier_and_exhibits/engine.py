"""
Master Orchestration Engine for Phase 8, Module 8.4:
DossierAndExhibitPackagerEngine coordinating Crime Dossiers, Freeze Sheets, Section 94 BNSS Notices, and Exhibits.
"""

import os
import sqlite3
from typing import Optional

from src.dossier_and_exhibits.models import (
    CrimeDossierRecord,
    DossierProfileType,
    ExportAudienceScope,
    NodalAgencyTarget,
    NodalFreezePacketRecord,
    RecipientNodalCategory,
    Section94BnssRequisitionRecord,
)
from src.dossier_and_exhibits.dossier_builder import CrimeTypologyDossierBuilder
from src.dossier_and_exhibits.nodal_freeze_and_requisitions import (
    NodalFreezeExporter,
    Section94BnssRequisitionDrafter,
)
from src.dossier_and_exhibits.exhibit_packager import ExhibitAndDefensePackager


class DossierAndExhibitPackagerEngine:
    """Production coordinator for Crime-Typology Dossiers, Golden-Hour Freezes, Section 94 Notices, and Exhibit Packaging."""

    def __init__(self):
        self.dossier_builder = CrimeTypologyDossierBuilder()
        self.freeze_exporter = NodalFreezeExporter()
        self.requisition_drafter = Section94BnssRequisitionDrafter()
        self.packager = ExhibitAndDefensePackager()

    def export_master_database(
        self,
        output_db_path: str,
        dossiers: list[CrimeDossierRecord],
        freeze_packets: list[NodalFreezePacketRecord],
        requisitions: list[Section94BnssRequisitionRecord],
    ) -> None:
        """Exports all 3 canonical tables and indexes into dossier_freeze_and_exhibit_packager.sqlite."""
        os.makedirs(os.path.dirname(os.path.abspath(output_db_path)), exist_ok=True)
        if os.path.exists(output_db_path):
            try:
                os.remove(output_db_path)
            except OSError as exc:
                _ = exc

        conn = sqlite3.connect(output_db_path)
        cur = conn.cursor()

        # Table 1: compiled_crime_dossiers_registry
        cur.execute(
            """
            CREATE TABLE compiled_crime_dossiers_registry (
                dossier_uid INTEGER PRIMARY KEY AUTOINCREMENT,
                dossier_profile_type TEXT NOT NULL,
                dossier_title TEXT NOT NULL,
                export_audience_scope TEXT NOT NULL,
                included_entity_uids_json TEXT NOT NULL,
                included_story_uids_json TEXT,
                pocso_or_intimate_media_withheld_count INTEGER DEFAULT 0,
                linked_sec63_certificate_uid INTEGER NOT NULL,
                exported_pdf_path_and_sha256 TEXT NOT NULL,
                exported_html5_bundle_sha256 TEXT,
                compiled_at_ist_iso TEXT NOT NULL
            );
            """
        )
        cur.execute("CREATE INDEX idx_dossier_profile ON compiled_crime_dossiers_registry(dossier_profile_type);")

        for d in dossiers:
            prof_val = d.dossier_profile_type.value if isinstance(d.dossier_profile_type, DossierProfileType) else str(d.dossier_profile_type)
            aud_val = d.export_audience_scope.value if isinstance(d.export_audience_scope, ExportAudienceScope) else str(d.export_audience_scope)
            cur.execute(
                """
                INSERT INTO compiled_crime_dossiers_registry (
                    dossier_uid, dossier_profile_type, dossier_title,
                    export_audience_scope, included_entity_uids_json, included_story_uids_json,
                    pocso_or_intimate_media_withheld_count, linked_sec63_certificate_uid,
                    exported_pdf_path_and_sha256, exported_html5_bundle_sha256, compiled_at_ist_iso
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    d.dossier_uid,
                    prof_val,
                    d.dossier_title,
                    aud_val,
                    d.included_entity_uids_json,
                    d.included_story_uids_json,
                    d.pocso_or_intimate_media_withheld_count,
                    d.linked_sec63_certificate_uid,
                    d.exported_pdf_path_and_sha256,
                    d.exported_html5_bundle_sha256,
                    d.compiled_at_ist_iso,
                ),
            )

        # Table 2: nodal_freeze_and_lien_exports_ledger
        cur.execute(
            """
            CREATE TABLE nodal_freeze_and_lien_exports_ledger (
                freeze_packet_uid INTEGER PRIMARY KEY AUTOINCREMENT,
                target_agency_or_portal TEXT NOT NULL,
                total_accounts_or_wallets_count INTEGER NOT NULL,
                total_utrs_or_txids_count INTEGER NOT NULL,
                total_disputed_fiat_inr REAL DEFAULT 0.0,
                total_disputed_crypto_summary TEXT,
                exported_csv_xlsx_path TEXT NOT NULL,
                exported_file_sha256 TEXT NOT NULL,
                generated_at_ist_iso TEXT NOT NULL
            );
            """
        )
        cur.execute("CREATE INDEX idx_freeze_agency ON nodal_freeze_and_lien_exports_ledger(target_agency_or_portal);")

        for fp in freeze_packets:
            target_val = (
                fp.target_agency_or_portal.value
                if isinstance(fp.target_agency_or_portal, NodalAgencyTarget)
                else str(fp.target_agency_or_portal)
            )
            cur.execute(
                """
                INSERT INTO nodal_freeze_and_lien_exports_ledger (
                    freeze_packet_uid, target_agency_or_portal, total_accounts_or_wallets_count,
                    total_utrs_or_txids_count, total_disputed_fiat_inr, total_disputed_crypto_summary,
                    exported_csv_xlsx_path, exported_file_sha256, generated_at_ist_iso
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    fp.freeze_packet_uid,
                    target_val,
                    fp.total_accounts_or_wallets_count,
                    fp.total_utrs_or_txids_count,
                    fp.total_disputed_fiat_inr,
                    fp.total_disputed_crypto_summary,
                    fp.exported_csv_xlsx_path,
                    fp.exported_file_sha256,
                    fp.generated_at_ist_iso,
                ),
            )

        # Table 3: section94_bnss_requisitions_queue
        cur.execute(
            """
            CREATE TABLE section94_bnss_requisitions_queue (
                requisition_uid INTEGER PRIMARY KEY AUTOINCREMENT,
                statutory_provision TEXT NOT NULL,
                recipient_nodal_category TEXT NOT NULL,
                recipient_organization_name TEXT NOT NULL,
                target_identifiers_json TEXT NOT NULL,
                requested_records_checklist TEXT NOT NULL,
                rendered_notice_doc_path TEXT NOT NULL
            );
            """
        )
        cur.execute("CREATE INDEX idx_req_recipient ON section94_bnss_requisitions_queue(recipient_organization_name);")

        for req in requisitions:
            cat_val = (
                req.recipient_nodal_category.value
                if isinstance(req.recipient_nodal_category, RecipientNodalCategory)
                else str(req.recipient_nodal_category)
            )
            cur.execute(
                """
                INSERT INTO section94_bnss_requisitions_queue (
                    requisition_uid, statutory_provision, recipient_nodal_category,
                    recipient_organization_name, target_identifiers_json, requested_records_checklist,
                    rendered_notice_doc_path
                ) VALUES (?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    req.requisition_uid,
                    req.statutory_provision,
                    cat_val,
                    req.recipient_organization_name,
                    req.target_identifiers_json,
                    req.requested_records_checklist,
                    req.rendered_notice_doc_path,
                ),
            )

        conn.commit()
        conn.close()

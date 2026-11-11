"""
Exhibit Packager & Air-Gapped Section 230 BNSS Redaction Gate (Sub-Engine 8.4C).
Enforces P. Gopalkrishnan (2019) CSAM/intimate-media withholding and Section 72 BNS victim anonymization.
"""

import os
from typing import Optional

from src.dossier_and_exhibits.models import (
    DefenseBundleResult,
    RedactionTag,
    SensitiveMediaItem,
)


class ExhibitAndDefensePackager:
    """Packages courtroom evidence exhibits and enforces statutory redaction safeguards for defense disclosure."""

    WITHHELD_NOTICE_TEMPLATE = (
        "================================================================================\n"
        "STATUTORY JUDICIAL-INSPECTION NOTICE CARD\n"
        "[WITHHELD UNDER POCSO ACT, 2012 & HON'BLE SUPREME COURT MANDATE]\n"
        "================================================================================\n\n"
        "Particulars of Withheld Evidentiary Visual Media:\n"
        " - Original File Name: {file_name}\n"
        " - Canonical VFS Path: {canonical_path}\n"
        " - Timestamps (UTC): {timestamps_utc}\n"
        " - EXIF / Container Metadata: {exif_metadata}\n"
        " - SHA-256 Digest: {sha256_hex}\n"
        " - MD5 Digest: {md5_hex}\n\n"
        "STATUTORY NOTICE:\n"
        "Visual media withheld from physical duplication pursuant to the POCSO Act, 2012 and the "
        "Hon'ble Supreme Court of India judgment in P. Gopalkrishnan v. State of Kerala (2019); "
        "original hashed exhibit preserved in official Court/FSL custody for supervised inspection.\n"
        "================================================================================\n"
    )

    def package_section_230_defense_bundle(
        self,
        case_id: str,
        items: list[SensitiveMediaItem],
        output_dir: str,
        anonymize_victim_identity: bool = True,
        victim_name: Optional[str] = None,
    ) -> DefenseBundleResult:
        """Packages self-contained Section 230 BNSS defense bundle with mandatory POCSO and victim identity gates."""
        exhibits_dir = os.path.join(output_dir, "exhibits")
        os.makedirs(exhibits_dir, exist_ok=True)

        pocso_withheld_count = 0
        catalog_entries: list[dict] = []

        for item in items:
            is_sensitive = item.redaction_tag in (
                RedactionTag.CSAM_POCSO,
                RedactionTag.NON_CONSENSUAL_INTIMATE_MEDIA,
                RedactionTag.SEXUAL_ASSAULT_FOOTAGE,
            )

            if is_sensitive:
                # Raw bytes MUST NEVER be written to the defense bundle!
                pocso_withheld_count += 1
                stem, _ = os.path.splitext(item.file_name)
                card_filename = f"{stem}_WITHHELD_NOTICE.txt"
                card_path = os.path.join(exhibits_dir, card_filename)

                notice_text = self.WITHHELD_NOTICE_TEMPLATE.format(
                    file_name=item.file_name,
                    canonical_path=item.canonical_path,
                    timestamps_utc=item.timestamps_utc or "N/A",
                    exif_metadata=item.exif_metadata or "Standard Visual Container",
                    sha256_hex=item.sha256_hex.lower(),
                    md5_hex=item.md5_hex.lower(),
                )

                with open(card_path, "w", encoding="utf-8") as f:
                    f.write(notice_text)

                catalog_entries.append(
                    {
                        "file": card_filename,
                        "status": "WITHHELD_SUPERVISED_INSPECTION_ONLY",
                        "sha256": item.sha256_hex.lower(),
                    }
                )
            else:
                # Safe visual or document exhibit
                file_dest = os.path.join(exhibits_dir, item.file_name)
                with open(file_dest, "wb") as f:
                    f.write(item.raw_bytes)

                catalog_entries.append(
                    {
                        "file": item.file_name,
                        "status": "ACCESSIBLE_RELIED_UPON_EXHIBIT",
                        "sha256": item.sha256_hex.lower(),
                    }
                )

        # Generate air-gapped HTML5 viewer
        html_path = os.path.join(output_dir, "Open_Case_Dossier.html")
        html_title = f"Case Dossier - {case_id} (Section 230 BNSS Defense Disclosure)"

        body_text = f"<h1>{html_title}</h1>\n"
        body_text += "<p>Relied-upon electronic exhibits prepared under Section 230 BNSS, 2023.</p>\n"
        if victim_name:
            body_text += f"<p>Complainant / Subject: {victim_name}</p>\n"

        body_text += "<ul>\n"
        for ent in catalog_entries:
            body_text += f"<li><strong>{ent['file']}</strong> - [{ent['status']}] (SHA-256: <code>{ent['sha256']}</code>)</li>\n"
        body_text += "</ul>\n"

        if anonymize_victim_identity and victim_name:
            body_text = body_text.replace(victim_name, "[VICTIM_PROTECTED_ID_01]")

        html_content = (
            "<!DOCTYPE html>\n"
            "<html lang='en'>\n"
            "<head>\n"
            "  <meta charset='UTF-8'>\n"
            f"  <title>{html_title}</title>\n"
            "  <style>body { font-family: sans-serif; padding: 20px; }</style>\n"
            "</head>\n"
            "<body>\n"
            f"{body_text}\n"
            "</body>\n"
            "</html>\n"
        )

        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        return DefenseBundleResult(
            bundle_path=output_dir,
            pocso_withheld_count=pocso_withheld_count,
            html_viewer_path=html_path,
        )

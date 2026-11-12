"""
Exhibit Packager & Section 230 BNSS Redaction Gate (Sub-Engine 8.4C).

Enforces P. Gopalkrishnan (2019) CSAM/intimate-media withholding and Section 72 BNS victim anonymisation.
The gate fails closed: an item with no explicit redaction decision aborts the whole bundle.
"""

import html
import os
import re
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

    # Everything except DISCLOSABLE is withheld: bytes are never written, only a notice card.
    WITHHELD_TAGS = (
        RedactionTag.CSAM_POCSO,
        RedactionTag.NON_CONSENSUAL_INTIMATE_MEDIA,
        RedactionTag.SEXUAL_ASSAULT_FOOTAGE,
        RedactionTag.PROTECTED_VICTIM_IDENTITY,
        RedactionTag.UNRELIED_PRIVATE_DATA,
    )
    POCSO_TAGS = (
        RedactionTag.CSAM_POCSO,
        RedactionTag.NON_CONSENSUAL_INTIMATE_MEDIA,
        RedactionTag.SEXUAL_ASSAULT_FOOTAGE,
    )

    @staticmethod
    def _safe_name(name: str, index: int) -> str:
        """A single path component derived from an item name: no separators, no traversal."""
        base = os.path.basename(str(name).replace("\\", "/")).strip().strip(".")
        base = re.sub(r"[^A-Za-z0-9._ -]", "_", base)
        return f"{index:03d}_{base or 'item'}"

    @staticmethod
    def _write(directory: str, filename: str, data: bytes) -> None:
        """Write inside `directory` only; refuse anything that resolves elsewhere."""
        directory = os.path.abspath(directory)
        dest = os.path.abspath(os.path.join(directory, filename))
        if os.path.dirname(dest) != directory:
            raise ValueError(f"Refusing to write outside the bundle: {filename}")
        with open(dest, "wb") as f:
            f.write(data)

    def package_section_230_defense_bundle(
        self,
        case_id: str,
        items: list[SensitiveMediaItem],
        output_dir: str,
        anonymize_victim_identity: bool = True,
        victim_name: Optional[str] = None,
    ) -> DefenseBundleResult:
        """Packages a Section 230 BNSS bundle. Fails closed.

        Only items tagged DISCLOSABLE are written as bytes. Every other tag is withheld and replaced
        by a notice card. An item with no tag aborts the bundle before anything is written.
        """
        unclassified = [str(i.file_name) for i in items if not isinstance(i.redaction_tag, RedactionTag)]
        if unclassified:
            raise ValueError(
                "Unclassified item(s): every item needs an explicit redaction decision "
                f"(use DISCLOSABLE to release). Offending: {', '.join(unclassified)}"
            )
        if anonymize_victim_identity and not (victim_name and victim_name.strip()):
            raise ValueError("Victim anonymisation is on but no victim name was given to redact.")

        def mask(text: object) -> str:
            text = str(text)
            if anonymize_victim_identity and victim_name:
                text = re.sub(re.escape(victim_name.strip()), "[VICTIM_PROTECTED_ID_01]", text, flags=re.IGNORECASE)
            return text

        def esc(text: object) -> str:
            return html.escape(mask(text), quote=True)

        output_dir = os.path.abspath(output_dir)
        exhibits_dir = os.path.join(output_dir, "exhibits")
        os.makedirs(exhibits_dir, exist_ok=True)

        pocso_withheld_count = 0
        catalog_entries: list[dict] = []

        for idx, item in enumerate(items, start=1):
            safe = self._safe_name(mask(item.file_name), idx)
            if item.redaction_tag in self.WITHHELD_TAGS:
                if item.redaction_tag in self.POCSO_TAGS:
                    pocso_withheld_count += 1
                stem, _ = os.path.splitext(safe)
                card_filename = f"{stem}_WITHHELD_NOTICE.txt"
                notice_text = self.WITHHELD_NOTICE_TEMPLATE.format(
                    file_name=mask(item.file_name),
                    canonical_path=mask(item.canonical_path),
                    timestamps_utc=mask(item.timestamps_utc or "N/A"),
                    exif_metadata=mask(item.exif_metadata or "Standard Visual Container"),
                    sha256_hex=item.sha256_hex.lower(),
                    md5_hex=item.md5_hex.lower(),
                )
                notice_text += f" - Withholding basis: {item.redaction_tag.value}\n"
                self._write(exhibits_dir, card_filename, notice_text.encode("utf-8"))
                catalog_entries.append(
                    {
                        "file": card_filename,
                        "status": "WITHHELD_SUPERVISED_INSPECTION_ONLY",
                        "sha256": item.sha256_hex.lower(),
                    }
                )
            else:
                self._write(exhibits_dir, safe, item.raw_bytes)
                catalog_entries.append(
                    {
                        "file": safe,
                        "status": "ACCESSIBLE_RELIED_UPON_EXHIBIT",
                        "sha256": item.sha256_hex.lower(),
                    }
                )

        html_path = os.path.join(output_dir, "Open_Case_Dossier.html")
        html_title = f"Case Dossier - {case_id} (Section 230 BNSS Defense Disclosure)"

        body = f"<h1>{esc(html_title)}</h1>\n"
        body += "<p>Relied-upon electronic exhibits prepared under Section 230 BNSS, 2023.</p>\n"
        if victim_name:
            body += f"<p>Complainant / Subject: {esc(victim_name)}</p>\n"
        body += "<ul>\n"
        for ent in catalog_entries:
            body += (
                f"<li><strong>{esc(ent['file'])}</strong> - [{esc(ent['status'])}] "
                f"(SHA-256: <code>{esc(ent['sha256'])}</code>)</li>\n"
            )
        body += "</ul>\n"

        html_content = (
            "<!DOCTYPE html>\n"
            "<html lang='en'>\n"
            "<head>\n"
            "  <meta charset='UTF-8'>\n"
            f"  <title>{esc(html_title)}</title>\n"
            "  <style>body { font-family: sans-serif; padding: 20px; }</style>\n"
            "</head>\n"
            "<body>\n"
            f"{body}\n"
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

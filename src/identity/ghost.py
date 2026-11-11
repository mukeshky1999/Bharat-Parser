"""
Ghost Application (Uninstalled App) Residual Discovery Engine.
Phase 1, Module 1.3, Section 5.
"""

import json
from typing import Optional, Dict, Set, Any

from src.identity.catalog import IdentitySandboxCatalog


class GhostAppDetector:
    """Discovers residual traces of deleted or uninstalled applications in OS telemetry."""

    def __init__(self, catalog: IdentitySandboxCatalog):
        self.catalog = catalog
        self.telemetry_records: Dict[str, Dict[str, Any]] = {}

    def record_telemetry_evidence(
        self,
        app_identifier: str,
        os_platform: str,
        evidence_source: str,
        last_seen_utc_iso: Optional[str] = None
    ) -> None:
        """Records an observed reference to an application in an OS telemetry stream."""
        if app_identifier not in self.telemetry_records:
            self.telemetry_records[app_identifier] = {
                "os_platform": os_platform,
                "sources": set(),
                "last_seen_utc_iso": last_seen_utc_iso
            }
        self.telemetry_records[app_identifier]["sources"].add(evidence_source)
        if last_seen_utc_iso:
            self.telemetry_records[app_identifier]["last_seen_utc_iso"] = last_seen_utc_iso

    def finalize_ghost_apps(self) -> int:
        """
        Cross-checks telemetry references against currently active packages/sandboxes.
        Registers any uninstalled residuals with install_status='UNINSTALLED_GHOST_APP'.
        """
        # Retrieve all currently installed active apps
        conn = self.catalog._get_connection()
        cur = conn.cursor()
        cur.execute(
            "SELECT DISTINCT app_identifier FROM resolved_application_catalog WHERE install_status != 'UNINSTALLED_GHOST_APP';"
        )
        active_ids = {row["app_identifier"] for row in cur.fetchall()}
        conn.close()

        ghost_count = 0
        for app_id, data in self.telemetry_records.items():
            if app_id not in active_ids:
                sources_json = json.dumps(sorted(list(data["sources"])))
                self.catalog.register_app_instance(
                    os_platform=data["os_platform"],
                    user_id=0,
                    app_identifier=app_id,
                    display_name=app_id.split(".")[-1].capitalize(),
                    install_status="UNINSTALLED_GHOST_APP",
                    last_update_utc_iso=data["last_seen_utc_iso"],
                    ghost_evidence_sources=sources_json
                )
                ghost_count += 1

        return ghost_count

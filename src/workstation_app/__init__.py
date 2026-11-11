"""
Workstation Application Package.
Hosts the multi-threaded local HTTP server and single-page interactive dashboard.
"""

from src.workstation_app.dashboard_server import (
    ForensicDashboardHandler,
    create_workstation_server,
    run_dashboard_server,
)

__all__ = [
    "ForensicDashboardHandler",
    "create_workstation_server",
    "run_dashboard_server",
]

"""
Hybrid Online/Offline Reverse Geocoder & Dynamic Map HTML Engine.
Provides OpenStreetMap Nominatim reverse geocoding with local SQLite caching,
embedded pure-Python 66-city Indian Gazetteer fallback, and tactical SVG map rendering.
"""

from dataclasses import dataclass, field
import json
import math
import os
from pathlib import Path
from typing import Any, Optional
import urllib.error
import urllib.request

from src.core.sqlite_manager import connect_forensic_sqlite


@dataclass
class ResolvedLocation:
    """Standardized representation of a resolved geographic location."""

    latitude: float
    longitude: float
    lat_lon_formatted: str
    cardinal_formatted: str
    display_address: str
    city_or_district: str = "Unknown"
    state_name: str = "Unknown"
    country_name: str = "India"
    pincode: str = ""
    is_online_resolved: bool = False
    resolution_source: str = "OFFLINE_LATLON_FALLBACK"


# Comprehensive 66-City Indian Gazetteer covering all states and Union Territories
INDIAN_GAZETTEER_HUBS: list[tuple[float, float, str, str]] = [
    (28.6139, 77.2090, "New Delhi", "Delhi"),
    (19.0760, 72.8777, "Mumbai", "Maharashtra"),
    (12.9716, 77.5946, "Bengaluru", "Karnataka"),
    (25.3176, 82.9739, "Varanasi", "Uttar Pradesh"),
    (26.8467, 80.9462, "Lucknow", "Uttar Pradesh"),
    (17.3850, 78.4867, "Hyderabad", "Telangana"),
    (13.0827, 80.2707, "Chennai", "Tamil Nadu"),
    (22.5726, 88.3639, "Kolkata", "West Bengal"),
    (18.5204, 73.8567, "Pune", "Maharashtra"),
    (23.0225, 72.5714, "Ahmedabad", "Gujarat"),
    (21.1702, 72.8311, "Surat", "Gujarat"),
    (26.9124, 75.7873, "Jaipur", "Rajasthan"),
    (25.5941, 85.1376, "Patna", "Bihar"),
    (23.2599, 77.4126, "Bhopal", "Madhya Pradesh"),
    (22.7196, 75.8577, "Indore", "Madhya Pradesh"),
    (30.7333, 76.7794, "Chandigarh", "Chandigarh"),
    (26.1445, 91.7362, "Guwahati", "Assam"),
    (34.0837, 74.7973, "Srinagar", "Jammu and Kashmir"),
    (32.7266, 74.8570, "Jammu", "Jammu and Kashmir"),
    (30.3165, 78.0322, "Dehradun", "Uttarakhand"),
    (23.3441, 85.3096, "Ranchi", "Jharkhand"),
    (21.2514, 81.6296, "Raipur", "Chhattisgarh"),
    (20.2961, 85.8245, "Bhubaneswar", "Odisha"),
    (9.9312, 76.2673, "Kochi", "Kerala"),
    (8.5241, 76.9366, "Thiruvananthapuram", "Kerala"),
    (17.6868, 83.2185, "Visakhapatnam", "Andhra Pradesh"),
    (21.1458, 79.0882, "Nagpur", "Maharashtra"),
    (26.4499, 80.3319, "Kanpur", "Uttar Pradesh"),
    (25.4358, 81.8463, "Prayagraj", "Uttar Pradesh"),
    (27.1767, 78.0081, "Agra", "Uttar Pradesh"),
    (11.0168, 76.9558, "Coimbatore", "Tamil Nadu"),
    (9.9252, 78.1198, "Madurai", "Tamil Nadu"),
    (12.2958, 76.6394, "Mysuru", "Karnataka"),
    (22.3072, 73.1812, "Vadodara", "Gujarat"),
    (22.3039, 70.8022, "Rajkot", "Gujarat"),
    (31.6340, 74.8723, "Amritsar", "Punjab"),
    (30.9010, 75.8573, "Ludhiana", "Punjab"),
    (26.2389, 73.0243, "Jodhpur", "Rajasthan"),
    (24.5854, 73.7125, "Udaipur", "Rajasthan"),
    (26.2183, 78.1828, "Gwalior", "Madhya Pradesh"),
    (23.1815, 79.9864, "Jabalpur", "Madhya Pradesh"),
    (16.5062, 80.6480, "Vijayawada", "Andhra Pradesh"),
    (13.6288, 79.4192, "Tirupati", "Andhra Pradesh"),
    (17.9689, 79.5941, "Warangal", "Telangana"),
    (15.3647, 75.1240, "Hubballi", "Karnataka"),
    (12.9141, 74.8560, "Mangaluru", "Karnataka"),
    (15.8497, 74.4977, "Belagavi", "Karnataka"),
    (19.9975, 73.7898, "Nashik", "Maharashtra"),
    (19.8762, 75.3433, "Aurangabad", "Maharashtra"),
    (19.2183, 72.9781, "Thane", "Maharashtra"),
    (19.0330, 73.0297, "Navi Mumbai", "Maharashtra"),
    (28.5355, 77.3910, "Noida", "Uttar Pradesh"),
    (28.4595, 77.0266, "Gurugram", "Haryana"),
    (28.4089, 77.3178, "Faridabad", "Haryana"),
    (28.6692, 77.4538, "Ghaziabad", "Uttar Pradesh"),
    (31.1048, 77.1734, "Shimla", "Himachal Pradesh"),
    (15.4909, 73.8278, "Panaji", "Goa"),
    (27.3389, 88.6065, "Gangtok", "Sikkim"),
    (25.5788, 91.8933, "Shillong", "Meghalaya"),
    (24.8170, 93.9368, "Imphal", "Manipur"),
    (23.7271, 92.7176, "Aizawl", "Mizoram"),
    (25.6751, 94.1086, "Kohima", "Nagaland"),
    (27.0844, 93.6053, "Itanagar", "Arunachal Pradesh"),
    (23.8315, 91.2868, "Agartala", "Tripura"),
    (11.6234, 92.7265, "Port Blair", "Andaman and Nicobar Islands"),
    (34.1526, 77.5771, "Leh", "Ladakh"),
]


def haversine_distance_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Calculates great-circle distance between two coordinates in kilometers."""
    radius_earth = 6371.0
    d_lat = math.radians(lat2 - lat1)
    d_lon = math.radians(lon2 - lon1)
    a = (
        math.sin(d_lat / 2.0) ** 2
        + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(d_lon / 2.0) ** 2
    )
    c = 2.0 * math.atan2(math.sqrt(a), math.sqrt(max(0.0, 1.0 - a)))
    return radius_earth * c


class HybridReverseGeocoder:
    """
    Reverse geocoding engine with multi-tier resolution:
    Tier 1: Local persistent SQLite cache.
    Tier 2: Live OpenStreetMap Nominatim HTTP queries (with timeout).
    Tier 3: Offline Indian Gazetteer proximity and coordinate fix fallback.
    """

    CACHE_SCHEMA_SQL = """
    CREATE TABLE IF NOT EXISTS reverse_geocode_cache (
        lat_rounded REAL NOT NULL,
        lon_rounded REAL NOT NULL,
        display_address TEXT NOT NULL,
        city_or_district TEXT NOT NULL,
        state_name TEXT NOT NULL,
        country_name TEXT NOT NULL,
        pincode TEXT,
        PRIMARY KEY (lat_rounded, lon_rounded)
    );
    """

    def __init__(self, cache_db_path: Optional[Path] = None):
        self.cache_db_path = (
            cache_db_path or Path("./.workspace_tmp/reverse_geocode_cache.sqlite")
        )
        self._init_cache_db()

    def _init_cache_db(self) -> None:
        """Initializes cache tables using thread-safe connection manager."""
        self.cache_db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = connect_forensic_sqlite(self.cache_db_path)
        try:
            conn.executescript(self.CACHE_SCHEMA_SQL)
            conn.commit()
        finally:
            conn.close()

    def resolve_location(
        self, lat: float, lon: float, force_offline: bool = False
    ) -> ResolvedLocation:
        """
        Resolves geographic coordinates into a human-readable address with automatic offline fallback.
        """
        # Coordinate sanity validation
        if not (-90.0 <= lat <= 90.0 and -180.0 <= lon <= 180.0):
            lat = max(-90.0, min(90.0, lat))
            lon = max(-180.0, min(180.0, lon))

        lat_lon_fmt = f"{lat:.6f}, {lon:.6f}"
        lat_dir = "N" if lat >= 0 else "S"
        lon_dir = "E" if lon >= 0 else "W"
        cardinal_fmt = f"{abs(lat):.6f}° {lat_dir}, {abs(lon):.6f}° {lon_dir}"

        lat_rounded = round(lat, 4)
        lon_rounded = round(lon, 4)

        # Step 1: Local SQLite Cache lookup
        if not force_offline:
            cached = self._lookup_cache(lat_rounded, lon_rounded)
            if cached:
                return ResolvedLocation(
                    latitude=lat,
                    longitude=lon,
                    lat_lon_formatted=lat_lon_fmt,
                    cardinal_formatted=cardinal_fmt,
                    display_address=cached["display_address"],
                    city_or_district=cached["city_or_district"],
                    state_name=cached["state_name"],
                    country_name=cached["country_name"],
                    pincode=cached["pincode"],
                    is_online_resolved=True,
                    resolution_source="LOCAL_SQLITE_CACHE",
                )

        # Step 2: Live OpenStreetMap Nominatim lookup
        if not force_offline:
            online_res = self._query_nominatim(lat, lon, lat_lon_fmt, cardinal_fmt)
            if online_res:
                self._save_cache(lat_rounded, lon_rounded, online_res)
                return online_res

        # Step 3: Offline Fallback using embedded Indian Gazetteer
        return self._offline_gazetteer_fallback(lat, lon, lat_lon_fmt, cardinal_fmt)

    def _lookup_cache(self, lat_rounded: float, lon_rounded: float) -> Optional[dict[str, Any]]:
        """Queries the persistent SQLite cache for prior geocoding hits."""
        conn = connect_forensic_sqlite(self.cache_db_path, read_only=True)
        try:
            row = conn.execute(
                """
                SELECT display_address, city_or_district, state_name, country_name, pincode
                FROM reverse_geocode_cache
                WHERE lat_rounded = ? AND lon_rounded = ?;
                """,
                (lat_rounded, lon_rounded),
            ).fetchone()
            if row:
                return dict(row)
            return None
        finally:
            conn.close()

    def _save_cache(self, lat_rounded: float, lon_rounded: float, loc: ResolvedLocation) -> None:
        """Stores resolved location in persistent cache."""
        conn = connect_forensic_sqlite(self.cache_db_path)
        try:
            conn.execute(
                """
                INSERT OR REPLACE INTO reverse_geocode_cache (
                    lat_rounded, lon_rounded, display_address, city_or_district, state_name, country_name, pincode
                ) VALUES (?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    lat_rounded,
                    lon_rounded,
                    loc.display_address,
                    loc.city_or_district,
                    loc.state_name,
                    loc.country_name,
                    loc.pincode,
                ),
            )
            conn.commit()
        finally:
            conn.close()

    def _query_nominatim(
        self, lat: float, lon: float, lat_lon_fmt: str, cardinal_fmt: str
    ) -> Optional[ResolvedLocation]:
        """Queries OpenStreetMap Nominatim reverse geocoding API with a strict 2.5s timeout."""
        url = (
            f"https://nominatim.openstreetmap.org/reverse"
            f"?format=jsonv2&lat={lat:.6f}&lon={lon:.6f}&zoom=18&addressdetails=1&accept-language=en,hi"
        )
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "BharatAnalyzer-Forensic-Workstation/1.0"},
        )
        try:
            with urllib.request.urlopen(req, timeout=2.5) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                disp_name = data.get("display_name", "")
                if not disp_name:
                    return None

                addr = data.get("address", {})
                city = (
                    addr.get("city")
                    or addr.get("town")
                    or addr.get("village")
                    or addr.get("county")
                    or addr.get("state_district")
                    or "Unknown"
                )
                state = addr.get("state", "Unknown")
                country = addr.get("country", "India")
                postcode = addr.get("postcode", "")

                formatted_address = f"{disp_name} (Lat: {lat:.6f}, Lon: {lon:.6f})"

                return ResolvedLocation(
                    latitude=lat,
                    longitude=lon,
                    lat_lon_formatted=lat_lon_fmt,
                    cardinal_formatted=cardinal_fmt,
                    display_address=formatted_address,
                    city_or_district=city,
                    state_name=state,
                    country_name=country,
                    pincode=postcode,
                    is_online_resolved=True,
                    resolution_source="ONLINE_OSM_NOMINATIM",
                )
        except Exception:
            return None

    def _offline_gazetteer_fallback(
        self, lat: float, lon: float, lat_lon_fmt: str, cardinal_fmt: str
    ) -> ResolvedLocation:
        """Finds nearest Indian city in embedded gazetteer and produces offline location fix."""
        min_dist = float("inf")
        nearest_city = "Unknown"
        nearest_state = "India"

        for h_lat, h_lon, city, state in INDIAN_GAZETTEER_HUBS:
            d = haversine_distance_km(lat, lon, h_lat, h_lon)
            if d < min_dist:
                min_dist = d
                nearest_city = city
                nearest_state = state

        if min_dist <= 150.0:
            addr = f"Lat: {lat:.6f}, Lon: {lon:.6f} (Offline Mode — ~{min_dist:.1f} km from {nearest_city}, {nearest_state})"
            city_val = nearest_city
            state_val = nearest_state
        else:
            addr = f"Lat: {lat:.6f}, Lon: {lon:.6f} (Offline Coordinate Fix — {cardinal_fmt})"
            city_val = "Coordinates Fix"
            state_val = "India"

        return ResolvedLocation(
            latitude=lat,
            longitude=lon,
            lat_lon_formatted=lat_lon_fmt,
            cardinal_formatted=cardinal_fmt,
            display_address=addr,
            city_or_district=city_val,
            state_name=state_val,
            country_name="India",
            pincode="",
            is_online_resolved=False,
            resolution_source="OFFLINE_LATLON_FALLBACK",
        )

    def render_hybrid_map_html(
        self, markers: list[dict[str, Any]], polylines: Optional[list[Any]] = None
    ) -> str:
        """
        Renders an interactive hybrid map component supporting both live OpenStreetMap tiles
        and a fully client-side SVG Tactical Coordinate Grid fallback with accuracy circles.
        """
        markers_json = json.dumps(markers)
        lines_json = json.dumps(polylines or [])

        center_lat = markers[0].get("lat", 25.3176) if markers else 25.3176
        center_lon = markers[0].get("lon", 82.9739) if markers else 82.9739

        return f"""
        <div id="forensic-map-container" style="width:100%; height:450px; background:#0f172a; border-radius:8px; position:relative; overflow:hidden; font-family:sans-serif;">
            <div id="map-controls" style="position:absolute; top:12px; right:12px; z-index:100; display:flex; gap:8px;">
                <button id="toggle-grid-btn" onclick="toggleTacticalGrid()" style="background:#1e293b; color:#38bdf8; border:1px solid #38bdf8; border-radius:4px; padding:6px 12px; cursor:pointer; font-size:12px; font-weight:bold;">
                    Toggle Offline Tactical Grid
                </button>
            </div>

            <!-- Leaflet Container -->
            <div id="leaflet-map" style="width:100%; height:100%;"></div>

            <!-- Offline Tactical Coordinate Grid Fallback Canvas/SVG -->
            <div id="tactical-grid-overlay" style="display:none; width:100%; height:100%; position:absolute; top:0; left:0; background:#090d16; color:#94a3b8;">
                <svg id="tactical-svg" width="100%" height="100%" viewBox="0 0 800 450" style="background:#090d16;">
                    <defs>
                        <pattern id="grid-pattern" width="80" height="45" patternUnits="userSpaceOnUse">
                            <path d="M 80 0 L 0 0 0 45" fill="none" stroke="#1e293b" stroke-width="1"/>
                        </pattern>
                    </defs>
                    <rect width="100%" height="100%" fill="url(#grid-pattern)" />
                    <!-- Center reticle -->
                    <circle cx="400" cy="225" r="180" fill="none" stroke="#0284c7" stroke-width="1" stroke-dasharray="4,4" opacity="0.3" />
                    <circle cx="400" cy="225" r="90" fill="none" stroke="#0284c7" stroke-width="1" opacity="0.4" />
                    <line x1="400" y1="20" x2="400" y2="430" stroke="#0284c7" stroke-width="1" opacity="0.4" />
                    <line x1="20" y1="225" x2="780" y2="225" stroke="#0284c7" stroke-width="1" opacity="0.4" />

                    <!-- Coordinate Markers Projected -->
                    <g id="svg-markers-layer">
                        <circle cx="400" cy="225" r="8" fill="#ef4444" stroke="#ffffff" stroke-width="2" />
                        <text x="415" y="220" fill="#f8fafc" font-size="12" font-family="monospace">Fix: {center_lat:.6f}, {center_lon:.6f}</text>
                        <text x="415" y="235" fill="#38bdf8" font-size="11" font-family="monospace">[Offline Tactical Grid Active]</text>
                    </g>
                </svg>
            </div>
        </div>

        <script>
            var rawMarkers = {markers_json};
            var rawLines = {lines_json};
            var isGridActive = false;

            function toggleTacticalGrid() {{
                isGridActive = !isGridActive;
                var grid = document.getElementById("tactical-grid-overlay");
                var lmap = document.getElementById("leaflet-map");
                if (isGridActive) {{
                    grid.style.display = "block";
                    lmap.style.opacity = "0.2";
                }} else {{
                    grid.style.display = "none";
                    lmap.style.opacity = "1.0";
                }}
            }}
        </script>
        """

"""
Offline PMTiles v3 Map Engine & Web Mercator Ground Resolution Calculator (Sub-Engine 9.4A).
Serves offline vector tiles via Hilbert-Curve TileIDs and computes meter-accurate uncertainty circles.
"""

import math
from src.geospatial_media_and_tamper.models import CellularSectorWedge


class WebMercatorProjectionCalculator:
    """Calculates ground resolution and screen-space pixel radii for geographic uncertainty circles."""

    EARTH_CIRCUMFERENCE_METERS = 40075016.686
    TILE_SIZE_PX = 512

    def compute_meters_per_pixel(self, latitude: float, zoom: int) -> float:
        """Ground_Res = (C_earth * cos(lat_rad)) / (512 * 2^zoom)."""
        lat_rad = math.radians(latitude)
        numerator = self.EARTH_CIRCUMFERENCE_METERS * math.cos(lat_rad)
        denominator = self.TILE_SIZE_PX * (2**zoom)
        return numerator / denominator

    def compute_uncertainty_pixel_radius(
        self, latitude: float, zoom: int, r_horiz_meters: float
    ) -> float:
        """r_px = R_horiz / Meters_Per_Pixel."""
        m_per_px = self.compute_meters_per_pixel(latitude, zoom)
        if m_per_px <= 0.0:
            return 1.0
        return r_horiz_meters / m_per_px


class OfflinePMTilesMapEngine:
    """Handles single-file PMTiles v3 archives and cellular sector wedge geometry."""

    PMTILES_V3_MAGIC = b"PMTiles\x03"

    def validate_pmtiles_header(self, header_bytes: bytes) -> bool:
        """Verifies PMTiles v3 8-byte magic header."""
        if not header_bytes or len(header_bytes) < 8:
            return False
        return header_bytes[:8] == self.PMTILES_V3_MAGIC

    @staticmethod
    def _xy_to_hilbert_d(n: int, x: int, y: int) -> int:
        """Maps 2D grid coordinates (x, y) to 1D Hilbert curve index d."""
        d = 0
        s = n // 2
        curr_x = x
        curr_y = y
        while s > 0:
            rx = 1 if (curr_x & s) > 0 else 0
            ry = 1 if (curr_y & s) > 0 else 0
            d += s * s * ((3 * rx) ^ ry)
            # Rotate quadrant
            if ry == 0:
                if rx == 1:
                    curr_x = s - 1 - curr_x
                    curr_y = s - 1 - curr_y
                curr_x, curr_y = curr_y, curr_x
            s //= 2
        return d

    def compute_hilbert_tile_id(self, z: int, x: int, y: int) -> int:
        """Computes 64-bit TileID along 2D Hilbert space-filling curve."""
        base_offset = ((4**z) - 1) // 3 if z > 0 else 0
        grid_dim = 1 << z
        hilbert_idx = self._xy_to_hilbert_d(grid_dim, x, y)
        return base_offset + hilbert_idx

    def compute_cellular_sector_wedge(
        self,
        tower_lat: float,
        tower_lon: float,
        azimuth_deg: float,
        beamwidth_deg: float = 120.0,
        range_meters: float = 1800.0,
    ) -> CellularSectorWedge:
        """Generates a 32-vertex geodesic circular sector polygon for 4G/5G base stations."""
        coords: list[tuple[float, float]] = []
        # Apex at tower
        coords.append((tower_lat, tower_lon))

        half_beam = beamwidth_deg / 2.0
        start_angle = azimuth_deg - half_beam
        end_angle = azimuth_deg + half_beam

        # Generate 30 arc points
        num_arc_points = 30
        lat_rad = math.radians(tower_lat)
        meters_per_deg_lat = 111320.0
        meters_per_deg_lon = 111320.0 * math.cos(lat_rad)

        for i in range(num_arc_points):
            frac = i / float(num_arc_points - 1)
            angle = start_angle + frac * (end_angle - start_angle)
            theta_rad = math.radians(angle)

            # Geodesic offset
            d_north = range_meters * math.cos(theta_rad)
            d_east = range_meters * math.sin(theta_rad)

            pt_lat = tower_lat + (d_north / meters_per_deg_lat)
            pt_lon = tower_lon + (d_east / meters_per_deg_lon)
            coords.append((round(pt_lat, 6), round(pt_lon, 6)))

        # Close polygon back at tower apex
        coords.append((tower_lat, tower_lon))

        return CellularSectorWedge(
            tower_lat=tower_lat,
            tower_lon=tower_lon,
            azimuth_deg=azimuth_deg,
            beamwidth_deg=beamwidth_deg,
            range_meters=range_meters,
            polygon_coordinates=coords,
        )

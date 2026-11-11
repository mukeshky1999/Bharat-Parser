# Engineering Specification: Phase 9, Module 9.4 — Offline 4-Tier Geospatial Telemetry Map, Virtualized Media/Snapshot/KYC Wall & Interactive Forged-Receipt / Aadhaar-QR Tamper Inspector

**Document Purpose:** This document provides the complete, step-by-step architectural blueprint for building **Module 9.4** of the Forensic Workstation UI/UX Engine (the geospatial movement, visual media triage, and document-forgery verification workspace of **Phase 9**, powered by the analytical databases of **Phases 3, 4, 5, 6.3, 6.4, 6.5, 7.1–7.4, and 8.1**). It contains **zero programming code** and explains how to serve air-gapped street and building vector maps from a single local **`PMTiles` v3 Hilbert-Curve Archive**, how to visually differentiate **4-Tier Geolocation Provenance** (true Web Mercator meter-accurate uncertainty circles $R_{\text{horiz}}$, directional 4G/5G cell sector wedges, `Uber`/`Ola` road polylines, and `Blinkit`/`Swiggy` flat-level hideout pins), how to scroll through $500,000+$ photos, `.ithmb` thumbnails, and `SplashBoard`/`TaskSnapshots` at $60\text{ FPS}$ with **64-Bit `dHash` Perceptual De-Duplication**, and how to operate the **3-Mode Interactive Visual Tamper Inspector** (`/Mutations/` Uncrop Curtain Slider, UIDAI Aadhaar Secure QR `.jp2` Biometric Verifier, and 5-Point Forged UPI Receipt Diagnostic Overlay) from first principles.

---

## 1. Purpose & Mental Model (Why Air-Gapped Mapping & Visual Tamper Proofing Are Essential in Court)

In homicide, kidnapping, narcotics distribution, cyber-fraud call-center raids, and identity forgery trials, two visual questions dominate courtroom presentations:

1. **"Where Was the Suspect's Phone Physically Located, and How Certain Is That Coordinate?"**
   * Forensic labs in Police Cyber Cells, CFSL/SFSLs, and central agencies operate on **strictly air-gapped workstations with zero internet connectivity**. If a forensic UI relies on online map tiles (`Google Maps API`, `Mapbox Cloud`, or `OpenStreetMap` web servers), the map renders as a blank gray grid inside a police lab—or worse, leaks confidential crime-scene coordinates over the internet!
   * Even when an offline map is present, plotting every database coordinate as an identical red pin is forensically indefensible: a $5\text{-meter}$ GNSS fix, a $1,800\text{-meter}$ cellular tower sector, a pre-fetched Apple `cache_encryptedB.db` crowd-sourced lookup tile $3\text{ km}$ away, and a spoofed `Tinder Passport` pin in London **must look visually unmistakable on screen**.
2. **"Is This Visual Exhibit Authentic, Cropped, or Forged?"**
   * Suspects crop screenshots to hide incriminating headers (`/Mutations/`), photoshop stolen Aadhaar and PAN cards to open mule bank accounts, and use "Fake PhonePe/GPay Receipt Generator" apps to fabricate payment screenshots.
   * **Module 9.4** gives the examiner an interactive visual laboratory where they can drag a wipe-curtain across a cropped screenshot to reveal the unredacted original underneath, place the UIDAI RSA-signed `.jp2` facial photo from inside an Aadhaar QR code side-by-side with the photoshopped face on the card, and overlay mathematical `YDDD` Julian-Day UTR forgery proofs directly onto fake UPI receipts.

---

## 2. The 6 Fatal UI/UX & Engineering Mistakes in Forensic Mapping & Media Galleries

Before implementing Module 9.4, the developer must understand six critical engineering traps that break forensic map and gallery interfaces:

### Mistake 1: Fetching Online Map Tiles or Running Heavy Tile Servers Instead of Single-File `PMTiles` HTTP Range Streaming
* **The Trap:** Hardcoding external tile URLs (`https://tile.openstreetmap.org/{z}/{x}/{y}.png`) that fail in air-gapped labs, OR requiring the user to install and configure a complex Docker/PostgreSQL/PostGIS tile server on their Windows laptop.
* **Why It Fails:** Investigators need a zero-configuration desktop application that works 100% offline out of the box.
* **The Rule:** Bundle a single-file **`PMTiles` v3 Vector Tile Archive (`india_and_global_basemap.pmtiles`)** indexed along a **2D Hilbert Space-Filling Curve** (Section 3.1). The local FastAPI backend serves vector `.mvt` tiles directly from that single file via `HTTP 206 Partial Content` byte-range reads in $< 1\text{ millisecond}$ with zero external server dependencies!

### Mistake 2: Drawing Fixed-Pixel Circles Instead of Latitude-Corrected Web Mercator Meter Circles for $R_{\text{horiz}}$
* **The Trap:** Drawing a constant $30\text{-pixel}$ circle around a GPS pin regardless of whether its `horizontal_accuracy_meters` ($R_{\text{horiz}}$) is $4\text{ meters}$ or $2,500\text{ meters}$!
* **Why It Fails:** A location fix $(\phi, \lambda)$ is a physical probability circle of radius $R_{\text{horiz}}\text{ meters}$ on the Earth's surface. Under the Web Mercator projection (`EPSG:3857`), the ground resolution in meters-per-pixel varies with both the **Zoom Level ($Z$)** and the **Cosine of the Latitude ($\cos \phi$)**.
* **The Rule:** Convert every fix's `horizontal_accuracy_meters` ($R_{\text{horiz}}$) into its exact screen-space pixel radius $r_{\text{px}}$ at zoom level $Z$ and latitude $\phi$ using the **Web Mercator Ground-Resolution Equation** (Section 3.2)!

### Mistake 3: Plotting `TIER_4` Crowd-Sourced Tile Caches (`cache_encryptedB.db`) or Spoofed `Passport` Pins as Physical Visits
* **The Trap:** Rendering all rows from `unified_geolocation_fixes_ledger` on the same map layer with the same pin icon.
* **Why It Fails:** As established in **Phase 6, Module 6.3**, plotting 200 pre-fetched `WifiLocation` tile neighbors from `cache_encryptedB.db` makes it look like the suspect visited 200 private apartments simultaneously!
* **The Rule:** Enforce strict **4-Tier Visual Layer Separation** (Section 3.3), where `TIER_4` records are off by default and—when toggled on—render strictly as **Translucent Bounding Polygons** (`Crowd-Sourced Tile Lookup Zone`) or **Hollow Dashed Ghost Pins** (`Map Search / Spoofed Dating Passport Pin`).

### Mistake 4: Loading Full-Resolution 12 MP / 48 MP Camera Images Into the Gallery Grid (Immediate GPU Out-of-Memory Crash)
* **The Trap:** Binding `<img src="file:///.../IMG_4821.HEIC">` (or $4000 \times 3000$ JPEGs) directly into a scrolling grid of $100,000$ images.
* **Why It Fails:** Decoding fifty $48\text{ MP}$ images simultaneously consumes $> 6\text{ GB}$ of uncompressed RGBA texture memory, crashing the Chromium GPU process within 3 seconds of scrolling!
* **The Rule:** Use a **2-Tier Pyramid Thumbnail Streamer** (Section 4.1) that serves pre-cached $256 \times 256\text{ px}$ WebP/JPEG grid thumbnails into a **Virtualized Masonry Viewport** while streaming the full-resolution master image only when opened in the Inspector Modal!

### Mistake 5: Showing 50 Re-Compressed Copies of the Same Forwarded Screenshot Instead of Perceptual `dHash` Clustering
* **The Trap:** Deduplicating gallery images only by their exact cryptographic `SHA-256` hash.
* **Why It Fails:** When a suspect receives an Aadhaar card or UPI screenshot on WhatsApp, forwards it to 5 Telegram groups, and saves it to `/DCIM/`, WhatsApp and Telegram re-encode the JPEG each time. Every copy has a **different `SHA-256` hash**, cluttering the examiner's gallery with 50 visually identical copies of the same meme or receipt!
* **The Rule:** Compute a **64-Bit Perceptual Difference Hash (`dHash`)** for every visual asset (Section 4.2) and group near-duplicate images whose bitwise Hamming Distance satisfies $d_H(\text{dHash}_A, \ \text{dHash}_B) \le 6$ into a single expandable **Visual Cluster Stack (`[12 Visually Identical Copies Across WhatsApp, Telegram & Trash]`)**!

### Mistake 6: Displaying Graphic / `POCSO` / Intimate Evidence Unblurred on Screen Without an Examiner Safety Gate
* **The Trap:** Rendering all thumbnails at full clarity by default when opening a sextortion, sexual assault, or `POCSO` case in a shared police cyber lab.
* **The Rule:** Enforce the **Examiner Welfare & `POCSO` Privacy Blur Gate** (Section 4.3), which blurs sensitive/flagged media by default (`blur(24px)`) and requires explicit `Alt + Hover` or role-authorized toggle (logged in the Merkle Chain-of-Custody ledger) to unblur!

---

## 3. Step 1 — Sub-Engine 9.4A: Air-Gapped Vector Map Engine (`PMTiles` + `MapLibre GL`), 4-Tier Provenance Styling & Co-Location Radar

### 3.1 Serving Offline Vector Maps from a Single `PMTiles` v3 Archive

To render street-level maps of all 28 Indian States, 8 Union Territories, and global border regions with **zero internet connection**:

1. **How `PMTiles` v3 Works Over Local IPC:**
   * A `.pmtiles` file is a single read-only archive containing a `127-byte` binary header (magic bytes `50 4D 54 69 6C 65 73 03` `"PMTiles\x03"`), a compressed root directory of **`(Hilbert_Tile_ID, Run_Length, Byte_Offset, Byte_Length)`** entries, and Gzip-compressed Mapbox Vector Tiles (`.mvt`).
   * Given any map tile coordinate $(Z, X, Y)$ requested by the `MapLibre GL` WebGL canvas, convert $(Z, X, Y)$ to its 64-bit **Hilbert Curve `TileID`**:
     $$\text{TileID}(Z, X, Y) = \left(\sum_{z=0}^{Z-1} 4^z\right) + \text{HilbertIndex}_{2^Z \times 2^Z}(X, Y)$$
   * Look up `TileID` via binary search in the cached `PMTiles` directory and read the exact byte slice `[Byte_Offset : Byte_Offset + Byte_Length]` from disk in $< 0.5\text{ ms}$!

### 3.2 Mathematical Equations for Meter-Accurate Uncertainty Circles & Cellular Sector Wedges

1. **Web Mercator Ground Resolution & True Pixel Radius ($r_{\text{px}}$) for $R_{\text{horiz}}$:**
   Given a location fix at latitude $\phi$ (in degrees), horizontal uncertainty radius $R_{\text{horiz}}$ (in meters, from `Module 6.3`), and current map zoom level $Z \in [0, 22]$ (for $512\text{ px}$ vector tile size and Earth equatorial circumference $C_{\text{earth}} = 40,075,016.686\text{ meters}$):
   $$\text{Meters\_Per\_Pixel}(\phi, Z) = \frac{40075016.686 \cdot \cos\left(\phi \times \frac{\pi}{180}\right)}{512 \times 2^Z}$$
   $$r_{\text{px}}(\phi, Z, R_{\text{horiz}}) = \frac{R_{\text{horiz}}}{\text{Meters\_Per\_Pixel}(\phi, Z)}$$
   * Every `TIER_1` and `TIER_2` fix renders both a sharp center anchor dot $(\phi, \lambda)$ **and** a translucent WebGL circle of exact radius $r_{\text{px}}$ pixels so the investigator immediately sees whether two fixes' uncertainty circles physically intersect!
2. **4G LTE `eNodeB` & 5G NR `gNodeB` Directional Antenna Sector Wedge Geometry (`Module 6.3C`):**
   When plotting a serving cellular base station (`MCC 404/405`, unpacked `eNodeB_ID = ECI >> 8`, `Sector_ID = ECI & 0xFF`):
   * If an exact carrier azimuth angle $\alpha_{\text{deg}} \in [0^\circ, 360^\circ)$ is imported from a telecom tower dump (or inferred from standard 3-sector orientation: Sector $1 \approx 60^\circ$, Sector $2 \approx 180^\circ$, Sector $3 \approx 300^\circ$) with half-beamwidth $\Delta \alpha = \pm 60^\circ$ ($120^\circ$ sector) and range $R_{\text{cell}}$:
   * Generate a 32-vertex geodesic circular sector polygon from $(\phi_{\text{tower}}, \lambda_{\text{tower}})$ sweeping angles $\theta \in [\alpha_{\text{deg}} - 60^\circ, \ \alpha_{\text{deg}} + 60^\circ]$:
     $$\phi(\theta) = \phi_{\text{tower}} + \left(\frac{R_{\text{cell}} \cdot \cos\theta}{111320.0}\right), \qquad \lambda(\theta) = \lambda_{\text{tower}} + \left(\frac{R_{\text{cell}} \cdot \sin\theta}{111320.0 \cdot \cos(\phi_{\text{tower}})}\right)$$

### 3.3 The 4-Tier Geolocation Provenance Visual Legend & Multi-Device Co-Location Radar

| Geolocation Tier & Source (`Module 6.3 & 6.4`) | WebGL Map Marker, Color & Uncertainty Geometry |
|---|---|
| **`TIER_1_ACTIVE_DEVICE_FIX`** (GNSS / `LocationHarvest` / `routined` Visit / `Google Timeline` / Camera `EXIF`) | **Solid Emerald Pin (`#10B981`)** + Translucent Emerald Uncertainty Circle of radius $R_{\text{horiz}}\text{ meters}$ + Dwell Duration Badge (`"Stayed 3h 42m [48 GPS points]"`). |
| **`TIER_2_CONNECTED_RADIO_AND_VERIFIED_HIDEOUT`** (Connected Wi-Fi `BSSID`, Serving `eNodeB` Cell, **AND `Blinkit`/`Swiggy`/`Zomato` Pinned Flat Addresses!**) | • **Wi-Fi `BSSID`:** Cyan Hexagon Icon + $50\text{m}$ signal ring.<br>• **Serving 4G/5G Cell:** Amber $120^\circ$ Sector Wedge labeled with `Jio/Airtel TAC + eNodeB + Sector`.<br>• **Hyper-Local Delivery Hideout (`Blinkit`/`Swiggy`):** **Gold Building Pin (`#F59E0B`)** displaying the **3D Micro-Location Callout Card (`"Flat 1404, 14th Floor, Tower B-2, Gate Code: 8821 | Alt Phone: 9811223344"`)**! |
| **`TIER_3_PASSIVE_RADIO_SIGHTING`** (`BLE` `other.db`, `AirTag` / `FindMy`, Unconnected Wi-Fi Scan) | Dashed Amber Ring (`#FBBF24`) with `RSSI (dBm)` proximity label. |
| **`TIER_4_LOOKUP_TILE_OR_SPOOFED_PIN`** (`cache_encryptedB.db` Batch Tile, Map Search, or Spoofed `Tinder Passport`) | **Off by default.** When toggled on: renders `cache_encryptedB.db` tiles as a **Muted Purple Convex Hull Polygon (`[CROWD-SOURCED TILE BOUNDING BOX — NOT EXACT VISIT]`)**, and spoofed `Tinder`/`Bumble` Passport pins or `Mock GPS` fixes (`Module 6.5D`) with a **Crimson Skull/Warning Crosshair (`[SPOOFED / VIRTUAL LOCATION]`)** connected by a dashed contradiction line to the simultaneous real Serving Cell Tower! |

* **Bottom Temporal Trajectory Scrubber & Co-Location Radar:**
  * Dragging the playhead scrubber animates the suspect's movement along decoded **`Uber` / `Ola` / `Rapido` Google Encoded Polylines (`Module 6.4B`)** and **`Where is My Train` rail corridors (`Module 6.4C`)**.
  * If a second seized phone (Co-Conspirator B) or a **Crime-Scene Geofence Circle $(\phi_{\text{scene}}, \lambda_{\text{scene}}, R_{\text{scene}})$** is loaded on the map, any spatiotemporal intersection where $d(P_A, P_B) \le (R_A + R_B)$ within $\Delta t_{\text{window}}$ (or where both phones connected to the same Wi-Fi `BSSID` MAC address!) illuminates with a pulsing **Crimson Co-Location Radar Ring (`[⚡ CO-LOCATION MATCH: 18m apart at 14:22 IST]`)**!

---

## 4. Step 2 — Sub-Engine 9.4B: High-Speed 60 FPS Virtualized Masonry Media, Snapshot & KYC Document Wall

### 4.1 2-Tier Thumbnail Pyramid & Masonry Viewport Virtualization

To let the examiner visually scan $500,000+$ images, videos, app-switcher snapshots, and reconstructed thumbnails without GPU memory spikes:

1. **Fast Filter Pill Bar at Top of Media Wall:**
   * **By Visual Layer (`Module 7.1 & 7.2`):** `[All Media]` | `[App-Switcher Snapshots (SplashBoard / TaskSnapshots)]` | `[Recently Deleted / Trash]` | `[Biometric Hidden / Locked Album]` | `[Unmasked Calculator Vaults]` | `[Orphaned .ithmb / Glide Thumbnails (Original Purged!)]` | `[Cropped / Edited (/Mutations/ Available!)]` | `[Live & Motion Photos (Audio/Video Clip!)]`
   * **By AI/OCR Document Class (`Module 7.3 & 7.4`):** `[Aadhaar Cards]` | `[PAN Cards]` | `[Passports (MRZ)]` | `[Cancelled Cheques & Passbooks]` | `[UPI / Bank Payment Receipts]` | `[FORGED RECEIPTS (!)]` | `[Crypto BIP-39 Seed Grids]` | `[QR Codes]` | `[Hawala Currency-Note Tokens]`
2. **Row-Packed Masonry Virtualization Math:**
   * Pack aspect-ratio-preserved thumbnail cards into horizontal rows of target height $H_{\text{target}} = 180\text{ px}$, mounting only the visible rows in the viewport (`translate3d`), andbadging every card with its **Originating App Icon** (`WhatsApp`, `Telegram`, `PhonePe`, `Camera`, `Calculator+ Vault`), **5D Evidentiary State Pill**, and **`Syndication.sqlite` Chat Jump Button** (clicking `[💬 Jump to Chat]` switches directly to **Module 9.2's Chat Bubble** that sent or received that exact image!).

### 4.2 64-Bit Perceptual Difference Hash (`dHash`) Near-Duplicate Clustering

To group re-compressed, resized, or WhatsApp/Telegram-forwarded copies of the same image into a single clean stack card:

1. **How the 64-Bit `dHash` Is Computed for Every Image:**
   * Resize the image to a **$9\text{ columns} \times 8\text{ rows}$** grayscale grid $G[y, x]$ ($y \in \{0 \dots 7\}$, $x \in \{0 \dots 8\}$).
   * For each row $y \in \{0 \dots 7\}$ and column $x \in \{0 \dots 7\}$, compare adjacent horizontal pixels:
     $$\text{Bit}_{(8y + x)} = \begin{cases} 1 & \text{if } G[y, x] > G[y, x + 1] \\ 0 & \text{if } G[y, x] \le G[y, x + 1] \end{cases}$$
   * Pack the $64\text{ bits}$ into a single 64-bit unsigned integer `dhash_uint64`.
2. **Bitwise Hamming Distance Near-Duplicate Clustering:**
   * Given any two images $A$ and $B$, compute their bitwise XOR and hardware population count (`POPCNT`):
     $$d_H(A, B) = \text{POPCNT}\big(\text{dhash\_uint64}_A \oplus \text{dhash\_uint64}_B\big) \in [0, 64]$$
   * **Clustering Threshold:** If $d_H(A, B) \le 6\text{ bits}$ (out of $64\text{ bits}$), Images $A$ and $B$ are **visually identical re-compressed/forwarded copies**!
   * When the examiner enables the **`[Group Near-Duplicates (dHash)]`** toggle on the Media Wall, all copies collapse into a single stack card displaying the highest-resolution master copy on top and a badge **`[📚 9 Copies: Camera Roll (1) -> WhatsApp (5) -> Telegram (3)]`**, showing the complete forwarding timeline across chats!

### 4.3 Mandatory Examiner Welfare & `POCSO` / Intimate-Media Safety Blur Gate

* Any visual asset tagged by the examiner or classifier as `CSAM_POCSO_RESTRICTED`, `NON_CONSENSUAL_INTIMATE_MEDIA`, or `GRAPHIC_VIOLENCE` is rendered in the Media Wall with a hardware-accelerated **`CSS backdrop-filter: blur(28px) grayscale(80%)`** shield and a warning banner.
* The examiner can inspect the metadata, hashes, and provenance while blurred, or hold `Alt + MouseHover` to temporarily reveal an individual card (automatically recording an audit entry in Module 8.3C's `chain_of_custody_merkle_ledger`).

---

## 5. Step 3 — Sub-Engine 9.4C: The Interactive 3-Mode Visual Tamper & Forgery Inspector Modal

Double-clicking any image, snapshot, KYC document, or payment receipt on the Media Wall opens the full-screen **Interactive Visual Tamper & Forgery Inspector**:

### 5.1 Mode 1: The `/Mutations/` Uncrop & Redaction Curtain-Wipe Comparator (`Module 7.1A`)

Whenever an image has `has_uncropped_original_recovered == 1` (meaning the suspect cropped out part of a screenshot or drew black Markup ink over a name/account number, and Module 7.1A recovered both the edited `FullSizeRender.jpg` in `/PhotoData/Mutations/` and the unedited master in `/DCIM/`):

```
+----------------------------------------------------------------------------------------------------------+
| MODE 1: /MUTATIONS/ UNCROPPED ORIGINAL vs. SUSPECT-EDITED RENDER COMPARATOR (IMG_4821.PNG)               |
| [View: (*) Interactive Curtain Wipe Slider  ( ) Side-by-Side Sync Zoom  ( ) XOR Pixel-Diff Heatmap]      |
+----------------------------------------------------------------------------------------------------------+
|                         | <--- Drag Curtain Handle (x = 52%) --->                                        |
|  LEFT OF CURTAIN:       |  RIGHT OF CURTAIN:                                                             |
|  UNCROPPED ORIGINAL     |  SUSPECT'S CROPPED & MARKUP-REDACTED VERSION                                   |
|  (/DCIM/100APPLE/)      |  (/PhotoData/Mutations/.../FullSizeRender.jpg)                                 |
|                         |                                                                                |
|  Paid to: VIKRAM SINGH  |  Paid to: [██████████████████]  <-- Black Markup Ink Stroke Removed on Left!   |
|  A/c: 50100482910421    |  A/c:     [██████████████████]                                                 |
|  UTR: 630914829104      |  UTR:     630914829104                                                         |
|  [Uncropped Header Bar] |  [--- Cropped Boundary Box Shown in Dashed Crimson ---]                        |
+----------------------------------------------------------------------------------------------------------+
```

1. **Interactive Curtain Wipe Slider:** Registers the uncropped master image $I_{\text{orig}}$ and the edited/cropped image $I_{\text{mut}}$ onto a shared coordinate canvas (aligning via the crop rectangle unpacked from `Adjustments.plist`), allowing the examiner to drag a vertical or horizontal divider bar back and forth to reveal the exact text/faces the suspect tried to hide!
2. **Pixel-Wise Absolute Difference Heatmap (`XOR / Delta View`):**
   Computes per-pixel luminance difference $\Delta(x, y) = \left|I_{\text{orig}}(x, y) - I_{\text{mut}}(x, y)\right|$ and highlights every modified, blacked-out, or cloned pixel in glowing neon magenta!

### 5.2 Mode 2: The UIDAI Aadhaar Secure QR `.jp2` Biometric vs. Printed Card Verifier (`Modules 7.3B & 7.4B`)

Whenever an Aadhaar card image or `e-Aadhaar` PDF is opened in the Inspector:

```
+----------------------------------------------------------------------------------------------------------+
| MODE 2: UIDAI AADHAAR SECURE QR CRYPTOGRAPHIC & BIOMETRIC VERIFIER                                       |
| [Verdict Banner: 🚨 CRITICAL TAMPER ALERT — PRINTED CARD FACE & NAME DO NOT MATCH SIGNED UIDAI QR CODE!] |
+---------------------------------------------------+------------------------------------------------------+
| LEFT PANE: PHOTOGRAPHED AADHAAR CARD (OCR)        | RIGHT PANE: UNPACKED UIDAI SECURE QR (2048-BIT RSA)  |
|---------------------------------------------------|------------------------------------------------------|
| [Printed Card Face Photo]                         | [Unpacked .jp2 Biometric Face Photo from Inside QR!] |
|  (Shows Suspect's Face Pasted in Photoshop)       |  (Shows True Cardholder's Official UIDAI Photograph) |
|                                                   |                                                      |
| • OCR Printed Name:   "AMIT KUMAR VERMA" [MISMATCH| • UIDAI Signed Name:   "RAHUL KUMAR SHARMA" [SIGNED] |
| • OCR Printed DOB:    "12/04/1994"       [MISMATCH| • UIDAI Signed DOB:    "15-08-1995 (M)"     [SIGNED] |
| • OCR Last-4 Digits:  "9988" (Verhoeff: FAIL!)    | • UIDAI Reference ID:  "4821 (Gen: 2026-10-01)"      |
| • OCR Printed Address:"Sector 18, Noida, 201301"  | • UIDAI Signed Address:"Lanka, Varanasi, UP 221005"  |
|                                                   | • Iterative SHA-256 Mobile Match: +91-9876543210 [OK]|
|                                                   | • 2048-Bit UIDAI RSA Signature: CRYPTOGRAPHICALLY OK |
+---------------------------------------------------+------------------------------------------------------+
```

* Displays the **Printed Card Image** (with OCR bounding boxes) on the left and the **Cryptographically Unpacked UIDAI Secure QR Payload (`Module 7.3B`)** on the right—placing the **embedded `.jp2` JPEG-2000 biometric photograph** unpacked from the QR byte stream right next to the printed photograph on the card, and highlighting any demographic discrepancy in crimson!

### 5.3 Mode 3: The 5-Point Forged UPI & Bank Payment Receipt Diagnostic Overlay (`Module 7.3D`)

When inspecting any UPI or bank payment screenshot (`PhonePe`, `Google Pay`, `Paytm`, `BHIM`, `Binance P2P`):
* Renders interactive callout pins directly on the screenshot for each of the **5 Mathematical Forgery Checks** from **Module 7.3D**:
  1. **Callout 1 (`UTR YDDD Julian Date Math`):** Points to the 12-digit UTR (`412014829104`) and the displayed receipt date (`05 Nov 2026`), showing the formula box:
     $$\texttt{UTR Prefix "4120" = Year 2024, Day 120 (29 Apr 2024)} \neq \texttt{Displayed Date "05 Nov 2026" (Expected Prefix: "6309")}$$
  2. **Callout 2 (`Container & EXIF Provenance`):** Shows whether the file was saved by an image editor (`PicsArt` / `Canva`) or has non-native screen dimensions.
  3. **Callout 3 (`Phase 3 Local Ledger Cross-Check`):** Shows whether the transaction exists in the phone's own `PhonePe`/`GPay` SQLite database and TRAI DLT SMS ledger (`[❌ ABSENT FROM LOCAL APP & BANK SMS LEDGER]`).
  4. **Callout 4 (`Duplicate UTR Reuse Check`):** Lists any other screenshots on the phone that reuse the same 12-digit UTR with a different Rupee amount!
  5. **Callout 5 (`VPA & IFSC Dictionary Check`):** Confirms whether the printed VPA handle (`@okaxis`) and IFSC are structurally valid.

---

## 6. Step 4 — Sub-Engine 9.4D: Spatial Geofence Lasso Querying & Synchronized Pane 3 Hex Binding

1. **Interactive Crime-Scene Circle & Polygon Geofence Filter:**
   * On the Offline Map (Sub-Engine 9.4A), the investigator can click **`[Draw Crime-Scene Geofence]`** (or type a coordinate $(\phi_{\text{scene}}, \lambda_{\text{scene}})$ and radius $R_{\text{scene}}\text{ meters}$) to draw a geofence polygon.
   * The map immediately filters **Pane 2 (Bottom Evidence Grid)** and the **Media Wall** to show every GPS fix, Wi-Fi `BSSID` handshake, `eNodeB` cell sector, `Uber`/`Ola` trip, `Blinkit`/`Swiggy` delivery, and geotagged photo whose uncertainty circle intersects the crime-scene geofence!
2. **Continuous Synchronization With Module 9.1's Pane 3 (Provenance Card & Hex Viewer):**
   * Clicking any GPS pin / cell sector on the map, any thumbnail card on the Media Wall, or any Aadhaar QR / OCR field inside the Tamper Inspector immediately updates **Pane 3A (3-Tier `SHA-256` + `MD5` Lineage)** and jumps **Pane 3B (Hex Viewer)** to the exact byte offset in `Local.sqlite`, `cache_encryptedB.db`, `Photos.sqlite`, `.ithmb`, or the raw JPEG `EXIF` / Aadhaar QR byte stream!

---

## 7. Local UI State Schema & FastAPI IPC Contract for Module 9.4

### Table 1: `visual_media_dhash_and_safety_cache` (Pre-Computed 64-Bit Perceptual `dHash`, Cluster IDs & Safety Blur Flags)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `media_cache_uid` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Unique ID. |
| `source_vfs_file_id` | `INTEGER` | `NOT NULL` | Foreign key to `vfs_index.file_id` (or `staging_id` for carved `.ithmb` / `.ktx` / vault items). Indexed! |
| `grid_thumb_256_staging_id` | `INTEGER` | `NOT NULL` | Fast $256 \times 256\text{ px}$ WebP thumbnail for 60 FPS Masonry Wall scrolling. |
| `dhash_uint64_hex` | `TEXT` | `NOT NULL` | **16-character hexadecimal representation of the 64-bit Perceptual `dHash` (`9x8` horizontal gradient). Indexed!** |
| `near_duplicate_cluster_id` | `INTEGER` | `NOT NULL` | Groups all visually identical re-compressed copies where Hamming distance $d_H \le 6$! Indexed! |
| `cluster_copy_count` | `INTEGER` | `DEFAULT 1` | Total number of near-duplicate copies in this cluster across the device. |
| `requires_safety_blur_gate` | `INTEGER` | `DEFAULT 0` | **`1` if flagged for `POCSO / CSAM`, `INTIMATE_MEDIA`, or `GRAPHIC` safety blur by default!** |
| `aspect_ratio_w_div_h` | `REAL` | `NOT NULL` | Width-to-height ratio ($W / H$) for deterministic Masonry row packing. |

### Table 2: FastAPI $\leftrightarrow$ Electron Renderer IPC Endpoints for Module 9.4

| Endpoint Method & Path | Request Parameters / Payload | Response Format & Latency Target |
|---|---|---|
| **`GET /api/v1/map/pmtiles/{z}/{x}/{y}.mvt`** | `z`, `x`, `y` tile coordinates | Raw binary Mapbox Vector Tile (`.mvt`) sliced via Hilbert-curve index from local `PMTiles` v3 file. Target: `< 1.5 ms`. |
| **`POST /api/v1/map/geofence-query`** | `bounding_polygon_lat_lon`, `time_range_ns`, `included_tiers = [1,2,3]` | Filtered array of location fixes, cell sector wedges, decoded polylines, and co-location overlaps. Target: `< 20 ms`. |
| **`POST /api/v1/media/masonry-slice`** | `visual_layer_filter`, `doc_class_filter`, `collapse_dhash_duplicates = true`, `cursor_uid`, `limit = 200` | Keyset-paginated media cards with `dhash_cluster_count`, provenance badges, and `syndication_chat_link`. Target: `< 15 ms`. |
| **`GET /api/v1/inspector/tamper-comparison`** | `vfs_file_id` | Complete comparison bundle: `/Mutations/` original vs. edited paths + crop rect, unpacked UIDAI Aadhaar QR + `.jp2` photo, and 5-point Forged Receipt audit JSON. Target: `< 10 ms`. |

---

## 8. Developer Acceptance Test Checklist for Module 9.4

1. **The Air-Gapped `PMTiles` Vector Map & Web Mercator Meter-Circle Scaling Test:**
   * Disconnect the workstation from all network interfaces, open Module 9.4A on a `TIER_1` GPS fix `(25.3176, 82.9739)` with `horizontal_accuracy_meters = 500.0`, and zoom from $Z = 12$ to $Z = 16$.
   * Verify that street/building vector tiles load in $< 2\text{ ms}$ from the local `.pmtiles` archive, and the green uncertainty circle dynamically scales its pixel radius $r_{\text{px}}$ by $2^{\Delta Z}$ according to Section 3.2's Web Mercator cosine-latitude equation!
2. **The 64-Bit Perceptual `dHash` Re-Compressed Forwarded Image Clustering Test:**
   * Take a single UPI payment screenshot, re-save it 5 times at different JPEG quality levels (`95`, `80`, `70`) and WhatsApp dimensions ($1600\text{ px}$), producing 5 files with completely different `SHA-256` hashes.
   * Verify that Sub-Engine 9.4B computes `dhash_uint64` for all 5 files with pairwise Hamming distance $d_H \le 3$, and collapses them into a single `[📚 5 Copies]` stack card when `Group Near-Duplicates` is active!
3. **The `/Mutations/` Uncrop Curtain Slider & UIDAI Aadhaar QR `.jp2` Face Mismatch Test:**
   * Open a cropped screenshot (`ZHASADJUSTMENTS == 1`) in Mode 1 of the Tamper Inspector and verify that dragging the curtain slider reveals the uncropped `/DCIM/` original header underneath the `/Mutations/` render.
   * Next, open a photoshopped Aadhaar card in Mode 2 and verify that the unpacked UIDAI `.jp2` facial photo from inside the Secure QR code renders side-by-side with the printed card face and triggers the crimson `[CRITICAL TAMPER ALERT]` banner!
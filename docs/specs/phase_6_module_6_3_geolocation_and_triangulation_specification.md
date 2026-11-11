# Engineering Specification: Phase 6, Module 6.3 — OS Geolocation, Wi-Fi/BLE/Cellular Triangulation, Significant Locations & On-Device Google Timeline Engine

**Document Purpose:** This document provides the complete, step-by-step architectural blueprint for building **Module 6.3** of the Forensic Data Parser (corresponding to **Groups 7, 8, 9, 10, and 15** of the Unified Master Register). It contains **zero programming code** and explains how to extract, disambiguate, and mathematically validate geolocation fixes, significant visit clusters, on-device Google Timeline semantic histories, Wi-Fi `BSSID` and Mobile Hotspot (`SoftAP`) logs, Bluetooth `Paired` vs. `BLE` sightings, and Indian 4G LTE / 5G NR Cellular Tower (`CGI`) identifiers from first principles so that any developer can build a courtroom-defensible physical movement and co-location engine.

---

## 1. Purpose & Mental Model (Why Location Forensics in 2026 Requires 4-Tier Provenance Separation)

In homicide, kidnapping, narcotics trafficking, terror conspiracy, hit-and-run, and organized cybercrime investigations, placing the suspect's handset at a specific physical coordinate—or proving that two co-conspirators' phones were in the same room at the same time—is often the centerpiece of the prosecution's case.

However, a modern smartphone contains **four fundamentally different types of location records** on disk. If your parser dumps every latitude and longitude found in SQLite databases onto a map without separating their provenance, a defence expert will easily discredit the entire map in court by pointing out that the tool plotted **pre-fetched crowd-sourced cell tower tiles ($3\text{ km}$ away)** or **map search previews** as if the suspect physically stood there!

### The 4 Mandatory Geolocation Provenance Tiers in Module 6.3

Every coordinate extracted by Module 6.3 must be classified into one of four strict evidentiary tiers:

1. **`TIER_1_ACTIVE_DEVICE_FIX` (High-Confidence Physical Device Presence):**
   * Recorded when the device's own GNSS (GPS / GLONASS / Galileo / NavIC) receiver, fused sensor engine (`CoreLocation` `LocationHarvest` / `routined`, or Android `FusedLocationProvider` / On-Device `Semantic Location`), or camera `EXIF` captured the handset's physical position, bounded by a measured **Horizontal Accuracy Radius ($R_{\text{horiz}}$ in meters)**.
2. **`TIER_2_CONNECTED_RADIO_HANDSHAKE` (Verified Physical Proximity to a Known Transceiver):**
   * Recorded when the handset completed an authenticated layer-2/layer-3 connection to a specific **Wi-Fi Router (`BSSID` MAC address with `LastJoined` timestamp)**, a **Paired Bluetooth Vehicle/Headset**, a **Mobile Hotspot (`SoftAP` client lease)**, or a **Serving Cellular Base Station (`MCC-MNC-TAC-ECI`)**.
3. **`TIER_3_PASSIVE_RADIO_SIGHTING` (Unconnected Ambient Radio Scan):**
   * Recorded when the phone's Wi-Fi or Bluetooth Low Energy (`BLE`) radio passively heard a beacon frame from a nearby router, AirTag, or smart device in passing (`RSSI` signal strength in $\text{dBm}$), without connecting to it.
4. **`TIER_4_CROWDSOURCED_LOOKUP_TILE_OR_SEARCH` (NOT Proof of Physical Presence at Exact Point!):**
   * When an iPhone (`cache_encryptedB.db`) or Android phone (`nlp` / `ulp` cache) queries Apple or Google's location servers to ask *"Where is Wi-Fi router `BSSID X`?"*, the server responds with a **pre-fetched geographic grid tile** containing the coordinates of $100\text{ to }500$ *other* Wi-Fi routers and cell towers within a $2\text{ km}\text{ to }5\text{ km}$ radius so the phone won't have to ask the server again as the user walks down the street!
   * Similarly, when a user searches for a city or previews a route in Apple Maps or Google Maps, the destination coordinates are cached locally.
   * **Forensic Rule:** Tier 4 records prove either that the device was **within the broad $2\text{–}5\text{ km}$ bounding box** that triggered the tile download, OR that the user **searched/previewed** that location—never that the device physically stood on top of every neighboring router inside the downloaded tile!

---

## 2. The 6 Fatal Mistakes Beginner Developers Make in Mobile Geolocation Forensics

Before implementing Module 6.3, the developer must understand six classic traps that cause catastrophic courtroom errors in location analysis:

### Mistake 1: Plotting Every Row in iOS `cache_encryptedB.db` (`WifiLocation` & `LteCellLocation`) as a Physical Visit
* **The Trap:** Running `SELECT MAC, Latitude, Longitude, Timestamp FROM WifiLocation;` on iOS `/private/var/root/Library/Caches/locationd/cache_encryptedB.db` and plotting all $15,000$ rows as the suspect's physical movement path.
* **Why It Fails:** `WifiLocation`, `CellLocation`, `LteCellLocation`, and `Nr5GCellLocation` inside `cache_encryptedB.db` are **Apple Crowd-Sourced Location Lookup Cache Tables**. When the phone sees 1 or 2 real Wi-Fi routers at an intersection, `locationd` downloads a batch of $200+$ neighboring BSSIDs (many inside locked private apartments 800 meters away!) and inserts all $200+$ rows into `WifiLocation` with the **exact same batch download timestamp**!
* **The Rule:** Use the **Batch-Timestamp & `LocationHarvest` Disambiguator** (Section 3.1): rows in `LocationHarvest` / `AppHarvest` are **Tier 1 Actual Device Fixes**, whereas rows in `WifiLocation` / `LteCellLocation` that share identical batch timestamps (`>= 5` rows within the same second spanning multiple locations) must be grouped into a single **Tier 4 Crowd-Sourced Tile Bounding Polygon** and cross-checked against `com.apple.wifi.known-networks.plist`!

### Mistake 2: Missing Google's 2024–2026 On-Device Location History ("Timeline") Migration
* **The Trap:** Telling an investigator: *"Google Timeline is stored only in Google Cloud (Google Takeout), not on the Android phone."*
* **Why It Fails:** Between late 2023 and 2025/2026, Google permanently **shut down cloud-based Location History** for standard accounts and **migrated the entire Google Maps Timeline database directly onto the user's local smartphone** (stored inside **Google Play Services `com.google.android.gms`** on Android and **Google Maps `com.google.Maps`** on iOS)! This means a seized Android or iOS phone in 2026 now holds **months or years of complete semantic visit history, place IDs, and transit paths locally on the flash chip**!
* **The Rule:** Sub-Engine 6.3B must parse the on-device Google Play Services (`com.google.android.gms`) Semantic Location / Timeline databases and local encrypted Timeline backup blobs (Section 4.1).

### Mistake 3: Ignoring `HorizontalAccuracy` ($R_{\text{horiz}}$) and Plotting a $2,000\text{-Meter}$ Cell Fix as a Pinpoint
* **The Trap:** Extracting `(Latitude = 25.3176, Longitude = 82.9739)` and displaying a sharp pinpoint on a specific house when the row's `HorizontalAccuracy` (`uncertainty` / `accuracy`) column is `1850.0` meters!
* **Why It Fails:** A location fix is not a dimensionless mathematical point—it is a **probability circle of radius $R_{\text{horiz}}\text{ meters}$** centered at $(\phi, \lambda)$:
  * **True GNSS / GPS Fix:** $R_{\text{horiz}} \in [3.0\text{ m}, \ 25.0\text{ m}]$.
  * **Wi-Fi / BLE Triangulation Fix:** $R_{\text{horiz}} \in [15.0\text{ m}, \ 100.0\text{ m}]$.
  * **Cellular Tower Triangulation Fix:** $R_{\text{horiz}} \in [300.0\text{ m}, \ 5000.0\text{ m}]$.
* **The Rule:** Every location record in `unified_geolocation_fixes_ledger` must store `horizontal_accuracy_meters` ($R_{\text{horiz}}$) and assign a **Spatial Precision Class** (`PINPOINT_GNSS_UNDER_25M`, `BUILDING_LEVEL_WIFI_25_TO_100M`, `NEIGHBORHOOD_CELL_100_TO_1000M`, `BROAD_SECTOR_OVER_1000M`).

### Mistake 4: Failing to Normalize stripped-zero Wi-Fi `BSSID` MAC Addresses in iOS
* **The Trap:** Joining `WifiLocation.MAC` from iOS `cache_encryptedB.db` (which stores `"0:1a:2b:3c:4:f0"`) with `com.apple.wifi.known-networks.plist` or Android `WifiConfigStore.xml` (which stores `"00:1a:2b:3c:04:f0"` or `"00:1A:2B:3C:04:F0"`).
* **Why It Fails:** In iOS `cache_encryptedB.db`, Apple formats 6-octet MAC addresses by converting each byte to hex **without leading zeroes** (so `0x00` becomes `"0"` and `0x04` becomes `"4"`!). If you do not pad each colon-separated octet to 2 lowercase hex digits, string joins between `cache_encryptedB.db` and `known-networks.plist` will fail!
* **The Rule:** Pass every extracted Wi-Fi `BSSID` and Bluetooth `MAC` address through the **Canonical 6-Octet Zero-Padded Lowercase MAC Normalizer** (`xx:xx:xx:xx:xx:xx`, Section 5.1) before storing or joining.

### Mistake 5: Confusing Paired Bluetooth Devices (`paired.db`) with Passive BLE Sightings (`other.db`)
* **The Trap:** Seeing a Bluetooth MAC address or device name inside iOS `com.apple.MobileBluetooth.ledevices.other.db` and reporting that the suspect "connected their phone to this Bluetooth device."
* **Why It Fails:**
  * `com.apple.MobileBluetooth.ledevices.paired.db` (and Android `bt_config.conf`) stores devices the suspect **actively paired and authenticated with** (their own car infotainment system, earbuds, smartwatch, or a co-conspirator's phone).
  * `com.apple.MobileBluetooth.ledevices.other.db` stores **passive Bluetooth Low Energy (`BLE`) advertisements** heard by the iPhone as the suspect walked through an airport, mall, or traffic jam!
* **The Rule:** Keep `ACTIVE_PAIRED_BLUETOOTH_DEVICE` and `PASSIVE_AMBIENT_BLE_SIGHTING` strictly separated (Section 5.2). *(Note: Passive BLE sightings are still forensically valuable when cross-matching whether Suspect A's iPhone passively sighted the BLE MAC / UUID of Suspect B's phone or AirTag at a crime scene!)*

### Mistake 6: Missing Mobile Hotspot (`SoftAP`) Client Logs (`dhcp.leases` & `WifiConfigStoreSoftAp.xml`)
* **The Trap:** Looking only at which Wi-Fi networks the seized phone connected *to* (as a client), and forgetting to check which other devices connected *into* the seized phone's **Personal Hotspot (`SoftAP`)**!
* **Why It Fails:** In field operations, one syndicate member with an active data SIM turns on their **Mobile Hotspot**, and 2 or 3 accomplices (carrying SIM-less burner phones or laptops) connect to that hotspot over Wi-Fi. Parsing the phone's hotspot configuration and DHCP lease logs reveals the **MAC addresses, hostnames (e.g., `"Vikrams-iPhone"`, `"Redmi-Note-13"`), and connection timestamps of the accomplices' devices**!

---

## 3. Step 1 — Sub-Engine 6.3A: iOS CoreLocation (`cache_encryptedB.db`), Significant Locations (`routined`) & `FindMy` Tracker

### 3.1 Parsing `cache_encryptedB.db` (`/private/var/root/Library/Caches/locationd/cache_encryptedB.db`)

Stage `cache_encryptedB.db` (and `cache_encryptedB.db-wal` + `cache_encryptedA.db` / `cache_encryptedC.db`) via Module 1.1 and process through **Phase 2, Module 2.1 (Active + `-wal` + Freelist)**. Separate its tables into **two strict forensic buckets**:

#### Bucket 1: True On-Device Location & Sensor Harvest Tables (`TIER_1_ACTIVE_DEVICE_FIX`)
* **Target Tables:** `LocationHarvest`, `AppHarvest`, `IndoorLocationHarvest`, `MotionStateHistory`, `PressureLocationHarvest`.
* **Columns to Extract:**
  * `Timestamp` (`REAL`): Apple Cocoa seconds since `2001-01-01 00:00:00 UTC` (convert via Module 1.2: $\text{Unix} = \text{Cocoa} + 978307200$).
  * `Latitude` & `Longitude` (`REAL`): WGS-84 decimal degrees. *(Reject dummy/null coordinates where $\text{Latitude} == 0.0$ and $\text{Longitude} == 0.0$, or $\text{Confidence} \le 0$).*
  * `HorizontalAccuracy` (`REAL`): Radius of uncertainty $R_{\text{horiz}}$ in meters.
  * `Altitude` & `VerticalAccuracy` (`REAL`): Elevation in meters.
  * `Speed` (`REAL` in meters/second — convert to $\text{km/h} = \text{Speed} \times 3.6$; negative values like `-1.0` mean speed was not measured) & `Course` (`REAL` heading in degrees $0\text{–}360$).
  * `BundleId` (in `AppHarvest`): The exact iOS application that requested this GPS fix!

#### Bucket 2: Radio Lookup & Crowd-Sourced Tile Tables (`WifiLocation`, `LteCellLocation`, `Nr5GCellLocation`, `CellLocation`, `CdmaCellLocation`)
* **How to Disambiguate Queried Anchors vs. Crowd-Sourced Tile Neighbors:**
  1. Group all rows in `WifiLocation` (or `LteCellLocation` / `Nr5GCellLocation`) by their exact integer second `ROUND(Timestamp)`.
  2. **Rule A (Cross-Match Against Known/Sighting Logs $\rightarrow$ Upgrade to `TIER_2` or `TIER_3`):**
     * Normalize `WifiLocation.MAC` to `xx:xx:xx:xx:xx:xx` (padding single-digit hex octets with a leading `'0'`).
     * If that normalized `BSSID` exists in `com.apple.wifi.known-networks.plist` (Connected Wi-Fi) or Biome `Connectivity.WiFi`, tag that specific row as **`TIER_2_CONNECTED_RADIO_HANDSHAKE`**!
  3. **Rule B (Crowd-Sourced Batch Tile Detection $\rightarrow$ Tag as `TIER_4`):**
     * When $N \ge 5$ rows in `WifiLocation` or `LteCellLocation` share the exact same `Timestamp` (within $\pm 2.0\text{ seconds}$):
       * Tag those individual rows as **`TIER_4_CROWDSOURCED_LOOKUP_TILE`** so they are never misreported as individual house visits.
       * Compute the **Centroid $(\bar{\phi}, \bar{\lambda})$** and **Bounding Radius ($R_{\text{tile}}$)** of the batch to show the broad $1\text{–}3\text{ km}$ area where the handset triggered the tile lookup!

### 3.2 Parsing `routined` Significant Locations (`Local.sqlite` & `Cloud.sqlite`)

* **Canonical Target Paths in `vfs_index`:**
  * `/private/var/mobile/Library/Caches/com.apple.routined/Local.sqlite` (+ `-wal`)
  * `/private/var/mobile/Library/Caches/com.apple.routined/Cloud.sqlite` (+ `-wal`) — *Note: `Cloud.sqlite` (and `Cloud-V2.sqlite`) stores end-to-end encrypted iCloud-synced Significant Locations across the user's Apple devices; always label whether a row came from `Local.sqlite` (this iPhone) vs. `Cloud.sqlite`!*

#### Step-by-Step 3-Table CoreData Join in `Local.sqlite`:
Process `Local.sqlite` through **Module 2.1 (Active + `-wal` + Freelist)** and execute the join:

$$\texttt{ZRTLEARNEDLOCATIONOFINTERESTVISITMO.ZLOCATIONOFINTEREST} = \texttt{ZRTLEARNEDLOCATIONOFINTERESTMO.Z\_PK}$$

1. **From `ZRTLEARNEDLOCATIONOFINTERESTVISITMO` (Every Physical Visit to a Learned Place):**
   * `ZENTRYDATE` (`REAL`, Cocoa seconds): **Exact arrival timestamp** at this location!
   * `ZEXITDATE` (`REAL`, Cocoa seconds): **Exact departure timestamp** from this location!
   * `ZLOCATIONLATITUDE` & `ZLOCATIONLONGITUDE` (`REAL`): Visit centroid coordinates.
   * `ZLOCATIONUNCERTAINTY` (`REAL`): Horizontal uncertainty radius in meters.
   * `ZCONFIDENCE` (`REAL`, $0.0\text{ to }1.0$): Algorithmic confidence (`1.0` = high certainty).
   * `ZDATAPOINTCOUNT` (`INTEGER`): Number of underlying GPS/Wi-Fi sensor fixes that proved the phone stayed at this location during `[ZENTRYDATE, ZEXITDATE]`.
2. **From `ZRTLEARNEDLOCATIONOFINTERESTMO` (The Learned Place Profile — Home, Work, Hideout):**
   * `ZLOCATIONLATITUDE`, `ZLOCATIONLONGITUDE`, `ZLOCATIONUNCERTAINTY`.
   * `ZTYPE` / `ZTYPESOURCE`: Semantic classification (`0` = Unknown/Frequent, `1` = **Home**, `2` = **Work**, `3` = **School**, `4` = **Gym**).
   * **`ZMAPITEM` / `ZPLACEMAPITEM` (`BLOB`):** Decode this binary plist / GEOMapItem protobuf to extract the **human-readable Street Address, Building/Business Name, Locality, City, and 6-digit PIN Code** resolved by Apple Maps!
3. **From `ZRTLEARNEDLOCATIONOFINTERESTTRANSITIONMO` (Trips Between Significant Locations):**
   * Links `ZVISITIDENTIFIERORIGIN` $\rightarrow$ `ZVISITIDENTIFIERDESTINATION` with `ZSTARTDATE`, `ZSTOPDATE`, and `ZMODE` (mode of transport: walking, driving, transit).
4. **From `ZRTHINTMO` (Granular Location Hints Table inside `Local.sqlite`):**
   * Contains thousands of high-frequency raw `(ZDATE, ZLATITUDE, ZLONGITUDE, ZHORIZONTALUNCERTAINTY)` sensor hints recorded whenever the user unlocked the phone, plugged in a charger, or connected to Wi-Fi/Bluetooth!

### 3.3 Apple `FindMy` & `searchpartyd` Offline Beacon, AirTag & Accessory Location Caches

Scan `/private/var/mobile/Library/Caches/com.apple.findmy.fmipcore/`, `/private/var/mobile/Library/Application Support/com.apple.searchpartyd/`, and `/private/var/db/searchparty/`:
* Decrypt plist/JSON files inside `searchpartyd` (`OwnedBeacons`, `BeaconNamingRecord`, `SafeLocations`, `WildModeAssociationRecord`) using the `BeaconStore` / `searchpartyd` key from **Module 2.2 (`case_cryptographic_keyring`)** if encrypted:
  * Extracts every **Apple AirTag**, AirPods case, or FindMy network accessory paired to the suspect's Apple ID, its custom name/emoji, serial number, and cached last-seen GPS coordinates.
  * Extracts **Unwanted Tracking Alerts (`UTAlert`)**: Proves if the victim's or suspect's iPhone detected an unknown AirTag or BLE tracker moving with them!

---

## 4. Step 2 — Sub-Engine 6.3B: Android On-Device Google Timeline (`GMS` Semantic Location), Google Maps & `Life360`

### 4.1 Android On-Device Google Timeline / Semantic Location (`com.google.android.gms`)

Following Google's 2024–2026 architecture update, **Google Maps Timeline (Location History)** is computed and stored **locally on the Android device** inside the Google Play Services (`com.google.android.gms`) sandbox:

1. **Locate All Location Databases & Stores Inside `/data/user/<id>/com.google.android.gms/` and `/data/user_de/<id>/com.google.android.gms/`:**
   * **On-Device Semantic Location / Timeline Databases (`/databases/` & `/files/`):**
     * Scan for SQLite databases and LevelDB/Protobuf stores matching `*semantic_location*`, `*timeline*`, `*odlh*` (**On-Device Location History!**), `*user_location*`, `*reporting*`, `*contextmanager*`, and `*places*`.
     * Unwrap any SQLCipher or Tink/Keystore-encrypted database or protobuf blob using keys harvested in **Phase 2, Module 2.2** from `com.google.android.gms/shared_prefs/` (`ulp_settings`, `semantic_location_prefs`, `odlh_keyset`) and Android Keystore (`persistent.sqlite`).
2. **Extract the 3 Core On-Device Google Timeline Structures:**
   * **Structure 1 — `PlaceVisit` (Semantic Place Visits):**
     * `place_id`: Google Maps unique 27-character `ChIJ...` Place ID! (e.g., `ChIJ...` uniquely identifies the exact hotel, ATM, cyber-cafe, or apartment building on Google Maps).
     * `latitude_e7` & `longitude_e7` (`int32`): Google stores coordinates in `E7` integer format ($\text{Degrees} \times 10^7$). Convert to decimal degrees using exact division:
       $$\text{Latitude} = \frac{\text{latitude\_e7}}{10,000,000.0}, \qquad \text{Longitude} = \frac{\text{longitude\_e7}}{10,000,000.0}$$
     * `arrival_timestamp_ms` & `departure_timestamp_ms` (13-digit Unix ms).
     * `place_confidence` / `visit_probability` & `semantic_type` (`TYPE_HOME`, `TYPE_WORK`, `TYPE_SEARCHED_ADDRESS`).
   * **Structure 2 — `ActivitySegment` / `TransitPath` (Movement Trajectories Between Visits):**
     * `start_location` $(\phi_1, \lambda_1)$ at `start_time_ms` $\rightarrow$ `end_location` $(\phi_2, \lambda_2)$ at `end_time_ms`.
     * `activity_type`: `IN_PASSENGER_VEHICLE`, `ON_MOTORCYCLE` (Two-wheeler mode heavily tracked in India!), `WALKING`, `RUNNING`, `IN_BUS`, `IN_TRAIN`, `FLYING`.
     * `distance_meters` & `waypoint_path` (array of intermediate GPS breadcrumbs along the road!).
   * **Structure 3 — Raw Fused Location & Activity Recognition Caches (`/files/` & `dumpsys location`):**
     * If an `adb bugreport` or live dump is present, parse the `FusedLocationProvider` and `LocationManagerService` ring buffers (`last location`, `historical locations`).

### 4.2 Google Maps (`com.google.android.apps.maps` on Android / `com.google.Maps` on iOS)

Stage all SQLite databases inside `/data/user/<id>/com.google.android.apps.maps/databases/` (via **Module 2.1 Active + `-wal` + Freelist**):
1. **`da_destination_history` (Turn-by-Turn Navigation Destination Ledger):**
   * Every row in `destination_history` proves that the suspect **actively started turn-by-turn driving/walking/two-wheeler navigation** in Google Maps!
   * Extract `time` (13-digit Unix ms), `dest_lat` & `dest_lng` (check `E6` $\div 10^6$ or decimal degrees), `dest_title` (business/building name), `dest_address` (full street address), `source_lat` & `source_lng` (where the suspect was standing when they pressed "Start Navigation"!), and `travel_mode`!
2. **`gmm_myplaces.db` & `gmm_storage.db` (`sync_item` / `search_history`):**
   * Unpack the binary Protocol Buffer blobs in `gmm_myplaces.db` and `gmm_storage.db` (via Module 2.3D) to extract Saved Places (`Starred`, `Want to go`, `Home`, `Work`), searched addresses, and recently viewed map pins (tagged as `TIER_4_MAP_SEARCH_OR_PIN`).

### 4.3 `Life360` (`com.life360.android.safetymapd` / `com.life360.ios.safetymap`) & Family Trackers

Stage all SQLite and log files in the `Life360` sandbox (`/databases/` & `/files/logs/` — `ALEAPP` / `iLEAPP` 2026 aligned):
* Extract high-frequency background GPS breadcrumb logs (`latitude`, `longitude`, `accuracy`, `speed`, `battery_level`, `is_driving`, `timestamp`), Circle member locations, and saved Geofence Places ("Home", "Office").

---

## 5. Step 3 — Sub-Engine 6.3C: Wi-Fi, Mobile Hotspot (`SoftAP`), Bluetooth & Indian Cellular (`MCC 404/405`) Triangulation Engine

### 5.1 Wi-Fi Connection Ledgers & Mobile Hotspot (`SoftAP`) Client Forensics

#### 1. Canonical 6-Octet Zero-Padded MAC Address Normalizer (`normalize_mac_6_octet`)
Given any MAC/BSSID string (e.g., `"0:1a:2b:3c:4:f0"` from iOS or `"00-1A-2B-3C-04-F0"`):
1. Split on `:` or `-` (or 2-char chunks if 12 contiguous hex chars).
2. If there are 6 valid hexadecimal tokens, left-pad each token with `'0'` to length $2$, convert to lowercase, and join with `:` to produce **`"00:1a:2b:3c:04:f0"`**.

#### 2. iOS Wi-Fi History (`com.apple.wifi.known-networks.plist` & `com.apple.wifi.plist`)
* Path: `/private/var/preferences/SystemConfiguration/com.apple.wifi.known-networks.plist` (and `/private/var/preferences/com.apple.wifi.known-networks.plist`).
* For each dictionary key `wifi.network.ssid.<SSID_Name>`:
  * Extract **`SSID_STR`** (Wi-Fi network name, e.g., `"Hotel_Taj_Guest"`, `"CrimeScene_Fiber_5G"`).
  * Extract **`BSSID`** (Normalized 6-octet hardware MAC address of the access point!) and iterate through the nested **`BSSList`** array (which lists *every individual access point `BSSID` MAC address* the iPhone connected to under that SSID, with per-BSSID **`LastJoined`** timestamps and **`Channel`** numbers!).
  * Extract **`AddedAt`** (when first joined), **`LastJoined`** (`UserPreferredTimestamp` / `SystemJoinedTimestamp`), **`CaptiveProfile`** (hotel/airport captive portal URL and login timestamp!), and **Static IP / DNS / Proxy** settings.

#### 3. Android Wi-Fi & Mobile Hotspot (`WifiConfigStore.xml` & `WifiConfigStoreSoftAp.xml`)
* Paths: `/data/misc/apexdata/com.android.wifi/WifiConfigStore.xml` and `WifiConfigStoreSoftAp.xml` (on Android 11–17) or `/data/misc/wifi/WifiConfigStore.xml`. (Deserialize via Sub-Engine 6.2B's `ABX\x00` reader if binary XML!).
* **From `WifiConfigStore.xml` (`<NetworkList>` $\rightarrow$ `<Network>`):**
  * Extract `SSID`, `PreSharedKey` (**the plaintext Wi-Fi password** saved on the Android phone!), `DefaultGwMacAddress` (**the router's hardware `BSSID` / Gateway MAC address!**), `CreationTime`, `LastConnectedTime`, ` randomizedMacAddress`, and `IpConfiguration`.
* **From `WifiConfigStoreSoftAp.xml`, `/data/misc/dhcp/dnsmasq.leases` & Unified/System Logs (Mobile Hotspot Forensics):**
  * Extract the suspect's own **Mobile Hotspot `SSID` name and `Passphrase`**!
  * Extract every client device (`client_mac_address`, `assigned_ip`, `client_hostname`—e.g., `"Galaxy-S24-Ultra"`, `"iPhone"`, `"Laptop-PC"`, and `lease_timestamp`) that connected into the suspect's phone hotspot!

### 5.2 Bluetooth Paired Devices vs. Passive BLE Sightings

1. **iOS Bluetooth Databases (`/private/var/containers/Shared/SystemGroup/<UUID>/Library/Database/`):**
   * **`com.apple.MobileBluetooth.ledevices.paired.db`:** Extract `Uuid`, `Name` (e.g., `"Hyundai Creta"`, `"AirPods"`, `"Mantra MFS110"`), `Address` (resolved public MAC), and `LastSeenTime` $\rightarrow$ Classify as **`ACTIVE_PAIRED_BLUETOOTH_DEVICE`**.
   * **`com.apple.MobileBluetooth.ledevices.other.db`:** Extract `Uuid`, `Name`, `Address`, `Rssi`, and `LastSeenTime` $\rightarrow$ Classify as **`PASSIVE_AMBIENT_BLE_SIGHTING`**.
2. **Android Bluetooth Config (`/data/misc/bluedroid/bt_config.conf` & `/data/misc/bluetooth/logs/`):**
   * Parse the INI-style sections `[<MAC_Address>]` in `bt_config.conf`:
     * Extract the 6-octet `MAC_Address`, `Name` (remote device name), `DevClass` (identifies Car Audio vs. Phone vs. Headset vs. Wearable), `LinkKey` (proves completed cryptographic pairing!), `Timestamp` (Unix seconds of last connection), and `Manufacturer`.

### 5.3 Indian Cellular Tower (`CGI` = `MCC-MNC-TAC/LAC-CID`) Decoder (`MCC 404` & `405`)

Whenever a cell tower record is extracted from iOS `cache_encryptedB.db` (`LteCellLocation`, `Nr5GCellLocation`, `CellLocation`), iOS Biome `Connectivity.Cellular`, Android `telephony` dumps, or app diagnostic logs, decode its **Cell Global Identity (`CGI`)**:

1. **Verify Country & Operator (`MCC` & `MNC`):**
   * India uses **two** Mobile Country Codes: **`MCC = 404`** and **`MCC = 405`** (e.g., `405-840` to `405-874` = **Reliance Jio** across the 22 Indian circles; `404-10`, `404-45`, `404-90`, etc. = **Bharti Airtel**; `404-11`, `404-20`, `404-86`, etc. = **Vodafone Idea \[Vi\]**; `404-34` to `404-81` = **BSNL**).
2. **4G LTE `ECI` (E-UTRAN Cell Identifier — 28-Bit Integer) Bit-Unpacking Math:**
   * In 4G LTE, the 28-bit `CellIdentity` (`CI` / `ECI`) packs both the physical **Base Station ID (`eNodeB ID` — upper $20\text{ bits}$)** and the directional **Antenna Sector ID (`Sector ID` — lower $8\text{ bits}$)**!
   * Unpack every 4G LTE `ECI` integer using bit-shifting:
     $$\text{eNodeB\_ID} = \text{ECI} \gg 8, \qquad \text{Sector\_ID} = \text{ECI} \ \& \ \text{0xFF}$$
   * **Why This Matters for Indian Police:** Telecom operator Tower Dump CDR spreadsheets list towers by `TAC` + `eNodeB_ID` + `Sector_ID` (or full `CGI`)! Automatically computing `eNodeB_ID` and `Sector_ID` lets the investigator immediately match on-device cellular records against carrier Tower Dump Excel sheets!
3. **5G NR `NCI` (NR Cell Identity — 36-Bit Integer) Bit-Unpacking Math:**
   * In 5G Standalone/Non-Standalone (`Jio True 5G` / `Airtel 5G Plus`), unpack the 36-bit `NCI` into the **`gNodeB ID`** (upper $22\text{ to }32\text{ bits}$, typically $\text{NCI} \gg 12$ or $\text{NCI} \gg 8$) and sector identifier.

---

## 6. Step 4 — Sub-Engine 6.3D: Haversine Velocity Validator & Multi-Device Co-Location Math

### 6.1 Exact Haversine Great-Circle Distance ($d_{\text{meters}}$) & Implied Speed ($v_{\text{km/h}}$)

Given two consecutive `TIER_1` or `TIER_2` location fixes $P_1 = (\phi_1, \lambda_1, t_1)$ and $P_2 = (\phi_2, \lambda_2, t_2)$ (where $\phi$ and $\lambda$ are latitude and longitude in degrees, converted to radians $\text{rad}(x) = x \times \frac{\pi}{180}$, and $R_{\text{earth}} = 6,371,000\text{ meters}$):

1. Compute the **Haversine Great-Circle Distance ($d_{\text{meters}}$)**:
   $$\Delta \phi = \text{rad}(\phi_2 - \phi_1), \qquad \Delta \lambda = \text{rad}(\lambda_2 - \lambda_1)$$
   $$a = \sin^2\left(\frac{\Delta \phi}{2}\right) + \cos\big(\text{rad}(\phi_1)\big) \cdot \cos\big(\text{rad}(\phi_2)\big) \cdot \sin^2\left(\frac{\Delta \lambda}{2}\right)$$
   $$d_{\text{meters}} = 2 \cdot R_{\text{earth}} \cdot \arcsin\left(\min\left(1.0, \sqrt{a}\right)\right)$$
2. Compute the **Minimum Required Travel Distance ($d_{\text{min\_edge}}$)** accounting for the horizontal accuracy circles $R_1$ and $R_2$ of both fixes:
   $$d_{\text{min\_edge}} = \max\left(0.0, \ d_{\text{meters}} - (R_1 + R_2)\right)$$
3. Compute the **Implied Minimum Ground Velocity ($v_{\text{km/h}}$)**:
   $$\Delta t_{\text{sec}} = |t_2 - t_1|$$
   $$v_{\text{km/h}} = \left(\frac{d_{\text{min\_edge}}}{\Delta t_{\text{sec}}}\right) \times 3.6$$
4. **Anomaly & Spoofing Flag Rule:**
   * If $\Delta t_{\text{sec}} > 5\text{ seconds}$, $d_{\text{min\_edge}} > 2,000\text{ meters}$, and $v_{\text{km/h}} > 1,000\text{ km/h}$ (faster than a commercial jetliner!):
     * Flag the transition as **`IMPOSSIBLE_VELOCITY_TELEPORTATION`** and pass it to **Module 6.5 (Mock GPS / VPN / Cell-ID Misattribution Auditor)**!

### 6.2 Crime-Scene Geofence & Two-Device Co-Location Overlap Equation

When an investigator enters a Crime Scene Coordinate $(\phi_{\text{scene}}, \lambda_{\text{scene}})$ with radius $R_{\text{scene}}$ (or loads a second seized phone from Co-Conspirator B):
* Two location fixes $P_A = (\phi_A, \lambda_A, R_A, t_A)$ and $P_B = (\phi_B, \lambda_B, R_B, t_B)$ **physically overlap in space and time** if and only if:
  $$d_{\text{meters}}(P_A, P_B) \le (R_A + R_B) \quad \text{AND} \quad |t_A - t_B| \le \Delta t_{\text{window}}$$
* Furthermore, if Phone A and Phone B **connected to or sighted the exact same Wi-Fi `BSSID` (`00:1a:2b:...`) or Bluetooth `MAC`** within $\Delta t_{\text{window}}$, flag a **`RADIO_BSSID_CO_LOCATION_MATCH`** (which proves physical co-location within $\approx 30\text{–}50\text{ meters}$ even indoors where GPS has zero satellite signal!).

---

## 7. Database Schema for Module 6.3 (`geolocation_and_triangulation_engine.sqlite`)

The developer must create the following four tables in the case database:

### Table 1: `unified_geolocation_fixes_ledger` (All 4-Tier Provenance-Classified Coordinates Across OS & Apps)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `geo_fix_uid` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Unique row ID. |
| `provenance_tier` | `TEXT` | `NOT NULL` | Mandatory 4-Tier Enum: `TIER_1_ACTIVE_DEVICE_FIX`, `TIER_2_CONNECTED_RADIO_HANDSHAKE`, `TIER_3_PASSIVE_RADIO_SIGHTING`, `TIER_4_CROWDSOURCED_LOOKUP_TILE_OR_SEARCH`. |
| `source_subsystem` | `TEXT` | `NOT NULL` | E.g., `IOS_LOCATION_HARVEST`, `IOS_ROUTINED_VISIT`, `IOS_ROUTINED_HINT`, `ANDROID_GMS_SEMANTIC_TIMELINE`, `GOOGLE_MAPS_NAVIGATION`, `LIFE360_BREADCRUMB`, `MEDIA_EXIF_GPS`, `UPI_QR_SCAN_GPS`, `IOS_WIFI_TILE_CACHE`. |
| `source_vfs_file_id` | `INTEGER` | `NOT NULL` | Source file in `vfs_index`. |
| `recovery_classification` | `TEXT` | `NOT NULL` | 6-State Enum (`ORIGINAL_RECORD`, `HISTORICAL_COMMITTED_RECORD`, `RESIDUAL_RECORD`). |
| `device_locality` | `TEXT` | `NOT NULL` | `LOCAL_SEIZED_HANDSET` vs. `CLOUD_SYNCED_ACCOUNT_HISTORY`. |
| `latitude_wgs84` | `REAL` | `NOT NULL` | Decimal latitude ($\phi$). |
| `longitude_wgs84` | `REAL` | `NOT NULL` | Decimal longitude ($\lambda$). |
| `horizontal_accuracy_meters` | `REAL` | `NULL` | Uncertainty radius $R_{\text{horiz}}$ in meters. |
| `spatial_precision_class` | `TEXT` | `NOT NULL` | Enum: `PINPOINT_GNSS_UNDER_25M`, `BUILDING_WIFI_25_TO_100M`, `NEIGHBORHOOD_CELL_100_TO_1000M`, `BROAD_SECTOR_OVER_1000M`, `UNSPECIFIED_RADIUS`. |
| `altitude_meters` | `REAL` | `NULL` | Elevation in meters (if recorded). |
| `speed_kmh` | `REAL` | `NULL` | Ground speed in $\text{km/h}$ ($\text{m/s} \times 3.6$). |
| `implied_velocity_from_prev_kmh` | `REAL` | `NULL` | Haversine edge-adjusted speed $v_{\text{km/h}}$ from preceding Tier-1 fix. |
| `is_impossible_velocity_flagged` | `INTEGER` | `DEFAULT 0` | `1` if $v_{\text{km/h}} > 1000\text{ km/h}$ (triggers Mock GPS audit in Module 6.5). |
| `resolved_address_or_place_name` | `TEXT` | `NULL` | Street address, Google `place_id`, or `routined` `ZMAPITEM` name. |
| `associated_bssid_or_cgi` | `TEXT` | `NULL` | Normalized Wi-Fi `BSSID` (`xx:xx:xx:xx:xx:xx`) or Cell `CGI` (`405-86-TAC-ECI`). |
| `fix_start_utc_ns` | `INTEGER` | `NOT NULL` | Normalized 64-bit UTC nanoseconds. |
| `fix_start_utc_iso` | `TEXT` | `NOT NULL` | Normalized UTC ISO-8601 start/observation timestamp. |
| `fix_end_utc_iso` | `TEXT` | `NULL` | Normalized UTC ISO-8601 departure timestamp (for dwell/visit intervals). |

### Table 2: `wifi_hotspot_and_bluetooth_connections_ledger` (Wi-Fi Networks, `SoftAP` Hotspot Clients & Bluetooth Pairings/Sightings)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `radio_conn_uid` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Unique row ID. |
| `radio_category` | `TEXT` | `NOT NULL` | Enum: `WIFI_KNOWN_CONNECTED_NETWORK`, `MOBILE_HOTSPOT_SOFTAP_CLIENT_LEASE`, `ACTIVE_PAIRED_BLUETOOTH_DEVICE`, `PASSIVE_AMBIENT_BLE_SIGHTING`. |
| `source_vfs_file_id` | `INTEGER` | `NOT NULL` | Source `.plist`, `WifiConfigStore.xml`, `bt_config.conf`, or `paired.db` in `vfs_index`. |
| `ssid_or_device_name` | `TEXT` | `NULL` | Wi-Fi `SSID`, connected Hotspot client hostname (`"Vikrams-iPhone"`), or Bluetooth device name (`"Hyundai Creta"`). |
| `normalized_bssid_or_mac` | `TEXT` | `NULL` | Canonical 6-octet zero-padded lowercase MAC (`00:1a:2b:3c:04:f0`). Indexed! |
| `saved_wifi_password_psk` | `TEXT` | `NULL` | Plaintext `PreSharedKey` from Android `WifiConfigStore.xml` or iOS Keychain! |
| `device_type_or_captive_url` | `TEXT` | `NULL` | Bluetooth device class (`Car Audio`, `Headset`, `Phone`) or Wi-Fi Captive Portal URL. |
| `first_added_utc_iso` | `TEXT` | `NULL` | Timestamp when network/device was first added or paired. |
| `last_connected_utc_iso` | `TEXT` | `NULL` | Timestamp of most recent connection or sighting (`LastJoined` / `LastConnectedTime`). |
| `recovery_classification` | `TEXT` | `NOT NULL` | 6-State Enum (`ORIGINAL_RECORD`, `HISTORICAL_COMMITTED_RECORD`, `RESIDUAL_RECORD`). |

### Table 3: `cellular_tower_cgi_observations` (Decoded Indian `MCC 404/405` 4G LTE `eNodeB` & 5G NR `gNodeB` Records)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `cell_obs_uid` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Unique row ID. |
| `provenance_tier` | `TEXT` | `NOT NULL` | `TIER_2_SERVING_CELL` vs. `TIER_4_CROWDSOURCED_TILE_NEIGHBOR`. |
| `rat_generation` | `TEXT` | `NOT NULL` | Enum: `5G_NR`, `4G_LTE`, `3G_UMTS`, `2G_GSM`. |
| `mcc_mnc` | `TEXT` | `NOT NULL` | E.g., `"405-86"` (Reliance Jio), `"404-10"` (Airtel). |
| `lac_or_tac` | `INTEGER` | `NOT NULL` | Location Area Code (`LAC`) or Tracking Area Code (`TAC`). |
| `raw_ci_eci_or_nci` | `INTEGER` | `NOT NULL` | Full 28-bit LTE `ECI` or 36-bit 5G `NCI`. |
| `unpacked_enodeb_or_gnodeb_id` | `INTEGER` | `NULL` | **Base Station ID ($\text{ECI} \gg 8$ for 4G LTE) for direct CDR Tower Dump matching!** |
| `unpacked_sector_id` | `INTEGER` | `NULL` | **Antenna Sector ID ($\text{ECI} \ \& \ \text{0xFF}$ for 4G LTE)!** |
| `tower_lat_wgs84` | `REAL` | `NULL` | Estimated tower/sector latitude (if in cache). |
| `tower_lon_wgs84` | `REAL` | `NULL` | Estimated tower/sector longitude. |
| `observed_utc_iso` | `TEXT` | `NOT NULL` | Normalized UTC ISO-8601 timestamp. |

### Table 4: `significant_places_and_navigation_trips` (Semantic `Home`/`Work` Clusters, `PlaceVisits` & Turn-by-Turn Routes)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `place_trip_uid` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Unique row ID. |
| `record_type` | `TEXT` | `NOT NULL` | Enum: `ROUTINED_SIGNIFICANT_VISIT`, `GOOGLE_TIMELINE_PLACE_VISIT`, `GOOGLE_TIMELINE_TRANSIT_SEGMENT`, `MAPS_TURN_BY_TURN_NAVIGATION`. |
| `semantic_label` | `TEXT` | `NULL` | `HOME`, `WORK`, `FREQUENT_HIDEOUT`, `SEARCHED_DESTINATION`, `MOTORCYCLE_TRIP`, `VEHICLE_TRIP`. |
| `place_title_and_address` | `TEXT` | `NULL` | Unpacked `ZMAPITEM` address, Google `place_id`, or `da_destination_history` address. |
| `origin_lat_lon_json` | `TEXT` | `NULL` | Starting `(lat, lon)` for trips/navigation. |
| `destination_lat_lon_json` | `TEXT` | `NOT NULL` | Visit or destination `(lat, lon, uncertainty_m)`. |
| `data_point_count_or_confidence` | `TEXT` | `NULL` | E.g., `"48 sensor points (Confidence: 1.00)"`. |
| `arrival_or_start_utc_iso` | `TEXT` | `NOT NULL` | Arrival or trip start timestamp. |
| `departure_or_end_utc_iso` | `TEXT` | `NULL` | Departure or trip end timestamp. |
| `dwell_duration_minutes` | `REAL` | `NULL` | Total minutes spent at the location. |

---

## 8. Developer Acceptance Test Checklist for Module 6.3

1. **The `cache_encryptedB.db` Crowd-Sourced Batch Tile vs. Connected Wi-Fi Disambiguation Test:**
   * Insert 50 rows into `WifiLocation` inside `cache_encryptedB.db` sharing the exact timestamp `784041600.0`, where Row 1 has `MAC = "0:1a:2b:3c:4:f0"` and Rows 2–50 are neighboring routers. Place `"00:1a:2b:3c:04:f0"` inside `com.apple.wifi.known-networks.plist` with `LastJoined = 2026-11-05T13:20:00Z`.
   * Verify that Sub-Engine 6.3A/C normalizes `"0:1a:2b:3c:4:f0"` $\rightarrow$ `"00:1a:2b:3c:04:f0"`, upgrades Row 1 to `TIER_2_CONNECTED_RADIO_HANDSHAKE`, and classifies Rows 2–50 as `TIER_4_CROWDSOURCED_LOOKUP_TILE` (preventing 49 false house visits!).
2. **The Google Timeline `E7` Coordinate & `da_destination_history` Test:**
   * Feed an On-Device Google Timeline `PlaceVisit` record with `latitude_e7 = 253176452`, `longitude_e7 = 829739140` and a `da_destination_history` navigation row. Verify that Sub-Engine 6.3B divides by $10^7$ to output `(25.3176452, 82.9739140)`.
3. **The Indian 4G LTE 28-Bit `ECI` (`eNodeB` + `Sector`) Bit-Unpacking Test:**
   * Pass a Reliance Jio 4G cell record (`MCC = 405`, `MNC = 86`, `TAC = 1042`, `ECI = 268435714` \[`0x10000102`\]) into Section 5.3's Cellular Decoder. Verify that it unpacks `unpacked_enodeb_or_gnodeb_id = 1048577` (`268435714 >> 8`) and `unpacked_sector_id = 2` (`268435714 & 0xFF`).
4. **The Haversine Impossible-Velocity Teleportation Test:**
   * Insert two `TIER_1` GPS fixes separated by $\Delta t = 10\text{ seconds}$: Fix 1 in Varanasi `(25.3176, 82.9739, R=10m)` and Fix 2 in Mumbai `(19.0760, 72.8777, R=10m)`. Verify that Sub-Engine 6.3D computes $d_{\text{meters}} \approx 1,252,000\text{ m}$, $v_{\text{km/h}} > 450,000\text{ km/h}$, and sets `is_impossible_velocity_flagged = 1`.
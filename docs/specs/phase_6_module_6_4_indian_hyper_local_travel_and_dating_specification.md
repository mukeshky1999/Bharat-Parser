# Engineering Specification: Phase 6, Module 6.4 — Indian Hyper-Local Delivery, Quick-Commerce, Ride-Hailing, Inter-City Travel & Dating/Matrimonial App Forensics

**Document Purpose:** This document provides the complete, step-by-step architectural blueprint for building **Module 6.4** of the Forensic Data Parser (corresponding to **Groups 1, 2, 5, 7, 13, and 15** of the Unified Master Register). It contains **zero programming code** and explains how to extract, decode, and cross-link physical hideout addresses (down to the exact apartment tower, floor, flat number, and gate passcode), intra-city parcel drops, ride-hailing trajectories (including bitwise Google Encoded Polyline unpacking), railway/airport travel ledgers (`IRCTC`, `Where is My Train`, `DigiYatra`), and Indian/global dating and matrimonial platforms (`Tinder`, `Bumble`, `Hinge`, `Grindr`, `Happn`, `Aisle`, `TrulyMadly`, `QuackQuack`, `Shaadi.com`, `BharatMatrimony`, `Jeevansathi`) from first principles.

---

## 1. Purpose & Mental Model (Why Hyper-Local, Mobility & Dating Apps Solve Cases Where OS GPS Fails)

In Indian law enforcement, fugitive tracking, cyber-fraud call-center raids, narcotics distribution, honeytrap extortion, and homicide investigations, operating-system GPS logs (Module 6.3) have a fundamental physical limitation: **satellite GPS is two-dimensional and degrades indoors**.

When a suspect is operating an illegal call center, mule-account hub, or safe house inside a 25-story high-rise apartment complex in Noida, Gurugram, Mumbai, Bengaluru, or Hyderabad, an OS GPS coordinate `(28.6014, 77.4321, Accuracy = 35m)` only tells police which building complex the phone is in—it cannot tell police **which of the 800 flats across 25 floors** the suspect is hiding inside.

**Module 6.4** bridges the gap between raw satellite coordinates and human-level physical & social attribution across four high-density Indian application ecosystems:

1. **Hyper-Local Food, Quick-Commerce & E-Commerce Delivery Apps (`Zomato`, `Swiggy`, `Blinkit`, `Zepto`, `BigBasket`, `Flipkart`, `Amazon India`, `Porter`, `Borzo`):**
   * Even the most opsec-conscious fugitive orders late-night food on `Zomato`/`Swiggy` or 10-minute groceries/SIM-card accessories on `Blinkit`/`Zepto`.
   * Because a delivery rider must physically reach the door, the suspect types their **exact Flat Number, Floor, Tower Name, Society Name, Landmark, Gate Passcode, Delivery Instructions (`"Don't ring bell, call on alternate number 9811xxxxxx"`), and precise pinned `(latitude, longitude)`** into the app's address book!
2. **Ride-Hailing, Auto/Bike-Taxi & Intra-City Parcel Couriers (`Uber`, `Ola`, `Rapido`, `Namma Yatri`, `InDrive`, `Swiggy Genie`, `Porter`):**
   * Reconstructs exact point-to-point urban movement, vehicle registration plates (`KA-01-...`, `DL-1R-...`) for highway/street ANPR CCTV correlation, and **unattended P2P parcel drops** (where syndicate handlers use `Rapido Parcel`, `Swiggy Genie`, `Porter`, or `Borzo` bike riders to courier cash, mule ATM welcome kits, SIM cards, or narcotics across town without traveling themselves!).
3. **Indian Railways, Aviation & Highway Travel (`IRCTC Rail Connect`, `Where is My Train`, `UTS`, `DigiYatra`, `MakeMyTrip`, `RedBus`):**
   * Reconstructs inter-city escape routes, co-traveler passenger manifests (with Aadhaar/ID numbers), offline cell-tower train tracking (`Where is My Train`), and biometric airport boarding passes (`DigiYatra` W3C Verifiable Credentials).
4. **Dating, Hookup & Matrimonial Platforms (`Tinder`, `Bumble`, `Hinge`, `Grindr`, `Happn`, `Aisle`, `TrulyMadly`, `QuackQuack`, `Shaadi.com`, `BharatMatrimony`, `Jeevansathi`):**
   * In India, dating and matrimonial apps are the primary initiation vectors for **"Pig-Butchering" (`SHA-ZHU-PAN`) USDT crypto-investment scams**, **video-call "sextortion" blackmail**, **NRI/fake-IAS matrimonial financial fraud**, and **in-person robbery, drugging, kidnapping, and homicide**.

---

## 2. The 6 Fatal Mistakes Beginner Developers Make in Hyper-Local, Mobility & Dating Forensics

Before implementing Module 6.4, the developer must understand six critical traps that cause existing forensic tools to miss decisive evidence:

### Mistake 1: Extracting Only the "Current Default Address" and Missing the Full Saved Address Book & Alternate Receiver Phones
* **The Trap:** Reading only `current_lat` and `current_lng` from `shared_prefs` in `Zomato`, `Swiggy`, `Blinkit`, or `Flipkart`.
* **Why It Fails:** A suspect's saved address array (`saved_addresses` / `address_list` in SQLite, `MMKV`, and `app_webview` JSON cache) typically holds **5 to 20 historical addresses** spanning multiple cities: their own hideout flat, their parents' home in their native village, their girlfriend's or accomplice's apartment, and hotels they stayed at! Even better, each saved address entry has a dedicated **`receiver_name` and `receiver_phone` (`contact_number`)** field—which frequently unmasks a secret secondary burner number or the phone number of the co-conspirator living at that address!
* **The Rule:** Extract every active, `-wal` historical, and freelist-carved saved address across all delivery and ride apps into `hyperlocal_saved_addresses_and_hideouts` (Section 3.2).

### Mistake 2: Ignoring Intra-City Parcel Courier Logs (`Swiggy Genie`, `Porter`, `Rapido Parcel`, `Uber Connect`, `Borzo`)
* **The Trap:** Treating `Swiggy` only as a food app and `Rapido`/`Uber` only as passenger ride apps.
* **Why It Fails:** Modern cybercrime and narcotics syndicates rarely hand-deliver physical mule kits (bank passbook + debit card + active SIM card) or cash in person. Instead, Handler A books a **`Swiggy Genie`**, **`Porter` 2-wheeler**, **`Rapido Parcel`**, or **`Borzo` (WeFast)** courier to pick up a package at Location A (`Sender Name + Sender Phone + Flat/Landmark`) and deliver it to Operative B at Location B (`Receiver Name + Receiver Phone + Flat/Landmark`).
* **The Rule:** Explicitly parse P2P courier/genie order objects to capture both the **Sender** and **Receiver** phone numbers, names, and exact GPS pins (Section 3.3).

### Mistake 3: Failing to Parse `Where is My Train` (`com.whereismytrain.android`) Offline Cell-Tower Train Tracking Logs
* **The Trap:** Assuming a suspect's train journey can only be proven if an `IRCTC` reserved ticket PNR or bank SMS exists on the phone.
* **Why It Fails:** Fugitives fleeing after a crime deliberately avoid booking online `IRCTC` tickets (which require a passenger name and payment trail) and instead board unreserved coaches or buy paper tickets in cash. However, over $100\text{ million}$ Indian travelers use Google's **`Where is My Train` (`com.whereismytrain.android`)** to check which platform their train is arriving on and track the train's live progress! When the suspect toggles **"Inside Train? (Cell Tower Mode)"** inside the app, `Where is My Train` logs the **exact 5-digit Train Number, boarding station code, destination station code, and cell-tower corridor timestamps** locally in SQLite and `shared_prefs`!
* **The Rule:** Sub-Engine 6.4C must include a dedicated parser for `Where is My Train` and `UTS` alongside `IRCTC` (Section 5.2).

### Mistake 4: Losing "Unmatched" or Blocked Perpetrator Profiles in Dating Apps (`Tinder`, `Bumble`, `Hinge`, `Aisle`, `Grindr`)
* **The Trap:** Querying only the active `matches` table in a dating app database after the perpetrator clicked **"Unmatch"** or **"Block"**.
* **Why It Fails:** In almost every dating-app assault, honeytrap extortion, or crypto scam, the perpetrator unmatches the victim on `Tinder`, `Bumble`, `Hinge`, or `Aisle` immediately after moving the conversation to WhatsApp/Telegram (or immediately after leaving the crime scene), causing the server to send a `DELETE` command to the victim's app. However, on the seized phone (of either the victim or the suspect):
  1. The deleted match and chat rows survive inside **`tinder-3.db-wal` / `Bumble.db-wal` and SQLite B-Tree `0x0D` Freeblocks** (recovered via Phase 2, Module 2.1)!
  2. The perpetrator's high-resolution **profile photos (`JPEG`/`WebP`)** survive inside `/cache/image_manager_disk_cache/` (Glide/Fresco/Kingfisher/SDWebImage) and `app_webview` / `NSURLCache` (`Cache.db` + `fsCachedData/`)!
  3. Push notification banners (`"New match!"` or `"Vikram sent you a message"`) survive inside **Android `notification_history` / iOS `DuetExpertCenter` & Biome** (Module 3.4 / Module 6.1)!
* **The Rule:** Combine SQLite `-wal`/freelist carving, disk image cache carving, and OS notification correlation on every dating app sandbox (Section 6).

### Mistake 5: Confusing a Dating App's Spoofed `Passport` / `Travel Mode` City with Physical Presence
* **The Trap:** Seeing `city = "London"` or `latitude = 51.5072, longitude = -0.1276` in a suspect's `Tinder` or `Bumble` profile JSON and reporting that the suspect was physically in London.
* **Why It Fails:** Paid tiers of `Tinder` (*Tinder Passport*), `Bumble` (*Travel Mode*), and `Hinge` allow a user to manually drop their dating pin anywhere in the world without leaving their room in India! Inside the app's local JSON/SQLite state, the app stores **two separate location objects**:
  * `pos` / `current_location`: The phone's real hardware GPS coordinates (or last real location).
  * `pos_info` / `travel_location` / `is_traveling = true`: The virtual `Passport` / `Travel Mode` coordinates!
* **The Rule:** Always extract and clearly distinguish `actual_device_gps_lat_lon` from `virtual_passport_spoofed_lat_lon` (`is_travel_mode_active = 1`).

### Mistake 6: Ignoring Indian Matrimonial Apps (`Shaadi.com`, `BharatMatrimony`, `Jeevansathi`) & `TrulyMadly` KYC Trust Scores
* **The Trap:** Focusing only on Western dating apps (`Tinder`/`Bumble`) and ignoring Indian matrimonial and trust-scored dating apps.
* **Why It Fails:**
  * Apps like **`TrulyMadly`** cache a **`Trust Score`** JSON detailing the verified mobile number, Facebook/LinkedIn account, and uploaded Government ID (`Aadhaar` / `PAN` / `DL`) used by the suspect!
  * Apps like **`Shaadi.com`**, **`BharatMatrimony`**, and **`Jeevansathi`** store the suspect's or victim's `Matrimony ID`, astrological birth details (`Date, Exact Time, and City of Birth` for `Kundli` matching), unlocked phone number quota logs, and in-app chat threads.

---

## 3. Step 1 — Sub-Engine 6.4A: Indian Hyper-Local Food, Quick-Commerce, E-Commerce & Parcel Courier Decoders

### 3.1 Master Target List of Indian Hyper-Local, E-Commerce & Courier Apps

Query **Module 1.3 (`resolve_app_targets`)** across all user profiles (`0`, `10`, `95`, `150`, `999`) for the following package and bundle identifiers:

| Sub-Sector | Application Name | Android Package Name(s) | iOS Bundle ID(s) | Primary Sandbox Storage Engines |
|---|---|---|---|---|
| **Food Delivery** | **Zomato** & **Zomato Delivery Partner** | `com.application.zomato`, `com.zomato.delivery` | `com.zomato.zomato` | SQLite/Room (`/databases/*.db`), `MMKV`, `shared_prefs`, `app_webview` (`*_0`). |
| **Food + Quick-Commerce + Courier** | **Swiggy** (`Food`, `Instamart`, `Dineout`, **`Swiggy Genie`**) | `in.swiggy.android`, `in.swiggy.deliveryapp` | `com.swiggy.swiggy` | SQLite/Room (`/databases/`), `MMKV`, `shared_prefs`, `app_webview` / `Cache.db`. |
| **10-Minute Quick-Commerce** | **Blinkit** (formerly Grofers), **Zepto**, **BigBasket (`bbnow`)**, **JioMart**, **Flipkart Minutes** | `com.grofers.customerapp`, `com.zeptoconsumerapp`, `com.bigbasket.mobileapp`, `com.jpl.jiomart` | `com.grofers.customerapp`, `com.zeptoconsumerapp`, `com.bigbasket.mobileapp` | SQLite/Room, `MMKV`, React Native `RKStorage`, `shared_prefs`, `app_webview`. |
| **E-Commerce & Quick Fashion** | **Flipkart**, **Amazon India**, **Meesho**, **Myntra**, **Ajio**, **Nykaa**, **Tata CLiQ** | `com.flipkart.android`, `in.amazon.mShop.android.shopping`, `com.meesho.supply`, `com.myntra.android`, `com.ril.ajio`, `com.fsn.nykaa` | Corresponding iOS bundles | SQLite, `MMKV`, `shared_prefs`, and extensive `app_webview` (`Simple Cache *_0` & `Local Storage`). |
| **Intra-City P2P Parcel & Logistics** | **Porter**, **Borzo (WeFast)**, **Dunzo**, **Delhivery Direct**, **Shadowfax**, **Shiprocket** | `com.theporter.android.customerapp`, `in.wefast.client`, `com.dunzo.user`, `com.delhivery.consigneeapp` | Corresponding iOS bundles | SQLite/Room, `MMKV`, `shared_prefs`, and `app_webview` JSON caches. |

### 3.2 Pillar 1: Extracting the Saved Address Book & Exact Flat/Door Hideout Directory
Across `Zomato`, `Swiggy`, `Blinkit`, `Zepto`, `BigBasket`, `Flipkart`, `Amazon India`, and `Porter`, scan all SQLite tables (`addresses`, `user_addresses`, `saved_address`, `delivery_address`), `MMKV` keys (`user_saved_addresses`, `selected_address`, `location_store`), `shared_prefs/*.xml`, and decompressed `app_webview` / `Cache.db` JSON responses (`*/addresses*`, `*/user/profile*`, `*/cart*`):

For every active, `-wal` historical, and freelist/slack-carved address object, extract:
1. **`address_native_id` & `address_label_tag`:** E.g., `"HOME"`, `"WORK"`, `"OTHER"`, `"HOTEL"`, `"FRIENDS_PLACE"`, `"GIRLFRIEND"`.
2. **`flat_house_floor_building_no`:** **The exact micro-location string** (e.g., `"Flat No. 1404, 14th Floor, Tower B-2, Supertech Eco Village 1"`).
3. **`street_society_and_landmark`:** Full street address and user-typed landmark (e.g., `"Near Gate No. 3, Opposite HDFC Bank ATM, Sector 1, Greater Noida West"`).
4. **`city_state_and_pincode`:** City name and **6-digit Indian PIN Code** (e.g., `"201306"`).
5. **`pinned_latitude_wgs84` & `pinned_longitude_wgs84`:** The exact map pin coordinate placed by the user so the delivery rider's GPS reaches the building entrance! *(Automatically feed this coordinate into **Module 6.3's `unified_geolocation_fixes_ledger`** as a `TIER_1` / `TIER_2` verified address anchor!).*
6. **`voice_or_text_delivery_instructions`:** E.g., `"Gate security code 8821, do not ring doorbell after 11 PM"` (Note: `Swiggy` and `Zomato` also allow users to record **audio voice-note directions** for riders—extract any cached audio direction URL or local `.mp3`/`.aac`/`.m4a` file!).
7. **`recipient_name` & `recipient_contact_phone`:**
   * **Crucial Attribution Check:** Compare `recipient_contact_phone` against the device owner's primary SIM MSISDN (from Module 3.2).
   * If `recipient_contact_phone` is **different** from the phone's primary SIM number, flag `is_alternate_or_third_party_phone = 1`! This either unmasks the suspect's **secret secondary burner number** OR identifies the **exact co-conspirator / family member** for whom the suspect ordered food, groceries, or electronics at that address!

### 3.3 Pillar 2: Extracting Order Ledgers, High-Value E-Commerce IMEIs & P2P Parcel Drops (`Genie` / `Porter` / `Borzo`)
1. **Food, Quick-Commerce & E-Commerce Orders (`Zomato`, `Swiggy`, `Blinkit`, `Zepto`, `Flipkart`, `Amazon`):**
   * Extract `order_id`, `order_placed_utc_iso`, `order_delivered_utc_iso`, `merchant_or_darkstore_name` (and darkstore coordinates), `delivery_address_full`, `items_summary_json` (product names, quantities, and—for mobile phones/laptops ordered on `Flipkart` or `Amazon`—the **15-digit `IMEI` or Serial Number printed on the cached JSON/PDF tax invoice**!), `total_amount_inr`, `payment_mode` (`UPI`, `CARD`, `COD_CASH`, `WALLET`), **`payment_utr_or_vpa`** (cross-link to Phase 3!), and `delivery_partner_name_and_phone`.
2. **Intra-City P2P Parcel Courier Drops (`Swiggy Genie`, `Porter`, `Borzo / WeFast`, `Dunzo`):**
   * Whenever an order has type `GENIE` / `PARCEL` / `P2P_COURIER` / `PORTER_TWO_WHEELER`:
     * Extract **Both Endpoints** of the courier drop:
       * **Pickup Endpoint:** `pickup_flat_and_address`, `pickup_lat_lon`, **`pickup_sender_name`**, **`pickup_sender_phone`**, `pickup_completed_utc`.
       * **Drop-off Endpoint:** `dropoff_flat_and_address`, `dropoff_lat_lon`, **`dropoff_receiver_name`**, **`dropoff_receiver_phone`**, `dropoff_completed_utc`.
       * **Driver & Vehicle Telemetry:** `driver_name`, `driver_phone`, **`driver_vehicle_plate_no`**, `declared_item_category`, and `delivery_otp_code`.

---

## 4. Step 2 — Sub-Engine 6.4B: Indian Ride-Hailing, Auto/Bike-Taxi & ONDC Mobility Decoders (`Uber`, `Ola`, `Rapido`, `Namma Yatri`, `InDrive`)

### 4.1 Master Target List of Ride-Hailing & Mobility Apps in India

| Application Name | Android Package Name(s) | iOS Bundle ID(s) | Specific Forensic Storage Locations & Nuances |
|---|---|---|---|
| **Uber** & **Uber Driver** | `com.ubercab`, `com.ubercab.driver` | `com.ubercab.UberClient`, `com.ubercab.UberPartner` | SQLite (`/databases/rider_trip_details*.db`, `carbon*.db`), `MMKV`, `shared_prefs`, and `app_webview` / `Cache.db` (`getTrip`, `pastTrips` JSON). |
| **Ola Cabs** & **Ola Driver** | `com.olacabs.customer`, `com.olacabs.oladriver` | `in.olacabs.OlaCabs` | SQLite (`/databases/ola*.db`, `bookings*.db`), `MMKV`, `shared_prefs/ola_prefs.xml`, and `app_webview` JSON cache. |
| **Rapido** (Bike-Taxi, Auto, Cab & Parcel) | `com.rapido.passenger`, `com.rapido.rider` | `com.rapido.passenger` | **Huge in Tier-1/2/3 India:** Suspects use Rapido Bike-Taxis to weave through traffic and `Rapido Local/Parcel` to send packages. Parse Room SQLite (`/databases/`), `MMKV`, and `shared_prefs`. |
| **Namma Yatri / Yatri Sathi / Mana Yatri** (`ONDC`) | `in.juspay.nammayatri`, `in.juspay.yatrisathi` | `in.juspay.nammayatri` | Built on the open **Beckn / ONDC** protocol (Bengaluru, Kolkata, Hyderabad, Delhi, Chennai). Direct driver-to-rider UPI/cash payment (`Zero Commission`). Parse SQLite, `MMKV`, and Juspay WebView caches. |
| **InDrive** & **BluSmart** | `sinet.startup.inDriver`, `com.blusmart.consumer` | `XC.sinet.startup.inDriver`, `com.blusmart.consumer` | **InDrive** is heavily favored by suspects because fares are negotiated peer-to-peer and paid in **Cash / Direct UPI to driver**. Parse SQLite (`/databases/`) and `shared_prefs`. |

### 4.2 Step-by-Step Ride & Route Extraction + The Bitwise Google Encoded Polyline Unpacker

1. **Extract Core Trip Attributes (Across `Uber`, `Ola`, `Rapido`, `Namma Yatri`, `InDrive`):**
   * `trip_uuid` / `booking_id` / `crn_number` (Ola `CRN...`).
   * `vehicle_category`: `BIKE_TAXI_2W`, `AUTO_RICKSHAW_3W`, `CAB_4W`, `PARCEL_DELIVERY`, `RENTAL_OUTSTATION`.
   * `trip_status`: `COMPLETED`, `CANCELLED_BY_RIDER`, `CANCELLED_BY_DRIVER`. *(Forensic Gold: Even a **`CANCELLED_BY_RIDER`** booking proves the exact timestamp and GPS `pickup_lat_lon` where the suspect stood while trying to hail a ride!)*
   * `pickup_address_text`, `pickup_lat`, `pickup_lon`, `request_time_utc`, `pickup_start_time_utc`.
   * `dropoff_address_text`, `dropoff_lat`, `dropoff_lon`, `dropoff_end_time_utc`.
   * **Driver & Vehicle Identification (For Police CCTV / ANPR Verification):**
     * `driver_full_name` & `driver_phone_number`.
     * **`vehicle_registration_number`**: Exact Indian RTO license plate (e.g., `"DL-1R-TC-4821"`, `"MH-02-F-9182"`, `"UP-32-HN-1029"`).
     * `vehicle_make_model_color` (e.g., `"White Maruti WagonR"`, `"Black Bajaj Pulsar"`).
   * **Third-Party Guest Rider Attribution (`"Book for Someone Else"`):**
     * Check `guest_rider` / `rider_info`: If the suspect booked the Uber/Ola/Rapido on their phone for an accomplice (`guest_name`, `guest_phone_number`), explicitly flag `is_booked_for_third_party_guest = 1` and cross-link `guest_phone_number` to Phase 5 Unified Actors!

2. **Exact Bitwise Algorithm to Unpack `route_polyline` (`Google Encoded Polyline` Format):**
   `Uber`, `Ola`, `Rapido`, `Swiggy`, and `Zomato` store the actual road path taken by the vehicle as a compact ASCII string called a **Google Encoded Polyline** (e.g., `"_p~iF~ps|U_ulLnnqC_mqNvxq`@"`). To decode any polyline string `poly_str` into an array of `(latitude, longitude)` road waypoints:
   * Initialize `index = 0`, `current_lat = 0`, `current_lon = 0`, and `waypoints = []`.
   * **While `index < len(poly_str)`:**
     1. **Decode the Latitude Delta ($\Delta \text{lat}$):**
        * Initialize `shift = 0`, `result = 0`.
        * Loop:
          * Read ASCII character `c = poly_str[index]`, increment `index += 1`.
          * Subtract $63$ from its ASCII byte value: $b = \text{ord}(c) - 63$.
          * Extract the lower $5\text{ bits}$ of $b$, shift left by `shift`, and bitwise-OR into `result`:
            $$\text{result} = \text{result} \mid \left((b \ \& \ \text{0x1F}) \ll \text{shift}\right)$$
          * Increment `shift += 5`.
          * If the $6\text{-th}$ continuation bit of $b$ is $0$ (`(b & 0x20) == 0`), break the inner loop!
        * Apply ZigZag sign decoding to `result`:
          $$\Delta \text{lat} = \begin{cases} \sim(\text{result} \gg 1) & \text{if } (\text{result} \ \& \ 1) \neq 0 \\ (\text{result} \gg 1) & \text{if } (\text{result} \ \& \ 1) == 0 \end{cases}$$
        * Add `current_lat = current_lat + delta_lat`.
     2. **Decode the Longitude Delta ($\Delta \text{lon}$):**
        * Repeat the exact same inner loop and ZigZag formula to obtain $\Delta \text{lon}$, and add `current_lon = current_lon + delta_lon`.
     3. **Convert to Decimal Degrees:**
        * Divide by $10^5$ ($100,000.0$ for standard `Polyline5`, or $10^6$ for `Polyline6` if coordinates exceed $\pm 180$ when divided by $10^5$):
          $$\phi = \frac{\text{current\_lat}}{100,000.0}, \qquad \lambda = \frac{\text{current\_lon}}{100,000.0}$$
        * Append $(\phi, \lambda)$ to `waypoints`!

---

## 5. Step 3 — Sub-Engine 6.4C: Indian Railways (`IRCTC`, `Where is My Train`, `UTS`), Aviation (`DigiYatra`) & Inter-City Travel Decoders

### 5.1 `IRCTC Rail Connect` (`cris.org.in.prs.ima`) & `UTS` (`com.cris.utsmobile`)
1. **In `IRCTC Rail Connect` (`/data/user/<id>/cris.org.in.prs.ima/`):**
   * Parse `shared_prefs/*.xml`, SQLite databases (`/databases/`), and `app_webview` caches:
     * **Account Profile:** `irctc_user_id`, registered mobile, email, and linked Aadhaar/PAN KYC state.
     * **Saved "Master Passenger List" (`passenger_master`):** Stores the full name, age, gender, berth preference, senior citizen status, and **Government ID Card Number (`Aadhaar` / `Voter ID` / `PAN` / `Passport`)** of every person the suspect regularly books train tickets for!
     * **Booked & Cancelled PNR History (`ticket_history`, `ers_tickets`):** Extracts **10-digit `PNR` Number**, **5-digit Train Number & Name**, `from_station_code` (e.g., `BSB` = Varanasi Jn) $\rightarrow$ `to_station_code` (e.g., `LTT` = Lokmanya Tilak Terminus Mumbai), `journey_date`, `booking_timestamp`, **Coach & Berth Assignment (`S4 / 32 MB`, `A1 / 12 LB`)**, passenger names + ages, `ticket_fare_inr`, and payment `UTR`.
   * Also cross-check `/Download/` and WhatsApp media for downloaded `IRCTC` Electronic Reservation Slip (`ERS`) PDFs and SMS messages from DLT header `*-IRCTCi-T` / `*-IRCTCR-S`!
2. **In `UTS` (`com.cris.utsmobile` — Unreserved Local & General Train Tickets):**
   * Parse `/databases/*.db` and `shared_prefs/` for unreserved general tickets, suburban local train tickets (Mumbai/Chennai/Kolkata/Secunderabad), and platform tickets (`uts_number`, `source_station_code`, `destination_station_code`, `adult_child_count`, `booking_timestamp`, and the **geofence GPS coordinate** recorded at ticket issuance!).

### 5.2 `Where is My Train` (`com.whereismytrain.android`) — The Unreserved Fugitive Tracker
Acquired by Google (`Sigmoid Labs`), `Where is My Train` is installed on virtually every Indian rail traveler's Android phone.
* **Step-by-Step Sandbox Extraction (`/data/user/<id>/com.whereismytrain.android/`):**
  1. Stage all SQLite files in `/databases/` (`history*.db`, `alarm*.db`, `pnr*.db`, `cell*.db`) via Module 2.1 (Active + `-wal` + Freelist) and parse `/shared_prefs/*.xml`:
     * **Station-to-Station Search History:** Every station pair searched by the user (`from_station_code`, `to_station_code`, `search_timestamp`)—revealing which cities the suspect planned to flee between!
     * **Live Train Spot History:** Every 5-digit Train Number (`12560 Shiv Ganga Exp`) opened by the suspect to monitor live running status.
     * **"Inside Train? (Cell Tower Mode)" Telemetry:** When a passenger sits inside a moving train, they toggle the top-right switch to **`"Cell Tower"` mode**. The app records the active `train_number`, the `coach_position` selected by the user, and correlates the phone's live `MCC-MNC-LAC-CID` cellular tower transitions against its offline railway-corridor cell database! Extracting these logs proves **the suspect was physically riding inside that specific train**, even if they paid ₹150 cash at a window counter for an unreserved ticket!
     * **Destination Wake-Up Alarms:** Suspects set location-based alarms inside `Where is My Train` (`"Wake me up 20 minutes before Kanpur Central [CNB]"`). Extracting the alarm table proves the suspect's exact intended alighting station!

### 5.3 `DigiYatra` (`com.digiyatra` — Biometric Airport Boarding), `MakeMyTrip`, `Goibibo`, `ixigo`, `RedBus` & `OYO`
1. **`DigiYatra` (`/data/user/<id>/com.digiyatra/` on Android; `<App-UUID>/Documents/` on iOS):**
   * DigiYatra is India's facial-recognition airport entry and boarding system. It stores **W3C Verifiable Credentials (`VC`)** inside its local wallet (`SQLite`, `MMKV`, `shared_prefs`, or encrypted JSON in `/files/` unwrapped via Android Keystore / iOS Keychain in Module 2.2):
     * **Identity Credential (`IdentityVC`):** Contains the suspect's **UIDAI Aadhaar e-KYC Verified Full Name, Date of Birth, Gender, Masked Aadhaar, and Base64 JPEG Facial Reference Photograph**!
     * **Travel Credentials & IATA Barcoded Boarding Passes (`BCBP`):** Every PDF or QR boarding pass shared into DigiYatra stores the raw **IATA Resolution 792 Barcoded Boarding Pass (`BCBP`) string** (starting with `'M1'` + `PASSENGER_LASTNAME/FIRSTNAME` + `E` + **6-character Airline `PNR`** + **3-letter Origin Airport IATA (`VNS`)** + **3-letter Destination Airport IATA (`DEL`)** + **Airline Code (`6E` IndiGo / `AI` Air India / `UK` / `QP` Akasa)** + **Flight Number** + **3-digit Julian Date of Flight** + **Cabin Class** + **Seat Number (`014A`)** + **Check-in Sequence Number**!).
2. **OTAs, Buses & Hotels (`MakeMyTrip`, `Goibibo`, `ixigo`, `Cleartrip`, `EaseMyTrip`, `RedBus`, `AbhiBus`, `OYO`, `Airbnb`, `Agoda`, `Booking.com`):**
   * Scan SQLite, `MMKV`, and `app_webview` HTTP caches (`*_0` & `Cache.db`) for:
     * **Hotel Bookings (`OYO`, `MakeMyTrip`, `Goibibo`, `Airbnb`):** Hotel name, full street address, GPS coordinates, check-in timestamp, check-out timestamp, room count, **co-guest full names**, and booking ID.
     * **Inter-City Bus Bookings (`RedBus`, `AbhiBus`):** Bus operator name, **boarding point landmark & GPS coordinates**, dropping point, seat/sleeper number, passenger names, and **bus driver / conductor contact phone number**!

---

## 6. Step 4 — Sub-Engine 6.4D: Global & Indian Dating, Hookup & Matrimonial App Forensics

### 6.1 Master Target List of 14 Priority Dating & Matrimonial Apps in India

Query **Module 1.3 (`resolve_app_targets`)** across all user profiles (`0`, `10`, `95`, `150`, `999`) for the following applications:

| Category | Application Name | Android Package Name(s) | iOS Bundle ID(s) | Primary Forensic Value in Indian Investigations |
|---|---|---|---|---|
| **Global Dating** | **Tinder** | `com.tinder` | `com.cardify.tinder` | Romance/crypto ("Pig-Butchering") scams, honeytrap extortion, in-person assault/homicide, `Passport` location spoofing. |
| **Global Dating** | **Bumble** | `com.bumble.app` | `com.mosocial.bumble` | High urban adoption in India. Stores chat text, voice notes, blurred "Private Detector" images, in-app VoIP calls, and `Travel Mode` flags. |
| **Global Dating** | **Hinge** | `co.hinge.app` | `co.hinge.mobile.ios` | Stores exact **Neighborhood Name + `(lat, lon)`**, voice prompts, introductory prompt comments, chat logs, and `"We Met"` confirmations. |
| **Proximity Grid** | **Grindr** | `com.grindrapp.android` | `com.grindrguy.grindr` | **High-Risk Robbery / Extortion / Homicide Target:** Logs exact **distance in meters** to nearby users, shared live GPS pins in chat, and expiring albums. |
| **Crossed-Paths** | **Happn** | `com.ftw_and_co.happn` | `com.ftw-and-co.happn` | **Logs Exact Physical Street Intersections (`lat, lon, timestamp`) where two users physically crossed paths within 250m!** |
| **Global Dating** | **OkCupid**, **Schmooze**, **Tantan**, **Badoo**, **Boo** | `com.okcupid.okcupid`, `com.schmooze.app`, `com.p1.mobile.putong`, `com.badoo.mobile`, `enterprises.dating.boo` | Corresponding iOS bundles | College/meme dating (`Schmooze`), Asian syndicate P2P lures (`Tantan`), and questionnaire profiles (`OkCupid`). |
| **Indian Dating** | **Aisle** (+ Regional: **`Arike`**, **`Anbe`**, **`Neetho`**, **`Neene`**) | `com.aisle.app`, `com.aisle.arike`, `com.aisle.anbe`, `com.aisle.neetho` | `co.aisle.app` | High-intent Indian & NRI dating. Extracts mother tongue, city, linked social handles, "Invites" comments, and chat history. |
| **Indian Dating (KYC Trust Score)** | **TrulyMadly** & **QuackQuack** | `com.trulymadly.android.app`, `com.quackquack.app` | `com.trulymadly.ios`, `in.quackquack.app` | **`TrulyMadly` caches `Trust Score` KYC verification metadata (uploaded Aadhaar/PAN/DL, LinkedIn, employment proof, and mobile number)!** |
| **Indian Matrimonial** | **Shaadi.com**, **BharatMatrimony** (+ Regional Matrimony apps), **Jeevansathi** | `com.shaadi.android`, `com.bharatmatrimony`, `com.jeevansathi.android` | `com.shaadi.iphone`, `com.bharatmatrimony`, `com.infoedge.jeevansathi` | **Matrimonial Financial Scams & Impersonation:** Extracts `Matrimony ID`, `Kundli` birth details, uploaded PAN/Passport KYC, **unlocked phone number logs**, and chats! |

### 6.2 Deep Sandbox Extraction Rules for Dating & Matrimonial Platforms

For every dating and matrimonial app discovered on the handset, process all SQLite/Room databases (`/databases/`), `MMKV` stores (`/files/mmkv/`), React Native `RKStorage`, `shared_prefs/*.xml`, and `app_webview` / `NSURLCache` (`*_0` & `Cache.db`) through **Phase 2 (Modules 2.1–2.4)**:

#### 1. Extracting the Suspect's Own Persona(s) & Detecting Spoofed `Passport` / `Travel Mode` Locations
* Extract the logged-in user's `user_id`, `display_name` (often a fake alias in honeytrap/crypto scams!), `birth_date` / `age`, `gender`, `bio`, `job_title`, `company`, `school`, `instagram_handle`, and **registered login phone number / email / Google/Apple ID**.
* **The `Passport` / `Travel Mode` Disambiguation Check:**
  * Inspect the profile's location JSON (`pos`, `pos_info`, `travel_location`, `user_location`):
    * Extract **`actual_hardware_gps_lat_lon`** (where the suspect's phone physically is).
    * Extract **`displayed_profile_lat_lon_and_city`** (where the suspect's profile claims to be!).
    * If `is_traveling == true` or `passport_active == true` or the Haversine distance between `actual_hardware_gps` and `displayed_profile_location` exceeds $50\text{ km}$, set **`is_dating_location_spoofed_via_passport = 1`**! *(For example: Proves the suspect was physically sitting in Noida/Jaipur while operating a `Tinder` / `Bumble` profile pretending to be an investor in Mumbai or San Francisco!)*

#### 2. Extracting Matches, Unmatched/Blocked Ghosts & `Happn` Crossed-Path Intersections
* **Active & Unmatched/Deleted Matches (`matches`, `conversations`, `connections`, `users`):**
  * Run **Module 2.1's Shared `-wal` Reader and B-Tree Freelist Carver** on `tinder-3.db`, `Bumble.db`, `grindr*.db`, `hinge*.db`, `aisle*.db`, and `shaadi*.db`!
  * Any match row recovered solely from `-wal` frames, freelist pages, or `app_webview` HTTP cache (`*_0`) that is no longer in the active `matches` table is flagged with **`was_unmatched_or_deleted = 1`** (`RESIDUAL_RECORD` / `HISTORICAL_COMMITTED_RECORD`)!
  * Also scan `/cache/image_manager_disk_cache/` (Glide) and `Cache.db` / `fsCachedData/` for cached profile photos (`https://images-ssl.gotinder.com/<user_id>/...`, `https://*.bmbcdn.com/...`, `https://*.hingecdn.com/...`)—Notice that **Tinder's CDN URL path literally embeds the remote user's 24-character hexadecimal `user_id` (`images-ssl.gotinder.com/<24_hex_user_id>/...`)** even after the match row was deleted from SQLite!
* **In `Happn` (`com.ftw_and_co.happn`) & `Grindr` (`com.grindrapp.android`):**
  * Extract the **Physical Proximity / Crossed-Path Encounter Log**:
    * In `Happn`: Extract `crossing_id`, `remote_user_id`, `remote_user_name`, `crossing_count` (how many times they crossed paths), **`crossing_latitude` & `crossing_longitude`**, and **`crossing_timestamp_utc`**!
    * In `Grindr`: Extract `profile_id`, `display_name`, **`distance_meters`** (exact distance in meters from the suspect's phone when the grid refreshed), `seen_timestamp`, and any shared live location pins (`lat, lon`) inside the chat thread!

#### 3. Extracting Indian Matrimonial (`Shaadi.com`, `BharatMatrimony`, `Jeevansathi`) & `TrulyMadly` KYC Artifacts
* **Unlocked Phone Number Quota Ledger (`contact_views` / `viewed_contacts`):**
  * In `Shaadi.com`, `BharatMatrimony`, and `Jeevansathi`, whenever a user clicks **"View Phone Number / Call Now"** on a prospect's profile, the app deducts 1 credit from their paid membership quota and caches the unlocked **`matrimony_id` (`SH...` / `M...` / `JS...`), `prospect_name`, `unlocked_mobile_number`, `unlocked_alternate_parent_number`, `email`, and `viewed_timestamp_utc`** in local SQLite / `app_webview` JSON cache!
* **Uploaded KYC & Astrological (`Kundli`) Identity Cache:**
  * Extract the user's uploaded verification metadata (`pan_number`, `aadhaar_last_4`, `passport_no`, `driving_license_no`, `trust_score_percentage` in `TrulyMadly`, and exact `date_of_birth`, `time_of_birth`, and `place_of_birth_city` from the astrological `horoscope` / `kundli` JSON!).

#### 4. Extracting Dating & Matrimonial Chat Messages & Off-Platform Handoff Triggers
* Extract every message across all 14 dating and matrimonial apps (`message_id`, `match_id`, `sender_id`, `receiver_id`, `message_text`, `media_attachment_url`, `sent_utc_iso`).
* **Automatic Off-Platform Handoff Detector:**
  * Scan every dating/matrimonial chat message for:
    * **10-digit Indian mobile numbers** or international numbers (`+91...`, `+1...`, `+44...`, `+971...`).
    * **WhatsApp, Telegram, Instagram, or Snapchat handles** (e.g., *"Let's talk on WhatsApp 9876543210"*, *"Add my Insta @..."*, *"Text me on Telegram @..."*).
    * **UPI VPAs, Bank Account Numbers, or Crypto Wallet Addresses (`T...`, `0x...`)**!
  * Whenever a match is found, automatically pass an **`IN_CHAT_HANDOFF_EDGE`** to **Phase 5, Module 5.5 (`unified_cross_platform_actors`)** so the dating/matrimonial profile (`Tinder ID` / `Shaadi ID`) is permanently fused with the suspect's or victim's WhatsApp/Telegram/UPI identity card!

---

## 7. Database Schema for Module 6.4 (`indian_hyperlocal_travel_and_dating_engine.sqlite`)

The developer must create the following five tables in the case database:

### Table 1: `hyperlocal_saved_addresses_and_hideouts` (Exact Flat/Floor/Tower/Gate-Code & Alternate Phone Directory)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `hideout_addr_uid` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Unique row ID. |
| `source_app_name` | `TEXT` | `NOT NULL` | E.g., `"Blinkit"`, `"Zepto"`, `"Swiggy"`, `"Zomato"`, `"Flipkart"`, `"Amazon India"`, `"Uber"`, `"Rapido"`. |
| `app_instance_id` | `INTEGER` | `NOT NULL` | Foreign key to owning app in Module 1.3. |
| `source_vfs_file_id` | `INTEGER` | `NOT NULL` | Source `.db`, `MMKV`, `shared_prefs`, or `*_0` cache file in `vfs_index`. |
| `recovery_classification` | `TEXT` | `NOT NULL` | Mandatory 6-State Enum (`ORIGINAL_RECORD`, `HISTORICAL_COMMITTED_RECORD`, `RESIDUAL_RECORD`). |
| `address_label_tag` | `TEXT` | `NULL` | E.g., `"HOME"`, `"WORK"`, `"HOTEL"`, `"OTHER"`, `"GIRLFRIEND"`. |
| `flat_floor_tower_building` | `TEXT` | `NULL` | **Exact unit micro-location** (e.g., `"Flat 1404, 14th Floor, Tower B-2, Supertech Eco Village"`). |
| `street_locality_landmark` | `TEXT` | `NOT NULL` | Full street address and user-entered landmark. |
| `city_and_state` | `TEXT` | `NULL` | City and State. |
| `pincode_6_digit` | `TEXT` | `NULL` | 6-digit Indian Postal PIN Code (indexed!). |
| `pinned_lat_wgs84` | `REAL` | `NULL` | Exact delivery pin latitude ($\phi$). |
| `pinned_lon_wgs84` | `REAL` | `NULL` | Exact delivery pin longitude ($\lambda$). |
| `gate_code_or_instructions` | `TEXT` | `NULL` | Rider instructions (`"Gate passcode 4412, don't ring bell"`). |
| `recipient_name` | `TEXT` | `NULL` | Name of person receiving deliveries at this address. |
| `recipient_contact_phone` | `TEXT` | `NULL` | 10-digit phone number assigned to this delivery address (indexed!). |
| `is_alternate_or_third_party_phone` | `INTEGER` | `DEFAULT 0` | **`1` if `recipient_contact_phone` differs from the handset's primary SIM number (unmasks secret burner or accomplice)!** |
| `first_or_last_used_utc_iso` | `TEXT` | `NULL` | Normalized UTC ISO-8601 timestamp. |

### Table 2: `hyperlocal_orders_and_parcel_drops_ledger` (Food, Quick-Commerce, E-Commerce & `Genie`/`Porter` Parcel Couriers)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `order_record_uid` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Unique row ID. |
| `source_app_name` | `TEXT` | `NOT NULL` | E.g., `"Swiggy Genie"`, `"Porter"`, `"Borzo"`, `"Blinkit"`, `"Zomato"`, `"Flipkart"`. |
| `order_category` | `TEXT` | `NOT NULL` | Enum: `FOOD_DELIVERY`, `QUICK_COMMERCE_10MIN`, `ECOMMERCE_PACKAGE`, `INTRACITY_P2P_PARCEL_COURIER`. |
| `native_order_id` | `TEXT` | `NOT NULL` | Platform Order ID. |
| `order_status` | `TEXT` | `NOT NULL` | `DELIVERED_COMPLETED`, `CANCELLED`, `IN_TRANSIT`. |
| `pickup_or_store_name_addr` | `TEXT` | `NULL` | Restaurant/Darkstore name OR **P2P Parcel Pickup Full Address + Landmark**. |
| `pickup_sender_name_phone` | `TEXT` | `NULL` | **Sender Name + 10-digit Phone Number (for `Swiggy Genie`, `Porter`, `Borzo` P2P parcel drops!)**. |
| `dropoff_full_address` | `TEXT` | `NOT NULL` | Full delivery Flat/Building/Street address. |
| `dropoff_receiver_name_phone` | `TEXT` | `NULL` | **Receiver Name + 10-digit Phone Number!** |
| `dropoff_lat_lon_json` | `TEXT` | `NULL` | `(lat, lon)` of delivery destination. |
| `items_or_parcel_type_json` | `TEXT` | `NULL` | Ordered items list, declared parcel type, or **15-digit `IMEI`/Serial from Flipkart/Amazon invoice**! |
| `amount_inr_decimal` | `REAL` | `NULL` | Total order value in INR (`₹`). |
| `payment_mode_and_utr` | `TEXT` | `NULL` | Payment method (`UPI`, `COD_CASH`, `CARD`) + 12-digit `UTR` (linked to Phase 3). |
| `rider_name_phone_and_plate` | `TEXT` | `NULL` | Delivery rider name, phone, and vehicle plate (if recorded). |
| `ordered_utc_iso` | `TEXT` | `NOT NULL` | Normalized UTC ISO-8601 order placement timestamp. |
| `delivered_utc_iso` | `TEXT` | `NULL` | Normalized UTC ISO-8601 completion timestamp. |
| `recovery_classification` | `TEXT` | `NOT NULL` | 6-State Enum (`ORIGINAL_RECORD`, `HISTORICAL_COMMITTED_RECORD`, `RESIDUAL_RECORD`). |

### Table 3: `mobility_rides_and_intercity_travel_ledger` (`Uber`, `Ola`, `Rapido`, `Namma Yatri`, `IRCTC`, `Where is My Train`, `DigiYatra` & Hotels)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `travel_record_uid` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Unique row ID. |
| `source_app_name` | `TEXT` | `NOT NULL` | E.g., `"Uber"`, `"Ola"`, `"Rapido"`, `"Namma Yatri"`, `"InDrive"`, `"IRCTC"`, `"Where is My Train"`, `"DigiYatra"`, `"MakeMyTrip"`, `"OYO"`. |
| `travel_modality` | `TEXT` | `NOT NULL` | Enum: `CAB_OR_AUTO_RIDE`, `BIKE_TAXI_2W`, `TRAIN_RESERVED_IRCTC`, `TRAIN_CELL_TOWER_TRACKED_WIMT`, `TRAIN_UNRESERVED_UTS`, `FLIGHT_DIGIYATRA_OR_OTA`, `INTERCITY_BUS`, `HOTEL_STAY_CHECKIN`. |
| `booking_id_or_pnr` | `TEXT` | `NULL` | Ride ID, 10-digit Railway `PNR`, 6-char Airline `PNR`, or `UTS` Ticket No. |
| `trip_status` | `TEXT` | `NOT NULL` | `COMPLETED`, `CANCELLED`, `CELL_TOWER_INSIDE_TRAIN_ACTIVE`, `ALARM_SET`. |
| `origin_station_or_pickup_addr` | `TEXT` | `NOT NULL` | Pickup street address, Railway Station Code (`BSB`), or Airport IATA (`VNS`). |
| `origin_lat_lon_json` | `TEXT` | `NULL` | Pickup `(lat, lon)`. |
| `dest_station_or_dropoff_addr` | `TEXT` | `NOT NULL` | Dropoff street address, Hotel address, Railway Station Code (`NDLS`), or Airport IATA (`DEL`). |
| `dest_lat_lon_json` | `TEXT` | `NULL` | Dropoff `(lat, lon)`. |
| `decoded_route_waypoints_json` | `TEXT` | `NULL` | **Unpacked Google Encoded Polyline `[(lat, lon), ...]` trajectory array (Section 4.2)!** |
| `vehicle_plate_or_train_flight_no` | `TEXT` | `NULL` | **RTO License Plate (`DL-1R-...`), 5-digit Train No (`12559`), or Flight No (`6E-2042`)!** |
| `seat_coach_or_room_assignment` | `TEXT` | `NULL` | E.g., `"Coach B2, Berth 44 LB"`, `"Seat 14A"`, or `"Vehicle: White Maruti Dzire"`. |
| `passengers_or_guest_rider_json` | `TEXT` | `NULL` | Co-passenger names/ages/IDs, Hotel co-guests, or Third-Party Guest Rider phone number! |
| `start_or_departure_utc_iso` | `TEXT` | `NOT NULL` | Normalized UTC ISO-8601 start/departure/check-in timestamp. |
| `end_or_arrival_utc_iso` | `TEXT` | `NULL` | Normalized UTC ISO-8601 arrival/check-out timestamp. |
| `recovery_classification` | `TEXT` | `NOT NULL` | 6-State Enum (`ORIGINAL_RECORD`, `HISTORICAL_COMMITTED_RECORD`, `RESIDUAL_RECORD`). |

### Table 4: `dating_and_matrimonial_profiles_and_matches` (All 14 Dating & Matrimonial Apps — Active, Unmatched & `Passport` Audited)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `dating_peer_uid` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Unique row ID. |
| `platform_name` | `TEXT` | `NOT NULL` | Enum: `TINDER`, `BUMBLE`, `HINGE`, `GRINDR`, `HAPPN`, `AISLE`, `TRULYMADLY`, `QUACKQUACK`, `OKCUPID`, `SCHMOOZE`, `SHAADI_COM`, `BHARAT_MATRIMONY`, `JEEVANSATHI`. |
| `app_instance_id` | `INTEGER` | `NOT NULL` | Foreign key to Module 1.3. |
| `profile_role` | `TEXT` | `NOT NULL` | Enum: `LOCAL_DEVICE_OWNER_PERSONA`, `ACTIVE_MATCH`, `UNMATCHED_OR_BLOCKED_RECOVERED`, `CROSSED_PATHS_PROXIMITY_PEER`, `UNLOCKED_MATRIMONIAL_CONTACT`. |
| `native_user_or_matrimony_id` | `TEXT` | `NOT NULL` | Tinder 24-hex ID, Bumble ID, Grindr ID, or Matrimony ID (`SH...` / `M...` / `JS...`). |
| `display_name_and_age` | `TEXT` | `NULL` | Profile name, age, and gender. |
| `unlocked_phone_or_social_handles` | `TEXT` | `NULL` | Unlocked Matrimony mobile number, `TrulyMadly` verified mobile, or linked Instagram/LinkedIn handle! |
| `kyc_trust_score_or_kundli_json` | `TEXT` | `NULL` | Extracted `TrulyMadly` KYC ID proof, Matrimonial PAN/Passport verification, or `Kundli` exact Date/Time/City of Birth! |
| `actual_gps_or_crossing_lat_lon` | `TEXT` | `NULL` | Actual hardware GPS `(lat, lon)`, `Happn` street crossing `(lat, lon)`, or `Grindr` `distance_meters`! |
| `displayed_passport_city_lat_lon` | `TEXT` | `NULL` | Displayed city / virtual `Passport` or `Travel Mode` coordinates. |
| `is_dating_location_spoofed` | `INTEGER` | `DEFAULT 0` | **`1` if `Passport` / `Travel Mode` is active or displayed location differs from hardware GPS by $> 50\text{ km}$!** |
| `was_unmatched_or_deleted` | `INTEGER` | `DEFAULT 0` | **`1` if recovered from `-wal`, B-Tree Freelist, CDN image cache (`gotinder.com/<id>`), or WebView cache after unmatching!** |
| `cached_photo_paths_json` | `TEXT` | `NULL` | Local staged paths in `vfs_index` of cached profile photos! |
| `matched_or_crossed_utc_iso` | `TEXT` | `NULL` | Normalized UTC ISO-8601 timestamp of match, crossing, or contact unlock. |
| `recovery_classification` | `TEXT` | `NOT NULL` | 6-State Enum (`ORIGINAL_RECORD`, `HISTORICAL_COMMITTED_RECORD`, `RESIDUAL_RECORD`). |

### Table 5: `dating_and_matrimonial_messages_ledger` (In-App Dating/Matrimonial Chats & WhatsApp/Telegram Handoff Links)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `dating_msg_uid` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Unique row ID. |
| `platform_name` | `TEXT` | `NOT NULL` | `TINDER`, `BUMBLE`, `HINGE`, `GRINDR`, `AISLE`, `SHAADI_COM`, etc. |
| `dating_peer_uid` | `INTEGER` | `NOT NULL` | Foreign key to `dating_and_matrimonial_profiles_and_matches.dating_peer_uid`. |
| `source_vfs_file_id` | `INTEGER` | `NOT NULL` | Source `.db` or `*_0` cache file in `vfs_index`. |
| `recovery_classification` | `TEXT` | `NOT NULL` | 6-State Enum (`ORIGINAL_RECORD`, `HISTORICAL_COMMITTED_RECORD`, `RESIDUAL_RECORD`). |
| `direction` | `TEXT` | `NOT NULL` | `OUTGOING_SENT`, `INCOMING_RECEIVED`, `VOIP_VIDEO_CALL`. |
| `message_text_or_prompt` | `TEXT` | `NULL` | Full message text or Hinge prompt reply. |
| `media_or_shared_pin_json` | `TEXT` | `NULL` | Shared voice note, Bumble Private Detector photo, or Grindr shared GPS pin `(lat, lon)`. |
| `extracted_handoff_phone_or_handle` | `TEXT` | `NULL` | **Automatically extracted `+91` phone number, WhatsApp/Telegram/Insta handle, or UPI/Crypto address shared inside the dating chat (bridges to Phase 5.5)!** |
| `sent_utc_ns` | `INTEGER` | `NOT NULL` | Normalized 64-bit UTC nanoseconds. |
| `sent_utc_iso` | `TEXT` | `NOT NULL` | Normalized UTC ISO-8601 timestamp. |

---

## 8. Developer Acceptance Test Checklist for Module 6.4

1. **The `Blinkit` / `Swiggy` Exact Flat/Door & Alternate Receiver Phone Test:**
   * Insert a saved address JSON in `Blinkit` (`com.grofers.customerapp`) with `flat_no = "Flat 902, Tower C"`, `society = "Gaur City 2"`, `pincode = "201009"`, `lat = 28.6189`, `lon = 77.4285`, and `receiver_phone = "9811223344"` (while the phone's primary SIM in `telephony.db` is `9988776655`).
   * Verify that Sub-Engine 6.4A populates `hyperlocal_saved_addresses_and_hideouts`, sets `is_alternate_or_third_party_phone = 1`, and exports `(28.6189, 77.4285)` to Module 6.3's geolocation ledger.
2. **The `Uber` / `Ola` Google Encoded Polyline Bitwise Unpacker Test:**
   * Pass the standard Google Encoded Polyline test string `"_p~iF~ps|U_ulLnnqC_mqNvxq`@"` into Section 4.2's bitwise ZigZag unpacker.
   * Verify that it decodes the exact 3 coordinate pairs: `[(38.5, -120.2), (40.7, -120.95), (43.252, -126.453)]`!
3. **The `Where is My Train` Cell-Tower Mode & `DigiYatra` IATA BCBP Test:**
   * Feed a `Where is My Train` record showing `"Inside Train = ON"` for Train `12559` (`BSB` $\rightarrow$ `NDLS`) and a `DigiYatra` boarding pass string `"M1SHARMA/RAHUL        EAB12CD VNSDEL 6E 2042 309Y014A0045 100"`.
   * Verify that Sub-Engine 6.4C extracts Train `12559` and decodes the IATA BCBP string into Passenger `"SHARMA/RAHUL"`, PNR `"AB12CD"`, Route `"VNS -> DEL"`, Flight `"6E 2042"`, Julian Day `309` (Nov 5), and Seat `"014A"`.
4. **The `Tinder` Unmatched `-wal` Recovery, `Passport` Spoof Detection & WhatsApp Handoff Test:**
   * In a test `tinder-3.db`, configure the owner profile with `actual_gps = (28.5355, 77.3910)` (Noida) and `pos_info` Passport city `London (51.5072, -0.1276)`. Place a deleted match and chat message (`"Text me on WhatsApp 9876543210"`) inside `tinder-3.db-wal`.
   * Verify that Sub-Engine 6.4D recovers the unmatched profile and chat from the `-wal` frame (`was_unmatched_or_deleted = 1`), flags `is_dating_location_spoofed = 1`, and bridges `9876543210` to Phase 5.5's `unified_cross_platform_actors`!
# Engineering Specification: Phase 3, Module 3.4 — The Indian TRAI DLT Financial SMS & System Notification Parser

**Document Purpose:** This document provides the complete, step-by-step architectural blueprint for building **Module 3.4** of the Forensic Data Parser (corresponding to **Groups 1, 8, 13, and 15** of the Unified Master Register). It contains **zero programming code** and explains how to extract, decode, validate, and structure financial SMS alerts and operating-system push notifications across Android (`mmssms.db`, `bugle_db`, Notification History) and iOS (`sms.db` including `attributedBody` binary streams, `DuetExpertCenter`, and Apple Biome) from first principles so that any developer can build a courtroom-grade Layer-2 and Layer-3 financial evidence engine.

---

## 1. Purpose & Mental Model (Why SMS and Notification Ledgers Are the Ultimate Fail-Safe)

In Indian financial crime investigations, suspects and mule-account operators routinely **uninstall** PhonePe, Google Pay, Paytm, and banking apps before surrendering their phones, or police seize the phone in an **Android BFU (Before First Unlock)** state where Credential Encrypted (`CE`) app sandboxes (`/data/user/0/`) are locked.

When the payment app sandbox (`Layer 1`) is gone or inaccessible, **Layer 2 (Carrier DLT SMS Databases)** and **Layer 3 (OS Notification Ledgers)** allow your software to reconstruct the suspect's entire banking and UPI history anyway:

1. **Android `mmssms.db` Lives in `DE` (Device Encrypted) Storage:** On modern Android (Android 7 through Android 17), `/data/user_de/0/com.android.providers.telephony/databases/mmssms.db` resides in `DE` storage so the phone can receive texts during Direct Boot. This means in a **BFU extraction** (via supported hardware/bootloader access), `mmssms.db` is **readable** even when every banking app in `/data/user/0/` is encrypted ciphertext!
2. **Uninstalling a Banking App Does Not Delete Carrier Bank SMS Alerts:** When a suspect uninstalls `YONO SBI` or `PhonePe`, the official debit/credit SMS alerts sent by `AD-SBIINB-S` or `JX-HDFCBK-S` remain inside `mmssms.db`, Google Messages `bugle_db`, and iOS `sms.db` (and inside their `-wal` and B-tree freelist pages even if the suspect deleted individual text messages!).
3. **OS Notification Ledgers Survive Both App Removal and SMS Deletion:** Even if a suspect deletes both the PhonePe app *and* their bank SMS messages, iOS **`DuetExpertCenter`** (`notificationAndSuggestionDB.db`) retains notification delivery metadata for $\approx 60\text{ days}$, **Apple Biome** retains notification streams in `SEGB` format, and Android **`adb bugreport` / Notification History** caches push notification alerts sent by UPI and banking apps.

---

## 2. The 6 Fatal Mistakes Beginner Developers Make in Financial SMS & Notification Parsing

Before implementing Module 3.4, the developer must understand six critical traps that break ordinary SMS parsers:

### Mistake 1: Reading Only `message.text` in iOS `sms.db` and Missing `attributedBody` (iOS 16–26)
* **The Trap:** Running `SELECT text FROM message;` on an iOS `/private/var/mobile/Library/SMS/sms.db` database and skipping any row where `text IS NULL`.
* **Why It Fails:** Starting in **iOS 16 through iOS 26**, Apple frequently leaves the `text` column in `sms.db` as **`NULL`** for incoming SMS and iMessage records and stores the actual message string inside the **`attributedBody` (`BLOB`)** column (serialized as an Apple `NSArchiver` / `typedstream` binary `NSAttributedString`)! A naive parser that only reads the `text` column will miss up to $50\%$ of all bank SMS messages on modern iPhones.
* **The Rule:** Whenever `message.text` is `NULL` or empty in iOS `sms.db`, automatically unpack the `message.attributedBody` BLOB using the exact byte-marker specification in Section 3.2.

### Mistake 2: Failing to Filter Out TRAI `-P` (Promotional) Loan Spam
* **The Trap:** Running a naive regex that looks for `"credited"` or `"Rs."` + an amount across all SMS messages.
* **Why It Fails:** Indian mobile users receive dozens of promotional spam SMS messages every week reading: *"CONGRATS! Rs. 5,00,000 Personal Loan is CREDITED/APPROVED for your A/c! Click bit.ly/xyz"*. If your parser ingests those spam messages as real credits, the investigator's financial summary will be polluted with millions of Rupees of non-existent transactions.
* **The Rule:** Enforce the **TRAI DLT Suffix & Spam Rejection Filter** (Section 4.1 & Section 5.2): any DLT sender ending in **`-P` (Promotional)** or containing spam/loan-offer grammar (`"pre-approved"`, `"eligible for"`, `"apply now"`, `"click"`, `"http"`, `"bit.ly"`) without a valid masked account number and UTR/balance clause must be routed to `PROMOTIONAL_SPAM_IGNORED`, never to the transaction ledger!

### Mistake 3: Failing to Parse Indian Lakh/Crore Comma Formatting & `Cr`/`Dr` Balance Suffixes
* **The Trap:** Using a standard US/European number parser that expects commas only every $3\text{ digits}$ (`100,000.00`) or expects negative balances to start with a minus sign (`-500.00`).
* **Why It Fails:** Indian banks format numbers using the **Indian Numbering System** (`1,00,000.00` for 1 Lakh; `1,45,67,890.50` for 1.45 Crore) and frequently write available balances as `"Avl Bal: INR 12,450.00 Cr"` (positive credit balance) or `"Avl Bal: INR 1,200.00 Dr"` / `"Bal: -Rs. 1,200.00"` (overdraft/debit balance).
* **The Rule:** Strip all commas (`,`) inside numeric strings before converting to 64-bit decimal floats, and inspect trailing `Cr` vs. `Dr` / `-` markers on balance strings (Section 5.3).

### Mistake 4: Ignoring the Carrier `SMSC` (`service_center`) Column to Detect Spoofed Fake Bank SMS
* **The Trap:** Trusting the `address` (sender ID) column of an incoming SMS without checking `service_center` (`SMSC`) and `creator`.
* **Why It Fails:** Fraudsters and mules sometimes use local "Fake SMS Injector" apps on Android to insert a fake bank credit SMS (`"Rs. 2,00,000 credited to A/c XX1234"`) directly into `mmssms.db` to fool a victim or an investigator. However, a genuine carrier-delivered SMS always arrives through the telecom operator's **Short Message Service Center (`SMSC`)**, which populates `sms.service_center` with a valid `+9198...` operator SMSC number and `sms.protocol = 0`. Locally injected fake SMS rows have `service_center = NULL` (or empty) and/or a non-system `creator` package!
* **The Rule:** Always inspect `service_center`, `protocol`, `sub_id`, and `creator` on every Android SMS to verify carrier authenticity (Section 4.4).

### Mistake 5: Overstating What iOS `DuetExpertCenter` Contains
* **The Trap:** Expecting `notificationAndSuggestionDB.db` (`DuetExpertCenter`) on iOS to contain the full text body and 12-digit UTR of a deleted bank notification.
* **Why It Fails:** As established in our Master Register (Group 1 & Group 8), the 36-column `notifications` table inside `/private/var/mobile/Library/DuetExpertCenter/streams/notificationAndSuggestionDB.db` records **notification metadata only (app bundle ID, delivery timestamp, thread identifier, category, and user interaction state)—it does NOT store the notification body preview text!** By contrast, **Apple Biome Notification streams (`SEGB`)** and **Android Notification History / `bugreport` dumps** *can* contain notification title and body text.
* **The Rule:** Maintain strict courtroom precision: use `DuetExpertCenter` to prove **that a UPI or banking app received a push notification at an exact timestamp** (surviving $\approx 60\text{ days}$ even after app deletion), and use Biome / Android Notification logs when extracting notification body text (Section 6).

### Mistake 6: Ignoring `1930` NCRP Cybercrime Lien, Hold & Account Freeze SMS Alerts
* **The Trap:** Only extracting `DEBIT` and `CREDIT` SMS messages and ignoring bank administrative alerts.
* **Why It Fails:** When an Indian cybercrime victim reports a fraud on the **`1930` National Cyber Crime Reporting Portal (NCRP)**, the suspect's bank places an automated **Lien / Hold / Freeze** on the disputed amount and sends an SMS to the suspect's phone (e.g., *"Hold of Rs. 45,000.00 has been marked on your A/c XX4821 for Cyber Crime complaint Ack No 3311..."* or *"Lien marked for UPI Ref 630914829104"*). Finding this SMS on a seized phone is **direct courtroom proof** that the suspect was notified of the cybercrime freeze on that exact account and timestamp!
* **The Rule:** Include a dedicated **`LIEN_HOLD_OR_FREEZE_ALERT`** extractor in your SMS grammar (Section 5.1, Category 7).

---

## 3. Step 1 — Sub-Engine 3.4A: Multi-Database SMS Ingestion & iOS `attributedBody` Unpacker

Module 3.4 first gathers all SMS/MMS/RCS records (active, `-wal` historical commits, and B-Tree freelist/freeblock carved rows via **Phase 2, Module 2.1**) across three primary databases:

### 3.1 Android SMS Sources (`mmssms.db` in DE Storage & `bugle_db` in CE Storage)

1. **Source 1 — Android Telephony Provider (`/data/user_de/0/com.android.providers.telephony/databases/mmssms.db`):**
   * Stage via Module 1.1 and process via Module 2.1 (Active + `-wal` + Freelist).
   * Query the **`sms`** table:
     * `_id` (`INTEGER`): Primary key `ROWID`.
     * `address` (`TEXT`): Sender ID (e.g., `"AD-SBIINB-S"`, `"JX-HDFCBK-S"`, `"+919876543210"`).
     * `body` (`TEXT`): Full SMS text body.
     * `date` (`INTEGER`): 13-digit Unix millisecond timestamp when the handset received/created the message.
     * `date_sent` (`INTEGER`): 13-digit Unix millisecond timestamp when the carrier SMSC transmitted the message.
     * `type` (`INTEGER`): `1` = `INBOX` (Received), `2` = `SENT`, `3` = `DRAFT`, `4` = `OUTBOX`, `5` = `FAILED`.
     * `read` & `seen` (`INTEGER`): `1` = Read by user, `0` = Unread.
     * `service_center` (`TEXT`): Carrier SMSC phone number (e.g., `"+919820005444"`).
     * `sub_id` (`INTEGER`): Joins to **`device_sim_card_history_ledger.android_sub_id`** (from Module 3.2) to identify the exact physical 20-digit `ICCID` SIM card that received the bank alert!
     * `creator` (`TEXT`): Package name that handled/inserted the message.
2. **Source 2 — Google Messages (`bugle_db` at `/data/user/<id>/com.google.android.apps.messaging/databases/bugle_db`):**
   * Why check `bugle_db` in addition to `mmssms.db`? Because on modern Android devices where Google Messages is the default SMS/RCS app, users sometimes delete a message inside Google Messages or receive rich RCS business messages from banks (`Verified SMS` / `RCS Business Messaging`) that exist in `bugle_db` (`messages` joined with `parts` on `messages._id = parts.message_id` and `participants` on `messages.sender_id = participants._id`) even if purged or unsynced in `mmssms.db`.
   * Deduplicate `bugle_db` rows against `mmssms.db` rows using `(address, body_hash, abs(timestamp_ms) < 5000)`.

### 3.2 iOS SMS Source (`/private/var/mobile/Library/SMS/sms.db`) & The `attributedBody` Unpacker

1. Stage `/private/var/mobile/Library/SMS/sms.db` (and `sms.db-wal`) via Module 1.1 and process via Module 2.1.
2. Join `message` (`m`) with `handle` (`h`) on `m.handle_id = h.ROWID`:
   * Extract `m.ROWID`, `h.id` (the sender header, e.g., `"AD-SBIINB-S"`), `m.service` (`"SMS"` vs. `"iMessage"`), `m.is_from_me` (`0` = Received, `1` = Sent), `m.is_read`, `m.date` (18-digit Apple Cocoa nanoseconds since `2001-01-01` — convert via Module 1.2!), `m.date_read`, `m.text`, and `m.attributedBody`.
3. **How the Developer Unpacks `m.attributedBody` When `m.text` Is `NULL` or Empty:**
   On iOS 16–26, `m.attributedBody` is a binary `typedstream` (`streamtyped` magic at Byte $0$) encoding an `NSMutableAttributedString` / `NSAttributedString`. To extract the clean UTF-8 message string without needing macOS Objective-C libraries:
   * **Step 1:** Locate the ASCII byte sequence `4E 53 53 74 72 69 6E 67` (`"NSString"`) inside the `attributedBody` byte array.
   * **Step 2:** Advance $5\text{ bytes}$ past the end of `"NSString"` (skipping the 5-byte typedstream class/marker sequence `01 94 84 01 2B`, where `0x2B` is the `'+'` UTF-8 string indicator).
   * **Step 3:** Read the string byte length $L$ at the next byte (`length_indicator_byte`):
     * **If `length_indicator_byte < 0x80` ($1\text{ to }127$):** The string length $L$ is simply `length_indicator_byte`, and the UTF-8 message text starts at the very next byte!
     * **If `length_indicator_byte == 0x81` (`129`):** The next **2 bytes** are a 16-bit Little-Endian unsigned integer (`uint16_le`) giving the string length $L$, followed immediately by the $L\text{ bytes}$ of UTF-8 message text!
     * **If `length_indicator_byte == 0x82` (`130`):** The next **3 bytes** (or 4 bytes in `0x84`) are a Little-Endian integer giving $L$, followed by the $L\text{ bytes}$ of UTF-8 message text!
   * **Step 4:** Decode those $L\text{ bytes}$ as UTF-8 text and use that string as the message body!

---

## 4. Step 2 — Sub-Engine 3.4B: TRAI DLT Header Anatomy, Circle Decoder & SMSC Spoof Detector

### 4.1 Exact Parsing of Indian TRAI DLT Sender Headers

Every commercial/transactional SMS in India uses a sender address (`address` / `h.id`) structured under TRAI's Distributed Ledger Technology (DLT) regulations:

$$\texttt{<Operator\_Char><Circle\_Char>}\text{-}\texttt{<Entity\_ID (5 to 8 chars)>}\text{-}\texttt{<Category\_Char>}$$

*(Note: Legacy or carrier-stripped headers may omit the trailing `-<Category_Char>`, appearing as `AD-SBIINB` or `VM-HDFCBK`).*

1. **Decode Character 1 (`Operator_Char` — Originating Telecom Access Provider):**
   * `A` = **Bharti Airtel**
   * `J` = **Reliance Jio Infocomm**
   * `V` = **Vodafone Idea (Vi)**
   * `B` = **BSNL (Bharat Sanchar Nigam Ltd.)**
   * `M` = **MTNL (Mahanagar Telephone Nigam Ltd.)**
   * `Q` / `T` = **Tata Tele / Videocon / Quadrant**
2. **Decode Character 2 (`Circle_Char` — The 22 Indian Telecom Circles):**
   * `A` = Andhra Pradesh & Telangana | `B` = Bihar & Jharkhand | `C` = Chennai | `D` = **Delhi NCR** | `E` = Kerala | `G` = Gujarat | `H` = Haryana | `J` = Jammu & Kashmir | `K` = **Kolkata** | `L` = Himachal Pradesh | `M` = **Mumbai** | `N` = North East | `O` = Odisha | `P` = Punjab | `R` = Rajasthan | `S` = Assam | `T` = Tamil Nadu | `U` = **Uttar Pradesh (East)** | `W` = **Uttar Pradesh (West) & Uttarakhand** | `X` = **Karnataka** | `Y` = Madhya Pradesh & Chhattisgarh | `Z` = West Bengal.
3. **Decode the Trailing Suffix (`-<Category_Char>`):**
   * **`-S` (`Service / Implicit Transactional`):** Official bank account statements, UPI/IMPS/NEFT alerts, and service updates.
   * **`-T` (`Transactional / OTP`):** Official bank OTPs and core financial alerts.
   * **`-G` (`Government`):** Official Government of India / RBI / UIDAI / Income Tax / Cybercrime `1930` alerts.
   * **`-P` (`Promotional`):** Marketing and third-party loan advertisements. **Rule:** Immediately mark any message with a `-P` suffix as `IS_PROMOTIONAL_DLT = 1` and exclude it from bank balance/transaction ledgers!

### 4.2 Master Dictionary of 60+ Financial, Crypto, Demat & Govt DLT Entity Codes

Map the middle `<Entity_ID>` string (Characters 4 to 9/10) against this built-in lookup dictionary:

| Institution Category | DLT `<Entity_ID>` Codes (Case-Insensitive) | Resolved Institution Name |
|---|---|---|
| **Public Sector Banks** | `SBIINB`, `SBIPSG`, `SBMSMS`, `CBSSBI`, `SBIUPI`, `SBICRD`, `YONOSB` | **State Bank of India (SBI)** |
| **Public Sector Banks** | `BOBTXN`, `BOBSMS`, `BOBCRD`, `BARODA` | **Bank of Baroda** |
| **Public Sector Banks** | `PNBSMS`, `PNBCRD`, `PNBOTP`, `PNBUPI` | **Punjab National Bank (PNB)** |
| **Public Sector Banks** | `CANBNK`, `CANARA`, `CNRBMS` | **Canara Bank** |
| **Public Sector Banks** | `UNIONB`, `UBISMS`, `UBINBK` | **Union Bank of India** |
| **Public Sector Banks** | `INDBNK`, `INDIAN` | **Indian Bank** |
| **Public Sector Banks** | `BOIIND`, `BOISMS`, `BKOFIN` | **Bank of India (BOI)** |
| **Public Sector Banks** | `CENTBK`, `CBIOTP` (Central Bank); `UCOBNK` (UCO Bank); `IOBCHN`, `IOBBNK` (IOB); `MAHABK`, `BOMBNK` (Bank of Maharashtra); `PSBANK` (Punjab & Sind Bank) | **Corresponding PSU Bank** |
| **Private Sector Banks** | `HDFCBK`, `HDFCBN`, `HDFCCC`, `PAYZAP` | **HDFC Bank** |
| **Private Sector Banks** | `ICICIB`, `ICICBK`, `ICICIC` | **ICICI Bank** |
| **Private Sector Banks** | `AXISBK`, `AXISMR`, `AXISCC` | **Axis Bank** |
| **Private Sector Banks** | `KOTAKB`, `KOTAKM`, `KTKBNK` | **Kotak Mahindra Bank** |
| **Private Sector Banks** | `INDUSB`, `INDUSL` (IndusInd Bank); `IDFCFB`, `IDFCBK` (IDFC FIRST Bank); `YESBNK`, `YESBKL` (Yes Bank); `FEDBNK`, `FDRLBK` (Federal Bank); `RBLBNK`, `RBLCRD` (RBL Bank); `AUBANK`, `AUSMFB` (AU Small Finance Bank); `EQUITA` (Equitas SFB); `UJJIVN` (Ujjivan SFB); `BANDHN` (Bandhan Bank); `JKBANK` (J&K Bank); `KVBANK` (Karur Vysya Bank); `SIBSMS` (South Indian Bank) | **Corresponding Private / SFB Bank** |
| **Payments Banks & UPI PSPs** | `AIRBNK`, `AIRTEL`, `AIRPAY` (Airtel Payments Bank); `IPPBSM`, `IPPBNK`, `DOPBNK` (India Post Payments Bank / POSB); `JIOPAY`, `JIOBNK` (Jio Payments Bank); `FINOBK` (Fino Payments Bank); `NSDLPB` (NSDL Payments Bank); `PAYTMB`, `PYTMSB` (Paytm); `PHONPE` (PhonePe); `NPCIUP`, `BHIMUP` (NPCI / BHIM); `SLICEP` (Slice); `FAMPAY` (FamPay); `CREDAP` (CRED) | **Corresponding Payments Bank / UPI Platform** |
| **Crypto Exchanges (FIU-IND / Domestic)** | `COINDC`, `DCXOTP` (**CoinDCX**); `WAZIRX` (**WazirX**); `COINSW`, `CSKUBR` (**CoinSwitch Kuber**); `MUDREX` (**Mudrex**); `ZEBPAY` (**ZebPay**); `GIOTTU` (**Giottus**); `BINANC` (**Binance**) | **Cryptocurrency Exchange Alert / OTP (Cross-Link to Phase 4!)** |
| **Securities, Demat & Law Enforcement** | `NSDLDP`, `NSDLCA` (**NSDL Demat**); `CDSLDP`, `CDSLTX` (**CDSL Demat**); `ZERODH` (**Zerodha**); `GROWWP` (**Groww**); `ANGELB` (**AngelOne**); `CYBERC`, `NCRPIN`, `MHAIND` (**1930 NCRP Cybercrime Portal**); `UIDAIG`, `ADHAAR` (**UIDAI Aadhaar**); `ITDEPT` (**Income Tax Dept**) | **Demat / Regulatory / Law Enforcement Alert** |

### 4.3 The Carrier `SMSC` Spoof & Fake-SMS Injection Detector

For every incoming financial SMS on Android (`type == 1`), inspect `service_center` (`SMSC`) and `creator`:
1. If `service_center` is present and starts with `+91` (or `91` + 10 digits) and `protocol == 0`: Mark `carrier_smsc_verified = 1`.
2. If `type == 1` (Inbox) on a traditional SMS in `mmssms.db`, **but `service_center` is `NULL`/empty AND `creator` is not a system telephony/messaging package (`com.android.phone`, `com.google.android.apps.messaging`, `com.samsung.android.messaging`)**:
   * Flag the message with `is_spoofed_sms_suspected = 1` (`"SPOOFED_LOCAL_SMS_INJECTION"`), recording the `creator` package name!

---

## 5. Step 3 — Sub-Engine 3.4C: The 10-Category Financial SMS Grammar & Regex Extraction Pipeline

Every non-promotional financial SMS is normalized ( collapsing multiple spaces/newlines into single spaces) and evaluated against a deterministic **10-Category Classification & Field Extraction Pipeline**:

### 5.1 The 10 Financial SMS Categories & Exact Extraction Rules

| Category Code | Trigger Keywords & Grammar Pattern (Case-Insensitive) | Fields Extracted From Message Body |
|---|---|---|
| **1. `TX_DEBIT_OUTFLOW`** | Contains (`debited` \| `sent` \| `paid` \| `withdrawn` \| `transferred` \| `spent` \| `dr from` \| `deducted`) AND an INR Amount pattern AND NOT (`ATM` \| `cash withdrawal` \| `failed` \| `declined`). | • `amount_inr_decimal`<br>• `masked_account_or_card` (`A/c XX1234`)<br>• `payment_rail` (`UPI`, `IMPS`, `NEFT`, `RTGS`, `POS`, `ECOM`, `NACH`)<br>• `utr_or_rrn` (12-digit numeric or 16–22 char NEFT/RTGS)<br>• `counterparty_vpa_or_name` (after `to `, `trf to `, `VPA `, `at `)<br>• `post_tx_available_balance_inr` |
| **2. `TX_CREDIT_INFLOW`** | Contains (`credited` \| `received` \| `deposited` \| `cr to` \| `refunded`) AND an INR Amount pattern AND NOT (`loan approved` \| `pre-approved` \| `eligible` \| `limit`). | • `amount_inr_decimal`<br>• `masked_account_or_card`<br>• `payment_rail`<br>• `utr_or_rrn`<br>• `counterparty_vpa_or_name` (after `from `, `by `, `VPA `)<br>• `post_tx_available_balance_inr` |
| **3. `ATM_CASH_WITHDRAWAL`** | Contains (`ATM` \| `cash withdrawal` \| `withdrawn at` \| `YONO Cash` \| `Cardless`) AND (`debited` \| `withdrawn`) AND an INR Amount pattern. | • `amount_inr_decimal`<br>• `masked_account_or_card` (`Card XX5678` / `A/c XX1234`)<br>• **`atm_terminal_id_and_location`** (string following `at `, `ATM `, `on ` — e.g., `"S1NW00048212 CANTONMENT VARANASI"`!)<br>• `utr_or_rrn`<br>• `post_tx_available_balance_inr` |
| **4. `BENEFICIARY_ADDITION_ALERT`** | Contains (`beneficiary` \| `payee`) AND (`added` \| `registered` \| `activated` \| `modified` \| `cooling period`). | • `beneficiary_name`<br>• `beneficiary_masked_account` & `beneficiary_ifsc`<br>• **Feeds directly into Module 3.3's `bank_beneficiaries_and_cooling_audit` table!** |
| **5. `OTP_AUTHENTICATION_CODE`** | Contains (`OTP` \| `One Time Password` \| `verification code` \| `auth code` \| `secret code`) AND a 4-to-8 digit numeric code. | • **`otp_code_digits`** (4, 6, or 8 digits)<br>• **`otp_purpose_type`** (`TXN_DEBIT_APPROVAL`, `LOGIN_AUTH`, `BENEFICIARY_ADD`, `UPI_MPIN_RESET`, `AADHAAR_EKYC`, `CRYPTO_WITHDRAWAL`)<br>• **`otp_linked_amount_inr`** (if the OTP SMS states `"OTP for transaction of Rs. 49,999..."`) |
| **6. `LIEN_HOLD_OR_FREEZE_ALERT`** | Contains (`lien` \| `hold` \| `freeze` \| `frozen` \| `blocked` \| `debit freeze` \| `cyber crime` \| `NCRP` \| `1930` \| `disputed`). | • **`lien_or_hold_amount_inr`**<br>• `masked_account_or_card`<br>• **`ncrp_acknowledgement_or_ref_no`** (14/15-digit NCRP Ack No or disputed 12-digit UTR!)<br>• **Immediate `CRITICAL` flag in Module 3.5!** |
| **7. `UPI_DEVICE_BINDING_OR_MPIN`** | Contains (`UPI registration` \| `device binding` \| `UPI PIN set` \| `MPIN changed` \| `linked to UPI`). | • `masked_account_or_card`<br>• `upi_app_or_vpa`<br>• **Corroborates Module 3.2's SIM-binding timeline!** |
| **8. `UPI_AUTOPAY_OR_MANDATE`** | Contains (`mandate` \| `autopay` \| `e-mandate` \| `standing instruction` \| `UMN`). | • `amount_inr_decimal`, `merchant_name`, `umn_reference`. |
| **9. `FAILED_OR_DECLINED_TX`** | Contains (`failed` \| `declined` \| `unsuccessful` \| `dishonoured` \| `insufficient balance` \| `invalid PIN` \| `limit exceeded`). | • `amount_inr_decimal`, `masked_account_or_card`, `decline_reason`, `utr_or_rrn`. |
| **10. `PROMOTIONAL_SPAM_IGNORED`** | DLT suffix == `-P` OR contains (`pre-approved` \| `instant loan` \| `apply now` \| `bonus` \| `rummy` \| `fantasy`). | Logged as `IGNORED_SPAM` so it never contaminates the financial ledger. |

### 5.2 Exact Field Extraction Rules for Indian Bank SMS Formats

1. **INR Amount Extraction Rule (Handling Indian Lakh/Crore Commas):**
   * Match currency markers `(?:Rs\.?|INR|₹|Amt)\s*[:\-]?\s*([0-9]{1,3}(?:,[0-9]{2,3})*(?:\.[0-9]{1,2})?|[0-9]+(?:\.[0-9]{1,2})?)`.
   * Strip all `,` characters from Capture Group 1 and parse as a 64-bit float (`amount_inr_decimal`).
   * *Important Disambiguation:* An SMS often contains **two** currency amounts: the **Transaction Amount** (`debited by Rs. 25,000.00`) and the **Available Balance** (`Avl Bal: Rs. 1,14,200.50`). Always extract the **`post_tx_available_balance_inr`** first (by matching the amount immediately following `Avl Bal`, `Available Bal`, `Bal`, `Clear Bal`, `Closing Bal`, or `Updated Bal`), and extract the **Transaction Amount** from the debit/credit verb clause!
2. **Account & Card Mask Normalization (`account_tail_digits`):**
   * Match `(?:A/c|Acct|Account|Card)\s*(?:no\.?|number|ending)?\s*([X\*x#0-9\-]*[0-9]{3,6})`.
   * Extract the final $4\text{ numeric digits}$ (or 3 digits if only 3 are shown by the bank, such as SBI's `A/c X1234` vs. ICICI's `Acct XX890`) as `account_tail_digits`.
3. **12-Digit UPI / IMPS `UTR` vs. 16–22 Character NEFT / RTGS `UTR`:**
   * Match `(?:Ref\s*(?:No\.?)?|UTR|RRN|IMPS\s*Ref|UPI\s*Ref|UPI:|txn\s*id)\s*[:\-]?\s*([A-Z0-9]{12,22})`, OR a standalone 12-digit number inside `UPI/<DR|CR>/<12_digits>/` or `(UPI Ref no 630914829104)`.

---

## 6. Step 4 — Sub-Engine 3.4D: OS Notification Ledgers (`DuetExpertCenter`, Biome & Android Notifications)

Even when a suspect deletes both the UPI app and their SMS inbox, operating-system notification subsystems preserve evidence of incoming payment alerts:

### 6.1 iOS `DuetExpertCenter` (`/private/var/mobile/Library/DuetExpertCenter/streams/notificationAndSuggestionDB.db`)
1. Stage `notificationAndSuggestionDB.db` (and `-wal`) via Module 1.1 and process via Module 2.1 (Active + `-wal` + Freelist).
2. Query the 36-column **`notifications`** table, filtering for rows where the bundle identifier column (`app_bundle_id` / `bundle_id` / `source_id`) matches any financial, UPI, banking, or crypto app from Module 1.3 (e.g., `com.phonepe.PhonePeApp`, `com.google.paisa`, `com.one97.paytm`, `com.sbi.lotusintouch`):
   * Extract the notification UUID, `bundle_id`, `timestamp` / `creation_date` (Apple Cocoa seconds — convert via Module 1.2!), `thread_id`, `category_id`, and user engagement flags (`Dismissed`, `Cleared`, `Engaged`/`Opened`).
   * **Mandatory Courtroom Reporting Tag:** Set `is_metadata_only_no_body = 1` on every `DuetExpertCenter` row. As documented in the Master Register, `DuetExpertCenter` proves **that the suspect's iPhone received a notification from that financial app at that exact timestamp and whether the suspect tapped/opened it** (retained for $\approx 60\text{ days}$ observed), even though the payment amount/body text is not stored in `DuetExpertCenter`.

### 6.2 iOS Apple Biome Notification Streams (`SEGB v1` & `v2`)
Query **Phase 2, Module 2.3C (`biome_segb_records_master`)** for Biome streams matching `Notification*`, `AppNotification*`, or `UserNotificationEvents`:
* Extract both active (`state == 1`) and deleted (`state == 3`) SEGB records where the bundle ID belongs to a financial, UPI, or crypto application.
* Extract `segb_write_utc_iso`, `payload_event_utc_iso`, notification `title`, `subtitle`, `body` (if present in the stream's protobuf), and `thread_id`.

### 6.3 Android Notification History, `NotificationListener` Caches & `adb bugreport` Dumps
Scan three Android notification sources for financial/UPI package names:
1. **`/data/system_ce/<user_id>/notification_history/` (Android 11–17 Notification History Protobufs):**
   * Decode the binary protobuf files inside `/notification_history/` via Module 2.3D to extract historical dismissed notifications (`package_name`, `title`, `text` — which often reads `"Received ₹15,000 from RAHUL SHARMA on PhonePe"`, and `posted_time_ms`).
2. **`adb bugreport` Notification Manager Service (`dumpsys notification`) Archive (`ALEAPP v2026.4.5` compatible):**
   * If a logical `bugreport` `.zip` was ingested in Module 1.1, parse the `NotificationRecord` entries inside `dumpsys notification` to extract active and recently archived notifications.
3. **Third-Party Notification-Logger / Smart-Watch Companion Databases:**
   * If the phone has a smartwatch companion app (`NoiseFit`, `boAt Crest`, `Zepp`, `Mi Fitness`, `Galaxy Wearable`) or a notification-saver app installed, query its SQLite database in `/data/user/0/<watch_pkg>/databases/`—smartwatch companion apps frequently log the full text of every incoming WhatsApp, SMS, and UPI push notification in plaintext SQLite to Bluetooth-sync them to the watch!

---

## 7. Database Schema for Module 3.4 (`dlt_sms_and_notifications_engine.sqlite`)

The developer must create the following three tables in the case database:

### Table 1: `dlt_financial_sms_ledger` (All Extracted Layer-2 Financial & OTP SMS Records)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `fin_sms_uid` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Unique row ID for each extracted financial or OTP SMS. |
| `source_vfs_file_id` | `INTEGER` | `NOT NULL` | Foreign key to `mmssms.db`, `bugle_db`, or `sms.db` in `vfs_index`. |
| `source_db_type` | `TEXT` | `NOT NULL` | Enum: `ANDROID_MMSSMS_DE`, `ANDROID_BUGLE_CE`, `IOS_SMS_DB_TEXT`, `IOS_SMS_DB_ATTRIBUTED_BODY`. |
| `original_sms_rowid` | `INTEGER` | `NULL` | Original `_id` or `ROWID` in the source SMS table. |
| `recovery_classification` | `TEXT` | `NOT NULL` | Mandatory 6-State Enum (`ORIGINAL_RECORD`, `HISTORICAL_COMMITTED_RECORD` \[`-wal`\], `RESIDUAL_RECORD` \[freelist carved\], etc.). |
| `raw_sender_address` | `TEXT` | `NOT NULL` | Exact sender header (e.g., `"AD-SBIINB-S"`, `"JX-HDFCBK-S"`). |
| `dlt_operator_and_circle` | `TEXT` | `NULL` | Decoded telco and circle (e.g., `"Airtel — Delhi NCR"`). |
| `dlt_entity_code` | `TEXT` | `NULL` | 6-char DLT entity ID (e.g., `"SBIINB"`, `"HDFCBK"`). |
| `dlt_category_suffix` | `TEXT` | `NULL` | `"S"` (Service), `"T"` (Transactional), `"G"` (Govt), or `"P"` (Promotional). |
| `resolved_institution_name` | `TEXT` | `NOT NULL` | E.g., `"State Bank of India (SBI)"`, `"HDFC Bank"`. |
| `sms_event_category` | `TEXT` | `NOT NULL` | 10-Category Enum from Section 5.1 (`TX_DEBIT_OUTFLOW`, `TX_CREDIT_INFLOW`, `ATM_CASH_WITHDRAWAL`, `OTP_AUTHENTICATION_CODE`, `LIEN_HOLD_OR_FREEZE_ALERT`, etc.). |
| `masked_account_or_card` | `TEXT` | `NULL` | Extracted account/card string (e.g., `"XX4821"`). |
| `account_tail_digits` | `TEXT` | `NULL` | Normalized last 3–4 digits (`"4821"`) for Module 3.5 joining. |
| `payment_rail` | `TEXT` | `NULL` | `UPI`, `IMPS`, `NEFT`, `RTGS`, `ATM`, `POS`, `ECOM`, `NACH`. |
| `utr_or_rrn_reference` | `TEXT` | `NULL` | Extracted 12-digit numeric UTR/RRN or 16–22 char NEFT/RTGS UTR (indexed!). |
| `amount_inr_decimal` | `REAL` | `NULL` | Parsed transaction/lien/OTP amount in INR (`₹`). |
| `post_tx_available_balance_inr` | `REAL` | `NULL` | Parsed available balance in INR (`₹`) immediately following this SMS! |
| `counterparty_vpa_or_name` | `TEXT` | `NULL` | Extracted VPA handle or beneficiary/sender name. |
| `atm_location_or_otp_digits` | `TEXT` | `NULL` | ATM terminal ID + location (if `ATM_CASH_WITHDRAWAL`), 4–8 digit OTP (if `OTP`), or NCRP Ack No (if `LIEN_HOLD_OR_FREEZE_ALERT`). |
| `android_sub_id` | `INTEGER` | `NULL` | `sms.sub_id` value. |
| `receiving_sim_iccid` | `TEXT` | `NULL` | Joined 20-digit `ICCID` from Module 3.2 (`device_sim_card_history_ledger`)! |
| `carrier_smsc_number` | `TEXT` | `NULL` | `sms.service_center` (`+9198...`). |
| `is_spoofed_sms_suspected` | `INTEGER` | `DEFAULT 0` | `1` if `service_center` is missing/anomalous on an Android inbox SMS (Section 4.3). |
| `full_sms_body_text` | `TEXT` | `NOT NULL` | Complete decoded SMS text (or unpacked iOS `attributedBody` text). |
| `received_utc_ns` | `INTEGER` | `NOT NULL` | Normalized 64-bit UTC nanoseconds. |
| `received_utc_iso` | `TEXT` | `NOT NULL` | Normalized UTC ISO-8601 timestamp (`YYYY-MM-DDTHH:MM:SS.fffZ`). |

### Table 2: `os_financial_notification_ledger` (Layer-3 `DuetExpertCenter`, Biome & Android Notification Records)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `fin_notif_uid` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Unique row ID. |
| `source_vfs_file_id` | `INTEGER` | `NOT NULL` | Source file in `vfs_index`. |
| `notification_subsystem` | `TEXT` | `NOT NULL` | Enum: `IOS_DUET_EXPERT_CENTER`, `IOS_BIOME_SEGB`, `ANDROID_NOTIF_HISTORY_PROTO`, `ANDROID_BUGREPORT_DUMP`, `SMARTWATCH_COMPANION_DB`. |
| `recovery_classification` | `TEXT` | `NOT NULL` | 6-State Enum (`ORIGINAL_RECORD`, `HISTORICAL_COMMITTED_RECORD`, `RESIDUAL_RECORD`, `PARTIAL_RECORD`). |
| `target_app_bundle_or_pkg` | `TEXT` | `NOT NULL` | E.g., `com.phonepe.PhonePeApp`, `com.google.android.apps.nbu.paisa.user`. |
| `is_metadata_only_no_body` | `INTEGER` | `NOT NULL DEFAULT 0` | **`1` for `IOS_DUET_EXPERT_CENTER`** (proves notification arrival & user engagement only; no preview body); `0` when title/body text is present. |
| `notif_title_text` | `TEXT` | `NULL` | Notification title (if `is_metadata_only_no_body == 0`). |
| `notif_body_text` | `TEXT` | `NULL` | Notification body text (if `is_metadata_only_no_body == 0`). |
| `extracted_amount_inr` | `REAL` | `NULL` | Amount in INR parsed from `notif_body_text` (if present). |
| `extracted_utr_reference` | `TEXT` | `NULL` | 12-digit UTR parsed from `notif_body_text` (if present). |
| `user_interaction_state` | `TEXT` | `NULL` | E.g., `OPENED_ENGAGED`, `DISMISSED`, `CLEARED`. |
| `delivered_utc_iso` | `TEXT` | `NOT NULL` | Normalized UTC ISO-8601 delivery timestamp. |

---

## 8. Developer Acceptance Test Checklist for Module 3.4

1. **The iOS 18/26 `attributedBody` Null-Text Unpacker Test:** Create a test `sms.db` row where `message.text = NULL` and `message.attributedBody` contains a binary `typedstream` blob with `"NSString"` + `01 94 84 01 2B` + length `0x81 74 00` ($116\text{ bytes}$) encoding `"Dear Customer, Rs.1,25,000.00 debited from A/c XX4821 on 05Nov26 to VPA mule@ybl. UPI Ref 630914829104. Avl Bal Rs.4,500.25"`. Verify that Sub-Engine 3.4A unpacks `attributedBody`, strips the Indian Lakh comma from `1,25,000.00` to output `125000.00`, extracts UTR `630914829104`, and records `post_tx_available_balance_inr = 4500.25`.
2. **The TRAI `-P` Promotional Loan Spam Rejection Test:** Feed two SMS messages into Sub-Engine 3.4B/3.4C:
   * Message 1: Sender `"VM-HDFCBK-P"`, Body: `"Congrats! Pre-approved Loan of Rs. 5,00,000 credited to your offer account! Click http://hdfc.lo/xyz"`.
   * Message 2: Sender `"VM-HDFCBK-S"`, Body: `"Rs. 5,00,000.00 credited to A/c XX4821 on 05-11-26 by IMPS Ref 630999887766. Avl Bal: Rs. 5,10,000.00"`.
   * Verify that Message 1 is classified as `PROMOTIONAL_SPAM_IGNORED` and excluded from the transaction ledger, while Message 2 is classified as `TX_CREDIT_INFLOW`.
3. **The `1930` Cybercrime Lien & SMSC Spoof Detection Test:** Insert a bank SMS reading `"Hold of INR 45,000.00 marked on A/c XX4821 for Cyber Crime Ack No 33111260048291"` with `service_center = "+919820005444"`, and a second fake credit SMS with `service_center = NULL` and `creator = "com.fake.sms.maker"`. Verify that the first triggers a `LIEN_HOLD_OR_FREEZE_ALERT` (extracting Ack No `33111260048291`), and the second is flagged with `is_spoofed_sms_suspected = 1`.
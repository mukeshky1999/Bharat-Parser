# Engineering Specification: Phase 3, Module 3.1 — Dedicated UPI Super-App Sandbox Decoders (`PhonePe`, `Google Pay India`, `Paytm`, `BHIM`, `WhatsApp Pay`, `FamPay`, `CRED`, `Navi`, `super.money` & Universal UPI QR/TLV Decoder)

**Document Purpose:** This document provides the complete, step-by-step architectural blueprint for building **Module 3.1** of the Forensic Data Parser. It contains **zero programming code** and explains every internal database schema, schema-fingerprinting algorithm, nested JSON/Protobuf column structure, currency unit conversion (`Paise` vs. `google.type.Money` vs. `Micros`), in-app P2P chat store, **UPI Lite / UPI Circle** on-device ledger, and **EMVCo / BharatQR TLV** parser from first principles so that any developer can build a commercial-grade Indian UPI sandbox decoder.

---

## 1. Purpose & Mental Model (How Indian UPI Super-Apps Actually Store Data)

A beginner developer assumes that an application like **PhonePe**, **Google Pay India**, or **Paytm** stores all of its transactions inside a single SQLite table called `transactions` inside a single file called `upi.db`. **In reality, modern Indian UPI Super-Apps distribute a single payment's forensic trail across five distinct internal storage subsystems inside their application sandbox:**

1. **Dynamic / User-Hashed SQLite & Room Databases (`/databases/` on Android; `Documents/` & `Application Support/` on iOS):**
   * To support account switching and multi-module isolation, apps like PhonePe and Google Pay India dynamically name their SQLite databases using the logged-in user's internal ID hash or Google Account ID (for example, `bullhorn_7f8a9d2c.db`, `phonepe_core_918273.db`, or `10492817263_paisa.db`).
   * Instead of storing 30 separate SQLite columns, modern Android **Jetpack Room** and iOS **CoreData** schemas store 5 or 6 indexed lookup columns (`tx_id`, `timestamp`, `status`, `type`) and pack the remaining 40 transaction fields inside a **single `TEXT` (JSON) column** or a **single `BLOB` (Protocol Buffer) column**.
2. **In-App P2P Messaging & Split-Bill Databases (`Bullhorn` / `StreamItems` / `Chat`):**
   * Every major Indian UPI app is also an instant messenger. Suspects, mule handlers, hawala operators, and extortionists frequently communicate **inside the payment chat thread of Google Pay India, PhonePe, Paytm, or FamPay** because they assume investigators only examine WhatsApp and Telegram.
3. **VPA Name-Verification & Pre-Transaction Lookup Caches:**
   * Before a user enters their UPI MPIN to send money, the app sends the recipient's VPA (`victim@okaxis`) or 10-digit mobile number to the NPCI switch (`ReqValAdd` API) to fetch the recipient's **Official Core Banking Solution (CBS) Account Holder Name**. The app caches that verified banking name locally—**even if the suspect cancels the payment and never sends a single Rupee**.
4. **Tencent `MMKV` & `shared_prefs` Key-Value Stores (Processed via Phase 2, Module 2.3A):**
   * Holds the active user profile, registered mobile number, linked bank account masks (`XXXX1234` + IFSC), **UPI Lite** on-device wallet balance, and—inside `MMKV` Layer 2 (superseded appends) and Layer 3 (mmap slack)—**historical profiles of previous mule accounts that logged out of the app prior to seizure**.
5. **Embedded `app_webview` & `NSURLCache` Passbook Caches (Processed via Phase 2, Module 2.4):**
   * Apps like Paytm, Amazon Pay, CRED, and banking super-apps fetch historical passbook statements via REST APIs and cache the Brotli/Gzip-compressed JSON responses inside `app_webview/Default/Cache/Cache_Data/*_0` or iOS `Cache.db`.

---

## 2. The 6 Fatal Mistakes Beginner Developers Make in UPI App Parsing

Before writing a single line of logic for Module 3.1, the developer must understand six critical traps that cause existing forensic tools to miss or misreport UPI evidence:

### Mistake 1: Hardcoding Database Filenames Instead of Using Schema-Fingerprint Discovery
* **The Trap:** Writing code that checks `if file_exists("/data/user/0/com.phonepe.app/databases/transactions.db")` and stops if that exact filename does not exist.
* **Why It Fails:** PhonePe, Google Pay India, Paytm, and CRED append account-specific hashes, user IDs, or version integers to their database filenames, and rename databases across major app updates.
* **The Rule:** Never rely on a hardcoded `.db` filename. For every resolved UPI app sandbox (from Module 1.3), enumerate **all** files inside `/databases/` (Android) and `Documents/` / `Library/Application Support/` (iOS) whose first 16 bytes equal `"SQLite format 3\0"` (or unwrap via Module 2.2 if SQLCipher-encrypted), inspect their table and column names in `sqlite_schema`, and route each table to the matching parser using the **Table Schema Fingerprint Rules** in Sections 3–6.

### Mistake 2: Confusing the Three Currency Encodings (`Paise`, `google.type.Money`, and `Micros`)
* **The Trap:** Dividing every integer amount by $100$, or forgetting to divide at all.
* **Why It Fails:** Indian UPI apps use **three different mathematical representations** for Indian Rupees (`INR`):
  1. **Integer Paise (`PhonePe`, `Paytm`, `BHIM`, `Razorpay`, `CRED`):** $₹1.00 = 100\text{ Paise}$. An integer column value of `250050` means:
     $$\text{INR} = \frac{250050}{100} = ₹2,500.50$$
  2. **Google `google.type.Money` Protobuf (`Google Pay India`):** Stores currency as a nested Protobuf message with three fields:
     * Field 1 (`currency_code`, `String`): `"INR"`
     * Field 2 (`units`, `int64`): Whole Rupees (e.g., `2500`)
     * Field 3 (`nanos`, `int32`): Nano-Rupees ($10^{-9}\text{ INR}$, e.g., `500000000` for $0.50\text{ INR}$).
     $$\text{INR} = \text{units} + \left(\frac{\text{nanos}}{10^9}\right)$$
  3. **Currency Micros (`Google Pay Legacy / Analytics Protobufs`):** Stores $₹1.00 = 1,000,000\text{ Micros}$ ($10^6$). An integer value of `2500500000` in a `micros` field means:
     $$\text{INR} = \frac{2500500000}{10^6} = ₹2,500.50$$
* **The Rule:** Always apply the exact currency conversion formula dictated by the specific column or Protobuf field definition, and record both the raw value and the normalized `amount_inr_decimal`.

### Mistake 3: Missing `UPI Lite` (On-Device Wallet) and `UPI Circle` (Delegated Payments)
* **The Trap:** Assuming every UPI transaction generates a bank SMS in `mmssms.db` and has a 12-digit core-banking UTR.
* **Why It Fails:**
  * **UPI Lite (NPCI On-Device Small-Value Wallet):** Allows users to load up to ₹4,000/₹5,000 into an on-device cryptographic balance and make instant PIN-less payments up to ₹500/₹1,000. **Crucial Forensic Fact:** Individual UPI Lite debit payments **do NOT hit the bank's core banking SMS switch in real time**. Only the initial "Top-Up" generates a bank SMS; all individual merchant/P2P payments made via UPI Lite exist **exclusively inside the UPI app's local sandbox database and `MMKV` store**.
  * **UPI Circle (NPCI Delegated Payments):** Allows a Primary User (`primary_vpa`) to authorize a Secondary User (`secondary_vpa`, often a family member, employee, or mule) to spend from the Primary User's bank account up to a monthly limit.
* **The Rule:** Explicitly parse `UPI_LITE` and `UPI_CIRCLE` tables and JSON tags, flagging them so the investigator understands why no corresponding carrier SMS exists for a UPI Lite debit.

### Mistake 4: Failing to Parse Scanned QR Codes (`upi://pay` URIs & EMVCo BharatQR TLV Strings)
* **The Trap:** Ignoring raw strings starting with `upi://pay?` or `0002010102...` inside SQLite, `MMKV`, or WebView logs.
* **Why It Fails:** When a suspect scans a merchant or hawala courier's QR code at a physical shop, hotel, or petrol pump, the UPI app logs the **entire raw QR payload string** along with the scan timestamp and device GPS coordinates. That QR string contains the merchant's full VPA, legal business name, **4-digit Merchant Category Code (`MCC`)**, city, **6-digit Indian PIN code (Postal Code)**, and terminal ID.
* **The Rule:** Pass every discovered `upi://` URI and `000201...` string through **Sub-Engine 3.1E (The Universal UPI URI & EMVCo BharatQR TLV Decoder)** specified in Section 7.

### Mistake 5: Ignoring WhatsApp's Built-In UPI Payment Ledger (`WhatsApp Pay`)
* **The Trap:** Treating WhatsApp (`com.whatsapp` / `net.whatsapp.WhatsApp`) solely as a chat app (Group 1) and forgetting that WhatsApp is a licensed NPCI TPAP (`@waicici`, `@wahdfcbank`, `@waaxis`, `@wasbi`).
* **Why It Fails:** If a suspect sends or receives money using **WhatsApp Pay**, the transaction does not appear in PhonePe or Google Pay—it is stored inside WhatsApp's own `msgstore.db` (`pay_transaction` table on Android) and `ChatStorage.sqlite` (on iOS), linked directly to the chat message bubble.
* **The Rule:** Sub-Engine 3.1D must scan WhatsApp's `msgstore.db` and `ChatStorage.sqlite` for UPI payment tables and message types, routing financial rows into Group 13 while preserving the chat link in Group 1.

### Mistake 6: Failing to Run Phase 2's Shared `-wal` & Freelist Carver Before Querying UPI Databases
* **The Trap:** Querying PhonePe or GPay databases with standard SQLite `SELECT` statements only.
* **Why It Fails:** UPI apps frequently prune old local cache rows or update a transaction row in place from `INITIATED` $\rightarrow$ `PENDING` $\rightarrow$ `COMPLETED` (or `FAILED`). When a user clears a P2P chat inside GPay or PhonePe, the deleted chat rows sit inside the `-wal` file and B-Tree `0x0D` Freeblocks.
* **The Rule:** Every SQLite database opened by Module 3.1 **must** be processed through **Phase 2, Module 2.1 (Pipelines A, B, and C)** so active rows, historical `-wal` frames, and carved freelist/freeblock rows are all captured.

---

## 3. Sub-Engine 3.1A — PhonePe & PhonePe Business Deep Sandbox Decoder

* **Target Identifiers (Query via Module 1.3 `resolve_app_targets`):**
  * **Android Consumer:** `com.phonepe.app` (across all user profiles: `User 0`, `Work 10`, `Dual 95`, `Secure Folder 150`, `Cloner 999`).
  * **Android Merchant / Business:** `com.phonepe.app.business`.
  * **iOS Consumer & Business:** `com.phonepe.PhonePeApp`, `com.phonepe.business`.
* **Associated VPA Handles:** `@ybl` (Yes Bank), `@ibl` (ICICI Bank), `@axl` (Axis Bank).

### 3.1 Step 1: Schema-Driven SQLite Database Discovery in `/databases/`
Enumerate every SQLite file inside the resolved PhonePe sandbox (`databases/` on Android; `Documents/`, `Library/Application Support/` on iOS). Match each table in `sqlite_schema` (across active, `-wal`, and freelist records via Module 2.1) against these **four PhonePe Subsystem Fingerprints**:

#### Subsystem 1: Core Transaction & Workflow Ledger
* **Candidate Database Names:** `phonepe*.db`, `transaction*.db`, `history*.db`, `workflow*.db`, `core*.db`, `zphonepe*.sqlite`.
* **Table Fingerprint Match:** Any table whose column list contains at least three of: `transactionId` (or `txnId` / `unitId`), `amount` (or `amountInPaise`), `state` (or `status` / `paymentState`), `utr` (or `bankReferenceNo`), `createdAt` (or `creationTime` / `updatedAt`), `workflowType` (or `instrumentType`).
* **Field Extraction & Normalization Rules:**
  1. **Primary & NPCI Identifiers:**
     * Extract `transactionId` / `unitId` / `merchantOrderId` (e.g., `T2611051430229182736451` or `NX261105...`).
     * Extract `utr` / `bankReferenceNo` / `upiTransactionId` (12-digit NPCI UTR/RRN).
  2. **Amount Normalization:**
     * PhonePe stores amounts in **Integer Paise** (`amountInPaise` or `amount`). Divide integer by $100.0$ to populate `amount_inr_decimal`.
  3. **Deep JSON Column Unpacking:**
     * PhonePe's Room entities include a serialized JSON column named `data`, `payload`, `rawPayload`, `workflowData`, `paymentInstrument`, or `extraInfo`. Parse that JSON string and extract:
       * `payerVpa` / `sender.vpa` / `fromVpa` $\rightarrow$ `sender_vpa`
       * `payeeVpa` / `receiver.vpa` / `toVpa` / `merchantVpa` $\rightarrow$ `receiver_vpa`
       * `payeeName` / `bankingName` / `accountHolderName` / `merchantName` $\rightarrow$ `counterparty_cbs_name`
       * `accountNumber` / `maskedAccountNumber` (e.g., `"XXXXXX4821"`) & `ifsc` (e.g., `"SBIN0001234"`) & `bankName`
       * `instrumentType`: `ACCOUNT` (standard UPI bank transfer), `UPI_LITE` (on-device PIN-less wallet), `RUPAY_CREDIT_ON_UPI` (RuPay Credit Card linked to UPI), `WALLET` (PhonePe Wallet), `CREDIT_LINE` (UPI Credit Line).
       * `flowType` / `direction`: `DEBIT` (`PAY` / `SEND`), `CREDIT` (`RECEIVE`), `COLLECT` (Collect request).
       * `note` / `remarks` / `message`: User-typed transaction remark.
       * `qrData` / `intentUrl`: Pass directly to **Sub-Engine 3.1E (QR/URI Decoder)**.

#### Subsystem 2: The `Bullhorn` Messaging & P2P Chat Subsystem
* **What `Bullhorn` Is:** PhonePe's internal synchronization and peer-to-peer messaging engine. Whenever two PhonePe users chat with each other inside the app, send payment bubbles, request money, or receive server-synced transaction updates, the payloads are stored inside `bullhorn_*.db` or `chat_*.db`.
* **Table Fingerprint Match:** Tables named `message`, `bullhorn_message`, `topic`, `conversation`, `chat_entry`, or any table containing columns `topicId`, `messageId`, `payload` (or `messageData`), `createdAt`, `senderId`.
* **How to Unpack a `Bullhorn` Message Row:**
  1. Read `topicId` / `conversationId`, `messageId`, `createdAt` (13-digit Unix ms), and `updatedAt`.
  2. Inspect the `payload` (or `data` / `body`) column:
     * Check if `payload` starts with `{` (raw JSON) or valid Base64 (decode Base64 $\rightarrow$ check if bytes start with Gzip magic `1F 8B` $\rightarrow$ decompress $\rightarrow$ parse JSON).
     * Inside the decoded JSON, check `type` / `messageType`:
       * If `TEXT_MESSAGE` / `CHAT`: Extract `text`, `senderVpa` / `senderPhone`, `receiverVpa` / `receiverPhone`, and store in `upi_in_app_p2p_chats`.
       * If `PAYMENT_BUBBLE` / `TRANSACTION_UPDATE` / `SPLIT_BILL`: Extract the embedded `utr`, `amountInPaise`, `state`, and `payer`/`payee` details.

#### Subsystem 3: VPA Verification, Beneficiary & Contact Resolution Cache
* **Table Fingerprint Match:** Tables matching `vpa*`, `beneficiary*`, `payee*`, `contact*`, or containing columns `vpa`, `verifiedName` (or `accountHolderName` / `bankingName`), `phoneNumber`.
* **Forensic Value:** Extract every row into `upi_scanned_qr_and_vpa_lookups`. If a row exists here for `hawala_operator@ybl` with `verifiedName = "MOHAMMAD IMRAN"`, but zero rows exist in the transaction table for `hawala_operator@ybl`, set `was_name_verified_without_tx = 1`—proving the suspect typed that exact VPA into PhonePe and verified the recipient's bank identity.

#### Subsystem 4: PhonePe Business (`com.phonepe.app.business`)
* If `com.phonepe.app.business` is present on the handset, extract:
  * **Merchant Profile:** `merchantId` (`MID`), `storeName`, `mcc` (Merchant Category Code), registered GST/PAN metadata, and the **Settlement Bank Account + IFSC** where daily QR collections are swept.
  * **SmartSpeaker / VoiceBox Notification Ledger:** Logs every incoming customer QR payment announced by the app (`utr`, `customerVpa`, `customerMaskedPhone`, `amountInPaise`, `timestamp`).

### 3.2 Step 2: PhonePe `MMKV` (`files/mmkv/`) & `shared_prefs` Extraction
Query **Phase 2, Module 2.3A (`kv_recovered_records_master`)** for all `MMKV` files and `shared_prefs/*.xml` inside PhonePe's sandbox:
1. Extract the active (`ORIGINAL_RECORD`) and **historical overwritten (`HISTORICAL_COMMITTED_RECORD` / `RESIDUAL_RECORD`)** values for:
   * **User Identity:** `user_id`, `phone_number`, `vpa_list`, `primary_vpa`, `kyc_name`, `email`.
   * **UPI Lite On-Device State:** `lite_account_id`, `lite_balance`, `lite_lrn` (Lite Reference Number), `last_topup_timestamp`.
   * **Location Cache:** Last known GPS `latitude`, `longitude`, `city`, and `pincode` recorded during app launch or QR payment.
2. **Account-Switching Detection Rule:** If `MMKV` Layer 2 (Superseded Appends) or Layer 3 (Mmap Slack) contains a different `user_id`, `phone_number`, or `primary_vpa` than Layer 1 (Active), automatically flag a **`MULTIPLE_UPI_ACCOUNTS_OPERATED_ON_SAME_APP`** alert.

---

## 4. Sub-Engine 3.1B — Google Pay India (`nbu.paisa.user`) Deep Sandbox & Protobuf Decoder

* **Target Identifiers (Query via Module 1.3 `resolve_app_targets`):**
  * **Android (Google Pay India / Tez):** `com.google.android.apps.nbu.paisa.user`
  * **iOS (Google Pay India):** `com.google.paisa`
  * *(Note: Keep strictly separate from Global Google Wallet `com.google.android.apps.walletnfcrel`).*
* **Associated VPA Handles:** `@okaxis` (Axis Bank), `@okhdfcbank` (HDFC Bank), `@okicici` (ICICI Bank), `@oksbi` (State Bank of India).

### 4.1 Step-by-Step Extraction of Google Pay India SQLite Databases
Enumerate all SQLite files inside `/data/user/<id>/com.google.android.apps.nbu.paisa.user/databases/` (and iOS `Documents/` / `Application Support/`). Process every `.db` file (and its `-wal` and freelist pages) through **Module 2.1**, and pass every `BLOB` column through **Module 2.3D (Schema-Less Protobuf Decoder)**:

#### 1. Participant & Counterparty Tables (`people`, `participants`, `contacts`, `vpa_directory`)
* Extract both the flat SQLite columns and the decoded Protobuf `BLOB` column (`participant_proto` / `blob_data` / `proto_bytes`):
  * **Counterparty Identifiers:** Google internal participant ID / Gaia ID, **Phone Number (`+919876543210`)**, and **VPA Handle** (e.g., `rahul@okaxis`).
  * **Dual Name Attribution:** Google Pay India stores **two distinct names** for every counterparty inside the participant Protobuf:
    1. `display_name` / `contact_name`: The nickname saved in the suspect's local phonebook or Google account (e.g., `"Boss Hawala"`).
    2. `banking_name` / `verified_name`: **The official KYC legal name registered at the counterparty's bank** returned by NPCI (e.g., `"RAJESH KUMAR VERMA"`).
  * **Counterparty Bank Details (IMPS / Bank Transfer Mode):** When direct bank transfer is used, the participant Protobuf stores the recipient's **Account Number (or mask)** and **11-character IFSC Code** (e.g., `HDFC0000123`).

#### 2. Stream Items, Transactions & P2P Chat Tables (`stream_items`, `transactions`, `payment_transactions`, `chat_messages`)
For every active, `-wal` historical, and freelist-carved row, classify the Stream Item Subtype:
* **Subtype A (`PAYMENT_TRANSACTION` / `UPI_TRANSFER`):**
  * **12-Digit UPI UTR / RRN:** Locate the 12-digit numeric string inside the Protobuf tree (validated via the `YDDD` Julian Day rule).
  * **Google Transaction ID:** Alphanumeric ID (typically starting with `CICAg...` or `PT_...`).
  * **Amount Extraction (The 3-Format GPay Check):**
    1. If `google.type.Money` (`Field 1 = "INR"`, `Field 2 = units`, `Field 3 = nanos`): Compute $\text{INR} = \text{units} + (\text{nanos} / 10^9)$.
    2. If single integer `amount_micros`: Compute $\text{INR} = \text{micros} / 10^6$.
    3. If flat SQLite integer column `amount_paise`: Compute $\text{INR} = \text{paise} / 100.0$.
  * **Direction, Status & Timestamps:** Map direction (`SENT` / `DEBIT`, `RECEIVED` / `CREDIT`, `COLLECT_REQUEST`), status (`SUCCESS`, `PENDING`, `FAILED`, `DECLINED`), `creation_time_ms`, `completion_time_ms`, and user-entered payment notes.
* **Subtype B (`IN_APP_CHAT_MESSAGE`):** Extract sender ID/VPA, receiver ID/VPA, message text, and timestamp into `upi_in_app_p2p_chats`.
* **Subtype C (`BILL_SPLIT_EXPENSE`):** Extract group name, total bill amount, each member's VPA/phone number, and whether each member's share is `PAID` or `UNPAID`.

#### 3. Local Linked Bank Accounts & UPI Lite (`bank_accounts`, `payment_methods`, `upi_lite`)
* Extract the suspect's own linked bank accounts: Bank Name, IFSC prefix, last 4 digits of account number (`XXXX1234`), account type (`SAVINGS`, `CURRENT`, `RUPAY_CREDIT`, `UPI_LITE`), and VPA handle (`@okaxis`, `@okhdfcbank`, `@okicici`, `@oksbi`).

---

## 5. Sub-Engine 3.1C — Paytm & Paytm for Business (`net.one97.paytm`, `com.paytm.business`) Deep Decoder

* **Target Identifiers:** Android `net.one97.paytm`, `com.paytm.business`; iOS `com.one97.paytm`, `com.one97.merchant`.
* **Associated VPA Handles:** `@ptyes` (Yes Bank), `@ptaxis` (Axis Bank), `@pthdfc` (HDFC Bank), `@ptsbi` (State Bank of India), and legacy `@paytm`.

### 5.1 Step-by-Step Paytm Sandbox Extraction Pipeline
1. **Layer 1 — Paytm SQLite & Room Databases (`/databases/`):**
   * **UPI & Passbook Ledger Tables (`passbook_entries`, `upi_transactions`, `transaction_table`, `wallet_txn`):** Extract 12-digit UPI `UTR` / `RRN`, Paytm `orderId`, `amount` (check decimal string vs. integer paise), `txnType` (`UPI`, `WALLET`, `FASTAG`, `POSTPAID`, `GIFT_VOUCHER`), `status`, `payerVpa`, `payeeVpa`, `counterpartyName`, `maskedAccountNo`, and `timestamp`.
   * **Recent Beneficiaries & Saved Payees (`beneficiary_table`, `recent_payees`, `upi_contacts`):** Extracts every bank account (`accountNumber` + `ifsc` + `holderName`) and VPA saved or paid by the suspect.
   * **Scanned QR Code History (`qr_scan_history`, `recent_qr`, `offline_merchant`):** Extracts the raw QR payload string (`upi://pay?...` or `000201...`), merchant name, scan timestamp, and cached GPS coordinates.
   * **Paytm In-App Chat (`chat_messages`, `p2p_chat`):** Extracts messages exchanged inside Paytm's payment chat threads.
2. **Layer 2 — Paytm `app_webview` & HTTP Cache Passbook Harvester:**
   * Query **Module 2.4's `webview_http_cache_records`** for all decompressed JSON bodies belonging to `net.one97.paytm` or `com.paytm.business`.
   * Scan JSON bodies for keys: `"txnList"`, `"passbookList"`, `"orderList"`, `"upiTxnId"`, `"rrn"`, `"bankTxnId"`, `"amount"`, `"narration"`, `"closingBalance"`, or `"fastagTollPlazaName"`, mapping each JSON transaction object into `upi_app_sandbox_transactions`.
3. **Layer 3 — Paytm `MMKV` & `shared_prefs`:**
   * Extract active and historical overwritten credentials: `custId`, `mobile`, `email`, `pan_masked`, active and previous `@ptyes`/`@ptaxis`/`@pthdfc`/`@ptsbi` VPA handles, **UPI Lite** balance, and **Paytm Soundbox / Merchant MID** settlement bank details.

---

## 6. Sub-Engine 3.1D — BHIM, WhatsApp Pay, FamPay, CRED, Navi, super.money, Slice, MobiKwik, Amazon Pay & BharatPe

### 6.1 Target 1: WhatsApp Pay (UPI Inside `com.whatsapp` & `net.whatsapp.WhatsApp`)
* **Associated VPA Handles:** `@waicici` (ICICI Bank), `@wahdfcbank` (HDFC Bank), `@waaxis` (Axis Bank), `@wasbi` (State Bank of India).
* **Inside Android `msgstore.db` (`/data/user/<id>/com.whatsapp/databases/msgstore.db`):**
  * Query the **`pay_transaction`** (and `pay_transactions` / `message_payment`) table across active, `-wal`, and freelist records via Module 2.1:
    * `id` / `key_id`: Joins directly to `message.key_id` or `message._id` in the main WhatsApp chat table.
    * `interop_id` / `tran_id` / `bank_transaction_id`: Contains the **12-digit UPI UTR / RRN**.
    * `sender_jid` & `receiver_jid`: The WhatsApp JIDs (`919876543210@s.whatsapp.net`) of the payer and payee.
    * `amount_1000`: Stores the amount in **thousandths of a Rupee ($\frac{1}{1000}\text{ INR}$)**:
      $$\text{INR} = \frac{\text{amount\_1000}}{1000}$$
    * `extra_data` / `country_data` (`TEXT` JSON or `BLOB`): Contains the **Payer VPA (`@waicici`, etc.)**, **Payee VPA**, **Verified CBS Banking Name**, **12-digit UPI UTR**, and masked bank account number.
* **Inside iOS `ChatStorage.sqlite`:** Extract payment rows from `ZWAPAYMENTTRANSACTION` / `ZWAMESSAGEINFO` and link to `ZWAMESSAGE`.

### 6.2 Target 2: BHIM (`in.org.npci.upiapp` — Official NPCI App)
* **Associated VPA Handle:** `@upi`.
* **Key Forensic Features Unique to BHIM:**
  1. **UPI Lite Ledger:** Full on-device `UPI_LITE` top-up and spend history (`LRN` — Lite Reference Number).
  2. **UPI Circle (Delegated Payment) Registry:** Explicitly lists whether this suspect's phone is acting as a **Primary Account Holder** (who delegated spending rights to another VPA/mobile number) or a **Secondary Delegated User** (who is spending money out of someone else's bank account), including delegation start time, monthly limit, and approval timestamps.
  3. **UPI Autopay / Mandate Ledger (`UMN` — Unique Mandate Number):** Lists all recurring mandates.

### 6.3 Target 3: High-Risk Youth, Neo-Bank & Credit UPI Apps

| Application | Package Name(s) | VPA Suffix(es) | Specific Sandbox Targets & Forensic Nuances |
|---|---|---|---|
| **FamPay** | `com.fampay.in` | `@fam`, `@fampay` | **Top Layer-1 Mule App:** Used by cybercrime syndicates because accounts/FamX prepaid cards can be operated by minors. Parse SQLite, `MMKV`, and `app_webview` for `@fam` UPI transfers, virtual/physical FamCard number masks, guardian approval phone numbers, and built-in P2P chat threads. |
| **Slice** | `indwin.c3.shareapp` | `@sliceaxis`, `@slice` | Credit/prepaid & UPI app (merged with North East Small Finance Bank). Extract credit-line drawdowns to bank accounts, `@sliceaxis` UPI ledger, and repayment UTRs. |
| **CRED** | `com.dreamplug.androidapp` | `@axisb`, `@yescred` | Extract all linked **Credit Card masks (`BIN` + last 4 digits + Issuing Bank)**, credit card bill payment UTRs, **CRED Cash** loan disbursements, **CRED Garage** (registered vehicle license plates), and UPI scan-and-pay history. |
| **Navi** | `com.naviapp` | `@naviaxis` | Parse SQLite, `MMKV`, and `app_webview` for `@naviaxis` UPI transfers and personal loan disbursement bank accounts. |
| **super.money** | `money.super.payments` | `@superyes` | Parse Room/SQLite and `MMKV` for `@superyes` VPA ledger, RuPay credit-on-UPI spends, and cashback history. |
| **MobiKwik** | `com.mobikwik_new` | `@ikwik` | Parse wallet-to-bank transfers, **Pocket UPI** (wallet-backed PIN-less UPI transfers that do not generate bank SMS alerts), and **ZIP** pay-later ledgers. |
| **Amazon Pay** | `in.amazon.mShop.android.shopping` | `@apl`, `@yapl`, `@rapl` | Query `webview_http_cache_records`, `Local Storage`, and SQLite for Amazon Pay UPI transfers and **Amazon Gift Card (`E-Gift Voucher`) purchase and redemption codes**. |
| **BharatPe** | `com.bharatpe.merchant` | `@bharatpe`, `@bpunity` | **Merchant Mule Target:** Extract Merchant ID, shop name, registered GPS location, **Settlement Bank Account + IFSC**, and daily QR collection ledgers. |

---

## 7. Sub-Engine 3.1E — Universal `upi://pay` Deep-Link URI & EMVCo BharatQR TLV Decoder

Whenever a suspect scans a QR code, clicks a payment link, or generates a receive-money QR code, the UPI app stores either a **`upi://pay` URI string** or an **EMVCo / BharatQR TLV (`Tag-Length-Value`) string**. Sub-Engine 3.1E decodes both formats across the entire device.

### 7.1 Decoding `upi://pay?...` & `upi://mandate?...` Deep-Link URIs

| Query Parameter | NPCI Field Name | Forensic Meaning & Extraction Rule |
|---|---|---|
| **`pa`** | `Payee Address (VPA)` | **The recipient's exact UPI VPA handle** (e.g., `merchant@icici`, `9876543210@ybl`). Run through Module 3.5's VPA Bank Resolver. |
| **`pn`** | `Payee Name` | The recipient's registered name or merchant shop name (e.g., `"SHREE BALAJI ENTERPRISES"`). |
| **`mc`** | `Merchant Category Code` | **4-digit ISO 18245 MCC** (e.g., `5411` = Grocery Store, `5812` = Restaurant, `7995` = **Betting/Casino Gambling**, `6051` = **Crypto/Quasi-Cash/Money Transfer**). |
| **`tid`** | `PSP Transaction ID` | Originating PSP transaction ID (if pre-populated). |
| **`tr`** | `Transaction Reference ID` | Merchant order ID or bill reference number (links directly to the merchant website or betting portal order). |
| **`tn`** | `Transaction Note` | Pre-filled payment remark / description. |
| **`am`** | `Transaction Amount` | Decimal Rupee amount requested by the QR/link (e.g., `"5000.00"`). |
| **`cu`** | `Currency Code` | `"INR"`. |
| **`mode`** | `Initiation Mode` | `01` = Static QR Code, `02` = Secure Static QR, `04` = Intent / In-App Deep Link, `05` = Secure Intent, `15` = Dynamic BharatQR. |
| **`orgid`** | `Organization ID` | 6-digit NPCI acquiring bank / PSP organization code. |
| **`sign`** | `Cryptographic Signature` | Base64 ECDSA signature of the QR code. |

### 7.2 Decoding EMVCo / BharatQR TLV (`000201...`) Strings

Many physical merchant QR stands encode a **BharatQR / EMVCo Merchant-Presented QR string**, which is a contiguous ASCII string always starting with **`000201`** (Tag `00`, Length `02`, Value `01`).

#### Step-by-Step EMVCo TLV Parsing Loop
Set cursor `pos = 0`. While `pos + 4 <= len(qr_string)`:
1. Read 2 ASCII characters as `tag_id = qr_string[pos : pos + 2]`.
2. Read 2 ASCII decimal digits as `val_len = int(qr_string[pos + 2 : pos + 4])`.
3. Read `val_str = qr_string[pos + 4 : pos + 4 + val_len]`.
4. Advance `pos = pos + 4 + val_len` and interpret `tag_id` using the complete BharatQR / NPCI EMVCo table below:

| EMVCo Tag | Field Name | Exact Decoding & Nested Sub-Tag Rules |
|---|---|---|
| **`00`** | `Payload Format Indicator` | Always `"01"`. |
| **`01`** | `Point of Initiation Method` | `"11"` = **Static QR Code** (printed sticker on shop counter); `"12"` = **Dynamic QR Code** (generated on POS screen for a specific bill amount). |
| **`02` – `15`** | `Card Network Merchant IDs` | Visa (`02`), Mastercard (`04`), RuPay (`06` / `08`) merchant identifiers inside dual BharatQR codes. |
| **`26`, `27`, `28`** | **`UPI Merchant Account Info (Nested TLV)`** | **Crucial:** Tags `26`, `27`, and `28` contain a **nested TLV string** inside `val_str`. Recursively run the `[2-char SubTag][2-digit Length][Value]` parser on `val_str` to extract:<br>• **Sub-Tag `00` (`GUID`):** `"A0000005240101"` or `"NPCI"` (identifies NPCI UPI).<br>• **Sub-Tag `01` (`Payee VPA`):** **The merchant's exact UPI VPA handle** (e.g., `bharatpe.90182736@bpunity`).<br>• **Sub-Tag `02` (`Minimum Amount / Bank IFSC+Acct`):** Optional floor amount or account routing string.<br>• **Sub-Tag `03` (`Transaction Reference / TR`):** Dynamic merchant order reference ID. |
| **`52`** | `Merchant Category Code (MCC)` | **4-digit ISO 18245 MCC** (e.g., `"5411"`, `"5812"`, `"7995"`). |
| **`53`** | `Transaction Currency` | `"356"` (ISO 4217 numeric code for Indian Rupee `INR`). |
| **`54`** | `Transaction Amount` | Decimal Rupee string (e.g., `"1250.00"`), present in Dynamic QR codes. |
| **`58`** | `Country Code` | `"IN"` (India). |
| **`59`** | `Merchant Legal Name` | Registered shop or business name (e.g., `"KASHI VISHWANATH TRADERS"`). |
| **`60`** | `Merchant City` | Registered city of the physical merchant shop (e.g., `"VARANASI"`, `"MUMBAI"`). |
| **`61`** | `Postal Code (PIN Code)` | **6-digit Indian Postal Index Number (PIN Code)** (e.g., `"221001"`). **Forensic Gold:** Even if GPS was turned off on the suspect's phone when scanning a physical BharatQR stand, Tag `60` + Tag `61` proves the exact city and 6-digit PIN code of the physical merchant shop! |
| **`62`** | **`Additional Data Field Template (Nested TLV)`** | Recursively parse `val_str` as a nested TLV to extract:<br>• **Sub-Tag `01` (`Bill Number`)**<br>• **Sub-Tag `02` (`Merchant Mobile Number`)**<br>• **Sub-Tag `03` (`Store Label`)**<br>• **Sub-Tag `05` (`Reference Label / Order ID`)**<br>• **Sub-Tag `07` (`Terminal ID / TID`)**: Identifies the exact POS machine or Soundbox terminal. |
| **`63`** | `CRC-16 Checksum` | 4-character hexadecimal **CRC-16/CCITT-FALSE** checksum (polynomial `0x1021`, initial value `0xFFFF`) computed over all preceding ASCII bytes of the QR string up to and including `"6304"`. |

---

## 8. Database Schema for Module 3.1 (`upi_superapp_sandbox_artifacts.sqlite`)

The developer must create the following four tables in the case database to store all Module 3.1 outputs (which then feed directly into Module 3.5's 4-Way UTR Correlator):

### Table 1: `upi_app_sandbox_transactions` (Normalized Layer-1 App Transactions)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `sandbox_tx_uid` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Unique row ID for each transaction extracted from a UPI app sandbox. |
| `app_instance_id` | `INTEGER` | `NOT NULL` | Foreign key to owning UPI app instance in Module 1.3 (`com.phonepe.app`, `nbu.paisa.user`, `net.one97.paytm`, etc.). |
| `source_vfs_file_id` | `INTEGER` | `NOT NULL` | Foreign key to exact `.db`, `mmkv`, or `*_0` cache file in `vfs_index`. |
| `source_subsystem` | `TEXT` | `NOT NULL` | E.g., `PHONEPE_WORKFLOW_DB`, `PHONEPE_BULLHORN_DB`, `GPAY_STREAM_ITEMS_PROTO`, `PAYTM_WEBVIEW_CACHE`, `WHATSAPP_PAY_TABLE`. |
| `recovery_classification` | `TEXT` | `NOT NULL` | Mandatory 6-State Enum (`ORIGINAL_RECORD`, `HISTORICAL_COMMITTED_RECORD`, `RESIDUAL_RECORD`, `PARTIAL_RECORD`, etc.). |
| `utr_12_digit` | `TEXT` | `NULL` | Extracted 12-digit NPCI UTR / RRN (indexed for Module 3.5 joining). |
| `app_order_or_tx_id` | `TEXT` | `NULL` | App-internal transaction ID (`T261105...`, `CICAg...`, Paytm Order ID). |
| `instrument_mode` | `TEXT` | `NOT NULL` | Enum: `UPI_BANK_ACCOUNT`, `UPI_LITE_ON_DEVICE`, `UPI_CIRCLE_DELEGATED`, `RUPAY_CREDIT_ON_UPI`, `PREPAID_WALLET`, `POCKET_UPI`. |
| `tx_direction` | `TEXT` | `NOT NULL` | Enum: `DEBIT_SENT`, `CREDIT_RECEIVED`, `COLLECT_REQUEST_SENT`, `COLLECT_REQUEST_RECEIVED`, `SELF_TRANSFER`. |
| `app_recorded_status` | `TEXT` | `NOT NULL` | Enum: `SUCCESS`, `PENDING`, `INITIATED`, `FAILED`, `DECLINED`, `EXPIRED`, `REFUNDED`. |
| `raw_amount_value` | `TEXT` | `NOT NULL` | Exact raw amount read from column/protobuf (e.g., `"2500000 paise"` or `"units:25000, nanos:0"`). |
| `amount_inr_decimal` | `REAL` | `NOT NULL` | Normalized amount in Indian Rupees (`₹`, e.g., `25000.00`). |
| `payer_vpa` | `TEXT` | `NULL` | Sender VPA handle (`user@ybl`). |
| `payee_vpa` | `TEXT` | `NULL` | Receiver VPA handle (`merchant@okaxis`). |
| `counterparty_display_name` | `TEXT` | `NULL` | Local phonebook / nickname of counterparty. |
| `counterparty_verified_cbs_name` | `TEXT` | `NULL` | Official NPCI-verified Core Banking Solution legal name of counterparty. |
| `counterparty_phone_number` | `TEXT` | `NULL` | 10-digit mobile number of counterparty (if present in row/VPA). |
| `counterparty_bank_acct_ifsc` | `TEXT` | `NULL` | Bank account mask/number + 11-char IFSC (if bank transfer mode). |
| `payment_note_remarks` | `TEXT` | `NULL` | User-entered transaction note. |
| `created_utc_iso` | `TEXT` | `NOT NULL` | Normalized UTC ISO-8601 timestamp (via Module 1.2). |
| `completed_utc_iso` | `TEXT` | `NULL` | Normalized UTC ISO-8601 settlement timestamp. |
| `raw_json_or_proto_dump` | `TEXT` | `NULL` | Complete unpacked JSON or Protobuf tree for examiner inspection. |

### Table 2: `upi_in_app_p2p_chats` (Messages Exchanged Inside UPI Payment Threads)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `upi_chat_uid` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Unique ID for each in-app chat message or split-bill note. |
| `app_instance_id` | `INTEGER` | `NOT NULL` | Foreign key to UPI app (`PhonePe`, `GPay India`, `Paytm`, `FamPay`). |
| `source_vfs_file_id` | `INTEGER` | `NOT NULL` | Foreign key to source database in `vfs_index`. |
| `recovery_classification` | `TEXT` | `NOT NULL` | 6-State Residual Classification (`ORIGINAL_RECORD`, `HISTORICAL_COMMITTED_RECORD`, `RESIDUAL_RECORD`). |
| `thread_or_topic_id` | `TEXT` | `NULL` | Conversation / stream ID. |
| `sender_vpa_or_phone` | `TEXT` | `NULL` | Sender VPA or phone number. |
| `receiver_vpa_or_phone` | `TEXT` | `NULL` | Receiver VPA or phone number. |
| `counterparty_verified_cbs_name` | `TEXT` | `NULL` | Official banking name of the chat counterparty. |
| `message_text` | `TEXT` | `NOT NULL` | Text message content sent inside the UPI payment thread. |
| `linked_utr_or_tx_id` | `TEXT` | `NULL` | Populated if the chat bubble is attached to a specific payment or split bill. |
| `sent_utc_iso` | `TEXT` | `NOT NULL` | Normalized UTC ISO-8601 timestamp. |

### Table 3: `upi_scanned_qr_and_vpa_lookups` (Decoded QR Scans & Cancelled VPA Lookups)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `lookup_uid` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Unique ID. |
| `app_instance_id` | `INTEGER` | `NOT NULL` | Owning UPI app instance. |
| `source_vfs_file_id` | `INTEGER` | `NOT NULL` | Source file in `vfs_index`. |
| `artifact_type` | `TEXT` | `NOT NULL` | Enum: `SCANNED_UPI_URI_QR`, `SCANNED_BHARATQR_EMVCO_TLV`, `VPA_NAME_VERIFICATION_CACHE`, `SAVED_BENEFICIARY`. |
| `raw_qr_or_uri_string` | `TEXT` | `NULL` | Unmodified `upi://pay?...` or `000201...` string. |
| `extracted_payee_vpa` | `TEXT` | `NULL` | Tag `pa` or EMVCo Tag `26` Sub-tag `01` VPA handle. |
| `verified_merchant_or_cbs_name` | `TEXT` | `NULL` | Tag `pn`, EMVCo Tag `59`, or NPCI `ReqValAdd` verified legal name. |
| `mcc_4_digit` | `TEXT` | `NULL` | 4-digit Merchant Category Code (`mc` or EMVCo Tag `52`). |
| `merchant_city` | `TEXT` | `NULL` | EMVCo Tag `60` City name. |
| `merchant_pincode_6_digit` | `TEXT` | `NULL` | EMVCo Tag `61` 6-digit Indian Postal PIN Code. |
| `terminal_or_store_id` | `TEXT` | `NULL` | EMVCo Tag `62` Sub-tag `03`/`07` Store or POS Terminal ID. |
| `scan_gps_lat_lon_json` | `TEXT` | `NULL` | Device GPS coordinates cached at the time of the QR scan. |
| `was_name_verified_without_tx` | `INTEGER` | `DEFAULT 0` | `1` if VPA was looked up/verified on NPCI but zero completed transactions exist for this VPA. |
| `event_utc_iso` | `TEXT` | `NULL` | Normalized UTC ISO-8601 timestamp. |

### Table 4: `upi_lite_and_circle_delegations` (On-Device Wallets & Delegated Spending)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `record_uid` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Unique ID. |
| `app_instance_id` | `INTEGER` | `NOT NULL` | Owning UPI app instance. |
| `feature_type` | `TEXT` | `NOT NULL` | Enum: `UPI_LITE_WALLET`, `UPI_CIRCLE_DELEGATION`, `POCKET_UPI_WALLET`, `UPI_AUTOPAY_MANDATE`. |
| `lite_lrn_or_mandate_umn` | `TEXT` | `NULL` | NPCI Lite Reference Number (`LRN`) or Unique Mandate Number (`UMN`). |
| `primary_holder_vpa` | `TEXT` | `NULL` | Primary bank account owner's VPA (in `UPI_CIRCLE`). |
| `secondary_delegate_vpa_phone` | `TEXT` | `NULL` | Delegated spender's VPA and mobile number (in `UPI_CIRCLE`). |
| `delegation_role_on_this_device` | `TEXT` | `NULL` | Enum: `PRIMARY_APPROVER`, `SECONDARY_DELEGATED_SPENDER`, `SELF_WALLET`. |
| `balance_or_limit_inr` | `REAL` | `NULL` | Current on-device UPI Lite balance or monthly UPI Circle limit in INR (`₹`). |
| `status` | `TEXT` | `NOT NULL` | E.g., `ACTIVE`, `REVOKED`, `EXPIRED`, `PAUSED`. |
| `updated_utc_iso` | `TEXT` | `NULL` | Normalized UTC ISO-8601 timestamp. |

---

## 9. Developer Acceptance Test Checklist for Module 3.1

1. **The Schema-Fingerprinted Dynamic Filename Test:** Rename a PhonePe database to `/data/user/999/com.phonepe.app/databases/workflow_99a8b7c6.db` (inside Xiaomi Cloned App `User 999`) containing a table with a nested `rawPayload` JSON column (`amountInPaise = 450000`, `utr = "630911223344"`). Verify that Sub-Engine 3.1A discovers the database without relying on its filename, unpacks the nested JSON, and records `amount_inr_decimal = 4500.00`.
2. **The Google Pay India (`nbu.paisa.user`) Dual-Name Protobuf Test:** Feed a `paisa.db` participant & stream-item Protobuf where `display_name = "Crypto Dealer"` and `banking_name = "VIKRAM ADITYA SINGH"`, with a `google.type.Money` message (`units = 15000`, `nanos = 500000000`). Verify that Sub-Engine 3.1B extracts both names side-by-side and computes `amount_inr_decimal = 15000.50`.
3. **The WhatsApp Pay `amount_1000` Math Test:** Insert a row into `msgstore.db` (`pay_transaction` table) with `amount_1000 = 12500000` and `extra_data` containing `{"vpa":"suspect@waicici","utr":"630999887766"}`. Verify that Sub-Engine 3.1D divides by $1000$ to output `₹12,500.00` (not `₹1,25,000.00`).
4. **The BharatQR EMVCo TLV Location & VPA Extraction Test:** Pass the raw BharatQR string `00020101021126420014A00000052401010120merchant.shop@icici5204541153033565802IN5914SHARMA TRADERS6008VARANASI61062210016304ABCD` into Sub-Engine 3.1E. Verify that it recursively decodes Tag `26` Sub-tag `01` (`merchant.shop@icici`), Tag `52` (`MCC 5411`), Tag `59` (`SHARMA TRADERS`), Tag `60` (`VARANASI`), and Tag `61` (`PIN Code 221001`).
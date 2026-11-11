# Engineering Specification: Phase 3, Module 3.3 — Indian Retail, Payments, AePS & Corporate/Mule Banking App Decoders (Top 25 PSU, Private, Payments & Corporate Banking Apps, Beneficiary Cooling-Period Audit & Password-Protected Statement Unlocker)

**Document Purpose:** This document provides the complete, step-by-step architectural blueprint for building **Module 3.3** of the Forensic Data Parser (corresponding to **Group 13** and cross-linked with **Groups 1, 2, 3, 5, 6, 8, 12, and 15** of the Unified Master Register). It contains **zero programming code** and explains every Indian banking application sandbox structure, offline `mPassbook` database schema, beneficiary addition cooling-period audit trail, cardless ATM cash-withdrawal token (`YONO Cash` / `IMT`), Aadhaar Enabled Payment System (`AePS`) agent cash-out ledger, corporate Maker-Checker bulk payout log, 11-character IFSC branch resolver, and deterministic PDF statement password unlocker from first principles so that any developer can build a courtroom-grade Indian banking forensic engine.

---

## 1. Purpose & Mental Model (Why UPI Alone Misses the Biggest Money Trails)

In Indian cybercrime, economic offences, corruption, narcotics, and organized mule-account investigations, investigators often focus exclusively on consumer UPI apps (PhonePe, Google Pay, Paytm). However, **NPCI imposes a strict ₹1,00,000 per day limit on standard peer-to-peer UPI transfers** (with higher limits restricted to specific verified merchant categories).

When cybercriminals, "Digital Arrest" extortion syndicates, investment/task-scam operators, or hawala networks steal or launder ₹5 Lakh to ₹5 Crore in a single day, **they cannot move that volume through consumer UPI alone**. Instead, they use **Indian Retail, Payments, AePS, and Corporate Banking Applications** installed on seized handsets to execute five high-velocity laundering operations:

1. **High-Value IMPS, NEFT & RTGS Transfers (`₹2 Lakh to ₹5 Crore`):** Executed directly through banking apps (**YONO SBI, iMobile Pay, HDFC Bank, Axis Mobile, Kotak811, bob World, PNB One**) after adding a mule beneficiary account and waiting out (or bypassing via "Quick Transfer") the bank's mandatory **Beneficiary Cooling Period**.
2. **Offline `mPassbook` Ledgers Inside Public Sector Bank Apps:** Almost every Indian Public Sector Undertaking (PSU) bank app (**SBI, Bank of Baroda, PNB, Canara, Union Bank, Indian Bank, BOI**) includes a built-in **Offline Passbook (`mPassbook`)** feature that downloads and caches months or years of complete core-banking account statements inside a local SQLite database so the customer can view their passbook without internet connectivity.
3. **Cardless ATM Cash Withdrawals (`YONO Cash`, `ICICI Cardless Cash`, `Axis/BOI IMT`):** Field-level cash-out mules withdraw stolen funds at physical ATMs *without possessing a physical debit card* by entering a 6-digit reference number and temporary PIN generated inside the banking app on the seized phone (or forwarded via WhatsApp/Telegram to a runner standing at an ATM).
4. **AePS (Aadhaar Enabled Payment System) & Micro-ATM Cash-Outs (`Fino Mitra`, `Spice Money`, `PayNearby`):** Rural and semi-urban cash-out rings use Business Correspondent (BC) agent apps paired with USB OTG fingerprint scanners (`Mantra` / `Morpho`) to withdraw cash directly from mule accounts without ATM cards or UPI PINs.
5. **Corporate & Merchant Current-Account Bulk Draining (`YONO Business`, `ICICI InstaBIZ`, `HDFC CorpApp`, `Axis Corporate`, `BharatPe`):** Layer-2 and Layer-3 mule handlers open corporate current accounts in the name of shell firms (`Proprietorship` / `LLP` / `Pvt Ltd`) and use corporate mobile banking apps with **Maker-Checker workflows** to upload bulk payout lists and sweep tens of lakhs of Rupees in minutes.

---

## 2. The 6 Fatal Mistakes Beginner Developers Make in Indian Banking App Forensics

Before implementing Module 3.3, the developer must understand six critical traps that cause standard forensic tools to report `"0 Banking Artifacts"` on seized Indian smartphones:

### Mistake 1: Assuming Banking Apps Store Nothing Locally Because "Banking Is Cloud-Based"
* **The Trap:** Skipping `/data/user/0/com.sbi.lotusintouch/` or `/data/user/0/com.snapwork.hdfc/` under the assumption that banking apps only display live server data in RAM.
* **Why It Fails:** Every Indian banking app persists four rich layers of local evidence inside its sandbox:
  1. **Pre-Login Identity & Session State (`shared_prefs` & `MMKV`):** To display `"Welcome back, R*** SHARMA (CIF: *****4821)"` and verify biometric/MPIN login, the app stores the user's **Customer ID (`CIF` / `CustID` / `CRN`)**, registered mobile number, masked account numbers, last login timestamp, and hardware device-binding IDs on disk.
  2. **Offline `mPassbook` & Mini-Statement SQLite/Realm Databases:** PSU and private banking apps cache downloaded passbook ledgers and recent transactions locally in `/databases/`.
  3. **Embedded `app_webview` & `NSURLCache` REST API JSON Responses:** Most modern banking apps are hybrid wrappers that fetch JSON responses (`getAccountSummary`, `getMiniStatement`, `getBeneficiaryList`) inside `app_webview/Default/Cache/Cache_Data/*_0` or iOS `Cache.db`.
  4. **Downloaded Statement PDFs & Transaction Receipt Images:** Saved inside `/files/`, `/cache/`, or `/data/media/0/Download/`.
* **The Rule:** Module 3.3 must systematically execute all **Four Extraction Prongs** across every discovered banking app sandbox.

### Mistake 2: Ignoring Beneficiary Addition & Cooling-Period Logs
* **The Trap:** Looking only for completed money transfers and ignoring the `beneficiaries` / `payees` table or `BENEFICIARY_ADDED` events.
* **Why It Fails:** Under RBI guidelines, when a user adds a new IMPS/NEFT/RTGS payee (`Account Number + IFSC`), banks enforce a **Cooling Period** (typically $30\text{ minutes}$ to $24\text{ hours}$) with a restricted transfer cap before large transfers are permitted. In court, proving **the exact timestamp when the mule beneficiary account was added on the seized handset**—and showing that the device was in the suspect's physical possession (or under active remote screen-share access) at that exact timestamp—is often more decisive than the transfer timestamp itself.
* **The Rule:** Extract every active, `-wal` historical, and freelist-carved beneficiary addition record, along with its exact `added_timestamp`, `activation_cooling_end_timestamp`, `account_number`, `ifsc_code`, and `beneficiary_name`.

### Mistake 3: Missing Cardless ATM Cash Withdrawal Tokens (`YONO Cash` / `IMT`)
* **The Trap:** Only parsing account-to-account transfers (`IMPS`/`NEFT`/`UPI`) and ignoring cardless cash tables and notifications.
* **Why It Fails:** Organized cybercrime gangs rarely transfer stolen funds into a cash-out mule's personal bank account (which would freeze the mule's account when the victim files a `1930` NCRP cybercrime complaint). Instead, the gang generates a **YONO Cash (SBI)**, **Cardless Cash (ICICI/Kotak/BoB)**, or **Instant Money Transfer (`IMT` — Axis/Bank of India)** voucher inside the compromised/mule banking app and texts the **6-digit Reference Number + 6-digit temporary PIN** to a runner standing at an ATM.
* **The Rule:** Explicitly scan banking sandboxes, WebView JSON caches, and DLT SMS messages (`YONO Cash`, `IMT`, `Cardless`) for cardless ATM token generation, expiry, and redemption records (Section 7.2).

### Mistake 4: Overlooking Corporate & Merchant Banking Apps (`YONO Business`, `InstaBIZ`, `HDFC CorpApp`)
* **The Trap:** Only supporting consumer retail banking apps (`YONO SBI`, `HDFC MobileBanking`) and ignoring corporate/merchant apps (`com.sbi.yonobusiness`, `com.icicibank.instabiz`, `com.hdfc.cbx`, `com.bharatpe.merchant`).
* **Why It Fails:** High-volume cyber-fraud proceeds are aggregated into corporate current accounts and merchant QR accounts. In a corporate banking app, two distinct users often touch a transaction: a **`MAKER`** (who uploads the beneficiary file or initiates the ₹25 Lakh RTGS payout) and a **`CHECKER` / `APPROVER`** (who enters the OTP/MPIN to release the batch).
* **The Rule:** Sub-Engine 3.3D must parse corporate banking sandboxes and explicitly attribute the logged-in user's **Corporate ID (`CorpID`)**, **User ID**, and **Role (`MAKER`, `CHECKER`, `VIEWER`, `SUPER_ADMIN`)**.

### Mistake 5: Leaving Password-Protected Bank Statement PDFs Locked
* **The Trap:** Finding `SBI_Statement_Nov2026.pdf` or `HDFC_Acct_Statement.pdf` in `/Download/`, seeing that it is encrypted with a standard PDF user password, and marking it as `"Encrypted / Unreadable"`.
* **Why It Fails:** Indian banks do **not** use random passwords for downloaded or emailed PDF account statements. Every Indian bank uses a **strictly deterministic password formula** constructed from the customer's own profile details (such as the first 4 letters of the customer's name + `DDMM` of their Date of Birth, or their `Customer ID`, or the last 5 digits of their mobile number + `DDMMYY`). Because Phase 1, Phase 2, and Phase 3 have *already extracted* the suspect's Name, DOB, Mobile Number, Account Number, PAN, and Customer ID from the phone, your software can **automatically unlock $> 90\%$ of Indian bank statement PDFs in under $10\text{ milliseconds}$**.
* **The Rule:** Implement **Sub-Engine 3.3E (The Deterministic Indian Bank Statement PDF Unlocker)** specified in Section 8.1.

### Mistake 6: Failing to Decode the 11-Character Indian `IFSC` Code Into Bank & Branch Location
* **The Trap:** Displaying an extracted IFSC code like `SBIN0004821` or `HDFC0001234` as a raw string without resolving which bank, city, and branch it belongs to.
* **Why It Fails:** Every Indian Financial System Code (`IFSC`) is an 11-character alphanumeric code (`BBBB0CCCCCC`) regulated by the Reserve Bank of India (RBI):
  * **Characters 1–4 (`BBBB`):** 4-letter Bank Code (`SBIN` = State Bank of India, `HDFC` = HDFC Bank, `ICIC` = ICICI Bank, `UTIB` = Axis Bank, `KKBK` = Kotak Mahindra Bank, `BARB` = Bank of Baroda, `PUNB` = Punjab National Bank, `CNRB` = Canara Bank, `UBIN` = Union Bank of India, `AIRP` = Airtel Payments Bank, `IPOS` = India Post Payments Bank).
  * **Character 5 (`0`):** Invariant control character (always numeric zero `'0'`).
  * **Characters 6–11 (`CCCCCC`):** 6-character specific **Physical Bank Branch Code**.
* **The Rule:** Bundle an offline compressed RBI IFSC lookup table inside Module 3.3 so every extracted IFSC code automatically resolves to its **Exact Bank Name, Branch Name, Street Address, City, District, State, and Nodal Law-Enforcement Jurisdiction** (Section 8.2).

---

## 3. Sub-Engine 3.3A — Public Sector Undertaking (PSU) Banking Apps Deep Decoder

For every PSU bank app below, query **Module 1.3 (`resolve_app_targets`)** across all user profiles (`0`, `10`, `95`, `150`, `999`), unwrap any SQLCipher/encrypted stores via **Module 2.2**, and run the **4-Pronged Extraction Pipeline** (`shared_prefs`/`MMKV` $\rightarrow$ `SQLite`/`mPassbook` $\rightarrow$ `app_webview` $\rightarrow$ `files/` & `/Download/`).

### 3.1 Target 1: State Bank of India (`YONO SBI`, `YONO Lite SBI`, `BHIM SBI Pay`)

* **Target Package & Bundle Identifiers:**
  * **YONO SBI (Flagship Super-App):** Android `com.sbi.lotusintouch` | iOS `com.sbi.lotusintouch`
  * **YONO Lite SBI (Retail Internet Banking & Offline `mPassbook`):** Android `com.sbi.SBIFreedomPlus` | iOS `com.sbi.sbilite`
  * **BHIM SBI Pay (Dedicated UPI App — `@sbi`):** Android `com.sbi.upi` | iOS `com.sbi.upi`

#### Step-by-Step Extraction of SBI Sandboxes:
1. **Prong 1 — Identity, CIF & Account Registration (`shared_prefs/*.xml` & `MMKV`):**
   * Scan `/data/user/<id>/com.sbi.lotusintouch/shared_prefs/` and `com.sbi.SBIFreedomPlus/shared_prefs/`:
     * Extract the **11-digit SBI CIF Number** (`cif`, `cifNo`, `customerId`).
     * Extract the **11-digit SBI Account Number** (or masked `XXXXXXX1234` — note that standard SBI account numbers are always **11 numeric digits**, typically starting with `1`, `2`, `3`, `4`, or `5`).
     * Extract `username` (Internet Banking login ID), `registeredMobile`, `mpinStatus`, `biometricEnabled`, `deviceBindingTimestamp`, and `lastLoginTime` (exact timestamp the user last logged into YONO).
2. **Prong 2 — Offline `mPassbook` & Local SQLite Databases (`/databases/`):**
   * In **`YONO Lite SBI` (`com.sbi.SBIFreedomPlus`)** and **`YONO SBI`**:
     * Locate SQLite databases in `/databases/` matching `*passbook*.db`, `*mpassbook*.db`, `*sbi*.db`, `*yono*.db`, `*txn*.db` (if encrypted with a user mPassbook PIN or a device-derived SQLCipher key stored in `shared_prefs` / Keystore, unwrap via Module 2.2).
     * **Offline `mPassbook` Ledger Table (`mpassbook_table`, `account_transactions`, `statement_entries`):**
       * `account_no` (`TEXT`): 11-digit SBI account number.
       * `txn_date` & `value_date` (`TEXT` or `INTEGER`): Transaction date.
       * `narration` / `description` / `particulars` (`TEXT`): Full core-banking narration string.
       * `debit_amt` & `credit_amt` (`REAL` or `TEXT`): Outflow or inflow amount in INR (`₹`).
       * `balance` (`REAL` or `TEXT`): Running account balance after the transaction.
     * **Core-Banking Narration Parser Rule:** Whenever a bank `Narration` string matches:
       $$\texttt{UPI/(DR|CR)/<12\_digit\_UTR>/<Counterparty\_Name>/<Bank\_4\_Char\_Code>/<VPA\_Handle>/<Remarks>}$$
       or
       $$\texttt{BY TRANSFER-IMPS/<12\_digit\_RRN>/<Sender\_Name>/<Bank\_Code>/<Account\_or\_Mobile>}$$
       or
       $$\texttt{TO TRANSFER-INB IMPS/<12\_digit\_RRN>/<Beneficiary\_Name>/<IFSC\_or\_Account>}$$
       automatically split that string on `/` to extract the 12-digit UTR/RRN, direction (`DR` = Debit, `CR` = Credit), Counterparty Name, 4-letter Bank Code, and VPA Handle or Account Number!
3. **Prong 3 — `YONO Cash` (Cardless ATM Withdrawal) & `Quick Transfer` Extraction:**
   * Query SQLite tables, `app_webview` HTTP cache (`webview_http_cache_records`), and notification caches for **YONO Cash** requests:
     * Extract `yonoCashRequestId`, **6-digit YONO Cash Reference Number** (delivered via SMS), `withdrawalAmount` (up to ₹20,000 per transaction), `debitAccountNo`, `requestTimestamp`, `expiryTimestamp` (valid for $4\text{ hours}$), `status` (`GENERATED`, `WITHDRAWN`, `EXPIRED`, `CANCELLED`), and `atmId` / `terminalLocation` (if redeemed).
   * Extract **Quick Transfer (Transfer Without Adding Beneficiary)** records:
     * Allows instant IMPS/UPI transfer up to ₹25,000–₹50,000 by typing `Recipient Name + Account Number + IFSC` without waiting for a cooling period. Extract every Quick Transfer recipient's full unmasked account number and IFSC.

### 3.2 Target 2: Other Major Public Sector Undertaking (PSU) Banking Apps

Every PSU bank below must be parsed across active SQLite tables, `-wal` historical frames, B-tree freelist pages (Module 2.1), `MMKV` (Module 2.3), and `app_webview` caches (Module 2.4):

#### 1. Bank of Baroda (`bob World` & `Baroda mPassbook`)
* **Target Identifiers:** Android `com.bankofbaroda.mconnect`, `com.bankofbaroda.mpassbook`, `com.bankofbaroda.upi` | iOS `com.bankofbaroda.mconnectplus`.
* **Account & Customer ID Format:**
  * **14-Digit Account Number:** The first $4\text{ digits}$ equal the numeric branch code (`BBBB`), the next $2\text{ digits}$ equal the product/scheme type (`01` = Savings, `02` = Current, `03` = Overdraft/CC), and the final $8\text{ digits}$ equal the account serial number.
  * **9-Digit Alphanumeric/Numeric Customer ID (`CustID`).**
* **Sandbox Extraction Targets:**
  * **`/databases/*passbook*.db` & `mconnect*.db`:** Extract `account_list` (`accountNumber`, `branchCode`, `ifscCode`, `accountType`, `availableBalance`) and `transaction_list` (`txnId`, `txnDate`, `narration`, `debitAmount`, `creditAmount`, `closingBalance`).
  * **Cash on Mobile (Cardless ATM Cash-Out):** Extract `cashOnMobile` requests (`referenceNo`, `amount`, `remarks`, `createdTime`, `expiryTime`, `status`).
  * **`@barodampay` Built-In UPI:** Extract VPA bindings, scanned QR strings, and collect requests.

#### 2. Punjab National Bank (`PNB One` & `PNB mPassbook`)
* **Target Identifiers:** Android `com.Version1` (`PNB One`), `com.pnb.mpassbook`, `com.MyPnb.pnbupi` | iOS `com.pnb.pnbone`.
* **Account & Customer ID Format:**
  * **16-Digit Account Number:** First $4\text{ digits}$ = Sol/Branch ID, next $4\text{ digits}$ = Scheme code (e.g., `0001`, `0021`), last $8\text{ digits}$ = Account number.
  * **9-Character Alphanumeric `User ID` (`Customer ID`).**
* **Sandbox Extraction Targets:**
  * **`shared_prefs/*.xml`:** Extract the saved `UserID` / `Customer_ID` (PNB One caches the User ID so the user only enters their 4-digit MPIN on launch), registered mobile number, and `SimSerial` (`ICCID` bound during PNB One activation).
  * **`/databases/*passbook*.db` & `app_webview` JSON Cache:** Extract offline passbook ledger tables (`mPassbook`), newly added IMPS/NEFT/RTGS beneficiaries (`payeeName`, `payeeAccNo`, `payeeIfsc`, `coolingPeriodStatus`), and **PNB Cardless Cash** tokens.

#### 3. Canara Bank (`Canara ai1` & `Canara eInfobook`)
* **Target Identifiers:** Android `com.canarabank.mobility` | iOS `com.canarabank.mobility`.
* **Account & Customer ID Format:** **13-Digit Account Number** (or 12-digit legacy Syndicate Bank account migrated to Canara) + **8/9-Digit Customer ID**.
* **Sandbox Extraction Targets:**
  * `Canara ai1` is a unified super-app with over 250 features. Inside `/databases/` and `/files/mmkv/`, extract the built-in **`e-Passbook`** SQLite tables (`passbook_table`, `account_master`, `beneficiary_master`), `@cnrb` UPI transaction tables, and credit card bill payment logs.

#### 4. Union Bank of India (`Vyom`), Indian Bank (`IndOASIS` / `IndSMART`), Bank of India (`BOI Mobile`), Central Bank (`Cent Mobile`), UCO Bank (`UCO mBanking Plus`), Indian Overseas Bank (`IOB Mobile`) & Bank of Maharashtra (`MahaMobile Plus`)

| PSU Bank & App Name | Android Package & iOS Bundle ID | Account & Customer ID Structure | Specific Sandbox Tables & Forensic Artifacts |
|---|---|---|---|
| **Union Bank of India (`Vyom`)** | Android: `com.infrasofttech.mahaesh`, `com.unionbank.ecommerce.mobile.android`<br>iOS: `com.unionbank.vyom` | **15-Digit Account No** (includes former Andhra Bank & Corporation Bank migrated accounts) + **Customer ID** | Parse `mPassbook` SQLite database (`txn_history`, `acct_summary`), `@uboi` UPI ledger, and `shared_prefs/` Customer ID & MPIN lock state. |
| **Indian Bank (`IndOASIS` / `IndSMART`)** | Android: `com.indianbank.indoasis`<br>iOS: `com.indianbank.indoasis` | **9-to-11 Digit Account No** (includes former Allahabad Bank accounts) + **CIF** | Parse offline `mPassbook` database, **Beneficiary Cooling Period** logs, `@indianbank` UPI history, and `app_webview` mini-statement JSONs. |
| **Bank of India (`BOI Mobile`)** | Android: `com.boi.ua.android`, `com.snapwork.boimpassbook`<br>iOS: `com.boi.ua.ios` | **15-Digit Account No** (first 4 digits = branch code) + **Customer ID** | Parse `boimpassbook` SQLite tables, **BOI IMT (Instant Money Transfer)** cardless ATM withdrawal tokens, and IMPS payee registry. |
| **Central Bank (`Cent Mobile`), UCO (`UCO mBanking`), IOB (`IOB Mobile`), MahaBank (`MahaMobile`)** | `com.infrasoftuboi.centmobile`, `com.lcode.ucomobilebanking`, `com.iob.iobmobile`, `com.kiya.mahamobileplus` | **10-Digit (Central)**, **14-Digit (UCO)**, **15-Digit (IOB)**, **11-Digit (MahaBank)** | Execute all 4 Extraction Prongs: `shared_prefs` CIF/Mobile $\rightarrow$ `/databases/*passbook*.db` $\rightarrow$ `app_webview` cached JSON statements $\rightarrow$ downloaded PDF statements. |

---

## 4. Sub-Engine 3.3B — Private Sector & Neo-Banking Apps Deep Decoder

Private sector banks (**ICICI, HDFC, Axis, Kotak Mahindra, IndusInd, IDFC FIRST, Yes Bank, Federal Bank**) and their partnered Neo-Bank wrappers (**Fi Money, Jupiter**) are heavily utilized in Layer-1 and Layer-2 cyber-fraud laundering due to instant video-KYC onboarding and high-throughput IMPS/UPI switches.

### 4.1 Target 1: ICICI Bank (`iMobile Pay` — `com.csam.icici.bank.imobile` / `com.icicibank.imobile`)
* **Account & Customer ID Format:** **12-Digit Numeric Account Number** + Alphanumeric/Numeric **User ID**.
* **Step-by-Step Extraction:**
  1. **SQLite, Realm & `shared_prefs` Stores:**
     * Enumerate `/databases/` and `/files/` for SQLite and `.realm` files:
       * Extract linked ICICI savings/current accounts (`accountNumber`, `ifscCode`, `branchName`, `balance`).
       * Extract linked **Non-ICICI Bank Accounts** (because `iMobile Pay` acts as a universal UPI app `@icici` for customers of any bank!).
       * Extract **`payees` / `beneficiaries` tables:** Full account number, IFSC, payee name, payee nickname, and registration timestamp.
       * Extract **ICICI Cardless Cash Withdrawal** records: Local ATM cash-out requests containing the **6-digit Reference ID**, **4-digit temporary PIN**, withdrawal amount (up to ₹20,000), and ATM redemption status.
  2. **Embedded `app_webview` & HTTP Cache (`Module 2.4`):**
     * Extract cached JSON responses for mini-statements, detailed account statements, credit card statements, and **Fastag** reload ledgers.

### 4.2 Target 2: HDFC Bank (`com.snapwork.hdfc`) & PayZapp (`com.enstage.wibmo.hdfc`)
* **Account & Customer ID Format:** **14-Digit Numeric Account Number** + **8- or 9-Digit Numeric `Customer ID` (`CustID`)**.
* **Step-by-Step Extraction:**
  1. **HDFC MobileBanking (`com.snapwork.hdfc` on Android / `com.hdfcbank.mobilebanking` on iOS):**
     * **Pre-Login Identity Cache (`shared_prefs`, `MMKV`, `Local Storage`):** Extract the saved `Customer ID` (`CustID`), masked account numbers, registered mobile number, and biometric/4-digit Quick Access PIN registration timestamp.
     * **`app_webview` & `NSURLCache` API JSON Harvesting (`Module 2.4`):** HDFC MobileBanking relies heavily on cached HTTPS JSON payloads inside `app_webview/Default/Cache/Cache_Data/*_0` (Android) and `Library/Caches/*/Cache.db` + `fsCachedData/` (iOS). Scan decompressed JSON bodies for:
       * `AccountSummary` / `CasaAccountList`: Full 14-digit account numbers, IFSC codes (`HDFC000xxxx`), available balances, and unclear funds.
       * `MiniStatement` / `AcctStatement`: Transaction date, narration (`UPI-...`, `IMPS-...`, `NEFT-...`), reference number, debit/credit indicator, and running balance.
       * `BeneficiaryList` / `PayeeList`: Newly added IMPS/NEFT/RTGS payees and their exact cooling-period expiry timestamps (HDFC enforces a $30\text{-minute}$ initial cooling period followed by a ₹50,000 cap for the first $24\text{ hours}$).
  2. **HDFC PayZapp (`com.enstage.wibmo.hdfc` — `@pz` / `@hdfcbank`):**
     * Parse SQLite, `MMKV`, and `app_webview` stores for **PayZapp Cash / Wallet** balances, **Swipe-to-Pay** PIN-less transfers, `@pz` UPI transactions, and virtual prepaid card numbers.

### 4.3 Target 3: Kotak Mahindra Bank (`Kotak811` — `com.msf.kbank.mobile` / `com.kotak.bank.mobile`)
* **Why `Kotak811` Is a Top Cybercrime Target:** Zero-balance digital `811` accounts are opened rapidly via Aadhaar OTP / Video KYC and represent one of the highest-frequency Layer-1 mule account types in Indian NCRP (`1930`) complaints.
* **Account & CRN Format:** **10-Digit Numeric Account Number** + **8- or 9-Digit Numeric `CRN` (Customer Relationship Number)**.
* **Step-by-Step Extraction:**
  1. Extract the **`CRN`** from `shared_prefs/`, `MMKV`, or `Local Storage` (even if the suspect logged out, the CRN and device registration token often remain in `shared_prefs` or `MMKV` Layer 2/3 slack!).
  2. Extract the **811 Virtual Prepaid / Debit Card** metadata, `@kotak` UPI transaction ledger, **Send Money Abroad / Remittance** logs, **KayMall** voucher/flight purchases (frequently used to launder stolen funds into airline tickets or Amazon/Flipkart vouchers), and **Cardless Cash (`ATM Cash without Card`)** requests.

### 4.4 Target 4: Axis Bank (`Axis Mobile`), IndusInd (`IndusMobile`), IDFC FIRST, Yes Bank (`IRIS`), Federal Bank (`FedMobile`) & Neo-Bank Wrappers (`Fi Money`, `Jupiter`)

| Private Bank / Neo-Bank | Android Package & iOS Bundle ID | Account & Customer ID Format | Specific Sandbox Targets & Forensic Artifacts |
|---|---|---|---|
| **Axis Bank (`Axis Mobile` / `open`)** | Android: `com.axis.mobile`<br>iOS: `com.axisbank.axismobile` | **15-Digit Account No** (starts with `9`) + **9-Digit Customer ID** | Parse SQLite, `MMKV`, and `app_webview` for `@axisbank` UPI logs, **Axis IMT (Instant Money Transfer)** cardless ATM tokens, FD/loan summaries, and beneficiary additions. |
| **IndusInd Bank (`IndusMobile` & `INDIE`)** | Android: `com.indusind.indusmobile`, `com.indusind.indie`<br>iOS: `com.indusind.indusmobile` | **12-Digit Account No** (often starts with `10`, `15`, or `20` + mobile number!) | **Forensic Note:** IndusInd allows customers to pick their **10-digit mobile number** as the last 10 digits of their 12-digit bank account number (`159876543210`)! Extract `@indus` UPI ledger, Indie virtual card logs, and IMPS payees. |
| **IDFC FIRST Bank** | Android: `com.idfcfirstbank.optimus`<br>iOS: `com.idfcfirstbank.mobilebanking` | **10- or 11-Digit Account No** + **10-Digit Customer ID (`UCIC`)** | Built on a modern Flutter/hybrid stack (`MMKV` + SQLite + WebView). Extract `UCIC` Customer ID, `@idfcfirst` UPI transfers, and high-frequency IMPS passbook caches. |
| **Yes Bank (`IRIS by YES BANK`)** | Android: `com.yesbank`<br>iOS: `com.yesbank.iris` | **15-Digit Account No** (`0001...`) + **Customer ID** | Extract `@yesbank` / `@yespay` UPI ledgers, virtual card tokens, and API JSON statements in `app_webview`. |
| **Federal Bank (`FedMobile`) + Neo-Banks (`Fi Money` & `Jupiter`)** | • FedMobile: `com.fedmobile`<br>• **Fi Money:** `com.epifi.paisa`<br>• **Jupiter:** `money.jupiter` | **14-Digit Federal Bank Account No** (`IFSC: FDRL0007777` for Fi; `FDRL0005555` for Jupiter) | **Crucial Attribution Rule:** When a suspect uses **Fi Money (`com.epifi.paisa`)** or **Jupiter (`money.jupiter`)**, the underlying core bank account is a **14-digit Federal Bank Savings Account** (`@federal` / `@fi` / `@jupiteraxis`). Parse SQLite, `MMKV`, and `app_webview` inside `com.epifi.paisa` and `money.jupiter` and automatically link the account to **Federal Bank** in `upi_and_bank_accounts_inventory`! |

---

## 5. Sub-Engine 3.3C — Payments Banks & AePS (Aadhaar Biometric Cash-Out) Agent Apps

### 5.1 Payments Banks (`Airtel`, `IPPB`, `Jio`, `Fino`, `NSDL Jiffy`)
Payments Banks are capped at ₹2,00,000 balance per account, but because accounts can be opened in minutes via biometric e-KYC, **they represent the single largest category of Layer-1 cyber-fraud collection accounts in India**.

1. **Airtel Payments Bank (`Airtel Thanks` — `com.myairtelapp` / `com.airtel.myairtel`):**
   * **Crucial Account Number Rule:** In Airtel Payments Bank (`IFSC: AIRP0000001`), the customer's **10-digit mobile number (or `91` + 10-digit mobile number) IS their Bank Account Number**!
   * Parse SQLite, `MMKV`, and `app_webview` inside `com.myairtelapp` for **Airtel SafePay** confirmations, `@airtel` UPI transfers, Airtel Money Wallet ledgers, and cash withdrawal receipts at local Airtel Banking Points.
2. **India Post Payments Bank (`IPPB Mobile` — `com.ippb.app` & `DakPay` — `com.ippb.dakpay`):**
   * **Account Format:** **12-Digit Account Number** + **10-Digit Customer ID** (`IFSC: IPOS0000001`).
   * Parse `shared_prefs`, SQLite, and `app_webview` caches for **POSB (Post Office Savings Bank) Sweep-In / Sweep-Out** transfers (mules frequently sweep stolen funds from IPPB into a linked traditional Post Office Savings Account to hide the balance!), `@postbank` / `@dakpay` UPI logs, and doorstep postman cash-out receipts.
3. **Jio Payments Bank (`JioFinance` — `com.jio.finance` & `MyJio` — `com.jio.myjio`):**
   * **IFSC:** `JIOP0000001` (`@jio` VPA handle). Extract Jio Payments Bank savings account numbers, `@jio` UPI ledgers, and Digital Gold / voucher purchases.

### 5.2 AePS (Aadhaar Enabled Payment System) & Micro-ATM BC Agent Apps
In cybercrime cash-out hubs (such as Jamtara, Deoghar, Mewat/Nuh, Bharatpur, Alwar, and rural pockets across India), cash-out operators do not use ATMs (which have CCTV cameras). Instead, they register as **Business Correspondent (BC) / CSP Agents** on **AePS & Micro-ATM platforms** and withdraw cash from mule accounts inside their own room using a ₹2,000 USB biometric fingerprint scanner (`Mantra MFS100`/`MFS110` or `Morpho MSO 1300`) plugged into the seized Android phone's USB-C OTG port!

Module 3.3 must scan `resolved_application_catalog` for the **two layers of an AePS Cash-Out Setup**:

#### Layer A: The AePS / BC Merchant Agent Apps
* **`Fino Mitra`** (`com.finopaymentbank.finomitra` — Fino Payments Bank BC Agent app)
* **`Spice Money Adhikari`** (`in.spicemoney.spicemoney` — Spice Money AePS & Micro-ATM app)
* **`PayNearby`** (`com.bnb.paynearby` — PayNearby Aadhaar ATM & DMT app)
* **`Relipay by RNFI`** (`com.rnfi.relipay`), **`Roinet Xpresso`** (`com.roinet.xpresso`), **`Ezeepay`** (`com.ezeepay.service`), **`Bankit Agent`** (`in.bankit.agent`), **`CSC DigiPay`** (`com.csc.digipay`).
* **Artifacts to Extract from AePS Agent Sandboxes (`SQLite`, `MMKV`, `shared_prefs`, `app_webview`):**
  1. **`BC Agent ID / CSP Code / Merchant ID`** and the agent's **Settlement Bank Account + IFSC** (where all cash-out reimbursements are deposited).
  2. **AePS Cash Withdrawal & Balance Inquiry Ledger:**
     * `customerAadhaarLast4` (`XXXX-XXXX-1234` — the Aadhaar number of the mule or victim whose fingerprint was scanned!).
     * `customerBankIIN` / `bankName` (the 6-digit NPCI Issuer Identification Number of the bank debited).
     * `rrn_12_digit` (12-digit NPCI AePS RRN!).
     * `withdrawalAmountInr` (up to ₹10,000 per biometric scan).
     * `agentCommissionInr`, `agentWalletBalanceInr`, and `timestamp`.
  3. **DMT (Domestic Money Transfer) Ledger:** Cash-to-account remittance logs where the agent deposits cash into multiple beneficiary bank accounts using walk-in sender mobile numbers.

#### Layer B: The Biometric Fingerprint RD (Registered Device) Service Apps
If any of the following UIDAI Registered Device (`RD Service`) packages are installed on the seized phone (detected via Module 1.3), it **mathematically proves the phone was configured to operate a physical biometric fingerprint or iris scanner**:
* **`Mantra RD Service`:** `com.mantra.rdservice`, `com.mantra.clientmanagement`, `com.mantra.mfs110.rdservice`
* **`Morpho / IDEMIA SCL RD Service`:** `com.scl.rdservice`
* **`Startek FM220 RD Service`:** `com.acpl.registersdk`, `com.acpl.registersdk_l1`
* **`SecuGen RD Service`:** `com.secugen.rdservice`
* **`Precision / Tatvik / NextBiometrics RD Service`:** `com.precision.pb510.rdservice`, `com.tatvik.bio.tmf20`
* **Extract from RD Service Sandboxes:** The **Physical Serial Number (`DeviceSerialNumber`)** of the attached Mantra/Morpho USB fingerprint scanner, PID data XML timestamps, and device registration certificate metadata!

---

## 6. Sub-Engine 3.3D — Corporate, SME & Merchant Banking Apps (`Maker-Checker` & Bulk Payout Forensics)

When stolen funds are moved from Layer-1 accounts into Layer-2 shell company current accounts (`Proprietorship` / `Partnership` / `LLP` / `Pvt Ltd`), the perpetrators operate **Corporate Mobile Banking Apps**:

* **Target Packages:**
  * **SBI:** `com.sbi.yonobusiness` (`YONO Business` / `CinB` — Corporate Internet Banking: *Saral*, *Vyapaar*, *Vistaar*)
  * **ICICI Bank:** `com.icicibank.instabiz` (`InstaBIZ`) & `com.icicibank.cib`
  * **HDFC Bank:** `com.hdfc.cbx` (`HDFC Bank CorpApp` / `ENet`)
  * **Axis Bank:** `com.axis.AxisCorporate` (`Axis Neo for Corporates`)
  * **Kotak:** `com.kotak.fyn` (`Kotak fyn`)
  * **Bank of Baroda:** `com.bankofbaroda.bobworldbusiness`
  * **Union Bank / PNB / Canara Corporate:** `com.unionbank.corporate`, `com.pnb.ibscorp`

### Step-by-Step Corporate Maker-Checker Attribution Logic
Unlike a retail bank account (where one person owns the account), a corporate current account has a **Corporate ID (`CorpID`)** and multiple individual **User IDs** with distinct legal culpability:
1. **Extract the 3-Part Corporate Credential from `shared_prefs`, `MMKV` & `app_webview`:**
   * **`corporate_id` (`CorpID` / `CompanyCode` / `DomainID`):** Identifies the shell company or firm.
   * **`corporate_user_id` (`UserID` / `OperatorID` / `LoginID`):** Identifies the specific individual operating this handset.
   * **`assigned_corporate_role`:**
     * **`SINGLE_USER_PROPRIETOR` (`Saral`):** Can both initiate and approve transfers alone.
     * **`MAKER` (`Initiator` / `Uploader`):** Creates beneficiaries, enters payout amounts, or uploads bulk salary/vendor CSV/Excel files (check `/Download/` and `/files/` for bulk `.csv`/`.xls`/`.txt` payout templates!), and submits them to the approval queue.
     * **`CHECKER` / `AUTHORIZER` (`Approver`):** Reviews the pending queue and enters the OTP/MPIN/Digital Token to release the funds from the bank.
2. **Extract Pending & Approved Batch Queues:**
   * Parse local SQLite tables and cached WebView JSON responses for **Approval Queue items**: `batchReferenceId`, `fileName` (if bulk file upload), `totalBatchAmountInr`, `beneficiaryCount`, `makerUserId`, `makerTimestamp`, `checkerUserId`, `checkerApprovalTimestamp`, and `batchStatus` (`PENDING_APPROVAL`, `APPROVED_RELEASED`, `REJECTED`).

---

## 7. Beneficiary Cooling-Period Audit & Cardless ATM Cash Withdrawal Forensics

### 7.1 Reconstructing the Beneficiary Addition & Cooling-Period Timeline
Whenever Module 3.3 (via app sandbox databases/WebViews) or Module 3.4 (via DLT Bank SMS alerts like `"You have added RAHUL A/c XX4821 as beneficiary on 05-Nov-26 14:10..."`) discovers a beneficiary record:
1. Extract:
   * `beneficiary_name`
   * `beneficiary_account_no` (full or masked)
   * `beneficiary_ifsc_11_char` (resolve branch & city via Section 8.2!)
   * `beneficiary_vpa_or_mobile`
   * `added_utc_iso` (Exact timestamp the payee was registered)
   * `cooling_period_end_utc_iso` (When full-limit transfers became active)
2. **First-Transfer Latency Calculation ($\Delta t$):**
   * Automatically query the transaction ledger for the *very first outbound transfer* sent to `beneficiary_account_no` after `added_utc_iso`.
   * Calculate:
     $$\Delta t_{\text{add}} = \text{first\_transfer\_utc} - \text{added\_utc}$$
     $$\Delta t_{\text{cool}} = \left|\text{first\_transfer\_utc} - \text{cooling\_period\_end\_utc}\right|$$
   * **Forensic Indicator:** If $\Delta t_{\text{add}} \le 15\text{ minutes}$ (immediate post-addition transfer up to the bank's cooling cap of ₹25,000/₹50,000) OR $\Delta t_{\text{cool}} \le 15\text{ minutes}$ (large drain executed immediately as the 30-minute or 24-hour cooling timer expired), flag the beneficiary with `is_rapid_mule_drain_flagged = 1`—demonstrating premeditated urgency to drain the account the instant the bank's cooling timer unlocked.

### 7.2 Cardless ATM Cash-Out Token Correlator (`YONO Cash`, `ICICI Cardless`, `IMT`)
When a cardless cash withdrawal token is generated on the seized phone:
1. Extract the **6-digit Reference ID**, **Amount**, and **Generation Timestamp ($t_{\text{gen}}$)** from the banking app sandbox or DLT SMS.
2. **Automatic Cross-App Runner Search (Linking Group 13 $\rightarrow$ Group 1):**
   * Immediately search all outbound **WhatsApp, Telegram, Signal, and SMS messages** sent from the seized phone within the window $[t_{\text{gen}}, t_{\text{gen}} + 4\text{ hours}]$ for either:
     * That exact 6-digit Reference ID text string, OR
     * An image/screenshot sent within $5\text{ minutes}$ of $t_{\text{gen}}$.
   * If found, automatically link the recipient of that WhatsApp/Telegram message as the **Suspected Field ATM Cash-Out Runner** (`linked_runner_chat_recipient`)!

---

## 8. Sub-Engine 3.3E — Deterministic Indian Bank Statement PDF Unlocker & Offline IFSC Resolver

### 8.1 The Deterministic Indian Bank Statement PDF Unlocker
Downloaded bank statements and credit card bills in `/Download/`, `/files/`, and WhatsApp document folders are almost always password-protected PDFs (`PDF 1.4–1.7` Standard Security Handler: RC4-128, AES-128, or AES-256).

Instead of performing a slow brute-force attack, Sub-Engine 3.3E harvests a small **Candidate Profile Dictionary** for the device owner (and any secondary mule profiles found on the phone) from Phase 1 (Module 1.3), Group 2 (Contacts "Me" card / Accounts), and Phase 3 (Customer IDs, Account Numbers, Mobile Numbers, PAN numbers, and Dates of Birth found in `shared_prefs`/`MMKV`/SMS):
* Let `NAME` = Stripped alphabetic characters of the account holder's name (e.g., `"RAHUL SHARMA"` $\rightarrow$ first 4 letters `"RAHU"` and `"rahu"`).
* Let `DOB` = Date of Birth `(DD, MM, YYYY, YY)` (harvested from KYC JSONs, PAN/Aadhaar OCR, or profile plists; **Crucial Fallback:** Even if the suspect's Date of Birth is completely unknown, if you know their 4-letter name prefix `"RAHU"`, iterating all $366\text{ possible } \texttt{DDMM}$ calendar days from `0101` to `3112` requires only $366\text{ attempts}$—which executes in under $5\text{ milliseconds}$ on a single CPU core!).
* Let `MOB` = 10-digit mobile number (and last 4 digits `MOB4`, last 5 digits `MOB5`).
* Let `ACCT` = Bank Account Number (and last 4 digits `ACCT4`, first 4 digits `ACCT_FIRST4`).
* Let `CUSTID` = Extracted `CIF` / `Customer ID` / `CRN`.
* Let `PAN` = 10-character Permanent Account Number (`AAAAA9999A`).

#### Master Table of Indian Bank PDF Password Formulas (Tested Automatically in $< 20\text{ ms}$)

| Bank Name | Official Bank Statement / e-Statement PDF Password Formula(s) | Example (`RAHUL SHARMA`, DOB `14-08-1995`, Mob `9876543210`, A/c `...4821`, CustID `87654321`) |
|---|---|---|
| **State Bank of India (SBI)** | 1. `<Last 5 digits of Mobile><DDMMYY of DOB>`<br>2. `<First 4 letters of Name (UPPER or lower)><DDMM of DOB>`<br>3. `<11-digit CIF or Account No>` | `43210140895` or `RAHU1408` or `rahu1408` |
| **HDFC Bank** | 1. **`<Customer ID (8 or 9 digits)>`**<br>2. `<First 4 letters of Name (UPPER)><DDMM of DOB>` (Credit Cards) | `87654321` or `RAHU1408` |
| **ICICI Bank** | 1. `<First 4 letters of Name (lowercase)><DDMM of DOB>`<br>2. `<Customer ID>` | `rahu1408` |
| **Axis Bank** | 1. `<First 4 letters of Name (UPPERCASE)><DDMM of DOB>`<br>2. `<First 4 letters of Name (lowercase)><DDMM of DOB>`<br>3. `<9-digit Customer ID>` | `RAHU1408` or `rahu1408` |
| **Kotak Mahindra Bank (`Kotak811`)** | 1. **`<CRN (8 or 9 digits)>`**<br>2. `<First 4 letters of Name (lowercase)><DDMM of DOB>` | `87654321` or `rahu1408` |
| **Bank of Baroda (`bob World`)** | 1. `<First 4 letters of Name (lowercase)><DDMM of DOB>`<br>2. `<Last 4 digits of Mobile><DDMMYY of DOB>` | `rahu1408` or `3210140895` |
| **Punjab National Bank (PNB)** | 1. **`<16-digit Account Number>`**<br>2. `<9-character Customer ID>`<br>3. `<First 4 letters of Name (UPPER)><DDMM of DOB>` | `0123000100004821` |
| **Canara Bank / Union Bank / Indian Bank** | 1. `<Customer ID>`<br>2. `<First 4 letters of Name (UPPER/lower)><DDMM of DOB>`<br>3. `<First 4 letters of Name><Last 4 digits of Account>` | `RAHU4821` or `rahu1408` |
| **IndusInd / IDFC FIRST / Yes Bank / Federal Bank** | 1. `<First 4 letters of Name (UPPER/lower)><DDMM of DOB>`<br>2. `<DDMMYYYY of DOB>`<br>3. `<Customer ID>` | `RAHU1408` or `14081995` |
| **Airtel Payments Bank / Paytm / PhonePe Statements** | 1. `<DDMMYYYY of DOB>`<br>2. `<10-digit Mobile Number>`<br>3. `<First 4 letters of Name (lowercase)><Last 4 digits of Mobile>` | `14081995` or `9876543210` or `rahu3210` |
| **PAN / CDSL / NSDL / Income Tax PDFs** | 1. `<10-char PAN (UPPER or lower)>`<br>2. `<10-char PAN (lowercase)><DDMMYYYY of DOB>` | `abcde1234f` or `abcde1234f14081995` |

Once unlocked, Sub-Engine 3.3E saves a decrypted `Product B2` PDF copy in the staging folder, hashes it via Module 1.2, logs the exact password that unlocked it in `case_cryptographic_keyring` (which also confirms the suspect's DOB/Name/CustID!), and parses the tabular rows inside the PDF statement directly into `bank_mpassbook_and_sandbox_ledger`.

### 8.2 Offline 11-Character RBI `IFSC` Branch & Jurisdiction Resolver
Validate every candidate 11-character IFSC string against the strict regular expression `^[A-Z]{4}0[A-Z0-9]{6}$` (where Character 5 is always numeric zero `'0'`). Look up the 11-character code in an embedded compressed SQLite/binary dictionary of RBI's $\approx 1,65,000$ Indian bank branches to populate:
* `bank_full_name` (e.g., `"State Bank of India"`)
* `branch_name` (e.g., `"Varanasi Main Branch"`)
* `branch_address`, `city`, `district`, `state`, and `pincode`
* **Why This Matters:** Automatically tells the investigating officer the exact physical bank branch, city, and state in India where the mule account or beneficiary account is domiciled.

---

## 9. Database Schema for Module 3.3 (`indian_banking_sandbox_engine.sqlite`)

The developer must create the following four tables in the case database:

### Table 1: `banking_app_profiles_and_roles` (Retail, Payments, AePS & Corporate App Profiles)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `bank_profile_uid` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Unique ID for each banking profile discovered in a sandbox. |
| `app_instance_id` | `INTEGER` | `NOT NULL` | Foreign key to owning banking app in Module 1.3 (`com.sbi.lotusintouch`, `com.snapwork.hdfc`, etc.). |
| `source_vfs_file_id` | `INTEGER` | `NOT NULL` | Foreign key to `shared_prefs`, `MMKV`, or SQLite file in `vfs_index`. |
| `bank_institution_name` | `TEXT` | `NOT NULL` | E.g., `"State Bank of India"`, `"HDFC Bank"`, `"Kotak Mahindra Bank"`, `"Spice Money AePS"`. |
| `app_tier_category` | `TEXT` | `NOT NULL` | Enum: `PSU_RETAIL`, `PRIVATE_RETAIL`, `NEO_BANK_WRAPPER`, `PAYMENTS_BANK`, `CORPORATE_SME_BANKING`, `AEPS_BC_AGENT_APP`, `BIOMETRIC_RD_SERVICE`. |
| `corporate_id_code` | `TEXT` | `NULL` | `CorpID` / Company ID (populated for Corporate/SME banking apps). |
| `customer_id_cif_crn` | `TEXT` | `NULL` | Extracted 11-digit SBI `CIF`, HDFC `CustID`, Kotak `CRN`, PNB `UserID`, or AePS `BC Agent ID`. |
| `corporate_role` | `TEXT` | `NULL` | Enum: `RETAIL_INDIVIDUAL`, `CORPORATE_MAKER`, `CORPORATE_CHECKER_APPROVER`, `CORPORATE_SUPER_ADMIN`, `BC_CASH_AGENT`. |
| `account_holder_name` | `TEXT` | `NULL` | Extracted customer or corporate firm name. |
| `registered_mobile_no` | `TEXT` | `NULL` | 10-digit registered mobile number. |
| `linked_account_numbers_json` | `TEXT` | `NULL` | JSON array of full or masked account numbers + IFSC codes linked to this profile. |
| `attached_biometric_scanner_sn` | `TEXT` | `NULL` | Physical Serial Number of attached Mantra/Morpho USB fingerprint scanner (if `AEPS_BC_AGENT_APP` or `BIOMETRIC_RD_SERVICE`). |
| `last_login_utc_iso` | `TEXT` | `NULL` | Exact UTC ISO-8601 timestamp of the most recent app login. |
| `recovery_classification` | `TEXT` | `NOT NULL` | 6-State Enum (`ORIGINAL_RECORD`, `HISTORICAL_COMMITTED_RECORD`, `RESIDUAL_RECORD`). |

### Table 2: `bank_mpassbook_and_sandbox_ledger` (Offline `mPassbook`, WebView Statements, AePS & Corporate Batches)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `bank_tx_uid` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Unique row ID. |
| `bank_profile_uid` | `INTEGER` | `NULL` | Foreign key to `banking_app_profiles_and_roles.bank_profile_uid`. |
| `source_vfs_file_id` | `INTEGER` | `NOT NULL` | Source `.db`, `*_0` WebView cache, or unlocked Statement PDF in `vfs_index`. |
| `source_artifact_type` | `TEXT` | `NOT NULL` | Enum: `OFFLINE_MPASSBOOK_DB`, `WEBVIEW_JSON_STATEMENT`, `AEPS_AGENT_LEDGER`, `CORPORATE_BATCH_QUEUE`, `UNLOCKED_PDF_STATEMENT`. |
| `recovery_classification` | `TEXT` | `NOT NULL` | 6-State Residual Classification (`ORIGINAL_RECORD`, `HISTORICAL_COMMITTED_RECORD`, `RESIDUAL_RECORD`). |
| `local_account_number` | `TEXT` | `NULL` | Account number debited or credited. |
| `payment_rail` | `TEXT` | `NOT NULL` | Enum: `IMPS`, `NEFT`, `RTGS`, `UPI`, `INTERNAL_TRANSFER`, `YONO_CARDLESS_ATM`, `AEPS_BIOMETRIC_CASHOUT`, `DMT_REMITTANCE`, `POSB_SWEEP`, `CHEQUE`. |
| `utr_or_rrn_reference` | `TEXT` | `NULL` | Extracted 12-digit UPI/IMPS/AePS RRN or 16–22 char NEFT/RTGS UTR (parsed from column or `Narration` string). |
| `tx_direction` | `TEXT` | `NOT NULL` | Enum: `DEBIT`, `CREDIT`, `CORPORATE_BATCH_PENDING`. |
| `amount_inr_decimal` | `REAL` | `NOT NULL` | Transaction amount in INR (`₹`). |
| `running_balance_inr` | `REAL` | `NULL` | Account balance immediately after this entry. |
| `raw_narration_text` | `TEXT` | `NULL` | Full core-banking narration string (e.g., `"UPI/DR/630914829104/..."`). |
| `extracted_counterparty_name` | `TEXT` | `NULL` | Counterparty name parsed from column or narration. |
| `extracted_counterparty_acct_vpa` | `TEXT` | `NULL` | Counterparty account number, VPA, or Aadhaar mask (`XXXX-1234` for AePS). |
| `extracted_counterparty_ifsc` | `TEXT` | `NULL` | 11-char IFSC code (resolved via Section 8.2). |
| `resolved_branch_city_state` | `TEXT` | `NULL` | Resolved Bank Name, Branch, City, and State from offline IFSC lookup. |
| `tx_utc_iso` | `TEXT` | `NOT NULL` | Normalized UTC ISO-8601 transaction timestamp. |

### Table 3: `bank_beneficiaries_and_cooling_audit` (Payee Additions & Cooling-Period Tracking)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `beneficiary_uid` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Unique row ID. |
| `app_instance_id` | `INTEGER` | `NULL` | Owning banking app (or `NULL` if sourced from DLT SMS). |
| `source_vfs_file_id` | `INTEGER` | `NOT NULL` | Source file in `vfs_index`. |
| `recovery_classification` | `TEXT` | `NOT NULL` | 6-State Enum (`ORIGINAL_RECORD`, `HISTORICAL_COMMITTED_RECORD`, `RESIDUAL_RECORD`). |
| `beneficiary_holder_name` | `TEXT` | `NOT NULL` | Name of the added payee/beneficiary. |
| `beneficiary_account_no` | `TEXT` | `NOT NULL` | Full or masked bank account number of the payee. |
| `beneficiary_ifsc_11_char` | `TEXT` | `NULL` | 11-char IFSC code of the payee's bank branch. |
| `resolved_bank_and_branch_loc` | `TEXT` | `NULL` | Resolved Bank, Branch Name, City, District, and State (via Section 8.2). |
| `added_utc_iso` | `TEXT` | `NULL` | Exact timestamp when the beneficiary was added. |
| `cooling_period_end_utc_iso` | `TEXT` | `NULL` | Timestamp when cooling restrictions expired. |
| `first_transfer_utc_iso` | `TEXT` | `NULL` | Timestamp of the first transfer sent to this beneficiary. |
| `post_cooling_latency_minutes` | `REAL` | `NULL` | Minutes elapsed between addition/cooling-end and first transfer ($\Delta t$). |
| `is_rapid_mule_drain_flagged` | `INTEGER` | `DEFAULT 0` | `1` if first transfer occurred within $\le 15\text{ minutes}$ of addition or cooling expiry. |

### Table 4: `cardless_atm_and_unlocked_pdfs_ledger` (`YONO Cash`/`IMT` Tokens & Unlocked Statement PDFs)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `special_artifact_uid` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Unique ID. |
| `artifact_category` | `TEXT` | `NOT NULL` | Enum: `YONO_CASH_CARDLESS_ATM`, `ICICI_CARDLESS_ATM`, `AXIS_BOI_IMT_ATM`, `BARODA_CASH_ON_MOBILE`, `UNLOCKED_BANK_STATEMENT_PDF`. |
| `source_vfs_file_id` | `INTEGER` | `NOT NULL` | Source file in `vfs_index`. |
| `bank_institution_name` | `TEXT` | `NOT NULL` | Issuing bank name. |
| `cardless_ref_id_or_pdf_name` | `TEXT` | `NOT NULL` | 6-digit Cardless ATM Reference ID or PDF filename. |
| `amount_inr_or_row_count` | `REAL` | `NULL` | Withdrawal amount in INR (for ATM token) or number of statement rows extracted (for PDF). |
| `unlocked_pdf_password` | `TEXT` | `NULL` | Exact deterministic password that unlocked the PDF (e.g., `"RAHU1408"`). |
| `linked_runner_chat_recipient` | `TEXT` | `NULL` | Populated if the 6-digit ATM Reference ID was forwarded via WhatsApp/Telegram/SMS to a runner (Section 7.2). |
| `event_utc_iso` | `TEXT` | `NOT NULL` | Normalized UTC ISO-8601 timestamp. |

---

## 10. Developer Acceptance Test Checklist for Module 3.3

1. **The SBI `mPassbook` Narration Splitter & IFSC Branch Resolver Test:** Insert a row into an offline `mPassbook` SQLite table with `Narration = "UPI/DR/630914829104/VIKRAM SINGH/HDFC/vikram@okhdfcbank/Rent"` and a beneficiary row with `IFSC = "SBIN0000201"`. Verify that Sub-Engine 3.3A splits the narration to extract UTR `630914829104`, direction `DEBIT`, and VPA `vikram@okhdfcbank`, and resolves `SBIN0000201` via the offline RBI IFSC dictionary to `"State Bank of India — Varanasi Main Branch, Uttar Pradesh"`.
2. **The `YONO Cash` ATM Runner Cross-App Correlation Test:** Create a `YONO Cash` record generating Reference Number `"849201"` for `₹20,000` at `14:00:00 UTC`, and place an outbound WhatsApp message in `msgstore.db` at `14:02:15 UTC` to `+919811223344` reading `"Ref 849201 pin 445512 nikalo"`. Verify that Section 7.2's correlator automatically links `+919811223344` as `linked_runner_chat_recipient`.
3. **The Deterministic Bank Statement PDF Auto-Unlocker Test:** Create a password-protected PDF encrypted with `"RAHU1408"` (first 4 letters of `"RAHUL SHARMA"` + `DDMM` of DOB `14-08-1995`). Provide `"RAHUL SHARMA"` from the `shared_prefs` profile and run Sub-Engine 3.3E (even without providing the year of birth). Verify that Sub-Engine 3.3E tests the $366$ `RAHU<DDMM>` combinations, unlocks the PDF in $< 15\text{ ms}$, records `"RAHU1408"` in `unlocked_pdf_password`, and extracts the statement rows.
4. **The AePS Biometric Cash-Out & RD Service Detection Test:** Simulate a phone with `in.spicemoney.spicemoney` (`BC Agent ID = "SMA102938"`) and `com.mantra.rdservice` (`DeviceSerialNumber = "MFS100-9988776"`). Verify that Sub-Engine 3.3C links the attached Mantra fingerprint scanner serial number to the Spice Money profile and extracts the AePS cash-out rows into `bank_mpassbook_and_sandbox_ledger`.
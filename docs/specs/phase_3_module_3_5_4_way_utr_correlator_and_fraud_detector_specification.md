# Engineering Specification: Phase 3, Module 3.5 — The 4-Way UTR Correlator, VPA Handle Resolver & Mule-Account Fraud Detector

**Document Purpose:** This document provides the complete, step-by-step architectural blueprint for building **Module 3.5** of the Forensic Data Parser (the master intelligence and correlation engine of **Phase 3 / Group 13**). It contains **zero programming code** and explains every mathematical algorithm, multi-layer entity-resolution rule, Julian-day `UTR` vs. Aadhaar Verhoeff checksum formula, VPA bank-routing table, balance-chain gap equation, and mule-account fraud detector from first principles so that any developer can build a courtroom-defensible financial correlation engine.

---

## 1. Purpose & Mental Model (Why Raw Extraction Without Correlation Fails in Court)

After Modules 3.1, 3.2, 3.3, and 3.4 finish running, your case database holds raw financial records from **four separate on-device layers**:
* **Layer 1 (`L1` — App Sandbox Databases, `MMKV` & WebViews):** From Module 3.1 (UPI Super-Apps: `PhonePe`, `GPay India`, `Paytm`, `BHIM`, `WhatsApp Pay`, `FamPay`, etc.) and Module 3.3 (25 Indian Banking Apps, Offline `mPassbook` DBs, AePS Agent Ledgers, and Unlocked Statement PDFs).
* **Layer 2 (`L2` — Carrier TRAI DLT Financial SMS):** From Module 3.4 (`dlt_financial_sms_ledger` across `mmssms.db`, `bugle_db`, and iOS `sms.db`).
* **Layer 3 (`L3` — OS Push Notification Ledgers):** From Module 3.4 (`os_financial_notification_ledger` across iOS `DuetExpertCenter`, Apple Biome `SEGB`, Android Notification History, and Smartwatch Companion DBs).
* **Layer 4 (`L4` — Visual Payment Receipts & Screenshots):** From Phase 7's Offline OCR & QR Pipeline (payment screenshots in `/DCIM/Screenshots/`, WhatsApp/Telegram image folders, and App-Switcher Snapshots).

If your software dumps all four layers into a report without correlating and deduplicating them, **two catastrophic courtroom failures occur**:
1. **Triple-Counting Turnover Inflation:** A single ₹50,000 UPI payment made via PhonePe from an SBI account appears once in PhonePe's `workflow.db` (`L1`), once in SBI's `YONO mPassbook` (`L1`), once in `mmssms.db` (`L2`), once in `NotificationHistory` (`L3`), and once as a WhatsApp screenshot (`L4`). A naive tool adds them together and tells the court the suspect transferred **₹2,50,000** instead of **₹50,000**!
2. **Missing Cross-Layer Proof When a Suspect Claims "It Failed" or "I Uninstalled the App":** By fusing all records that share the same **12-Digit NPCI `UTR` / `RRN`** (or matching Fuzzy Time + Amount + Account Tail) into **one single Master Transaction Row**, your engine proves that an `INITIATED` or `PENDING` record in an app cache actually **settled at the bank switch** (via the matching `L2` DLT SMS and updated balance), or proves that a transaction occurred even after the app was uninstalled!

---

## 2. The 6 Fatal Mistakes Beginner Developers Make in Financial Correlation

Before implementing Module 3.5, the developer must understand six critical traps:

### Mistake 1: Confusing a 12-Digit Indian Aadhaar Number (`UIDAI`) with a 12-Digit NPCI `UTR` / `RRN`
* **The Trap:** Using a simple regex `\b[0-9]{12}\b` to extract 12-digit UPI UTR numbers from SMS messages, PDFs, or OCR screenshots.
* **Why It Fails:** India's national biometric ID—the **Aadhaar Number**—is also a **12-digit numeric string**! If a suspect receives an Aadhaar e-KYC message or stores an Aadhaar card photo, a naive `\b[0-9]{12}\b` extractor will misclassify the suspect's Aadhaar number as a UPI Transaction Reference!
* **The Rule:** Run every candidate 12-digit number through **Sub-Engine 3.5A (The Julian-Day `YDDD` & Verhoeff Dihedral Checksum Disambiguator)** in Section 3.

### Mistake 2: Failing to Merge Records When One Source Has a Truncated or Missing `UTR`
* **The Trap:** Grouping transactions strictly by `WHERE l1.utr == l2.utr`.
* **Why It Fails:** Some bank SMS templates or `DuetExpertCenter` notification rows omit the 12-digit UTR (or truncate it to the last 6 digits, e.g., `Ref XX29104`), recording only the timestamp, the exact Rupee amount (`₹25,000.00`), and the masked account tail (`XX4821`). If you only join on exact 12-digit UTR strings, that SMS and that PhonePe database row will not merge!
* **The Rule:** Use the **Two-Pass Deterministic + Fuzzy Window Fusion Engine** specified in Section 5.

### Mistake 3: Letting a Stale App Cache Status (`PENDING`) Override a Carrier Bank Debit SMS (`SETTLED`)
* **The Trap:** Taking the `status` field from whichever table is read first.
* **Why It Fails:** If a suspect's internet connection drops right after entering their UPI MPIN in PhonePe, PhonePe's local SQLite cache may record the transaction state as `PENDING` (or an earlier `-wal` frame may show `INITIATED`), even though the NPCI switch completed the transfer and the suspect's bank delivered a `DEBIT` SMS with a reduced `Avl Bal`.
* **The Rule:** Enforce the **Strict Evidence Hierarchy for Status & Field Resolution** (Section 5.3), where a verified Carrier DLT Bank SMS (`L2`) or Core-Banking `mPassbook`/PDF entry (`L1-Bank`) mathematically proves bank settlement.

### Mistake 4: Triggering False "Deleted SMS Balance Gaps" Due to Bank Charges, SMS Fees, or Interest
* **The Trap:** Flagging every tiny discrepancy where $\text{Bal}_{i-1} - \text{Debit}_i \neq \text{Bal}_i$ as "User Deleted a Bank SMS!"
* **Why It Fails:** Indian banks routinely deduct small automated charges—such as quarterly SMS alert fees (`₹17.70`), IMPS transfer fees (`₹2.36`, `₹5.90`, or `₹11.80` including $18\%$ GST), or minimum-balance penalties—without sending a separate SMS for the ₹5.90 fee!
* **The Rule:** Build an **Automated Fee & Micro-Charge Tolerance Filter** into the Balance-Chain Auditor (Section 6.1) so that minor bank fee deltas ($\le ₹50.00$ or exact $18\%$ GST multiples) are classified as `BANK_FEE_OR_CHARGES_DELTA`, reserving `CRITICAL` `DELETED_SMS_BALANCE_GAP` alerts for substantive unexplained discrepancies!

### Mistake 5: Missing the "Split-SIM / Two-Phone Mule Architecture"
* **The Trap:** Assuming the SIM card linked to a bank account is always inside the same phone that runs the UPI/banking app.
* **Why It Fails:** Professional cybercrime syndicates split operations across two physical locations:
  * **Location A (The SIM Box / Mule SIM Holder):** Holds the physical SIM card (`XX4821`) that receives incoming Bank DLT Debit/Credit SMS alerts and OTPs (`Layer 2` present, `Layer 1` absent).
  * **Location B (The Cash-Out Operator):** Runs the logged-in UPI or Internet Banking app (`Layer 1` present, `Layer 2` absent or on a different SIM).
* **The Rule:** Sub-Engine 3.5D (Detector 3) compares `Layer 1` account activity against `Layer 2` SIM (`sub_id` / `ICCID`) activity on the seized phone to automatically prove whether the seized handset was acting as the **App Operator**, the **SIM/OTP Relay**, or **Both**.

### Mistake 6: Failing to Link Counterparty VPAs to Messaging & Call Logs (Group 13 $\leftrightarrow$ Groups 1 & 2)
* **The Trap:** Leaving a counterparty VPA like `9876543210@ybl` or `vikram.singh@okaxis` isolated inside the Financial tab.
* **Why It Fails:** Investigators need to know immediately: *Did the suspect talk to this counterparty on WhatsApp, Telegram, Signal, or phone calls before sending them ₹1,00,000?*
* **The Rule:** Automatically cross-link every counterparty mobile number and verified CBS name extracted in Phase 3 against **Group 1 (Calls/Chats)** and **Group 2 (Contacts)**.

---

## 3. Step 1 — Sub-Engine 3.5A: The 12-Digit NPCI `UTR` / `RRN` Validator vs. Aadhaar Verhoeff Disambiguator

Whenever any module extracts a 12-digit numeric string $S = d_1 d_2 d_3 d_4 d_5 d_6 d_7 d_8 d_9 d_{10} d_{11} d_{12}$, Sub-Engine 3.5A executes a **3-Stage Mathematical Classification Test**:

### 3.1 Stage 1: NPCI `YDDD` Julian Date Extraction & Timestamp Consistency Math
In NPCI's standard 12-digit RRN/UTR specification (used by UPI, IMPS, and AePS switches):
1. **Digit 1 ($d_1$):** Last digit of the calendar year:
   $$y_{\text{utr}} = \text{int}(d_1)$$
   *(For example, in 2026 $y_{\text{utr}} = 6$; in 2025 $y_{\text{utr}} = 5$; in 2024 $y_{\text{utr}} = 4$).*
2. **Digits 2–4 ($d_2 d_3 d_4$):** 3-digit **Julian Day of the Year** ($1\text{ to }366$):
   $$J_{\text{utr}} = \text{int}(d_2 d_3 d_4)$$
   * **How to Compute the Expected Julian Day $J_{\text{tx}}$ from the Transaction Timestamp:**
     * Convert the transaction's UTC timestamp to **Indian Standard Time (`IST = UTC + 05:30`)** (because Indian bank switches generate the RRN using the IST calendar date!).
     * Let $(Y_{\text{ist}}, M_{\text{ist}}, D_{\text{ist}})$ be the IST Year, Month ($1\text{–}12$), and Day ($1\text{–}31$).
     * Compute the ordinal day of the year $J_{\text{tx}} \in [1, 366]$ (where Jan 1 = $1$, Feb 1 = $32$, ..., Nov 5, 2026 = $309$, Dec 31 = $365$ or $366$ in a leap year).
3. **Evaluate the `YDDD` Match:**
   * **Condition A (Invalid Julian Range):** If $J_{\text{utr}} == 0$ or $J_{\text{utr}} > 366$, then $S$ **cannot** be a standard `YDDD` NPCI RRN!
   * **Condition B (Exact Date Match):** If $y_{\text{utr}} == (Y_{\text{ist}} \bmod 10)$ AND $|J_{\text{utr}} - J_{\text{tx}}| \le 1$ (allowing $\pm 1\text{ day}$ for midnight switch settlement tolerance):
     * Mark `utr_validation_status = "VALID_NPCI_YDDD_MATCH"`.
   * **Condition C (Date Mismatch on OCR Screenshot):** If $S$ was extracted from a payment screenshot (`Layer 4`) with an explicit labeled label `"UPI transaction ID"` or `"UTR"`, and $1 \le J_{\text{utr}} \le 366$, **but $|J_{\text{utr}} - J_{\text{tx}}| > 2$ or $y_{\text{utr}} \neq (Y_{\text{ist}} \bmod 10)$**:
     * Mark `utr_validation_status = "ANOMALOUS_UTR_DATE_MISMATCH"` and trigger a **Forged Receipt Alert**!

### 3.2 Stage 2: Disambiguating 12-Digit UIDAI Aadhaar Numbers (`Verhoeff` Algorithm)
If a 12-digit number appears without an explicit `"UTR"`/`"Ref"` prefix, test if it is an **Indian Aadhaar Number**:
1. **Aadhaar Prefix Rule:** A valid UIDAI Aadhaar number **never starts with `0` or `1`** ($d_1 \in \{2, 3, 4, 5, 6, 7, 8, 9\}$).
2. **The Verhoeff Dihedral Group $D_5$ Checksum Test:**
   * UIDAI generates the 12th digit ($d_{12}$) of every Aadhaar number using the **Verhoeff Checksum Algorithm**, which uses three fixed $10 \times 10$ lookup tables: the multiplication table $d(j, k)$, the permutation table $p(\text{pos}, \text{digit})$, and the inverse table $\text{inv}(j)$.
   * Process the 12 digits from **right to left** ($i = 0, 1, \dots, 11$, where $i=0$ is $d_{12}$):
     * Initialize checksum accumulator $c = 0$.
     * For $i = 0\text{ to }11$: set $c = d\big(c, \ p(i \bmod 8, \ \text{digit}_{12 - i})\big)$.
   * If final $c == 0$ AND the surrounding text does not say `"UPI"`/`"Ref"`/`"UTR"`, classify as an **Aadhaar Identifier** rather than a UPI UTR.

---

## 4. Step 2 — Sub-Engine 3.5B: Master VPA Suffix (`@<handle>`) Resolver & Identity Graph Builder

Whenever any module extracts a UPI Virtual Payment Address (`<prefix>@<suffix>`), Sub-Engine 3.5B normalizes the string to lowercase, splits it on `@`, and resolves both parts:

### 4.1 Complete 45-Handle Indian UPI VPA Routing Dictionary

| VPA `@suffix` | Consumer / Merchant UPI App (TPAP) | Acquiring / Sponsor PSP Bank (For Section 94 BNSS Notice) |
|---|---|---|
| `@ybl` | **PhonePe** | **Yes Bank** |
| `@ibl` | **PhonePe** | **ICICI Bank** |
| `@axl` | **PhonePe** | **Axis Bank** |
| `@okaxis` | **Google Pay India** | **Axis Bank** |
| `@okhdfcbank` | **Google Pay India** | **HDFC Bank** |
| `@okicici` | **Google Pay India** | **ICICI Bank** |
| `@oksbi` | **Google Pay India** | **State Bank of India (SBI)** |
| `@ptyes` | **Paytm** | **Yes Bank** |
| `@ptaxis` | **Paytm** | **Axis Bank** |
| `@pthdfc` | **Paytm** | **HDFC Bank** |
| `@ptsbi` | **Paytm** | **State Bank of India (SBI)** |
| `@paytm` | **Paytm (Legacy PPBL)** | **Paytm Payments Bank / Migrated TPAP** |
| `@upi` | **BHIM** | **NPCI (National Payments Corporation of India)** |
| `@waicici` | **WhatsApp Pay** | **ICICI Bank** |
| `@wahdfcbank` | **WhatsApp Pay** | **HDFC Bank** |
| `@waaxis` | **WhatsApp Pay** | **Axis Bank** |
| `@wasbi` | **WhatsApp Pay** | **State Bank of India (SBI)** |
| `@apl` | **Amazon Pay India** | **Axis Bank** |
| `@yapl` | **Amazon Pay India** | **Yes Bank** |
| `@rapl` | **Amazon Pay India** | **RBL Bank** |
| `@fam` / `@fampay` | **FamPay** | **IDFC FIRST Bank / Tri O Tech** |
| `@sliceaxis` / `@slice` | **Slice** | **Axis Bank / North East Small Finance Bank** |
| `@axisb` | **CRED** | **Axis Bank** |
| `@yescred` | **CRED** | **Yes Bank** |
| `@naviaxis` | **Navi** | **Axis Bank** |
| `@superyes` | **super.money (Flipkart)** | **Yes Bank** |
| `@ikwik` | **MobiKwik** | **HDFC Bank / ICICI Bank** |
| `@freecharge` | **Freecharge** | **Axis Bank** |
| `@bharatpe` / `@bpunity` | **BharatPe (Merchant)** | **Unity Small Finance Bank / Yes Bank** |
| `@sbi` | **YONO SBI / BHIM SBI Pay** | **State Bank of India (SBI)** |
| `@icici` | **iMobile Pay (ICICI)** | **ICICI Bank** |
| `@hdfcbank` / `@pz` | **HDFC MobileBanking / PayZapp** | **HDFC Bank** |
| `@kotak` | **Kotak811 / Kotak Mobile** | **Kotak Mahindra Bank** |
| `@axisbank` | **Axis Mobile** | **Axis Bank** |
| `@barodampay` | **bob World** | **Bank of Baroda** |
| `@pnb` | **PNB One** | **Punjab National Bank** |
| `@cnrb` | **Canara ai1** | **Canara Bank** |
| `@uboi` | **Union Bank Vyom** | **Union Bank of India** |
| `@indianbank` | **IndOASIS / IndSMART** | **Indian Bank** |
| `@airtel` / `@airtelpaymentsbank` | **Airtel Thanks** | **Airtel Payments Bank** |
| `@postbank` / `@dakpay` | **IPPB Mobile / DakPay** | **India Post Payments Bank (IPPB)** |
| `@jio` | **MyJio / JioFinance** | **Jio Payments Bank** |
| `@federal` / `@fi` / `@jupiteraxis` | **FedMobile / Fi Money / Jupiter** | **Federal Bank (`@federal`/`@fi`) / Axis Bank (`@jupiteraxis`)** |
| `@indus` | **IndusMobile / INDIE** | **IndusInd Bank** |
| `@idfcfirst` | **IDFC FIRST Mobile** | **IDFC FIRST Bank** |
| `@yesbank` / `@yespay` | **IRIS by YES BANK** | **Yes Bank** |
| `@aubank` | **AU 0101** | **AU Small Finance Bank** |

### 4.2 Counterparty Mobile Number & Special VPA Prefix Extraction
Inspect the `<prefix>` before `@`:
1. **Direct 10-Digit Mobile VPA (`9876543210@ybl`):** If `<prefix>` matches `^[6-9][0-9]{9}$` (or `^91[6-9][0-9]{9}$`), extract the 10-digit number as `inferred_mobile_number`.
2. **Suffixed Secondary Account Mobile VPA (`9876543210-2@okaxis` or `9876543210.wallet@paytm`):** When a user links a second bank account in Google Pay or PhonePe, the app appends `-1`, `-2`, or `.wallet` to their 10-digit phone number! Strip `-[0-9]+$` or `\..+$` and check if the leading 10 digits match `^[6-9][0-9]{9}$`—if so, extract those 10 digits as `inferred_mobile_number`!
3. **Bank Account + IFSC Direct Routing VPA (`<AccountNo>@<11_Char_IFSC>.ifsc.npci`):**
   * When a UPI app sends money directly to a bank account + IFSC (without knowing the recipient's VPA), NPCI formats the payee address as:
     $$\texttt{<Bank\_Account\_Number>@<11\_Char\_IFSC>.ifsc.npci}$$
   * Whenever `@suffix` ends with `.ifsc.npci`, split `<prefix>` as the **Full Unmasked Counterparty Bank Account Number** and the 11 characters after `@` as the **Exact Counterparty IFSC Code** (and resolve its physical branch and city via Module 3.3 Section 8.2)!

---

## 5. Step 3 — Sub-Engine 3.5C: The 4-Way Transaction Fusion & Deduplication State Machine

Sub-Engine 3.5C ingests all records from:
* `upi_app_sandbox_transactions` (`Module 3.1 — Layer 1A`)
* `bank_mpassbook_and_sandbox_ledger` (`Module 3.3 — Layer 1B`)
* `dlt_financial_sms_ledger` (`Module 3.4 — Layer 2`)
* `os_financial_notification_ledger` (`Module 3.4 — Layer 3`)
* `ocr_visual_payment_receipts` (`Phase 7 — Layer 4`)

### 5.1 Pass 1: Exact `UTR` / `RRN` Deterministic Clustering
1. Normalize all extracted `utr_or_rrn` strings (trim whitespace, uppercase alphanumeric NEFT/RTGS UTRs, strip leading/trailing punctuation).
2. Group every record across Layers 1, 2, 3, and 4 that shares the exact same non-null `utr_or_rrn` into a single **Master Transaction Cluster**.
   * *Special Self-Transfer Handling:* If the suspect transferred ₹50,000 from **their own SBI Account (`XX4821`)** to **their own HDFC Account (`XX9912`)** on the same phone, the phone will receive *two* DLT SMS messages with the exact same 12-digit UTR: one `DEBIT` SMS from `SBIINB` (`XX4821`) and one `CREDIT` SMS from `HDFCBK` (`XX9912`).
   * **Rule:** When a cluster contains both a verified `DEBIT` on Local Account A and a verified `CREDIT` on Local Account B for the same UTR, merge them into a single Master Row with `transaction_type = "SELF_ACCOUNT_TRANSFER"`, recording `sender_account = XX4821 (SBI)` and `receiver_account = XX9912 (HDFC)`!

### 5.2 Pass 2: Secondary Fuzzy Window Clustering (For Records Missing a Full UTR)
For records that do not have a full 12-digit UTR (such as an OS push notification in `Layer 3`, a truncated SMS `Ref XX9104` in `Layer 2`, or a `PENDING`/`FAILED` app initiation row in `Layer 1`):
1. Search existing Master Transaction Clusters within a timestamp window of:
   $$|\text{ts}_{\text{candidate}} - \text{ts}_{\text{cluster}}| \le 180\text{ seconds}$$
   *(Expandable to $\le 600\text{ seconds}$ if matching an `os_financial_notification_ledger` `DuetExpertCenter` metadata-only ping where `app_bundle_id` matches the UPI app that executed the transaction).*
2. **Fuzzy Match Criteria:** Attach the un-keyed record to the cluster if:
   * `amount_inr_decimal` is an **exact match** ($\Delta \text{Amount} == 0.00$), AND
   * At least one secondary identifier matches: `account_tail_digits` (`4821`), `truncated_utr_suffix` (`9104`), `counterparty_vpa`, or `app_bundle_id`.

### 5.3 Pass 3: Field Priority & Conflict Resolution Rules

When merging multiple layers into a single row in `unified_financial_transactions_ledger`, resolve each column using this strict priority order:

| Target Master Column | Priority 1 (Highest Authority) | Priority 2 | Priority 3 (Fallback) |
|---|---|---|---|
| **`settlement_status`** | **Layer 2 (DLT Bank Debit/Credit SMS)** or **Layer 1B (`mPassbook` / Unlocked Bank PDF)** $\rightarrow$ Proves `SETTLED_SUCCESS` at the core bank switch! | **Layer 1A (UPI App Sandbox DB)** (`COMPLETED` / `SUCCESS` / `FAILED` / `DECLINED`) | **Layer 3 (OS Notification)** or **Layer 4 (OCR Screenshot)** |
| **`counterparty_cbs_name`** | **Layer 1A (UPI App NPCI `ReqValAdd` Verified CBS Banking Name)** or **Layer 1B (`mPassbook` Narration)** | **Layer 2 (DLT SMS Counterparty String)** | **Layer 4 (OCR Screenshot Name)** |
| **`sender_vpa` & `receiver_vpa`** | **Layer 1A (UPI App Sandbox DB / QR TLV)** | **Layer 1B (`mPassbook` Narration)** or **Layer 2 (DLT SMS)** | **Layer 4 (OCR Screenshot)** |
| **`post_tx_balance_inr`** | **Layer 1B (`mPassbook` / Bank Statement PDF Running Balance)** | **Layer 2 (DLT Bank SMS `Avl Bal`)** | `NULL` (Consumer UPI apps do not know post-tx bank balance unless queried) |
| **`tx_timestamp_utc_iso`** | **Layer 1A (UPI App Millisecond Timestamp)** or **Layer 2 (DLT SMS `date_sent`)** | **Layer 3 (OS Notification Delivery Timestamp)** | **Layer 4 (Screenshot File `btime`/`EXIF`)** |

---

## 6. Step 4 — Sub-Engine 3.5D: The 6 Automated Mule-Account, Balance-Gap & Cyber-Fraud Detectors

After building `unified_financial_transactions_ledger`, Sub-Engine 3.5D runs six mathematical fraud detectors across the ledger and writes findings into `financial_corroboration_and_fraud_flags`:

### 6.1 Detector 1: The Mathematical Balance-Chain & Deleted-SMS Gap Auditor
For every discovered bank account in `upi_and_bank_accounts_inventory` that has $\ge 2$ records containing a non-null `post_tx_balance_inr` (from DLT SMS or `mPassbook`):
1. Sort all balance-bearing transactions for that bank account in strict chronological order ($i = 1, 2, \dots, N$).
2. For each consecutive pair of transactions $(i - 1, i)$, let:
   * $B_{i-1} =$ `post_tx_balance_inr` after Transaction $i - 1$.
   * $B_{i} =$ `post_tx_balance_inr` after Transaction $i$.
   * $A_i =$ signed `amount_inr_decimal` of Transaction $i$ ($-A_i$ if `DEBIT_OUTFLOW`, $+A_i$ if `CREDIT_INFLOW`).
3. Compute the **Expected Balance ($B_{\text{expected}}$)** and the **Unexplained Balance Discrepancy ($\Delta B$)**:
   $$B_{\text{expected}} = B_{i-1} + A_i$$
   $$\Delta B = B_i - B_{\text{expected}}$$
4. **Evaluate $\Delta B$:**
   * **Case 1 ($|\Delta B| \le ₹0.05$):** **Perfect Mathematical Continuity!** Every single Rupee between $t_{i-1}$ and $t_i$ is accounted for.
   * **Case 2 ($₹0.05 < |\Delta B| \le ₹50.00$ OR $|\Delta B|$ matches a standard IMPS+GST fee such as `₹2.36`, `₹2.95`, `₹5.90`, `₹11.80`, `₹17.70`, `₹23.60`):** Classify as `MINOR_BANK_FEE_OR_SMS_CHARGE_DELTA` (do not false-alarm!).
   * **Case 3 ($|\Delta B| > ₹50.00$):**
     * **Mathematical Proof of Missing/Deleted Evidence!** Between $t_{i-1}$ and $t_i$, the account balance changed by $\Delta B$ Rupees with no surviving SMS or passbook entry!
     * Check if a carved residual row from **Phase 2, Module 2.1 (`-wal` or Freelist)** exists in that exact time window $[t_{i-1}, t_i]$ with amount $\approx |\Delta B|$.
     * Emit a **`CRITICAL` Alert (`DELETED_SMS_BALANCE_GAP`)** stating the exact missing Rupee amount $\Delta B$, the exact start time $t_{i-1}$, and the exact end time $t_i$!

### 6.2 Detector 2: The High-Velocity Mule Pass-Through & Layering Detector
Scan every local bank account across a sliding **$60\text{-minute}$ window** (and a **$24\text{-hour}$ window**):
* Let $\sum \text{Inflow}$ be the sum of settled credits from $\ge 3$ distinct sender VPAs/accounts inside the window, and let $\sum \text{Outflow}$ be the sum of settled debits sent out within $60\text{ minutes}$ of those credits.
* Calculate the **Pass-Through Ratio ($R_{\text{pass}}$)**:
  $$R_{\text{pass}} = \frac{\sum \text{Outflow}}{\sum \text{Inflow}}$$
* If $\sum \text{Inflow} \ge ₹25,000$ AND $R_{\text{pass}} \in [0.80, 1.05]$ (meaning $80\%\text{ to }100\%$ of incoming funds were immediately drained out to Layer-2 accounts, cardless ATMs, or crypto P2P sellers, leaving a near-zero retention balance):
  * Emit a **`CRITICAL` Alert (`MULE_HIGH_VELOCITY_PASSTHROUGH`)**!

### 6.3 Detector 3: The Split-SIM / Remote-Device Mule Architecture Detector
For every bank account in `upi_and_bank_accounts_inventory`, inspect which layers contributed transactions:
* **Pattern A (`REMOTE_APP_LOCAL_SIM_OTP_RELAY`):** The phone's physical SIM card (`mmssms.db` in `Layer 2`) received $\ge 3$ bank debit/OTP DLT SMS alerts for Account `XX4821`, **but zero UPI or banking apps for Account `XX4821` exist in `Layer 1` (active or uninstalled Ghost Apps)**!
  * *Forensic Meaning:* This seized phone was holding the **Mule SIM Card** to relay OTPs and monitor bank alerts while a co-conspirator operated the internet banking / UPI app on a **separate remote device**!
* **Pattern B (`LOCAL_APP_EXTERNAL_SIM_CARD`):** A UPI or Corporate Banking app on this phone (`Layer 1`) executed settled transactions on Account `XX4821`, **but the SIM card `ICCID` / `MSISDN` bound to `XX4821` was never inserted in this phone (`telephony.db` `siminfo`) and zero DLT SMS alerts for `XX4821` exist in `mmssms.db`**!
  * *Forensic Meaning:* The suspect operated Account `XX4821` on this phone using a SIM card housed inside a different phone (e.g., via remote Ghost SIM-Binding or Corporate Internet Banking login)!

### 6.4 Detector 4: Concurrent Trojan, Screen-Share ("Digital Arrest") & OTP Relay Detector
For every outbound `DEBIT_OUTFLOW` transaction and every `OTP_AUTHENTICATION_CODE` SMS in `dlt_financial_sms_ledger` at timestamp $t_{\text{tx}}$:
1. **Check 1 (Concurrent Voice/Video/Screen-Share Call — "Digital Arrest" / Social Engineering Signature):**
   * Query **Group 1 (Call History, WhatsApp Calls, Telegram Calls)** and **Group 8 (`UsageStats` / `knowledgeC` foreground apps)** for any active call or remote-desktop session (`AnyDesk`, `RustDesk`, `TeamViewer`, `AirDroid`, `QuickSupport`, `WhatsApp Video Call`, `Skype`, `Zoom`) overlapping $t_{\text{tx}}$!
2. **Check 2 (Active SMS-Forwarding / Overlay Malware):**
   * Check **Group 9 & Group 17** for any sideloaded APK installed prior to $t_{\text{tx}}$ holding `RECEIVE_SMS`, `READ_SMS`, or `BIND_ACCESSIBILITY_SERVICE` permissions, or check if the OTP string was transmitted outbound via SMS, WhatsApp, Telegram, or HTTP within $\le 60\text{ seconds}$ of $t_{\text{tx}}$.
   * If matched, emit a **`CRITICAL` Alert (`CONCURRENT_TROJAN_OR_SCREENSHARE_DURING_TX`)**.

### 6.5 Detector 5: The `1930` NCRP Lien & Post-Freeze Account-Hopping Detector
Whenever Sub-Engine 3.4C detects a **`LIEN_HOLD_OR_FREEZE_ALERT`** on Account A at timestamp $t_{\text{lien}}$:
* Check if the suspect initiated transfers or switched active UPI/banking usage to a **different bank account (Account B)** within $[t_{\text{lien}}, t_{\text{lien}} + 24\text{ hours}]$, or searched for `"account freeze"` / `"cyber cell"` / `"lien"` in Group 6 (Browser History) or Group 1 (Chats).
* Emit a **`CRITICAL` Alert (`NCRP_1930_LIEN_AND_POST_FREEZE_ACTIVITY`)**—proving guilty knowledge (`mens rea`) of the cybercrime freeze!

---

## 7. Database Schema for Module 3.5 (`financial_correlator_and_fraud_engine.sqlite`)

Module 3.5 populates the five master tables defined in our Phase 3 overview (`upi_and_bank_accounts_inventory`, `unified_financial_transactions_ledger`, `upi_vpa_and_counterparty_directory`, `npci_device_sim_binding_audit`, and `financial_corroboration_and_fraud_flags`), plus the following dedicated **Cross-Group Communication Link Table**:

### Table: `financial_counterparty_comms_crosslink` (Linking Group 13 Money Flows $\leftrightarrow$ Group 1 & 2 Calls/Chats/Contacts)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `crosslink_uid` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Unique ID. |
| `vpa_entry_uid` | `INTEGER` | `NOT NULL` | Foreign key to `upi_vpa_and_counterparty_directory.vpa_entry_uid`. |
| `counterparty_vpa_or_acct` | `TEXT` | `NOT NULL` | Counterparty VPA or bank account number. |
| `counterparty_cbs_name` | `TEXT` | `NULL` | Verified banking name. |
| `matched_mobile_number` | `TEXT` | `NOT NULL` | 10-digit mobile number bridging Group 13 to Groups 1 & 2. |
| `local_contact_saved_name` | `TEXT` | `NULL` | Name in suspect's phonebook (`AddressBook.sqlitedb` / `contacts2.db`). |
| `voice_calls_count` | `INTEGER` | `DEFAULT 0` | Number of cellular/WhatsApp/Telegram calls with this counterparty. |
| `chat_messages_count` | `INTEGER` | `DEFAULT 0` | Number of WhatsApp/Telegram/Signal/SMS messages exchanged with this counterparty. |
| `shortest_chat_to_tx_delta_sec` | `INTEGER` | `NULL` | Smallest time gap (in seconds) between a chat/call with this person and a financial transfer to/from them! |

---

## 8. Developer Acceptance Test Checklist for Module 3.5

1. **The 4-Layer Single-Transaction Deduplication Test:** Insert the same ₹50,000 transaction (`UTR = "630914829104"`) into four input tables: (a) PhonePe `upi_app_sandbox_transactions`, (b) SBI `bank_mpassbook_and_sandbox_ledger`, (c) `dlt_financial_sms_ledger`, and (d) `os_financial_notification_ledger`. Run Sub-Engine 3.5C and verify that **exactly 1 row** is created in `unified_financial_transactions_ledger` (not 4 rows!), with `corroboration_level = "SETTLED_BANK_AND_APP_VERIFIED"` and all 4 source row IDs preserved in `source_records_lineage_json`.
2. **The Verhoeff Aadhaar vs. Julian-Day `UTR` Disambiguation Test:** Pass a valid 12-digit Aadhaar number (satisfying the Verhoeff $D_5$ checksum where Digits 2–4 are `482 > 366`) and a valid 12-digit NPCI UTR (`630914829104` on Nov 5, 2026, Julian day `309`) into Sub-Engine 3.5A. Verify that the Aadhaar number is rejected as a UTR and tagged as an Aadhaar ID, while `630914829104` is validated as `VALID_NPCI_YDDD_MATCH`.
3. **The IMPS+GST Fee Tolerance vs. True Deleted-SMS Gap Test:**
   * Test A: `SMS 1` has `Avl Bal = 10,000.00`. `SMS 2` is an IMPS debit of `5,000.00` with `Avl Bal = 4,994.10` (a `₹5.90` IMPS + 18% GST bank fee). Verify that Detector 1 classifies the `₹5.90` difference as `MINOR_BANK_FEE_OR_SMS_CHARGE_DELTA` without raising a false deletion alarm.
   * Test B: `SMS 3` is a debit of `1,000.00` with `Avl Bal = 994.10` (an unexplained `₹3,000.00` missing drop!). Verify that Detector 1 triggers a `CRITICAL` `DELETED_SMS_BALANCE_GAP` alert for exactly `₹3,000.00`.
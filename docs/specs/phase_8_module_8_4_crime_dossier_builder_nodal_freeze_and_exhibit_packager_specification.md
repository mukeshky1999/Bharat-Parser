# Engineering Specification: Phase 8, Module 8.4 — Crime-Typology Dossier Builder, Nodal Agency (`1930` NCRP / `FIU-IND` / CEX) Freeze Exporter, Section 94 BNSS Requisition Drafter & Courtroom Exhibit Packager

**Document Purpose:** This document provides the complete, step-by-step architectural blueprint for building **Module 8.4** of the Forensic Data Parser (completing **Phase 8** and synthesizing all outputs from **Modules 1.1 through 8.3**). It contains **zero programming code** and explains how to automatically compile raw forensic findings into **4 Statutory Indian Crime-Typology Investigation Dossiers**, how to generate immediate **"Golden Hour" Nodal Agency Freeze & Lien Packets** (`I4C NCRP 1930 CFCFRMS`, `NPCI`, `FIU-IND`, `Binance LERP`, and `Tether USDT` smart-contract freeze tables), how to auto-draft **Section 94 BNSS, 2023** (formerly Section 91 CrPC) legal requisitions for discovered bank accounts, cell towers, and CEX UIDs, and how to package deterministic `PDF/A-3b` Courtroom Reports and **Section 230 BNSS, 2023 Air-Gapped Defense Disclosure Bundles** (with mandatory **POCSO / CSAM & Unrelied-Privacy Redaction Gates**) from first principles.

---

## 1. Purpose & Mental Model (Why Law Enforcement Needs "Golden Hour" Action Packets & Chargesheet-Ready Dossiers)

When a seized mobile phone arrives at a Police Cyber Cell, Economic Offences Wing (`EOW`), Special Task Force (`STF`), or Central Agency (`CBI`, `NIA`, `ED`, `NCB`), the Investigating Officer (IO) operates under **two distinct operational clocks**:

1. **Clock 1 — The "Golden Hour" Asset Freeze & Requisition Window (First $1\text{ to }6\text{ Hours}$ After Seizure):**
   * If the seized phone belongs to a cyber-fraud mule coordinator, a hawala operator, or an extortionist, the stolen money (`INR` in Layer-1/2/3 bank accounts and `USDT` in `TronLink` or `Binance` wallets) will be moved and cashed out by remote accomplices within hours of the suspect's arrest!
   * An IO cannot wait 3 days to read 50,000 chat messages to find which bank accounts and crypto wallets need to be frozen.
   * **Sub-Engine 8.4B** extracts every bank account, 12-digit `UTR`, UPI `VPA`, CEX `UID`, P2P Order ID, and `TRC-20`/`ERC-20` wallet address discovered across **Phases 3, 4, 5, and 7** and exports them—within minutes of ingestion—into ready-to-upload **I4C NCRP (`1930` `CFCFRMS`) Bank Lien CSVs**, **FIU-IND / Binance LERP / Tether (`USDT`) Freeze Requests**, and pre-drafted **Section 94 BNSS, 2023 Statutory Notices** to Nodal Officers!
2. **Clock 2 — The Statutory Chargesheet / Final Report Window (`60` or `90 Days` under Section 187 / Section 193 BNSS, 2023):**
   * When filing the Chargesheet (Final Report under **Section 193 of the Bharatiya Nagarik Suraksha Sanhita \[BNSS\], 2023**, formerly Section 173 CrPC), a 40,000-page raw dump of every table on the phone is useless to a Public Prosecutor and overwhelming to a Sessions Judge.
   * **Sub-Engine 8.4A & 8.4C** organize the cross-linked evidence from **Modules 8.1–8.3** into concise, self-proving **Crime-Typology Courtroom Dossiers** where every factual assertion is backed by its exact 3-Tier `SHA-256` Hash Lineage, SQLite/WAL/Hex byte offset, and bound **Section 63(4)(c) BSA 2023 Certificate**.

---

## 2. The 6 Fatal Mistakes Beginner Developers Make in Law Enforcement Exports & Courtroom Packaging

Before implementing Module 8.4, the developer must understand six critical operational and legal traps:

### Mistake 1: Dumping Raw Unfiltered Database Tables Instead of Ingredient-Mapped Crime Dossiers
* **The Trap:** Exporting a 15,000-page PDF listing all 200,000 WhatsApp messages in chronological order when only 45 messages relate to the extortion or mule conspiracy.
* **Why It Fails:** Public Prosecutors and Judges need evidence grouped by the **legal ingredients of the offence**:
  * *Identity & Attribution of the Device Owner* (Who used this phone?)
  * *Mens Rea & Conspiracy Communications* (With whom did they conspire, including recovered deleted/revoked messages and platform switches?)
  * *Actus Reus & Financial/Physical Execution* (Which transactions, travel routes, or crime-scene visits occurred while the user physically held and unlocked the phone?)
  * *Anti-Forensics & Spoliation* (What did the suspect delete, hide in a vault, or tamper with?)
* **The Rule:** Sub-Engine 8.4A structures every dossier into these exact courtroom-logical sections tailored to the 4 primary Indian crime typologies (Section 3).

### Mistake 2: Exporting Bank & UPI Data in Non-Standard Columns That Cannot Be Uploaded to `NCRP (1930)` or Bank Nodal Portals
* **The Trap:** Exporting a generic table of UPI transactions without separating the **12-digit `UTR`**, **Beneficiary Account Number**, **11-character `IFSC`**, **Bank Name**, **VPA**, and **IST Transaction Timestamp**.
* **Why It Fails:** India's **National Cybercrime Reporting Portal (`NCRP` / `1930` `CFCFRMS`)** operated by **I4C (Indian Cyber Crime Coordination Centre, MHA)** and Bank Nodal Officer bulk-lien portals require specific standardized fields (`UTR / RRN Number [12 digits]`, `Transaction Date & Time [IST]`, `Transaction Amount [INR]`, `Beneficiary Bank Name`, `Beneficiary Account No / VPA`, `IFSC Code`, and `Layer Number`) to place an automated debit freeze (`Lien`) on a mule account.
* **The Rule:** Sub-Engine 8.4B formats bank and UPI exports strictly to the **I4C / NCRP / NPCI Nodal Freeze Specification** (Section 4.1).

### Mistake 3: Forgetting to Auto-Generate `Section 94 BNSS, 2023` (erstwhile `Section 91 CrPC`) Requisitions for Unmasked Leads
* **The Trap:** Discovering an accomplice's phone number (`+919876543210`), a serving 4G Cell Tower (`405-86-1042-eNodeB 1048577`), a Binance `UID` (`482910482`), or a Blinkit Order ID (`ORD998877`) on the phone, and leaving the Investigating Officer to manually type 25 separate legal notices in Microsoft Word.
* **Why It Fails:** Manually drafting 25 notices under **Section 94 of the Bharatiya Nagarik Suraksha Sanhita (BNSS), 2023** (which replaced Section 91 CrPC on July 1, 2024) wastes hours of critical investigation time and introduces typographical errors in 12-digit UTRs, 19-digit P2P Order IDs, or 34-char TRON addresses.
* **The Rule:** Sub-Engine 8.4B automatically drafts **ready-to-sign Section 94 BNSS, 2023 Requisition Notices** addressed to the exact Telecom Service Provider (`Jio`/`Airtel`/`Vi`/`BSNL`), Bank Nodal Officer (resolved via IFSC!), CEX Compliance Officer, or Hyper-Local/Mobility Nodal Officer (Section 4.3)!

### Mistake 4: Violating `POCSO Act` & Supreme Court Privacy Safeguards When Creating `Section 230 BNSS` Defense Copies
* **The Trap:** Creating a full "Clone Report / Defense Export" for supply to the accused under **Section 230 BNSS, 2023** (erstwhile Section 207 CrPC) that includes **raw images/videos of Child Sexual Exploitation and Abuse Material (`CSAM` / `POCSO` offences)**, **non-consensual intimate/sexual assault footage** (in rape/sextortion cases), or **unrelied-upon private data**!
* **Why It Fails:**
  1. In **In Re: Prajwala** and **P. Gopalkrishnan @ Dileep v. State of Kerala (2019)**, the Supreme Court of India held that while an accused is entitled to copies of relied-upon electronic records under Section 207 CrPC (now Section 230 BNSS), **visual media depicting sexual assault, sextortion intimacy, or CSAM/POCSO material MUST NEVER be handed over as raw image/video copies to the accused or defense** (to prevent secondary victimization and illegal redistribution; instead, only the hash/metadata schedule is supplied and physical inspection is permitted in court/FSL under judicial supervision!).
  2. Furthermore, under **Section 230 BNSS**, the prosecution only supplies **relied-upon** documents/extracts, not unrelated personal data of third parties.
* **The Rule:** Implement the **Mandatory POCSO / Intimate-Media & Relied-Upon Redaction Gate** in Sub-Engine 8.4C (Section 5.2) whenever packaging a `SECTION_230_BNSS_DEFENSE_COPY`!

### Mistake 5: Generating PDFs With Missing Indic Glyphs ("Tofu Boxes" `□□□`) or Broken Emoji Rendering
* **The Trap:** Exporting a PDF report containing Hindi (`Devanagari`), Tamil, Bengali, Urdu/Arabic, or emoji reactions (`👍`, `🙏`, `💰`) using a standard PDF library configured only with `Helvetica` or `Times-Roman` ASCII fonts.
* **Why It Fails:** Every regional-language WhatsApp/Telegram message, Truecaller name, and Aadhaar address renders as unreadable empty boxes (`□□□□`), rendering the printed courtroom exhibit useless!
* **The Rule:** Embed full offline **Noto Sans / Noto Serif Indic & Emoji Font Subsets (`PDF/A-3b` compliant)** inside the PDF rendering engine so all 22 scheduled Indian languages and Unicode emojis render crisply on any computer or printer without external font dependencies.

### Mistake 6: Omitting the Raw Source Pointer & Evidentiary State Badge From Report Tables
* **The Trap:** Printing a chat message or transaction in a PDF table with only `[Sender, Receiver, Timestamp, Text]`.
* **Why It Fails:** If defense counsel challenges whether a message was fabricated, the report table itself must state: **Source File (`msgstore.db-wal` \[File ID #142, SHA-256: `a1b2...`\]), Table/Offset (`message` Row #1042, WAL Frame #88, Byte Offset `0x0041A2B0`), and Evidentiary State (`HISTORICAL_COMMITTED_RECORD — Recovered Pre-Revoke Text`)**!

---

## 3. Step 1 — Sub-Engine 8.4A: The 4 Automated Crime-Typology Dossier Compilers

Sub-Engine 8.4A queries the converged tables of **Modules 8.1, 8.2, and 8.3** (`entity_master_profiles`, `entity_graph_edges_ledger`, `unified_super_timeline`, `forensic_action_burst_stories`, and `evidentiary_hash_manifest_ledger`) to compile four specialized investigation dossiers:

### 3.1 Dossier Profile 1: Cyber-Financial Fraud, Mule Account Syndicate & Rupee-to-USDT Laundering Dossier
* **Target Statutory Offences:** Sections 318(4), 319(2), 336, 338, 340, 61(2), and 111 (*Organized Crime*) of the **Bharatiya Nyaya Sanhita (BNS), 2023**; Sections 66C & 66D of the **IT Act, 2000**; Sections 3 & 4 of the **Prevention of Money Laundering Act (PMLA), 2002**.
* **Automated 7-Section Structure:**
  1. **Executive Summary & Device Owner Attribution:** Hardware identity (`IMEI 1/2`), active & historical SIM `ICCID`s (`Module 3.2`), and verified KYC identities of the device user.
  2. **Inventory of Discovered Mule Bank Accounts, UPI VPAs & SIM-Bindings:** Every bank account and VPA found in apps (`Module 3.1/3.3`), DLT SMS (`Module 3.4`), and **Cancelled Cheque / Passbook / QR Photos (`Modules 7.3 & 7.4`)**—highlighting accounts whose SIM card (`ICCID`) was physically bound on this handset vs. accounts operated remotely!
  3. **Mule Typology & Anomaly Proof:** Tables of **High-Velocity Pass-Throughs** (inflow $\rightarrow$ outflow $< 15\text{ min}$), **Circular Laundering Loops**, **Split-UPI Smurfing**, and **Forged Payment Receipt Screenshots (`Module 7.3D`)**.
  4. **The End-to-End Rupee-to-Crypto (`USDT` / `XMR`) Laundering Chains (`Module 4.4D`):** Step-by-step table chaining `Phase 3 Bank/UPI UTR` $\rightarrow$ `Phase 4.2 Binance/Bybit P2P Order & In-Order Chat` $\rightarrow$ `Phase 4.1 TronLink/Trust Wallet TRC-20/BEP-20 Withdrawal` $\rightarrow$ `FixedFloat/ChangeNow Monero Swap`.
  5. **Recovered `BIP-39` Seed Phrases & Derived Unhosted Wallets (`Module 4.4A/B`):** Lists all recovered seed phrases, unwrapped vaults, `Ledger Live` cold-wallet `xpub`s, and their mathematically derived `T...`, `0x...`, and `bc1q...` addresses.
  6. **Syndicate Handler Communications & Action-Burst Proofs (`Module 5.5 & Module 8.1D`):** Stitched conversations across WhatsApp, Telegram (`Saved Messages` & Bots), Session, and Botim where mule kits, OTPs, UTR screenshots, and USDT `txid`s were exchanged, paired with `UsageStats`/`knowledgeC` human-operation proofs.
  7. **Physical Hideout & ATM Withdrawal Geolocation (`Modules 6.3 & 6.4`):** Exact flat/tower addresses from `Blinkit`/`Swiggy`/`Zomato` and cell tower `eNodeB` sectors active during each financial transaction.

### 3.2 Dossier Profile 2: Organized Crime, Narcotics (`NDPS`), Terror Financing (`UAPA`) & Hawala Dossier
* **Target Statutory Offences:** Sections 111 & 113 BNS, 2023; **NDPS Act, 1985**; **UAPA, 1967**; **FEMA / PMLA**.
* **Automated Structure:**
  1. **High-OpSec & Cross-Border Communications Ledger:** Full reconstruction of `Session` (`05...`), `SimpleX Chat` (pairwise SMP queues), `Threema`, `Briar`, `Zangi` (`10-...`), `Botim` / `IMO` (`+971` UAE / `+966` / `+855` handlers), and **Cloud Dead-Drops** (`Google Docs`, `Google Keep`, `Shared Apple Notes`, and `Shared Email Drafts` from `Module 5.5D`).
  2. **Hawala Bearer Token & Cash Settlement Ledger (`Module 7.4C`):** All photographed **Indian Currency Notes (`₹10`/`₹20`/`₹50` RBI Serial Numbers)**, handwritten chits, and P2P parcel drops (`Swiggy Genie`, `Porter`, `Rapido Parcel`, `Borzo` from `Module 6.4A` showing pickup and dropoff phone numbers and GPS pins!).
  3. **Multi-Device Co-Location, Travel & Safe-House Reconstruction (`Modules 6.3 & 6.4`):** `routined` / Google Timeline significant places, `Where is My Train` cell-tower train corridors, `IRCTC` / `DigiYatra` passenger manifests, `Uber`/`Ola` decoded polylines, and **Shared Wi-Fi `BSSID` / `SoftAP` Hotspot Client Leases** proving physical meetings with co-conspirators!

### 3.3 Dossier Profile 3: Honeytrap, Sextortion, Cyber-Stalking, Matrimonial Fraud & `POCSO` Safeguarded Dossier
* **Target Statutory Offences:** Sections 64–79, 308 (*Extortion*), 318 BNS, 2023; Sections 66E, 67, 67A, 67B IT Act, 2000; **POCSO Act, 2012**.
* **Automated Structure:**
  1. **Dating, Matrimonial & Social Lure Reconstruction (`Modules 5.4 & 6.4D`):** All personas, active and **unmatched/deleted matches** (`-wal` & `gotinder.com` CDN cache), **`Passport` / `Travel Mode` spoofed locations vs. true hardware GPS**, `Happn` street-crossing coordinates, `Shaadi.com`/`BharatMatrimony` unlocked contact logs, and off-platform WhatsApp/Telegram/Instagram handoff edges.
  2. **Visual Provenance, Ephemeral Media & Uncropped Original Ledger (`Modules 7.1 & 7.2`):** Side-by-side provenance of images (`Camera Original` vs. `Messenger Re-Encoded`), `/Mutations/` uncropped originals, `SplashBoard` / `TaskSnapshots` captures of View-Once / video-call extortion screens, `.ithmb` orphaned thumbnails of purged photos, and **unmasked Disguised Calculator Vault files (`Calculator+`, `Hide It Pro`)**.
  3. **Extortion Demand & Payment Trail:** Links threats/blackmail messages directly to the demanded `upi://pay` QR codes, burner numbers, gift cards, or mule accounts.

### 3.4 Dossier Profile 4: Malware APK Trojan, Remote Access (`AnyDesk`), Call-Forwarding & Anti-Forensic Tamper Dossier
* **Target Statutory Offences:** Sections 43, 66, 66C, 66D IT Act, 2000; Section 238 BNS, 2023 (*Causing disappearance of evidence of offence*).
* **Automated Structure:**
  1. **Sideloaded Trojan APK & Extracted C2 Attribution (`Module 6.5E`):** Details the sideloaded `.apk` (`installer_package`), abused permissions (`RECEIVE_SMS`, `BIND_ACCESSIBILITY_SERVICE`, `SYSTEM_ALERT_WINDOW`), and the **hardcoded Telegram Bot API Token (`bot<TOKEN>`), Attacker `chat_id`, or Firebase URL** carved from `classes.dex`!
  2. **Remote Access (`AnyDesk` `ad_svc.trace`) & USSD Call-Forwarding (`*21*`/`*401*`) Timeline:** Exact remote `AnyDesk 9-digit Client-ID`s, IP addresses, session start/end timestamps, dialed call-forwarding numbers, and the exact bank/UPI debits that occurred while the remote session or trojan was active (`Module 8.1D` Story Signature #2).
  3. **Anti-Forensics & Spoliation Proof (`Module 6.5A–D`):** Mathematical proof of `Magisk`/`KernelSU`/`LSPosed` hooks, `ROWID` clock-rollback inversions, `sqlite_sequence` tail-deletion gaps, telemetry-proven wiped chat windows, and Mock GPS radio contradictions.

---

## 4. Step 2 — Sub-Engine 8.4B: Golden-Hour Nodal Agency Freeze Packets & Section 94 BNSS Requisition Drafter

### 4.1 Packet 1: I4C / NCRP (`1930` `CFCFRMS`) & Bank Nodal Officer Lien/Freeze Sheet (`CSV` & `XLSX`)

Sub-Engine 8.4B exports `ncrp_1930_bank_freeze_packet.csv` (and `.xlsx`) containing one row per unique fraudulent/mule transaction or discovered mule account, formatted with these exact 14 Nodal columns:

1. `S_No`
2. `Transaction_Layer` (`Layer 1 Direct`, `Layer 2 Pass-Through`, `P2P Crypto Settlement`, `Unmasked Cheque/Passbook Mule Account`)
3. `Payment_Rail` (`UPI`, `IMPS`, `NEFT`, `RTGS`, `AEPS`, `DEBIT_CARD`)
4. `UTR_or_RRN_12_Digit` (Validated via Module 3.5A; indexed for instant NPCI lookup!)
5. `Transaction_Timestamp_IST` (`DD-MM-YYYY HH:MM:SS IST`)
6. `Transaction_Amount_INR` (`Numeric 2-decimal`)
7. `Payer_Account_or_VPA`
8. `Beneficiary_Bank_Name` (Resolved from IFSC / VPA PSP Dictionary!)
9. `Beneficiary_Account_Number` (Full unmasked account number where recovered from PDF/Cheque/App, or tail digits)
10. `Beneficiary_IFSC_11_Char` (Validated 11-char IFSC + Branch & City)
11. `Beneficiary_UPI_VPA` (`<handle>@<psp>`)
12. `Beneficiary_Verified_CBS_Name` (`banking_DisplayName` from Phase 3.1/3.2 or Cheque OCR)
13. `Linked_Mobile_Number_E164`
14. `Forensic_Source_Artifact_and_SHA256` (Exact database/image source on seized phone)

### 4.2 Packet 2: FIU-IND, Global CEX (`Binance LERP` / `Bybit` / `KuCoin`) & Tether (`USDT`) Freeze Packet

Exports `fiu_ind_and_cex_crypto_freeze_packet.csv` (and `.xlsx` + structured JSON) containing two actionable sheets:
* **Sheet A — Centralized Exchange (`CEX`) Account & P2P Freeze Table (For Binance LERP / Bybit / CoinDCX / Mudrex):**
  * Columns: `Exchange_Name`, `FIU_IND_Registration_Status`, `Target_CEX_User_UID` (e.g., `482910482`), `Binance_Pay_ID_or_Nickname`, `KYC_Verified_Name`, `PAN_10_Char`, `Registered_Email_and_Phone`, `P2P_Order_Numbers_List`, `Deposit_Withdrawal_TxIDs_List`, `Requested_Action` (`"Immediate Account Freeze & Production of KYC, P2P Counterparty UIDs, On-Chain Withdrawal Addresses & Login IP Logs under Sec 94 BNSS, 2023"`).
* **Sheet B — Self-Custody On-Chain `USDT` (`Tether`) & Blockchain Freeze Table:**
  * Columns: `Blockchain_Network` (`TRON TRC-20` / `Ethereum ERC-20` / `BSC BEP-20`), `Token_Contract` (`TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t`), `Target_Wallet_Address` (`34-char T...` or `42-char 0x...`), `Control_Classification` (`Suspect Seed Recovered on Device` vs. `Suspect TronLink Active Wallet` vs. `Upstream Syndicate Boss Watch-Only Wallet`), `Cached_USDT_Balance`, `Associated_TxIDs_List`, `Swap_Aggregator_Order_IDs` (`FixedFloat` / `ChangeNow` Trade IDs for subpoena!).

### 4.3 Packet 3: Automated `Section 94 BNSS, 2023` (erstwhile `Section 91 CrPC`) Statutory Requisition Generator

For every external lead discovered on the phone that requires server-side records from a third-party service provider, Sub-Engine 8.4B auto-generates a print-ready **Notice under Section 94 of the Bharatiya Nagarik Suraksha Sanhita (BNSS), 2023** pre-addressed to the specific Nodal Officer:

1. **To Telecom Service Providers (`Reliance Jio`, `Bharti Airtel`, `Vodafone Idea`, `BSNL`):**
   * Pre-fills all discovered suspect/accomplice **MSISDNs (`+91...`)**, **IMEIs (`15-digit`)**, **SIM `ICCID`s (`19/20-digit`)**, and **Serving 4G/5G Cell Tower IDs (`MCC-MNC-TAC-eNodeB-Sector` + exact IST time windows from Module 6.3C)**—requesting **CAF (Customer Application Form), CDR, IPDR, IMEI history, and Tower Dump CDRs**, accompanied by a Section 63 BSA Certificate from the TSP!
2. **To Bank Nodal Officers & NPCI:**
   * Grouped automatically by **Bank Name (via IFSC prefix)**—requesting **Account Opening Form (AOF), KYC documents (PAN/Aadhaar), Registered Mobile Number, Complete CBS Account Statement, IP/Device-ID Login Logs, and Beneficiary Details** for all listed Account Numbers, VPAs, and 12-digit UTRs!
3. **To Hyper-Local, E-Commerce, Ride-Hailing & Travel Nodal Officers (`Zomato`, `Swiggy`, `Blinkit`, `Zepto`, `Flipkart`, `Amazon`, `Uber`, `Ola`, `Rapido`, `IRCTC`, `MakeMyTrip`):**
   * Pre-fills the exact discovered **`Order ID`s, `Trip UUID`s, `CRN`s, `PNR`s, and Registered Mobile Numbers** (from Module 6.4)—requesting delivery rider details, payment UTRs, IP addresses, and historical delivery coordinates!
4. **To Social Media, Messaging & Dating Intermediaries (`WhatsApp`, `Telegram`, `Instagram`, `Snapchat`, `Google`, `Apple`, `Tinder`, `Bumble`, `Shaadi.com`):**
   * Pre-fills the exact discovered **`@lid` / `JID`, Telegram `user_id`, Instagram `pk`, Snapchat `UUID`, Discord `Snowflake ID`, or Tinder `24-hex user_id` / `Matrimony ID`**—requesting basic subscriber information (`BSI`), registration MSISDN/email, and access IP logs!

---

## 5. Step 3 — Sub-Engine 8.4C: Deterministic `PDF/A-3b` Courtroom Dossier & Air-Gapped `Section 230 BNSS` HTML5 Packager

### 5.1 Deterministic `PDF/A-3b` Courtroom Report Compiler

Every PDF dossier generated by Sub-Engine 8.4C adheres to strict forensic reproducibility standards:
1. **Embedded Multilingual Font Subsetting:** Bundles offline `Noto Sans` (Latin, Devanagari, Bengali, Tamil, Telugu, Gujarati, Kannada, Malayalam, Gurmukhi, Arabic) and `Noto Emoji` so every regional chat message and OCR string renders identically on any machine.
2. **Inline Provenance Footers on Every Exhibit Item:** Every message bubble, financial row, location fix, and image exhibit printed in the PDF includes a compact **Forensic Provenance Footer**:
   $$\texttt{[VFS ID: \#142 | Source: msgstore.db-wal (SHA-256: 8f3a...91c2) | Offset: 0x0041A2B0 | State: HISTORICAL\_COMMITTED\_RECORD]}$$
3. **Bound Statutory Certification:** Automatically appends the completed **Part A + Part B Section 63(4)(c) BSA 2023 Certificate** and **3-Tier Cryptographic Hash Schedule Annexure** (from Module 8.3) as the final bound section of the dossier, and records the final PDF's `SHA-256` and `MD5` in `evidentiary_hash_manifest_ledger`.

### 5.2 The `Section 230 BNSS, 2023` Air-Gapped HTML5 Disclosure Bundle & Mandatory Redaction Gate

To allow the Investigating Officer to supply an electronic copy of the relied-upon forensic report to the Court and to the Accused/Defense Counsel under **Section 230 of the Bharatiya Nagarik Suraksha Sanhita (BNSS), 2023** on a read-only DVD or Pen-Drive:

1. **Zero-Dependency Offline Single-Folder Architecture:**
   * Packages a self-contained static HTML5/CSS/JS viewer (`Open_Case_Dossier.html` + chunked read-only JSON data files + `verify_hashes.bat`/`.sh` script) that opens in any standard web browser **with zero internet connection and zero software installation required**.
2. **The Mandatory 3-Rule Statutory Redaction Gate (For `SECTION_230_BNSS_DEFENSE_COPY` Mode):**
   When exporting a package designated as a **Section 230 BNSS Defense Disclosure Copy**, Sub-Engine 8.4C enforces three strict legal safeguards:
   * **Safeguard 1 (`RELIED_UPON_SCOPE_FILTER`):** Exports only the specific artifacts, chat threads, transactions, and timeline windows **marked as `"Relied Upon"` (or included in the active Crime-Typology Dossier)** by the Investigating Officer, excluding unrelated personal files.
   * **Safeguard 2 (`POCSO_CSAM_AND_SEXUAL_ASSAULT_MEDIA_LOCK` — *P. Gopalkrishnan v. State of Kerala* Compliance):**
     * Any image or video tagged as **`CSAM / POCSO`**, **`NON_CONSENSUAL_INTIMATE_MEDIA`**, or **`SEXUAL_ASSAULT_FOOTAGE`** is **NEVER** exported as a viewable `.jpg`/`.mp4` file inside the Defense Disclosure Copy!
     * Instead, the export replaces the visual media file with a **Statutory Judicial-Inspection Placeholder Card** displaying the file's **Canonical Path, Exact Timestamps, EXIF/Container Provenance, and `SHA-256` / `MD5` Cryptographic Hash**, accompanied by the legal notice: *"Visual media withheld from physical duplication pursuant to thePOCSO Act, 2012 and the Hon'ble Supreme Court of India judgment in P. Gopalkrishnan v. State of Kerala (2019); original hashed exhibit preserved in official Court/FSL custody for supervised inspection."*
   * **Safeguard 3 (`VICTIM_IDENTITY_ANONYMIZATION_TOGGLE` — Section 72 BNS, 2023 & Section 23 POCSO Act):**
     * Provides a 1-click toggle to mask the name, address, and contact details of a sexual-offence or minor victim (`"[VICTIM_PROTECTED_ID_01]"`) in printed/exported public reports in compliance with **Section 72 of the Bharatiya Nyaya Sanhita (BNS), 2023** (formerly Section 228A IPC) and **Section 23 of the POCSO Act, 2012**!

---

## 6. Database Schema for Module 8.4 (`dossier_freeze_and_exhibit_packager.sqlite`)

The developer must create the following three tables in the master case convergence database:

### Table 1: `compiled_crime_dossiers_registry` (Generated Crime-Typology Courtroom Dossiers)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `dossier_uid` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Unique Dossier ID. |
| `dossier_profile_type` | `TEXT` | `NOT NULL` | Enum: `PROFILE_1_CYBER_FRAUD_MULE_AND_USDT_LAUNDERING`, `PROFILE_2_ORGANIZED_CRIME_NDPS_HAWALA`, `PROFILE_3_HONEYTRAP_SEXTORTION_POCSO`, `PROFILE_4_MALWARE_APK_ANYDESK_AND_TAMPERING`, `CUSTOM_INVESTIGATOR_SELECTION`. |
| `dossier_title` | `TEXT` | `NOT NULL` | E.g., `"Final Forensic Investigation Dossier — FIR No. 412/2026 (Cyber Crime PS)"`. |
| `export_audience_scope` | `TEXT` | `NOT NULL` | Enum: `IO_AND_COURT_UNREDACTED_MASTER`, `SECTION_230_BNSS_DEFENSE_DISCLOSURE_COPY`, `PUBLIC_VICTIM_ANONYMIZED_BNS_SEC72`. |
| `included_entity_uids_json` | `TEXT` | `NOT NULL` | JSON array of `entity_master_uid`s included in this dossier. |
| `included_story_uids_json` | `TEXT` | `NULL` | JSON array of `forensic_action_burst_stories.story_uid`s included. |
| `pocso_or_intimate_media_withheld_count` | `INTEGER` | `DEFAULT 0` | Count of sensitive visual files replaced with hash-only judicial inspection cards (under Safeguard 2). |
| `linked_sec63_certificate_uid` | `INTEGER` | `NOT NULL` | Foreign key to Module 8.3 `section63_bsa_certificates_registry.certificate_uid`. |
| `exported_pdf_path_and_sha256` | `TEXT` | `NOT NULL` | Path and 64-char `SHA-256` + 32-char `MD5` of the generated `PDF/A-3b` file. |
| `exported_html5_bundle_sha256` | `TEXT` | `NULL` | `SHA-256` of the offline HTML5 viewer archive (if generated). |
| `compiled_at_ist_iso` | `TEXT` | `NOT NULL` | `"YYYY-MM-DD HH:MM:SS IST (+05:30)"`. |

### Table 2: `nodal_freeze_and_lien_exports_ledger` (Golden-Hour `1930` NCRP, NPCI, `FIU-IND` & CEX Freeze Packets)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `freeze_packet_uid` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Unique row ID. |
| `target_agency_or_portal` | `TEXT` | `NOT NULL` | Enum: `I4C_NCRP_1930_CFCFRMS_BANK_LIEN`, `FIU_IND_AND_CEX_LERP_FREEZE`, `TETHER_USDT_SMART_CONTRACT_FREEZE`. |
| `total_accounts_or_wallets_count` | `INTEGER` | `NOT NULL` | Number of unique bank accounts, VPAs, CEX UIDs, or crypto wallets in the packet. |
| `total_utrs_or_txids_count` | `INTEGER` | `NOT NULL` | Number of unique 12-digit UTRs or blockchain `txid`s in the packet. |
| `total_disputed_fiat_inr` | `REAL` | `DEFAULT 0.0` | Total INR volume covered by the freeze sheet. |
| `total_disputed_crypto_summary` | `TEXT` | `NULL` | E.g., `"145,200.00 USDT (TRC-20)"`. |
| `exported_csv_xlsx_path` | `TEXT` | `NOT NULL` | Path to generated `.csv` / `.xlsx` packet. |
| `exported_file_sha256` | `TEXT` | `NOT NULL` | 64-char `SHA-256` of the exported freeze sheet. |
| `generated_at_ist_iso` | `TEXT` | `NOT NULL` | `"YYYY-MM-DD HH:MM:SS IST (+05:30)"`. |

### Table 3: `section94_bnss_requisitions_queue` (Auto-Drafted Statutory Notices to TSPs, Banks, CEXs & App Nodal Officers)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `requisition_uid` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Unique Requisition ID. |
| `statutory_provision` | `TEXT` | `NOT NULL` | `"Section 94 of the Bharatiya Nagarik Suraksha Sanhita (BNSS), 2023 [erstwhile Sec 91 CrPC]"`. |
| `recipient_nodal_category` | `TEXT` | `NOT NULL` | Enum: `TELECOM_TSP_NODAL`, `BANK_NODAL_OFFICER`, `CRYPTO_CEX_OR_SWAP_COMPLIANCE`, `HYPERLOCAL_DELIVERY_OR_RIDE_NODAL`, `SOCIAL_OR_MESSAGING_INTERMEDIARY`. |
| `recipient_organization_name` | `TEXT` | `NOT NULL` | E.g., `"Reliance Jio Infocomm Ltd."`, `"State Bank of India"`, `"Binance Compliance (LERP)"`, `"Blinkit / Eternal Ltd."`, `"Uber India Systems Pvt. Ltd."`. |
| `target_identifiers_json` | `TEXT` | `NOT NULL` | Exact list of MSISDNs, `eNodeB` cell IDs, Bank A/Cs + UTRs, CEX `UID`s, or `Order_ID`s queried in this notice! |
| `requested_records_checklist` | `TEXT` | `NOT NULL` | E.g., `"CAF, CDR, IPDR, Tower Dump & Sec 63 BSA Certificate"` or `"KYC, AOF, CBS Statement, Login IPs & Beneficiary Details"`. |
| `rendered_notice_doc_path` | `TEXT` | `NOT NULL` | Path to generated print/email-ready PDF/DOCX requisition notice. |

---

## 7. Developer Acceptance Test Checklist for Module 8.4

1. **The Golden-Hour `NCRP 1930` & `Binance LERP` Freeze Sheet Export Test:**
   * Run Sub-Engine 8.4B on a case containing 3 Phase 3 UPI outflows (`UTR 630911111111`, `630922222222`, `630933333333`), 1 unmasked SBI account from a Cancelled Cheque photo (`SBIN0004821`, `A/c 30984718291`), 1 Binance P2P `UID 482910482`, and 1 `TronLink` `USDT-TRC20` address (`TXYZ...`).
   * Verify that Sub-Engine 8.4B generates `ncrp_1930_bank_freeze_packet.csv` with all 14 mandatory I4C columns and `fiu_ind_and_cex_crypto_freeze_packet.csv` with both CEX UID and `TRC-20` freeze sheets!
2. **The Auto-Drafted `Section 94 BNSS, 2023` Nodal Requisition Grouping Test:**
   * Verify that Sub-Engine 8.4B automatically groups discovered identifiers by organization (generating one Section 94 BNSS notice to `"State Bank of India"` for all `SBIN*` accounts/UTRs, one notice to `"Reliance Jio"` for all `405-86` cell towers and Jio numbers, and one notice to `"Blinkit"` for discovered delivery order IDs).
3. **The `Section 230 BNSS` Defense Copy `POCSO` / Intimate-Media Redaction Gate Test:**
   * Mark an image in the case as `CSAM / POCSO` (or `NON_CONSENSUAL_INTIMATE_MEDIA`) and run Sub-Engine 8.4C with `export_audience_scope = "SECTION_230_BNSS_DEFENSE_DISCLOSURE_COPY"`.
   * Verify that the exported HTML5/PDF defense bundle **does not contain the raw image bytes**, and instead renders the **Statutory Judicial-Inspection Placeholder Card** containing the file's path, metadata, and `SHA-256` + `MD5` hashes!
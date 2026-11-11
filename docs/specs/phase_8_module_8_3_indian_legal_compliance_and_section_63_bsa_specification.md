# Engineering Specification: Phase 8, Module 8.3 — Indian Legal Evidentiary Compliance Engine, Hierarchical Hash Manifest, Merkle Chain-of-Custody Ledger & Section 63(4)(c) BSA 2023 Statutory Certificate Generator

**Document Purpose:** This document provides the complete, step-by-step architectural blueprint for building **Module 8.3** of the Forensic Data Parser (corresponding to **Group 17** and cross-linked across **Groups 1 through 16** of the Unified Master Register). It contains **zero programming code** and explains how to mathematically and procedurally satisfy **Sections 57, 61, 62, and 63 of the Bharatiya Sakshya Adhiniyam (BSA), 2023**, how to automatically populate **Part A (Person in Charge / Investigating Officer)** and **Part B (Forensic Expert)** of the statutory **Schedule to Section 63(4)(c) BSA 2023**, how to construct a 3-Tier Hierarchical Cryptographic Hash Manifest (`SHA-256` + `MD5` + `BLAKE3`), and how to maintain a tamper-evident **Merkle Hash-Chained Audit & Chain-of-Custody Ledger (`chain_of_custody_ledger`)** from first principles.

---

## 1. Purpose & Mental Model (Why Technical Extraction Without Statutory Certification Is Inadmissible in Indian Courts)

Under Indian evidence law—governed since July 1, 2024 by the **Bharatiya Sakshya Adhiniyam (BSA), 2023** (which replaced the Indian Evidence Act, 1872)—even the most brilliant technical recovery of a deleted WhatsApp chat, a `TronLink Pro` USDT transaction, or a forged Aadhaar card is **legally inadmissible as secondary "computer output" in any Indian trial unless it strictly satisfies the statutory conditions and two-part certification mandate of Section 63 of the BSA, 2023** (read with the Supreme Court's binding constitutional bench jurisprudence in *Anvar P.V. v. P.K. Basheer* and *Arjun Panditrao Khotkar v. Kailash Kushanrao Gorantyal*).

### How the Bharatiya Sakshya Adhiniyam (BSA), 2023 Transformed Digital Evidence Architecture

A developer building forensic software for Indian Law Enforcement Agencies (LEAs), Central Agencies (`CBI`, `NIA`, `ED`, `NCB`, `DRI`, `FIU-IND`), and Forensic Science Laboratories (`CFSL` / `SFSL`) must design the software around four statutory pillars of the BSA, 2023:

1. **Section 57 BSA (Explanations 4 to 7 — Primary Electronic Evidence) vs. Section 63 BSA (Secondary Computer Output):**
   * When the physical seized mobile handset itself or a bit-stream/file-system forensic image stored and produced directly from official custody is inspected, **Section 57 BSA** governs primary electronic evidence.
   * However, whenever the prosecution produces **derived "computer output"**—such as a printed forensic report, an exported PDF/HTML dossier, a decrypted `msgstore.db.crypt15` SQLite table, an unpacked UIDAI Aadhaar `.jp2` photograph, a reconstructed `.ithmb` thumbnail, or a pen-drive copy supplied to the Court and Defense Counsel under **Section 230 of the Bharatiya Nagarik Suraksha Sanhita (BNSS), 2023**—that output is governed by **Section 62 & Section 63 BSA** and **MUST be accompanied by a valid Section 63(4)(c) Certificate** at the exact instance it is submitted for admission!
2. **The Mandatory Two-Part Statutory Schedule (`Part A` + `Part B`):**
   * Unlike the repealed Section 65B(4) of the 1872 Act (which had no prescribed form and required only a single signature), **Section 63(4)(c) of the BSA, 2023** mandates a strict **Two-Part Certificate prescribed in the Schedule to the Act**:
     * **`Part A` (To be filled by the Party / Person in Charge of the Computer or Communication Device / Investigating Officer):** Identifies the device (Make, Model, IMEI, Serial), the lawful control/seizure custody, the manner of production, the operating state under Section 63(2), and the **Cryptographic Hash Value (`SHA-256` / `MD5`)** of the electronic record.
     * **`Part B` (To be filled by the Forensic Expert / Examiner):** Certifies the technical extraction/parsing process, the hardware/software tools used, the cryptographic hash computation and verification, and affirms that the produced computer output is an authentic, unaltered representation of the source electronic record.
3. **Section 63(3) BSA (Multi-System & Intermediary Processing Continuity):**
   * Section 63(3) BSA explicitly recognizes that an electronic record may pass through multiple computers or communication devices operating in succession (e.g., `Seized Handset` $\rightarrow$ `Extraction Tool UFED/GrayKey/ADB` $\rightarrow$ `Your Forensic Data Parser Workstation` $\rightarrow$ `Court Exhibit Storage Drive`). To prove unbroken continuity across all systems under Section 63(3), your software must maintain a **3-Tier Hierarchical Hash Manifest** linking the Master Acquisition Image hash $\rightarrow$ Intermediate Container/DB hash $\rightarrow$ Final Exported Exhibit hash!
4. **Hardware Malfunction & Tamper Disclosure Under Section 63(2)(c) BSA:**
   * Section 63(2)(c) requires certifying that during the material period, the device was operating properly, OR if it was not operating properly (or was rooted, clock-rolled-back, or infected by a trojan), that **"such operation was not such as to affect the electronic record or the accuracy of its contents."** By automatically integrating **Phase 6, Module 6.5's OS Integrity, Clock-Tamper & Malware Audit**, Module 8.3 pre-populates an objective, scientifically accurate disclosure for Section 63(2)(c)!

---

## 2. The 6 Fatal Mistakes Beginner Developers Make in Legal Compliance & Section 63 BSA Generators

Before implementing Module 8.3, the developer must understand six critical legal-engineering traps that cause forensic certificates and reports to be rejected during trial cross-examination:

### Mistake 1: Generating Old "Section 65B Indian Evidence Act" Certificates Instead of the Prescribed BSA 2023 Schedule (`Part A` + `Part B`)
* **The Trap:** Using legacy report templates that cite `"Section 65B of the Indian Evidence Act, 1872"` or generate a single-paragraph certificate signed by one person.
* **Why It Fails:** For all proceedings filed or taken up under the new criminal codes on or after July 1, 2024, **Section 65B is repealed**. Courts across India reject single-part certificates that do not conform to the **two-part (`Part A` + `Part B`) Schedule appended to Section 63(4)(c) of the Bharatiya Sakshya Adhiniyam, 2023**.
* **The Rule:** Module 8.3 must generate the exact statutory structure of the **Schedule to the Bharatiya Sakshya Adhiniyam, 2023 (`Part A` and `Part B`)** (Section 4) while also providing a dual-caption toggle (`"Section 63(4)(c) of the Bharatiya Sakshya Adhiniyam, 2023 [Corresponding to erstwhile Section 65B(4) of the Indian Evidence Act, 1872]"`) for legacy pre-July-2024 FIR trials!

### Mistake 2: Listing Only the Final PDF Report's Hash and Omitting the Source Image & Intermediate Database Hashes
* **The Trap:** Computing the `SHA-256` hash of the final generated `Forensic_Report.pdf` file and placing only that hash in Part A and Part B of the Section 63 certificate.
* **Why It Fails:** During cross-examination, defense counsel will ask: *"You certified the hash of your PDF report, but what was the SHA-256 hash of the raw `.ufdr`/`.tar` phone dump, what was the SHA-256 hash of the encrypted `msgstore.db.crypt15` file inside it, and what was the SHA-256 hash of the decrypted `msgstore.db` SQLite database from which Page 14 of your PDF was generated?"* If those three hashes are not bound together in the certificate's Hash Schedule, the chain of provenance between the seized phone and the PDF printout is broken!
* **The Rule:** Every Section 63(4)(c) BSA Certificate generated by Module 8.3 must include an automated **3-Tier Cryptographic Hash Schedule Annexure** (Section 3.1):
  $$\texttt{Tier 1 (Master Acquisition Image Hash)} \longrightarrow \texttt{Tier 2 (Internal VFS Container \& Unwrapped Derivative Hash)} \longrightarrow \texttt{Tier 3 (Final Courtroom Report \& Exhibit Hash)}$$

### Mistake 3: Modifying Source Files In-Place (Violating Read-Only Immutability by Opening SQLite without `?mode=ro` or `immutable=1`)
* **The Trap:** Opening an extracted SQLite database (`msgstore.db` or `cache4.db`) directly from the extraction folder using standard SQLite read-write mode, which causes SQLite to automatically replay and delete the `-wal` journal file, modifying the `SHA-256` hash of `msgstore.db`!
* **Why It Fails:** If the `SHA-256` hash of `msgstore.db` after running your tool differs by even 1 bit from the `SHA-256` hash recorded in the original UFED/Oxygen/GrayKey acquisition manifest, defense counsel can prove in court that your software altered the primary evidence!
* **The Rule:** Module 8.3 executes a **Pre-Ingest & Post-Ingest Source Hash Attestation** ($\text{SHA256}_{\text{pre}} == \text{SHA256}_{\text{post}}$, verifying Phase 1's Read-Only VFS Mount & Copy-on-Write Derivative Staging workspace) and prints that mathematical attestation directly inside **Part B** of the Section 63 Certificate!

### Mistake 4: Certifying "Unconditional Proper Operation" When the Device Had a Rolled-Back Clock or Root Framework
* **The Trap:** Blindly hardcoding the boilerplate sentence *"The mobile phone was operating properly at all material times and there was no distortion"* on a phone where the suspect had installed `Magisk` root, `Fake GPS`, or rolled the system clock back by 4 days.
* **Why It Fails:** If the forensic expert signs a blanket statement that the phone had zero anomalies, and the defense (or another part of your own report!) shows the clock was rolled back on November 1, the expert's credibility is impugned under cross-examination.
* **The Rule:** Section 63(2)(c) BSA specifically provides for the clause: *"...or, if it was not operating properly during that period, was not such as to affect the electronic record or the accuracy of its contents."* Module 8.3 automatically queries **Module 6.5 (`os_integrity_root_and_hook_audit` & `clock_tampering_and_deletion_gaps_ledger`)** and injects a **Precision Statutory Exception & Compensation Note** into Part B whenever root, malware, or clock tampering is detected (Section 4.3)!

### Mistake 5: Storing the Examiner Audit Log in a Standard Mutable SQLite Table
* **The Trap:** Logging user actions (`"Case opened"`, `"File hashed"`, `"Report exported"`) in an ordinary SQLite table where rows can be deleted or edited with `UPDATE audit_log SET ...`.
* **Why It Fails:** An ordinary database table does not prove non-tampering of the chain-of-custody log itself.
* **The Rule:** Implement the **Merkle Hash-Chained Append-Only Audit Ledger** (Section 5), where every log entry $n$ computes:
  $$H_n = \text{SHA256}\Big(H_{n-1} \ \parallel \ \text{uint64\_be}(\text{seq}_n) \ \parallel \ \text{uint64\_be}(\text{timestamp\_utc\_ns}_n) \ \parallel \ \text{UTF8}(\text{action\_payload\_json}_n)\Big)$$
  anchored to a genesis seed $H_0$, with an automated chain-verification routine before any report can be exported!

### Mistake 6: Forgetting Section 230 BNSS 2023 Defense Disclosure Hash Manifests (Pen-Drive / Optical Media Copies)
* **The Trap:** Generating a certificate only for the Investigating Officer's master copy and forgetting that under **Section 230 of the Bharatiya Nagarik Suraksha Sanhita (BNSS), 2023** (which replaced Section 207 CrPC), the prosecution must supply copies of relied-upon electronic records to the accused/defense counsel on digital storage media.
* **The Rule:** Module 8.3 automatically generates a dedicated **Section 230 BNSS / Court & Defense Copy Hash Verification Manifest** so that the exact files copied onto the Court DVD/Pen-Drive and the Accused/Defense Pen-Drive have identical, pre-verified `SHA-256` and `MD5` hashes bound to their own Section 63(4)(c) BSA Certificate!

---

## 3. Step 1 — Sub-Engine 8.3A: The 3-Tier Hierarchical Cryptographic Hash Manifest (`SHA-256` + `MD5` + `BLAKE3`)

Why must the engine compute **both** `SHA-256` and **`MD5`** (plus internal `BLAKE3`) for every evidentiary artifact?
* **The Statutory Reason:** The Schedule to Section 63(4)(c) of the BSA, 2023 explicitly lists **`SHA1` / `SHA256` / `MD5`** as the recognized hash algorithms on the statutory form, with **`SHA-256`** as the primary cryptographic standard. Meanwhile, legacy acquisition tools (`UFED`, `XRY`, `Oxygen`, `Magnet`) often write `MD5` or `SHA-256` inside their `.ufdr` / `.xml` acquisition logs. By recording **both `SHA-256` (64 hex chars) and `MD5` (32 hex chars)** for every artifact in `evidentiary_hash_manifest_ledger`, your Section 63 Certificate cross-verifies 100% with both the BSA Schedule and every third-party extraction tool's acquisition log!

### 3.1 The 3-Tier Provenance Hash Hierarchy

Every piece of evidence cited in a courtroom report or exported exhibit is backed by a **3-Tier Cryptographic Lineage**:

1. **Tier 1 — Primary Acquisition Container Hash (`TIER_1_MASTER_ACQUISITION_SOURCE`):**
   * The exact `SHA-256` and `MD5` digest of the immutable input file(s) ingested in Phase 1, Module 1.1 (e.g., `Seized_iPhone16Pro_FFS.ufdr` or `Redmi_Note13_Physical.bin`), plus a **Post-Processing Re-Verification Hash** confirming that zero bytes of the master input file changed during parsing:
     $$\text{SHA256}_{\text{pre\_ingest}}\big(\text{Master\_Image}\big) == \text{SHA256}_{\text{post\_ingest}}\big(\text{Master\_Image}\big)$$
2. **Tier 2 — Internal VFS Source File & Unwrapped Derivative Hash (`TIER_2_VFS_ARTIFACT_AND_DERIVATIVE`):**
   * **Tier 2A (`Product A — Original VFS File`):** The `SHA-256` and `MD5` of the exact internal file inside the phone's filesystem (e.g., `/data/user/0/com.whatsapp/databases/msgstore.db` + `msgstore.db-wal`, or `/sdcard/Android/media/com.whatsapp/WhatsApp/Databases/msgstore.db.crypt15`).
   * **Tier 2B (`Product B2 — Decrypted / Reconstructed Derivative`):** Whenever Phase 2, Module 2.2 or Phase 7 unwraps an encrypted/encoded container (such as decrypting `msgstore.db.crypt15` using `/files/key`, decrypting `Signal.sqlite` using the Keychain key, unmasking a `Calculator+` XORed JPEG, or inflating a UIDAI Aadhaar Secure QR `.jp2` photo), the engine records:
     * The `SHA-256` & `MD5` of the **Encrypted Input (`Product A`)**
     * The exact **Cryptographic Algorithm & Key Provenance Pointer** (e.g., `"AES-256-GCM unwrapped via /data/user/0/com.whatsapp/files/key [SHA-256: 8f3a...]"` — never exposing raw victim passwords in public printouts unless toggled by the examiner, while proving deterministic mathematical derivation!)
     * The `SHA-256` & `MD5` of the resulting **Plaintext Derivative (`Product B2`)**!
3. **Tier 3 — Final Exported Courtroom Dossier & Exhibit Hash (`TIER_3_EXPORTED_COURT_EXHIBIT`):**
   * The exact `SHA-256` and `MD5` of every generated PDF Dossier, Excel/CSV Nodal Freeze Sheet, exported voice-note `.opus`/`.wav` file, exported image/video exhibit, and standalone HTML5 Section 230 BNSS viewer bundle!

### 3.2 Computing the Case Master Merkle Root (`case_merkle_root_sha256`)

To bind all $K$ files in the **Tier 1, Tier 2, and Tier 3 Hash Manifest** into a single 64-character hexadecimal master fingerprint that can be written by the Investigating Officer in the physical Case Diary / Panchnama / Seizure Memo:
1. Sort all manifest rows deterministically by `(hash_tier ASC, canonical_path_or_exhibit_id ASC)`.
2. For each row $i \in \{0, \dots, K-1\}$, compute leaf hash:
   $$L_i = \text{SHA256}\Big(\text{UTF8}(\text{canonical\_path}_i) \ \parallel \ \text{0x00} \ \parallel \ \text{bytes32}(\text{sha256}_i) \ \parallel \ \text{bytes16}(\text{md5}_i) \ \parallel \ \text{uint64\_be}(\text{byte\_size}_i)\Big)$$
3. Construct a binary **SHA-256 Merkle Tree** bottom-up (if a level has an odd number of nodes, duplicate the final node at that level), computing parent nodes:
   $$P_{j} = \text{SHA256}\big(\text{0x01} \ \parallel \ \text{Child}_{\text{left}} \ \parallel \ \text{Child}_{\text{right}}\big)$$
4. The root of the tree is the **32-byte (`64-hex-char`) `case_merkle_root_sha256`**. Changing even a single byte in any of the $100,000$ files or exhibits in the case changes `case_merkle_root_sha256`!

---

## 4. Step 2 — Sub-Engine 8.3B: Automated Section 63(4)(c) BSA 2023 Statutory Certificate Generator (`Part A` + `Part B`)

Sub-Engine 8.3B implements the exact statutory fields required by **Section 63(1), Section 63(2)(a)–(d), Section 63(3), Section 63(4)(a)–(c), and the Schedule to the Bharatiya Sakshya Adhiniyam, 2023**.

### 4.1 Statutory Mapping of `Part A` (To Be Filled by the Party / Investigating Officer / Device Custodian)

The Schedule to the BSA 2023 specifies that **Part A** is completed by the Party / Person in Charge of the computer or communication device or the management of the relevant activities (in law enforcement seizures, the Investigating Officer / Seizing Officer / Authorised Custodian producing the record, or the Complainant/Victim for voluntary production of a victim device):

| Statutory Part A Element in the BSA 2023 Schedule | Automated Data Source Populated by Module 8.3B |
|---|---|
| **1. Deponent / Affirmation Header** | `"I, [Name of Officer/Party], Son/Daughter/Spouse of [Father's/Spouse's Name], aged [Age] years, residing at / posted as [Designation, Rank, Police Station / Unit / Agency Address], do hereby solemnly affirm and sincerely state..."` (Populated from Case Metadata Form + FIR/Crime No, Police Station, District, State, and Sections of Law). |
| **2. Device & Record Identification Table (`Make / Model / Color / Serial / IMEI / OS`)** | Automatically populated from **Phase 1, Module 1.1 & Phase 3, Module 3.2**:<br>• **Device Type:** Mobile Handset / Smartphone (`Android` or `iOS`)<br>• **Make & Brand:** E.g., `Samsung` (`SM-S928B`) / `Apple` (`iPhone16,2`)<br>• **IMEI 1 & IMEI 2 / MEID:** Exact 15-digit Luhn-verified IMEIs (`35482910...`)<br>• **Hardware Serial Number & Chipset:** `R58N...` / `UDID`<br>• **Operating System & Build:** E.g., `Android 15 (OneUI 7.0, Patch 2026-10-01)` or `iOS 18.2 (22C152)`<br>• **Active SIM ICCIDs & MSISDNs:** Extracted from `telephony.db` / `siminfo`. |
| **3. Lawful Control & Custody Clause (`Section 63(2)(a)-(b) & 63(4)`)** | Automatically formats either:<br>• **Mode A (Seized Exhibit in Official Custody):** Cites the Seizure Memo / Panchnama timestamp, Maalkhana / FSL Property Register entry, and continuous official custody of the extraction image (`Tier 1 Master Image`), OR<br>• **Mode B (Complainant / Witness Device):** Cites continuous lawful ownership and regular day-to-day operation by the complainant/witness. |
| **4. Proper Operation & Integrity Clause (`Section 63(2)(c)-(d)`)** | Pre-populates the statutory affirmation that the computer/communication device was operating properly during the material period, cross-linked to **Part B's Technical Integrity Audit** (see Section 4.3). |
| **5. Part A Cryptographic Hash Value Block (`SHA-256` & `MD5`)** | Embeds the **Tier 1 Master Acquisition Hash**, the **Tier 3 Exported Report/Dossier Hash**, and the **Case Master Merkle Root (`case_merkle_root_sha256`)**, referencing Annexure-A for item-level Tier 2 hashes! |

### 4.2 Statutory Mapping of `Part B` (To Be Filled by the Forensic Expert / Examiner)

Under the Schedule to Section 63(4)(c) BSA 2023, **Part B** is completed and signed by the **Expert** (Forensic Examiner / Cyber Forensics Analyst / FSL Scientist / Authorised Technical Officer) who processed the electronic record and produced the computer output:

| Statutory Part B Element in the BSA 2023 Schedule | Automated Technical Data Populated by Module 8.3B |
|---|---|
| **1. Expert Identification & Qualifications** | Name, Designation, Qualification, Laboratory / Cyber Cell / Unit Name, and Official Address of the Forensic Examiner. |
| **2. Produced Electronic Record & Source Details** | Exact filename, byte size ($N\text{ bytes}$), acquisition format (`UFED .ufdr`, `GrayKey .tar`, `Physical .bin`), and **Pre-Ingest & Post-Ingest `SHA-256` and `MD5` Hashes** of the Tier 1 Master Image. |
| **3. Multi-System Processing & Workstation Specification (`Section 63(3) BSA`)** | Automatically records the Forensic Workstation's Hostname, OS Version, CPU Architecture, RAM, **Forensic Data Parser Engine Version & Git Commit Hash**, Read-Only VFS Mount verification (`vfs_mount_mode = READ_ONLY_IMMUTABLE`), and exact `UTC` and `IST (+05:30)` Processing Start & Completion Timestamps. |
| **4. Cryptographic Hash Algorithm & Verification Statement** | Explicitly states the hash functions used (`SHA-256 [FIPS 180-4 256-bit]` and `MD5 [RFC 1321 128-bit]`), embeds the **Tier 1, Tier 2, and Tier 3 Hash Schedule**, and attaches the auto-generated **Hash Verification Report**. |
| **5. Technical Operating State & Anomaly Disclosure (`Section 63(2)(c) BSA`)** | Automatically synthesized from **Phase 6, Module 6.5** (see Section 4.3 below). |

### 4.3 Automated Section 63(2)(c) BSA Technical Exception & Compensation Clause Generator

When **Phase 6, Module 6.5** detects an operating-system modification on the seized phone (such as `Magisk`/`KernelSU` root, an unlocked bootloader, a manual clock rollback in `mmssms.db`, a Mock GPS provider, or a sideloaded SMS-stealer trojan), Sub-Engine 8.3B **never hides the anomaly**. Instead, it automatically generates a legally bulletproof **Section 63(2)(c) Technical Disclosure Clause** in Part B:

* **Case 1 (Zero Integrity Anomalies Detected in Module 6.5):**
  * Outputs: *"Technical audit of the operating system kernel properties, bootloader lock state (`verifiedbootstate = green`), monotonic timebase anchors (`.timesync` / `ROWID` progression), and permission ledgers (`appops`) confirms that the communication device was operating normally and properly at all material times without root modification, clock rollback, or location simulation."*
* **Case 2 (Root, Clock Tampering, Mock GPS, or Malware Detected in Module 6.5):**
  * Outputs a precise technical enumeration of the exact findings from Module 6.5 (e.g., *"Technical examination detected that `auto_time` was disabled and a manual system clock rollback of `-48.5 hours` occurred at `ROWID 501` of `mmssms.db`, and `Magisk v27.0` root policy was active..."*), followed by the **Statutory Section 63(2)(c) Scientific Compensation Statement**:
  * *"Pursuant to Section 63(2)(c) of the Bharatiya Sakshya Adhiniyam, 2023, it is certified that the above-identified non-standard operating conditions have been mathematically isolated, bounded via monotonic hardware/database sequence counters (`ROWID`, `FSEvents event_id`, and `mach_continuous_time` ticks), and explicitly flagged on the affected records, and **were not such as to affect the integrity of the remaining electronic records or the accuracy of their contents** as reproduced in this Computer Output."*

---

## 5. Step 3 — Sub-Engine 8.3C: The Tamper-Evident Merkle Chain-of-Custody & Examiner Audit Ledger

From the exact millisecond a case is created in Phase 1 until the final courtroom PDF and Section 230 BNSS disclosure bundle are exported in Phase 8.4, every system operation and examiner interaction is recorded in `chain_of_custody_merkle_ledger`.

### 5.1 Mathematical Formula for the Hash-Chained Audit Log

1. **Genesis Anchor ($H_0$):**
   When the case is initialized with `case_uuid` and the Tier 1 Master Image `master_sha256`, compute the 32-byte Genesis Hash $H_0$:
   $$H_0 = \text{SHA256}\Big(\texttt{"FORENSIC\_GENESIS\_V1:"} \ \parallel \ \text{UTF8}(\text{case\_uuid}) \ \parallel \ \text{UTF8}(\text{master\_sha256})\Big)$$
2. **Sequential Entry Chaining ($H_n$ for $n = 1, 2, \dots$):**
   For each subsequent audit event $n$ (`INGEST_STARTED`, `MASTER_HASH_VERIFIED_PRE`, `KEY_BROKER_PASS_TESTED`, `MODULE_COMPLETED`, `EXAMINER_BOOKMARK_ADDED`, `MASTER_HASH_VERIFIED_POST`, `SECTION_63_CERTIFICATE_GENERATED`, `DOSSIER_EXPORTED`), compute:
   $$H_n = \text{SHA256}\Big(\text{UTF8}(\text{hex}(H_{n-1})) \ \parallel \ \texttt{"|"} \ \parallel \ \text{UTF8}(\text{str}(n)) \ \parallel \ \texttt{"|"} \ \parallel \ \text{UTF8}(\text{str}(\text{timestamp\_utc\_ns}_n)) \ \parallel \ \texttt{"|"} \ \parallel \ \text{UTF8}(\text{event\_type}_n) \ \parallel \ \texttt{"|"} \ \parallel \ \text{UTF8}(\text{canonical\_json\_payload}_n)\Big)$$
3. **Pre-Export Chain Integrity Verification:**
   Before Module 8.3B or Module 8.4C generates any courtroom certificate or report, it recomputes $H_1 \dots H_{\text{last}}$ from row $1$ to the final row. If any row was deleted, inserted out of order, or modified in SQLite, the chain breaks at the exact modified sequence number $n$, halting export and raising a `CHAIN_OF_CUSTODY_TAMPER_EXCEPTION`!

---

## 6. Database Schema for Module 8.3 (`legal_compliance_and_section63_bsa.sqlite`)

The developer must create the following three tables in the master case convergence database:

### Table 1: `evidentiary_hash_manifest_ledger` (The 3-Tier `SHA-256` + `MD5` + `BLAKE3` Provenance Schedule)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `manifest_item_uid` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Unique row ID. |
| `hash_tier` | `TEXT` | `NOT NULL` | Enum: `TIER_1_MASTER_ACQUISITION_SOURCE`, `TIER_2A_VFS_ORIGINAL_CONTAINER`, `TIER_2B_UNWRAPPED_OR_CARVED_DERIVATIVE`, `TIER_3_EXPORTED_COURT_EXHIBIT`, `TIER_3_SEC230_BNSS_DEFENSE_COPY`. |
| `vfs_file_id_or_staging_id` | `INTEGER` | `NULL` | Foreign key to `vfs_index.file_id` or `derivative_staging_ledger.staging_id`. |
| `canonical_path_or_exhibit_name` | `TEXT` | `NOT NULL` | Full VFS path, staging path, or exported exhibit filename (e.g., `"Exhibit_01_Finance_Dossier.pdf"`). |
| `artifact_description` | `TEXT` | `NOT NULL` | Human-readable description for the BSA Schedule Annexure (e.g., `"WhatsApp Primary Message Database (Decrypted from crypt15)"`). |
| `byte_size` | `INTEGER` | `NOT NULL` | Exact file size in bytes. |
| `sha256_hex` | `TEXT` | `NOT NULL` | **64-character lowercase hexadecimal `SHA-256` digest. Indexed!** |
| `md5_hex` | `TEXT` | `NOT NULL` | **32-character lowercase hexadecimal `MD5` digest (for BSA Schedule & legacy UFED cross-matching). Indexed!** |
| `blake3_hex` | `TEXT` | `NULL` | 64-character hexadecimal `BLAKE3` digest. |
| `parent_manifest_item_uid` | `INTEGER` | `NULL` | Points to the parent container (links Tier 3 Exhibit $\rightarrow$ Tier 2B Decrypted DB $\rightarrow$ Tier 2A Encrypted File $\rightarrow$ Tier 1 Master Image!). |
| `crypto_unwrap_provenance_note` | `TEXT` | `NULL` | Documents the exact mathematical/cryptographic transformation between `parent_manifest_item_uid` and this item. |
| `post_run_reverified_status` | `TEXT` | `NOT NULL` | `IMMUTABILITY_VERIFIED_IDENTICAL` (proves zero bytes changed during processing). |
| `hashed_at_utc_iso` | `TEXT` | `NOT NULL` | UTC ISO-8601 timestamp when hash was computed. |

### Table 2: `section63_bsa_certificates_registry` (Generated Part A & Part B Statutory Certificates)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `certificate_uid` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Unique Certificate ID. |
| `certificate_reference_no` | `TEXT` | `NOT NULL` | Unique reference string (e.g., `"BSA63-2026-FIR0412-EX01"`). |
| `statutory_regime_mode` | `TEXT` | `NOT NULL` | Enum: `BSA_2023_SECTION_63_4_C_SCHEDULE`, `DUAL_BSA_SEC_63_AND_IEA_SEC_65B_LEGACY`. |
| `case_fir_or_rc_number` | `TEXT` | `NOT NULL` | FIR No. / RC No. / ECIR No., Police Station / Agency, District, and Statutory Sections. |
| `part_a_deponent_details_json` | `TEXT` | `NOT NULL` | JSON holding Part A Officer/Party Name, Rank/Designation, Father's Name, Age, Address, and Custody Mode. |
| `part_a_device_metadata_json` | `TEXT` | `NOT NULL` | Auto-populated Make, Model, IMEI 1/2, Serial, Chipset, OS Version, and SIM ICCIDs. |
| `part_b_expert_details_json` | `TEXT` | `NOT NULL` | JSON holding Part B Forensic Expert Name, Designation, Lab/Unit, and Qualifications. |
| `part_b_workstation_env_json` | `TEXT` | `NOT NULL` | Workstation Hostname, OS, Parser Version, Read-Only VFS Attestation, and Start/End IST/UTC timestamps. |
| `sec63_2_c_integrity_clause_text` | `TEXT` | `NOT NULL` | Auto-synthesized Section 63(2)(c) proper-operation or isolated-anomaly compensation statement (from Section 4.3). |
| `tier1_master_image_sha256` | `TEXT` | `NOT NULL` | 64-char `SHA-256` of the primary extraction source. |
| `case_merkle_root_sha256` | `TEXT` | `NOT NULL` | 64-char `SHA-256` Merkle Root of all items in `evidentiary_hash_manifest_ledger` (Section 3.2). |
| `rendered_certificate_pdf_sha256` | `TEXT` | `NULL` | `SHA-256` of the final rendered Part A + Part B Certificate PDF. |
| `generated_at_ist_iso` | `TEXT` | `NOT NULL` | `"YYYY-MM-DD HH:MM:SS IST (+05:30)"`. |

### Table 3: `chain_of_custody_merkle_ledger` (Append-Only Hash-Chained Examiner & System Audit Log)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `seq_no` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Strictly monotonic sequence number ($1, 2, \dots, N$). |
| `timestamp_utc_ns` | `INTEGER` | `NOT NULL` | 64-bit UTC nanoseconds. |
| `timestamp_ist_iso` | `TEXT` | `NOT NULL` | Human-readable IST timestamp (`+05:30`). |
| `actor_or_subsystem` | `TEXT` | `NOT NULL` | E.g., `"SYSTEM_PHASE_1_INGEST"`, `"EXAMINER: Insp. R.K. Verma"`, `"MODULE_8_3_CERT_ENGINE"`. |
| `event_action_type` | `TEXT` | `NOT NULL` | E.g., `CASE_INITIALIZED`, `PRE_INGEST_HASH_LOCKED`, `VFS_MOUNTED_READ_ONLY`, `DERIVATIVE_UNWRAPPED`, `POST_INGEST_HASH_VERIFIED`, `BOOKMARK_CREATED`, `CERTIFICATE_ISSUED`. |
| `canonical_payload_json` | `TEXT` | `NOT NULL` | Deterministic sorted-key JSON describing the exact action, target `file_id`, and hashes. |
| `previous_entry_hash_hex` | `TEXT` | `NOT NULL` | 64-char `SHA-256` hash $H_{n-1}$ of row `seq_no - 1` (or Genesis $H_0$ for `seq_no == 1`). |
| `current_entry_hash_hex` | `TEXT` | `NOT NULL` | **64-char `SHA-256` hash $H_n$ computed via Section 5.1's formula!** |

---

## 7. Developer Acceptance Test Checklist for Module 8.3

1. **The Pre-Ingest vs. Post-Ingest Source Immutability Verification Test:**
   * Ingest a test `.tar` / `.ufdr` extraction containing an active `msgstore.db` and `msgstore.db-wal`. Run Phases 1 through 8, and verify in `evidentiary_hash_manifest_ledger` that the `SHA-256` and `MD5` hashes of the input archive and the original VFS `msgstore.db` after processing are bit-for-bit identical to their pre-ingest hashes (`IMMUTABILITY_VERIFIED_IDENTICAL`).
2. **The Section 63(2)(c) BSA Anomaly Compensation Auto-Drafting Test:**
   * Run Sub-Engine 8.3B on a case where Module 6.5 flagged a `-48.5 hour` clock rollback in `mmssms.db` (`ROWID 501`) and `Magisk` root.
   * Verify that `sec63_2_c_integrity_clause_text` in `section63_bsa_certificates_registry` automatically discloses both findings, cites their monotonic `ROWID` isolation bounds, and includes the statutory Section 63(2)(c) BSA compensation attestation rather than claiming unconditional normal operation!
3. **The Merkle Audit Log Tamper-Detection Test:**
   * Insert 10 sequential audit events into `chain_of_custody_merkle_ledger`, then manually execute an SQL `UPDATE` altering a single character inside Row #5's `canonical_payload_json`.
   * Run Sub-Engine 8.3C's pre-export verifier and confirm that it detects the cryptographic hash mismatch at `seq_no = 5` ($H_5 \neq \text{expected}$) and halts certificate export with `CHAIN_OF_CUSTODY_TAMPER_EXCEPTION`!
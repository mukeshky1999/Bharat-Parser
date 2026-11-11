# Engineering Specification: Phase 7, Module 7.4 — Offline Multilingual OCR, Indian KYC Document Classifier (`PAN`, `Aadhaar`, `GSTIN`, `Passport MRZ`, `Voter ID`, `DL`), Financial Instrument Extractor & Grid-Aware Crypto Seed Screenshot Hunter

**Document Purpose:** This document provides the complete, step-by-step architectural blueprint for building **Module 7.4** of the Forensic Data Parser (completing **Phase 7** and corresponding to **Groups 3, 4, 5, 12, 13, 15, and 16** of the Unified Master Register). It contains **zero programming code** and explains how to harvest pre-computed OS `Live Text` (`ZCHARACTERRECOGNITIONATTRIBUTES`) blobs, execute tiered offline multilingual OCR, apply position-constrained homoglyph correction, mathematically validate Indian KYC identity documents (`PAN`, `Aadhaar`, `GSTIN`, `Passport ICAO 9303 MRZ`, `Voter ID`, `Driving Licence`), extract bank details from photographed `Cancelled Cheques`, `Bank Passbooks`, `Debit/Credit Cards`, and `Hawala Currency-Note Tokens`, and reconstruct multi-column `BIP-39` seed phrase screenshots from first principles.

---

## 1. Purpose & Mental Model (Why Visual Text Is the Missing Link in Mule, Hawala & Crypto Syndicates)

In real-world Indian and international investigations, suspects frequently store their most incriminating evidence inside **images** rather than searchable database text:

1. **The "Mule Kit" Photo Folder (Stolen/Rented Identity & Banking Documents):**
   * A cyber-fraud mule coordinator's phone typically contains hundreds of WhatsApp/Telegram images of **Aadhaar Cards**, **PAN Cards**, **Voter IDs**, **Shell-Company GST Certificates**, **Bank Passbook Front Pages**, **Cancelled Cheques**, and **ATM Debit Cards** belonging to dozens of recruited money-mule account holders across India.
   * Without an automated KYC Document Classifier and Financial Instrument OCR engine, an investigator must manually open and read $20,000$ gallery images one by one to compile the list of mule accounts and shell companies!
2. **Multi-Column `BIP-39` Crypto Seed Phrase Screenshots:**
   * When creating a self-custody wallet in `Trust Wallet`, `MetaMask`, `TronLink Pro`, `Phantom`, or `Tonkeeper`, suspects routinely take a **screenshot of the 12-word or 24-word recovery phrase screen** (or take a photo of a handwritten paper slip).
   * Because wallet apps display the 12 or 24 words in a **2-column or 3-column visual grid**, naive line-by-line OCR scrambles the word order (reading Row 1 across columns: `Word #1`, then `Word #7`, instead of `Word #1, #2, #3...`), causing standard `BIP-39` checksum validators to miss the seed phrase!
3. **Indian Hawala "Currency-Note Serial Number" Bearer Tokens:**
   * In traditional Indian hawala cash deliveries (moving ₹10 Lakh to ₹5 Crore in physical cash), the sender takes a photograph of a **₹10, ₹20, or ₹50 Indian Currency Note** (showing its unique **RBI 9-Character Serial Number**, e.g., `45B 829104`) and sends that photo over WhatsApp/Telegram/Botim to the courier. The courier hands the cash only to the person who physically presents that exact ₹10 note!
4. **Harvesting Pre-Computed Apple `Live Text` (`Photos.sqlite`) Before Running CPU OCR:**
   * On modern iOS (iOS 15 through iOS 26), Apple's background `mediaanalysisd` daemon automatically runs hardware Neural-Engine OCR (**`Live Text`**) on photos in the user's camera roll and saves the extracted text and document classification inside **`Photos.sqlite` (`ZCHARACTERRECOGNITIONATTRIBUTES`)**! Harvesting that pre-computed table gives you instant OCR for thousands of iPhone photos in milliseconds before your local OCR engine even starts!

---

## 2. The 6 Fatal Mistakes Beginner Developers Make in Forensic OCR & Indian KYC Parsing

Before implementing Module 7.4, the developer must understand six critical traps that break standard OCR tools:

### Mistake 1: Running Heavy CPU/GPU OCR on Every iPhone Photo Without First Reading `ZCHARACTERRECOGNITIONATTRIBUTES`
* **The Trap:** Running a local Tesseract/PaddleOCR/ONNX model from scratch on all $40,000$ images in `/private/var/mobile/Media/DCIM/` on an iOS Full File System extraction, taking 6 hours of CPU time.
* **Why It Fails:** Inside `/private/var/mobile/Media/PhotoData/Photos.sqlite`, the table **`ZCHARACTERRECOGNITIONATTRIBUTES`** (joined via `ZADDITIONALASSETATTRIBUTES.ZCHARACTERRECOGNITIONATTRIBUTES = ZCHARACTERRECOGNITIONATTRIBUTES.Z_PK`) already stores Apple Vision's Neural-Engine OCR output inside **`ZCHARACTERRECOGNITIONDATA` (`BLOB`)** and **`ZHANDWRITINGRECOGNITIONDATA` (`BLOB`)**!
* **The Rule:** Always unpack `ZCHARACTERRECOGNITIONATTRIBUTES` first (Section 3.1), and only run the local offline OCR engine on images that lack pre-computed `Live Text` (or on deleted/carved/Android/messenger-cached images)!

### Mistake 2: Using a Naive Regex `[A-Z]{5}[0-9]{4}[A-Z]` for Indian `PAN` Numbers Without Structural & Surname Validation
* **The Trap:** Matching any 10-character string `[A-Z]{5}[0-9]{4}[A-Z]` in OCR text and reporting it as an Indian Income Tax `PAN` (`Permanent Account Number`).
* **Why It Fails:**
  1. In an authentic 10-character Indian `PAN` ($C_1 C_2 C_3 C_4 C_5 D_6 D_7 D_8 D_9 C_{10}$), the **4th character ($C_4$) is NOT a random letter**—it is strictly restricted by the Income Tax Department to **10 valid Entity Status Codes**:
     $$C_4 \in \{\texttt{'P'}, \ \texttt{'C'}, \ \texttt{'H'}, \ \texttt{'F'}, \ \texttt{'A'}, \ \texttt{'T'}, \ \texttt{'B'}, \ \texttt{'L'}, \ \texttt{'J'}, \ \texttt{'G'}\}$$
     *(where `'P'` = Individual Person \[95%+ of all PAN cards!\], `'C'` = Company, `'H'` = Hindu Undivided Family \[HUF\], `'F'` = Partnership Firm, `'A'` = Association of Persons, `'T'` = Trust, `'B'` = Body of Individuals, `'L'` = Local Authority, `'J'` = Artificial Juridical Person, `'G'` = Government).* Any candidate string where $C_4 \in \{\texttt{D, E, I, K, M, N, O, Q, R, S, U, V, W, X, Y, Z}\}$ is **100% impossible as an Indian PAN**!
  2. Furthermore, the **5th character ($C_5$)** of an Individual (`'P'`) PAN card is **always the first letter of the cardholder's Surname / Last Name** (e.g., for `"RAHUL SHARMA"`, $C_5$ **must** be `'S'`!).
* **The Rule:** Enforce the strict `PAN` 4th-character domain filter and 5th-character surname cross-check in Section 4.1.

### Mistake 3: Failing to Apply Position-Constrained OCR Homoglyph Correction (`O` $\leftrightarrow$ `0`, `I` $\leftrightarrow$ `1`, `S` $\leftrightarrow$ `5`, `B` $\leftrightarrow$ `8`, `Z` $\leftrightarrow$ `2`)
* **The Trap:** Rejecting an OCR-extracted `IFSC` code `"SBINO004821"` or `PAN` `"ABCDE1234F"` when the OCR engine misreads the digit `'0'` as the capital letter `'O'` (or `'1'` as `'I'`, `'5'` as `'S'`, `'8'` as `'B'`).
* **Why It Fails:** Indian identity and banking codes have **fixed positional character classes** (some positions are *strictly alphabetic `[A-Z]`*, and other positions are *strictly numeric `[0-9]`*):
  * In an **11-character `IFSC` code**: Positions $1\text{–}4$ are **always letters**, and Position $5$ is **always the digit `'0'`**!
  * In a **10-character `PAN` code**: Positions $1\text{–}5$ are **always letters**, Positions $6\text{–}9$ are **always digits**, and Position $10$ is **always a letter**!
  * In a **15-character `GSTIN`**: Positions $1\text{–}2$ are **always digits**, Positions $3\text{–}7$ are **letters**, Positions $8\text{–}11$ are **digits**, Position $12$ is a **letter**, Position $14$ is `'Z'`.
* **The Rule:** Before validating any fixed-mask Indian identifier, apply the **Positional Homoglyph Normalizer** (Section 3.3) to convert digit-lookalikes in letter positions and letter-lookalikes in digit positions!

### Mistake 4: Reading Multi-Column `BIP-39` Seed Phrase Grids in Naive Left-to-Right Scanline Order
* **The Trap:** Taking the flat string output of an OCR engine on a `Trust Wallet`, `TronLink`, or `MetaMask` seed backup screenshot and feeding consecutive 12-word windows into the `BIP-39` validator.
* **Why It Fails:** Suppose a wallet app displays a 12-word recovery phrase in **2 vertical columns of 6 words**:
  * Column 1 (Left): `1. abandon`, `2. ability`, ..., `6. absent`
  * Column 2 (Right): `7. absorb`, `8. abstract`, ..., `12. about`
  A standard OCR engine scans from top to bottom, left to right across the full image width, outputting: `"1. abandon 7. absorb 2. ability 8. abstract ..."`! When those interleaved words are fed into the `BIP-39` SHA-256 checksum validator, **the checksum fails** (or worse, derives the wrong wallet address)!
* **The Rule:** Sub-Engine 7.4D uses **Bounding-Box Coordinate & Number-Badge Grid Reconstruction** (Section 6.1) to test explicit index badges (`1..12`/`24`), **Row-Major**, and **2-Column / 3-Column Column-Major** orderings against Module 4.4's `BIP-39` SHA-256 checksum validator!

### Mistake 5: Extracting Passport Numbers From Photos Without Validating the 5 `ICAO Doc 9303` MRZ Check Digits
* **The Trap:** Using a simple regex to scrape passport numbers or dates of birth from photos of Indian or foreign Passports.
* **Why It Fails:** Every ICAO-compliant Passport contains a 2-line **Machine Readable Zone (`MRZ`, `TD3` format: two lines of 44 `OCR-B` characters each)** at the bottom of the bio-data page. That 88-character block contains **five mathematical Modulo-10 (`7-3-1` weighted) check digits** that verify the Passport Number, Date of Birth, Expiry Date, Personal Number, and the Composite Row!
* **The Rule:** Implement the exact **ICAO Doc 9303 `7-3-1` Modulo-10 Validator** in Section 4.4 to guarantee $100\%$ error-free passport extraction and catch forged passport images!

### Mistake 6: Missing `Cancelled Cheques` & `Bank Passbook` Photos (The Primary Mule-Onboarding Artifact)
* **The Trap:** Building OCR classifiers only for government ID cards (`Aadhaar`/`PAN`) and ignoring photos of **Cancelled Cheques (`"CANCELLED"` written across a cheque leaf)** and **Bank Passbook Front Pages**.
* **Why It Fails:** Whenever a money mule is recruited in India, the syndicate handler requires the mule to send three photos on WhatsApp/Telegram: (1) Aadhaar Card, (2) PAN Card, and (3) a **Cancelled Cheque or Bank Passbook Front Page** (which proves the exact unmasked 11- to 16-digit Bank Account Number, 11-character `IFSC`, and 9-digit `MICR` code!).
* **The Rule:** Sub-Engine 7.4C provides dedicated structural extractors for Cancelled Cheques, Bank Passbooks, Physical Debit/Credit Cards (`Luhn Mod-10`), and Hawala Currency-Note Tokens (Section 5).

---

## 3. Step 1 — Sub-Engine 7.4A: Pre-Computed iOS `Live Text` Harvester, Tiered Offline OCR Queue & Homoglyph Normalizer

### 3.1 Stage 1: Harvesting Pre-Computed Apple Vision `Live Text` From iOS `Photos.sqlite`

Before running CPU/GPU OCR on any iOS extraction, query `/private/var/mobile/Media/PhotoData/Photos.sqlite` (via **Module 2.1 Active + `-wal` + Freelist**):

$$\texttt{ZASSET.ZADDITIONALATTRIBUTES} = \texttt{ZADDITIONALASSETATTRIBUTES.Z\_PK}$$
$$\texttt{ZADDITIONALASSETATTRIBUTES.ZCHARACTERRECOGNITIONATTRIBUTES} = \texttt{ZCHARACTERRECOGNITIONATTRIBUTES.Z\_PK}$$

From **`ZCHARACTERRECOGNITIONATTRIBUTES`**, extract:
1. **`ZCHARACTERRECOGNITIONDATA` (`BLOB`) & `ZHANDWRITINGRECOGNITIONDATA` (`BLOB`):**
   * These blobs are serialized Apple **`NSKeyedArchiver` (`bplist00`)** objects (`VNDocumentObservation` / `VNRecognizedTextBlockObservation`) generated by iOS's Neural Engine!
   * Unpack the binary plist (`bplist00` string table and `NS.string` / `topTranscript` objects) to extract **every line of recognized printed text and handwritten text**, along with its normalized bounding box coordinates and confidence score—with **zero OCR CPU cost**!
2. **`ZMACHINEREADABLECODEDATA` (`BLOB`):**
   * Unpacks any QR/Barcode payload that iOS `mediaanalysisd` already detected inside that photo!
3. **`ZALGORITHMVERSION` & `ZADJUSTMENTVERSION`:**Timestamp/version of the recognition pass.

### 3.2 Stage 2: The 4-Tier Priority Offline Multilingual OCR Queue

For all images that do not have pre-computed `Live Text` (all Android images, app-switcher snapshots, unmasked vault images, reconstructed thumbnails, PDF image pages, and unindexed WhatsApp/Telegram/Signal media), process them through the **Offline Multilingual OCR Engine** (supporting **Latin/English**, **Devanagari/Hindi**, and major regional scripts) in four priority tiers so critical financial/KYC evidence is available to the examiner within seconds:

* **Priority Tier 1 (Immediate Execution):**
  * All **OS App-Switcher Snapshots** (`SplashBoard` & `TaskSnapshots` from Module 7.2).
  * All **Screenshots** (`/DCIM/Screenshots/`, `/Pictures/Screenshots/`, `ZKINDSUBTYPE == 10`).
  * All **Unmasked Disguised Vault Images** (`Calculator+`, `Hide It Pro`, `mars_files` Locked Folder).
  * All **CEX P2P & Betting Live-Chat Uploaded Receipt Images** (from Modules 4.2 and 5.5).
* **Priority Tier 2 (High Priority):**
  * All **WhatsApp, Telegram, Signal, Session, SimpleX, Zangi, Botim, and Dating App Media Images** (`/WhatsApp Images/`, `/Telegram Images/`, etc.).
* **Priority Tier 3 (Document & Camera Scans):**
  * Images created by document-scanner apps (`CamScanner`, `Adobe Scan`, `Microsoft Lens`, `Google Drive Scanner`, `Files` Document Scanner) and Camera Roll photos with text-density features.
* **Priority Tier 4 (Background Sweep):**
  * Remaining general Camera Roll photos and reconstructed `.ithmb` / `Glide` cache thumbnails.

### 3.3 Stage 3: The Position-Constrained OCR Homoglyph Normalizer

When matching candidate fixed-format alphanumeric identifiers (such as `PAN`, `IFSC`, `GSTIN`, `Passport MRZ`, `Voter ID`, `Driving Licence`, or `Vehicle RC Plate`), define two deterministic character-repair maps:

1. **Map A (`force_alpha_position`: When the format specification mandates an Uppercase Letter `[A-Z]` at Position $p$):**
   * `'0'` / `'O'` / `'Q'` $\rightarrow$ `'O'` (or `'D'` if context requires)
   * `'1'` / `'I'` / `'l'` / `'|'` $\rightarrow$ `'I'`
   * `'2'` $\rightarrow$ `'Z'`
   * `'5'` $\rightarrow$ `'S'`
   * `'8'` $\rightarrow$ `'B'`
   * `'6'` $\rightarrow$ `'G'`
2. **Map B (`force_digit_position`: When the format specification mandates a Numeric Digit `[0-9]` at Position $p$):**
   * `'O'` / `'o'` / `'Q'` / `'D'` $\rightarrow$ `'0'`
   * `'I'` / `'i'` / `'l'` / `'|'` / `'L'` $\rightarrow$ `'1'`
   * `'Z'` / `'z'` $\rightarrow$ `'2'`
   * `'S'` / `'s'` $\rightarrow$ `'5'`
   * `'B'` $\rightarrow$ `'8'`
   * `'G'` $\rightarrow$ `'6'`

---

## 4. Step 2 — Sub-Engine 7.4B: Deterministic Indian KYC & Identity Document Classifier & Mathematical Validator

Every OCR text block (along with its word bounding boxes) is evaluated against six deterministic Indian & international KYC document validators:

### 4.1 Validator 1: Indian Income Tax `PAN` Card (`Permanent Account Number` — 10 Characters)

* **Structural Pattern (After Positional Homoglyph Repair):**
  $$P = L_1 L_2 L_3 L_4 L_5 D_6 D_7 D_8 D_9 L_{10}$$
  where $L_1..L_5, L_{10} \in [\texttt{A–Z}]$ and $D_6..D_9 \in [\texttt{0–9}]$.
* **Step 1 (Mandatory 4th-Character Entity Status Check):**
  * Verify that $L_4$ belongs to the official 10-code set:
    * `'P'` = **Individual / Person**
    * `'C'` = **Company**
    * `'H'` = **Hindu Undivided Family (`HUF`)**
    * `'F'` = **Partnership Firm / LLP**
    * `'A'` = **Association of Persons (`AOP`)**
    * `'T'` = **Trust**
    * `'B'` = **Body of Individuals (`BOI`)**
    * `'L'` = **Local Authority**
    * `'J'` = **Artificial Juridical Person**
    * `'G'` = **Government Agency**
  * If $L_4$ is not one of those 10 letters, reject immediately!
* **Step 2 (Contextual Card Header & 5th-Character Surname Cross-Check):**
  * Check if the image also contains PAN card anchor phrases (`"INCOME TAX DEPARTMENT"`, `"GOVT. OF INDIA"`, `"Permanent Account Number"`, `"Father's Name"`, `"Date of Birth"`).
  * Extract the Cardholder's `Full Name`, `Father's Name`, and `Date of Birth (DD/MM/YYYY)` from the lines above the PAN number.
  * **Surname Initial Verification:** For an Individual PAN ($L_4 == \texttt{'P'}$), check whether the **5th character ($L_5$)** matches the initial letter of the cardholder's extracted Surname (or First Name if single-name cardholder). If $L_5$ contradicts all name tokens on a physical PAN card image, flag **`SUSPECTED_FORGED_PAN_SURNAME_MISMATCH`**!

### 4.2 Validator 2: `UIDAI Aadhaar` Card & `e-Aadhaar` (`12-Digit UID` & `16-Digit VID`)

1. **Candidate Extraction:** Locate any 12-digit number formatted as `XXXX XXXX XXXX` (or masked `XXXX XXXX 1234`) in the presence of Aadhaar anchor terms (`"Government of India"`, `"Aadhaar"`, `"Mera Aadhaar"`, `"Unique Identification Authority"`, `"DOB"`, `"YEAR OF BIRTH"`, `"VID :"`).
2. **Mathematical Verification (Unmasked 12-Digit Aadhaar):**
   * Verify Digit $1 \in \{2, 3, 4, 5, 6, 7, 8, 9\}$ (never `0` or `1`).
   * Verify the **12-digit Verhoeff Dihedral Group $D_5$ Checksum** (using the exact multiplication $d(j,k)$ and permutation $p(\text{pos}, \text{digit})$ tables defined in **Phase 3, Module 3.5A Section 3.2**).
3. **Cross-Verification Against Module 7.3B's Unpacked Secure QR Code (Anti-Photoshop Check!):**
   * If the Aadhaar card image also yielded a decoded **UIDAI Secure QR Code** in **Module 7.3B (`uidai_aadhaar_secure_qr_unpacked_ledger`)**:
     * Compare the **OCR-printed `Full Name`, `Date of Birth`, `Gender`, and `Last 4 Aadhaar Digits`** on the face of the card against the **RSA-signed `signed_full_name`, `signed_dob_and_gender`, and `aadhaar_last_4_digits`** unpacked from the Secure QR code!
     * If the printed text on the card face does **not** match the cryptographic QR payload (for example, a mule or fraudster photoshopped a new name or Aadhaar number onto the card image while leaving an old QR code!), immediately trigger **`CRITICAL: PHOTOSHOPPED_AADHAAR_TEXT_VS_QR_MISMATCH`**!

### 4.3 Validator 3: Indian `GSTIN` (`Goods and Services Tax Identification Number` — 15 Characters)

In shell-company ("Dummy Firm") mule account investigations, suspects store photos/PDFs of **GST Registration Certificates (`Form GST REG-06`)**.
* **Exact 15-Character Structure:**
  $$\text{GSTIN} = S_1 S_2 \underbrace{L_3 L_4 L_5 L_6 L_7 D_8 D_9 D_{10} D_{11} L_{12}}_{\text{Embedded 10-Char PAN!}} E_{13} \texttt{'Z'}_{14} C_{15}$$
  1. **Characters $1\text{–}2$ ($S_1 S_2$):** 2-digit **Indian State Census Code** (`01` = J&K, `06` = Haryana, `07` = Delhi, `08` = Rajasthan, `09` = **Uttar Pradesh**, `10` = Bihar, `19` = West Bengal, `24` = Gujarat, `27` = **Maharashtra**, `29` = **Karnataka**, `33` = Tamil Nadu, `36` = Telangana, etc., within `01`–`38` or `97`).
  2. **Characters $3\text{–}12$:** **Automatically extract Characters $3\text{–}12$ as the proprietor's or company's 10-character `PAN` (`Permanent Account Number`)** and validate it via Validator 1!
  3. **Character $13$ ($E_{13}$):** Entity registration count within that state (`1–9` or `A–Z`).
  4. **Character $14$:** Must equal **`'Z'`**.
  5. **Character $15$ ($C_{15}$ — Modulo-36 Checksum Character):**
     * Map characters `'0'–'9'` to values $0\text{–}9$ and `'A'–'Z'` to values $10\text{–}35$.
     * For positions $i = 0 \dots 13$ (the first 14 characters): multiply value $v_i$ by factor $f_i = 1$ (if $i$ is even) or $f_i = 2$ (if $i$ is odd). Compute quotient $q_i = \lfloor (v_i \times f_i) / 36 \rfloor$ and remainder $r_i = (v_i \times f_i) \bmod 36$, and sum $S = \sum_{i=0}^{13} (q_i + r_i)$.
     * The expected 15th check character has value:
       $$v_{\text{check}} = (36 - (S \bmod 36)) \bmod 36$$
     * Verify that $C_{15}$ matches $v_{\text{check}}$!

### 4.4 Validator 4: Indian & International `Passports` (`ICAO Doc 9303 TD3 MRZ` — Two 44-Char Lines)

Whenever OCR detects two consecutive lines of $\approx 44$ uppercase characters containing `<<` filler chevrons (`P<...`), execute the **ICAO Doc 9303 TD3 Machine Readable Zone (`MRZ`) Decoder & `7-3-1` Modulo-10 Validator**:

1. **Unpack Line 1 (Characters $0\text{–}43$):**
   * **Chars $0\text{–}1$:** Document Type (`"P<"`).
   * **Chars $2\text{–}4$:** Issuing Country ISO-3166-1 alpha-3 code (e.g., `"IND"` = India, `"ARE"` = UAE, `"GBR"` = UK, `"USA"`, `"KHM"` = Cambodia).
   * **Chars $5\text{–}43$:** Split on double chevron `"<<"`:
     * Before `"<<"` = **Surname** (replace single `'<'` with space).
     * After `"<<"` = **Given Names** (replace `'<'` with space).
2. **Unpack Line 2 (Characters $0\text{–}43$) & Verify All 5 Check Digits:**
   * **Chars $0\text{–}8$:** **Passport Number** (9 chars, padded with `'<'`).
   * **Char $9$:** **Check Digit 1** (verifies Chars $0\text{–}8$).
   * **Chars $10\text{–}12$:** Nationality (`"IND"`).
   * **Chars $13\text{–}18$:** **Date of Birth (`YYMMDD`)**.
   * **Char $19$:** **Check Digit 2** (verifies Chars $13\text{–}18$).
   * **Char $20$:** Sex (`"M"`, `"F"`, or `"<"`).
   * **Chars $21\text{–}26$:** **Passport Expiration Date (`YYMMDD`)**.
   * **Char $27$:** **Check Digit 3** (verifies Chars $21\text{–}26$).
   * **Chars $28\text{–}41$:** Personal Number ($14\text{ chars}$).
   * **Char $42$:** **Check Digit 4** (verifies Chars $28\text{–}41$).
   * **Char $43$:** **Composite Check Digit 5** (verifies `Line2[0:10] + Line2[13:20] + Line2[21:43]`).
3. **The Exact ICAO `7-3-1` Modulo-10 Checksum Formula:**
   * Assign numeric values $v(c)$ to each character $c$:
     * `'0'–'9'` $\rightarrow 0\text{–}9$
     * `'A'–'Z'` $\rightarrow 10\text{–}35$
     * `'<'` (filler chevron) $\rightarrow \mathbf{0}$
   * Repeat the 3-element weight pattern $W = [7, 3, 1, 7, 3, 1, \dots]$ across the slice of length $L$:
     $$\text{Check Digit} = \left(\sum_{i=0}^{L-1} v(c_i) \times W[i \bmod 3]\right) \bmod 10$$
   * Verify all 5 check digits! If any check digit fails after homoglyph repair (`'O'` $\leftrightarrow$ `'0'`), flag **`FORGED_OR_ALTERED_PASSPORT_MRZ`**!

### 4.5 Validator 5: Indian `Voter ID` (`EPIC`), `Driving Licence` (`Parivahan DL`) & `Vehicle RC`

1. **Election Commission of India `Voter ID` (`EPIC`):**
   * Match 3 uppercase letters + 7 digits (`^[A-Z]{3}[0-9]{7}$`) in the presence of `"ELECTION COMMISSION OF INDIA"`, `"IDENTITY CARD"`, `"Elector's Name"`. Extract `EPIC Number`, `Elector Name`, `Father's/Husband's Name`, and `Address`.
2. **Indian `Driving Licence` (`DL` — Sarathi Parivahan Standard):**
   * Match `^([A-Z]{2})[- ]?([0-9]{2})[- ]?((?:19|20)[0-9]{2})([0-9]{7})$` (e.g., `UP14 20190048291` or `DL-0420210123456`):
     * Group 1 (`UP`): 2-letter State Code.
     * Group 2 (`14`): 2-digit RTO Code (`UP-14` = Ghaziabad RTO; `UP-65` = Varanasi RTO!).
     * Group 3 (`2019`): 4-digit Year of Issue.
     * Group 4 (`0048291`): 7-digit Licence Serial Number.

---

## 5. Step 3 — Sub-Engine 7.4C: Financial Instrument OCR (`Cancelled Cheques`, `Bank Passbooks`, `Payment Cards` & `Hawala Currency Tokens`)

### 5.1 Target 1: Photographed `Cancelled Cheques` & `Bank Passbook Front Pages`

When OCR detects banking anchor terms (`"IFSC"`, `"IFS Code"`, `"MICR"`, `"A/c No"`, `"Account Number"`, `"Pay "`, `"Rupees"`, `"Or Bearer"`, `"CANCELLED"`, `"PASSBOOK"`, `"Branch"`):

1. **Extract & Validate the 11-Character `IFSC` Code:**
   * Apply Positional Homoglyph Repair (`Chars 1–4` = Alpha, `Char 5` = `'0'`, `Chars 6–11` = Alphanumeric) and resolve the **Exact Bank Name, Branch Name, and City** via **Phase 3, Module 3.3 Section 8.2**!
2. **Extract the Unmasked `Bank Account Number` ($9\text{ to }18\text{ Digits}$):**
   * Locate the numeric string inside the `"A/c No."` box on the cheque leaf or passbook page, validating its length against the resolved bank's account-length rule (e.g., **11 digits for SBI**, **14 digits for HDFC / Kotak**, **12 digits for ICICI**, **15 digits for Axis / Union Bank**, **16 digits for PNB**!).
3. **Extract the 9-Digit `MICR` (`Magnetic Ink Character Recognition`) Code (`E-13B` Font at Bottom of Cheque):**
   * On the bottom white border of every Indian cheque leaf sits `[6-Digit Cheque Number]` + **`[9-Digit MICR Code]`** + `[2-Digit Account Transaction Code]`:
     * **MICR Digits $1\text{–}3$:** First 3 digits of the **City Postal PIN Code** (e.g., `110` = Delhi NCR, `400` = Mumbai, `221` = Varanasi, `560` = Bengaluru)!
     * **MICR Digits $4\text{–}6$:** 3-digit **RBI Bank Code** (e.g., `002` = SBI, `240` = HDFC, `229` = ICICI).
     * **MICR Digits $7\text{–}9$:** 3-digit **Branch Code**.
4. **Extract the Printed `Account Holder Name(s)`** (above `"Please sign above"` on the right side of the cheque leaf or on the passbook cover) and **automatically insert the unmasked account into Phase 3's `upi_and_bank_accounts_inventory`**!

### 5.2 Target 2: Photographed Physical `Debit / Credit Cards` (`Luhn Mod-10` + `BIN` Resolver)

Suspects and carding/mule operators photograph the front and back of physical **RuPay, Visa, and MasterCard** ATM debit cards:
1. Locate candidate 16-digit (or 15/19-digit) card numbers (`XXXX XXXX XXXX XXXX`, starting with `'4'` = Visa, `'5'`/`'2'` = MasterCard, `'60'`/`'65'`/`'81'`/`'82'`/`'508'` = **NPCI RuPay**).
2. **Verify the `Luhn Modulo-10` Checksum:**
   * Double every second digit from right to left (subtracting $9$ if the product $> 9$), sum all digits, and verify $\text{Sum} \bmod 10 == 0$!
3. Extract `VALID THRU (MM/YY)`, `Cardholder Name`, and any 3-digit `CVV` (if back of card photographed), and resolve the 6-to-8 digit **`BIN` (`Bank Identification Number`)** to the issuing Indian or foreign bank!

### 5.3 Target 3: Indian `Hawala Currency-Note Serial Number` Bearer Tokens

To detect photos of Indian banknotes (`₹10`, `₹20`, `₹50`, `₹100`, `₹200`, `₹500`) used as **Hawala Physical Bearer Tokens**:
* Check if the OCR text contains `"RESERVE BANK OF INDIA"`, `"GUARANTEED BY THE CENTRAL GOVERNMENT"`, `"I PROMISE TO PAY THE BEARER"`, or `"महात्मा गांधी"` / `"भारतीय रिजर्व बैंक"`.
* Extract the **RBI Currency Note Serial Number** (formatted as **3 characters \[2 digits + 1 letter or Inset Letter\] + space + 6 digits**, e.g., **`45B 829104`** or **`7GW 104928`**), along with any handwritten phone number, date, or Rupee amount written on the note or on a paper slip beside the note!
* Flag the image as **`HAWALA_CURRENCY_NOTE_BEARER_TOKEN`**!

---

## 6. Step 4 — Sub-Engine 7.4D: The Grid-Aware `BIP-39` Seed Phrase Screenshot Reconstructor & Cross-Phase Router

### 6.1 Reconstructing Multi-Column `BIP-39` Seed Grids From Screenshots & Photos

When a user takes a screenshot of a wallet's "Backup Seed Phrase" screen (or photographs a written seed sheet), standard OCR returns a list of word bounding boxes:
$$\text{Token}_i = \big(\text{text}_i, \ x_{\text{min},i}, \ y_{\text{min},i}, \ x_{\text{max},i}, \ y_{\text{max},i}\big)$$

Whenever $\ge 12$ tokens in an image match words (or 4-letter prefixes) in the **2,048-word `BIP-39` wordlist** (or 25 words in the Monero wordlist), Sub-Engine 7.4D reconstructs the true word sequence using **Three Candidate Spatial Orderings** and tests each ordering against **Phase 4, Module 4.4's `BIP-39` SHA-256 Checksum Validator**:

1. **Ordering 1 — Explicit Number-Badge Sorting (`1. word` .. `12. word` / `24. word`):**
   * Look for numeric prefixes or adjacent number badges (`1` through `12` or `1` through `24`) immediately to the left of each BIP-39 word bounding box ($|y_{\text{num}} - y_{\text{word}}| < \text{line\_height}$ and $0 < x_{\text{word}} - x_{\text{num}} < 120\text{ px}$).
   * Sort the BIP-39 words by their paired badge integer $1, 2, \dots, W$ and test the SHA-256 checksum!
2. **Ordering 2 — Row-Major Ordering (Top-to-Bottom, then Left-to-Right within each horizontal row):**
   * Cluster tokens into horizontal rows where vertical centers $y_c$ differ by $< 0.5 \times \text{box\_height}$, sort each row left-to-right by $x_{\text{min}}$, concatenate, and test the SHA-256 checksum!
3. **Ordering 3 — Column-Major Ordering (2-Column & 3-Column Vertical Grids):**
   * Cluster tokens by their horizontal left edge $x_{\text{min}}$ into $C \in \{2, 3\}$ vertical columns (using k-means / gap splitting on $x_{\text{min}}$).
   * Sort Column 1 top-to-bottom by $y_{\text{min}}$, followed by Column 2 top-to-bottom by $y_{\text{min}}$ (and Column 3 if $C=3$), concatenate, and test the SHA-256 checksum!
4. **Immediate HD Address Derivation Upon Checksum Match:**
   * Whichever ordering passes the **`BIP-39` SHA-256 Checksum**, immediately pass that verified 12/24-word sequence to **Phase 4, Module 4.4B** to derive the suspect's `T...` (TRON), `0x...` (EVM), `bc1q...` (Bitcoin), and `Solana` wallet addresses!

### 6.2 Automated Cross-Phase Intelligence Routing

Every structured entity extracted by Module 7.4 is automatically routed into the master ledgers of Phases 3, 4, 5, and 6:
* **UPI Receipts & Bank Cheques/Passbooks** $\rightarrow$ **Phase 3 (`Module 3.5C` Layer-4 Visual Receipts & `upi_and_bank_accounts_inventory`)** + **Module 7.3D (Forged Receipt Auditor)**.
* **BIP-39 Seeds & Crypto Addresses (`T...`, `0x...`, `bc1q...`)** $\rightarrow$ **Phase 4 (`Module 4.3` & `Module 4.4`)**.
* **Screenshots of WhatsApp / Telegram / Signal / Session / Instagram Chats** $\rightarrow$ **Phase 5 (Tagged as `RESIDUAL_RECORD: Visual Chat Screenshot Survivor`)**—preserving messages even if the chat app itself was uninstalled and wiped!

---

## 7. Database Schema for Module 7.4 (`ocr_indian_kyc_and_visual_intelligence.sqlite`)

The developer must create the following three tables in the case database:

### Table 1: `visual_ocr_master_index` (Full-Text Searchable OCR & `Live Text` Ledger Across All Visual Assets)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `ocr_record_uid` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Unique row ID. |
| `source_vfs_file_id` | `INTEGER` | `NOT NULL` | Foreign key to the image, snapshot, thumbnail, or vault file in `vfs_index`. |
| `visual_source_category` | `TEXT` | `NOT NULL` | Enum: `IOS_PRECOMPUTED_LIVETEXT`, `OS_APP_SWITCHER_SNAPSHOT`, `GALLERY_SCREENSHOT`, `MESSENGER_MEDIA_IMAGE`, `UNMASKED_VAULT_IMAGE`, `RECONSTRUCTED_THUMBNAIL`. |
| `visual_document_classification` | `TEXT` | `NOT NULL` | Enum: `INDIAN_PAN_CARD`, `UIDAI_AADHAAR_CARD`, `INDIAN_GST_CERTIFICATE`, `PASSPORT_MRZ_BIO_PAGE`, `VOTER_ID_EPIC`, `DRIVING_LICENCE_DL`, `CANCELLED_CHEQUE_OR_PASSBOOK`, `DEBIT_OR_CREDIT_CARD`, `HAWALA_CURRENCY_TOKEN_NOTE`, `CRYPTO_BIP39_SEED_SCREENSHOT`, `UPI_OR_BANK_PAYMENT_RECEIPT`, `CHAT_CONVERSATION_SCREENSHOT`, `GENERAL_TEXT_IMAGE`. |
| `full_extracted_text` | `TEXT` | `NOT NULL` | Complete normalized UTF-8 text (indexed via SQLite **`FTS5`** Full-Text Search for instant keyword querying!). |
| `detected_scripts_and_langs` | `TEXT` | `NULL` | E.g., `"Latin/English, Devanagari/Hindi"`. |
| `mean_ocr_confidence` | `REAL` | `NULL` | Confidence score ($0.0\text{ to }1.0$). |
| `image_captured_or_mtime_utc` | `TEXT` | `NULL` | Normalized UTC ISO-8601 timestamp of the image. |
| `recovery_classification` | `TEXT` | `NOT NULL` | 6-State Enum (`ORIGINAL_RECORD`, `HISTORICAL_COMMITTED_RECORD`, `RESIDUAL_RECORD`). |

### Table 2: `indian_kyc_and_identity_documents_ledger` (Structured Mule & Suspect KYC Cards Extracted From Images/PDFs)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `kyc_doc_uid` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Unique row ID. |
| `ocr_record_uid` | `INTEGER` | `NOT NULL` | Foreign key to `visual_ocr_master_index.ocr_record_uid`. |
| `source_vfs_file_id` | `INTEGER` | `NOT NULL` | Source image or PDF in `vfs_index`. |
| `document_type` | `TEXT` | `NOT NULL` | Enum: `PAN_CARD`, `AADHAAR_CARD`, `GSTIN_CERTIFICATE`, `PASSPORT_MRZ`, `VOTER_ID_EPIC`, `DRIVING_LICENCE`, `VEHICLE_RC`. |
| `document_id_number` | `TEXT` | `NOT NULL` | **Validated ID (`ABCDE1234F` PAN, 12-digit Aadhaar, 15-char GSTIN, Passport No, EPIC, or DL No)! Indexed!** |
| `mathematical_validation_status` | `TEXT` | `NOT NULL` | E.g., `"PAN_4TH_CHAR_AND_SURNAME_VERIFIED"`, `"AADHAAR_VERHOEFF_AND_QR_VERIFIED"`, `"GSTIN_MOD36_VERIFIED"`, `"ICAO_9303_MRZ_5_CHECKDIGITS_VERIFIED"`, **`"CRITICAL_FORGED_DOCUMENT_DETECTED"`**. |
| `holder_full_name` | `TEXT` | `NULL` | Extracted legal name of the document holder. |
| `father_or_guardian_name` | `TEXT` | `NULL` | Extracted Father's / Husband's Name. |
| `date_of_birth_or_incorp` | `TEXT` | `NULL` | Extracted Date of Birth (`DD/MM/YYYY`). |
| `entity_type_or_state` | `TEXT` | `NULL` | E.g., `"Individual (P)"`, `"Company (C)"`, `"State: 09 (Uttar Pradesh)"`, `"Nationality: IND"`. |
| `extracted_address_and_pin` | `TEXT` | `NULL` | Full address and 6-digit PIN code (if present on document). |
| `shared_in_chat_or_app_context` | `TEXT` | `NULL` | Links to the exact WhatsApp/Telegram chat and sender who sent this KYC document image! |

### Table 3: `visual_financial_instruments_and_hawala_tokens` (`Cancelled Cheques`, `Passbooks`, `Cards` & `Hawala Currency Notes`)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `fin_instrument_uid` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Unique row ID. |
| `ocr_record_uid` | `INTEGER` | `NOT NULL` | Foreign key to `visual_ocr_master_index.ocr_record_uid`. |
| `source_vfs_file_id` | `INTEGER` | `NOT NULL` | Source image in `vfs_index`. |
| `instrument_category` | `TEXT` | `NOT NULL` | Enum: `CANCELLED_CHEQUE_LEAF`, `BANK_PASSBOOK_FRONT_PAGE`, `PHYSICAL_DEBIT_OR_CREDIT_CARD`, `HAWALA_CURRENCY_NOTE_TOKEN`. |
| `bank_name_and_branch` | `TEXT` | `NULL` | Resolved Bank Name, Branch, and City (from IFSC/MICR/BIN). |
| `account_or_card_number` | `TEXT` | `NULL` | **Full unmasked Bank Account Number ($9\text{–}18$ digits) or Luhn-verified 16-digit Card Number!** |
| `ifsc_and_micr_code` | `TEXT` | `NULL` | E.g., `"IFSC: SBIN0004821 | MICR: 221002014"`. |
| `account_or_card_holder_name` | `TEXT` | `NULL` | Printed account holder or cardholder name. |
| `card_expiry_and_cvv` | `TEXT` | `NULL` | Expiry `MM/YY` (and `CVV` if back of card photographed). |
| `hawala_note_denomination_serial` | `TEXT` | `NULL` | **E.g., `"INR ₹10 Note — RBI Serial: 45B 829104"` (if `HAWALA_CURRENCY_NOTE_TOKEN`)!** |
| `linked_phase3_account_uid` | `INTEGER` | `NULL` | Foreign key to Phase 3 `upi_and_bank_accounts_inventory`. |

---

## 8. Developer Acceptance Test Checklist for Module 7.4

1. **The Indian `PAN` 4th-Character Entity & 5th-Character Surname Validator Test:**
   * Feed two OCR text blocks into Validator 1 (Section 4.1):
     * Block A: `"INCOME TAX DEPARTMENT / RAHUL KUMAR SHARMA / ABCPS1234K"` (where 4th char `'P'` = Individual, and 5th char `'S'` matches Surname `"SHARMA"`).
     * Block B: `"ABCZS1234K"` (where 4th char `'Z'` is an invalid entity code).
   * Verify that Block A is accepted and classified as `PAN_4TH_CHAR_AND_SURNAME_VERIFIED`, while Block B is rejected!
2. **The `ICAO Doc 9303` Passport `MRZ` `7-3-1` Modulo-10 Checksum Test:**
   * Feed a 2-line Indian Passport MRZ into Validator 4 (Section 4.4):
     * Line 1: `"P<INDSHARMA<<RAHUL<KUMAR<<<<<<<<<<<<<<<<<<<<"`
     * Line 2: `"Z4829104<6IND9508155M3211048<<<<<<<<<<<<<<02"`
   * Verify that Validator 4 computes the `7-3-1` Modulo-10 checksums across all 5 check digits (`6`, `5`, `8`, `0`, `2`), extracts Surname `"SHARMA"`, Given Name `"RAHUL KUMAR"`, Passport No `"Z4829104"`, DOB `"1995-08-15"`, and Expiry `"2032-11-04"`.
3. **The `Cancelled Cheque` Homoglyph `IFSC` Repair (`SBINO004821` $\rightarrow$ `SBIN0004821`) & `MICR` Test:**
   * Feed OCR text from a Cancelled Cheque containing `"A/c No: 30984718291"`, `"IFSC: SBINO004821"` (with letter `'O'` in position 5), and `"MICR: 221002014"`.
   * Verify that Sub-Engine 7.4A/C repairs Position 5 of the IFSC to `'0'` (`"SBIN0004821"`), resolves `"State Bank of India"` + `"Varanasi (PIN 221xxx)"` from the IFSC and MICR, and inserts Account `30984718291` into Phase 3!
4. **The 2-Column `BIP-39` Seed Screenshot Column-Major Reconstruction Test:**
   * Create a screenshot image displaying the 12-word test seed in **two vertical columns of 6 words** (where naive left-to-right scanline OCR reads `"1. abandon 7. absorb 2. ability 8. abstract ..."`).
   * Verify that Sub-Engine 7.4D sorts the bounding boxes via Badge/Column-Major order, validates the `BIP-39` SHA-256 checksum, and triggers Module 4.4B to derive the `T...` (TRON) and `0x...` (EVM) wallet addresses!
# Engineering Specification: Phase 7, Module 7.3 — Offline Universal Barcode/QR Decoder, UIDAI Aadhaar Secure QR (`BigInt` + `Gzip` + `.jp2` Photo) Unpacker & Forged UPI/Bank Payment Screenshot Detector

**Document Purpose:** This document provides the complete, step-by-step architectural blueprint for building **Module 7.3** of the Forensic Data Parser (corresponding to **Groups 3, 5, 12, 13, 15, and 17** of the Unified Master Register). It contains **zero programming code** and explains how to pre-process and decode 1D/2D barcodes and QR codes across all images, thumbnails, snapshots, and PDFs; how to mathematically unpack **India's UIDAI Aadhaar Secure QR Code** (`BigInt` Base-10 $\rightarrow$ Big-Endian Byte Array $\rightarrow$ `Gzip` Inflate $\rightarrow$ `0xFF`-delimited demographic fields + embedded `.jp2` JPEG-2000 facial photograph + iterative SHA-256 mobile/email verifier + 2048-bit RSA signature); and how to detect **Forged UPI & Bank Payment Screenshots** from first principles.

---

## 1. Purpose & Mental Model (Why QR Codes & Payment Screenshots Are High-Priority Forensic Evidence)

In Indian cybercrime, mule-account onboarding, hawala settlement, crypto laundering, and identity fraud, criminals routinely avoid typing sensitive bank details, wallet addresses, or identity numbers as searchable text in WhatsApp or Telegram. Instead, they exchange **images containing QR codes and payment screenshots**:

1. **Mule & Bookie QR Codes (`upi://pay` & `BharatQR`):**
   * Rather than typing a UPI ID or bank account number in a chat (which can be easily searched by keywords), a handler sends a **screenshot or photo of a PhonePe / Paytm / BharatPe QR code standee**. Without an automated QR decoder that scans every image, thumbnail, and app-switcher snapshot on the phone, those mule bank accounts remain invisible to the financial ledger in Phase 3!
2. **Cryptocurrency, Darknet & Covert Pairing QR Codes:**
   * Suspects store screenshots of `TRON` (`T...`) and `Ethereum` (`0x...`) deposit QR codes, `WalletConnect v2` (`wc:...`) pairing codes, `WhatsApp Web` companion linking codes, `SimpleX Chat` / `Session` invitation QR codes, and **eSIM (`LPA:1$...`) activation QR codes** (used to provision international burner eSIM profiles!).
3. **India's UIDAI Aadhaar Secure QR Code (The Ultimate Anti-Forgery KYC Check):**
   * Every physical Aadhaar card and `e-Aadhaar` PDF in India carries a high-density **UIDAI Secure QR Code**. When criminals forge an Aadhaar card in Photoshop (swapping the photograph and name on the card to rent a hotel room, buy a SIM card, or open a mule bank account), **they cannot forge the 2048-bit UIDAI RSA digital signature inside the Aadhaar QR code**!
   * By unpacking the `BigInt` + `Gzip` binary payload inside the Aadhaar QR code, your software extracts the **true UIDAI-signed Name, Date of Birth, Address, Last 4 Digits of Aadhaar, and the official embedded `.jp2` (JPEG-2000) biometric photograph of the real cardholder**—instantly proving whether the Aadhaar card photo on the suspect's phone was photoshopped!
4. **Forged UPI & Bank Payment Receipts ("Fake Payment Screenshot" Scams):**
   * Both fraudsters (tricking victims or merchants) and syndicate mules (cheating their own handlers) use "Fake PhonePe / Google Pay Receipt Generator" APKs or image editors to fabricate payment screenshots. Sub-Engine 7.3D catches forged payment receipts using a 5-point mathematical and cross-database audit.

---

## 2. The 6 Fatal Mistakes Beginner Developers Make in QR & Payment Receipt Forensics

Before implementing Module 7.3, the developer must understand six critical traps that cause standard QR scanners and forensic tools to fail:

### Mistake 1: Running a Single-Pass QR Scanner Without Dark-Mode Inversion & Perspective Dewarping
* **The Trap:** Passing raw image files directly into a standard `ZXing` or `ZBar` QR reader with default settings.
* **Why It Fails:**
  1. **Dark-Mode Inverted QR Codes:** Modern apps (`Telegram`, `Session`, `Phantom`, `MetaMask`, `X`, `Instagram`) often render QR codes with **white/colored modules on a dark/black background**! Standard QR specification (`ISO/IEC 18004`) expects dark modules on a light background; many standard decoders fail on inverted dark-mode screenshots unless you also test the bitwise luminance-inverted image ($I_{\text{inv}}(x, y) = 255 - I(x, y)$).
  2. **Angled Photos of Physical Shop Standees:** When a field operative takes a camera photo of a physical Paytm/PhonePe Soundbox QR standee on a shop counter at a $45^\circ$ angle or under uneven fluorescent glare, simple global thresholding washes out one corner of the QR finder patterns.
* **The Rule:** Implement the **4-Pass Pre-Processing & Multi-Engine Barcode Pipeline** in Section 3.1.

### Mistake 2: Treating the Aadhaar Secure QR Code's 1,200-Digit Base-10 String as "Corrupted / Unreadable"
* **The Trap:** Scanning a modern Indian Aadhaar card QR code, seeing that the decoded QR string is a massive 1,200-to-2,000 character base-10 integer (`"9847192837465918273645..."`), and discarding it as a numeric error!
* **Why It Fails:** Legacy pre-2018 Aadhaar cards used plain XML (`<PrintLetterBarcodeData uid="..." name="..."/>`) inside the QR code. In 2018, UIDAI replaced the XML format with the **UIDAI Secure QR Code (v2 / v3)**, which compresses the demographic text fields, the **JPEG-2000 (`.jp2`) facial photograph**, and a **256-byte RSA-2048 signature** using **Gzip (`DEFLATE`)**, treats the resulting compressed byte array as a single giant **Big-Endian Unsigned Integer (`BigInt`)**, and encodes it in QR **Numeric Mode (Base-10 digits)** for maximum data density!
* **The Rule:** Whenever a QR code yields a base-10 numeric string of length $\ge 500\text{ digits}$ (or legacy `<PrintLetterBarcodeData` XML), route it to **Sub-Engine 7.3B (The UIDAI Aadhaar Secure QR Unpacker)** in Section 4!

### Mistake 3: Failing to Verify Mobile Numbers & Emails Against the Aadhaar QR's Iterative `SHA-256` Hash
* **The Trap:** Thinking that because the Aadhaar Secure QR code hashes the cardholder's 10-digit mobile number and email address, you cannot verify if the suspect's phone number matches the Aadhaar card.
* **Why It Fails:** UIDAI does not use a random salt when hashing the mobile number and email inside the Secure QR code! Instead, UIDAI computes **iterated `SHA-256` where the number of hash iterations $N_{\text{iter}}$ is equal to the 4th digit of the 4-digit Aadhaar tail (`reference_id[3]`)** (replacing `0` with `1`)!
* **The Rule:** Because your parser already knows the candidate mobile numbers and email addresses on the seized phone (from Phase 1, Phase 3, and Phase 5), **Sub-Engine 7.3B automatically runs the UIDAI Iterative `SHA-256` Verification Formula** (Section 4.3) against every phone number and email on the device—mathematically proving which 10-digit mobile number is linked to that Aadhaar card!

### Mistake 4: Missing `LPA:1$` eSIM Activation QR Codes (International Burner eSIM Provisioning)
* **The Trap:** Ignoring QR strings that start with `LPA:1$`.
* **Why It Fails:** Cybercriminals and fugitives purchase anonymous international **eSIM profiles** (from providers like *Airalo*, *Holafly*, *Nomad*, *Numero*, *RedteaGO*, or foreign carriers in Dubai/UK/Cambodia) and receive the **eSIM Activation QR Code** as an image on WhatsApp, Telegram, or Email. Under the **GSMA SGP.22 RSP (Remote SIM Provisioning)** standard, every eSIM QR code encodes:
  $$\texttt{LPA:1\$<SM-DP+\_Server\_FQDN>\$<Matching\_ID\_Activation\_Code>[\$<OID>][\$<Confirmation\_Code\_Flag>]}$$
* **The Rule:** Explicitly parse `LPA:1$` QR codes to extract the carrier's **SM-DP+ Server Domain** and the unique **Activation Matching ID**, and cross-link to **Phase 3, Module 3.2 (`telephony.db` `siminfo` / `euicc`)**!

### Mistake 5: Trusting a UPI Payment Screenshot Without Checking the 12-Digit `UTR`'s `YDDD` Julian Date
* **The Trap:** Extracting `"Paid ₹50,000"` and `"UTR: 412098765432"` from a payment screenshot dated `"05 Nov 2026"` via OCR and accepting it as a genuine transaction receipt.
* **Why It Fails:** As established in **Phase 3, Module 3.5A**, the first 4 digits of a standard 12-digit NPCI UPI/IMPS `UTR` encode **`YDDD`** (`Digit 1` = last digit of the year; `Digits 2–4` = 3-digit Julian Day of the Year $1\text{–}366$ in IST). In the example above, `"05 Nov 2026"` is Year `6` (`2026`), Julian Day `309` (`YDDD = 6309`), **not `4120` (Year 2024, Day 120 = April 29, 2024)**! Fake receipt generator apps and Photoshop scammers almost always leave an old or random 12-digit UTR on the screenshot when they edit the date and amount!
* **The Rule:** Sub-Engine 7.3D automatically cross-validates the OCR-extracted date on the screenshot against the `YDDD` Julian date encoded inside the screenshot's 12-digit `UTR` (Section 6.2).

### Mistake 6: Scanning Only `/DCIM/` and Forgetting App-Switcher Snapshots, Thumbnails & PDF Pages
* **The Trap:** Running the QR decoder only on active photos in `/DCIM/Camera/`.
* **Why It Fails:** QR codes frequently exist inside **deleted thumbnails (`.ithmb` / `Glide` cache)**, **OS App-Switcher Snapshots (`SplashBoard` / `TaskSnapshots` from Module 7.2)**, **WhatsApp/Telegram media folders**, and **PDF documents** (`e-Aadhaar.pdf`, boarding passes, or bank statements).
* **The Rule:** Feed every visual asset from **Module 7.1**, **Module 7.2**, and embedded PDF images into Module 7.3.

---

## 3. Step 1 — Sub-Engine 7.3A: Multi-Pass Image Pre-Processing & Universal Barcode / QR Classification Pipeline

### 3.1 The 4-Pass Pre-Processing Pipeline for Degraded, Glare-Damaged & Dark-Mode QR Codes

For every visual asset (still images, video keyframe thumbnails, `.ithmb`/`Glide` cache images, `SplashBoard`/`TaskSnapshots`, unmasked vault images, and rendered PDF pages):

1. **Pass 1 (Fast Native Grayscale Scan):** Convert image to 8-bit luminance grayscale ($Y = 0.299R + 0.587G + 0.114B$) and scan for 2D/1D symbologies (`QR Code`, `Micro QR`, `Aztec`, `DataMatrix`, `PDF417`, `Code-128`).
2. **Pass 2 (Dark-Mode Bitwise Luminance Inversion):** If Pass 1 finds no barcode, invert luminance ($Y_{\text{inv}} = 255 - Y$) and scan—recovering white-on-black dark-mode QR codes from `Telegram`, `MetaMask`, `Phantom`, `Session`, and `X`!
3. **Pass 3 (Local Adaptive Sauvola / Gaussian Binarization & CLAHE):** Apply Contrast Limited Adaptive Histogram Equalization (`CLAHE`) + local adaptive thresholding ($31 \times 31$ window) to defeat uneven lighting, shadows, and glossy plastic reflection on physical shop QR standees.
4. **Pass 4 (Finder-Pattern Contour Homography Dewarping & $2\times$ Super-Resolution Upscaling):** For low-resolution `.ithmb` thumbnails ($< 250 \times 250\text{ px}$) or perspective-skewed camera photos, apply bicubic/lanczos $2\times$ upscaling and 4-point perspective homography rectification before scanning.

### 3.2 Master Classification Table of 10 Forensic QR / Barcode Payload Types

Once a raw string or byte payload is decoded from a QR code or 2D barcode, classify it deterministically using this 10-category routing table:

| Payload Category Code | Signature / Prefix Pattern | Extracted Fields & Target Cross-Phase Destination |
|---|---|---|
| **1. `UIDAI_AADHAAR_SECURE_QR`** | Base-10 numeric string (`^[0-9]{500,3500}$`) OR legacy XML `<PrintLetterBarcodeData` / `<QPDB` | Route to **Sub-Engine 7.3B (Section 4)** to unpack `BigInt` $\rightarrow$ `Gzip` $\rightarrow$ Name, DOB, Address, Last-4 Aadhaar, Mobile/Email Hash, `.jp2` Photo & RSA Signature! |
| **2. `NPCI_UPI_PAYMENT_QR`** | Starts with `upi://pay?` or `upi://mandate?` or `bhim://` (Case-Insensitive) | Route to **Section 5.1 & Phase 3 (Module 3.1E)**: Extract `pa` (Payee VPA), `pn` (Merchant/Payee Name), `mc` (MCC), `am` (Amount), `tr`, `orgid`, `mode`, and `sign` (ECDSA signature). |
| **3. `EMVCO_BHARATQR_MERCHANT`** | Starts with `000201` or `000202` (EMVCo Merchant-Presented QR TLV stream) | Route to **Section 5.2**: Unpack `[2-digit Tag][2-digit Length][Value]` TLV tree (`Tag 26–51` Merchant VPA/Account/IFSC, `Tag 52` MCC, `Tag 59` Merchant Name, `Tag 60` City, `Tag 61` PIN Code, `Tag 63` CRC-16). |
| **4. `CRYPTO_WALLET_URI_OR_ADDRESS`** | Starts with `bitcoin:`, `ethereum:`, `tron:`, `solana:`, `monero:` OR passes **Module 4.3 Checksum Validators** (`T...`, `0x...`, `bc1q...`, `4...`/`8...`, `EQ...`) | Route to **Phase 4 (Module 4.3 & 4.4)**: Extract blockchain, canonical wallet address, requested token `amount`, and `contractAddress` (`uint256`), and cross-link to the image's sender/chat! |
| **5. `WALLETCONNECT_PAIRING_QR`** | Starts with `wc:` (`wc:<topic>@2?relay-protocol=irn&symKey=...`) | Route to **Phase 4 (Module 4.3C)**: Extract 64-hex `topic` and `symKey` and match against `wc@2:core:0.3//pairing` to prove which DApp QR the suspect scanned! |
| **6. `GSMA_ESIM_ACTIVATION_QR`** | Starts with `LPA:1$` | **Unmasks Burner eSIM Provisioning!** Split on `$` to extract:<br>• Field 1: `SM-DP+ Carrier Server FQDN` (e.g., `rsp.truphone.com`, `smdp.io`)<br>• Field 2: `Activation Matching ID / Token`<br>• Field 3: `OID / Confirmation Code Flag`<br>Cross-link to **Phase 3, Module 3.2 (`device_sim_card_history_ledger`)**! |
| **7. `MESSENGER_COMPANION_OR_OPSEC_INVITE_QR`** | • WhatsApp Web (`1@...` or `2@...` comma-separated Base64 server ref + curve25519 pubkey)<br>• Telegram (`tg://login?token=...`)<br>• Signal (`sgnl://linkdevice?...`)<br>• SimpleX (`https://simplex.chat/contact#...`)<br>• Session (`^05[0-9a-fA-F]{64}$`) | Route to **Phase 5 (Modules 5.1D, 5.2, 5.3)**: Proves the suspect photographed or received a QR code to link a remote computer (`WhatsApp Web` / `Telegram Desktop`) or connect to a covert `SimpleX` / `Session` contact! |
| **8. `WIFI_CREDENTIALS_SHARE_QR`** | Starts with `WIFI:` (`WIFI:S:<SSID>;T:<WEP\|WPA\|nopass>;P:<Password>;H:<true\|false>;;`) | Extract shared Wi-Fi `SSID`, encryption type `T`, and **plaintext Wi-Fi password `P`**, and cross-link to **Module 6.3 (`wifi_hotspot_and_bluetooth_connections_ledger`)**! |
| **9. `IATA_BOARDING_PASS_BCBP_OR_IRCTC_QR`** | Starts with `M1` / `M2` (PDF417 / Aztec / QR boarding pass) | Route to **Phase 6, Module 6.4C**: Unpack Passenger Name, 6-char Airline PNR, Origin/Destination Airport IATA codes, Flight Number, Date, and Seat! |
| **10. `DIGILOCKER_OR_GOVT_JWT_QR`** | Contains signed JSON / JWT / URL from `digilocker.gov.in`, `parivahan.gov.in`, `incometax.gov.in` (e-PAN QR), or `cowin.gov.in` | Unpack signed Government of India credential payload (extracting verified Name, PAN, DOB, Father's Name, or Vehicle Registration/DL details). |

---

## 4. Step 2 — Sub-Engine 7.3B: The UIDAI Aadhaar Secure QR Code (`BigInt` + `Gzip` + `.jp2` Biometric Photo) Mathematical Unpacker

When a QR code on an Aadhaar card image or `e-Aadhaar` PDF decodes to a base-10 numeric string $S_{\text{dec}}$ of $500\text{ to }3,500\text{ digits}$ (`^[0-9]{500,3500}$`), Sub-Engine 7.3B executes the **5-Stage UIDAI Secure QR Unpacking & Cryptographic Verification Pipeline**:

### 4.1 Stage 1: Base-10 `BigInt` to Decompressed Byte Stream (`decompressed_bytes`)

1. Parse the base-10 numeric string $S_{\text{dec}}$ into an arbitrary-precision unsigned integer $N_{\text{big}} = \text{BigInt}(S_{\text{dec}})$.
2. Convert $N_{\text{big}}$ into a Big-Endian byte array `compressed_bytes` of length $\left\lceil \frac{\text{bit\_length}(N_{\text{big}})}{8} \right\rceil$.
3. **Verify Gzip Header & Decompress:**
   * Inspect Bytes $0\text{–}2$ of `compressed_bytes`: they **must equal `1F 8B 08` (Standard Gzip `DEFLATE` magic header)**!
   * Decompress `compressed_bytes` using standard `Gzip` / `zlib` (`wbits = 16 + MAX_WBITS`) to obtain the raw binary buffer **`decompressed_bytes`** of total length $L_{\text{total}} = \text{len}(\text{decompressed\_bytes})$.

### 4.2 Stage 2: Walking the `0xFF`-Delimited Demographic Fields (`ISO-8859-1` / `UTF-8`)

Inside `decompressed_bytes`, all demographic text fields are separated by the single byte delimiter **`0xFF` ($255$ in decimal)**.

Walk `decompressed_bytes` from Byte Offset $0$, splitting on `0xFF` to extract the sequential text fields in this exact deterministic order:

* **Note on Version Shift (`"V2"` vs. `"V3"`/`"V4"`):**
  * Inspect the very first slice `field[0]` before the first `0xFF` byte:
    * **If `field[0]` is `"V2"`, `"V3"`, `"V4"`, or `"V5"`:** Set index offset $k = 1$ (modern Secure QR with version prefix).
    * **If `field[0]` is a single digit `"0"`, `"1"`, `"2"`, or `"3"`:** Set index offset $k = 0$ (Secure QR without version prefix, where `field[0]` is the Email/Mobile Indicator directly!).

| Field Sequence Index (with offset $k \in \{0, 1\}$) | UIDAI Field Name | Forensic Meaning & Exact Format |
|---|---|---|
| **Field $0$ (if $k == 1$)** | `version_str` | `"V2"`, `"V3"`, etc. |
| **Field $k + 0$** | **`email_mobile_indicator`** | Integer string (`"0"`, `"1"`, `"2"`, or `"3"`):<br>• **`"0"`**: Neither Email nor Mobile hash is present.<br>• **`"1"`**: **Email SHA-256 Hash ($32\text{ bytes}$) is present!**<br>• **`"2"`**: **Mobile SHA-256 Hash ($32\text{ bytes}$) is present!**<br>• **`"3"`**: **Both Email ($32\text{ bytes}$) AND Mobile ($32\text{ bytes}$) SHA-256 Hashes are present!** |
| **Field $k + 1$** | **`reference_id`** | **Last 4 Digits of the Cardholder's Aadhaar Number** (`reference_id[0:4]`, e.g., `"4821"`) followed by the **Exact Timestamp (`YYYYMMDDHHMMSSfff`) when the Aadhaar QR was generated by UIDAI**! |
| **Field $k + 2$** | **`full_name`** | Cardholder's Official UIDAI Registered Name (e.g., `"Rahul Kumar Sharma"`). |
| **Field $k + 3$** | **`date_of_birth`** | Official Date of Birth (`DD-MM-YYYY` or `DD/MM/YYYY` or `YYYY`). |
| **Field $k + 4$** | **`gender`** | `"M"`, `"F"`, or `"T"`. |
| **Field $k + 5$** | **`care_of`** | Father's / Husband's / Guardian's Name (`"S/O: ..."` or `"W/O: ..."`). |
| **Field $k + 6$** | **`district`** | District Name (e.g., `"Varanasi"`). |
| **Field $k + 7$** | **`landmark`** | Address Landmark. |
| **Field $k + 8$** | **`house_building`** | House / Flat / Building Number. |
| **Field $k + 9$** | **`location_locality`** | Locality / Sector. |
| **Field $k + 10$** | **`pincode`** | **6-Digit Indian PIN Code** (e.g., `"221002"`). |
| **Field $k + 11$** | **`post_office`** | Post Office Name. |
| **Field $k + 12$** | **`state`** | State Name (e.g., `"Uttar Pradesh"`). |
| **Field $k + 13$** | **`street`** | Street / Road Name. |
| **Field $k + 14$** | **`sub_district`** | Sub-District / Tehsil. |
| **Field $k + 15$** | **`vtc`** | Village / Town / City Name. |

Let `photo_start_offset` be the byte offset immediately following the `0xFF` delimiter that terminates **Field $k + 15$ (`vtc`)**!

### 4.3 Stage 3: Slicing the Trailing Binary Tail (256-Byte RSA Signature, Mobile/Email Hashes & `.jp2` Biometric Photo!)

From the end of `decompressed_bytes` (length $L_{\text{total}}$) working **backward** toward `photo_start_offset`:

1. **The Last 256 Bytes (`decompressed_bytes[L_total - 256 : L_total]`):**
   * This 256-byte slice is **UIDAI's 2048-bit RSA-SHA256 Digital Signature** computed over `decompressed_bytes[0 : L_total - 256]`!
2. **The Preceding 32-Byte Mobile & Email SHA-256 Hashes (Controlled by `email_mobile_indicator`):**
   * **If `email_mobile_indicator == "3"` (Both Email and Mobile Present):**
     * `mobile_sha256_hash` ($32\text{ bytes}$) $= \text{decompressed\_bytes}[L_{\text{total}} - 256 - 32 : L_{\text{total}} - 256]$
     * `email_sha256_hash` ($32\text{ bytes}$) $= \text{decompressed\_bytes}[L_{\text{total}} - 256 - 64 : L_{\text{total}} - 256 - 32]$
     * Set `photo_end_offset` $= L_{\text{total}} - 256 - 64$.
   * **If `email_mobile_indicator == "2"` (Only Mobile Present):**
     * `mobile_sha256_hash` ($32\text{ bytes}$) $= \text{decompressed\_bytes}[L_{\text{total}} - 256 - 32 : L_{\text{total}} - 256]$
     * Set `photo_end_offset` $= L_{\text{total}} - 256 - 32$.
   * **If `email_mobile_indicator == "1"` (Only Email Present):**
     * `email_sha256_hash` ($32\text{ bytes}$) $= \text{decompressed\_bytes}[L_{\text{total}} - 256 - 32 : L_{\text{total}} - 256]$
     * Set `photo_end_offset` $= L_{\text{total}} - 256 - 32$.
   * **If `email_mobile_indicator == "0"` (Neither Present):**
     * Set `photo_end_offset` $= L_{\text{total}} - 256$.
3. **The Embedded UIDAI Biometric Facial Photograph (`decompressed_bytes[photo_start_offset : photo_end_offset]`):**
   * The exact binary slice `jp2_bytes = decompressed_bytes[photo_start_offset : photo_end_offset]` is a **JPEG-2000 (`.jp2` container starting with `00 00 00 0C 6A 50 20 20` or `.j2k` codestream starting with `FF 4F FF 51`) photograph of the Aadhaar cardholder's face**!
   * Save `jp2_bytes` (and decode it into a viewable `.png` derivative in the staging workspace!) so the investigator can visually and biometrically compare the **authentic UIDAI-signed face inside the QR code** against the **face printed on the physical Aadhaar card**!

### 4.4 Stage 4: The UIDAI Iterative `SHA-256` Mobile Number & Email Unmasker

How does your software prove which 10-digit phone number (or email address) on the seized phone matches `mobile_sha256_hash` (or `email_sha256_hash`) inside the Aadhaar QR code?

1. **Determine the UIDAI Hash Iteration Count $N_{\text{iter}}$ from `reference_id`:**
   * Read the **4th character** (`reference_id[3]`, which is the 4th digit of the 4-digit Aadhaar tail, i.e., the **12th and final digit of the person's Aadhaar number**!).
   * Convert that character to an integer $d_4 = \text{int}(\text{reference\_id}[3])$.
   * **UIDAIZero-Digit Rule:** If $d_4 == 0$, set $N_{\text{iter}} = \mathbf{1}$. Otherwise, set $N_{\text{iter}} = \mathbf{d_4} \in \{1, 2, 3, 4, 5, 6, 7, 8, 9\}$.
2. **Test Every Candidate 10-Digit Mobile Number $M_{10}$ (e.g., `"9876543210"`) Discovered on the Device:**
   * Start with the ASCII string $h = M_{10}$.
   * Repeat $N_{\text{iter}}$ times ($i = 1 \dots N_{\text{iter}}$):
     * Compute the SHA-256 digest of the ASCII string $h$, and convert the digest to a **64-character lowercase hexadecimal ASCII string**:
       $$h = \text{ lowercase\_hex}\big(\text{SHA256}(\text{ASCII}(h))\big)$$
   * After $N_{\text{iter}}$ iterations, compare the 32-byte binary value of $h$ against `mobile_sha256_hash`:
     * **If they match:** You have **mathematically proven ($100\%$ certainty)** that the 10-digit mobile number $M_{10}$ is the official UIDAI-registered mobile number of that Aadhaar cardholder!

---

## 5. Step 3 — Sub-Engine 7.3C: Indian NPCI `upi://pay` & `BharatQR` (`EMVCo TLV`) Merchant Unpacker

1. **For `upi://pay?...` QR Strings:**
   * Parse URL query parameters via **Phase 3, Module 3.1E**:
     * `pa` (Payee VPA, e.g., `merchant99@ybl` — resolve PSP & bank via Module 3.5B!), `pn` (Payee Name), `mc` (4-digit Merchant Category Code), `tr` / `tid`, `am` (Amount), `cu` (`INR`), `orgid`, `mode` (`02` = Static QR, `15` = Dynamic BharatQR, `22` = Mandate), and `sign` (Base64 ECDSA signature).
2. **For `BharatQR` (`000201...` EMVCo Merchant-Presented TLV Streams):**
   * Walk sequential `[2-char ASCII Tag][2-char ASCII Length][Length-char Value]` records:
     * **Tag `26`, `27`, `28` (NPCI UPI Merchant Account Information):** Recursively unpack nested sub-tags `00` (`A000000524` = NPCI AID), `01` (**Merchant UPI VPA** `pa`!), `02` (Minimum Amount / Reference).
     * **Tag `02`–`25` & `29`–`51`:** Extracts **Visa / MasterCard / RuPay Merchant PAN**, **Bank Account Number**, and **11-Character IFSC Code** embedded inside a BharatQR standee!
     * **Tag `52`:** 4-digit Merchant Category Code (`MCC`).
     * **Tag `59`:** Merchant Legal/Trade Name.
     * **Tag `60` & `61`:** Merchant City and **6-Digit PIN Code**!
     * **Tag `63`:** 4-hex-character `CRC16-CCITT` (`0xFFFF` init) checksum—verify the CRC-16 to confirm the BharatQR string is intact!

---

## 6. Step 4 — Sub-Engine 7.3D: The 5-Point Forged UPI & Bank Payment Screenshot Detector

Whenever an image is classified as a **UPI or Bank Payment Receipt Screenshot** (by containing keywords like `"Paid to"`, `"Payment Successful"`, `"Transaction ID"`, `"UTR"`, `"UPI Ref"`, `"Debited from"`, or `"Google Pay"` / `"PhonePe"` / `"Paytm"` in Module 7.4's OCR text), Sub-Engine 7.3D runs five mathematical authenticity checks:

### 6.1 Check 1: Container & Generator APK Provenance Check (Module 7.1 Integration)
* Inspect the image's `provenance_classification`, `originating_app_bundle_or_pkg` (`owner_package_name`), and `EXIF Software` from Module 7.1:
  * If `EXIF Software` or `owner_package_name` matches an image editor (`PicsArt`, `Canva`, `Photoshop`, `PixelLab`, `Image Editor`) or a spoof generator APK, OR if the image claims to be a screenshot taken on the seized phone (`OS_SCREENSHOT`) but its pixel dimensions $(W \times H)$ do **not** match the seized phone's physical display resolution, flag **`FORGED_RECEIPT_CONTAINER_OR_RESOLUTION_ANOMALY`**!

### 6.2 Check 2: The NPCI 12-Digit `UTR` `YDDD` Julian Date vs. Displayed Receipt Date Check
1. From the screenshot's OCR text (Module 7.4), extract:
   * The **12-Digit numeric UPI / IMPS `UTR` / `RRN`** ($d_1 d_2 d_3 d_4 \dots d_{12}$).
   * The **Displayed Transaction Date & Time** printed on the receipt (e.g., `"05 Nov 2026, 02:35 PM"`).
2. Convert the displayed receipt date $(Y_{\text{disp}}, M_{\text{disp}}, D_{\text{disp}})$ into its **Expected 3-Digit Julian Day of the Year ($J_{\text{disp}} \in [1, 366]$)** and last digit of year ($y_{\text{disp}} = Y_{\text{disp}} \bmod 10$).
3. Compare against `Digit 1` ($y_{\text{utr}} = d_1$) and `Digits 2–4` ($J_{\text{utr}} = \text{int}(d_2 d_3 d_4)$) of the 12-digit `UTR`:
   * **If $y_{\text{utr}} \neq y_{\text{disp}}$ OR $|J_{\text{utr}} - J_{\text{disp}}| > 1$ (for standard `YDDD`-formatted UPI/IMPS switches):**
     * Emit a **`CRITICAL` Alert (`FORGED_RECEIPT_UTR_JULIAN_DATE_MISMATCH`)**—proving that the date or the 12-digit UTR printed on the screenshot was fabricated or altered!

### 6.3 Check 3: Local Device Phase 3 Ledger Cross-Verification (For Locally Captured Screenshots)
* If the payment screenshot has `provenance_classification == "OS_SCREENSHOT_OR_SCREEN_RECORDING"` (meaning the screenshot was physically captured on the **seized phone's own screen** at timestamp $t_{\text{shot}}$):
  * Query **Phase 3 (`unified_financial_transactions_ledger` & `dlt_financial_sms_ledger`)** for the extracted 12-digit `UTR` (or any transaction of that exact Rupee amount within $[t_{\text{shot}} - 24\text{ hours}, \ t_{\text{shot}} + 10\text{ minutes}]$).
  * If the screenshot shows a `"Payment Successful"` screen for `PhonePe` or `Google Pay` captured on this phone, **yet this phone's own `PhonePe`/`Google Pay` database (`Layer 1`) and `mmssms.db` (`Layer 2`) contain zero record of that transaction** (and no database wiping gap was detected in Module 6.5C):
    * Flag **`CRITICAL: LOCAL_SCREENSHOT_ABSENT_FROM_APP_AND_BANK_SMS_LEDGER`** (proving the screenshot was generated inside a Fake Receipt Prank App or HTML template on the screen!).

### 6.4 Check 4: Duplicate `UTR` Reuse Across Multiple Receipts With Altered Amounts
* Index every 12-digit `UTR` extracted from all screenshots across the device.
* If two or more screenshots share the **exact same 12-digit `UTR`**, **but** their OCR-extracted **Rupee Amount (`₹`)**, **Payee Name**, or **Payee VPA** differ:
  * Flag **`CRITICAL: DUPLICATE_UTR_WITH_ALTERED_AMOUNT_OR_PAYEE`** (proving one receipt is a template-edited forgery of the other!).

### 6.5 Check 5: VPA Handle & IFSC Structural Validation
* Pass any VPA (`<user>@<handle>`) or 11-character IFSC code printed on the screenshot through **Module 3.5B (VPA Handle Dictionary)** and **Module 3.3 Section 8.2 (IFSC Validator)**. If a screenshot displays a non-existent VPA handle (e.g., `@okphonepe` or `@yblbank`—typos commonly made by manual receipt fakers!), flag **`INVALID_FABRICATED_VPA_OR_IFSC_ON_RECEIPT`**.

---

## 7. Database Schema for Module 7.3 (`qr_aadhaar_and_forged_receipt_engine.sqlite`)

The developer must create the following three tables in the case database:

### Table 1: `decoded_barcodes_and_qr_master_ledger` (All 1D/2D Barcodes & QR Codes Across Images, Snapshots, Thumbnails & PDFs)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `barcode_uid` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Unique row ID. |
| `source_vfs_file_id` | `INTEGER` | `NOT NULL` | Foreign key to source image, `.ithmb`, snapshot, or PDF in `vfs_index`. |
| `source_visual_layer` | `TEXT` | `NOT NULL` | Enum: `CAMERA_OR_GALLERY_IMAGE`, `MESSENGER_MEDIA_IMAGE`, `APP_SWITCHER_SNAPSHOT`, `RECONSTRUCTED_THUMBNAIL_OR_CACHE`, `UNMASKED_VAULT_FILE`, `PDF_DOCUMENT_PAGE`. |
| `symbology_type` | `TEXT` | `NOT NULL` | `QR_CODE`, `AZTEC`, `PDF417`, `DATAMATRIX`, `CODE_128`. |
| `preprocessing_pass_used` | `TEXT` | `NOT NULL` | `PASS1_NATIVE`, `PASS2_DARKMODE_INVERTED`, `PASS3_ADAPTIVE_GLARE`, `PASS4_DEWARP_UPSCALED`. |
| `payload_category` | `TEXT` | `NOT NULL` | 10-Category Enum from Section 3.2 (`UIDAI_AADHAAR_SECURE_QR`, `NPCI_UPI_PAYMENT_QR`, `EMVCO_BHARATQR_MERCHANT`, `CRYPTO_WALLET_URI_OR_ADDRESS`, `GSMA_ESIM_ACTIVATION_QR`, etc.). |
| `raw_decoded_text` | `TEXT` | `NOT NULL` | Verbatim decoded string from the barcode/QR code. |
| `structured_unpacked_json` | `TEXT` | `Not NULL` | Unpacked key-value JSON (`pa`, `pn`, `mc` for UPI; `SM-DP+` server for eSIM; `SSID`+`Password` for Wi-Fi; `T...`/`0x...` for Crypto). |
| `linked_phase3_or_phase4_id` | `TEXT` | `NULL` | Cross-link ID to Phase 3 VPA Directory, Phase 4 Crypto Index, or Phase 5 Companion Audit. |
| `image_created_utc_iso` | `TEXT` | `NULL` | Timestamp of the containing image/snapshot. |
| `recovery_classification` | `TEXT` | `NOT NULL` | 6-State Enum (`ORIGINAL_RECORD`, `HISTORICAL_COMMITTED_RECORD`, `RESIDUAL_RECORD`). |

### Table 2: `uidai_aadhaar_secure_qr_unpacked_ledger` (Decoded `BigInt` + `Gzip` Demographics, `.jp2` Biometric Photo & Forgery Check)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `aadhaar_qr_uid` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Unique row ID. |
| `barcode_uid` | `INTEGER` | `NOT NULL` | Foreign key to `decoded_barcodes_and_qr_master_ledger.barcode_uid`. |
| `source_vfs_file_id` | `INTEGER` | `NOT NULL` | Source Aadhaar card image or PDF in `vfs_index`. |
| `qr_format_version` | `TEXT` | `NOT NULL` | `"SECURE_QR_V2_V3_BIGINT_GZIP"` or `"LEGACY_XML_BARCODE"`. |
| `aadhaar_last_4_digits` | `TEXT` | `NOT NULL` | First 4 digits of `reference_id` (e.g., `"4821"`). Indexed! |
| `qr_generation_timestamp_str` | `TEXT` | `NULL` | Timestamp embedded inside `reference_id[4:]` (`YYYY-MM-DD HH:MM:SS`). |
| `signed_full_name` | `TEXT` | `NOT NULL` | Official UIDAI-signed Name unpacked from the QR code! |
| `signed_dob_and_gender` | `TEXT` | `NOT NULL` | E.g., `"15-08-1995 (M)"`. |
| `signed_care_of_guardian` | `TEXT` | `NULL` | Father's / Husband's Name (`S/O`, `W/O`, `C/O`). |
| `signed_full_address_and_pin` | `TEXT` | `NOT NULL` | Complete unpacked House, Street, Landmark, VTC, District, State, and 6-digit PIN Code. |
| `extracted_jp2_photo_staging_id` | `INTEGER` | `NULL` | **Foreign key to `derivative_staging_ledger.staging_id` holding the unpacked UIDAI `.jp2` / `.png` Biometric Facial Photograph!** |
| `unmasked_registered_mobile` | `TEXT` | `NULL` | **10-digit mobile number on the device that matched the QR's Iterative `SHA-256` `mobile_sha256_hash` (Section 4.4)!** |
| `unmasked_registered_email` | `TEXT` | `NULL` | Email address on the device that matched `email_sha256_hash`! |
| `rsa_2048_signature_hex` | `TEXT` | `NULL` | 256-byte (512-hex-char) UIDAI RSA digital signature. |
| `visual_vs_qr_tamper_status` | `TEXT` | `NOT NULL` | **`AUTHENTIC_MATCH`** vs. **`CRITICAL: PHOTOSHOPPED_AADHAAR_CARD_DETECTED (Printed Name/DOB/Last-4 differs from signed QR payload!)`**. |

### Table 3: `payment_receipt_screenshots_authenticity_audit` (5-Point Forged UPI/Bank Receipt Audit Ledger)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `receipt_audit_uid` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Unique row ID. |
| `source_vfs_file_id` | `INTEGER` | `NOT NULL` | Foreign key to the payment screenshot image in `vfs_index`. |
| `claimed_payment_app` | `TEXT` | `Not NULL` | E.g., `"PhonePe"`, `"Google Pay"`, `"Paytm"`, `"BHIM"`, `"SBI YONO"`, `"Binance P2P"`. |
| `ocr_extracted_utr_12_digit` | `TEXT` | `NULL` | 12-digit UPI/IMPS `UTR` / `RRN` printed on the screenshot. Indexed! |
| `ocr_extracted_amount_inr` | `REAL` | `NULL` | Rupee amount (`₹`) printed on the screenshot. |
| `ocr_extracted_payee_and_vpa` | `TEXT` | `NULL` | Payee Name and VPA (`@ybl`, `@okaxis`) printed on the screenshot. |
| `ocr_displayed_date_str` | `TEXT` | `NULL` | Date and time printed on the receipt UI. |
| `utr_yddd_julian_check_status` | `TEXT` | `NOT NULL` | `VALID_YDDD_DATE_MATCH` vs. **`FORGED_UTR_JULIAN_DATE_MISMATCH`** (Section 6.2). |
| `phase3_corroboration_status` | `TEXT` | `NOT NULL` | `CORROBORATED_IN_PHASE3_LEDGER` vs. `UNCORROBORATED_EXTERNAL_SCREENSHOT` vs. **`CRITICAL_LOCAL_SCREENSHOT_MISSING_FROM_LEDGER`**. |
| `is_forged_receipt_flagged` | `INTEGER` | `DEFAULT 0` | **`1` if any of the 5 Forgery Checks in Section 6 triggered!** |
| `forgery_proof_reasons_json` | `TEXT` | `NULL` | Detailed JSON explanation of why the screenshot is mathematically proven to be forged! |

---

## 8. Developer Acceptance Test Checklist for Module 7.3

1. **The UIDAI Aadhaar Secure QR (`BigInt` $\rightarrow$ `Gzip` $\rightarrow$ `0xFF` Fields + `.jp2` Photo + Iterative SHA-256 Mobile) Test:**
   * Construct a test Aadhaar Secure QR payload containing `V2\xff2\xff482120261105143000000\xffRAHUL SHARMA\xff15-08-1995\xffM\xff...` (where the 4th digit of `reference_id` is `'1'`, `mobile_sha256_hash` is $\text{SHA256}(\texttt{"9876543210"})$ iterated $1\text{ time}$, followed by a mock `.jp2` image `00 00 00 0C 6A 50 20 20...` and a 256-byte signature), compress with `Gzip`, convert the bytes to a base-10 `BigInt` string, and encode into a QR code image.
   * Verify that Sub-Engine 7.3B decodes the base-10 string, inflates the Gzip stream, extracts `"RAHUL SHARMA"` and `"4821"`, carves the `.jp2` facial photo into `derivative_staging_ledger`, and matches `"9876543210"` against `mobile_sha256_hash`!
2. **The Photoshopped Aadhaar Card Tamper Detection Test:**
   * Take the Aadhaar image from Test 1 (whose signed QR code says `"RAHUL SHARMA"` and last-4 digits `"4821"`), but place printed text `"AMIT KUMAR"` and `"9988"` on the card face (read by Module 7.4 OCR).
   * Verify that Sub-Engine 7.3B sets `visual_vs_qr_tamper_status = "CRITICAL: PHOTOSHOPPED_AADHAAR_CARD_DETECTED"`!
3. **The Forged UPI Receipt `YDDD` Julian Date Mismatch & Duplicate `UTR` Test:**
   * Feed a payment screenshot displaying `"Paid ₹75,000 on 05 Nov 2026"` with `"UPI transaction ID: 412014829104"` (where `4120` = Year 2024, Day 120, contradicting Nov 5, 2026 = `6309`!).
   * Verify that Sub-Engine 7.3D flags `is_forged_receipt_flagged = 1` with `utr_yddd_julian_check_status = "FORGED_UTR_JULIAN_DATE_MISMATCH"`.
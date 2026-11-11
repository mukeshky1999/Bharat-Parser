# Engineering Specification: Phase 4, Module 4.4 — Cross-System `BIP-39` Seed Phrase Hunter, `BIP-32/44/84` HD Public Address Derivation, Web3 Vault Unwrapper & The Phase 3 $\leftrightarrow$ Phase 4 Rupee-to-USDT Money Laundering Correlator

**Document Purpose:** This document provides the complete, step-by-step architectural blueprint for building **Module 4.4** of the Forensic Data Parser (completing **Phase 4** and bridging **Groups 1, 4, 5, 6, 12, 13, and 15** of the Unified Master Register). It contains **zero programming code** and explains how to mathematically validate 12/15/18/21/24-word **`BIP-39` Mnemonic Seed Phrases**, **25-word `Monero` seeds**, and **`WIF` / 64-hex Private Keys** across the entire device, how to deterministically derive **`TRON` (`T...`), `Ethereum/BSC` (`0x...`), `Bitcoin` (`bc1q...`/`1...`), and `Solana`** public addresses directly from any recovered seed phrase using **`BIP-32`/`BIP-44`/`SLIP-0010`**, how to unwrap encrypted Web3 Keystore / MetaMask vaults, and how to fuse **Phase 3 (Indian UPI & Banking)** with **Phase 4 (CEX P2P & Self-Custody Crypto)** into a single end-to-end money laundering chain.

---

## 1. Purpose & Mental Model (Why Seed Derivation & Cross-Phase Correlation Are the Crown Jewels of Financial Forensics)

In a real-world cryptocurrency or cyber-fraud raid, two scenarios happen constantly:

1. **Scenario A — The Suspect Uninstalled the Wallet Apps, Leaving Only a 12-Word Phrase in a Note or Screenshot:**
   * Before police seize the phone, the suspect uninstalls `TronLink Pro`, `MetaMask`, and `Trust Wallet`. Standard forensic tools report `"0 Crypto Wallets Found"`.
   * However, six months earlier, the suspect wrote their **12-word `BIP-39` recovery phrase** in an Apple Note (`NoteStore.sqlite`), a Google Keep note (`keep.db`), a Telegram `"Saved Messages"` chat, an iOS Dynamic Keyboard cache (`dynamic-text.dat`), or took a screenshot of the seed phrase (`Phase 7 OCR`).
   * Even when an examiner finds those 12 words, **a 12-word phrase by itself does not tell the police what the wallet's `T...` (TRON) or `0x...` (Ethereum/BSC) public address is**—so the police cannot check the blockchain balance or serve a Tether (`USDT`) freeze request!
   * **Module 4.4 solves this automatically:** The instant Sub-Engine 4.4A validates a 12/24-word `BIP-39` seed phrase (or unwraps a wallet vault via Sub-Engine 4.4C), **Sub-Engine 4.4B executes offline `BIP-32 / BIP-44 / BIP-84 / SLIP-0010` Hierarchical Deterministic (`HD`) key derivation** and outputs the exact `T...` (TRON), `0x...` (EVM), `bc1q...` (Bitcoin), and `Solana` public wallet addresses controlled by those 12 words!
2. **Scenario B — Connecting the Indian Bank/UPI Trail (Phase 3) to the Blockchain Trail (Phase 4):**
   * Prosecutors in Indian courts must prove the complete **Proceeds of Crime (`PoC`)** trail under the Prevention of Money Laundering Act (`PMLA`) and Bharatiya Nyaya Sanhita (`BNS`): showing how ₹10,00,000 stolen from a victim in Phase 3 was split across three UPI/IMPS transfers (`Smurfing`), paid to a Binance/Bybit P2P seller, released as `11,100 USDT`, withdrawn over `TRC-20` to a local `TronLink Pro` wallet, and swapped via `FixedFloat` into `Monero (XMR)` or forwarded to an overseas syndicate wallet. **Sub-Engine 4.4D automates this 4-Hop Laundering Chain reconstruction.**

---

## 2. The 6 Fatal Mistakes Beginner Developers Make in Seed Recovery, HD Derivation & Laundering Correlation

Before implementing Module 4.4, the developer must understand six critical traps:

### Mistake 1: Failing to Normalize Unicode (`NFKD`) and 4-Letter BIP-39 Prefixes Before Validating Seed Phrases
* **The Trap:** Splitting text on spaces and rejecting a candidate 12-word phrase if one word has a capital letter, a trailing comma, or an OCR typo on the 6th letter (e.g., `"abandoo"` instead of `"abandon"`).
* **Why It Fails:**
  1. The official `BIP-39` specification mandates **UTF-8 `NFKD` normalization** and lowercase conversion.
  2. Even more importantly, **the `BIP-39` 2,048-word English wordlist was mathematically designed so that the first 4 letters of every single word are 100% unique across all 2,048 words!** (That is why physical hardware seed plates like *Cryptosteel* only store the first 4 letters of each word, e.g., `ABAN ABIL ABLE ABOU...`).
* **The Rule:** When scanning OCR text, notes, or keyboard caches, if a word is 4 letters long (from a *Cryptosteel* plate) or has a minor OCR typo after the 4th character, match its **4-letter prefix** against the 2,048-word BIP-39 dictionary and test the resulting 11-bit sequence against the **mandatory SHA-256 checksum** (Section 3.1)!

### Mistake 2: Forgetting That a `BIP-39` Seed Phrase Can Have an Optional 13th/25th Word (`BIP-39 Passphrase`)
* **The Trap:** Hardcoding the `PBKDF2-HMAC-SHA512` salt in `BIP-39` seed generation as the fixed ASCII string `"mnemonic"`.
* **Why It Fails:** In `BIP-39`, the salt for `PBKDF2-HMAC-SHA512` is `"mnemonic" + passphrase` (where `passphrase` is `""` \[empty string\] by default, OR a custom user-defined **"13th / 25th word passphrase"** if the user enabled passphrase protection!).
* **The Rule:** Always derive the default wallets using `salt = "mnemonic"` (empty passphrase) first, **and** if a 13th/25th word or adjacent password/PIN is found in the same note/chat (or in the Candidate Profile Password Dictionary), also derive the passphrase-protected child addresses using `salt = "mnemonic" + passphrase`!

### Mistake 3: Using `secp256k1` (`BIP-32`) Instead of `SLIP-0010` (`Ed25519`) When Deriving Solana & TON Addresses
* **The Trap:** Using standard Bitcoin `BIP-32` (`secp256k1` elliptic curve with HMAC key `"Bitcoin seed"`) to derive Solana (`m/44'/501'/0'/0'`) or TON (`m/44'/607'/0'`) addresses from a BIP-39 seed.
* **Why It Fails:**
  * **Bitcoin (`0'`), Ethereum/BSC/Polygon (`60'`), and TRON (`195'`)** use the **`secp256k1` curve** under standard **`BIP-32`** (root HMAC key = `"Bitcoin seed"`).
  * **Solana (`501'`) and TON (`607'`)** use the **`Ed25519` curve** under **`SLIP-0010`** (root HMAC key = **`"ed25519 seed"`**, where all child derivation steps **must be hardened** $i \ge 2^{31}$)!
* **The Rule:** Follow the exact curve and root-key specifications in Section 4.2 and Section 4.3.

### Mistake 4: Failing to Strip the `0x04` Uncompressed Prefix Byte Before Hashing Public Keys in Ethereum & TRON
* **The Trap:** Computing `Keccak-256` over all $65\text{ bytes}$ (`0x04` + 32-byte $X$ + 32-byte $Y$) of an uncompressed `secp256k1` public key when deriving an Ethereum (`0x...`) or TRON (`T...`) address.
* **Why It Fails:** In both Ethereum and TRON, you must **strip Byte 0 (`0x04`)** of the 65-byte uncompressed `secp256k1` public key and compute Original `Keccak-256` (`0x01` padding) over **only the 64-byte $(X \parallel Y)$ coordinate bytes**! Then take the **last $20\text{ bytes}$ (Bytes $12\text{–}31$)** of that 32-byte Keccak-256 digest:
  * Prepend `0x` + `EIP-55` for Ethereum/BSC/Polygon!
  * Prepend `0x41` + `Base58Check` for TRON!

### Mistake 5: Missing "Smurfing / Split-UPI" P2P Payments When Correlating Phase 3 to Phase 4
* **The Trap:** Only joining a Phase 4 P2P order (`fiat_total_amount = ₹1,80,000`) to Phase 3 if a single ₹1,80,000 UPI transaction exists in Phase 3.
* **Why It Fails:** Because standard UPI caps a single peer-to-peer transaction at **₹1,00,000** (or a bank imposes a ₹50,000 per-transaction limit), a suspect buying `₹1,80,000` of USDT on Binance P2P will send **two or three separate UPI transfers** (e.g., `₹90,000` + `₹90,000`, or `₹1,00,000` + `₹80,000`) to the P2P seller within a 15-minute window!
* **The Rule:** Sub-Engine 4.4D includes a **Subset-Sum Split-Payment Correlator** (Section 6.2) that automatically groups multiple UPI/IMPS transfers sent to the same counterparty within $\pm 30\text{ minutes}$ of a P2P order whose sum equals `fiat_total_amount`!

### Mistake 6: Using Standard `SHA-256` Instead of `Keccak-256` When Verifying Web3 Keystore JSON Passwords
* **The Trap:** Trying to verify a candidate password against a `TronLink` or `Trust Wallet` Web3 Keystore JSON (`version: 3`) by checking AES-128-CTR padding.
* **Why It Fails:** `AES-128-CTR` is a stream cipher—it has **no padding** and will happily "decrypt" any ciphertext with a wrong password into random garbage bytes without throwing an error! To verify whether a candidate password is correct on a Web3 Secret Storage JSON, you must compute the **Web3 MAC (`Keccak-256` over the second half of the derived key `derivedKey[16 : 32]` concatenated with `ciphertext`)** and compare it against the JSON's `crypto.mac` field (Section 5.2)!

---

## 3. Step 1 — Sub-Engine 4.4A: Cross-System `BIP-39` Seed, `Monero 25-Word` Seed & `WIF`/Hex Private Key Hunter

Sub-Engine 4.4A scans all text-bearing artifacts across the entire extraction—including **Notes** (`NoteStore.sqlite`, `keep.db`, Samsung Notes), **Messaging Self-Chats** (Telegram `"Saved Messages"` `uid == self_user_id`, WhatsApp `"Message Yourself"`), **iOS Dynamic Keyboard Lexicon** (`/private/var/mobile/Library/Keyboard/dynamic-text.dat`), **Android Keyboard & Clipboard Caches** (`trainingcache*.db`, `clipboard.db`), **Browser Autofill / Local Storage**, and **Phase 7 OCR Text** (from screenshots and photos)—for four cryptographic secret formats:

### 3.1 Format 1: `BIP-39` 12, 15, 18, 21 & 24-Word Mnemonic Seed Phrases

Given any sequence of $W \in \{12, 15, 18, 21, 24\}$ whitespace/newline/numbered-list separated tokens (stripping numbering prefixes like `"1."`, `"2)"`, `"#3"` that users or wallet backup screens place before each word!):

1. **Normalize & Map Each Word to Its 11-Bit Index ($0\text{ to }2047$):**
   * Apply Unicode `NFKD` normalization and convert to lowercase ASCII.
   * Look up each word $w_k$ ($k = 1 \dots W$) in the official 2,048-word `BIP-39` English wordlist (or match its unique 4-letter prefix if the user recorded a 4-letter *Cryptosteel* backup). If any word fails lookup, reject the window.
   * Convert each word's integer index $idx_k \in [0, 2047]$ into an 11-bit big-endian binary string and concatenate all $W$ 11-bit strings into a single bit array $B$ of length $11 \times W\text{ bits}$.
2. **Split Entropy Bits ($ENT$) and Checksum Bits ($CS$):**
   * Compute $CS = \frac{W}{3}\text{ bits}$ and $ENT = (11 \times W) - CS = \frac{32 \times W}{3}\text{ bits}$:
     * **$W = 12\text{ words}$ ($132\text{ bits}$):** $ENT = 128\text{ bits}$ ($16\text{ bytes}$), $CS = 4\text{ bits}$.
     * **$W = 15\text{ words}$ ($165\text{ bits}$):** $ENT = 160\text{ bits}$ ($20\text{ bytes}$), $CS = 5\text{ bits}$.
     * **$W = 18\text{ words}$ ($198\text{ bits}$):** $ENT = 192\text{ bits}$ ($24\text{ bytes}$), $CS = 6\text{ bits}$.
     * **$W = 21\text{ words}$ ($231\text{ bits}$):** $ENT = 224\text{ bits}$ ($28\text{ bytes}$), $CS = 7\text{ bits}$.
     * **$W = 24\text{ words}$ ($264\text{ bits}$):** $ENT = 256\text{ bits}$ ($32\text{ bytes}$), $CS = 8\text{ bits}$.
   * Convert the first $ENT\text{ bits}$ of $B$ into an $\left(\frac{ENT}{8}\right)$-byte array `entropy_bytes`.
   * Extract the final $CS\text{ bits}$ of $B$ as the integer `extracted_cs`.
3. **Verify the `SHA-256` Checksum:**
   * Compute $H = \text{SHA256}(\text{entropy\_bytes})$.
   * Extract the top (most significant) $CS\text{ bits}$ of the first byte $H[0]$:
     $$\text{expected\_cs} = H[0] \gg (8 - CS)$$
   * **Verification Condition:** Valid `BIP-39` seed phrase **if and only if** $\text{extracted\_cs} == \text{expected\_cs}$!

### 3.2 Format 2: `Monero (XMR)` 25-Word (`Electrum-Style` 1,626-Word Dictionary) Mnemonic Seeds

Monero (`Cake Wallet` / `Monerujo` / `Feather`) uses a **25-word seed phrase** drawn from a 1,626-word dictionary where the **25th word is a `CRC-32` checksum word**:
1. Check if all 25 words exist in the 1,626-word Monero English dictionary.
2. Take the **first 3 letters (unique prefix)** of each of the first 24 words ($w_1 \dots w_{24}$) and concatenate those 24 three-letter prefixes into a single 72-character ASCII string `prefix_str`!
3. Compute the standard **CRC-32** checksum of `prefix_str` (`crc32_val`), and compute the 0-based index:
   $$\text{checksum\_word\_index} = \text{crc32\_val} \bmod 24$$
4. **Verification Condition:** Valid 25-word Monero seed **if and only if** the 25th word equals the $(\text{checksum\_word\_index} + 1)$-th word of the phrase ($w_{25} == w_{\text{checksum\_word\_index} + 1}$)!

### 3.3 Format 3: Bitcoin / TRON / EVM `WIF` (`Wallet Import Format`) & 64-Hex Private Keys

1. **`WIF` Private Keys ($51$ or $52$ Base58 Characters Starting with `'5'`, `'K'`, or `'L'`):**
   * Decode the Base58 string and verify the 4-byte **Double-SHA256** checksum at the end:
     * **Uncompressed `WIF` ($51\text{ chars}$, starts with `'5'`):** Decodes to $37\text{ bytes}$: Byte $0 == \text{0x80}$, Bytes $1\text{–}32 = \mathbf{32\text{-byte Private Key}}$, Bytes $33\text{–}36 = \text{Checksum}$.
     * **Compressed `WIF` ($52\text{ chars}$, starts with `'K'` or `'L'`):** Decodes to $38\text{ bytes}$: Byte $0 == \text{0x80}$, Bytes $1\text{–}32 = \mathbf{32\text{-byte Private Key}}$, Byte $33 == \mathbf{\text{0x01}}$ (compressed flag!), Bytes $34\text{–}37 = \text{Checksum}$.
2. **Raw 64-Character Hexadecimal Private Keys (`secp256k1`):**
   * When a 64-character hex string (`^[0-9a-fA-F]{64}$`) is found in a wallet keystore, clipboard, note, or chat adjacent to keywords (`private key`, `privkey`, `tron`, `metamask`, `import`, `key`, `0x`, `USDT`), verify that its 256-bit integer value $k$ satisfies $1 \le k < n_{\text{secp256k1}}$ (where $n = \text{0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141}$) and derive its corresponding TRON `T...` and Ethereum `0x...` public addresses (Section 4.3) to check if those addresses match any known transaction on the device!

---

## 4. Step 2 — Sub-Engine 4.4B: Offline `BIP-32` / `BIP-44` / `BIP-84` / `SLIP-0010` Hierarchical Deterministic (`HD`) Public Address Derivation Engine

Whenever Sub-Engine 4.4A (or 4.4C) recovers a valid `BIP-39` mnemonic seed phrase (or raw 32-byte private key), Sub-Engine 4.4B **automatically derives the suspect's public wallet addresses across the top 5 blockchain networks for Account Index $0$ and Address Indices $0, 1, 2, 3, 4$**:

### 4.1 Step 1: Mnemonic Words to 512-Bit (`64-Byte`) Master Seed (`BIP-39`)

Given the UTF-8 NFKD-normalized space-separated mnemonic string `mnemonic_str` and optional passphrase `passphrase_str` (default `""`):
$$\text{Seed}_{64\text{B}} = \text{PBKDF2-HMAC-SHA512}\big(\text{password} = \text{UTF8}(\text{mnemonic\_str}), \ \text{salt} = \text{UTF8}(\texttt{"mnemonic"} \parallel \text{passphrase\_str}), \ \text{iterations} = 2048, \ \text{dkLen} = 64\big)$$

### 4.2 Step 2: Master Node & Child Key Derivation (`BIP-32` for `secp256k1` vs. `SLIP-0010` for `Ed25519`)

1. **For `secp256k1` Chains (`TRON`, `Ethereum/BSC/Polygon`, `Bitcoin`):**
   * Compute Master Node $(k_{\text{master}}, c_{\text{master}})$ using **`HMAC-SHA512`** with key **`"Bitcoin seed"`**:
     $$I = \text{HMAC-SHA512}\big(\text{key} = \texttt{"Bitcoin seed"}, \ \text{msg} = \text{Seed}_{64\text{B}}\big)$$
     $$k_0 = I[0 : 32] \text{ (Master Private Key)}, \qquad c_0 = I[32 : 64] \text{ (Master Chain Code)}$$
   * **Standard `BIP-32` Child Derivation Step `(k_parent, c_parent)` $\rightarrow$ `index`:**
     * If Hardened Child (denoted with apostrophe `'`, where $\text{index} \ge 2^{31}$, i.e., $\text{index} = \text{num} + \text{0x80000000}$):
       $$D = \text{0x00} \parallel k_{\text{parent}} \text{ (32 bytes)} \parallel \text{uint32\_be}(\text{index})$$
     * If Normal (Non-Hardened) Child ($\text{index} < 2^{31}$):
       $$D = \text{ CompressedPubKey}_{33\text{B}}(k_{\text{parent}}) \parallel \text{uint32\_be}(\text{index})$$
     * Compute $I = \text{HMAC-SHA512}(\text{key} = c_{\text{parent}}, \ \text{msg} = D)$, and set:
       $$k_{\text{child}} = \big(\text{uint256\_be}(I[0 : 32]) + \text{uint256\_be}(k_{\text{parent}})\big) \bmod n_{\text{secp256k1}}$$
       $$c_{\text{child}} = I[32 : 64]$$
2. **For `Ed25519` Chains (`Solana` & `TON` — `SLIP-0010`):**
   * Compute Master Node using **`HMAC-SHA512`** with key **`"ed25519 seed"`**:
     $$I = \text{HMAC-SHA512}\big(\text{key} = \texttt{"ed25519 seed"}, \ \text{msg} = \text{Seed}_{64\text{B}}\big)$$
   * For each hardened path component ($\text{index} = \text{num} + \text{0x80000000}$):
     $$I = \text{HMAC-SHA512}\big(\text{key} = c_{\text{parent}}, \ \text{msg} = \text{0x00} \parallel k_{\text{parent}} \parallel \text{uint32\_be}(\text{index})\big)$$
     $$k_{\text{child}} = I[0 : 32], \qquad c_{\text{child}} = I[32 : 64]$$

### 4.3 Step 3: Exact Derivation Paths & Public Key-to-Address Transformation Rules

For each derived child private key $k_{\text{child}}$ (at address index $i \in \{0, 1, 2, 3, 4\}$), compute the public blockchain address using these exact paths and transformations:

| Target Blockchain | Standard Derivation Path (`BIP-44` / `BIP-84`) | Exact Mathematical Transformation from Private Key $k_{\text{child}}$ to Public Address |
|---|---|---|
| **1. `TRON` (`TRX` / `USDT-TRC20`)** | **`m/44'/195'/0'/0/i`** | 1. Compute uncompressed `secp256k1` public key point $(X, Y)$ ($64\text{ bytes}$, stripping the leading `0x04` byte!).<br>2. Compute $H = \text{Keccak256}_{0x01}(X \parallel Y)$ ($32\text{ bytes}$).<br>3. Take the last $20\text{ bytes}$ $H[12 : 32]$ and prepend byte **`0x41`**: $P_{21} = \text{0x41} \parallel H[12 : 32]$.<br>4. Compute $C_4 = \text{SHA256}(\text{SHA256}(P_{21}))[0 : 4]$ and encode $(P_{21} \parallel C_4)$ in **Base58** $\rightarrow$ **`T...` (34 chars)**! |
| **2. `Ethereum`, `BSC`, `Polygon`, `Arbitrum`, `Base`** | **`m/44'/60'/0'/0/i`** (Standard MetaMask / Trust) & **`m/44'/60'/i'/0/0`** (Ledger Live) | 1. Compute uncompressed `secp256k1` public key $(X, Y)$ ($64\text{ bytes}$, without `0x04`).<br>2. Compute $H = \text{Keccak256}_{0x01}(X \parallel Y)$ ($32\text{ bytes}$).<br>3. Take the last $20\text{ bytes}$ $H[12 : 32]$, format as 40 hex chars, prepend **`0x`**, and apply **`EIP-55` mixed-case checksum** $\rightarrow$ **`0x...` (42 chars)**! |
| **3. `Bitcoin` Native SegWit (`BIP-84`)** | **`m/84'/0'/0'/0/i`** | 1. Compute **compressed** `secp256k1` public key $P_{33}$ ($33\text{ bytes}$, starting with `0x02` or `0x03`).<br>2. Compute `HASH160`: $H_{20} = \text{RIPEMD160}\big(\text{SHA256}(P_{33})\big)$ ($20\text{ bytes}$).<br>3. Convert $H_{20}$ to 5-bit groups, prepend Witness Version `0` (`'q'`), and encode with **`Bech32` (`hrp = "bc"`)** $\rightarrow$ **`bc1q...` (42 chars)**! |
| **4. `Bitcoin` Legacy (`BIP-44`)** | **`m/44'/0'/0'/0/i`** | 1. Compute $H_{20} = \text{RIPEMD160}\big(\text{SHA256}(P_{33})\big)$.<br>2. Prepend `0x00` and encode via **`Base58Check`** $\rightarrow$ **`1...` (34 chars)**! |
| **5. `Solana` (`SOL` / `SPL`)** | **`m/44'/501'/i'/0'`** (Phantom / Trust) & **`m/44'/501'/i'`** | 1. Derive $k_{\text{child}}$ ($32\text{ bytes}$) via `SLIP-0010` (`"ed25519 seed"`).<br>2. Compute the 32-byte **`Ed25519` Public Key** from $k_{\text{child}}$ and encode in **Base58** $\rightarrow$ **Solana Address**! |

---

## 5. Step 3 — Sub-Engine 4.4C: Web3 Keystore (`scrypt` / `pbkdf2`) & MetaMask Vault Unwrapper

Whenever Module 4.1 extracts an encrypted wallet vault (`MetaMask` `KeyringController.vault`, `Trust Wallet` `/files/keystore/*.json`, `TronLink` keystore, or `Exodus` `seed.seco`), Sub-Engine 4.4C tests:
1. Any **unwrapped biometric/Keychain password** harvested by **Phase 2, Module 2.2 (`case_cryptographic_keyring`)**, AND
2. Every candidate password in the **Suspect's Candidate Profile Dictionary** (harvested from the device's Chrome/Safari/Keychain saved passwords, user PINs, phone numbers, names, and DOB combinations from Module 3.3).

### 5.1 Unwrapping MetaMask `KeyringController.vault` (`PBKDF2-HMAC-SHA256` + `AES-256-GCM`)
Given the MetaMask vault JSON `{"data":"<b64_ct_and_tag>","iv":"<b64_iv>","salt":"<b64_salt>","keyMetadata":{"algorithm":"PBKDF2","params":{"iterations":600000}}}` (note: legacy MetaMask vaults used `10,000` iterations; modern vaults specify `iterations` inside `keyMetadata.params.iterations`—always read the dynamic `iterations` count if present, and test `10000` if omitted!):
1. Decode Base64 `salt` ($32\text{ bytes}$), `iv` ($16\text{ bytes}$), and `data` (where the last $16\text{ bytes}$ of `data` are the 128-bit GCM authentication tag).
2. Compute $K_{32} = \text{PBKDF2-HMAC-SHA256}(\text{password}, \text{salt}, \text{iterations}, \text{dkLen} = 32)$.
3. Decrypt `data` using **AES-256-GCM** with key $K_{32}$ and `iv`. If the 16-byte GCM authentication tag validates, parse the decrypted UTF-8 JSON array to extract the plaintext 12-word `mnemonic` (which is sometimes stored as an array of 12 ASCII byte arrays `[97, 98, ...]` in newer MetaMask builds—convert byte array to UTF-8 string!) and pass it to Sub-Engine 4.4B!

### 5.2 Unwrapping Standard Web3 Secret Storage Keystores (`Trust Wallet`, `TronLink`, `TokenPocket`)
Given a Version 3 Web3 Keystore JSON (`crypto.cipher = "aes-128-ctr"`, `crypto.kdf = "scrypt"` or `"pbkdf2"`):
1. **Derive the 32-Byte Key (`derivedKey`):**
   * If `kdf == "scrypt"`: Run `scrypt(password, salt, N = kdfparams.n, r = kdfparams.r, p = kdfparams.p, dkLen = 32)`.
   * If `kdf == "pbkdf2"`: Run `PBKDF2-HMAC-SHA256(password, salt, iterations = kdfparams.c, dkLen = 32)`.
2. **Verify the Password via the `Keccak-256` MAC (`crypto.mac`):**
   * Concatenate the **second half (Bytes $16\text{–}31$)** of `derivedKey` with the raw `ciphertext` bytes:
     $$M = \text{derivedKey}[16 : 32] \parallel \text{ciphertext\_bytes}$$
   * Compute **Original `Keccak-256` (`0x01` padding)** over $M$:
     $$\text{computed\_mac\_hex} = \text{Keccak256}_{0x01}(M)$$
   * **Password Match Condition:** If $\text{computed\_mac\_hex} == \texttt{crypto.mac}$, the password is $100\%$ verified!
3. **Decrypt the Secret Payload:**
   * Decrypt `ciphertext_bytes` using **AES-128-CTR** with the **first half (Bytes $0\text{–}15$)** of `derivedKey` (`derivedKey[0 : 16]`) as the 16-byte AES-128 key and `crypto.cipherparams.iv` as the 16-byte initial counter!

---

## 6. Step 4 — Sub-Engine 4.4D: The 4-Way "Rupee-to-USDT" Money Laundering Chain Correlator

Sub-Engine 4.4D is the master cross-phase intelligence engine that links **Phase 3 (Indian UPI & Banking)**, **Phase 4.2 (CEX P2P & Off-Chain Transfers)**, **Phase 4.1 (Self-Custody Web3 Wallets & Monero/BTC Swaps)**, and **Phase 5 (WhatsApp / Telegram / Session Chats)** into unified **End-to-End Money Laundering Chains**:

### 6.1 Hop 1 $\rightarrow$ Hop 2: Linking Phase 3 Indian Bank/UPI Transfers to Phase 4.2 CEX P2P Orders

For every P2P order $O$ in `cex_p2p_escrow_orders_ledger` (`Module 4.2`) with `fiat_currency == "INR"`, `fiat_total_amount` $= A_{\text{p2p}}$, and timestamp $t_{\text{p2p}}$:

1. **Tier-A Match (Deterministic 12-Digit `UTR` / `RRN` Join):**
   * If $O$ has an `extracted_utr_or_giftcard_code` (from the order details, P2P chat, or uploaded receipt OCR), match it directly against `unified_financial_transactions_ledger.utr_or_rrn_reference` in **Phase 3**.
2. **Tier-B Match (Single-Transfer Exact Amount + Counterparty VPA/Account + Time Window Join):**
   * Search Phase 3's `unified_financial_transactions_ledger` within $[t_{\text{p2p}} - 15\text{ min}, \ t_{\text{p2p}} + 60\text{ min}]$ for a settled transaction where:
     $$\left|\text{Amount}_{\text{phase3}} - A_{\text{p2p}}\right| \le ₹1.00 \quad \text{AND} \quad (\text{VPA or Account Tail matches } O\text{'s counterparty})$$
3. **Tier-C Match (The "Split-UPI Smurfing" Subset-Sum Correlator!):**
   * If $A_{\text{p2p}} > ₹50,000$ and no single Phase 3 transaction equals $A_{\text{p2p}}$, gather all settled Phase 3 outflows sent within $[t_{\text{p2p}} - 10\text{ min}, \ t_{\text{p2p}} + 45\text{ min}]$ (especially to the same counterparty VPA/account):
   * Find any subset of $k \in \{2, 3, 4, 5\}$ transactions $\{T_1, T_2, \dots, T_k\}$ whose sum satisfies:
     $$\sum_{j=1}^{k} \text{Amount}(T_j) == A_{\text{p2p}}$$
   * If found, link all $k$ split UPI/IMPS transactions to P2P Order $O$ and tag the link as **`SPLIT_UPI_SMURFING_TO_P2P_USDT`**!

### 6.2 Hop 2 $\rightarrow$ Hop 3 $\rightarrow$ Hop 4: Chaining P2P Escrow Release $\rightarrow$ CEX Withdrawal $\rightarrow$ Self-Custody Wallet $\rightarrow$ Offshore / Monero Exit

Once P2P Order $O$ (`crypto_quantity_decimal` $= Q_{\text{usdt}}$ at completion time $t_{\text{release}}$) is linked to Phase 3:
1. **Link to Hop 3 (CEX Withdrawal or `Binance Pay` Transfer in Module 4.2):**
   * Find all CEX withdrawals or `Binance Pay` internal transfers in `cex_withdrawals_deposits_and_internal_pay` occurring within $[t_{\text{release}}, \ t_{\text{release}} + 24\text{ hours}]$.
2. **Link to Hop 4 (Local Self-Custody Wallet in Module 4.1 & Chat Handoff in Phase 5):**
   * If the CEX withdrawal destination address $W_{\text{dest}}$ (`T...` or `0x...`) matches a wallet in Module 4.1 (`TronLink Pro`, `Trust Wallet`, `MetaMask`, `SafePal`) or a derived seed address in Sub-Engine 4.4B, chain all subsequent outbound `TRC-20`/`BEP-20` transfers and `FixedFloat`/`ChangeNow` swap orders (to `XMR` or `BTC`) from $W_{\text{dest}}$!
   * Cross-check the final destination `txid` and wallet address against **Phase 5 (`whatsapp_messages_master_ledger`, `telegram_and_signal_messages_ledger`, `opsec_messenger_messages_ledger`)** to identify the exact WhatsApp/Telegram/Session chat message where the suspect pasted the `txid` or wallet address to report completion to their syndicate boss!

---

## 7. Database Schema for Module 4.4 (`bip39_derivation_and_rupee_usdt_correlator.sqlite`)

The developer must create the following three tables in the case database:

### Table 1: `recovered_seeds_private_keys_and_unwrapped_vaults` (All Plaintext & Unwrapped Seeds, Keys & Vaults)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `seed_record_uid` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Unique row ID. |
| `secret_type` | `TEXT` | `NOT NULL` | Enum: `BIP39_MNEMONIC_12_TO_24_WORDS`, `MONERO_25_WORD_SEED`, `WIF_PRIVATE_KEY`, `RAW_64_HEX_PRIVATE_KEY`, `UNWRAPPED_METAMASK_OR_WEB3_VAULT`, `LOCKED_WEB3_VAULT_EXPORT`. |
| `discovery_source_detail` | `TEXT` | `NOT NULL` | E.g., `"Apple Notes (NoteStore.sqlite)"`, `"iOS Dynamic Keyboard Cache"`, `"Telegram Saved Messages"`, `"Phase 7 OCR Screenshot"`, `"MetaMask RKStorage (Unwrapped via Keychain)"`. |
| `source_vfs_file_id` | `INTEGER` | `NOT NULL` | Foreign key to `vfs_index.file_id`. |
| `checksum_validation_status` | `TEXT` | `NOT NULL` | E.g., `"BIP39_SHA256_CHECKSUM_VERIFIED"`, `"MONERO_CRC32_25TH_WORD_VERIFIED"`, `"WEB3_KECCAK256_MAC_VERIFIED"`. |
| `plaintext_mnemonic_or_privkey` | `TEXT` | `NULL` | Verified plaintext 12/24/25-word seed phrase or private key (`NULL` if still locked). |
| `unlocked_with_password` | `TEXT` | `NULL` | Password or Keychain key that unwrapped the vault (if encrypted vault). |
| `raw_encrypted_vault_json` | `TEXT` | `NULL` | Exported `{"data":...}` or Web3 keystore JSON (for external GPU cracking if locked). |
| `recovery_classification` | `TEXT` | `NOT NULL` | Mandatory 6-State Enum (`ORIGINAL_RECORD`, `HISTORICAL_COMMITTED_RECORD`, `RESIDUAL_RECORD`). |

### Table 2: `hd_derived_public_addresses_from_seeds` (Automatically Derived `TRON`, `EVM`, `BTC` & `Solana` Addresses)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `derived_addr_uid` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Unique row ID. |
| `seed_record_uid` | `INTEGER` | `NOT NULL` | Foreign key to `recovered_seeds_private_keys_and_unwrapped_vaults.seed_record_uid`. |
| `blockchain_network` | `TEXT` | `NOT NULL` | Enum: `TRON_TRC20`, `ETHEREUM_EVM_0X`, `BITCOIN_SEGWIT_BIP84`, `BITCOIN_LEGACY_BIP44`, `SOLANA_SLIP0010`. |
| `derivation_path` | `TEXT` | `NOT NULL` | E.g., `"m/44'/195'/0'/0/0"`, `"m/44'/60'/0'/0/0"`, `"m/84'/0'/0'/0/0"`. |
| `derived_public_address` | `TEXT` | `NOT NULL` | **Derived public address (`T...`, `0x...`, `bc1q...`, `1...`, or Solana Base58)! Indexed!** |
| `matches_on_device_activity` | `INTEGER` | `DEFAULT 0` | **`1` if this derived address appears in any wallet DB, CEX withdrawal, or chat message on the phone!** |

### Table 3: `end_to_end_rupee_to_crypto_laundering_chains` (Master Phase 3 $\leftrightarrow$ Phase 4 $\leftrightarrow$ Phase 5 Trail)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `laundering_chain_uid` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Unique ID for each reconstructed laundering chain. |
| `chain_pattern_classification` | `TEXT` | `NOT NULL` | Enum: `SINGLE_UPI_TO_P2P_USDT`, `SPLIT_UPI_SMURFING_TO_P2P_USDT`, `THIRD_PARTY_TRIANGULATION_P2P`, `DIRECT_INDIAN_FIU_CEX_ONRAMP`, `P2P_TO_SELF_CUSTODY_AND_MONERO_SWAP`. |
| `hop1_phase3_tx_master_uids_json` | `TEXT` | `NOT NULL` | JSON array of Phase 3 `tx_master_uid`s and 12-digit `UTR`s (`["UTR 630914829104 (₹90,000)", "UTR 630914899201 (₹90,000)"]`). |
| `hop1_total_fiat_outflow_inr` | `REAL` | `NOT NULL` | Total Indian Rupees (`₹`) debited from the bank/UPI rail. |
| `hop2_cex_p2p_order_uid` | `INTEGER` | `NULL` | Foreign key to Module 4.2 `cex_p2p_escrow_orders_ledger.p2p_order_uid`. |
| `hop2_acquired_crypto_amount` | `TEXT` | `NOT NULL` | E.g., `"2000.00 USDT (Binance P2P Order #2059...)"`. |
| `hop3_cex_withdrawal_or_pay_uid` | `INTEGER` | `NULL` | Foreign key to Module 4.2 `cex_withdrawals_deposits_and_internal_pay.cex_transfer_uid`. |
| `hop4_self_custody_or_swap_json` | `TEXT` | `NULL` | Linked Module 4.1 `TronLink`/`Trust Wallet` `txid`, destination `T...`/`0x...` address, or `FixedFloat` `XMR` swap order! |
| `hop5_chat_confirmation_msg_uid` | `TEXT` | `NULL` | Linked Phase 5 WhatsApp/Telegram/Session message where the suspect shared the `UTR` or `txid` with their handler! |
| `chain_start_utc_iso` | `TEXT` | `NOT NULL` | Timestamp of the initial Rupee bank/UPI transfer. |
| `chain_completion_utc_iso` | `TEXT` | `NULL` | Timestamp of the final crypto withdrawal/swap. |

---

## 8. Developer Acceptance Test Checklist for Module 4.4

1. **The 12-Word `BIP-39` SHA-256 Checksum & Multi-Chain HD Address Derivation Test:**
   * Feed the standard 12-word BIP-39 test mnemonic `"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"` (with empty passphrase `""`) into Sub-Engine 4.4A and Sub-Engine 4.4B.
   * Verify that Sub-Engine 4.4A validates the 4-bit SHA-256 checksum (`0x06`), and Sub-Engine 4.4B deterministically derives the exact known Index `0` addresses across all chains:
     * **TRON (`m/44'/195'/0'/0/0`):** `"TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYdH"`
     * **Ethereum / BSC (`m/44'/60'/0'/0/0`):** `"0x9858EfFD232B4033E47d90003D41EC34EcaEda94"`
     * **Bitcoin SegWit (`m/84'/0'/0'/0/0`):** `"bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"`
     * **Bitcoin Legacy (`m/44'/0'/0'/0/0`):** `"1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA"`
2. **The Web3 Keystore `Keccak-256` MAC Verification & AES-128-CTR Unwrap Test:**
   * Feed a Version 3 Web3 Keystore JSON encrypted with password `"Rahul@1408"` into Sub-Engine 4.4C.
   * Verify that Sub-Engine 4.4C validates `Keccak256(derivedKey[16:32] || ciphertext) == crypto.mac`, decrypts the payload via `AES-128-CTR`, and passes the recovered seed/private key to Sub-Engine 4.4B.
3. **The "Split-UPI Smurfing" Subset-Sum to Binance P2P & `TRC-20` Chain Correlator Test:**
   * Create two Phase 3 PhonePe UPI debits to `"seller99@okaxis"` at `14:02 UTC` (`₹95,000.00`, `UTR 630911111111`) and `14:05 UTC` (`₹85,000.00`, `UTR 630922222222`), alongside a Phase 4.2 Binance P2P `BUY` order at `14:00 UTC` for `2,000.00 USDT` (`fiat_total_amount = ₹1,80,000.00`, counterparty VPA `"seller99@okaxis"`), followed at `14:20 UTC` by a `2,000.00 USDT` `TRC-20` withdrawal to a local `TronLink Pro` wallet.
   * Verify that Sub-Engine 4.4D detects that $₹95,000 + ₹85,000 == ₹1,80,000$, links both UPI transfers to the P2P order (`SPLIT_UPI_SMURFING_TO_P2P_USDT`), and chains the subsequent `TronLink Pro` withdrawal into `end_to_end_rupee_to_crypto_laundering_chains`!
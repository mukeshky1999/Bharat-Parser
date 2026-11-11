# Engineering Specification: Phase 4, Module 4.3 — Mathematical Blockchain Address Validators, Smart Contract ABI Unpacker & `WalletConnect v2` Decoder

**Document Purpose:** This document provides the complete, step-by-step architectural blueprint for building **Module 4.3** of the Forensic Data Parser (corresponding to **Groups 5, 6, 12, 13, and 15** of the Unified Master Register). It contains **zero programming code** and explains the exact mathematical checksum algorithms for seven major blockchain address standards (`TRON`, `Bitcoin Legacy/SegWit/Taproot`, `Ethereum/EVM`, `Solana`, `Monero`, and `TON`), byte-level **Smart Contract ABI (`Application Binary Interface`) call-data unpacking** (including `ERC-20`/`TRC-20` transfers, `Permit2` phishing drainers, DEX routers, and mixer deposits), and **`WalletConnect v2` (`CAIP-10`)** multi-chain session and JSON-RPC history decoding from first principles.

---

## 1. Purpose & Mental Model (Why Regex Scraping Fails and Why ABI Unpacking Is Mandatory)

When an investigator searches a seized smartphone for cryptocurrency evidence across SQLite databases, WhatsApp/Telegram chats, browser caches, clipboards, and OCR text from screenshots, two technical obstacles cause standard forensic tools to fail:

1. **The Regex False-Positive Flood (Why Mathematical Checksums Are Mandatory):**
   * Mobile operating systems and apps generate millions of random alphanumeric strings: 32-to-44 character Base64 authentication tokens, 40-character hexadecimal SHA-1 file hashes, YouTube video IDs, and UUIDs.
   * If a developer writes a simple regular expression like `\bT[1-9A-HJ-NP-Za-km-z]{33}\b` (for TRON) or `\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b` (for Bitcoin), it will match thousands of random Base64 strings in `app_webview` and `MMKV`, flooding the forensic report with garbage false positives.
   * **Every major blockchain embeds a mathematical checksum or structural invariant inside its address format.** By enforcing strict cryptographic checksum validation (`Double-SHA256`, `BCH Polymod`, `Keccak-256`, `CRC16-CCITT`), Module 4.3 reduces false positives to near zero ($< 1\text{ in }4.29 \times 10^9$ for `Base58Check` and `Bech32`).
2. **The Smart Contract "Outer Recipient" Illusion (Why ABI Call-Data Unpacking Is Mandatory):**
   * When a suspect sends native Ether (`ETH`) or native `TRX`, the transaction's outer `to` field is the recipient's wallet address, and the outer `value` field is the amount sent.
   * However, **when a suspect sends `USDT`, `USDC`, `SHIB`, or any `ERC-20` / `BEP-20` / `TRC-20` token, the outer `to` field of the transaction is NOT the recipient's wallet address**—it is the **Token Smart Contract Address** (e.g., `0xdAC17F958D2ee523a2206206994597C13D831ec7` for Ethereum USDT), and the outer `value` field is **`0`**!
   * The **true recipient's wallet address** and the **true USDT amount** are encoded as 32-byte hexadecimal words inside the transaction's **`data` (`input`)** payload according to the **Contract Application Binary Interface (`ABI`)** specification! Without an ABI Unpacker, an investigator looking at a MetaMask or Trust Wallet database sees only `"Sent 0 ETH to USDT Contract"` and completely misses who received the ₹50 Lakh worth of USDT and how much was sent!

---

## 2. The 6 Fatal Mistakes Beginner Developers Make in Crypto Validation & ABI Parsing

Before implementing Module 4.3, the developer must understand six critical traps that break amateur cryptocurrency parsers:

### Mistake 1: Using NIST `SHA3-256` (`0x06` Padding) Instead of Original `Keccak-256` (`0x01` Padding)
* **The Trap:** Calling Python's standard `hashlib.sha3_256()` or OpenSSL's `EVP_sha3_256()` to validate Ethereum `EIP-55` mixed-case address checksums, compute Solidity 4-byte function selectors, or verify Monero (`XMR`) address checksums.
* **Why It Fails:** Ethereum, TRON, and Monero were designed before NIST finalized FIPS 202 (`SHA-3`) in August 2015. In the final FIPS 202 standard, NIST changed the domain separation padding byte from **`0x01` (Original Keccak-256)** to **`0x06` (NIST SHA3-256)**. Because of that single changed bit in the padding, **`SHA3-256` and `Keccak-256` produce completely different 32-byte hash digests for the exact same input!** If you use `SHA3-256`, every single `EIP-55` Ethereum address checksum and every Monero address checksum will fail validation!
* **The Rule:** Always use **Original `Keccak-256` (with `0x01` padding, $r = 1088, c = 512$)** for all Ethereum, EVM, TRON, and Monero cryptographic operations.

### Mistake 2: Using a Single `Bech32` Constant for Both Bitcoin SegWit (`bc1q...`) and Taproot (`bc1p...`)
* **The Trap:** Validating all Bitcoin `bc1...` addresses using the original `BIP-173` `Bech32` checksum constant `1`.
* **Why It Fails:** Bitcoin uses two different witness address standards under the `bc1` prefix:
  1. **SegWit v0 (`bc1q...`, Witness Version `0`, 42 or 62 chars):** Uses **`BIP-173` (`Bech32`)**, where the `polymod` remainder must equal **`1`**.
  2. **Taproot v1 (`bc1p...`, Witness Version `1`, 62 chars):** Uses **`BIP-350` (`Bech32m`)**, where the `polymod` remainder must equal **`0x2bc830a3` ($734,539,939$)**!
* **The Rule:** Inspect the 5-bit value of the very first character after the `"bc1"` separator (`'q'` = Witness Version `0` $\rightarrow$ check `polymod == 1`; `'p'` = Witness Version `1` $\rightarrow$ check `polymod == 0x2bc830a3`, Section 3.2).

### Mistake 3: Expecting a 4-Byte Checksum on Solana (`SOL`) Base58 Addresses
* **The Trap:** Passing a Solana wallet address (e.g., `7EcDhSYGxXyscszYEp35KHN8vvw3svAuLKTzXwCFLtV`) into the Bitcoin/TRON `Base58Check` validator.
* **Why It Fails:** Unlike Bitcoin and TRON (which decode to $25\text{ bytes}$: 1 version byte + 20 hash bytes + 4 checksum bytes), **a Solana address is a raw 32-byte `Ed25519` public key encoded directly in Base58 with ZERO version byte and ZERO checksum bytes!**
* **The Rule:** Validate Solana addresses using the dedicated **32-Byte `Ed25519` Base58 & Context Validator** in Section 3.4.

### Mistake 4: Decoding Monero (`XMR`) `4...` / `8...` Addresses as a Single Giant Base58 Integer
* **The Trap:** Decoding a 95-character Monero address using standard Bitcoin Base58 big-integer multiplication over the whole 95-character string.
* **Why It Fails:** Monero (`Cryptonote`) does **not** use standard whole-string Base58! If you decode a 95-character Monero address as a single Base58 big integer, the resulting byte array is corrupted and the Keccak-256 checksum fails. Instead, **Monero splits the 95-character string into eight 11-character Base58 blocks (each decoding to exactly $8\text{ big-endian bytes}$) followed by one final 7-character Base58 block (decoding to $5\text{ big-endian bytes}$)**, producing $8 \times 8 + 5 = \mathbf{69\text{ bytes}}$!
* **The Rule:** Follow the exact **Monero Block-Wise Base58 + Keccak-256 Checksum Algorithm** in Section 3.5.

### Mistake 5: Missing Gasless Phishing Signatures (`EIP-2612 Permit` & Uniswap `Permit2`)
* **The Trap:** Looking only for `0xa9059cbb` (`transfer`) and `0x095ea7b3` (`approve`) transactions when investigating how a victim's crypto wallet was drained.
* **Why It Fails:** Modern crypto drainer kits (*Angel Drainer*, *Pink Drainer*, *Inferno Drainer*) trick victims on Telegram/Discord into clicking a link inside MetaMask or Trust Wallet's DApp browser and signing an **off-chain `eth_signTypedData_v4` (`Permit` / `Permit2`) message**—which costs the victim $0\text{ gas}$ and does not even broadcast a transaction from the victim's phone! The attacker then submits that signed `Permit2` payload from the attacker's own wallet to drain the victim's USDT.
* **The Rule:** Scan both on-chain ABI call data (`0xd505accf` `permit`, `0x30f28b7a` `permitTransferFrom`) AND `WalletConnect v2` / DApp browser JSON-RPC logs for `eth_signTypedData_v4` requests containing `PermitSingle`, `PermitBatch`, or `Permit` (Section 4.2 & Section 5.2)!

### Mistake 6: Failing to Parse `CAIP-10` Multi-Chain Strings in `WalletConnect v2`
* **The Trap:** Expecting `WalletConnect` session logs to store a simple `0x...` address field.
* **Why It Fails:** `WalletConnect v2` uses the **Chain Agnostic Improvement Proposal (`CAIP-10`)** format inside its `namespaces` object, formatting every exposed account as:
  $$\texttt{<namespace>:<chain\_reference>:<account\_address>}$$
  For example: `"eip155:1:0x71C7656EC7ab88b098defB751B7401B5f6d8976F"` (Ethereum), `"eip155:56:0x71C..."` (BNB Smart Chain), or `"tron:0x2b6653dc:TXYZopYRdj2D9XRtbG411XZZ3kM5VkAeBf"` (TRON Mainnet)!
* **The Rule:** Implement the **CAIP-10 Namespace & Chain Resolver** in Section 5.1.

---

## 3. Step 1 — Sub-Engine 4.3A: Mathematical Blockchain Address Checksum Validators (7 Ecosystems)

Every candidate cryptocurrency address discovered anywhere on the device (in app databases, chat messages, browser caches, clipboards, or Phase 7 OCR text) must pass through the corresponding mathematical validator below before being indexed.

### 3.1 Validator 1: `Base58Check` for `TRON` (`T...`) and `Bitcoin` Legacy/P2SH (`1...` / `3...`)

Both TRON and Bitcoin use the 58-character **Bitcoin Base58 Alphabet**:
$$\Sigma_{\text{B58}} = \texttt{"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"}$$

1. **Candidate Pre-Filter:**
   * **TRON Mainnet:** Exactly **34 characters**, starting with **`'T'`** (`^T[1-9A-HJ-NP-Za-km-z]{33}$`).
   * **Bitcoin Legacy (`P2PKH`) & Script (`P2SH`):** **26 to 35 characters**, starting with **`'1'`** or **`'3'`** (`^[13][1-9A-HJ-NP-Za-km-z]{25,34}$`).
2. **Base58 String to 25-Byte Array Conversion:**
   * Count the number of leading `'1'` characters at the start of the string: let this count be $z$.
   * Initialize an arbitrary-precision integer $\text{val} = 0$. For each character $c$ in the string from left to right:
     * Look up the 0-based index $idx \in [0, 57]$ of $c$ in $\Sigma_{\text{B58}}$ (if $c \notin \Sigma_{\text{B58}}$, reject immediately).
     * Compute $\text{val} = (\text{val} \times 58) + idx$.
   * Convert $\text{val}$ to a big-endian byte array, and prepend $z$ zero bytes (`0x00`) to the front.
   * **Length Check:** The resulting byte array `raw_bytes` **must be exactly $25\text{ bytes}$ long**! If $\text{len}(\text{raw\_bytes}) \neq 25$, reject immediately.
3. **Version Byte & Double-SHA256 Checksum Verification:**
   * Inspect `version_byte = raw_bytes[0]`:
     * `0x41` ($65$): **TRON (`TRX` / `TRC-20`) Mainnet Address**.
     * `0x00` ($0$): **Bitcoin (`BTC`) Mainnet P2PKH Address**.
     * `0x05` ($5$): **Bitcoin (`BTC`) Mainnet P2SH Address**.
     * *(Optional altcoins using Base58Check: `0x30` = Litecoin `L...`, `0x32` = Litecoin `M...`, `0x1E` = Dogecoin `D...`).*
   * Slice the 21-byte payload `payload = raw_bytes[0 : 21]` and the 4-byte embedded checksum `embedded_crc = raw_bytes[21 : 25]`.
   * Compute **Double-SHA256**:
     $$D = \text{SHA256}\big(\text{SHA256}(\text{payload})\big)$$
   * **Verification Condition:** The address is valid **if and only if** $D[0 : 4] == \text{embedded\_crc}$!

### 3.2 Validator 2: `Bech32` (`BIP-173`) & `Bech32m` (`BIP-350`) for Bitcoin SegWit (`bc1q...`) & Taproot (`bc1p...`)

Bitcoin Native SegWit (`bc1q...`) and Taproot (`bc1p...`) addresses use the 32-character **Bech32 Alphabet**:
$$\Sigma_{\text{B32}} = \texttt{"qpzry9x8gf2tvdw0s3jn54khce6mua7l"}$$
*(where `'q'` $= 0$, `'p'` $= 1$, `'z'` $= 2$, ..., `'l'` $= 31$).*

1. **Candidate Pre-Filter & Case Rule:**
   * Length must be between **42 and 62 characters** (specifically **42 chars** for P2WPKH `bc1q...` and **62 chars** for P2WSH `bc1q...` or P2TR Taproot `bc1p...`).
   * **BIP-173 Mixed-Case Rejection Rule:** The string must be either all-lowercase or all-uppercase (never mixed-case!). Convert to lowercase and verify it starts with **`"bc1"`** (or `"ltc1"` for Litecoin SegWit).
2. **Split Human-Readable Part (`hrp`) and 5-Bit Data Array (`data_5bit`):**
   * Here, `hrp = "bc"`, and the characters after `"bc1"` are mapped via $\Sigma_{\text{B32}}$ to an array of 5-bit integers $d = [d_0, d_1, \dots, d_{k-1}]$.
   * The very first 5-bit integer $d_0$ is the **Witness Version (`witness_ver` $= d_0$)**:
     * If $d_0 == 0$ (`'q'`): Witness Version `0` (**SegWit `Bech32`**).
     * If $1 \le d_0 \le 16$ (`'p'` is $d_0 == 1$): Witness Version $1\text{–}16$ (**Taproot `Bech32m`**).
3. **Execute the `Bech32` BCH Polynomial Checksum (`polymod`):**
   * Construct the expanded prefix array for `hrp = "bc"` (ASCII bytes `98`, `99`):
     $$\text{hrp\_expand}(\texttt{"bc"}) = \left[\lfloor 98/32 \rfloor, \ \lfloor 99/32 \rfloor, \ 0, \ (98 \ \& \ 31), \ (99 \ \& \ 31)\right] = [3, 3, 0, 2, 3]$$
   * Concatenate `values = [3, 3, 0, 2, 3] + d`.
   * Initialize `chk = 1`. For each 5-bit value $v$ in `values`:
     * Let $b = \text{chk} \gg 25$.
     * Update $\text{chk} = \big((\text{chk} \ \& \ \text{0x1FFFFFF}) \ll 5\big) \oplus v$.
     * XOR `chk` with the five generator constants for bits $0\text{..}4$ of $b$:
       * If $(b \ \& \ 1) \neq 0$: $\text{chk} = \text{chk} \oplus \text{0x3b6a57b2}$
       * If $(b \ \& \ 2) \neq 0$: $\text{chk} = \text{chk} \oplus \text{0x26508e6d}$
       * If $(b \ \& \ 4) \neq 0$: $\text{chk} = \text{chk} \oplus \text{0x1ea119fa}$
       * If $(b \ \& \ 8) \neq 0$: $\text{chk} = \text{chk} \oplus \text{0x3d4233dd}$
       * If $(b \ \& \ 16) \neq 0$: $\text{chk} = \text{chk} \oplus \text{0x2a1462b3}$
4. **Verification Condition:**
   * If `witness_ver == 0` (`bc1q...`): Valid **if and only if** $\text{chk} == \mathbf{1}$!
   * If `witness_ver >= 1` (`bc1p...`): Valid **if and only if** $\text{chk} == \mathbf{\text{0x2bc830a3}}$ ($734,539,939$)!

### 3.3 Validator 3: Ethereum & EVM (`0x...`) `EIP-55` Keccak-256 Checksum Validator

Every Ethereum, BNB Smart Chain (`BSC`), Polygon, Arbitrum, Base, Optimism, and Avalanche address is a 42-character string matching `^0x[0-9a-fA-F]{40}$`.

1. **Reject Trivial Null / Burn / Padding Strings:**
   * If the 40 hex characters consist entirely of `'0'`s (`0x0000...0000`), entirely of `'f'`s (`0xffff...ffff`), or have fewer than 4 distinct hexadecimal characters, reject as a non-wallet constant/burn address.
2. **Case 1 — Mixed-Case `0x` Address (`EIP-55` Deterministic Checksum Verification):**
   * If the 40 hex characters contain **both** at least one uppercase letter (`A–F`) **and** at least one lowercase letter (`a–f`):
     1. Convert the 40 hex characters (without the `0x` prefix) to a 40-byte lowercase ASCII string `addr_lower`.
     2. Compute the **Original `Keccak-256` (`0x01` padding)** digest of `addr_lower`, formatted as a 64-character lowercase hex string `hash_hex`.
     3. Loop $i$ from $0\text{ to }39$:
        * If `addr_raw[i]` is an alphabetic character (`a–f` or `A–F`):
          * Read the integer value $n \in [0, 15]$ of the hex nibble `hash_hex[i]`.
          * If $n \ge 8$, `addr_raw[i]` **MUST be UPPERCASE (`A–F`)**!
          * If $n < 8$, `addr_raw[i]` **MUST be lowercase (`a–f`)**!
     4. If all alphabetic characters match their `Keccak-256` nibble parity, mark `checksum_verification = "EIP55_CRYPTOGRAPHICALLY_VERIFIED"`. If any character fails, **reject immediately** (it is a random 40-char mixed-case token or corrupted string, not an EIP-55 address!).
3. **Case 2 — All-Lowercase or All-Uppercase `0x` Address:**
   * Accept only if it appears inside a structured wallet/exchange database column, an ABI 32-byte word, a `CAIP-10` string, or adjacent to crypto context keywords (`USDT`, `ERC20`, `BEP20`, `ETH`, `Polygon`, `MetaMask`, `Trust`, `wallet`, `0x`), and convert it to its canonical `EIP-55` mixed-case form for storage.

### 3.4 Validator 4: Solana (`SOL` / `SPL`) 32-Byte `Ed25519` Base58 Validator

1. **Candidate Pre-Filter:** 32 to 44 characters from the Base58 alphabet $\Sigma_{\text{B58}}$.
2. **Exact 32-Byte Decode Check:**
   * Decode the Base58 string (preserving leading `'1'`s as `0x00` bytes).
   * The decoded byte array **must be exactly 32 bytes long ($\text{len} == 32$)**!
3. **Context & Ed25519 Validation:**
   * Because a Solana address has no internal checksum, require either that the string comes from a structured Solana/Phantom/CEX database field (`solana:`, `app.phantom`, `mint`, `pubkey`, `spl`) OR that it is accompanied by Solana context markers in chat/OCR text, and verify that its byte entropy is $> 3.5\text{ bits/byte}$ (filtering out ASCII words that happen to be 32 bytes in Base58).

### 3.5 Validator 5: Monero (`XMR`) 95-Character (`4...` / `8...`) Block-Wise Base58 + `Keccak-256` Validator

Monero primary addresses (`4...`) and subaddresses (`8...`) are **95 characters long** (or **106 characters** for Integrated Addresses containing an embedded 8-byte payment ID).

1. **Candidate Pre-Filter:** Match `^[48][1-9A-HJ-NP-Za-km-z]{94}$` (or `{105}` for integrated addresses).
2. **Monero Block-Wise Base58 Decoding (69 Bytes Total for 95-Char Address):**
   * Slice the 95-character string into **8 full blocks of 11 characters each** ($8 \times 11 = 88\text{ chars}$) plus **1 final block of 7 characters** ($88 + 7 = 95\text{ chars}$):
     * Decode each 11-character block using standard Base58 into an **8-byte big-endian unsigned integer (`uint64_be`)**! (If the decoded integer $\ge 2^{64}$, reject immediately).
     * Decode the final 7-character block using Base58 into a **5-byte big-endian integer** ($40\text{ bits}$; if $\ge 2^{40}$, reject immediately).
   * Concatenate the eight 8-byte blocks and the one 5-byte block to form the **69-byte `xmr_raw_bytes` array**:
     * **Byte $0$ (`network_byte`):**
       * `0x12` ($18$): **Monero Mainnet Primary Address** (starts with `'4'`).
       * `0x2A` ($42$): **Monero Mainnet Subaddress** (starts with `'8'`).
     * **Bytes $1\text{–}32$ ($32\text{ bytes}$):** Public Spend Key ($K_{\text{spend}}$).
     * **Bytes $33\text{–}64$ ($32\text{ bytes}$):** Public View Key ($K_{\text{view}}$).
     * **Bytes $65\text{–}68$ ($4\text{ bytes}$):** Embedded `Keccak-256` Checksum!
3. **Verify the 4-Byte `Keccak-256` Checksum:**
   * Compute **Original `Keccak-256` (`0x01` padding)** over the first $65\text{ bytes}$ (`xmr_raw_bytes[0 : 65]`):
     $$K = \text{Keccak256}\big(\text{xmr\_raw\_bytes}[0 : 65]\big)$$
   * **Verification Condition:** Valid **if and only if** $K[0 : 4] == \text{xmr\_raw\_bytes}[65 : 69]$!

### 3.6 Validator 6: TON (`Toncoin` / `USDT-TON`) 48-Character (`EQ...` / `UQ...`) `CRC16-CCITT` Validator

In Telegram (`TON Space`), `Tonkeeper`, and CEXs, user-friendly TON addresses are **48-character Base64 or Base64URL strings starting with `EQ` (Bounceable) or `UQ` (Non-Bounceable)**:

1. **Candidate Pre-Filter:** Match `^(?:EQ|UQ)[A-Za-z0-9_\-\+/]{46}$`.
2. **Decode Base64 / Base64URL to Exactly 36 Bytes (`ton_36_bytes`):**
   * **Byte $0$ (`tag_byte`):** `0x11` (Mainnet Bounceable `'EQ'`) or `0x51` (Mainnet Non-Bounceable `'UQ'`).
   * **Byte $1$ (`workchain_id`):** `0x00` (Basechain) or `0xFF` ($-1$, Masterchain).
   * **Bytes $2\text{–}33$ ($32\text{ bytes}$):** The 256-bit TON Account ID.
   * **Bytes $34\text{–}35$ ($2\text{ bytes}$, `uint16_be`):** Embedded **CRC16-CCITT (XMODEM)** Checksum!
3. **Verify the 2-Byte `CRC16-CCITT` Checksum:**
   * Compute `CRC16-CCITT` (polynomial `0x1021`, initial value `0x0000`, no final XOR) over the first $34\text{ bytes}$ (`ton_36_bytes[0 : 34]`).
   * **Verification Condition:** Valid **if and only if** $\text{uint16\_be}(\text{ton\_36\_bytes}[34 : 36]) == \text{crc16\_computed}$!

---

## 4. Step 2 — Sub-Engine 4.3B: The EVM & TRON Smart Contract ABI Call-Data (`data`) Unpacker

Whenever Module 4.1 (MetaMask, Trust Wallet, TronLink, SafePal) or Module 4.3C (`WalletConnect v2`) extracts a transaction or signing request with a hexadecimal `data` (`input` / `parameter`) payload, Sub-Engine 4.3B decodes the ABI structure.

### 4.1 How Solidity / TVM ABI Call Data Is Structured at the Byte Level

Every Smart Contract call payload (after stripping `0x`) consists of:

1. **The 4-Byte Function Selector (Hex Characters $0\text{–}7$, $4\text{ bytes}$):**
   * Computed as the first $4\text{ bytes}$ of `Keccak-256("functionName(type1,type2,...)")`.
2. **Sequence of 32-Byte (`64-Hex-Character`) Big-Endian Parameter Words (Starting at Hex Character $8$):**
   * **Word 0:** Hex Characters $8\text{–}71$ (Bytes $4\text{–}35$).
   * **Word 1:** Hex Characters $72\text{–}135$ (Bytes $36\text{–}67$).
   * **Word 2:** Hex Characters $136\text{–}199$ (Bytes $68\text{–}99$).
   * **Word $k$:** Hex Characters $(8 + 64k)\text{ through }(8 + 64(k+1) - 1)$.
3. **How Individual Types Are Packed Inside a 64-Hex-Character Word:**
   * **For an `address` parameter:** The first $24\text{ hex chars}$ ($12\text{ bytes}$) are zero-padding (`000000000000000000000000`); the **final $40\text{ hex chars}$** are the 20-byte wallet address!
     * *On Ethereum / BSC / Polygon:* Prepend `"0x"` to the final $40\text{ hex chars}$ and apply `EIP-55` checksumming.
     * *On TRON (`TriggerSmartContract`):* Prepend `"41"` to the final $40\text{ hex chars}$ and encode via `Base58Check` (Section 3.1) into a **34-character `'T'` TRON address**!
   * **For a `uint256` parameter:** Parse all $64\text{ hex chars}$ as a 256-bit unsigned big-endian integer (`BigInt`).

### 4.2 Master Table of 10 High-Priority Smart Contract ABI Selectors

| 4-Byte Hex Selector | Solidity / TVM Function Signature | Forensic Meaning & Exact Word Extraction Rules |
|---|---|---|
| **`a9059cbb`** | `transfer(address _to, uint256 _value)` | **Direct `ERC-20` / `BEP-20` / `TRC-20` Token Transfer!**<br>• **Word 0 (Chars $32\text{–}71$):** **True Recipient Wallet Address (`_to`)**!<br>• **Word 1 (Chars $72\text{–}135$):** **Raw `uint256` Token Amount (`_value`)**! |
| **`23b872dd`** | `transferFrom(address _from, address _to, uint256 _value)` | **Delegated Token Transfer (or Drainer Sweep)!**<br>• **Word 0 (Chars $32\text{–}71$):** **True Sender Address (`_from`)**!<br>• **Word 1 (Chars $96\text{–}135$):** **True Recipient Address (`_to`)**!<br>• **Word 2 (Chars $136\text{–}199$):** **Raw `uint256` Token Amount (`_value`)**! |
| **`095ea7b3`** | `approve(address _spender, uint256 _value)` | **Token Spending Approval (Allowance Grant)!**<br>• **Word 0 (Chars $32\text{–}71$):** Approved **`_spender` Contract / Drainer Address**!<br>• **Word 1 (Chars $72\text{–}135$):** Approved allowance (if $\ge 2^{255}$ or all `'f'`s `ffffffff...`, flag as **`UNLIMITED_TOKEN_APPROVAL_DRAIN_RISK`**!). |
| **`39509351`** | `increaseAllowance(address spender, uint256 addedValue)` | **Allowance Increase (Often Used by Phishing Drainers to Bypass `approve` Warnings)!**<br>• **Word 0 (Chars $32\text{–}71$):** `_spender` address.<br>• **Word 1 (Chars $72\text{–}135$):** `addedValue`. |
| **`d505accf`** | `permit(address owner, address spender, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s)` | **`EIP-2612` Gasless Permit Signature Execution!**<br>• **Word 0 (Chars $32\text{–}71$):** Victim `owner` address.<br>• **Word 1 (Chars $96\text{–}135$):** Drainer `spender` address.<br>• **Word 2 (Chars $136\text{–}199$):** Approved `value`. |
| **`30f28b7a`** & **`2b67b570`** | `permitTransferFrom(...)` (Uniswap `Permit2` Contract `0x000000000022D473030F116dDEE9F6B43aC78BA3`) | **Uniswap `Permit2` Gasless Token Sweep!**<br>• Extracts the `token` contract address, `requestedAmount`, and `to` (recipient address where tokens were swept). |
| **`38ed1739`** & **`18cbafe5`** | `swapExactTokensForTokens(...)` & `swapExactTokensForETH(...)` (Uniswap v2 / PancakeSwap / SunSwap Router) | **Decentralized Exchange (`DEX`) Token Swap!**<br>• **Word 0:** `amountIn` (Input token amount).<br>• **Word 1:** `amountOutMin` (Minimum output token amount).<br>• **Word 2:** Offset to `address[] path` array (first address in `path` = Input Token; last address in `path` = Output Token!).<br>• **Word 3 (Chars $224\text{–}263$):** **`to` (Recipient Wallet Address receiving the swapped tokens!)**. |
| **`7ff36ab5`** | `swapExactETHForTokens(uint256 amountOutMin, address[] path, address to, uint256 deadline)` | **DEX Native Coin (`ETH`/`BNB`/`TRX`) $\rightarrow$ Token Swap!**<br>• Outer `value` = Input ETH/BNB/TRX.<br>• **Word 2 (Chars $160\text{–}199$):** **`to` (Recipient Wallet Address)**! |
| **`3593564c`** | `execute(bytes commands, bytes[] inputs, uint256 deadline)` (Uniswap `UniversalRouter`) | **Modern Uniswap Universal Router Multi-Hop Swap / Permit2 Execution!**<br>• Unpacks each command byte (`0x00` = `V3_SWAP_EXACT_IN`, `0x08` = `V2_SWAP_EXACT_IN`, `0x0a` = `PERMIT2_PERMIT`) and extracts token paths and recipient addresses. |
| **`b214faa5`** & **`21a0adb6`** | `deposit(bytes32 _commitment)` & `withdraw(bytes _proof, bytes32 _root, bytes32 _nullifierHash, address _recipient, ...)` | **Tornado Cash / Zero-Knowledge Crypto Mixer Interaction!**<br>• For `b214faa5` (`deposit`): **Word 0** = 32-byte cryptographic `_commitment` hash.<br>• For `21a0adb6` (`withdraw`): **Word 3 (Chars $224\text{–}263$)** = **Unmasked `_recipient` Wallet Address receiving the mixed funds!** |

### 4.3 Built-In Known Token Smart Contract Address & Decimal Registry

To ensure $100\%$ accurate decimal conversion when unpacking `a9059cbb` or `23b872dd` calls, Sub-Engine 4.3B includes a built-in lookup table of the most common stablecoin and token contracts:

| Blockchain Network | Token Symbol | Official Smart Contract Address | Exact `decimals` Exponent |
|---|---|---|---|
| **TRON (`TRC-20`)** | **`USDT`** | `TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t` (`41a614f803b6fd780986a42c78ec9c7f77e6ded13c`) | **`6`** ($10^6$) |
| **TRON (`TRC-20`)** | **`USDC`** | `TEkxiTehnzSmSe2XqrBj4w32RUN966rdz8` | **`6`** ($10^6$) |
| **Ethereum (`ERC-20`)** | **`USDT`** | `0xdAC17F958D2ee523a2206206994597C13D831ec7` | **`6`** ($10^6$) |
| **Ethereum (`ERC-20`)** | **`USDC`** | `0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48` | **`6`** ($10^6$) |
| **Ethereum (`ERC-20`)** | **`DAI`** | `0x6B175474E89094C44Da98b954EedeAC495271d0F` | **`18`** ($10^{18}$) |
| **BNB Smart Chain (`BEP-20`)** | **`USDT` (`BSC-USD`)** | `0x55d398326f99059fF775485246999027B3197955` | **`18`** ($10^{18}$ — **Note: 18 decimals on BSC!**) |
| **BNB Smart Chain (`BEP-20`)** | **`USDC`** | `0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d` | **`18`** ($10^{18}$) |
| **Polygon (`POS`)** | **`USDT`** | `0xc2132D05D31c914a87C6611C10748AEb04B58e8F` | **`6`** ($10^6$) |
| **Polygon (`POS`)** | **`USDC`** | `0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359` (Native) / `0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174` (`USDC.e`) | **`6`** ($10^6$) |
| **Arbitrum One** | **`USDT` & `USDC`** | `0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9` (`USDT`) / `0xaf88d065e77c8cC2239327C5EDb3A432268e5831` (`USDC`) | **`6`** ($10^6$) |
| **TON (`Jetton`)** | **`USDT-TON`** | `EQCxE6mUtQJKFnGfaROTKOt1lZbDiiX1kCixRv7Nw2Id_sDs` | **`6`** ($10^6$) |

---

## 5. Step 3 — Sub-Engine 4.3C: `WalletConnect v2` (`CAIP-10`) Session, Pairing & JSON-RPC Phishing Drainer Decoder

Whenever a suspect connects their mobile wallet (`TronLink Pro`, `MetaMask`, `Trust Wallet`, `Phantom`, `SafePal`, `OKX Web3`) to an external website, a desktop DApp, an offshore casino/betting site, or a phishing drainer link, the connection is managed by the **`WalletConnect v2` protocol**.

### 5.1 Decoding `WalletConnect v2` Storage Keys & `CAIP-10` Account Strings

Scan all `LevelDB` (`Local Storage/leveldb/`), `RKStorage`, `MMKV`, and SQLite databases across all wallets and browsers for keys beginning with **`wc@2:`**:

1. **`wc@2:core:0.3//pairing` (Active & Historical Pairing Topics):**
   * Extracts `topic` (64-char hex session topic), `relay.protocol` (`"irn"`), `peerMetadata` (`name`, `description`, **`url` — the exact web domain of the external DApp!**), `active` boolean, and **`expiry` (`int64` Unix seconds)**:
     * **Timestamp Calculation Rule:** In `WalletConnect v2`, a standard pairing topic is created with a **30-day TTL (`2,592,000` seconds)**, and an active session is created with a **7-day TTL (`604,800` seconds)**! Therefore, subtracting $604,800\text{ seconds}$ ($7\text{ days}$) from a session's initial `expiry` timestamp reveals the **exact second the suspect scanned the QR code or clicked the deep-link to connect their wallet**!
2. **`wc@2:client:0.3//session` (Approved Multi-Chain Wallet Namespaces & `CAIP-10` Accounts):**
   * Inside each session JSON object, iterate through `namespaces` (`eip155`, `tron`, `solana`, `bip122`):
     * Each entry in `namespaces.<chain>.accounts` is a **`CAIP-10` String**:
       $$\texttt{<namespace>:<chain\_reference>:<wallet\_address>}$$
     * Split on `:` and resolve using this lookup table:
       * `eip155:1:0x...` $\rightarrow$ **Ethereum Mainnet** (`0x...`)
       * `eip155:56:0x...` $\rightarrow$ **BNB Smart Chain (`BSC`)** (`0x...`)
       * `eip155:137:0x...` $\rightarrow$ **Polygon Mainnet** (`0x...`)
       * `eip155:42161:0x...` $\rightarrow$ **Arbitrum One** (`0x...`)
       * `eip155:8453:0x...` $\rightarrow$ **Base Mainnet** (`0x...`)
       * `tron:0x2b6653dc:T...` $\rightarrow$ **TRON Mainnet** (`T...` 34-char address!)
       * `solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp:...` $\rightarrow$ **Solana Mainnet**
       * `bip122:000000000019d6689c085ae165831e93:bc1...` $\rightarrow$ **Bitcoin Mainnet**

### 5.2 Decoding `wc@2:core:0.3//history` (JSON-RPC Signing & Phishing Drainer Requests)

`wc@2:core:0.3//history` (and `wc@2:client:0.3//proposal`) stores the **verbatim JSON-RPC request/response array** sent between the external website and the mobile wallet:
* Extract every JSON-RPC record (`id`, `topic`, `request.method`, `request.params`, `response.result` / `response.error`):
  * **`eth_sendTransaction` / `tron_signTransaction`:** Pass `params[0].data` to Sub-Engine 4.3B's ABI Unpacker!
  * **`eth_signTypedData_v4` / `eth_signTypedData` (Gasless `Permit` / `Permit2` Drainer Detection!):**
    * Parse the `params[1]` JSON string (`EIP-712` Typed Data structure):
    * Inspect `primaryType` and `message`:
      * If `primaryType` is **`"Permit"`**, **`"PermitSingle"`**, **`"PermitBatch"`**, or **`"OrderComponents"`** (`Seaport`):
      * Extract `message.spender` (the **Attacker Drainer Contract Address**!), `message.token` / `domain.verifyingContract` (the **Victim's Token Contract**, e.g., `USDT`), `message.amount` / `message.value`, and `message.sigDeadline`!
      * If `response.result` contains a 65-byte (`132-hex-char`) `0x...` ECDSA signature, flag the record as **`CRITICAL: SIGNED_GASLESS_PERMIT_DRAINER_PAYLOAD`**!

---

## 6. Database Schema for Module 4.3 (`address_validators_abi_and_walletconnect.sqlite`)

The developer must create the following three tables in the case database:

### Table 1: `validated_crypto_addresses_global_index` (All Cryptographically Checksum-Verified Addresses Across the Entire Device)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `addr_index_uid` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Unique row ID. |
| `blockchain_ecosystem` | `TEXT` | `NOT NULL` | Enum: `TRON_TRC20`, `BITCOIN_LEGACY_P2PKH_P2SH`, `BITCOIN_SEGWIT_BECH32`, `BITCOIN_TAPROOT_BECH32M`, `ETHEREUM_EVM_0X`, `SOLANA_ED25519`, `MONERO_XMR_CRYPTONOTE`, `TON_CRC16`. |
| `canonical_address` | `TEXT` | `NOT NULL` | Checksum-verified canonical address (`T...`, `bc1q...`, `bc1p...`, `EIP-55 0x...`, `4.../8...`, `EQ.../UQ...`). Indexed! |
| `checksum_verification_method` | `TEXT` | `NOT NULL` | E.g., `"BASE58CHECK_DOUBLE_SHA256_OK"`, `"BECH32_POLYMOD_1_OK"`, `"BECH32M_POLYMOD_0x2bc830a3_OK"`, `"EIP55_KECCAK256_OK"`, `"MONERO_BLOCK_BASE58_KECCAK256_OK"`, `"TON_CRC16_CCITT_OK"`. |
| `discovered_in_module_and_app` | `TEXT` | `NOT NULL` | E.g., `"WhatsApp msgstore.db (Chat with +919876543210)"`, `"Phase 7 Screenshot OCR (IMG_4821.PNG)"`, `"Clipboard Cache"`, `"TronLink Pro DB"`. |
| `source_vfs_file_id` | `INTEGER` | `NOT NULL` | Foreign key to `vfs_index.file_id`. |
| `associated_actor_or_context` | `TEXT` | `NULL` | Sender/receiver name, phone number, or surrounding text snippet where the address was found! |
| `first_seen_utc_iso` | `TEXT` | `NULL` | Normalized UTC ISO-8601 timestamp. |
| `recovery_classification` | `TEXT` | `NOT NULL` | 6-State Enum (`ORIGINAL_RECORD`, `HISTORICAL_COMMITTED_RECORD`, `RESIDUAL_RECORD`). |

### Table 2: `unpacked_smart_contract_abi_calls` (Decoded `transfer`, `transferFrom`, `approve`, `Permit2`, DEX Swaps & Mixer Calls)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `abi_call_uid` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Unique row ID. |
| `linked_web3_tx_uid` | `INTEGER` | `NULL` | Joins to Module 4.1 `web3_wallet_transactions_ledger.web3_tx_uid` (or WalletConnect RPC ID). |
| `tx_hash_hex` | `TEXT` | `NULL` | 64/66-char transaction hash. |
| `blockchain_network` | `TEXT` | `NOT NULL` | `TRON_TRC20`, `ETHEREUM_ERC20`, `BSC_BEP20`, `POLYGON_POS`, `ARBITRUM`. |
| `outer_contract_address` | `TEXT` | `NOT NULL` | Smart contract called (e.g., `TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t` or `Uniswap UniversalRouter`). |
| `resolved_token_or_protocol` | `TEXT` | `NULL` | E.g., `"USDT (TRC-20)"`, `"USDT (BSC-USD)"`, `"Uniswap Permit2"`, `"Tornado Cash Mixer"`. |
| `selector_4byte_hex` | `TEXT` | `NOT NULL` | E.g., `"0xa9059cbb"`, `"0x095ea7b3"`, `"0x23b872dd"`, `"0xd505accf"`, `"0x21a0adb6"`. |
| `decoded_function_name` | `TEXT` | `NOT NULL` | E.g., `"transfer(address,uint256)"`, `"approve(address,uint256)"`, `"withdraw(bytes,bytes32,bytes32,address,...)"`. |
| `unpacked_true_sender` | `TEXT` | `NULL` | True `_from` / `owner` address (for `transferFrom` / `permit`). |
| `unpacked_true_recipient_or_spender` | `TEXT` | `NOT NULL` | **True `_to` recipient wallet address, `_spender` drainer contract, or mixer `_recipient`!** Indexed! |
| `unpacked_raw_uint256_amount` | `TEXT` | `NULL` | Raw decoded `uint256` integer string. |
| `unpacked_human_token_amount` | `TEXT` | `NULL` | Decimal-adjusted token amount (e.g., `"50000.000000 USDT"` or `"UNLIMITED_MAX_UINT256"`). |
| `is_unlimited_approval_or_drainer` | `INTEGER` | `DEFAULT 0` | **`1` if unlimited token allowance or `Permit2` drainer signature detected!** |

### Table 3: `walletconnect_v2_sessions_and_rpc_audit` (`CAIP-10` Pairings, Connected DApps & Signed `EIP-712` Payloads)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `wc_audit_uid` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Unique row ID. |
| `app_instance_id` | `INTEGER` | `NOT NULL` | Owning wallet/browser app in Module 1.3. |
| `source_vfs_file_id` | `INTEGER` | `NOT NULL` | Source LevelDB, SQLite, or MMKV file in `vfs_index`. |
| `wc_record_type` | `TEXT` | `NOT NULL` | Enum: `WC_V2_PAIRING_OR_SESSION`, `WC_V2_JSON_RPC_TRANSACTION`, `WC_V2_EIP712_PERMIT_SIGNATURE`. |
| `session_topic_hex` | `TEXT` | `NULL` | 64-character hexadecimal WalletConnect session topic. |
| `dapp_peer_name` | `TEXT` | `NULL` | Name of external DApp (`peerMetadata.name`). |
| `dapp_peer_url` | `TEXT` | `NOT NULL` | URL of external DApp (`peerMetadata.url`). |
| `exposed_caip10_accounts_json` | `TEXT` | `NULL` | JSON array of decoded `CAIP-10` chains and wallet addresses (`["TRON: TXYZ...", "ETH: 0x71C..."]`). |
| `rpc_method_and_params_json` | `TEXT` | `NULL` | Decoded JSON-RPC method (`eth_sendTransaction`, `eth_signTypedData_v4`) and unpacked parameters. |
| `is_phishing_permit_drainer_sig` | `INTEGER` | `DEFAULT 0` | **`1` if the user signed a gasless `Permit` / `Permit2` / `Seaport` allowance grant over WalletConnect!** |
| `session_paired_utc_iso` | `TEXT` | `NULL` | Calculated pairing/session start timestamp ($\text{expiry} - 604800\text{ s}$). |
| `session_expiry_utc_iso` | `TEXT` | `NULL` | Session expiration timestamp. |
| `recovery_classification` | `TEXT` | `NOT NULL` | 6-State Enum (`ORIGINAL_RECORD`, `HISTORICAL_COMMITTED_RECORD`, `RESIDUAL_RECORD`). |

---

## 7. Developer Acceptance Test Checklist for Module 4.3

1. **The Original `Keccak-256` (`0x01`) vs. NIST `SHA3-256` (`0x06`) `EIP-55` Checksum Test:**
   * Pass the mixed-case Ethereum address `"0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"` (an official EIP-55 test vector) and a single-case-flipped invalid string `"0x5aaeb6053F3E94C9b9A09f33669435E7Ef1BeAed"` into Validator 3 (Section 3.3).
   * Verify that the first passes `EIP55_KECCAK256_OK` (confirming true `0x01`-padded Keccak-256 is used, not NIST SHA3-256!), and the second is rejected!
2. **The Bitcoin `Bech32` (`bc1q`) vs. `Bech32m` (`bc1p`) Dual-Constant Test:**
   * Pass a SegWit v0 address `"bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"` (Witness Version `0`) and a Taproot v1 address `"bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0"` (Witness Version `1`) into Validator 2 (Section 3.2).
   * Verify that the `bc1q` address validates against `polymod == 1`, and the `bc1p` address validates against `polymod == 0x2bc830a3`.
3. **The Monero (`XMR`) 95-Char Block-Wise Base58 + Keccak-256 Test:**
   * Pass `"44Affq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A"` into Validator 5 (Section 3.5).
   * Verify that it decodes the eight 11-char blocks ($8 \times 8\text{ bytes}$) + one 7-char block ($5\text{ bytes}$) into $69\text{ bytes}$, verifies Byte $0 == \text{0x12}$, and validates the 4-byte Keccak-256 checksum at Bytes $65\text{–}68$!
4. **The TRON `TriggerSmartContract` `a9059cbb` & `WalletConnect v2` `Permit2` Drainer Test:**
   * Feed a TRON `TriggerSmartContract` call to `TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t` with `data = "a9059cbb000000000000000000000000eb8f23b921b9d83b5d69c219c0a84674a694820b00000000000000000000000000000000000000000000000000000002540be400"` ($10,000.00\text{ USDT}$), plus a `wc@2:core:0.3//history` `eth_signTypedData_v4` request with `primaryType = "PermitSingle"`.
   * Verify that Sub-Engine 4.3B prepends `0x41` to `eb8f23b921b9d83b5d69c219c0a84674a694820b` and encodes it via `Base58Check` into the 34-char `'T'` recipient address with amount `"10000.000000 USDT"`, and Sub-Engine 4.3C flags `is_phishing_permit_drainer_sig = 1`!
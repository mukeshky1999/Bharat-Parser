# Engineering Specification: Phase 4, Module 4.1 — Self-Custody Web3, DeFi, Privacy Coin & Hardware Companion Wallet Sandbox Decoders (`TronLink Pro`, `MetaMask`, `Trust Wallet`, `Phantom`, `SafePal`, `TokenPocket`, `OKX Web3`, `Exodus`, `Tonkeeper`, `Cake Wallet / Monero` & `Ledger Live`)

**Document Purpose:** This document provides the complete, step-by-step architectural blueprint for building **Module 4.1** of the Forensic Data Parser (corresponding to **Groups 5, 6, 12, 13, and 15** of the Unified Master Register). It contains **zero programming code** and explains the internal sandbox directory layouts, SQLite/Room schemas, React Native `RKStorage` (`persist:root`) JSON trees, `LevelDB` and `MMKV` key-value structures, `uint256` fixed-point token decimal conversions, privacy-coin (`Monero`) local swap logs, and hardware cold-wallet companion (`Ledger Live` / `SafePal S1`) `xpub` ledgers from first principles so that any developer can build a commercial-grade Web3 self-custody wallet forensic engine.

---

## 1. Purpose & Mental Model (Why Self-Custody Wallets Are the Final Destination of Cybercrime Proceeds)

In organized cybercrime ("Digital Arrest" extortion, investment/task scams, illegal offshore betting like `Mahadev` / `Lotus365`, ransomware, and darknet narcotics), perpetrators never store their long-term profits inside Indian bank accounts (which can be frozen within minutes via a `1930` NCRP lien) or inside KYC-verified Centralized Exchanges (which can be frozen via a Law Enforcement Request to Binance or FIU-IND).

Instead, within minutes of converting stolen Indian Rupees (`INR`) into **USDT (Tether)** on a P2P exchange, the syndicate withdraws the USDT into a **Non-Custodial (Self-Custody) Web3 Wallet** installed on the handler's smartphone.

### Why Standard Forensic Tools Fail on Self-Custody Wallets (And How Module 4.1 Succeeds)

A beginner developer assumes that if a self-custody wallet like **TronLink Pro**, **MetaMask**, **Trust Wallet**, or **Phantom** is protected by a user password or PIN, nothing inside the wallet app can be read without cracking the password. **That assumption is mathematically and architecturally false:**

1. **Public Addresses, Balances, Transaction Histories & DApp Sessions Are Stored in Plaintext:**
   * Because a mobile wallet must display balances, receive push notifications for incoming transfers, and render transaction history without forcing the user to re-derive keys on every screen refresh, **every self-custody wallet stores its public blockchain addresses (`T...`, `0x...`, `bc1q...`, `EQ...`), cached token balances, historical transaction hashes (`txid`), watch-only addresses, and built-in DApp browser histories in unencrypted plaintext** inside SQLite (`RKStorage` / `.db`), `LevelDB`, or `MMKV`!
2. **Biometric / "Remember Me" Unlock Stores the Vault Decryption Key in the OS Keychain / Keystore:**
   * Over $80\%$ of mobile wallet users enable **FaceID / Fingerprint / Biometric Unlock** inside MetaMask, Trust Wallet, TronLink, and Phantom so they don't have to type a 12-character password every time they open the app. When Biometric Unlock is enabled, the wallet stores the **exact plaintext vault password or AES key** inside the **iOS Keychain** or **Android Keystore**! When **Phase 2, Module 2.2** harvests the unlocked Keychain/Keystore (`UNWRAPPED_READY`), **Module 4.1 automatically unwraps the wallet's encrypted `vault` and recovers the suspect's plaintext 12/24-word `BIP-39` seed phrase and private keys**!
3. **`RKStorage-wal` & `LevelDB` Tombstones Preserve Deleted Wallets:**
   * When a suspect deletes/removes a compromised wallet account inside MetaMask (`RKStorage`) or Phantom (`LevelDB`), earlier versions of the `persist:root` JSON or LevelDB sequence numbers survive inside **`RKStorage-wal`**, **SQLite B-Tree Freelist pages** (Module 2.1), and **LevelDB `.ldb` historical sequence records** (Module 2.3B)!

---

## 2. The 6 Fatal Mistakes Beginner Developers Make in Web3 Wallet Parsing

Before implementing Module 4.1, the developer must understand six critical traps that corrupt or miss Web3 evidence:

### Mistake 1: Failing to Double-Parse Stringified Nested JSON Inside MetaMask's `RKStorage` (`persist:root`)
* **The Trap:** Querying `SELECT value FROM catalystLocalStorage WHERE key = 'persist:root';` in MetaMask's `RKStorage` database, parsing `value` once with `JSON.parse()`, and trying to read `root.engine.backgroundState.AccountTrackerController`.
* **Why It Fails:** MetaMask uses `redux-persist`. In `redux-persist`, the top-level `persist:root` JSON is a dictionary where **every top-level property value (`"engine"`, `"browser"`, `"settings"`, `"privacy"`) is itself a serialized JSON string (escaped with `\"`) rather than a nested JSON object**! If you only call `JSON.parse()` once on the outer string, `root.engine` is a giant string, not an object, and looking up `root.engine.backgroundState` returns `undefined`!
* **The Rule:** Always perform **Two-Stage Recursive JSON Deserialization** on `persist:root` (parse the outer JSON dictionary, and for every key whose value is a string starting with `{` or `[`, parse that inner string as JSON as well!).

### Mistake 2: Confusing TRON's 21-Byte `41...` Hex Address Format with Ethereum's 20-Byte `0x...` Hex Format
* **The Trap:** Seeing a 42-character hexadecimal string starting with `41` inside TronLink's SQLite database (for example, `41a614f803b6fd780986a42c78ec9c7f77e6ded13c`), stripping `41`, prepending `0x`, and reporting it as an Ethereum address!
* **Why It Fails:** On the **TRON blockchain (`TRX` / `TRC-20`)**, every address internally is a **21-byte array** where Byte $0$ is the TRON Mainnet prefix byte **`0x41`** ($65$ in decimal) followed by the $20\text{-byte}$ Keccak-256 hash suffix! When encoded via `Base58Check` (appending a 4-byte Double-SHA256 checksum), that 21-byte `41...` hex string becomes the familiar **34-character TRON address starting with `'T'`** (for example, `41a614f803b6fd780986a42c78ec9c7f77e6ded13c` encodes to **`TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t`**, the official Tether USDT-TRC20 contract!).
* **The Rule:** Inside TronLink, Trust Wallet (`coin = 195`), TokenPocket, and SafePal databases, **always convert any 42-character hex address starting with `41` into its canonical 34-character `'T'` `Base58Check` representation** (and store both representations side-by-side so searches for either `T...` or `41...` match!).

### Mistake 3: Overflowing 64-Bit Integers or Losing Precision on `uint256` Token Balances (`Wei` / `Sun` / `Lamports`)
* **The Trap:** Converting hexadecimal or string balances (like `"0x152d02c7e14af6800000"` or `"45000000000"`) into standard 64-bit integers (`int64`) or 64-bit IEEE-754 floats (`double`).
* **Why It Fails:**
  * A 64-bit signed integer (`int64`) overflows at $9,223,372,036,854,775,807$ ($\approx 9.22 \times 10^{18}$), which is only $9.22\text{ ETH}$ **or** $9.22\text{ BNB}$ in 18-decimal `Wei`! Any balance or transfer larger than $9.22\text{ ETH/BNB/MATIC}$ will crash or wrap around to a negative number if parsed as `int64`!
  * Furthermore, different tokens on different chains use completely different decimal divisors:
    * **USDT (`TRC-20` on TRON & `ERC-20` on Ethereum):** $\text{Decimals} = \mathbf{6}$ ($1\text{ USDT} = 10^6\text{ micro-USDT}$).
    * **USDT (`BEP-20` Binance-Peg BSC-USD on BNB Smart Chain `0x55d398...`):** $\text{Decimals} = \mathbf{18}$ ($1\text{ BSC-USD} = 10^{18}\text{ units}$)! *(Crucial Trap: USDT has 6 decimals on TRON and Ethereum, but **18 decimals on BNB Smart Chain**!)*
    * **TRX (TRON Native):** $\text{Decimals} = \mathbf{6}$ ($1\text{ TRX} = 10^6\text{ Sun}$).
    * **ETH / BNB / MATIC (EVM Native):** $\text{Decimals} = \mathbf{18}$ ($1\text{ Coin} = 10^{18}\text{ Wei}$).
    * **BTC (Bitcoin):** $\text{Decimals} = \mathbf{8}$ ($1\text{ BTC} = 10^8\text{ Satoshis}$).
    * **SOL (Solana) & TON (Toncoin):** $\text{Decimals} = \mathbf{9}$ ($1\text{ SOL/TON} = 10^9\text{ Lamports/Nanotons}$).
    * **XMR (Monero):** $\text{Decimals} = \mathbf{12}$ ($1\text{ XMR} = 10^{12}\text{ Piconeros}$).
* **The Rule:** Always parse raw crypto amounts into a **256-bit / Arbitrary-Precision Integer (`BigInt`)** and format the decimal output string using exact fixed-point string placement:
  $$\text{Decimal String} = \text{BigInt\_DivMod}\left(\text{Raw\_BigInt}, \ 10^{\text{decimals}}\right)$$

### Mistake 4: Missing "Watch-Only" ("Observed") Boss Wallets in TronLink, Trust Wallet & SafePal
* **The Trap:** Assuming every wallet address found inside a seized phone's TronLink or Trust Wallet app has a corresponding private key on that phone.
* **Why It Fails:** In organized cyber-fraud syndicates, the field-level mule coordinator in India does **not** hold the private key to the syndicate boss's main USDT collection wallet in Dubai or Cambodia. However, the Indian coordinator adds the boss's `T...` TRON address into their own `TronLink Pro` or `SafePal` app as a **"Watch-Only / Observed Wallet"** so they can watch incoming USDT deposits confirm in real time!
* **The Rule:** Explicitly extract the wallet's **`account_mode` (`FULL_PRIVATE_KEY_CONTROLLED` vs. `WATCH_ONLY_OBSERVED_ADDRESS` vs. `HARDWARE_WALLET_PAIRED`)**—identifying both the suspect's own wallets and the upstream syndicate boss wallets they were monitoring!

### Mistake 5: Ignoring Local Swap & Bridge Aggregator Logs (`FixedFloat`, `ChangeNow`, `Changelly`, `SunSwap`, `Bridgers`)
* **The Trap:** Looking only at standard `Send` and `Receive` transfers and ignoring built-in Cross-Chain Swap / Bridge tables.
* **Why It Fails:** When launderers want to break the on-chain link between `USDT-TRC20` (on TRON) and `Bitcoin (BTC)`, `Ethereum (ETH)`, or `Monero (XMR)`, they use the **built-in Swap / Bridge tab** inside `TronLink`, `Trust Wallet`, `SafePal`, `TokenPocket`, `Exodus`, or `Cake Wallet` (which routes through instant no-KYC swap APIs like **`ChangeNow`**, **`FixedFloat`**, **`Changelly`**, **`SideShift`**, **`SWFTAllChain`**, or **`Bridgers`**). While the public blockchain only shows USDT entering a giant liquidity pool on TRON, **the local wallet database on the seized phone records the exact `Swap Order ID`, the input `USDT-TRC20` `txid`, the destination `BTC`/`XMR`/`ETH` payout address, and the output `txid`!**
* **The Rule:** Extract every local cross-chain swap and bridge order across all wallet sandboxes (Section 4 & Section 6).

### Mistake 6: Overlooking `Ledger Live` & `SafePal` Hardware Cold-Wallet Companion Caches
* **The Trap:** When police raid a suspect's premises and cannot find their physical **Ledger Nano X / S Plus** or **Trezor** USB stick (or the suspect refuses to disclose the 8-digit hardware PIN), assuming the hardware wallet's balances and addresses cannot be discovered from the phone.
* **Why It Fails:** Suspects manage their physical Ledger or SafePal hardware wallets using the **`Ledger Live`** (`com.ledger.live`) or **`SafePal`** (`io.safepal.wallet`) companion app on their smartphone! Inside `Ledger Live`'s sandbox, the file **`app.json`** (and `RKStorage`) stores—in **100% unencrypted plaintext JSON**—every single hardware wallet account name, **Extended Public Key (`xpub` / `ypub` / `zpub`)**, derived address, current balance, and complete historical transaction list!

---

## 3. Step 1 — Sub-Engine 4.1A: Master Target Catalog of 15 Self-Custody & Hardware Companion Wallets

Module 4.1 queries **Phase 1, Module 1.3 (`resolve_app_targets`)** across all Android user profiles (`User 0`, `Work 10`, `Dual 95`, `Secure Folder 150`, `Cloner 999`) and iOS containers (`Data` + `Shared AppGroups`) for the following 15 priority wallet applications:

| Wallet Category | Application Name | Android Package Name(s) | iOS Bundle & AppGroup IDs | Primary Sandbox Storage Engines |
|---|---|---|---|---|
| **TRON / TRC-20 Specialist** | **TronLink Pro** & **TronLink Global** | `com.tronlinkpro.wallet`, `com.tronlink.global` | `com.tronlink.hdwallet` | SQLite (`/databases/*.db`), `MMKV`, `shared_prefs`, `app_webview` (`*_0`). |
| **EVM / Multi-Chain Flagship** | **MetaMask Mobile** | `io.metamask` | `io.metamask` | React Native `RKStorage` SQLite (`catalystLocalStorage` $\rightarrow$ `persist:root`), `MMKV`, iOS `RCTAsyncLocalStorage_V1`. |
| **Multi-Chain Flagship** | **Trust Wallet** | `com.wallet.crypto.trustapp` | `com.sixdays.trust` (`group.com.sixdays.trust`) | `/files/keystore/*.json` (`TrustWalletCore`), SQLite (`/databases/*.db`), Realm, `shared_prefs`. |
| **Solana / Multi-Chain** | **Phantom Wallet** & **Solflare** | `app.phantom`, `com.solflare.mobile` | `app.phantom`, `com.solflare.mobile` | `LevelDB` (`Local Storage/leveldb/`), `RKStorage` SQLite, `MMKV`. |
| **Asian Multi-Chain & Hardware** | **SafePal** (Software + S1 Hardware Wallet) | `io.safepal.wallet` | `io.safepal.wallet` | SQLite (`/databases/*.db`), `MMKV`, `shared_prefs`, and built-in **Binance Mini-Program** cache! |
| **Asian Multi-Chain & DeFi** | **TokenPocket**, **OKX Web3**, **BitKeep (Bitget Wallet)**, **imToken** | `vip.mytokenpocket`, `com.okinc.okex.gp`, `com.bitkeep.wallet`, `im.token.app` | Corresponding iOS bundles | SQLite (`/databases/`), `MMKV`, `LevelDB`, and `app_webview` DApp caches. |
| **Multi-Chain Desktop/Mobile** | **Exodus**, **Coinbase Wallet (Base)**, **Rainbow**, **Rabby** | `exodusmovement.exodus`, `org.toshi`, `me.rainbow`, `com.debank.rabbymobile` | Corresponding iOS bundles | `RKStorage` SQLite, `/files/v1/seed.seco` (Exodus), `LevelDB`, `MMKV`. |
| **Telegram / TON Ecosystem** | **Tonkeeper**, **MyTonWallet**, **Telegram `TON Space`** | `com.ton_keeper`, `org.mytonwallet.app` (+ `org.telegram.messenger` WebView) | `com.tonkeeper.Tonkeeper` | `RKStorage`, `MMKV`, and `Local Storage/leveldb/` (`EQ...` & `UQ...` TON addresses). |
| **Privacy Coin (`Monero / XMR`)** | **Cake Wallet**, **Monero.com**, **Monerujo** | `com.cakewallet.cake_wallet`, `com.monero.app`, `com.m2049r.xmrwallet` | `com.fotolockr.cakewallet` | **Flutter `Hive` binary `.hive` boxes** (Cake Wallet), `.keys` files, and SQLite/JSON swap ledgers (`ChangeNow`/`FixedFloat`/`Trocador`). |
| **Hardware Cold Wallet Companions** | **Ledger Live**, **Trezor Suite Lite**, **OneKey**, **Tangem** | `com.ledger.live`, `io.trezor.suite`, `so.onekey.app.wallet`, `com.tangem.wallet` | Corresponding iOS bundles | **`/files/app.json` & `RKStorage` (`Ledger Live` plaintext `xpub` & transaction ledger!)**, SQLite, `MMKV`. |

---

## 4. Step 2 — Sub-Engine 4.1B: `TronLink Pro` (`com.tronlinkpro.wallet`) Deep Sandbox Decoder

Because **USDT on TRON (`TRC-20`, contract `TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t`)** is the primary cryptocurrency rail in Indian cybercrime, gambling, and mule laundering, Sub-Engine 4.1B implements a dedicated 4-stage parser for `TronLink Pro`.

### 4.1 Stage 1: Extracting Wallet Accounts, Watch-Only Addresses & Keystore Blobs

Scan `/data/user/<id>/com.tronlinkpro.wallet/shared_prefs/`, `/files/mmkv/`, and `/databases/` (via **Module 2.1 Active + `-wal` + Freelist** and **Module 2.3A `MMKV`**):

1. **Locate Wallet Configuration Stores:**
   * Inspect `/shared_prefs/*wallet*.xml`, `tron_preferences.xml`, `user_info.xml`, and `MMKV` files, plus SQLite tables matching `wallet*`, `account*`, `user_wallet*`, and `address_book*`.
2. **Extract Every Configured Wallet Object:**
   * **`address_base58` & `address_hex41`:**
     * Extract the 34-character TRON `Base58Check` address (`T...`).
     * If stored in 21-byte hex format (`41` + 40 hex chars), convert to 34-char `'T'` `Base58Check` by computing $\text{Double-SHA256}(\text{bytes}(\texttt{41...}))[0:4]$ and encoding the resulting $25\text{ bytes}$ in Base58!
   * **`wallet_name`:** The custom label given by the suspect (e.g., `"Main USDT"`, `"P2P Buyer 2"`, `"Boss Cold Wallet"`).
   * **`create_type` / `wallet_mode` (Crucial Attribution Distinction):**
     * `0` / `HD_MNEMONIC`: Created or imported via a 12/24-word BIP-39 seed phrase (`m/44'/195'/0'/0/index`).
     * `1` / `PRIVATE_KEY`: Imported via a raw 64-character hexadecimal private key.
     * `2` / `KEYSTORE`: Imported via a Web3 JSON keystore.
     * **`3` / `WATCH_ONLY` (`isWatchOnly == true` / `coldWallet`):** **Observed / Watch-Only Wallet!** The suspect does not hold the private key on this device, but is actively monitoring this `T...` address's balance and incoming transfers!
     * `4` / `LEDGER_HARDWARE`: Paired via Bluetooth/USB to a physical Ledger hardware wallet.
   * **`encrypted_keystore_json` / `mnemonic_cipher` / `priv_key_cipher`:**
     * Extract the encrypted Web3 JSON or AES ciphertext string (`{"crypto":{"cipher":"aes-128-ctr","ciphertext":"...","cipherparams":{"iv":"..."},"kdf":"scrypt"|"pbkdf2",...}}`) and pass it to **Module 4.4's Vault Unwrapper**!
     * Check **Module 2.2 (`case_cryptographic_keyring`)** for any Android Keystore / iOS Keychain biometric key belonging to `com.tronlinkpro.wallet`—if present, unwrap the wallet password immediately!

### 4.2 Stage 2: Extracting TRON & `TRC-20` Transaction Ledgers, Energy Rentals & Approvals

Inside `/databases/`, enumerate all `.db` files (TronLink often names transaction databases per-address or per-network, such as `tron_main_*.db`, `trans_*.db`, `wallet_*.db`) and extract across active, `-wal`, and freelist records:

1. **Transactions & Transfers (`trans_record`, `transfer_record`, `trc20_transfer`, `transaction_history`):**
   * `tx_id` / `hash`: 64-character hexadecimal TRON transaction hash.
   * `from_address` (`owner_address`) & `to_address`: Normalize both to 34-char `'T'` `Base58Check` strings.
   * `contract_address` & `contract_type`:
     * If `contract_address == "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"` (or `41a614f803b6fd780986a42c78ec9c7f77e6ded13c`): Token is **`USDT (TRC-20)`**, `decimals = 6`.
     * If `contract_address == "TEkxiTehnzSmSe2XqrBj4w32RUN966rdz8"`: Token is **`USDC (TRC-20)`**, `decimals = 6`.
     * If `contract_type == 1` (`TransferContract`, native coin): Token is **`TRX`**, `decimals = 6` (`1 TRX = 1,000,000 Sun`).
     * If `contract_type == 31` (`TriggerSmartContract`): Pass `data` (hex call data) to **Module 4.3's ABI Unpacker** (`0xa9059cbb` / `0x095ea7b3`).
   * `amount` / `quant`: Parse as `BigInt` and divide by $10^6$ (`decimals = 6`) to output `human_token_amount_decimal`.
   * `block_timestamp`: 13-digit Unix millisecond timestamp.
2. **TRON Energy Rental & Bandwidth Delegation Logs (`DelegateResourceContract` / `FreezeBalanceV2`):**
   * **Forensic Gold in USDT Laundering:** Sending `USDT-TRC20` on TRON requires **`Energy`** ($\approx 32,000\text{ to }65,000\text{ Energy}$ per transfer, or burning $\approx 13\text{ to }27\text{ TRX}$). Professional USDT launderers frequently use **TRON Energy Rental Bots** (on Telegram or DApps like `Feee.io`, `TokenGoodies`, `JustLend`) where a parent wallet delegates `Energy` (`DelegateResourceContract`, `contract_type = 57`) to the suspect's wallet right before a large USDT transfer!
   * Extract every `DelegateResourceContract` record—because the wallet that delegated `Energy` or sent the initial $30\text{ TRX}$ "gas activation funding" (`Gas Station Wallet`) often links all of the syndicate's mule wallets together!
3. **Built-In Cross-Chain Swap & DApp Browser Logs (`swap_record`, `dapp_history`, `app_webview`):**
   * Extract all swap orders (e.g., `SWFT` / `Bridgers` / `SunSwap` orders converting `USDT-TRC20` $\rightarrow$ `BTC` or `ERC-20`), recording `order_id`, `from_token`, `to_token`, `from_address`, **`destination_payout_address` (on Bitcoin/Ethereum!)**, `deposit_txid`, and `payout_txid`!

---

## 5. Step 3 — Sub-Engine 4.1C: `MetaMask Mobile` (`io.metamask`) & `Trust Wallet` (`com.wallet.crypto.trustapp`) Deep Decoders

### 5.1 `MetaMask Mobile` (`RKStorage` / `persist:root` & `RCTAsyncLocalStorage_V1`)

1. **Locate & Stage MetaMask's State Store:**
   * **Android:** `/data/user/<id>/io.metamask/databases/RKStorage` (+ `RKStorage-wal`) and `/files/mmkv/`.
   * **iOS:** `<App-UUID>/Documents/RCTAsyncLocalStorage_V1/manifest.json` (plus shard files `0`, `1`, ... in the same directory) or `Library/Application Support/.../RKStorage`.
   * **Mandatory `-wal` & Freelist Recovery:** Always run **Phase 2, Module 2.1 (Pipelines A, B, and C)** on `RKStorage`! Because `catalystLocalStorage` updates the `persist:root` row in place, earlier committed frames in `RKStorage-wal` and B-tree freeblocks contain historical versions of `persist:root` from before the user cleared browser history or removed an imported account!
2. **Execute Two-Stage JSON Unpacking on `persist:root`:**
   * Parse the outer `persist:root` JSON object, then parse the inner stringified JSON objects for `"engine"`, `"browser"`, `"settings"`, `"user"`, and `"fiatOrders"`:
   * **Controller 1 — `engine.backgroundState.KeyringController`:**
     * Extract `vault` (`{"data":"<base64_ct>","iv":"<base64_iv>","salt":"<base64_salt>"}`).
     * Check **Module 2.2 (`case_cryptographic_keyring`)** for iOS Keychain / Android Keystore entry where `access_group_or_pkg` contains `io.metamask` (service `"io.metamask"` or `"MetaMask"`). When the user enables Biometrics / "Remember Me", MetaMask stores the plaintext password inside that Keychain/Keystore entry! Pass the password + `vault` to **Module 4.4** to decrypt the `KeyringController.vault` and extract every `hdKeyTree` (12-word BIP-39 mnemonic) and `Simple Key Pair` (imported 64-hex private key)!
   * **Controller 2 — `engine.backgroundState.PreferencesController`, `InternalAccountsController` & `AccountTrackerController`:**
     * Extract `selectedAddress` and iterate over `identities` / `internalAccounts.accounts` to extract every `0x...` address, its custom `name` (`"Account 1"`, `"Imported Account 2"`), `type` (`eip155:eoa` vs. `Hardware` Ledger/Trezor/QR), `importTime`, and native balance in `Wei`.
   * **Controller 3 — `engine.backgroundState.TokensController` & `TokenBalancesController`:**
     * Extract every custom ERC-20 / BEP-20 / Polygon token added to the wallet (`address`, `symbol`, `decimals`, `chainId`) and its cached `hex` balance (`contractBalances`).
   * **Controller 4 — `engine.backgroundState.TransactionController` & `SwapsController`:**
     * Iterate through `transactions` (and `methodData`):
       * Extract `id`, `hash` (66-char `0x...` txid), `chainId` (`0x1` = Ethereum, `0x38` = BSC, `0x89` = Polygon, `0xa4b1` = Arbitrum, `0xa` = Optimism, `0x2105` = Base, `0xa86a` = Avalanche), `time` (13-digit Unix ms), `status`, `origin` (DApp domain), and `txParams` (`from`, `to`, `value`, `data`, `gas`, `gasPrice`, `nonce`).
       * Pass `txParams.data` (`0xa9059cbb`, `0x095ea7b3`, `0x23b872dd`) to **Module 4.3's Smart Contract ABI Unpacker** to extract the true token recipient and token amount!
   * **Controller 5 — `engine.backgroundState.NetworkController`:**
     * Extract custom RPC URLs (`providerConfig` / `networkConfigurations`)—flagging private or custom RPC endpoints!
   * **Controller 6 — `browser` (`history`, `tabs`, `whitelist`) & `PermissionController`:**
     * Extract every DApp URL visited (`browser.history`), currently open tabs (`browser.tabs`), and every DApp origin granted `eth_accounts` wallet access (`PermissionController.subjects`)!

### 5.2 `Trust Wallet` (`com.wallet.crypto.trustapp` / `com.sixdays.trust`)

1. **Unpacking `/files/keystore/*.json` (`TrustWalletCore` Multi-Coin Keystores):**
   * Every JSON file inside `/data/user/<id>/com.wallet.crypto.trustapp/files/keystore/` (Android) or `Documents/keystore/` (iOS) represents a wallet container:
     * Extract `id` (UUID), `name` (user-assigned wallet name), `type` (`"mnemonic"`, `"private-key"`, or `"address"` \[Watch-Only!\]), and `version`.
     * **Extract Plaintext `activeAccounts` Array (Zero Decryption Needed!):**
       * Even while `crypto.ciphertext` is encrypted, `activeAccounts` is a plaintext JSON array listing every blockchain enabled in that wallet:
         * `coin` (`SLIP-0044` Coin Type Integer):
           * `195` = **TRON (`TRX` / `TRC-20`)**
           * `60` = **Ethereum (`ETH` / `ERC-20`)**
           * `20000714` or `714` = **BNB Smart Chain (`BSC` / `BEP-20`)**
           * `966` = **Polygon (`MATIC`)**
           * `0` = **Bitcoin (`BTC`)**
           * `501` = **Solana (`SOL`)**
           * `607` = **TON (`Toncoin`)**
           * `144` = **XRP (`Ripple`)**
           * `2` = **Litecoin (`LTC`)**
           * `3` = **Dogecoin (`DOGE`)**
         * `address`: The exact derived public blockchain address (`T...`, `0x...`, `bc1q...`, etc.)!
         * `derivationPath`: E.g., `"m/44'/195'/0'/0/0"`.
         * `extendedPublicKey`: The plaintext **`xpub` / `zpub`** (allows deriving all child receive/change addresses for UTXO coins like Bitcoin and Litecoin!).
     * **Unwrapping `crypto.ciphertext` via Android Keystore / iOS Keychain:**
       * Look up the matching wallet `id` password in **Module 2.2 (`case_cryptographic_keyring`)** (Trust Wallet stores the generated random password for each keystore file in `shared_prefs` encrypted by the Android Keystore key alias, or in the iOS Keychain!). If `UNWRAPPED_READY`, pass the password + keystore JSON to **Module 4.4** to recover the plaintext 12-word BIP-39 mnemonic!
2. **Parsing Trust Wallet SQLite & Realm Databases (`/databases/`):**
   * Stage all SQLite databases (`trust_*.db`, `assets.db`, `transactions.db`, `dapp_browser.db`, `wallet_connect.db`) through **Module 2.1 (Active + `-wal` + Freelist)** to extract cached token balances, pending/historical transactions, DApp browser history, and `WalletConnect` pairings.

---

## 6. Step 4 — Sub-Engine 4.1D: `Phantom`, `SafePal`, `TokenPocket`, `OKX Web3`, `Exodus`, `Tonkeeper`, `Cake Wallet` (`Monero`) & `Ledger Live`

### 6.1 `Phantom` (`app.phantom`), `TokenPocket`, `OKX Web3` & `Tonkeeper`

1. **`Phantom Wallet` (`app.phantom`):**
   * Process `/app_webview/Default/Local Storage/leveldb/` (via **Module 2.3B LevelDB + Tombstone Decoder**), `RKStorage` (via **Module 2.1**), and `MMKV` (via **Module 2.3A**):
     * Extract every configured Solana (`Ed25519` Base58), Ethereum/Polygon/Base (`0x...`), and Bitcoin (`bc1q...` / `bc1p...`) public address, user-assigned account labels, encrypted vault blobs (`cipher`, `nonce`, `salt`, `kdf`), cached SPL/ERC-20 token balances, recent swap history (`Jupiter` / `Li.Fi`), and connected DApp origins.
     * Check LevelDB `0x00` deletion tombstones and older sequence numbers (`Module 2.3B`) to recover removed accounts!
2. **`SafePal` (`io.safepal.wallet` — Software Wallet + `SafePal S1` Hardware Companion + Binance Mini-App):**
   * Parse SQLite databases in `/databases/` and `MMKV` in `/files/mmkv/`:
     * Distinguish Software Wallets (`mnemonic`/`private_key`) from paired **`SafePal S1 / X1` Hardware Cold Wallets** (extracting the hardware wallet's device serial/name, `xpub`s, and derived `T...`, `0x...`, and `bc1...` addresses!).
     * **Crucial SafePal Feature:** SafePal embeds a built-in **Binance Trading Mini-Program** and **MEXC / Bitget Mini-Program** that lets users trade on Binance/MEXC directly inside the SafePal wallet app! Scan SafePal's databases and `app_webview` cache (`Module 2.4`) for internal mini-program exchange UIDs, deposit addresses, and swap orders!
3. **`Tonkeeper` (`com.ton_keeper`) & `MyTonWallet`:**
   * Extract TON wallet versions (`v3R2`, `v4R2`, `W5` / `v5R1`), raw 64-hex account IDs (`0:<64_hex>`), user-friendly bounceable (`EQ...`) and non-bounceable (`UQ...`) 48-character Base64URL addresses, Jetton token balances (`USDT-TON` jUSDT / native Tether on TON!), TON DNS `.ton` domains, and transaction histories.

### 6.2 `Exodus` (`exodusmovement.exodus`) & `Cake Wallet` / `Monerujo` (`Monero / XMR` Privacy Coin Forensics)

1. **`Exodus Wallet` (`exodusmovement.exodus`):**
   * Extract public addresses, portfolio balances, transaction histories, and **built-in Exchange Swap Orders** (Exodus caches every cross-chain swap order in JSON/SQLite, recording `orderId`, `fromCoin`, `fromAmount`, `fromTxId`, `toCoin`, `toAmount`, `toAddress`, and `toTxId`!).
   * Stage `/files/v1/seed.seco` (Exodus's `seco` container—magic bytes `53 45 43 4F` `"SECO"`—encrypted with `scrypt` + `AES-256-GCM`) into `recovered_mnemonics_and_encrypted_vaults` for password unlocking in Module 4.4.
2. **`Cake Wallet` (`com.cakewallet.cake_wallet`) & `Monerujo` (`com.m2049r.xmrwallet`) — Defeating Monero (`XMR`) On-Chain Opacity via Local Device Forensics:**
   * **Why This Sub-Engine Is Essential:** On the public Monero (`XMR`) blockchain, Ring Signatures, RingCT, and Stealth Addresses hide the sender, the receiver, and the amount of every transaction. However, **inside the local `Cake Wallet` or `Monerujo` sandbox on the seized phone, nothing is hidden by RingCT**:
     * In **`Cake Wallet` (`/app_flutter/` on Android; `Documents/` on iOS):**
       * Cake Wallet uses Flutter **`Hive` binary key-value boxes** (`wallets.hive`, `transactions.hive`, `trades.hive`, `templates.hive`, `contacts.hive`, `nodes.hive`).
       * Parse the `Hive` binary frames (`[frame_length][key_type][key][value_type][value]`) and encrypted/unencrypted wallet files:
         * **`trades.hive` (The Cross-Chain Laundering Rosetta Stone!):** Suspects use Cake Wallet's built-in exchange aggregator (`ChangeNow`, `FixedFloat`, `SideShift`, `Trocador`, `Exolix`) to convert **`USDT-TRC20` or `BTC`** $\leftrightarrow$ **`Monero (XMR)`**! Every entry in `trades.hive` stores the **`trade_id`**, **`provider`** (`FixedFloat`, `ChangeNow`), **`from_currency` (`USDTTRC20`)**, **`to_currency` (`XMR`)**, **`amount`**, **`input_txid`**, and **`payout_address` (the destination `T...` or `4...`/`8...` wallet address!)**!
         * **Local Monero Transaction & Subaddress Ledger:** Extracts the suspect's own **95-character Primary Monero Address (`4...`)**, **95-character Subaddresses (`8...`)**, the **Secret View Key (`view_key`)**, and—for outgoing XMR transfers cached locally—the **True Destination `4...`/`8...` Address**, the **Per-Transaction Secret Key (`tx_key` — which mathematically proves on-chain that the suspect sent that exact Monero transaction!)**, the exact `XMR` amount, and the timestamp!

### 6.3 `Ledger Live` (`com.ledger.live`) & `Trezor Suite Lite` — Unmasking Physical Hardware Cold Wallets

Even if a suspect hid their physical **Ledger Nano X / Nano S Plus / Stax / Flex** or **Trezor** hardware wallet in a bank locker or with an accomplice, installing `Ledger Live` (`com.ledger.live`) or `Trezor Suite Lite` (`io.trezor.suite`) on their smartphone leaves the **entire cold wallet portfolio exposed in plaintext**:

1. Locate `/data/user/<id>/com.ledger.live/files/app.json` and `/databases/RKStorage` (Android) or `<App-UUID>/Documents/app.json` and `RCTAsyncLocalStorage_V1` (iOS).
2. Parse `app.json` (and `RKStorage` + `-wal` frames via Module 2.1):
   * Iterate over `data.accounts`:
     * Each entry in `data.accounts` is a JSON object representing a hardware-wallet account on the physical Ledger device!
     * Extract:
       * `id`: Contains the coin type, hardware wallet `xpub` or address, and derivation mode (e.g., `"js:2:bitcoin:xpub6CUGRUo...:native_segwit"` or `"js:2:tron:TXYZ...:"` or `"js:2:ethereum:0x71C...:"`).
       * **`xpub`**: The full **Extended Public Key (`xpub` / `ypub` / `zpub`)** or root public address of the hardware wallet!
       * **`name`**: User-assigned hardware account name (e.g., `"Ledger Nano X - Bitcoin Cold Storage"`).
       * **`freshAddress` & `freshAddressPath`**: Current receive address and BIP-44/84 derivation path (e.g., `"84'/0'/0'/0/14"`).
       * **`balance`**: Exact balance in raw units (`Satoshis` / `Wei` / `Sun`).
       * **`operations` Array**: The complete historical transaction list (`hash`, `type` \[`IN` / `OUT`\], `value`, `fee`, `senders` array, `recipients` array, `blockHeight`, and `date` ISO-8601 timestamp) of the physical Ledger hardware wallet!
   * Iterate over `data.user` / `settings` / `ble.knownDevices`:
     * In **`ble.knownDevices`**: Extracts the **Bluetooth MAC Address, Device ID, Model (`nanoX` / `stax`), and Custom Name** of every physical Ledger hardware wallet ever paired with the suspect's phone!

---

## 7. Database Schema for Module 4.1 (`web3_self_custody_wallets_engine.sqlite`)

The developer must create the following four tables in the case database to store all Module 4.1 outputs (which also feed into the master Phase 4 tables in Module 4.4):

### Table 1: `web3_wallet_instances_and_accounts` (All Discovered Self-Custody, Watch-Only & Hardware Companion Wallets)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `web3_account_uid` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Unique row ID for each discovered wallet account/address. |
| `app_instance_id` | `INTEGER` | `NOT NULL` | Foreign key to owning wallet app in Module 1.3 (`TronLink`, `MetaMask`, `Trust Wallet`, `Ledger Live`, etc.). |
| `wallet_app_name` | `TEXT` | `NOT NULL` | E.g., `"TronLink Pro"`, `"MetaMask"`, `"Trust Wallet"`, `"Phantom"`, `"Cake Wallet"`, `"Ledger Live"`. |
| `source_vfs_file_id` | `INTEGER` | `NOT NULL` | Source `.db`, `RKStorage`, `.json`, or `.hive` file in `vfs_index`. |
| `recovery_classification` | `TEXT` | `NOT NULL` | Mandatory 6-State Enum (`ORIGINAL_RECORD`, `HISTORICAL_COMMITTED_RECORD`, `RESIDUAL_RECORD`). |
| `account_control_mode` | `TEXT` | `NOT NULL` | Enum: `FULL_PRIVATE_KEY_OR_SEED`, `WATCH_ONLY_OBSERVED_WALLET`, `PAIRED_HARDWARE_COLD_WALLET`. |
| `blockchain_network` | `TEXT` | `NOT NULL` | Enum: `TRON_TRC20`, `ETHEREUM_ERC20`, `BSC_BEP20`, `POLYGON_POS`, `BITCOIN`, `SOLANA`, `TON_NETWORK`, `MONERO_XMR`. |
| `public_address_canonical` | `TEXT` | `NOT NULL` | Normalized address (`34-char T...` TRON, `EIP-55 0x...` EVM, `bc1q...` BTC, Solana Base58, `EQ...`/`UQ...` TON, `95-char 4.../8...` Monero). Indexed! |
| `tron_hex41_representation` | `TEXT` | `NULL` | 42-char `41...` hex address (populated for TRON addresses so both `T...` and `41...` searches match). |
| `extended_public_key_xpub` | `TEXT` | `NULL` | `xpub` / `ypub` / `zpub` or Monero `view_key` (from Trust Wallet, Ledger Live, SafePal, or Cake Wallet). |
| `bip44_derivation_path` | `TEXT` | `NULL` | E.g., `m/44'/195'/0'/0/0` or `m/84'/0'/0'/0/14`. |
| `user_assigned_wallet_label` | `TEXT` | `NULL` | Suspect's custom account name (e.g., `"Boss Cold Wallet"`, `"Mule Payout"`). |
| `paired_hardware_device_info` | `TEXT` | `NULL` | Ledger/SafePal hardware model, serial, or Bluetooth MAC (`ble.knownDevices`). |
| `cached_token_balances_json` | `TEXT` | `NULL` | JSON dictionary of cached balances (e.g., `{"USDT": "142500.00", "TRX": "340.50"}`). |
| `is_vault_unwrapped` | `INTEGER` | `DEFAULT 0` | `1` if the seed phrase / private key was automatically unwrapped via Keychain/Keystore in Module 2.2/4.4. |

### Table 2: `web3_wallet_transactions_ledger` (All Local On-Chain Transfers, Energy Delegations & Token Approvals)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `web3_tx_uid` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Unique row ID. |
| `web3_account_uid` | `INTEGER` | `NOT NULL` | Foreign key to `web3_wallet_instances_and_accounts.web3_account_uid`. |
| `source_vfs_file_id` | `INTEGER` | `NOT NULL` | Source file in `vfs_index`. |
| `recovery_classification` | `TEXT` | `NOT NULL` | 6-State Enum (`ORIGINAL_RECORD`, `HISTORICAL_COMMITTED_RECORD`, `RESIDUAL_RECORD`). |
| `tx_hash_hex` | `TEXT` | `NOT NULL` | 64- or 66-character hexadecimal transaction hash (`txid`). Indexed! |
| `blockchain_network` | `TEXT` | `NOT NULL` | `TRON_TRC20`, `ETHEREUM_ERC20`, `BSC_BEP20`, `POLYGON_POS`, `BITCOIN`, `SOLANA`, `TON_NETWORK`, `MONERO_XMR`. |
| `tx_operation_type` | `TEXT` | `NOT NULL` | Enum: `NATIVE_COIN_TRANSFER`, `SMART_CONTRACT_TOKEN_TRANSFER`, `TOKEN_APPROVAL_ALLOWANCE`, `TRON_ENERGY_DELEGATION`, `DEX_SWAP_EXECUTION`. |
| `token_symbol` | `TEXT` | `NOT NULL` | E.g., `"USDT"`, `"USDC"`, `"TRX"`, `"ETH"`, `"BNB"`, `"BTC"`, `"SOL"`, `"TON"`, `"XMR"`. |
| `token_contract_address` | `TEXT` | `NULL` | Smart contract address (e.g., `TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t`). |
| `from_address` | `TEXT` | `NULL` | Sender wallet address. |
| `to_recipient_address` | `TEXT` | `NULL` | **True recipient wallet address** (unpacked from ABI `0xa9059cbb` or local Monero `transactions.hive`). |
| `raw_bigint_amount_str` | `TEXT` | `NOT NULL` | Raw unmodified `uint256` / integer string (`Wei`, `Sun`, `Satoshis`, `Piconeros`). |
| `token_decimals` | `INTEGER` | `NOT NULL` | Exact decimal exponent ($6, 8, 9, 12,$ or $18$). |
| `human_amount_decimal_str` | `TEXT` | `NOT NULL` | Exact fixed-point decimal amount string (e.g., `"50000.000000"`). |
| `monero_secret_tx_key` | `TEXT` | `NULL` | Per-transaction `tx_key` extracted from Cake Wallet / Monerujo (proves XMR transfer on-chain!). |
| `tx_status` | `TEXT` | `NOT NULL` | `CONFIRMED`, `PENDING`, `FAILED`. |
| `tx_utc_ns` | `INTEGER` | `NOT NULL` | Normalized 64-bit UTC nanoseconds. |
| `tx_utc_iso` | `TEXT` | `NOT NULL` | Normalized UTC ISO-8601 timestamp. |

### Table 3: `web3_cross_chain_bridge_and_swap_orders` (`FixedFloat`, `ChangeNow`, `SunSwap`, `SWFT` & `Cake Wallet` `trades.hive`)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `swap_order_uid` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Unique row ID. |
| `app_instance_id` | `INTEGER` | `NOT NULL` | Owning wallet app (`Cake Wallet`, `TronLink`, `Exodus`, `SafePal`, `Trust Wallet`). |
| `source_vfs_file_id` | `INTEGER` | `NOT NULL` | Source `.hive`, `.db`, or WebView cache file in `vfs_index`. |
| `swap_aggregator_provider` | `TEXT` | `NOT NULL` | E.g., `"FixedFloat"`, `"ChangeNow"`, `"SideShift"`, `"Trocador"`, `"SWFTAllChain"`, `"Bridgers"`, `"Jupiter"`. |
| `provider_order_or_trade_id` | `TEXT` | `NOT NULL` | Aggregator Order / Trade ID (used to subpoena the swap provider!). |
| `input_chain_and_asset` | `TEXT` | `NOT NULL` | E.g., `"USDT (TRC-20)"`. |
| `input_amount_decimal` | `TEXT` | `NOT NULL` | Input amount sent into the swap bridge. |
| `input_deposit_txid` | `TEXT` | `NULL` | On-chain `txid` of the input deposit. |
| `output_chain_and_asset` | `TEXT` | `NOT NULL` | E.g., `"XMR (Monero)"` or `"BTC (Bitcoin)"`. |
| `output_amount_decimal` | `TEXT` | `NULL` | Output amount received from the bridge. |
| `destination_payout_address` | `TEXT` | `NOT NULL` | **The destination wallet address on the target blockchain (`4...` XMR or `bc1q...` BTC)!** |
| `output_payout_txid` | `TEXT` | `NULL` | On-chain `txid` of the bridge payout. |
| `swap_created_utc_iso` | `TEXT` | `NOT NULL` | Normalized UTC ISO-8601 timestamp. |
| `recovery_classification` | `TEXT` | `NOT NULL` | 6-State Enum (`ORIGINAL_RECORD`, `HISTORICAL_COMMITTED_RECORD`, `RESIDUAL_RECORD`). |

---

## 8. Developer Acceptance Test Checklist for Module 4.1

1. **The `TronLink Pro` 21-Byte `41...` Hex to 34-Char `'T'` `Base58Check` & Watch-Only Test:**
   * Insert a wallet record in TronLink with `address = "41a614f803b6fd780986a42c78ec9c7f77e6ded13c"` and `isWatchOnly = true`.
   * Verify that Sub-Engine 4.1B converts the `41...` hex string into `"TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"` (`public_address_canonical`), preserves the `41...` string in `tron_hex41_representation`, and sets `account_control_mode = "WATCH_ONLY_OBSERVED_WALLET"`.
2. **The `MetaMask` `persist:root` Double-JSON Deserialization & `uint256` `BigInt` Test:**
   * Create a test `RKStorage` database where `catalystLocalStorage` key `'persist:root'` has an escaped inner JSON string `"engine":"{\"backgroundState\":{\"AccountTrackerController\":{\"accounts\":{\"0x71c7656ec7ab88b098defb751b7401b5f6d8976f\":{\"balance\":\"0x152d02c7e14af6800000\"}}}}}"` ($100.0\text{ ETH}$ in Wei, which exceeds 64-bit `int64`).
   * Verify that Sub-Engine 4.1C double-parses the nested JSON string without crashing on 64-bit integer overflow and outputs `100.000000000000000000 ETH`.
3. **The `Cake Wallet` `trades.hive` `USDT-TRC20` $\rightarrow$ `Monero (XMR)` Bridge Unmasking Test:**
   * Feed a test `trades.hive` record containing `provider = "FixedFloat"`, `trade_id = "FF998877"`, `from = "USDTTRC20"`, `to = "XMR"`, and `payout_address = "44Affq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A"`.
   * Verify that Sub-Engine 4.1D extracts the complete cross-chain swap into `web3_cross_chain_bridge_and_swap_orders`, linking the TRON laundering trail to the destination Monero wallet!
4. **The `Ledger Live` `app.json` Hardware Cold-Wallet Unmasking Test:**
   * Place a plaintext `app.json` inside `/com.ledger.live/files/` containing a `nanoX` Bluetooth pairing (`ble.knownDevices`) and an account with `xpub6CUGRUonZSQ4TWtTMmzXdrXDtypWKiKrhko4egpiMZbpiaQL2jkwSB1icqYh2cfDfVxdx4df189oLKnC5fSwqPfgyP3hooxujYzAu3fDVmz` and `balance = "250000000"` ($2.50\text{ BTC}$).
   * Verify that Sub-Engine 4.1D extracts the `xpub`, balance, transaction `operations`, and Bluetooth MAC of the physical Ledger Nano X!
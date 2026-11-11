# Engineering Specification: Phase 4, Module 4.2 — Centralized Exchanges (`CEX`), Indian FIU-Registered Exchanges, P2P Escrow Order/Chat Decoders & Off-Chain `Binance Pay` / Internal UID Transfers

**Document Purpose:** This document provides the complete, step-by-step architectural blueprint for building **Module 4.2** of the Forensic Data Parser (corresponding to **Groups 5, 6, 12, 13, and 15** of the Unified Master Register, and bridging directly to **Phase 3's Indian UPI & Banking Ledger**). It contains **zero programming code** and explains the internal sandbox architectures (`MMKV`, SQLite, `RKStorage`, and `app_webview` `Simple Cache *_0`) of both **Global P2P Exchanges** (`Binance`, `Bybit`, `KuCoin`, `MEXC`, `Gate.io`, `Bitget`, `HTX`, `BingX`, `Noones`/`Paxful`) and **Domestic Indian FIU-IND Registered Exchanges** (`CoinDCX`, `WazirX`, `CoinSwitch Kuber`, `Mudrex`, `ZebPay`, `Giottus`, `Flitpay`, `SunCrypto`, `Delta Exchange`, `Pi42`) from first principles so that any developer can build a courtroom-grade CEX and P2P fiat-to-crypto forensic engine.

---

## 1. Purpose & Mental Model (How the Rupee-to-USDT P2P Escrow Bridge Actually Works)

In Indian cybercrime, "Digital Arrest" extortion, task/investment fraud, illegal betting (`Mahadev` / `Lotus365`), and darknet operations, a suspect holding ₹10 Lakh of stolen funds in an Indian mule bank account faces an immediate problem: **Indian banks block or flag direct merchant transfers to known cryptocurrency exchanges**.

To bypass banking blocks, syndicates use **Centralized Exchange Peer-to-Peer (`P2P` / `C2C` — Customer-to-Customer) Escrow Markets** (primarily on **`Binance`**, **`Bybit`**, **`KuCoin`**, **`MEXC`**, **`Bitget`**, and **`Noones`**) or **Indian FIU-IND Registered On-Ramps / Crypto Futures Platforms** (`CoinDCX`, `Mudrex`, `ZebPay`, `Flitpay`, `CoinSwitch`, `WazirX`).

### The Anatomy of a P2P Escrow Trade (Why the Phone Holds More Proof Than the Bank Statement)
When a suspect uses **Binance P2P** or **Bybit P2P** to convert stolen Indian Rupees (`INR`) into **USDT**:
1. **Step 1 (Escrow Lock):** The suspect (`Buyer`) opens a P2P order to buy `5,000 USDT` for `₹4,50,000 INR` from a P2P Merchant (`Seller`). The exchange locks `5,000 USDT` of the Seller's crypto in escrow and assigns a **19-to-20 digit P2P Order Number** (e.g., `20594829104829104128`).
2. **Step 2 (Payment Method Disclosure & In-Order Chat):** Inside the P2P order screen, the exchange displays the Seller's **Indian UPI VPA (`@ybl` / `@okaxis`) or Bank Account Number + IFSC + Verified Legal Name**. Simultaneously, an **In-Order Escrow Chat Box** opens where the Buyer and Seller exchange messages, phone numbers, payment screenshots, and **12-digit NPCI UPI `UTR` / `IMPS RRN` numbers**!
3. **Step 3 (Bank Transfer on Phase 3 Rails):** The suspect switches to `PhonePe`, `Google Pay India`, or `YONO SBI` (parsed in **Phase 3**) and sends `₹4,50,000 INR` to the Seller's VPA/bank account. To the Indian bank, this looks like an ordinary domestic peer-to-peer Rupee transfer between two individuals—the bank has **no idea** that cryptocurrency is involved!
4. **Step 4 (Escrow Release & Off-Chain / On-Chain Movement):** Once the Seller verifies the 12-digit UTR in their bank account, they click **"Release Crypto"**. The `5,000 USDT` lands in the suspect's `Funding Wallet` on the CEX, and the suspect immediately moves it either **on-chain** (via `TRC-20` to `TronLink Pro` in Module 4.1) OR **off-chain** (via **`Binance Pay` / `Internal UID Transfer`** to an overseas syndicate boss's Binance UID with zero blockchain fees!).

**Only by parsing the seized smartphone's CEX sandbox (`Module 4.2`) and joining it to the UPI/Banking ledger (`Phase 3`) can an investigator prove that the domestic ₹4,50,000 bank transfer was actually a USDT cryptocurrency purchase!**

---

## 2. The 6 Fatal Mistakes Beginner Developers Make in CEX & P2P Exchange Forensics

Before implementing Module 4.2, the developer must understand six critical traps that cause standard forensic tools to miss CEX evidence:

### Mistake 1: Looking Only in SQLite Databases for `Binance` (`com.binance.dev`) Instead of Tencent `MMKV` & `app_webview` Cache
* **The Trap:** Opening `/data/user/0/com.binance.dev/databases/` in a SQLite viewer, seeing mostly empty or generic analytics tables, and concluding that Binance stores nothing locally.
* **Why It Fails:** Binance's Android and iOS applications store almost all persistent user state, account `UID`s, KYC profiles, payment method bindings, and session configurations inside **Tencent `MMKV` memory-mapped files (`/files/mmkv/`)** (decoded by **Phase 2, Module 2.3A**—including encrypted `.crc` stores and overwritten append history!), and cache REST API responses (`/bapi/c2c/v2/...`, `/bapi/capital/...`, `/bapi/pay/...`) inside **`app_webview` / `okhttp` HTTP disk caches** (decoded by **Phase 2, Module 2.4**)!
* **The Rule:** For every CEX app, run a unified 3-engine sweep across **SQLite (Module 2.1)** + **`MMKV` (Module 2.3A)** + **WebView/HTTP Cache (Module 2.4)**.

### Mistake 2: Missing the Suspect's 8-to-10 Digit CEX `UID` (`userId`)
* **The Trap:** Extracting a suspect's email address or username from a Binance or Bybit sandbox without extracting their numeric **`Exchange UID` (`userId`)**.
* **Why It Fails:** Suspects change their email address or phone number on an exchange, or use disposable protonmail/temp-mail addresses. However, every account on `Binance`, `Bybit`, `KuCoin`, `MEXC`, `Bitget`, and `OKX` is assigned an immutable numeric **`UID` (User ID, e.g., `482910482`)** at account creation. Furthermore, **Internal Off-Chain Transfers (`Binance Pay` / `Bybit Internal Transfer`)** route funds directly by `UID`, and **Government Law Enforcement Request Portals (such as Binance's `LERP` and FIU-IND notices)** require the target's `UID` to freeze balances immediately!
* **The Rule:** Prioritize extracting and indexing the numeric `cex_user_uid` across `MMKV`, `shared_prefs`, SQLite, JWT tokens (`sub` / `userId`), and push notification logs.

### Mistake 3: Ignoring Off-Chain Internal CEX Transfers (`Binance Pay`, `Red Packets` / `Crypto Boxes`, `Internal UID Withdrawal`)
* **The Trap:** Searching only for 64-character hexadecimal blockchain transaction hashes (`txid`).
* **Why It Fails:** If Mule Coordinator A (on Binance) wants to send `10,000 USDT` to Handler B (also on Binance), they use **Binance Pay** or select **"Send via Binance UID / Email / Phone"**. This transfer executes 100% off-chain inside Binance's internal ledger—it generates an **18-to-19 digit numeric `Pay Order ID` / `Internal Transfer ID`** instead of a 64-char blockchain `txid`! Similarly, syndicates distribute payouts to dozens of workers inside Telegram groups using **Binance `Crypto Box` / `Red Packet` Claim Codes** (alphanumeric codes like `BP8X9K2M`).
* **The Rule:** Sub-Engine 4.2B must explicitly extract `BINANCE_PAY_TRANSFER`, `INTERNAL_UID_TRANSFER`, and `CRYPTO_BOX_RED_PACKET` records alongside on-chain withdrawals (Section 4.3).

### Mistake 4: Failing to Extract "Third-Party Payment" Mismatches in P2P Escrow Orders
* **The Trap:** Assuming the bank account or UPI VPA used to pay for a Binance/Bybit P2P order always belongs to the person whose KYC name is on the Binance/Bybit account.
* **Why It Fails:** In **"Triangulation / Third-Party P2P Fraud"**, a syndicate criminal opens a P2P order on their own (or a rented) Binance account to buy `2,000 USDT` from an innocent P2P Seller, takes the Seller's UPI VPA (`seller@okaxis`), and tricks a **completely different cyber-fraud victim** into sending `₹1,80,000` directly from the victim's bank account to `seller@okaxis`!
* **The Rule:** For every P2P order, compare the **CEX Account Owner's KYC Name (`cex_owner_kyc_name`)** against the **Payer CBS Name on the linked Phase 3 UPI/Bank Transfer (`phase3_payer_cbs_name`)**. Whenever `cex_owner_kyc_name != phase3_payer_cbs_name`, automatically trigger a **`CRITICAL` Alert (`THIRD_PARTY_TRIANGULATION_P2P_LAUNDERING`)**!

### Mistake 5: Overlooking Indian `1% TDS` (Tax Deducted at Source under Section 194S) & `FIU-IND` Registration Artifacts
* **The Trap:** Treating Indian exchanges (`CoinDCX`, `WazirX`, `CoinSwitch`, `ZebPay`, `Mudrex`, `Flitpay`, `Giottus`, `SunCrypto`) the same as anonymous offshore wallets.
* **Why It Fails:** Under **Section 194S of the Indian Income Tax Act** and **FIU-IND (Financial Intelligence Unit — India)** regulations (with ~50–54 registered VDA Service Providers in 2026), every trade or transfer on a compliant Indian exchange automatically deducts **`1% TDS` tied to the user's 10-character `PAN` (Permanent Account Number)** and logs the user's verified **Aadhaar e-KYC**, **Selfie Video KYC**, and **Penny-Drop Verified Bank Account + IFSC**!
* **The Rule:** Sub-Engine 4.2C must extract the suspect's `PAN`, `1% TDS` deduction records, verified bank accounts, and FIU-IND compliance logs from domestic exchange sandboxes (Section 5).

### Mistake 6: Missing Browser-Based & PWA Access to Unregistered Offshore Exchanges (Via VPN / Mirror Domains)
* **The Trap:** Checking only for installed `.apk` / `.ipa` apps of exchanges (`com.binance.dev`, `com.bybit.app`).
* **Why It Fails:** When an offshore exchange is geo-blocked or removed from the Indian Play Store / App Store, suspects access the exchange via **Chrome, Safari, Brave, or Tor Browser** using a VPN or official mirror domain (e.g., `binance.com`, `bybitglobal.com`, `mexc.com`, `noones.com`, `localcoinswap.com`). All of their P2P orders, JWT tokens, and chat transcripts are sitting inside the browser's **`Simple Cache (*_0)` / `Cache.db`, `Cookies`, `Local Storage`, and `IndexedDB`** (parsed by **Phase 2, Module 2.4**)!
* **The Rule:** Sub-Engine 4.2D scans all browser and WebView caches from Module 2.4 for CEX API endpoints, regardless of whether the native CEX app is installed (Section 6).

---

## 3. Step 1 — Sub-Engine 4.2A: Master Target Catalog of 20 Global & Indian Centralized Exchanges (`CEX`)

Module 4.2 queries **Phase 1, Module 1.3 (`resolve_app_targets`)** across all Android user profiles (`0`, `10`, `95`, `150`, `999`) and iOS containers for the following 20 priority exchange applications:

| Exchange Category | Platform Name | Android Package Name(s) | iOS Bundle ID(s) | Primary Sandbox Storage Engines & Forensic Focus |
|---|---|---|---|---|
| **Global Tier-1 & P2P Leader** | **Binance** (FIU-IND Registered) | `com.binance.dev` | `com.czzhao.binance` | **Tencent `MMKV` (`/files/mmkv/`)**, SQLite (`/databases/*.db`), `shared_prefs`, `okhttp` / `app_webview` cache (`*_0`). Primary target for `P2P (C2C)`, `Binance Pay`, and `TRC-20` withdrawals. |
| **Global P2P & Derivatives** | **Bybit** (FIU-IND Registered) | `com.bybit.app` | `com.bybit.app` | SQLite/Room (`/databases/`), `MMKV`, `shared_prefs`, `app_webview`. Heavy adoption in Indian P2P USDT buying and internal UID transfers. |
| **Global P2P & Altcoin CEX** | **KuCoin** (FIU-IND Registered) | `com.kubi.kucoin` | `com.kucoin.app` | SQLite (`/databases/`), `MMKV`, `shared_prefs`, `app_webview` JSON cache. |
| **Global Offshore / High-Risk P2P** | **MEXC**, **Gate.io**, **Bitget**, **HTX (Huobi)**, **BingX**, **OKX**, **LBank** | `com.mexc.client`, `com.gateio.gateio`, `com.bitget.exchange`, `pro.huobi`, `com.bingbon.app`, `com.okinc.okex.gp`, `com.lbank.exchange` | Corresponding iOS bundles | Frequently sideloaded via APK when Play Store restricted. Parse SQLite, `MMKV`, and `app_webview` P2P/withdrawal caches. |
| **Dedicated P2P / Gift-Card Marketplaces** | **Noones**, **Paxful**, **LocalCoinSwap**, **AgoraDesk** | `com.noones.app`, `com.paxful.wallet` (+ Browser PWAs) | Corresponding iOS bundles / WebKit | **High-Risk Laundering Vector:** Used to trade **Amazon / Apple / Steam Gift Cards** and UPI transfers for USDT/BTC! |
| **Indian Domestic Tier-1 (FIU-IND)** | **CoinDCX** & **CoinDCX Pro** | `com.coindcx.btc`, `com.coindcx` | `com.coindcx.btc` | SQLite, `MMKV`, React Native `RKStorage`, `shared_prefs`, `app_webview`. Extracts PAN, Aadhaar KYC, linked Indian bank account, and 1% TDS logs. |
| **Indian Domestic Tier-1 (FIU-IND)** | **CoinSwitch / CoinSwitch PRO** | `com.coinswitch.kuber` | `com.coinswitch.kuber` | `RKStorage` / SQLite, `MMKV`, `app_webview`. Extracts KYC profile, INR deposit/withdrawal UTRs, and spot trades. |
| **Indian Domestic & Vault/Transfer** | **Mudrex**, **ZebPay**, **Flitpay** (FIU-IND Registered) | `com.mudrex.app`, `zebpay.Application`, `com.flitpay.app` | Corresponding iOS bundles | **Crucial:** Because `Mudrex`, `ZebPay`, and `Flitpay` support external on-chain crypto withdrawals (subject to EDD/KYC), they are heavily used to bridge INR to external wallets! |
| **Indian Domestic & Regional** | **WazirX**, **Giottus**, **SunCrypto**, **BuyUcoin**, **Unocoin**, **KoinBX**, **Bitbns** | `com.wrx.wazirx`, `com.giottus.app`, `com.suncrypto.in`, `com.buyucoin.app`, `com.unocoin.unocoin`, `com.koinbx.app` | Corresponding iOS bundles | SQLite, `MMKV`, `RKStorage`, and `app_webview` caches (including WazirX restructuring/claim balance ledgers and P2P history). |
| **Indian Crypto Derivatives (FIU-IND)** | **Delta Exchange India** & **Pi42** | `com.delta.exchange`, `com.pi42.app` | Corresponding iOS bundles | INR-settled crypto futures platforms; extracts bank deposit UTRs, PAN KYC, and realized PnL ledgers. |

---

## 4. Step 2 — Sub-Engine 4.2B: `Binance` (`com.binance.dev`), `Bybit` & Global P2P Exchange Deep Decoder

### 4.1 Pillar 1: Extracting the Logged-In CEX Owner Profile & Historical Switched Accounts (`MMKV` + SQLite + JWT)

Inside `/data/user/<id>/com.binance.dev/` (and peer CEX sandboxes `com.bybit.app`, `com.kubi.kucoin`, `com.bitget.exchange`, `com.mexc.client`):

1. **Process All `MMKV` Files in `/files/mmkv/` via Phase 2, Module 2.3A:**
   * Remember: **Module 2.3A** extracts **Layer 1 (Active Keys)**, **Layer 2 (Superseded Overwritten Appends)**, and **Layer 3 (Unallocated Mmap Slack)**, and decrypts any AES-128-CFB encrypted `MMKV` store using the key/IV in its companion `.crc` file or Keystore!
   * Scan all decoded `MMKV` keys, `shared_prefs/*.xml`, SQLite tables, and unpacked JWT bearer tokens (`Module 2.4`) for:
     * **`userId` / `uid` / `bnc_uid`:** The suspect's **8-to-10 digit numeric Exchange UID** (e.g., `482910482`).
     * **`payId` / `merchantId`:** The suspect's **Binance Pay ID** and P2P Nickname.
     * **`email` & `mobile` / `phoneNumber`:** Registered login credentials.
     * **KYC Identity Object (`userKycInfo` / `certificateInfo`):**
       * `firstName`, `middleName`, `lastName` (Official verified legal name).
       * `country` / `nationality` (`"IN"`).
       * `idType` (`"PAN"`, `"AADHAAR"`, `"PASSPORT"`, `"DRIVING_LICENSE"`) & `idNumber` (exact 10-char PAN or Aadhaar/Passport number!).
       * `kycStatus` (`"PASS"` / `"VERIFIED"`) and `approveTime`.
     * **Saved P2P Fiat Payment Methods (`p2pPaymentMethods` / `userPaymentConfig`):**
       * Every Indian UPI VPA (`@ybl`, `@okaxis`), IMPS Bank Account Number + IFSC, or Digital eRupee (`CBDC`) wallet registered by the suspect inside their Binance/Bybit P2P settings to receive INR when selling USDT!
2. **Multi-Account Mule Switching Detection:**
   * If `MMKV` Layer 2 (Superseded Appends) or Layer 3 (Mmap Slack) or historical `-wal` frames contain a **different `userId` (`UID`)** than the currently logged-in account, flag a **`MULTIPLE_CEX_ACCOUNTS_OPERATED_ON_SAME_DEVICE`** alert and extract both accounts!

### 4.2 Pillar 2: Decoding P2P (`C2C`) Escrow Orders & In-Order Chat Transcripts

In `Binance`, `Bybit`, `KuCoin`, `Bitget`, and `Noones`, P2P order details and chat messages are stored across **local SQLite databases** (`/databases/*c2c*.db`, `*p2p*.db`, `*chat*.db`, `*im*.db`) AND **cached HTTP API JSON responses** inside `/cache/` and `app_webview/Default/Cache/Cache_Data/*_0` (decoded via **Module 2.4**):

1. **Match P2P Order API Endpoints & SQLite Tables:**
   * In HTTP/WebView caches (`webview_http_cache_records`) and `MMKV`/SQLite, filter for JSON objects or tables matching:
     * **Binance P2P (`C2C`):** `/bapi/c2c/v2/private/c2c/orderMatch/getUserOrderDetail`, `/orderList`, `/listUserOrderHistory`, `/bapi/c2c/v1/private/c2c/chat/`
     * **Bybit P2P (`OTC`):** `/x-api/fiat/otc/order/info`, `/order/list`, `/message/listpage`
     * **KuCoin / Bitget / MEXC P2P:** `*/otc/order/*`, `*/p2p/order/*`, `*/c2c/order/*`
2. **Extract the 12 Core P2P Order Fields:**
   * `orderNumber` / `orderId`: 19-to-20 digit P2P Order ID (e.g., `20594829104829104128`).
   * `tradeType`: **`BUY`** (Suspect paid INR via UPI/IMPS to acquire USDT/BTC) vs. **`SELL`** (Suspect sold USDT/BTC and received INR into their bank account).
   * `orderStatus`:
     * `COMPLETED` / `4` (Crypto released from escrow!)
     * `CANCELLED` / `2`
     * `APPEALING` / `DISPUTED` / `5` (Order frozen under P2P dispute—often because a bank account was frozen or payment was third-party!)
     * `TRADING` / `PAID_PENDING_RELEASE` / `1`
   * `asset` (`"USDT"`, `"BTC"`, `"ETH"`, `"FDUSD"`, `"BNB"`) & `amount` / `notifyTokenAmount` (Quantity of crypto, e.g., `5000.00 USDT`).
   * `fiatUnit` (`"INR"`, `"AED"`, `"USD"`) & `totalPrice` (Total fiat amount, e.g., `450000.00 INR`) & `unitPrice` (Exchange rate, e.g., `90.00 INR/USDT`).
   * `createTime` & `confirmPayEndTime` & `releaseTime` (13-digit Unix ms timestamps).
   * **Buyer & Seller Attribution:**
     * `buyerUserNo` / `buyerUid`, `buyerNickname`, **`buyerRealName`** (Verified KYC legal name of the buyer!).
     * `sellerUserNo` / `sellerUid`, `sellerNickname`, **`sellerRealName`** (Verified KYC legal name of the seller!).
   * **Selected Fiat Payment Method Object (`payMethod` / `tradeMethod`):**
     * Extracts the exact **`UPI VPA` (`fields` $\rightarrow$ `upiId`)**, **`Bank Account Number`**, **`IFSC Code`**, **`Bank Name`**, and **`Account Holder Name`** used to settle the Rupee side of the trade!
3. **Extract the P2P In-Order Escrow Chat Transcript (`c2c_chat_messages`):**
   * For every message exchanged between the Buyer and Seller inside the P2P order chat:
     * Extract `msgId`, `orderNo`, `fromUid`, `fromNickName`, `type` (`text`, `image`, `system`, `auto_reply`), `content` (message text or image URL / local cached image path in `/cache/`), and `createTime`.
     * **Automatic Regex & OCR Extraction on P2P Chat:**
       * Automatically extract any **10-digit Indian mobile number** (P2P traders almost always write *"Call me on 9876543210 before paying"* in the chat!), any **UPI VPA**, and any **12-digit NPCI `UTR` / `RRN` number** typed in the chat or printed inside an uploaded payment screenshot (via Phase 7 OCR)!

### 4.3 Pillar 3: On-Chain Withdrawals/Deposits vs. Off-Chain `Binance Pay` / Internal UID Transfers

Scan SQLite tables, `MMKV`, and cached JSON responses (`/bapi/capital/v1/private/capital/withdraw/history`, `/deposit/history`, `/bapi/pay/v1/private/binance-pay/transaction/list`) to extract:

1. **On-Chain Crypto Withdrawals & Deposits:**
   * `id` / `tranId`, `asset` (`USDT`), `network` (`TRX` \[TRC-20\], `BSC` \[BEP-20\], `ETH` \[ERC-20\], `MATIC`, `SOL`, `BTC`), `amount`, `transactionFee`, **`address` (the destination self-custody wallet address `T...` or `0x...`!)**, **`txId` (the 64-char public blockchain transaction hash!)**, and `applyTime`.
   * **Cross-Module Self-Custody Link:** Automatically check if the withdrawal destination `address` (`T...` or `0x...`) matches a wallet in **Module 4.1 (`web3_wallet_instances_and_accounts`)** on the same phone! If it matches, flag **`VERIFIED_CEX_TO_LOCAL_SELF_CUSTODY_WITHDRAWAL`**!
2. **Off-Chain Internal Transfers (`Binance Pay`, `Internal UID Transfer`, `Crypto Box / Red Packet`):**
   * `orderId` / `prepayId` / `internalTranId`: Off-chain transfer reference ID.
   * `transferMethod`: `BINANCE_PAY_C2C`, `INTERNAL_UID_EMAIL_PHONE_WITHDRAWAL`, `CRYPTO_BOX_RED_PACKET_SEND`, `CRYPTO_BOX_RED_PACKET_CLAIM`.
   * `payerInfo` & `receiverInfo`: Extracts the counterparty's **`Binance UID`**, **`Pay ID`**, **Nickname**, **Masked Email / Phone**, or **`Red Packet Grab Code`**!
   * `amount`, `currency` (`USDT`), `note` (user payment remark), and `transactionTime`.

---

## 5. Step 3 — Sub-Engine 4.2C: Domestic Indian `FIU-IND` Registered Exchanges (`CoinDCX`, `CoinSwitch`, `Mudrex`, `ZebPay`, `Flitpay`, `WazirX`, `Giottus`, `SunCrypto`)

In 2026, over 50 Virtual Digital Asset Service Providers (`VDA SPs`) are registered as Reporting Entities with **FIU-IND (Financial Intelligence Unit — India)** under the Prevention of Money Laundering Act (`PMLA`). Domestic Indian exchanges store three unique forensic artifacts that make law enforcement attribution and asset seizure straightforward:

### 5.1 Extracting Indian KYC, `PAN`, `1% VDA TDS` (Section 194S) & Linked Bank Accounts

For every domestic Indian exchange sandbox (`com.coindcx.btc`, `com.coinswitch.kuber`, `com.mudrex.app`, `zebpay.Application`, `com.flitpay.app`, `com.wrx.wazirx`, `com.giottus.app`, `com.suncrypto.in`, `com.delta.exchange`, `com.pi42.app`), process SQLite, `RKStorage`, `MMKV`, `shared_prefs`, and `app_webview` (`*_0`) caches:

1. **Mandatory Indian KYC & Tax Identifiers:**
   * **`pan_number_10_char`:** Exact 10-character Indian Income Tax PAN (`AAAAA9999A`, e.g., `ABCDE1234F`).
   * **`aadhaar_kyc_reference`:** Masked Aadhaar number (`XXXX-XXXX-1234`), DigiLocker / UIDAI e-KYC reference ID, and KYC verification timestamp.
   * **`penny_drop_verified_bank_accounts`:** Full unmasked **Bank Account Number**, **11-character IFSC Code** (resolve branch & city via Module 3.3 Section 8.2!), **Bank Name**, and penny-drop verification UTR!
2. **INR Fiat Deposit & Withdrawal Ledger:**
   * Extract every INR deposit (`IMPS`, `NEFT`, `RTGS`, `UPI`, `Bank Transfer`) and INR withdrawal (`bank_tx_id`, `utr_12_digit`, `amount_inr`, `status`, `timestamp`) and link directly to **Phase 3 (`unified_financial_transactions_ledger`)**.
3. **Section 194S `1% TDS` (Tax Deducted at Source) Transaction Audit:**
   * Every sell or crypto-to-crypto trade on an Indian exchange records `tds_amount_inr` (or `tds_usdt` at $1\%$ of trade value). Extracting the cumulative `tds_deducted_inr` and `total_turnover_inr` provides an instant, statutory calculation of the suspect's taxable VDA trading volume for Income Tax / Enforcement Directorate (`ED`) attachment!
4. **External Crypto Withdrawals & `Travel Rule` Declarations (`Mudrex`, `ZebPay`, `Flitpay`, `CoinDCX`):**
   * When a user withdraws crypto on-chain from a compliant Indian exchange to an external wallet, FIU-IND's **Travel Rule** requires the user to declare whether the destination wallet is a **`SELF_OWNED_UNHOSTED_WALLET`** or another **`VASP_EXCHANGE`** and provide the beneficiary's name! Extract every Travel Rule declaration JSON cached in the app's database or WebView cache!

---

## 6. Step 4 — Sub-Engine 4.2D: Browser & WebView CEX Session Harvester (`Chrome`, `Safari`, `Brave`, `app_webview`)

To catch suspects who use web browsers (rather than mobile apps) to access `Binance`, `Bybit`, `MEXC`, `KuCoin`, `Noones`, `Paxful`, or `LocalCoinSwap`:

1. Query **Phase 2, Module 2.4 (`webview_http_cache_records`, `webview_cookies_and_tokens`, `webview_autofill_and_storage`)** and **Group 6 (Browser History / Cookies / Local Storage)** across all browsers (`com.android.chrome`, `com.brave.browser`, `org.mozilla.firefox`, `org.torproject.torbrowser`, `MobileSafari`) for domains matching:
   * `*binance.*`, `*bybit*`, `*kucoin.*`, `*mexc.*`, `*gate.io*`, `*bitget.*`, `*htx.*`, `*huobi.*`, `*bingx.*`, `*okx.*`, `*noones.*`, `*paxful.*`, `*localcoinswap.*`, `*coindcx.*`, `*wazirx.*`, `*mudrex.*`, `*flitpay.*`, `*zebpay.*`.
2. Automatically unpack any **JWT Bearer Token** (`is_jwt_token == 1` in Module 2.4) from those domains to extract the suspect's `user_id` (`UID`), `email`, and login `iat` timestamp, and feed any cached P2P or withdrawal JSON responses into Sub-Engine 4.2B!

---

## 7. Database Schema for Module 4.2 (`cex_and_p2p_exchange_engine.sqlite`)

The developer must create the following four tables in the case database:

### Table 1: `cex_exchange_accounts_and_kyc_profiles` (All Discovered Global & Indian CEX Accounts)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `cex_account_uid` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Unique row ID. |
| `exchange_name` | `TEXT` | `NOT NULL` | E.g., `"Binance"`, `"Bybit"`, `"KuCoin"`, `"MEXC"`, `"Noones"`, `"CoinDCX"`, `"Mudrex"`, `"ZebPay"`, `"Flitpay"`. |
| `fiu_ind_compliance_tier` | `TEXT` | `NOT NULL` | Enum: `INDIAN_DOMESTIC_FIU_REGISTERED`, `GLOBAL_FIU_REGISTERED_VASP`, `OFFSHORE_UNREGISTERED_CEX_OR_P2P`. |
| `app_instance_id` | `INTEGER` | `NULL` | Foreign key to Module 1.3 (`NULL` if accessed via Browser/PWA). |
| `source_vfs_file_id` | `INTEGER` | `NOT NULL` | Source `MMKV`, `.db`, `RKStorage`, or `*_0` cache file in `vfs_index`. |
| `recovery_classification` | `TEXT` | `NOT NULL` | Mandatory 6-State Enum (`ORIGINAL_RECORD`, `HISTORICAL_COMMITTED_RECORD` \[`MMKV` Layer 2 / `-wal`\], `RESIDUAL_RECORD` \[`MMKV` Slack / Freelist\]). |
| `cex_user_uid` | `TEXT` | `NOT NULL` | **Immutable Exchange User ID (`UID`, e.g., Binance 9-digit `482910482`)** for Law Enforcement freeze requests! Indexed! |
| `binance_pay_id_or_nick` | `TEXT` | `NULL` | `Binance Pay ID` or P2P Merchant Nickname. |
| `kyc_verified_full_name` | `TEXT` | `NULL` | Official KYC legal name registered on the exchange. |
| `indian_pan_10_char` | `TEXT` | `NULL` | 10-character Indian Income Tax `PAN` (`AAAAA9999A`). Indexed! |
| `aadhaar_or_passport_id` | `TEXT` | `NULL` | Masked Aadhaar (`XXXX-1234`) or Passport/DL number. |
| `registered_email` | `TEXT` | `NULL` | Account email address. |
| `registered_mobile_phone` | `TEXT` | `NULL` | Account mobile phone number. |
| `linked_indian_banks_vpas_json` | `TEXT` | `NULL` | JSON array of linked Bank Account Numbers + IFSCs and UPI VPAs configured for P2P or INR deposits/withdrawals! |
| `cached_spot_funding_balances` | `TEXT` | `NULL` | JSON dictionary of cached CEX balances (`Spot`, `Funding`, `Futures`). |
| `last_active_utc_iso` | `TEXT` | `NULL` | Normalized UTC ISO-8601 timestamp. |

### Table 2: `cex_p2p_escrow_orders_ledger` (All P2P / C2C Fiat-to-Crypto Orders & Triangulation Audits)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `p2p_order_uid` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Unique row ID. |
| `cex_account_uid` | `INTEGER` | `NULL` | Foreign key to `cex_exchange_accounts_and_kyc_profiles.cex_account_uid`. |
| `exchange_name` | `TEXT` | `NOT NULL` | E.g., `"Binance P2P"`, `"Bybit P2P"`, `"KuCoin P2P"`, `"Noones P2P"`. |
| `source_vfs_file_id` | `INTEGER` | `NOT NULL` | Source `.db`, `MMKV`, or `*_0` HTTP cache file in `vfs_index`. |
| `recovery_classification` | `TEXT` | `NOT NULL` | 6-State Enum (`ORIGINAL_RECORD`, `HISTORICAL_COMMITTED_RECORD`, `RESIDUAL_RECORD`). |
| `p2p_order_number` | `TEXT` | `NOT NULL` | **19-to-20 digit P2P Order ID (e.g., `20594829104829104128`). Indexed!** |
| `trade_direction` | `TEXT` | `NOT NULL` | Enum: `BUY_CRYPTO_PAID_FIAT`, `SELL_CRYPTO_RECEIVED_FIAT`. |
| `order_status` | `TEXT` | `NOT NULL` | Enum: `COMPLETED_RELEASED`, `CANCELLED`, `APPEAL_DISPUTED`, `IN_ESCROW_PENDING`. |
| `crypto_asset` | `TEXT` | `NOT NULL` | E.g., `"USDT"`, `"BTC"`, `"FDUSD"`, `"ETH"`. |
| `crypto_quantity_decimal` | `REAL` | `NOT NULL` | Quantity of crypto bought or sold (e.g., `5000.00`). |
| `fiat_currency` | `TEXT` | `NOT NULL` | E.g., `"INR"`, `"AED"`, `"USD"`. |
| `fiat_total_amount` | `REAL` | `NOT NULL` | Total fiat amount (e.g., `450000.00` INR). |
| `unit_exchange_rate` | `REAL` | `NULL` | Price per 1 unit of crypto (e.g., `90.00` INR/USDT). |
| `counterparty_cex_uid_nick` | `TEXT` | `NULL` | Counterparty's CEX UID and P2P nickname. |
| `counterparty_verified_kyc_name` | `TEXT` | `NULL` | Counterparty's real KYC legal name (`buyerRealName` / `sellerRealName`). |
| `fiat_payment_rail` | `TEXT` | `NULL` | `UPI`, `IMPS`, `BANK_TRANSFER`, `DIGITAL_ERUPEE_CBDC`, `AMAZON_GIFT_CARD`. |
| `counterparty_vpa_or_bank_ifsc` | `TEXT` | `NULL` | **Counterparty's exact UPI VPA (`@ybl`/`@okaxis`) or Bank Account No + IFSC!** |
| `extracted_utr_or_giftcard_code` | `TEXT` | `NULL` | **12-digit NPCI UPI/IMPS `UTR` or Gift Card code extracted from order/chat! Indexed!** |
| `is_third_party_payer_mismatch` | `INTEGER` | `DEFAULT 0` | **`1` if CEX Owner KYC Name $\neq$ Phase 3 Bank Payer Name (Triangulation Fraud Alert)!** |
| `order_created_utc_iso` | `TEXT` | `NOT NULL` | Normalized UTC ISO-8601 timestamp. |
| `order_completed_utc_iso` | `TEXT` | `NULL` | Normalized UTC ISO-8601 escrow release timestamp. |

### Table 3: `cex_p2p_in_order_chat_messages` (Verbatim Escrow Chat Messages, Shared Phone Numbers & Receipt Images)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `p2p_chat_uid` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Unique row ID. |
| `p2p_order_number` | `TEXT` | `NOT NULL` | Joins to `cex_p2p_escrow_orders_ledger.p2p_order_number`. |
| `exchange_name` | `TEXT` | `NOT NULL` | Exchange name. |
| `sender_uid_and_nickname` | `TEXT` | `NULL` | Sender CEX UID and nickname. |
| `message_type` | `TEXT` | `NOT NULL` | `TEXT`, `IMAGE_RECEIPT`, `SYSTEM_PROMPT`, `AUTO_REPLY`. |
| `message_text_or_image_url` | `TEXT` | `NOT NULL` | Chat message text or uploaded receipt image path/URL. |
| `extracted_phone_utr_or_vpa` | `TEXT` | `NULL` | Automatically extracted 10-digit phone number, 12-digit UTR, or VPA inside the chat message! |
| `sent_utc_iso` | `TEXT` | `NOT NULL` | Normalized UTC ISO-8601 timestamp. |
| `recovery_classification` | `TEXT` | `NOT NULL` | 6-State Enum (`ORIGINAL_RECORD`, `HISTORICAL_COMMITTED_RECORD`, `RESIDUAL_RECORD`). |

### Table 4: `cex_withdrawals_deposits_and_internal_pay` (On-Chain Withdrawals, Off-Chain `Binance Pay` & Indian `1% TDS` Logs)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `cex_transfer_uid` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Unique row ID. |
| `cex_account_uid` | `INTEGER` | `NULL` | Foreign key to `cex_exchange_accounts_and_kyc_profiles.cex_account_uid`. |
| `exchange_name` | `TEXT` | `NOT NULL` | E.g., `"Binance"`, `"Bybit"`, `"CoinDCX"`, `"Mudrex"`. |
| `transfer_category` | `TEXT` | `NOT NULL` | Enum: `ONCHAIN_CRYPTO_WITHDRAWAL`, `ONCHAIN_CRYPTO_DEPOSIT`, `OFFCHAIN_BINANCE_PAY_OR_UID_TRANSFER`, `CRYPTO_BOX_RED_PACKET`, `INDIAN_FIAT_INR_DEPOSIT_WITHDRAWAL`, `VDA_SPOT_TRADE_WITH_1PCT_TDS`. |
| `asset_or_currency` | `TEXT` | `NOT NULL` | E.g., `"USDT"`, `"BTC"`, `"INR"`. |
| `network_or_rail` | `TEXT` | `NULL` | `TRC20`, `BEP20`, `ERC20`, `BINANCE_PAY_INTERNAL`, `IMPS`, `UPI`. |
| `amount_decimal` | `REAL` | `NOT NULL` | Transfer or trade amount. |
| `tds_1pct_deducted_inr` | `REAL` | `NULL` | **Indian Section 194S `1% TDS` deducted in INR (for domestic FIU-IND exchanges)!** |
| `txid_or_internal_pay_order_id` | `TEXT` | `NOT NULL` | 64-char on-chain `txid`, 18-digit `Binance Pay ID`, `Red Packet Code`, or 12-digit bank `UTR`. Indexed! |
| `destination_wallet_or_peer_uid` | `TEXT` | `NULL` | Destination `T...`/`0x...` address, recipient `Binance UID`, or Travel Rule beneficiary name. |
| `matches_local_web3_wallet_uid` | `INTEGER` | `NULL` | **Foreign key to Module 4.1 `web3_wallet_instances_and_accounts.web3_account_uid` if withdrawn to a self-custody wallet on this same phone!** |
| `transfer_utc_iso` | `TEXT` | `NOT NULL` | Normalized UTC ISO-8601 timestamp. |
| `recovery_classification` | `TEXT` | `NOT NULL` | 6-State Enum (`ORIGINAL_RECORD`, `HISTORICAL_COMMITTED_RECORD`, `RESIDUAL_RECORD`). |

---

## 8. Developer Acceptance Test Checklist for Module 4.2

1. **The `Binance` `MMKV` Layer-2 Account-Switch & P2P WebView Cache Test:**
   * Populate a test `/com.binance.dev/files/mmkv/` store where Layer 1 (Active) has `userId = "482910482"` (`kycName = "RAHUL SHARMA"`) and Layer 2 (Superseded Append) has an earlier logged-out mule account `userId = "991122334"`, plus a Brotli-compressed `*_0` cache file for `/bapi/c2c/v2/private/c2c/orderMatch/getUserOrderDetail` (`orderNumber = "20594829104829104128"`, `amount = "2000.00"`, `totalPrice = "180000.00"`, `upiId = "seller99@okaxis"`).
   * Verify that Sub-Engine 4.2B extracts both `userId`s (flagging the historical account switch as `HISTORICAL_COMMITTED_RECORD`), decompresses the P2P order JSON, and extracts the P2P order and `seller99@okaxis` VPA!
2. **The P2P In-Order Chat Phone/UTR Extractor & Third-Party Payer Triangulation Test:**
   * Insert a P2P chat message `"Paid Rs 1,80,000 from my brother's account, UTR 630914829104, call me on 9811223344"` where the Binance account KYC name is `"RAHUL SHARMA"` (`cex_owner_kyc_name`) but the matched Phase 3 UPI transaction for UTR `630914829104` was debited from an account owned by `"AMIT VERMA"`.
   * Verify that Sub-Engine 4.2B extracts `9811223344` and `630914829104` from the chat and sets `is_third_party_payer_mismatch = 1`!
3. **The Off-Chain `Binance Pay` vs. On-Chain `TRC-20` Self-Custody Link Test:**
   * Insert one off-chain `Binance Pay` transfer (`orderId = "291827364519283746"`, `receiverUid = "554433221"`, `amount = 500 USDT`) and one on-chain `TRC-20` withdrawal (`txId = "a1b2c3..."`, `address = "TXYZopYRdj2D9XRtbG411XZZ3kM5VkAeBf"`, `amount = 1500 USDT`) where `TXYZ...` is present in Module 4.1's `TronLink Pro` table on the same phone.
   * Verify that Sub-Engine 4.2B records the off-chain Binance Pay transfer and automatically populates `matches_local_web3_wallet_uid` on the on-chain withdrawal!
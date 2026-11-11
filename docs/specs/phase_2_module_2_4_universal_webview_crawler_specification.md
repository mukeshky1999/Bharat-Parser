# Engineering Specification: Phase 2, Module 2.4 — The Universal Embedded WebView (`app_webview` & `WKWebView`) Crawler, Chromium Simple Cache Parser, Apple `binarycookies` Decoder & `Cache.db` Correlator

**Document Purpose:** This document provides the complete, byte-level architectural blueprint for building **Module 2.4** of the Forensic Data Parser. It contains **zero programming code** and explains every binary structure, byte offset, endianness switch, compression format, and database join from first principles so that a developer with no prior forensic experience can build an automated crawler that extracts hidden web activity, cached JSON API responses, form autofill inputs, session cookies, and JWT authentication tokens from inside every third-party mobile application.

---

## 1. Purpose & Mental Model (Why Embedded WebViews Are the Biggest Blind Spot in Commercial Forensics)

When an investigator examines a smartphone using standard forensic suites, the tool parses the device's main web browsers (Safari on iOS and Google Chrome on Android). However, **on a modern smartphone, over $70\%$ of web and HTTP/HTTPS interactions never happen inside Chrome or Safari.**

Instead, almost every third-party mobile application embeds its own private, miniature web browser engine directly inside its application sandbox:
* On **Android**, the operating system provides the Chromium-based `WebView` engine, which creates a private folder named **`app_webview/`** (or `app_chrome/` / `app_xwalkcore/`) inside `/data/user/<user_id>/<package_name>/`.
* On **iOS**, the operating system provides `WKWebView` and `NSURLCache`, which create private folders inside `<App-Data-UUID>/Library/WebKit/`, `<App-Data-UUID>/Library/Cookies/`, and `<App-Data-UUID>/Library/Caches/<BundleID>/`.

### What Criminals and Suspects Unknowingly Leave Inside Embedded WebViews
Because developers build hybrid mobile apps using embedded web views for speed and cross-platform compatibility, crawling `app_webview` and `WKWebView` across every installed app uncovers evidence that does not exist anywhere else on the phone:
1. **Indian UPI & Banking Payment Gateways:** When a suspect makes a payment or launders money through an app using **Razorpay, BillDesk, Paytm Payment Gateway, Cashfree, or CCAvenue**, the checkout and OTP redirect screens execute inside the app's `app_webview`—leaving behind autofill VPA handles, card numbers, session cookies, and cached JSON transaction receipts!
2. **In-App Browsers Inside Messengers (`WhatsApp`, `Telegram`, `Instagram`, `Facebook`):** When a suspect clicks a phishing link, a darknet market mirror, a crypto drainer link, or a Telegram **Mini-App / WebApp bot** inside a chat, the link opens inside the messenger's private `app_webview` / `WKWebView` rather than Chrome or Safari.
3. **Web3 & Cryptocurrency DApp Browsers (`MetaMask`, `Trust Wallet`, `Phantom`, `TronLink`):** Every decentralized exchange (Uniswap, SunSwap, PancakeSwap) and illicit token-swap portal accessed by a suspect inside a crypto wallet's built-in DApp browser is recorded inside that wallet's `app_webview` cache, `Local Storage`, and `IndexedDB`.
4. **Illicit Betting, Hawala & Loan-Shark Portals (`Lotus365`, `Aviator`, `Mahadev`-style PWAs):** Many illegal betting and predatory loan apps are thin wrappers around an embedded `app_webview`. Their entire transaction ledger, user balance, and agent WhatsApp numbers sit inside `app_webview/Default/Cache/Cache_Data/` and `Local Storage/leveldb/`!

---

## 2. The 6 Fatal Mistakes Beginner Developers Make in WebView Forensics

Before implementing Module 2.4, the developer must understand six classic traps that cause amateur tools to miss or corrupt WebView artifacts:

### Mistake 1: Looking Only in `/app_webview/Default/Cookies` and Missing the Chromium 96+ `Network/` Subfolder
* **The Trap:** Hardcoding the path `/data/user/0/<pkg>/app_webview/Default/Cookies` or `/data/user/0/<pkg>/app_webview/Cookies`.
* **Why It Fails:** Google changed the directory hierarchy of Android `app_webview` three times across Android 9 through Android 17:
  * **Generation 1 (Legacy Android WebView):** Files lived directly in `/app_webview/Cookies` and `/app_webview/Cache/`.
  * **Generation 2 (Chromium 80–95):** Files moved into a profile subfolder: `/app_webview/Default/Cookies` and `/app_webview/Default/Cache/`.
  * **Generation 3 (Chromium 96–135+ / Modern Android 12–17):** Network-related files moved into a deeper `Network/` subdirectory (`/app_webview/Default/Network/Cookies` and `/app_webview/Default/Network/TransportSecurity`) and cache files moved into `/app_webview/Default/Cache/Cache_Data/`!
* **The Rule:** Never hardcode a single relative path inside `app_webview`. Use the **Relative Sub-Tree Scanner** specified in Section 3.1.

### Mistake 2: Reading Chromium Simple Cache (`*_0`) Files Forward Only and Missing Stream 0 (HTTP Headers)
* **The Trap:** Opening a Chromium Simple Cache file (e.g., `f8a3c1b20049d812_0`) from Byte $0$, reading the URL string, and trying to scan forward for the HTTP headers.
* **Why It Fails:** Chromium's **Simple Cache (`SimpleEntryFormat v5`)** stores two separate data streams inside a single `*_0` file, and it locates them by **reading backward from the End-Of-File (`EOF`)**:
  * **Stream 0 (HTTP Response Headers & Timestamps)** is stored at the **very end of the `*_0` file**, immediately before the final 24-byte `SimpleFileEOF` footer!
  * **Stream 1 (The HTTP Response Body: JSON, HTML, Image)** is stored in the **middle of the `*_0` file**, between the URL header at the start of the file and Stream 0 at the end of the file!
* **The Rule:** Always parse `*_0` cache files from both ends (Header at Offset $0$, Stream 0 EOF at `file_size - 24`) using the exact byte math in Section 4.

### Mistake 3: Forgetting to Decompress Brotli (`br`), Gzip (`gzip`), or Zstd (`zstd`) HTTP Cache Bodies
* **The Trap:** Extracting the Stream 1 HTTP response body from `*_0` or iOS `Cache.db`, seeing binary bytes instead of readable text, and classifying it as "Opaque Binary Data."
* **Why It Fails:** Over $90\%$ of modern REST API JSON responses and HTML pages cached by `app_webview` and `NSURLCache` are compressed over the network using **Brotli (`Content-Encoding: br`)**, **Gzip (`Content-Encoding: gzip`)**, or **Zstandard (`Content-Encoding: zstd`)**!
* **The Rule:** Always inspect the decoded HTTP Response Headers (and magic bytes of the Stream 1 body) and automatically decompress `gzip`, `deflate`, `br` (Brotli), and `zstd` payloads so that cached JSON API responses become readable plaintext!

### Mistake 4: Failing to Switch From Big-Endian to Little-Endian Inside Apple's `Cookies.binarycookies`
* **The Trap:** Reading an iOS `Cookies.binarycookies` file using Big-Endian integers throughout the entire file, or Little-Endian throughout the entire file.
* **Why It Crashes:** Apple's `Cookies.binarycookies` format is famously **hybrid-endian**:
  * The **File Header** (magic `"cook"`, page count, and array of page byte sizes) uses **32-Bit Big-Endian (`uint32_be`)** integers.
  * The **Page Header** starts with a Big-Endian magic tag (`00 00 01 00`), and then **switches on Byte 4 of the page to 32-Bit Little-Endian (`uint32_le`) and 64-Bit Little-Endian IEEE-754 Floats (`float64_le`)** for all cookie counts, offsets, flags, and Cocoa timestamps!
* **The Rule:** Follow the exact byte-by-byte endianness table in Section 5.

### Mistake 5: Missing External `fsCachedData/<UUID>` Payloads When Parsing iOS `Cache.db`
* **The Trap:** Querying `SELECT receiver_data FROM cfurl_cache_receiver_data;` inside an iOS app's `Library/Caches/<BundleID>/Cache.db` and assuming `receiver_data` always contains the cached image or JSON response.
* **Why It Fails:** In iOS `Cache.db`, if a cached HTTP response is smaller than $\approx 16\text{ KB}$, iOS sets `isDataOnFS = 0` and stores the payload bytes directly inside `receiver_data`. However, if the response is larger than $\approx 16\text{ KB}$ (such as a full transaction history JSON, a high-res QR code, or a profile photo), iOS sets **`isDataOnFS = 1`** and stores only a **36-character ASCII UUID string** inside `receiver_data`! The actual file payload sits in an external file at `Library/Caches/<BundleID>/fsCachedData/<UUID>`.
* **The Rule:** Always check `isDataOnFS` in `cfurl_cache_receiver_data` and automatically join `receiver_data` to the matching file inside `fsCachedData/` via `vfs_index` (Section 6).

### Mistake 6: Ignoring the 1-Byte Encoding Prefix on Chromium `Local Storage` Strings
* **The Trap:** Decoding Chromium `Local Storage/leveldb/` keys and values directly as UTF-8 strings.
* **Why It Fails:** Chromium prefixes every `Local Storage` and `Session Storage` value (and sub-key) inside LevelDB with a **1-byte character encoding tag**:
  * `0x00`: **UTF-16LE** (2 bytes per character — used whenever the string contains non-ASCII characters like the Indian Rupee symbol `₹` or Devanagari script!).
  * `0x01`: **Latin-1 / ISO-8859-1 / ASCII** (1 byte per character).
* **The Rule:** Strip Byte $0$ of the `Local Storage` value and decode the remaining bytes as UTF-16LE (if Byte $0 == \text{0x00}$ and even length with null high bytes) or Latin-1/UTF-8 (if Byte $0 == \text{0x01}$).

---

## 3. Step 1 — Automated Discovery of All Embedded WebView Sandboxes

Module 2.4 iterates through every application instance in **Module 1.3's `resolved_application_catalog` (`app_storage_mounts`)** across every user profile (`0`, `10`, `95`, `150`, `999`) and scans `vfs_index` for WebView storage roots.

### 3.1 Android WebView Target Discovery Matrix
For every Android application mount (`ANDROID_CE_SANDBOX` and `ANDROID_DE_SANDBOX`), query `vfs_index` for any subdirectory matching `*/app_webview/*`, `*/app_chrome/*`, `*/app_xwalkcore/*`, or `*/cache/WebView/*` and classify discovered files into five target buckets:

| Bucket ID | Target File Pattern in `vfs_index` | Storage Format | Forensic Evidence Contained |
|---|---|---|---|
| **A1** | `.../Cookies` (in `app_webview/`, `Default/`, or `Default/Network/`) | **SQLite 3** (`+ -wal`) | Session cookies, authentication tokens, tracking IDs, and exact first-creation and last-access timestamps per domain. |
| **A2** | `.../Web Data` & `.../History` | **SQLite 3** (`+ -wal`) | `autofill` table (every form field name, VPA, phone number, or username typed in a WebView), `credit_cards`, and visited URLs. |
| **A3** | `.../Local Storage/leveldb/*` & `.../Session Storage/*` | **Google LevelDB** | Persistent key-value pairs per web origin (`https://...`), cached user profiles, wallet addresses, and **JWT Bearer tokens**. |
| **A4** | `.../IndexedDB/*.indexeddb.leveldb/*` & `*.indexeddb.blob/*` | **LevelDB + V8 Blink** | Structured client-side NoSQL databases for WebApps, Telegram Mini-Apps, crypto wallets, and PWAs. |
| **A5** | `.../Cache/Cache_Data/*_0`, `*_1`, `*_s` (or `.../Cache/*_0`) | **Chromium Simple Cache** | Full HTTP/HTTPS request URLs, response headers, server timestamps, and cached JSON/HTML/image response bodies. |

### 3.2 iOS WebKit & `NSURLCache` Target Discovery Matrix
For every iOS application mount (`IOS_DATA_SANDBOX` and `IOS_SHARED_APP_GROUP`), query `vfs_index` for:

| Bucket ID | Target File Pattern in `vfs_index` | Storage Format | Forensic Evidence Contained |
|---|---|---|---|
| **I1** | `.../Library/Cookies/Cookies.binarycookies` | **Apple Binary Cookies** | All HTTP/HTTPS cookies persisted by the app's networking layer and `UIWebView`/`WKWebView`. |
| **I2** | `.../Library/WebKit/WebsiteData/Default/<OriginHash>/Cookies/` or `.../WKHTTPCookieStore` | **Binary Cookies / Plist** | Isolated per-origin `WKWebView` cookie stores on iOS 14–26. |
| **I3** | `.../Library/Caches/*/Cache.db` + `.../fsCachedData/*` | **SQLite 3 + External Blobs** | Apple `NSURLCache` database storing API request URLs, binary plist response headers, and inline or external response bodies. |
| **I4** | `.../Library/WebKit/WebsiteData/LocalStorage/*` (`*.localstorage` or `leveldb/`) | **SQLite 3 or LevelDB** | Origin-specific `localStorage` key-value pairs (`ItemTable` with `key` and UTF-16LE `value` BLOB). |
| **I5** | `.../Library/WebKit/WebsiteData/IndexedDB/*` (`IndexedDB.sqlite3`) | **SQLite 3 (`Records` table)** | iOS WebKit stores `IndexedDB` inside SQLite files named `IndexedDB.sqlite3` (`Records`, `ObjectStoreInfo`, `DatabaseInfo`), unlike Android's LevelDB! |
| **I6** | `.../Library/WebKit/WebsiteData/ResourceLoadStatistics/observations.db` | **SQLite 3** (`+ -wal`) | iOS Intelligent Tracking Prevention (ITP) database logging every domain (`ObservedDomains`) the app contacted, with exact `lastSeen` Cocoa timestamps! |

---

## 4. Step 2 — Sub-Engine 2.4A: Chromium `Simple Cache` (`*_0`, `*_1`, `*_s`) Binary Parser

Android `app_webview` (and Chrome) uses Chromium's **Simple Cache (`SimpleEntryFormat v5`)** inside `Cache/Cache_Data/`. Instead of packing all cache entries into block files like desktop Windows Chrome (`data_1`, `data_2`), Simple Cache creates **individual files named after a 16-character hexadecimal hash followed by an underscore and a stream number**:
* **`<16_hex_hash>_0`**: Contains the **Initial File Header**, the **Full Request URL / Cache Key**, **Stream 1 (The HTTP Response Body)**, and **Stream 0 (The HTTP Response Headers)**!
* **`<16_hex_hash>_1`**: Created only when Stream 1 (or Stream 2, such as V8 compiled JS bytecode) is stored separately for very large files.
* **`<16_hex_hash>_s`**: Sparse range data (for chunked video/audio streaming).

### 4.1 Step-by-Step Binary Layout of a `<16_hex_hash>_0` File

To parse a `<16_hex_hash>_0` file of total size $F\text{ bytes}$, the developer must read from **both the start of the file (Offset $0$)** and **the end of the file (Offset $F$)**:

#### Phase 1: Read the 24-Byte `SimpleFileHeader` at Byte Offset $0$
1. **Bytes $0\text{–}7$ (`initial_magic_number`, `uint64_le`):**
   * Must equal `0xfcfb6d1ba7725c30` (on disk in little-endian hex: **`30 5C 72 A7 1B 6D FB FC`**). If those 8 bytes do not match, skip the file.
2. **Bytes $8\text{–}11$ (`format_version`, `uint32_le`):** Typically `5`.
3. **Bytes $12\text{–}15$ (`key_length`, `uint32_le`):** Exact byte length $K$ of the cache key / URL string that immediately follows Byte $23$!
4. **Bytes $16\text{–}19$ (`key_hash`, `uint32_le`):** SuperFastHash of the key.
5. **Bytes $20\text{–}23$ (`padding`, `uint32_le`).**
6. **Bytes $24\text{ through } (24 + K - 1)$ (`raw_cache_key_string`):**
   * Read $K$ UTF-8 bytes.
   * **Note on Modern Chromium Network Isolation Keys (`1/0/` and `_dk_` prefixes):** In modern Chromium (Android 12–17), the cache key looks like:
     `1/0/_dk_https://phonepe.com https://phonepe.com https://api.phonepe.com/apis/v3/transaction/status`
   * Parse the final space-delimited URL as the **`request_url`**, and parse the preceding `_dk_` domains as the **`top_level_initiator_origin`**!

#### Phase 2: Read Backward from `EOF` ($F$) to Locate Stream 0 (HTTP Headers)
Every stream inside a Simple Cache file ends with a **24-Byte `SimpleFileEOF` Record**:
* **Structure of a 24-Byte `SimpleFileEOF` Record:**
  * **Bytes $0\text{–}7$ (`final_magic_number`, `uint64_le`):** Must equal `0xf4fa6f45970d41d8` (on disk in little-endian hex: **`D8 41 0D 97 45 6F FA F4`**).
  * **Bytes $8\text{–}11$ (`eof_flags`, `uint32_le`):**
    * Bit 0 (`flags & 1`): `FLAG_HAS_CRC32` (indicates `data_crc32` is valid).
    * Bit 1 (`flags & 2`): `FLAG_HAS_KEY_SHA256` (if this bit is set, a **32-byte SHA-256 hash of the cache key** sits *immediately before* this 24-byte `SimpleFileEOF` record!).
  * **Bytes $12\text{–}15$ (`data_crc32`, `uint32_le`):** CRC-32 checksum of the stream data.
  * **Bytes $16\text{–}19$ (`stream_size`, `uint32_le`):** Exact byte length $S_0$ of this stream's payload!
  * **Bytes $20\text{–}23$ (`padding`, `uint32_le`).**

* **Exact Backward Offset Math for Stream 0 (HTTP Headers):**
  1. Seek to `eof_0_offset = F - 24` and read the 24-byte `SimpleFileEOF` record for Stream 0.
  2. Verify `final_magic_number == 0xf4fa6f45970d41d8` and read `stream_0_size` ($S_0$) and `eof_0_flags`.
  3. Check Bit 1 of `eof_0_flags`:
     * If `(eof_0_flags & 2) != 0`, set `sha256_len = 32`; else set `sha256_len = 0`.
  4. Calculate the exact byte range of **Stream 0 (The `HttpResponseInfo` Header Pickle)**:
     $$\text{stream\_0\_end} = F - 24 - \text{sha256\_len}$$
     $$\text{stream\_0\_start} = \text{stream\_0\_end} - S_0$$
  5. Read `stream_0_bytes = buf[stream_0_start : stream_0_end]`.

#### Phase 3: Locate Stream 1 (The HTTP Response Body)
Immediately before `stream_0_start` sits the **24-byte `SimpleFileEOF` Record for Stream 1**!
1. Seek to `eof_1_offset = stream_0_start - 24` and read the 24-byte `SimpleFileEOF` record for Stream 1.
2. Verify `final_magic_number == 0xf4fa6f45970d41d8` and read `stream_1_size` ($S_1$).
3. If $S_1 > 0$:
   * The exact byte range of **Stream 1 (The Cached HTTP Body: JSON, HTML, Image)** inside `<16_hex_hash>_0` is:
     $$\text{stream\_1\_start} = 24 + K \quad (\text{right after the URL key!})$$
     $$\text{stream\_1\_end} = \text{stream\_1\_start} + S_1 = \text{eof\_1\_offset}$$
   * Read `stream_1_body_bytes = buf[stream_1_start : stream_1_end]`.
4. *(Note: If $S_1 == 0$ inside `*_0`, check `vfs_index` for a companion file named `<16_hex_hash>_1`, which starts with its own 24-byte `SimpleFileHeader` + $K\text{-byte}$ URL key, followed immediately by the Stream 1 body bytes up to `F - 24`!)*

### 4.2 Decoding Stream 0 (`HttpResponseInfo` Chromium Pickle)
Stream 0 is serialized using Chromium's 32-bit aligned **`base::Pickle`** format:
1. **Bytes $0\text{–}3$ (`pickle_payload_size`, `uint32_le`).**
2. **Bytes $4\text{–}7$ (`flags_and_version`, `uint32_le`).**
3. **Bytes $8\text{–}15$ (`request_time_webkit_us`, `int64_le`):** Exact timestamp when the app sent the HTTP request (in **WebKit Microseconds since `1601-01-01 00:00:00 UTC`**! Convert via Module 1.2: $\text{Unix Seconds} = (\text{us} / 10^6) - 11644473600$).
4. **Bytes $16\text{–}23$ (`response_time_webkit_us`, `int64_le`):** Exact timestamp when the app received the HTTP response!
5. **Bytes $24\text{–}27$ (`raw_headers_byte_len`, `uint32_le`):** Byte length $H_{\text{len}}$ of the raw HTTP status and response headers block.
6. **Bytes $28\text{ through } (28 + H_{\text{len}} - 1)$ (`raw_http_headers_block`):**
   * In Chromium's `HttpResponseHeaders` format, individual header lines are separated by **Null Bytes (`0x00`)** rather than `\r\n`!
   * Split `raw_http_headers_block` on `0x00`:
     * Element 0 is the **HTTP Status Line** (e.g., `"HTTP/1.1 200 OK"`).
     * Elements $1 \dots M$ are the **`Header-Name: Header-Value`** lines (e.g., `"content-type: application/json"`, `"content-encoding: br"`, `"set-cookie: session_id=xyz..."`).

### 4.3 Decompressing & Classifying Stream 1 (The Cached HTTP Body)
Inspect the extracted `Content-Encoding` header and the first $4\text{ bytes}$ of `stream_1_body_bytes`:
1. If `Content-Encoding` is `"gzip"` (or Bytes $0\text{–}2$ equal `1F 8B 08`): Decompress using **GZIP**.
2. If `Content-Encoding` is `"deflate"`: Decompress using **Zlib / Raw Deflate**.
3. If `Content-Encoding` is `"br"`: Decompress using **Brotli**.
4. If `Content-Encoding` is `"zstd"` (or Bytes $0\text{–}3$ equal `28 B5 2F FD`): Decompress using **Zstandard**.
5. Once decompressed, inspect the payload:
   * If `Content-Type` contains `"json"` or payload starts with `{` or `[`: Store as searchable JSON text in `webview_http_cache_records` (and pass to Phase 3/4/5 financial/crypto/chat correlators!).
   * If `Content-Type` contains `"image/"` or magic bytes match JPEG (`FF D8 FF`), PNG (`89 50 4E 47`), WebP (`RIFF....WEBP`), or HEIC: Register the cached image in Phase 7's **Visual Residuals & QR/OCR Pipeline**!

---

## 5. Step 3 — Sub-Engine 2.4B: Apple `Cookies.binarycookies` Hybrid-Endian Decoder

On iOS, every application stores HTTP/HTTPS cookies inside `<App-UUID>/Library/Cookies/Cookies.binarycookies` (and `Library/WebKit/WebsiteData/...`).

### 5.1 Step-by-Step Binary Layout of `Cookies.binarycookies`

#### Phase 1: Parse the File Header (Big-Endian!)
1. **Bytes $0\text{–}3$ (`file_magic`, ASCII):** Must equal **`63 6F 6F 6B`** (`"cook"` in ASCII).
2. **Bytes $4\text{–}7$ (`num_pages`, `uint32_be`):** 32-bit **Big-Endian** integer giving the number of cookie pages $P$ in the file.
3. **Bytes $8\text{ through } (8 + 4P - 1)$ (`page_sizes_array`, `uint32_be[P]`):** Read $P$ 4-byte **Big-Endian** integers ($L_1, L_2, \dots, L_P$), where $L_k$ is the exact byte length of Page $k$.
4. **Page Start Offsets:** Page $1$ begins immediately at Byte Offset $8 + 4P$, Page $2$ begins at $8 + 4P + L_1$, and so on.

#### Phase 2: Parse Each Cookie Page (Switches to Little-Endian at Byte 4!)
For each page slice `page_buf` of length $L_k$:
1. **Bytes $0\text{–}3$ of Page (`page_header_tag`, `uint32_be`):** Must equal **`00 00 01 00`** (`0x00000100`).
2. **Bytes $4\text{–}7$ of Page (`num_cookies_in_page`, `uint32_le`):** 32-bit **Little-Endian** integer giving the number of cookies $C$ on this page!
3. **Bytes $8\text{ through } (8 + 4C - 1)$ of Page (`cookie_offsets_array`, `uint32_le[C]`):** Read $C$ 4-byte **Little-Endian** integers ($O_1, O_2, \dots, O_C$). Each offset $O_m$ is measured **relative to Byte $0$ of `page_buf`**.

#### Phase 3: Parse Each Cookie Record (100% Little-Endian!)
For each cookie offset $O_m$, slice `cookie_buf = page_buf[O_m : ]` and read the fixed 56-byte Little-Endian header:

| Relative Offset in `cookie_buf` | Size (Bytes) | Field Name | Endianness / Type | Decoding Rule |
|---|---|---|---|---|
| $0\text{–}3$ | $4$ | `cookie_record_size` | `uint32_le` | Total byte length of this cookie record. |
| $4\text{–}7$ | $4$ | `unknown_version` | `uint32_le` | Typically `0` or `1`. |
| $8\text{–}11$ | $4$ | `cookie_flags` | `uint32_le` | Bitmask: `0x01` = **`is_secure` (`Secure`)**; `0x04` = **`is_http_only` (`HttpOnly`)**. |
| $12\text{–}15$ | $4$ | `has_port_flag` | `uint32_le` | `0` or `1`. |
| $16\text{–}19$ | $4$ | `url_domain_offset` | `uint32_le` | Offset (relative to Byte $0$ of `cookie_buf`) where the null-terminated (`0x00`) **Domain / URL string** begins. |
| $20\text{–}23$ | $4$ | `name_offset` | `uint32_le` | Offset (relative to Byte $0$ of `cookie_buf`) where the null-terminated **Cookie Name string** begins. |
| $24\text{–}27$ | $4$ | `path_offset` | `uint32_le` | Offset (relative to Byte $0$ of `cookie_buf`) where the null-terminated **Cookie Path string** (e.g., `"/"`) begins. |
| $28\text{–}31$ | $4$ | `value_offset` | `uint32_le` | Offset (relative to Byte $0$ of `cookie_buf`) where the null-terminated **Cookie Value string** begins. |
| $32\text{–}39$ | $8$ | `comment_bytes` | `uint64_le` | Typically `0x0000000000000000` (or comment offset). |
| $40\text{–}47$ | $8$ | `expiration_cocoa_ts` | `float64_le` | 64-bit IEEE-754 Little-Endian float: **Apple Cocoa seconds since `2001-01-01 00:00:00 UTC`**! Convert via Module 1.2 ($\text{Unix} = \text{Cocoa} + 978307200$). |
| $48\text{–}55$ | $8$ | `creation_cocoa_ts` | `float64_le` | 64-bit IEEE-754 Little-Endian float: **Apple Cocoa seconds since `2001-01-01 00:00:00 UTC`** when the cookie was created! |

Read the four null-terminated UTF-8 strings at `url_domain_offset`, `name_offset`, `path_offset`, and `value_offset`, and pass `value` into the **JWT & Session Token Unpacker** (Section 7.3).

---

## 6. Step 4 — Sub-Engine 2.4C: iOS `Cache.db` (`NSURLCache`) & `fsCachedData` Correlator

On iOS, almost every application (including WhatsApp, PhonePe iOS, GPay iOS, Instagram, and banking apps) caches HTTP/HTTPS responses in `<App-UUID>/Library/Caches/<BundleID>/Cache.db`.

1. **Stage `Cache.db` via Module 1.1 & Process via Module 2.1:**
   * Always run Module 2.1's **Shared `-wal` Reader** and **B-Tree Freelist Carver** on `Cache.db` first! Deleted API responses in `cfurl_cache_response` and `cfurl_cache_receiver_data` are frequently recoverable from `Cache.db-wal` and freelist pages.
2. **Execute the 3-Table Relational Join:**
   * Join `cfurl_cache_response` (`r`), `cfurl_cache_blob_data` (`b`), and `cfurl_cache_receiver_data` (`d`) on `r.entry_ID = b.entry_ID AND r.entry_ID = d.entry_ID`:
     * `r.request_key` (`TEXT`): The full HTTP/HTTPS Request URL!
     * `r.time_stamp` (`REAL` or `INTEGER`): Apple Cocoa timestamp (or Unix timestamp depending on iOS version—auto-detect via Module 1.2's epoch range check!).
     * `b.response_object` (`BLOB`): An Apple Binary Plist (`bplist00`) containing the array of raw HTTP response headers, status code, and MIME type. Decode this binary plist automatically!
     * `d.isDataOnFS` (`INTEGER`) & `d.receiver_data` (`BLOB`):
       * **Case A (`d.isDataOnFS == 0`):** `d.receiver_data` contains the raw HTTP response body bytes directly inside the SQLite column! Pass `d.receiver_data` to Section 4.3's Decompressor & Classifier.
       * **Case B (`d.isDataOnFS == 1`):** `d.receiver_data` contains an ASCII string (a 36-character UUID, e.g., `"8F1D4A22-..."`). Query `vfs_index` in the sibling folder `.../Library/Caches/<BundleID>/fsCachedData/<UUID>` and stream that external file as the HTTP response body!
3. **Orphaned `fsCachedData/` File Sweeper:**
   * After processing all active and carved rows in `Cache.db`, check if there are any files inside `.../fsCachedData/` whose `<UUID>` filename was **not** referenced by any active row in `Cache.db` (meaning the database row was deleted and overwritten, but the external cached payload file survived on disk!).
   * Tag every unreferenced file in `fsCachedData/` as **`RESIDUAL_RECORD (Orphaned iOS fsCachedData Payload)`**, use its filesystem `mtime`/`btime` from Module 1.2, and inspect its content (JSON, image, PDF).

---

## 7. Step 5 — Sub-Engine 2.4D: WebView SQLite, LevelDB & JWT Token Unpacker

### 7.1 Android WebView SQLite Stores (`Cookies`, `Web Data`, `History`)
Stage each SQLite database via Module 1.1 and parse active + WAL + carved rows via Module 2.1:
* **From `Cookies` (`cookies` table):**
  * Extract `host_key` (domain), `name`, `value`, `encrypted_value` (if non-empty, check prefix `v10`/`v11` and unwrap via Module 2.2 if key present), `path`, `creation_utc` (WebKit microseconds), `expires_utc`, `last_access_utc`, `last_update_utc`, `is_secure`, and `is_httponly`.
* **From `Web Data` (`autofill` table):**
  * Extract `name` (the HTML `<input name="...">` attribute, such as `"vpa"`, `"upi_id"`, `"account_no"`, `"mobile"`, `"username"`), `value` (the exact text typed by the suspect!), `date_created` (Unix seconds), `date_last_used` (Unix seconds), and `count` (how many times the suspect submitted this value).
* **From `History` (`urls` and `visits` tables):**
  * Extract `url`, `title`, `visit_count`, `last_visit_time` (WebKit microseconds), and individual `visit_time` transitions.

### 7.2 WebView `Local Storage` & `IndexedDB` Extraction
* **For Android (`Local Storage/leveldb/` & `IndexedDB/*.indexeddb.leveldb/`):**
  * Pass the directory to **Module 2.3's LevelDB & Tombstone Decoder (Sub-Engine 2.3B)**.
  * For `Local Storage` entries where the key begins with `META:` (e.g., `META:https://web.telegram.org`), extract the origin metadata timestamp; for keys beginning with `_<origin>\x00<1_byte_enc_prefix><var_name>`, strip the 1-byte encoding prefix (`0x01` = Latin-1/UTF-8, `0x00` = UTF-16LE) from both `<var_name>` and `<value>` and decode to clean UTF-8 text.
* **For iOS (`*.localstorage` & `IndexedDB.sqlite3`):**
  * Open `*.localstorage` via Module 2.1: query `SELECT key, value FROM ItemTable;` (where `key` is `TEXT` and `value` is a **UTF-16LE** encoded `BLOB`—decode `value` from UTF-16LE to UTF-8!).
  * Open `IndexedDB.sqlite3` via Module 2.1: join `Records` (`objectStoreID`, `key`, `value`) with `ObjectStoreInfo` (`id`, `name`) and `DatabaseInfo`.

### 7.3 The Automated JWT (JSON Web Token) & Session Identity Unpacker
Whenever Sub-Engines 2.4A–2.4D extract a Cookie value, an HTTP `Authorization: Bearer ...` header, an `MMKV` value, or a `Local Storage` value, run a fast regex check for a **3-part Base64URL JSON Web Token (`eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`)**:
1. Split the JWT string on `.` into `header_b64`, `payload_b64`, and `signature_b64`.
2. Base64URL-decode `header_b64` and `payload_b64` into UTF-8 JSON objects.
3. Automatically extract and index the high-value identity claims inside `payload_b64`:
   * **`sub` / `user_id` / `uid`:** The suspect's internal account ID on that server.
   * **`phone_number` / `mobile` / `email` / `vpa` / `username`:** Often embedded directly inside the JWT payload in plaintext even when the app's local database is encrypted or cleared!
   * **`iat` (`Issued At` in Unix seconds):** Exact timestamp when the suspect authenticated/logged in!
   * **`exp` (`Expiration` in Unix seconds):** Token validity window.
   * **`iss` (`Issuer` domain) & `ip` / `device_id`.**

---

## 8. Database Schema for Module 2.4 (`webview_forensic_engine.sqlite`)

The developer must create the following four tables in the case database:

### Table 1: `webview_sandbox_inventory` (Per-App WebView Discovery Summary)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `wv_sandbox_id` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Unique ID for each discovered embedded WebView instance. |
| `app_instance_id` | `INTEGER` | `NOT NULL` | Foreign key to owning app in `resolved_application_catalog` (Module 1.3). |
| `os_platform` | `TEXT` | `NOT NULL` | Enum: `ANDROID`, `IOS`. |
| `webview_engine_type` | `TEXT` | `NOT NULL` | Enum: `ANDROID_CHROMIUM_WEBVIEW`, `IOS_WKWEBVIEW`, `IOS_NSURLCACHE`. |
| `canonical_root_path` | `TEXT` | `NOT NULL` | Normalized root path of the WebView directory. |
| `cookies_extracted_count` | `INTEGER` | `DEFAULT 0` | Total active + residual cookies extracted. |
| `http_cache_entries_count` | `INTEGER` | `DEFAULT 0` | Total HTTP cache entries decoded (`*_0` or `Cache.db`). |
| `local_storage_keys_count` | `INTEGER` | `DEFAULT 0` | Total `Local Storage` & `IndexedDB` records extracted. |
| `jwt_tokens_unpacked_count` | `INTEGER` | `DEFAULT 0` | Count of JWT authentication tokens automatically unpacked. |

### Table 2: `webview_http_cache_records` (Decoded Simple Cache `*_0` & iOS `Cache.db` Responses)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `cache_record_uid` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Unique ID for each cached HTTP request/response pair. |
| `wv_sandbox_id` | `INTEGER` | `NOT NULL` | Foreign key to `webview_sandbox_inventory.wv_sandbox_id`. |
| `app_instance_id` | `INTEGER` | `NOT NULL` | Foreign key to owning app (e.g., `com.phonepe.app`, `org.telegram.messenger`). |
| `source_vfs_file_id` | `INTEGER` | `NOT NULL` | Foreign key to `*_0` file, `Cache.db`, or orphaned `fsCachedData/<UUID>` in `vfs_index`. |
| `recovery_classification` | `TEXT` | `NOT NULL` | Mandatory 6-State Enum (`ORIGINAL_RECORD`, `HISTORICAL_COMMITTED_RECORD`, `RESIDUAL_RECORD`, etc.). |
| `request_url` | `TEXT` | `NOT NULL` | Full HTTP/HTTPS URL requested by the embedded WebView. |
| `initiator_top_origin` | `TEXT` | `NULL` | Top-level `_dk_` network isolation domain (if present). |
| `http_status_code` | `INTEGER` | `NULL` | E.g., `200`, `201`, `302`, `401`. |
| `content_type_mime` | `TEXT` | `NULL` | E.g., `application/json`, `text/html`, `image/png`. |
| `original_content_encoding` | `TEXT` | `NULL` | E.g., `br`, `gzip`, `zstd`, `identity`. |
| `request_time_utc_iso` | `TEXT` | `NULL` | Normalized UTC ISO-8601 request timestamp. |
| `response_time_utc_iso` | `TEXT` | `NULL` | Normalized UTC ISO-8601 response timestamp. |
| `response_headers_json` | `TEXT` | `NULL` | JSON dictionary of all HTTP response headers. |
| `decompressed_body_text` | `TEXT` | `NULL` | Decompressed UTF-8 text / JSON / HTML body (if textual). |
| `body_sha256` | `TEXT` | `NULL` | SHA-256 hash of the decompressed HTTP response body. |

### Table 3: `webview_cookies_and_tokens` (Cookies + Unpacked JWT Identity Claims)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `cookie_uid` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Unique row ID. |
| `app_instance_id` | `INTEGER` | `NOT NULL` | Foreign key to owning application in Module 1.3. |
| `source_vfs_file_id` | `INTEGER` | `NOT NULL` | Foreign key to `Cookies` SQLite or `Cookies.binarycookies` in `vfs_index`. |
| `recovery_classification` | `TEXT` | `NOT NULL` | 6-State Enum (`ORIGINAL_RECORD`, `HISTORICAL_COMMITTED_RECORD`, `RESIDUAL_RECORD`). |
| `host_domain` | `TEXT` | `NOT NULL` | Cookie domain (e.g., `.razorpay.com`, `.lotus365.in`, `.binance.com`). |
| `cookie_name` | `TEXT` | `NOT NULL` | Name of cookie or token key. |
| `cookie_value` | `TEXT` | `NULL` | Decoded value string. |
| `is_jwt_token` | `INTEGER` | `DEFAULT 0` | `1` if a Base64URL JWT (`eyJ...`) was detected and unpacked; `0` otherwise. |
| `unpacked_jwt_payload_json` | `TEXT` | `NULL` | Decoded JSON claims (`sub`, `phone_number`, `email`, `vpa`, `iat`, `exp`) if `is_jwt_token == 1`. |
| `created_utc_iso` | `TEXT` | `NULL` | Normalized UTC ISO-8601 creation timestamp (from WebKit us or Cocoa seconds). |
| `last_accessed_utc_iso` | `TEXT` | `NULL` | Normalized UTC ISO-8601 last access timestamp. |
| `expires_utc_iso` | `TEXT` | `NULL` | Normalized UTC ISO-8601 expiration timestamp. |

### Table 4: `webview_autofill_and_storage` (`Web Data` Autofill, `Local Storage` & `IndexedDB`)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `storage_row_uid` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Unique row ID. |
| `app_instance_id` | `INTEGER` | `NOT NULL` | Foreign key to owning application in Module 1.3. |
| `source_vfs_file_id` | `INTEGER` | `NOT NULL` | Foreign key to source file in `vfs_index`. |
| `storage_category` | `TEXT` | `NOT NULL` | Enum: `FORM_AUTOFILL`, `LOCAL_STORAGE`, `SESSION_STORAGE`, `INDEXED_DB`, `ITP_DOMAIN_OBSERVATION`. |
| `recovery_classification` | `TEXT` | `NOT NULL` | 6-State Enum (`ORIGINAL_RECORD`, `HISTORICAL_COMMITTED_RECORD`, `RESIDUAL_RECORD`). |
| `web_origin_or_domain` | `TEXT` | `NULL` | Origin URL (e.g., `https://paytm.com`, `https://app.uniswap.org`). |
| `field_or_key_name` | `TEXT` | `NOT NULL` | HTML input `name` or `Local Storage` / `IndexedDB` key. |
| `decoded_value_text` | `TEXT` | `NULL` | Decoded UTF-8/UTF-16LE value or V8 serialized JSON object. |
| `unpacked_jwt_payload_json` | `TEXT` | `NULL` | Populated if the stored value contains a JWT bearer token. |
| `first_recorded_utc_iso` | `TEXT` | `NULL` | Normalized UTC ISO-8601 creation/first-use timestamp. |
| `last_used_utc_iso` | `TEXT` | `NULL` | Normalized UTC ISO-8601 last-used/last-seen timestamp. |

---

## 9. Developer Acceptance Test Checklist for Module 2.4

1. **The Chromium Simple Cache (`*_0`) Dual-Ended Brotli JSON Test:** Construct or load a real Android `app_webview/Default/Cache/Cache_Data/<hash>_0` file where Stream 1 is a Brotli-compressed (`Content-Encoding: br`) JSON API response (`{"status":"SUCCESS","utr":"431098765432","vpa":"merchant@icici"}`) and Stream 0 is the `HttpResponseInfo` Pickle at the end of the file. Verify that Sub-Engine 2.4A validates `0xfcfb6d1ba7725c30` at Offset $0$, reads backward from `EOF` via `0xf4fa6f45970d41d8`, extracts the WebKit microsecond timestamps and null-delimited headers from Stream 0, and decompresses Stream 1 from Brotli into plaintext JSON!
2. **The Apple `Cookies.binarycookies` Hybrid-Endian Test:** Feed a real iOS `Cookies.binarycookies` file into Sub-Engine 2.4B. Verify that the parser reads `num_pages` and `page_sizes` in **Big-Endian**, switches to **Little-Endian** at Byte $4$ of each page, decodes `domain`, `name`, `path`, and `value`, and converts the 64-bit Little-Endian IEEE-754 float Cocoa timestamps (`Bytes 40–55`) to exact UTC ISO-8601 dates.
3. **The iOS `Cache.db` + `fsCachedData/<UUID>` Join & Orphan Test:** Load an iOS app's `Library/Caches/<BundleID>/` folder containing `Cache.db` (with one inline `isDataOnFS = 0` row and one external `isDataOnFS = 1` row pointing to `fsCachedData/UUID-1`), plus a second file `fsCachedData/UUID-2` whose row was deleted from `Cache.db`. Verify that Sub-Engine 2.4C joins `UUID-1` to its `request_key` URL and flags `UUID-2` as `RESIDUAL_RECORD (Orphaned iOS fsCachedData Payload)`.
4. **The UTF-16LE `Local Storage` & JWT Unpacker Test:** Insert a `Local Storage` LevelDB value prefixed with `0x00` (UTF-16LE) containing `"₹50,000"` and a second value containing a JWT bearer token (`eyJhbGciOiJIUzI1NiIs...`). Verify that Sub-Engine 2.4D decodes the UTF-16LE string without null-byte corruption and automatically unpacks the JWT's `sub`, `phone_number`, and `iat` timestamp into `unpacked_jwt_payload_json`.
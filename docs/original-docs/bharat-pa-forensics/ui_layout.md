+--------------------------------------------------------------------------------------------------+
| TOP RIBBON: [Open Dump] [Parse/Carve] [Global Search] [UPI Link Graph] [Hex] [Sec 63 BSA Report] |
+-----------------------+--------------------------------------------------+-----------------------+
| LEFT DOCK:            | CENTER WORKSPACE (Multi-Tab Dockable Canvas)     | RIGHT DOCK:           |
| Project Tree          | [Extraction Summary] [Chats] [UPI Ledger] [SQL]  | Artifact Provenance   |
|                       |--------------------------------------------------| & Decoder Inspector   |
| v Case #2026-CYB-09   | Filter: [All Apps v] [Deleted Only] [Search UTR] |                       |
|  v Extraction (.tar)  |--------------------------------------------------| Source File:          |
|   > Device Info       | # | State    | Timestamp (IST)     | UTR / VPA   | /data/data/com.phonepe|
|   v Analyzed Data     |---|----------|---------------------|-------------| /databases/core.db    |
|     - Instant Msgs (4)| 1 | [Active] | 2026-10-14 14:22:01 | 628719384712| Table: transactions   |
|     - UPI & Fin (142) | 2 | [WAL]    | 2026-10-14 14:25:19 | 628719991023| Page: 42 | Offset:    |
|     - Mule Alerts (9) | 3 | [Carved] | 2026-10-14 14:29:00 | T26101414290| 0x000A4F20            |
|     - Remote APK (2)  |--------------------------------------------------|                       |
|     - Crypto Wallets  | CONTEXT VIEW (Split Pane: Chat Bubble / Receipt) | Raw Timestamps:       |
|     - Deleted / Carved|  [Sent Rs. 45,000 to merch.axis@okaxis]          | Epoch: 1760431921000  |
|   > File System (VFS) |  [Status: SUCCESS | Bank: SBI XX4921]            | UTC:   08:52:01       |
|   > Keystore / Keys   |--------------------------------------------------| IST:   14:22:01 +05:30|
|                       | BOTTOM PANE: Synchronized Hex / Protobuf Viewer  |                       |
|                       | 000A4F20: 36 32 38 37 31 39 33 38 34 37 31 32    | SHA-256 Verified: YES |
+-----------------------+--------------------------------------------------+-----------------------+
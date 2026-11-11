# Engineering Specification: Phase 9, Module 9.3 — WebGL Financial & Crypto Laundering Flow Canvas, Force-Directed Entity Graph & 60-Second Action-Burst Behavioral Storyboard

**Document Purpose:** This document provides the complete, step-by-step architectural blueprint for building **Module 9.3** of the Forensic Workstation UI/UX Engine (the visual link-analysis, financial-flow, and behavioral-reconstruction workspace of **Phase 9**, powered by the analytical databases of **Phases 3, 4, 5, 6, 7, and 8**). It contains **zero programming code** and explains how to render an interactive **5-Stage Rupee-to-USDT Sankey Laundering Canvas** with non-linear ribbon scaling and split-UPI smurfing fans, how to build a **60 FPS WebGL2 Instanced Force-Directed Entity & Mule-Ring Link Graph** using Barnes-Hut quadtree physics ($O(V \log V)$) and R-Tree label de-occlusion, how to execute interactive graph algorithms (Tarjan/Johnson Circular Mule-Loop detection, Bidirectional Shortest Evidentiary Path, and TRON Gas-Station Hub isolation), how to render the **5-Swimlane 60-Second "Action-Burst" Behavioral Storyboard**, and how to stage selected graph nodes directly into the **Golden-Hour Nodal Freeze Cart (`1930 NCRP` & `FIU-IND`)** while maintaining continuous **Pane 3 Hex/Provenance Synchronization** from first principles.

---

## 1. Purpose & Mental Model (Why Spreadsheets Cannot Expose Multi-Hop Syndicates or Prove Human-in-the-Loop Execution)

In complex Indian cyber-financial investigations ("Digital Arrest" extortion, investment/task scams, offshore betting syndicates like `Mahadev` / `Lotus365`, and darknet narcotics), the backend engines of **Phase 3 (Indian UPI & Banking)**, **Phase 4 (CEX P2P & Self-Custody Crypto)**, and **Phase 8.1 (Entity Graph & Action-Burst Stories)** extract thousands of interconnected financial transfers, wallet hops, and OS behavioral telemetry events.

However, presenting those connections purely as rows in a table creates three severe analytical blind spots for an Investigating Officer (IO) or Public Prosecutor:

1. **The "Multi-Hop Laundering Forest" Blind Spot:**
   * A single seized mule-coordinator phone often tracks ₹2 Crore of stolen funds entering across $40$ Layer-1 victim UPI credits, splitting into $120$ Layer-2 `₹50,000–₹95,000` UPI/IMPS transfers (`Smurfing`), settling across $25$ **Binance / Bybit P2P Escrow Orders**, withdrawing as `USDT-TRC20` into $6$ **`TronLink Pro` / `Trust Wallet`** addresses, and exiting through **`FixedFloat` / `ChangeNow` into `Monero (XMR)`**.
   * In a flat spreadsheet, tracing how Victim Deposit #14 funded P2P Order #8 and ended up in TRON Wallet `TXYZ...` requires manually cross-referencing four tables. **Sub-Engine 9.3A's 5-Stage Sankey Flow Canvas** plots the entire fiat-to-crypto laundering pipeline on a single interactive screen.
2. **The "Hidden Syndicate Hub & Circular Ring" Blind Spot:**
   * Often, 15 seemingly independent mule accounts or `TRON` wallets on a device are secretly controlled by the same upstream syndicate boss because they all received their initial **`30 TRX` gas-activation funding (`DelegateResourceContract` Energy Rental)** from the same parent wallet, OR they all connected to the same **Wi-Fi `BSSID` (`00:1a:2b:...`)**, OR they form a **Circular Mule Loop ($A \rightarrow B \rightarrow C \rightarrow A$)**. **Sub-Engine 9.3B's WebGL Force-Directed Entity Graph** reveals these structural hubs and circular rings visually in one click.
3. **The "Remote Hack vs. Active Human Operation" Courtroom Defense:**
   * When a suspect is charged with operating a mule account or sending an extortion demand, defense counsel routinely argues: *"My client's phone was hacked by a remote trojan or `AnyDesk` session; my client was asleep and never touched the phone!"* (Or conversely, a genuine cyber-fraud victim needs to prove that a sideloaded APK trojan drained their bank account while the phone lay flat on a table).
   * **Sub-Engine 9.3C's 5-Swimlane Action-Burst Storyboard** aligns second-by-second OS sensor telemetry (`FaceID/Fingerprint Unlock`, `Portrait Hand-Tilt Orientation`, `Pedometer Steps`, `App Foreground Focus`, `Accessibility Overlay / AnyDesk State`), `SMS OTP Arrival`, `UPI/Crypto Debit`, and `Chat Screenshot Sharing` onto a single visual diagram that anyone in a courtroom can understand in 10 seconds.

---

## 2. The 6 Fatal UI/UX & Engineering Mistakes in Forensic Graph & Financial Visualizers

Before implementing Module 9.3, the developer must understand six classic engineering traps that make standard link-analysis and financial charts unusable on real forensic cases:

### Mistake 1: Rendering Nodes and Edges with HTML `<svg>` DOM Elements (The "3,000-Node Hairball Freeze")
* **The Trap:** Using standard D3.js `<svg><circle><line><text>` DOM elements to render the Master Entity Graph (`entity_master_profiles` + `entity_graph_edges_ledger`).
* **Why It Fails:** A real seized phone has $2,000\text{ to }15,000$ entities (contacts, group members, VPAs, bank accounts, crypto wallets, cell towers, Wi-Fi BSSIDs) and $25,000+$ edges. Creating $40,000$ SVG DOM nodes with CSS styles and event listeners chokes the browser's layout/paint engine, dropping panning/zooming frame rates to $< 3\text{ FPS}$ and turning the screen into an unreadable black "hairball" of overlapping text labels!
* **The Rule:** Implement **Sub-Engine 9.3B's Dual-Layer Rendering Architecture**:
  1. Render all nodes, halos, and directed edges inside a **single `WebGL2` Canvas** using GPU-instanced draw calls (`gl.drawArraysInstanced`, rendering $50,000$ nodes and edges in $< 1.5\text{ milliseconds}$ per frame at $60\text{ FPS}$!).
  2. Run the **Barnes-Hut Quadtree ($O(V \log V)$) Force Simulation inside a background `Web Worker`** using a shared `Float32Array` buffer, and apply **2D Grid / R-Tree Label De-Occlusion** so only non-overlapping labels prioritized by forensic PageRank/financial weight are drawn at the current zoom level!

### Mistake 2: Using Linear Ribbon Thickness Scaling on Financial Sankey Diagrams
* **The Trap:** Making the pixel height $W_{\text{ribbon}}$ of each Sankey flow ribbon strictly proportional to its linear Rupee or USDT value ($W_{\text{ribbon}} = k \times \text{Amount}$).
* **Why It Fails:** In a real case, a suspect executes a **₹25,00,000 RTGS/P2P transfer** alongside a **₹1.00 "Penny-Drop" bank account verification test** or a **$30\text{ TRX}$ ($\approx ₹600$) TRON gas-activation transfer**. Under linear scaling, if the ₹25,00,000 ribbon is $200\text{ px}$ thick, the ₹1.00 penny-drop or ₹600 gas-activation ribbon is $0.00008\text{ px}$ thick—completely invisible ($0\text{ px}$) on screen and impossible to click!
* **The Rule:** Use the **Clamped Hybrid Root-Logarithmic Ribbon Scaling Law** (Section 3.2) with a guaranteed minimum clickable height $W_{\text{min}} = 4.0\text{ px}$ while displaying exact linear amounts and percentage shares in high-contrast badges!

### Mistake 3: Breaking the Acyclic (`DAG`) Requirement of a Sankey Layout When Circular Mule Loops Exist
* **The Trap:** Feeding a financial transaction graph containing a circular mule loop ($A \rightarrow B \rightarrow C \rightarrow A$) directly into a standard Sankey layout algorithm, causing an infinite loop or a crash!
* **Why It Fails:** Standard Sankey algorithms require a strict **Directed Acyclic Graph (`DAG`)** where every edge flows strictly from Column $c$ to Column $c+1$. In Indian money laundering, mules frequently bounce funds back to an earlier account ($C \rightarrow A$) or trade both `BUY` and `SELL` legs on P2P!
* **The Rule:** Sub-Engine 9.3A enforces **Stage-Column Stratification (Columns 1 to 5)** and renders any backward/circular return transfer ($c_{\text{target}} \le c_{\text{source}}$) as a distinct **Top-Arched Crimson "Circular Feedback Arc" Ribbon** above the main horizontal Sankey flow (Section 3.2)!

### Mistake 4: Failing to Visually Flag "Third-Party Payer Triangulation" & "Split-UPI Smurfing" on P2P Escrow Nodes
* **The Trap:** Drawing a simple line from `"Bank Account"` to `"Binance P2P"` without showing that **three different UPI transfers (`₹90k + ₹50k + ₹40k`)** were combined to settle a single `₹1,80,000` P2P order, or that the **bank payer's CBS name (`AMIT VERMA`) did not match the Binance account's KYC name (`RAHUL SHARMA`)**!
* **The Rule:** Render explicit **Converging Smurfing Fan Connectors** and pulsing **Crimson `[TRIANGULATION MISMATCH !]` Warning Badges** directly on the P2P Escrow node (Section 3.3).

### Mistake 5: Plotting OS Behavioral Telemetry on a Uniform Time Axis Where 12 Hours of Idle Time Crushes a 45-Second Crime Burst into a 1-Pixel Line
* **The Trap:** Using a uniform linear 24-hour timeline axis to display device sensor and app events.
* **Why It Fails:** A phone sits idle for 8 hours overnight, followed by a frantic **45-second crime burst** where 14 events happen across 5 subsystems (`Unlock` $\rightarrow$ `App Resume` $\rightarrow$ `OTP Read` $\rightarrow$ `UPI Debit` $\rightarrow$ `Screenshot` $\rightarrow$ `Telegram Send`). On a 24-hour linear axis, all 14 events pile on top of each other inside a single $1\text{-pixel}$ vertical line!
* **The Rule:** Sub-Engine 9.3C provides a dedicated **Micro-Timeline Swimlane View** (scaled at $1\text{ second} = 12\text{ to }30\text{ pixels}$, with non-linear **Idle-Gap Compression Folding** `// [4h 12m Idle Gap Folded] //` between bursts!).

### Mistake 6: Requiring Manual Copy-Pasting From Visual Graphs Into `1930 NCRP` or `FIU-IND` Freeze Sheets
* **The Trap:** Letting the investigator visually discover a cluster of 18 mule accounts and 4 TRON wallets on the graph, but forcing them to write down the account numbers on paper to export them.
* **The Rule:** Implement the **Persistent "Golden Hour" Nodal Freeze Selection Tray** (Section 6.1): `Shift+Drag` lasso-selecting any set of nodes or ribbons on the Sankey or WebGL Graph immediately adds all underlying Bank Accounts, 12-digit UTRs, UPI VPAs, CEX UIDs, and Crypto Addresses into the bottom-right **Nodal Freeze Cart**, ready for 1-click export to **Module 8.4B's I4C NCRP 1930 CSV or FIU-IND / Binance LERP Freeze Packet**!

---

## 3. Step 1 — Sub-Engine 9.3A: The Interactive 5-Stage Rupee-to-USDT Sankey Laundering Flow Canvas

### 3.1 Visual Layout of the 5-Stage Fiat-to-Crypto Sankey Workspace

```
+----------------------------------------------------------------------------------------------------------+
| [View: (*) 5-Stage Laundering Sankey  ( ) WebGL Entity Graph  ( ) Action-Burst Storyboard] [Freeze Cart:8]|
+----------------------------------------------------------------------------------------------------------+
| STAGE 1: INFLOWS   | STAGE 2: DEVICE BANK | STAGE 3: CEX P2P    | STAGE 4: SELF-CUSTODY | STAGE 5: EXIT  |
| & VICTIM CREDITS   | & SPLIT-UPI SMURFING | ESCROW & OFF-CHAIN  | WEB3 & SEED WALLETS   | & MONERO SWAPS |
|--------------------|----------------------|---------------------|-----------------------|----------------|
| [Victim A (IMPS)]  |                      |                     |                       |                |
|  ₹1,00,000 ========+==> [SBI A/c ...8291] |                     |                       |                |
|                    |     (SIM Bound: JIO) |                     |                       |                |
| [Victim B (UPI)]   |      |-- ₹95,000 ----+--> [Binance P2P]    |                       |                |
|  ₹80,000 ==========+==/   |-- ₹85,000 ----+--> Order #205948... |                       |                |
|                    |      [SMURFING FAN!] |    (2,000.00 USDT)  |                       |                |
| [ Penny-Drop ₹1 ] -+->                    |    [Seller: @okaxis]|                       |                |
|                    |                      |    [Chat: 6 Msgs]   |                       |                |
|                    | [HDFC A/c ...4410]   |         |           |                       |                |
|                    |  (CBS: AMIT VERMA) --+--> [TRIANGULATION!] +==> [TronLink: TXYZ..] +==> [FixedFloat]|
|                    |                      |    (Binance KYC:    |    (BIP-39 Seed #1)   |    Order #FF99 |
|                    |                      |     RAHUL SHARMA)   |    [Gas: TDeg...30TRX]|    -> 8.42 XMR |
+----------------------------------------------------------------------------------------------------------+
| [Bottom Docked Pane 2/3: Underlying Transactions (14) | P2P Chat Transcript | Synchronized Hex Viewer ]  |
+----------------------------------------------------------------------------------------------------------+
```

### 3.2 Mathematical Specification of the 5-Stage Sankey Layout & Hybrid Ribbon Scaling

1. **Deterministic 5-Column Stage Stratification ($c \in \{0, 1, 2, 3, 4\}$):**
   Every node in `end_to_end_rupee_to_crypto_laundering_chains` (`Module 4.4D`) and `financial_flow_graph_edges` (`Module 3.5D`) is assigned to one of five horizontal x-coordinates $X_c = X_{\text{margin}} + c \times \Delta X_{\text{col}}$:
   * **Column $0$ (`STAGE_1_EXTERNAL_INFLOW_SOURCES`):** External payer bank accounts, VPAs, cash deposits, or loan/betting payouts crediting the suspect's accounts.
   * **Column $1$ (`STAGE_2_LOCAL_MULE_ACCOUNTS_AND_VPAS`):** Bank accounts and UPI VPAs operated on or monitored by the seized handset (badged with **`[SIM-BOUND ON DEVICE: ICCID ...]`** vs. **`[REMOTE MULE ACCOUNT — SMS/CHAT ONLY]`** from Module 3.2/3.5).
   * **Column $2$ (`STAGE_3_P2P_ESCROW_AND_DOMESTIC_FIU_ONRAMPS`):** `Binance P2P`, `Bybit P2P`, `KuCoin P2P`, `Noones`, `CoinDCX`, `Mudrex`, `ZebPay`, or Layer-2 domestic mule beneficiary accounts.
   * **Column $3$ (`STAGE_4_SELF_CUSTODY_AND_CEX_WALLETS`):** `TronLink Pro` (`T...`), `MetaMask` / `Trust Wallet` (`0x...`), `Phantom`, `Ledger Live` cold wallets, `Binance Pay` UIDs, and **HD Wallets derived from recovered `BIP-39` seeds (`Module 4.4B`)**.
   * **Column $4$ (`STAGE_5_OFFSHORE_BOSS_AND_PRIVACY_SWAPS`):** Upstream syndicate boss Watch-Only wallets, `FixedFloat` / `ChangeNow` / `Cake Wallet` (`Monero XMR`) cross-chain swap exits, and Tornado Cash / mixer contracts.

2. **Clamped Hybrid Square-Root / Logarithmic Ribbon Thickness Formula:**
   To ensure that a ₹1.00 penny-drop verification transfer or a $30\text{ TRX}$ ($\approx ₹600$) gas-delegation transfer remains visibly clickable alongside a ₹50,00,000 laundering transfer, convert every flow's normalized INR-equivalent value $V_e$ (where $V_{\text{max}}$ is the largest flow on screen, $W_{\text{min}} = 4.0\text{ px}$, and $W_{\text{max}} = 140.0\text{ px}$) using the **Hybrid Power-Law Scaling Function ($\gamma = 0.40$)**:
   $$W_{\text{ribbon}}(V_e) = \max\left(W_{\text{min}}, \ W_{\text{max}} \times \left(\frac{V_e}{V_{\text{max}}}\right)^{0.40}\right)$$
   * **Why $\gamma = 0.40$ Works Perfectly:** When $V_{\text{max}} = ₹50,00,000$ ($140\text{ px}$), a ₹50,000 transfer ($\frac{1}{100}\text{-th}$ of max) renders at $140 \times (0.01)^{0.40} = \mathbf{22.1\text{ px}}$ (instead of a tiny $1.4\text{ px}$ under linear scaling!), and a ₹1.00 penny-drop clamps cleanly to $\mathbf{4.0\text{ px}}$ with a dashed `[PENNY-DROP VERIFICATION ₹1.00]` callout pill!

3. **Iterative Barycenter Crossing Minimization & Cubic Bézier Ribbon Path Math:**
   * Within each column $c \in \{0 \dots 4\}$, sweep $4$ iterations left-to-right and right-to-left, ordering nodes vertically by the weighted barycenter $B(u)$ of their connected neighbors in adjacent columns:
     $$B(u) = \frac{\sum_{v \in \text{Adj}(u)} Y_{\text{center}}(v) \cdot W_{\text{ribbon}}(u, v)}{\sum_{v \in \text{Adj}(u)} W_{\text{ribbon}}(u, v)}$$
   * Render each forward ribbon from $(x_0, y_0)$ to $(x_1, y_1)$ with thickness $w = W_{\text{ribbon}}$ as a smooth cubic Bézier path with horizontal control points at $x_{\text{mid}} = \frac{x_0 + x_1}{2}$:
     $$C\left(\frac{x_0 + x_1}{2}, \ y_0, \quad \frac{x_0 + x_1}{2}, \ y_1, \quad x_1, \ y_1\right)$$
   * **Circular Return / Feedback Arcs ($c_{\text{target}} \le c_{\text{source}}$):** Any transaction that loops backward (e.g., a Circular Mule Loop where Account C sends ₹90,000 back to Account A) is drawn as a **Top-Arched Crimson Dashed Bézier Curve** arching above the columns with an animated directional chevron **`[🔄 CIRCULAR MULE LOOP: +18m]`**!

### 3.3 Specialized Forensic Overlays on the Sankey Canvas

* **Overlay 1 — The "Split-UPI Smurfing Fan" Bracket:** When Module 4.4D links $k \ge 2$ split UPI transfers (e.g., `₹95,000 + ₹85,000`) to a single `₹1,80,000` P2P Escrow Order, the Sankey canvas groups the $k$ ribbons inside a gold brace labeled **`[⚡ SPLIT-UPI SMURFING FAN: 2 Transfers = ₹1,80,000.00 in 4m 12s]`**.
* **Overlay 2 — The In-Canvas P2P Escrow Chat & Triangulation Popover:** Clicking any CEX P2P node in Column 2 opens an inline popover displaying the **Verbatim In-Order P2P Chat Transcript** (`Module 4.2B`), the Seller's UPI VPA / Bank details, and—if `is_third_party_payer_mismatch == 1`—a crimson comparison box showing **`CEX KYC Name: RAHUL SHARMA` $\neq$ `Bank Payer CBS Name: AMIT VERMA`**.
* **Overlay 3 — TRON "Gas-Station / Energy Rental" Dotted Connectors:** In Column 3, if multiple `TRON` wallets received `TRX` gas activation or `DelegateResourceContract` Energy from the same parent wallet (`Module 4.1B`), a **Cyan Dotted Arc** connects the parent "Gas Station Wallet" to each child mule wallet!

---

## 4. Step 2 — Sub-Engine 9.3B: The 60 FPS WebGL2 Force-Directed Entity & Mule-Ring Link Graph

When the investigator switches to the **WebGL Entity & Mule-Ring Link Graph**, Sub-Engine 9.3B renders the complete cross-phase knowledge graph (`entity_master_profiles` and `entity_graph_edges_ledger` from Module 8.1) at 60 FPS.

### 4.1 WebGL2 Instanced Rendering & Barnes-Hut Quadtree ($O(V \log V)$) Web Worker Physics

1. **Background `GraphPhysicsWorker` with Barnes-Hut Quadtree Approximation:**
   * Computing pairwise Coulomb repulsion across $V = 10,000$ nodes naively requires $V^2 = 100,000,000$ calculations per frame ($O(V^2)$), freezing the CPU.
   * Instead, `GraphPhysicsWorker` partitions the 2D canvas into a recursive **Barnes-Hut Quadtree** where each quadtree cell $Q$ of width $s_Q$ stores its total mass $M_Q$ and center-of-mass $(X_Q, Y_Q)$.
   * For any node $u$ at distance $d$ from cell $Q$'s center of mass, if the **Barnes-Hut Opening Angle Criterion** is satisfied:
     $$\frac{s_Q}{d} < \theta \qquad (\text{with } \theta = 0.80)$$
     the worker treats the entire distant cluster of nodes inside $Q$ as a **single super-node**, reducing complexity to **$O(V \log V)$** and streaming updated $(x_i, y_i)$ coordinates to the WebGL2 renderer via a double-buffered `Float32Array`!

2. **Collision-Free Semantic Zoom Label Culling (2D Screen-Space Occupancy Grid):**
   * To prevent overlapping text labels ("hairball text"), on every camera zoom/pan frame, rank all visible nodes by their **Forensic Importance Score ($S_{\text{rank}}$)**:
     $$S_{\text{rank}}(u) = 100 \cdot I_{\text{bookmarked}}(u) + 50 \cdot I_{\text{has\_tamper\_or\_seed}}(u) + 10 \cdot \log_{10}\big(1 + \text{INR\_Volume}(u)\big) + \text{Degree}(u)$$
   * Iterate through visible nodes in descending order of $S_{\text{rank}}(u)$, compute the screen-space bounding box $[x_{\text{scr}}, y_{\text{scr}}, w_{\text{lbl}}, h_{\text{lbl}}]$ of node $u$'s label, and check a fast **Screen-Space Spatial Hash Grid** ($16 \times 16\text{ px}$ cells):
     * If all grid cells under the label are unoccupied, draw the label and mark those cells occupied!
     * If any cell is already occupied by a higher-priority label, hide node $u$'s text label until the user zooms in closer (or hovers over node $u$)!

### 4.2 Interactive 1-Click Forensic Graph Algorithms Toolbar

At the top of the WebGL Graph sits a 4-button **Forensic Graph Analytics Toolbar**:

1. **Algorithm 1 — `Highlight Circular Mule & Laundering Loops` (Tarjan's `SCC` + Johnson's Elementary Cycle Finder):**
   * Runs Tarjan's $O(V + E)$ Strongly Connected Components algorithm followed by Johnson's cycle-finding algorithm over `TRANSFERRED_FIAT_TO` and `TRANSFERRED_CRYPTO_TO` edges.
   * Dims all non-cyclic nodes to $15\%$ opacity and illuminates every closed financial loop ($A \rightarrow B \rightarrow \dots \rightarrow A$) with pulsing crimson directional particles, displaying the **Total Loop Duration ($\Delta t$) and Net Retained Commission (`₹` / `USDT`)** at each hop!
2. **Algorithm 2 — `Find Shortest Evidentiary Path Between Two Entities` (Bidirectional BFS / Weighted Dijkstra):**
   * When the investigator selects any two nodes `Entity X` (e.g., a suspect phone number) and `Entity Y` (e.g., a victim bank account, an overseas Telegram handle, or a crime-scene flat address), computes the shortest multi-phase path connecting them across all 8 edge verbs (`COMMUNICATED_WITH`, `TRANSFERRED_FIAT_TO`, `OWNS_OR_CONTROLS_INSTRUMENT`, `VISITED_OR_ORDERED_AT_LOCATION`, `POSSESSED_KYC_DOCUMENT_OF`).
   * Renders the exact step-by-step evidentiary chain as a highlighted breadcrumb banner at the top of the canvas!
3. **Algorithm 3 — `Isolate Common Syndicate Hubs ("Shared Resource Detector")`:**
   * Highlights all high-centrality **Bridge Nodes** (`betweenness_centrality`) where $\ge 2$ otherwise-unconnected actors converge on:
     * The **same Wi-Fi `BSSID` (`00:1a:2b:...`)** or **Mobile Hotspot (`SoftAP` lease)** (`Module 6.3C`).
     * The **same `Blinkit` / `Swiggy` / `Zomato` Delivery Flat Address** (`Module 6.4A`).
     * The **same `TRON` Gas-Activation / Energy-Rental Parent Wallet** (`Module 4.1B`).
     * The **same `Binance` / `Bybit` P2P Counterparty or Device Login Environment**.
4. **Algorithm 4 — `Time-Window Graph Slicing`:**
   * Links the WebGL Graph directly to the top Timeline Histogram Scrubber so dragging a time window $[t_1, t_2]$ animates the graph, showing only the actors, wallets, and edges active during that exact hour or day!

---

## 5. Step 3 — Sub-Engine 9.3C: The 5-Swimlane 60-Second "Action-Burst" Behavioral Storyboard

When the investigator clicks any detected **Action-Burst Crime Story** (`forensic_action_burst_stories` from Module 8.1D) or presses `S` on any financial/chat event, Sub-Engine 9.3C renders a synchronized **5-Swimlane Horizontal Micro-Timeline** spanning $[T_{\text{burst\_start}} - 30\text{s}, \ T_{\text{burst\_end}} + 30\text{s}]$:

```
+----------------------------------------------------------------------------------------------------------+
| STORY #04: ACTIVE HUMAN-AUTHENTICATED UPI OUTFLOW & TELEGRAM SCREENSHOT PROOF (Duration: 22.4 Seconds)   |
| [Verdict Badge: VERIFIED HUMAN-IN-THE-LOOP EXECUTION — Defeats Remote Hack / Trojan Defense]             |
+------------------+---------------------------------------------------------------------------------------+
| SWIMLANE         | SECOND-BY-SECOND SYNCHRONIZED MICRO-TIMELINE (IST +05:30)                             |
|                  | 14:10:00       14:10:05       14:10:10       14:10:15       14:10:20       14:10:25   |
+------------------+---------------------------------------------------------------------------------------+
| 1. PHYSICAL &    | [🔓 Keyguard Hidden / Biometric Match]                                                |
|    BIOMETRIC     | [📱 Orientation: Portrait (1) — Held Upright in Hand | Pedometer: 14 Steps]           |
|------------------+---------------------------------------------------------------------------------------|
| 2. OS FOREGROUND |       [▶️ com.phonepe.app: ACTIVITY_RESUMED (InFocus)]      [▶️ org.telegram.messenger]|
|    & APPOPS      |       [🛡️ Overlay/AnyDesk Check: ZERO Active Overlays or Remote Sessions]            |
|------------------+---------------------------------------------------------------------------------------|
| 3. TELECOM, OTP  |                        [📩 SMS DLT: AD-SBIINB-S "Debited Rs 95,000 UTR 630914829104"] |
|    & LOCATION    | [📍 Serving 4G Cell: Jio 405-86 TAC 1042 eNodeB 1048577 | Wi-Fi: "Home_Fiber_5G"]     |
|------------------+---------------------------------------------------------------------------------------|
| 4. FINANCIAL &   |                    [💸 PhonePe Outflow: ₹95,000.00 -> vikram99@okaxis]                |
|    CRYPTO RAIL   |                    [UTR: 630914829104 | SIM ICCID Bound: 89918540...]                 |
|------------------+---------------------------------------------------------------------------------------|
| 5. VISUAL & CHAT |                                       [📸 Screenshot_141019_PhonePe.jpg]              |
|    CONFIRMATION  |                                              [📤 Sent in Telegram Secret Chat to Boss]|
+------------------+---------------------------------------------------------------------------------------+
```

### 5.1 The 5 Mandatory Synchronized Swimlanes & Idle-Gap Folding Math

1. **Swimlane 1 (`PHYSICAL_AND_BIOMETRIC_STATE`):**
   * Plots `LockState` / `KEYGUARD_HIDDEN`, `biometrickitd` FaceID / TouchID / Fingerprint authentication matches, physical device orientation (`Portrait`, `Landscape`, `FaceUp Flat`, `FaceDown` from iOS `BacklightServices` / Android `SensorPrivacy`), charger cable plug state (`AC_CHARGER` / `USB_HOST`), and hardware pedometer step bursts (`HealthDB` / `Health Connect`).
2. **Swimlane 2 (`OS_FOREGROUND_AND_SENSOR_APPOPS`):**
   * Plots exact millisecond `ACTIVITY_RESUMED` $\rightarrow$ `ACTIVITY_PAUSED` (`UsageStats`) and `/app/inFocus` (`knowledgeC` / `App.InFocus` Biome) bars, overlaid with `appops/discrete` and `PrivacyAccounting` microphone (`RECORD_AUDIO`), camera (`CAMERA`), clipboard (`READ_CLIPBOARD`), and screen-overlay (`SYSTEM_ALERT_WINDOW` / `AnyDesk` session) markers!
3. **Swimlane 3 (`TELECOM_OTP_AND_RADIO_ANCHOR`):**
   * Plots incoming TRAI DLT OTP/Bank SMS messages (`Module 3.4`), cellular/VoIP calls, and the simultaneous `TIER_1` GPS / `TIER_2` Connected Wi-Fi `BSSID` / `4G eNodeB` cell sector (`Module 6.3`).
4. **Swimlane 4 (`FINANCIAL_AND_CRYPTO_EXECUTION`):**
   * Plots the exact UPI/IMPS/NEFT debit/credit (`Module 3.5`), CEX P2P order event (`Module 4.2`), or `TronLink`/`MetaMask` transaction (`Module 4.1`).
5. **Swimlane 5 (`VISUAL_SCREENSHOT_AND_CHAT_HANDOFF`):**
   * Plots OS screenshot captures (`Module 7.1`), `SplashBoard` / `TaskSnapshots` (`Module 7.2`), and outgoing/incoming chat messages (`Phase 5`) sharing the receipt or `txid`.

6. **Piecewise-Linear Idle-Gap Compression (`Non-Linear Time Axis Folding`):**
   * If the examiner expands the Storyboard time range to cover a 2-hour window where two 60-second bursts are separated by $45\text{ minutes}$ of complete device inactivity ($\Delta t_{\text{gap}} > 120\text{ seconds}$ with zero events across all 5 swimlanes), the horizontal time-to-pixel mapping function $X(t)$ automatically folds the empty gap into a fixed $48\text{ px}$ zig-zag accordion break `// [45m 12s Idle Gap — Click to Expand] //`, preserving full $20\text{ px/second}$ resolution inside the active crime bursts!

---

## 6. Step 4 — Sub-Engine 9.3D: The "Golden Hour" Nodal Freeze Cart & Synchronized Pane 3 Hex Binding

### 6.1 Interactive Lasso Selection & The Live Nodal Freeze Cart

Across both the **5-Stage Sankey Canvas (Sub-Engine 9.3A)** and the **WebGL Force-Directed Graph (Sub-Engine 9.3B)**:
1. **Freehand Polygon Lasso & Shift-Click Selection:**
   * Holding `Shift` and dragging the cursor draws a translucent gold selection polygon $P = [(x_1, y_1), \dots, (x_m, y_m)]$.
   * Every node $(x_u, y_u)$ inside polygon $P$ (tested via the $O(m)$ **Ray-Casting Point-in-Polygon Algorithm**) and its incident financial/crypto edges are selected.
2. **1-Click "Add to Nodal Freeze & Section 94 BNSS Cart":**
   * Clicking **`[+ Add Selected to Nodal Freeze Cart (N)]`** in the floating action bar immediately extracts all underlying:
     * **Bank Account Numbers + 11-Char IFSCs + UPI VPAs + 12-Digit UTRs** $\rightarrow$ Staged into **Module 8.4B's `1930 NCRP / Bank Nodal Lien Sheet`**!
     * **CEX `UID`s + P2P Order IDs + `TRC-20`/`ERC-20` Wallet Addresses + `txid`s** $\rightarrow$ Staged into **Module 8.4B's `FIU-IND / Binance LERP / Tether Freeze Sheet`**!
     * **Phone Numbers + `eNodeB` Cell Towers + Delivery Order IDs** $\rightarrow$ Staged into **Module 8.4B's `Section 94 BNSS Statutory Requisition Queue`**!

### 6.2 Continuous Synchronization With Pane 3 (Provenance Card & Byte-Highlighted Hex Viewer)

Every visual object in Module 9.3 obeys the **Zero-Trust Click Law (`Module 9.1`)**:
* Clicking any **Sankey Node or Flow Ribbon**, any **WebGL Graph Node or Edge**, or any **Swimlane Event Pill in the Action-Burst Storyboard** immediately updates the docked **Pane 2/3 Verification Drawer**:
  * **Pane 3A** renders the 3-Tier `SHA-256` + `MD5` Hash Lineage and 5D Evidentiary State of the underlying database row or image.
  * **Pane 3B** jumps the built-in Hex Viewer directly to the exact `physical_byte_offset` in `phonepe.db`, `mmssms.db`, `com.binance.dev` `MMKV`, `tron_main.db`, or `usage-history.xml`!

---

## 7. Local UI State Schema & FastAPI IPC Contract for Module 9.3

### Table 1: `saved_graph_views_and_freeze_cart_state` (Persisted Canvas Layouts, Pinned Nodes & Nodal Freeze Selections)

| Column Name | SQLite Type | Constraints | Description |
|---|---|---|---|
| `view_state_uid` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Unique saved view ID. |
| `canvas_mode` | `TEXT` | `NOT NULL` | Enum: `SANKEY_5_STAGE_LAUNDERING`, `WEBGL_ENTITY_LINK_GRAPH`, `ACTION_BURST_SWIMLANE_STORYBOARD`. |
| `view_title` | `TEXT` | `NOT NULL` | E.g., `"Rupee-to-USDT Trail for Victim UTR 630914829104"`, `"Circular Mule Ring #2"`. |
| `pinned_node_positions_json` | `TEXT` | `NULL` | JSON map of `{entity_master_uid: [x, y]}` preserving the investigator's custom node arrangements for courtroom PDF export! |
| `active_graph_filters_json` | `TEXT` | `NOT NULL` | Applied time window, minimum INR/USDT threshold, and edge-verb filters. |
| `staged_freeze_cart_items_json` | `TEXT` | `NULL` | JSON array of selected Bank A/Cs, UTRs, VPAs, CEX UIDs, and Crypto Wallets staged for Module 8.4B export. |
| `saved_svg_png_snapshot_sha256` | `TEXT` | `NULL` | High-DPI vector/raster snapshot hash for inclusion as an Exhibit Figure in the Section 63 BSA Courtroom Dossier! |
| `updated_at_ist_iso` | `TEXT` | `NOT NULL` | `"YYYY-MM-DD HH:MM:SS IST (+05:30)"`. |

### Table 2: FastAPI $\leftrightarrow$ Electron Renderer IPC Endpoints for Module 9.3

| Endpoint Method & Path | Request Parameters / Payload | Response Format & Latency Target |
|---|---|---|
| **`GET /api/v1/graph/sankey-laundering`** | `min_amount_inr`, `filter_entity_uid`, `include_penny_drops = true` | 5-Stage stratified nodes (`Columns 0..4`), hybrid-scaled flow ribbons, Smurfing fan groups, P2P triangulation flags, and circular feedback arcs. Target: `< 25 ms`. |
| **`GET /api/v1/graph/webgl-topology`** | `edge_verbs_list`, `time_range_ns`, `max_nodes = 15000` | Binary/MessagePack buffer of node attributes (`entity_uid`, `class`, `rank_score`, `risk_flags`) and directed edges for `GraphPhysicsWorker`. Target: `< 30 ms`. |
| **`POST /api/v1/graph/run-algorithm`** | `algorithm = "CIRCULAR_LOOPS" \| "SHORTEST_PATH" \| "SHARED_RESOURCE_HUBS"`, `source_uid`, `target_uid` | Ordered cycles, shortest evidentiary path array, or high-centrality bridge hubs (`BSSID` / `Gas Wallet` / `Hideout Flat`). Target: `< 20 ms`. |
| **`GET /api/v1/storyboard/action-burst`** | `story_uid` (or `center_timestamp_ns`, `window_sec = 120`) | 5-Swimlane event array (`Physical/Biometric`, `Foreground/AppOps`, `Telecom/Location`, `Financial/Crypto`, `Visual/Chat`) with pre-computed idle-gap fold markers. Target: `< 10 ms`. |

---

## 8. Developer Acceptance Test Checklist for Module 9.3

1. **The 5-Stage Sankey Hybrid Scaling (`₹1.00` Penny-Drop vs. `₹25,00,000` P2P) & Circular Feedback Arc Test:**
   * Load a laundering chain containing a `₹1.00` penny-drop verification credit, two split UPI debits (`₹95,000 + ₹85,000`) into a `₹1,80,000` Binance P2P order (with `is_third_party_payer_mismatch = 1`), a `2,000 USDT` `TRC-20` withdrawal to `TronLink`, and a circular return transfer of `₹50,000` from Stage 2 back to Stage 1.
   * Verify that the `₹1.00` penny-drop ribbon renders at the guaranteed minimum clickable height of $4.0\text{ px}$, the two split UPI transfers group under a `[⚡ SPLIT-UPI SMURFING FAN]` bracket, the P2P node displays the `[TRIANGULATION MISMATCH !]` badge, and the circular transfer renders as a top-arched crimson feedback arc without crashing the DAG layout!
2. **The 10,000-Node WebGL2 Barnes-Hut 60 FPS & Label De-Occlusion Test:**
   * Load a synthetic graph of $10,000$ entities and $25,000$ edges into Sub-Engine 9.3B. Pan and zoom continuously across the canvas.
   * Verify that `GraphPhysicsWorker` (with $\theta = 0.80$ Barnes-Hut quadtree) and WebGL2 instanced rendering maintain $\ge 55\text{ FPS}$, and the 2D screen-space occupancy grid prevents any two visible text labels from overlapping at any zoom level!
3. **The 1-Click Circular Loop, Shortest Path & Lasso Nodal Freeze Cart Test:**
   * Click `Highlight Circular Mule Loops` and verify that the 3-node cycle ($A \rightarrow B \rightarrow C \rightarrow A$) illuminates in crimson. Next, `Shift+Drag` lasso-select the cycle nodes and click `[+ Add Selected to Nodal Freeze Cart]`, verifying that all 3 bank accounts and their 12-digit UTRs populate in `staged_freeze_cart_items_json` for immediate `1930 NCRP` CSV export!
4. **The 5-Swimlane Action-Burst Storyboard & Synchronized Pane 3 Hex Jump Test:**
   * Open Story #04 (`ACTIVE_HUMAN_AUTH_FINANCIAL_OR_CRYPTO_OUTFLOW`) in Sub-Engine 9.3C. Verify that all 5 swimlanes align chronologically (`Keyguard Unlock` $\rightarrow$ `PhonePe InFocus` $\rightarrow$ `SMS OTP` $\rightarrow$ `₹95,000 Debit` $\rightarrow$ `Telegram Screenshot`), and clicking the `₹95,000 Debit` pill in Swimlane 4 immediately jumps **Pane 3B's Hex Viewer** to the exact physical byte offset of that transaction in `phonepe.db`!
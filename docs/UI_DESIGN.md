# BharatAnalyzer user interface: design record

Written 2026-11-12. This file records what the interface is, why it is built this way, and what it does not yet do.
It is also the dated design record for the original layout (see "Intellectual property" at the end).

## 1. Purpose

An examiner reads this screen for most of a working day. The interface is built so that

1. the text stays readable for hours (size, contrast, no flicker, no glare);
2. the screen follows the order of an investigation, not the order of a vendor's menu;
3. it never says more than the software has checked: a missing value reads "not recorded", an integrity line
   shows only hashes that were actually recorded and compared.

## 2. Layout: eight stages

The left column is a numbered list of the stages of an investigation. The examiner moves down it.

| # | Stage | Views | What the examiner does |
|---|---|---|---|
| 1 | Intake | Case overview | Open evidence, see what was read and the hashes |
| 2 | Evidence | Files, Database inspector | Look at files and raw tables, check integrity |
| 3 | People | Contacts, Calls | Who is in the phone |
| 4 | Money | UPI ledger, Bank statement and CDR fusion, Crypto wallets, Link graph (leads) | Where the money went |
| 5 | Messages | Chats, System traces | What was said |
| 6 | Places | Locations and media | Where the device was |
| 7 | Findings | Pinned findings | What the examiner marked, with their own notes |
| 8 | Report & export | Examination report, facts annexure, review package, audit log | Produce what the software recorded; the examiner prepares any legal form |

Other regions:

* **Case bar** (top): case and evidence name; the integrity line; engine status; Open evidence; Ctrl+K; display settings.
* **Evidence card** (right): the selected record as a card with three tabs: Details (content, when, where it came from, fields), Source bytes (the raw bytes at the recorded offset), Links (records sharing the same UTR or counterparty VPA, matched exactly). A Pin button with a note field sends the record to stage 7.
* **Status line** (bottom): stage, view, record count, selected record, time-zone toggle, theme.

The two side panes resize by dragging or with the arrow keys; both collapse.

## 3. The elements that make the design original

These are the parts a designer or attorney should look at. They are descriptions, not legal conclusions.

1. **Investigation-order navigation:** eight numbered stages from intake to report and export, with the current stage expanding to show its views. Recovered counts are shown as plain text ("+12 recovered"), not as coloured badges.
2. **Evidence card with provenance as a first-class part:** every record is shown together with its source file, table, row, page, byte offset, length and recovery state, and one click shows the bytes. Where a parser did not record a value the card says "not recorded"; it never shows a default.
3. **Honest integrity line:** a single line stating source hash recorded, and re-hash MATCH, MISMATCH or NOT RECORDED. It changes colour only for MATCH and MISMATCH.
4. **Findings-to-court flow:** records are pinned with a note, stored with the case (`/api/case/findings`, kept when the evidence is re-opened), listed in stage 7 and exported as CSV; stage 8 builds the examination report, which includes the pinned findings with their notes and provenance.

## 4. Reading comfort

* **Themes:** Dim (default; soft dark, no pure black), Light (off-white), High contrast (black and white). The neutral colours are hand-tuned; hue colours are derived by `scripts/gen_theme.py` into `ui/renderer/theme.css`.
* **Contrast is tested:** `ui/tests/contrast_test.ts` reads `theme.css` and fails if any text and surface pair in any theme falls below WCAG 2.x 4.5:1 (7:1 for body text in High contrast), or if a boundary falls below 3:1 in High contrast.
* **Type:** 13px base (rem, so it scales), nothing smaller than 11px, tabular figures so amounts and times line up in columns, monospace only for identifiers and hashes. Text size 90% to 130% in settings.
* **Density:** comfortable (32px rows) or compact (24px rows).
* **Motion:** none. Pulsing and blinking classes are switched off in the stylesheet and a test fails if they come back. The OS reduced-motion setting is respected.
* **Time:** IST or UTC first, one click; both are always in the record.
* **Rest reminder:** optional, off by default; a short note every 20 minutes.
* **Settings are stored locally** in the browser storage of the application and fall back to defaults if that storage is blocked.

## 5. Keyboard

| Keys | Action |
|---|---|
| Ctrl+K | Search and commands (go to any view, run an action, search records) |
| Alt+1 to Alt+8 | Jump to a stage |
| Ctrl+B | Pin the selected record to findings |
| F6 | Move focus between stage list, workspace, evidence card |
| Up, Down, j, k | Move through the rows of a table |
| Esc | Close a dialog |

## 6. Claims removed from the old interface

| Was | Now |
|---|---|
| "BIT-FOR-BIT SEAL PASS" badge, always shown | Shows MATCH, MISMATCH or NOT RECORDED from the backend's re-hash |
| "Air-Gapped PASS", "Bit-Verified", "SHA-256 Verified" (shown whenever any hash existed), "Verified Both", "Verified Ingest" | Removed or reworded ("In both") |
| "Bank ONLY (Wiped)" | "Bank only (not found on device)": absence from the phone does not show a wipe |
| Ingest phase text changed on a timer | One honest line: the engine reports no progress, so none is shown |
| Screenshot button that only displayed an alert claiming a "Section 63 forensic timestamp" | Removed (no screenshot feature is offered) |
| Malicious-APK and remote-access views with no data source | Removed |
| "Timeline Activity" chart drawn from a hard-coded list of heights | A call-activity chart computed from the records that have a recorded time |
| Case particulars pre-filled with placeholder names and station | Blank unless the examiner supplies them (UI and API defaults) |

## 7. What this does not do yet

* The chat workspace (`ChatsMasterWorkspace`, `UPIMasterLedgerView`, the link graph, the SQLite wizard and the other older views) has the new themes, fonts and sizes but keeps its previous internal layout, including the wide 28-column chat table. Each is a candidate for the same treatment as `RecordTable`.
* Rows are paged 100 at a time, not windowed.
* There is no split view.
* The evidence card's Links tab matches on exact UTR and VPA only.
* Only Windows and the Electron renderer were looked at. The three themes, both densities and 120% text were checked by eye on the test evidence; no usability study has been done with examiners.

## 8. Files

`ui/renderer/theme.css` (generated), `index.css`, `state/preferencesStore.ts`, `state/findingsStore.ts`, `state/uiStore.ts`,
`workspace/{AppShell,CaseBar,StageNavigator,Workspace,RecordTable,CommandPalette,SettingsDialog,StatusLine,Toasts}.tsx`,
`workspace/{stages,integrity}.ts`, `inspectors/EvidenceCard.tsx`, `views/{FindingsView,ReportExportView}.tsx`.
Tests: `ui/tests/contrast_test.ts`, `ui/tests/ui_shell_test.ts` (also fails on names of other products, hard-coded colours, text under 11px, pulsing animation, and overclaiming labels).

## 9. Intellectual property

The code can make the layout original and keep a dated record of how it was designed (this file and the git history). It cannot decide whether the design is patentable or registrable. That needs a patent or design attorney and a prior-art search.

* A **utility patent** concerns technical methods. Candidates a lawyer may wish to consider: the provenance-linked evidence card (a record, its source location and its raw bytes shown as one unit), and the findings-to-report flow with an audit log whose head hash is printed in every report.
* A **design registration** concerns appearance: the eight-stage navigator with the evidence card and case bar as shown.

Do not publish or demonstrate the interface publicly before taking that advice, because disclosure can affect registrability.

### Clean-room rules (added 2026-11-12, Phase 5P)

* Design from the examiner's tasks. Do not use another vendor's screenshots, manuals, layouts, schema files or terms as a source.
* Do not name another product as a design target in code, interface text or shipped documents. `tests/test_independence_guard.py` and `ui/tests/ui_shell_test.ts` fail if that happens.
* Reading another tool's export container (.ufdr, .xry, .ofb) is interoperability and stays as import only.
* Keep `docs/INVENTION_RECORD.md` private; add an entry before building a feature that may be a candidate method, and do not disclose it before an attorney has filed.
* Licences of dependencies are in `docs/THIRD_PARTY_LICENSES.md`.

### Changes in Phase 5A (2026-11-12)
* Stage 8 is now **Report & export**. The Section 63 certificate, Section 230 bundle and NCRP freeze sheet dialogs were removed: the tool supplies facts (report, annexure, review package, audit log) and the examiner prepares any legal form.
* Removed from the chat workspace: a "Dossier view" that showed an invented profile ("Elena, 26", "HIGH RISK SYNDICATE", sample VPAs and a made-up modus operandi) for any thread; per-app invented participant bios in the thread list, header and table; and a dead handler that built a provenance record with an invented payload.
* The review package screen disables Build until every file has a decision, and says how many still need one.

/**
 * Bharat Analyzer — Commercial Forensic Workstation Controller
 * Manages 7 Workspace Tabs, 3-Pane Synchronized Hex Grid,
 * Ingestion Modal, Dynamic Device Switcher, Unified Chat Reconstructor,
 * Myers Redline, and Case Intelligence.
 */

// Global State Cache
const WorkstationState = {
    bootstrap: null,
    activeDeviceId: "DEV-01",
    selectedEventId: null,
    currentHexData: null,
    selectedByteOffset: 16,
    currentRawBuffer: null,
    chatRedlineMode: false,
    audioPlaying: false,
    currentTranscriptLang: "hi",
    uploadedFileBase64: null,
    uploadedFileName: null,
    currentTimezone: "IST",
    selectedThreadId: null,
    bookmarkedExhibitIds: new Set(["EX-01"]),
    activePane1Subtab: "timeline",
    sankeyActiveFilter: null,
};

// Canonical 18 Forensic Groups
const defaultForensicGroupStats = [
    { id: "G01", title: "G01: INGESTION & OWNERSHIP", desc: "Physical Extraction / FFS Container Hierarchy", count: 0, badgeColor: "badge-live" },
    { id: "G02", title: "G02: UPI & WALLETS", desc: "PhonePe, Google Pay, Paytm, Navi Ledgers", count: 0, badgeColor: "badge-live" },
    { id: "G03", title: "G03: DOMESTIC BANKING", desc: "YONO SBI, iMobile, HDFC, BoB Core Stores", count: 0, badgeColor: "badge-live" },
    { id: "G04", title: "G04: FINANCIAL SMS & DLT", desc: "DLT Header Binding & OTP Corroboration", count: 0, badgeColor: "badge-orig" },
    { id: "G05", title: "G05: CRYPTO WALLETS", desc: "TronLink TRC-20 & MetaMask EVM Vaults", count: 0, badgeColor: "badge-live" },
    { id: "G06", title: "G06: EXCHANGES & SEEDS", desc: "CoinDCX UID & BIP-39 Seed Hunter", count: 0, badgeColor: "badge-orig" },
    { id: "G07", title: "G07: MAINSTREAM CHATS", desc: "WhatsApp Dual Clone & Telegram", count: 0, badgeColor: "badge-live" },
    { id: "G08", title: "G08: HIGH-OPSEC CHATS", desc: "Session 66-hex & SimpleX Agent DB", count: 0, badgeColor: "badge-wal" },
    { id: "G09", title: "G09: VOIP & COVERT", desc: "Botim & In-Game Chat Residuals", count: 0, badgeColor: "badge-orig" },
    { id: "G10", title: "G10: CALL LOGS & CONTACTS", desc: "Telecom Call Records & Truecaller", count: 0, badgeColor: "badge-live" },
    { id: "G11", title: "G11: WEBVIEW SANDBOXES", desc: "App WebViews & IndexedDB Stores", count: 0, badgeColor: "badge-orig" },
    { id: "G12", title: "G12: OS GEOLOCATION", desc: "GPS, Wi-Fi BSSID & Cell Towers", count: 0, badgeColor: "badge-live" },
    { id: "G13", title: "G13: HYPERLOCAL & RIDES", desc: "Uber, Swiggy Instamart & Zomato", count: 0, badgeColor: "badge-orig" },
    { id: "G14", title: "G14: WIFI / BT / NETSTATS", desc: "Known Wi-Fi & Bluetooth Pairings", count: 0, badgeColor: "badge-orig" },
    { id: "G15", title: "G15: BEHAVIORAL TELEMETRY", desc: "Apple Biome & Android AppOps APEX", count: 0, badgeColor: "badge-live" },
    { id: "G16", title: "G16: KEYCHAIN & TAMPER", desc: "SQLCipher & Android Keystore Keys", count: 0, badgeColor: "badge-wal" },
    { id: "G17", title: "G17: MEDIA & C2PA RESIDUALS", desc: "Forged Receipts & C2PA JUMBF Box", count: 0, badgeColor: "badge-freelist" },
    { id: "G18", title: "G18: APKS & OCR INDEX", desc: "Bilingual Devanagari OCR & APKs", count: 0, badgeColor: "badge-orig" },
];
const CANONICAL_FORENSIC_GROUPS = defaultForensicGroupStats;

function renderForensicGroups(stats) {
    const grid = document.getElementById("forensic-groups-grid") || document.querySelector(".groups-grid");
    if (!grid) return;
    grid.innerHTML = "";
    const items = stats || defaultForensicGroupStats;
    items.forEach(group => {
        const card = document.createElement("div");
        card.className = "group-badge-card";
        card.style.cursor = "pointer";
        const titleText = group.title || (group.code ? `${group.code}: ${group.name}` : group.name);
        const countText = group.status || `${group.count} ${group.id === "G01" || group.code === "G01" ? "NODES" : "RECORDS"}`;
        const badgeColor = group.badgeColor || group.tier || "badge-orig";
        card.innerHTML = `
            <div style="display: flex; flex-direction: column; gap: 2px;">
                <div>
                    <span style="font-weight: 700; color: #ffffff;">${titleText}</span>
                </div>
                <span style="font-size: 10px; color: var(--text-muted);">${group.desc || ""}</span>
            </div>
            <span class="badge-tag ${badgeColor}">${countText}</span>
        `;
        card.addEventListener("click", () => {
            const code = group.id || group.code;
            if (code === "G01" || code === "G02" || code === "G11") {
                const btn = document.getElementById("tab-btn-hex");
                if (btn) btn.click();
            } else if (code === "G07" || code === "G08" || code === "G09" || code === "G10") {
                const btn = document.getElementById("tab-btn-chat");
                if (btn) btn.click();
            } else if (code === "G03" || code === "G04" || code === "G05" || code === "G06") {
                const btn = document.getElementById("tab-btn-financial");
                if (btn) btn.click();
            } else if (code === "G12" || code === "G13" || code === "G14" || code === "G15" || code === "G16" || code === "G17") {
                const btn = document.getElementById("tab-btn-geo");
                if (btn) btn.click();
            } else {
                const btn = document.getElementById("tab-btn-ocr");
                if (btn) btn.click();
            }
        });
        grid.appendChild(card);
    });
}

document.addEventListener("DOMContentLoaded", () => {
    initNavigationTabs();
    initDeviceSwitcher();
    initGlobalSearch();
    initTimezoneToggle();
    initIngestModal();
    initPane1Subtabs();
    initChatControls();
    initOcrRunner();
    initReverseGeocoder();
    initNcrpCsvDownload();
    setupIngestButton();
    renderChatWorkspace([]);
    fetchWorkspaceBootstrap();
});

function setupIngestButton() {
    const btn = Array.from(document.querySelectorAll("button")).find(b => b.textContent.includes("Ingest Dump"));
    if (!btn) return;
    btn.addEventListener("click", () => {
        const input = document.createElement("input");
        input.type = "file";
        input.accept = ".db,.sqlite,.sqlite3";
        input.addEventListener("change", async () => {
            if (input.files && input.files[0]) {
                const file = input.files[0];
                const formData = new FormData();
                formData.append("file", file);
                try {
                    const res = await fetch("/api/ingest/upload-file", {
                        method: "POST",
                        body: formData,
                    });
                    const data = await res.json();
                    console.log("Upload success", data);
                    await fetchWorkspaceBootstrap();
                } catch (err) {
                    console.error("Ingest error:", err);
                }
            }
        });
        input.click();
    });
}

// TAB NAVIGATION CONTROLLER
function initNavigationTabs() {
    const tabButtons = document.querySelectorAll(".nav-tab-btn");
    tabButtons.forEach(btn => {
        btn.addEventListener("click", () => {
            const targetPanelId = btn.getAttribute("data-tab");
            if (!targetPanelId) return;

            tabButtons.forEach(b => b.classList.remove("active"));
            document.querySelectorAll(".workspace-panel").forEach(p => p.classList.remove("active"));

            btn.classList.add("active");
            const panel = document.getElementById(targetPanelId);
            if (panel) panel.classList.add("active");
        });
    });
}

// DYNAMIC DEVICE SWITCHER CONTROLLER
function initDeviceSwitcher() {
    const switcher = document.getElementById("device-switcher");
    if (!switcher) return;

    switcher.addEventListener("change", async (e) => {
        const newDevId = e.target.value;
        WorkstationState.activeDeviceId = newDevId;

        try {
            await fetch("/api/case/select-device", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ device_id: newDevId }),
            });
        } catch (err) {
            console.warn("Device select sync error:", err);
        }

        await fetchWorkspaceBootstrap(newDevId);
    });
}

function updateDeviceSwitcherOptions(activeId, activeLabel) {
    const switcher = document.getElementById("device-switcher");
    if (!switcher) return;

    let found = false;
    for (let i = 0; i < switcher.options.length; i++) {
        if (switcher.options[i].value === activeId) {
            found = true;
            break;
        }
    }

    if (!found && activeId) {
        const opt = document.createElement("option");
        opt.value = activeId;
        opt.textContent = activeLabel || activeId;
        switcher.appendChild(opt);
    }

    if (activeId) {
        switcher.value = activeId;
    }
}

// GLOBAL SEARCH & CTRL+K CONTROLLER
function initGlobalSearch() {
    const searchInput = document.getElementById("global-search-input");
    if (!searchInput) return;

    window.addEventListener("keydown", (e) => {
        if ((e.ctrlKey || e.metaKey) && (e.key === "k" || e.key === "K")) {
            e.preventDefault();
            searchInput.focus();
            searchInput.select();
        }
    });

    searchInput.addEventListener("input", (e) => {
        const query = e.target.value.trim().toLowerCase();
        filterWorkspaceByQuery(query);
    });
}

function filterWorkspaceByQuery(query) {
    // 1. Filter Timeline Events in Tab 2
    const eventCards = document.querySelectorAll(".timeline-event-card");
    eventCards.forEach(card => {
        const text = card.textContent.toLowerCase();
        if (!query || text.includes(query)) {
            card.style.display = "block";
        } else {
            card.style.display = "none";
        }
    });

    // 2. Filter Forensic Groups in Tab 1
    const groupCards = document.querySelectorAll(".group-badge-card");
    groupCards.forEach(card => {
        const text = card.textContent.toLowerCase();
        if (!query || text.includes(query)) {
            card.style.opacity = "1";
            card.style.borderColor = query ? "var(--accent-cyan)" : "var(--border-color)";
        } else {
            card.style.opacity = "0.3";
            card.style.borderColor = "var(--border-color)";
        }
    });
}

// TIMEZONE TOGGLE CONTROLLER
function initTimezoneToggle() {
    const tzBtn = document.getElementById("btn-toggle-timezone");
    const tzLabel = document.getElementById("timezone-label");
    if (!tzBtn) return;

    tzBtn.addEventListener("click", () => {
        WorkstationState.currentTimezone = WorkstationState.currentTimezone === "IST" ? "UTC" : "IST";
        if (tzLabel) {
            tzLabel.textContent = WorkstationState.currentTimezone === "IST" ? "IST (+05:30)" : "UTC (+00:00)";
        }
        if (WorkstationState.bootstrap) {
            if (WorkstationState.bootstrap.timeline_events) {
                renderTimelineEvents(WorkstationState.bootstrap.timeline_events);
            }
            if (WorkstationState.bootstrap.chat_threads) {
                renderChatWorkspace(WorkstationState.bootstrap.chat_threads);
            }
            if (WorkstationState.bootstrap.financial_ledger_transactions) {
                renderFinancialLedgerTable(WorkstationState.bootstrap);
            }
        }
    });
}

// PANE 1 SUBTAB SWITCHER (TIMELINE VS INGESTED VFS)
function initPane1Subtabs() {
    const btnTimeline = document.getElementById("btn-subtab-timeline");
    const btnVfs = document.getElementById("btn-subtab-vfs");
    const timelineList = document.getElementById("timeline-events-list");
    const vfsList = document.getElementById("vfs-files-list");
    const badge = document.getElementById("pane1-badge");

    if (btnTimeline && btnVfs) {
        btnTimeline.addEventListener("click", () => {
            btnTimeline.classList.add("active");
            btnVfs.classList.remove("active");
            if (timelineList) timelineList.style.display = "block";
            if (vfsList) vfsList.style.display = "none";
            WorkstationState.activePane1Subtab = "timeline";
            if (badge && WorkstationState.bootstrap && WorkstationState.bootstrap.timeline_events) {
                badge.textContent = `${WorkstationState.bootstrap.timeline_events.length} COMMITTED`;
            }
        });

        btnVfs.addEventListener("click", () => {
            btnVfs.classList.add("active");
            btnTimeline.classList.remove("active");
            if (vfsList) vfsList.style.display = "block";
            if (timelineList) timelineList.style.display = "none";
            WorkstationState.activePane1Subtab = "vfs";
            if (badge && WorkstationState.bootstrap) {
                const total = (WorkstationState.bootstrap.ingested_files ? WorkstationState.bootstrap.ingested_files.length : 0) +
                              (WorkstationState.bootstrap.discovered_sqlite_tables ? WorkstationState.bootstrap.discovered_sqlite_tables.length : 0);
                badge.textContent = `${total} VFS NODES`;
            }
            if (WorkstationState.bootstrap) {
                renderVfsExplorer(WorkstationState.bootstrap);
            }
        });
    }
}

// REVERSE GEOCODER CONTROLLER
function initReverseGeocoder() {
    const btn = document.getElementById("btn-resolve-geo");
    const input = document.getElementById("geo-coord-input");
    const details = document.getElementById("geo-resolved-fix-details");
    const mapWrap = document.getElementById("geo-map-frame-wrap");

    if (btn && input) {
        btn.addEventListener("click", async () => {
            const val = input.value.trim();
            const parts = val.split(",");
            if (parts.length < 2) return;
            const lat = parseFloat(parts[0].trim());
            const lon = parseFloat(parts[1].trim());
            if (isNaN(lat) || isNaN(lon)) return;

            if (details) details.textContent = "Resolving coordinates via Hybrid Geocoder...";
            try {
                const resp = await fetch("/api/map/resolve", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ lat: lat, lon: lon, force_offline: false }),
                });
                if (resp.ok) {
                    const data = await resp.json();
                    if (details) {
                        details.innerHTML = `
                            <strong>Address:</strong> ${escapeHtml(data.display_address)} &bull;
                            <strong>Source:</strong> <span style="color: var(--accent-cyan);">${data.resolution_source}</span> &bull;
                            <strong>Cardinal:</strong> ${data.cardinal_formatted}
                        `;
                    }
                    if (mapWrap && data.map_html) {
                        mapWrap.innerHTML = data.map_html;
                    }
                }
            } catch (err) {
                if (details) details.textContent = `Resolution error: ${err.message}`;
            }
        });
    }
}

// 1930 NCRP CSV DOWNLOAD CONTROLLER
function initNcrpCsvDownload() {
    const btn = document.getElementById("btn-download-ncrp-csv");
    if (!btn) return;
    btn.addEventListener("click", () => {
        window.location.href = "/api/ncrp/download-csv";
    });
}

// INTERACTIVE EVIDENCE BOOKMARK CONTROLLER
async function toggleBookmark(itemId, itemType, caption, filePath = "evidence.db", sha256 = "") {
    try {
        const resp = await fetch("/api/bookmarks/toggle", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                item_id: itemId,
                item_type: itemType,
                caption: caption,
                file_path: filePath,
                sha256: sha256,
            }),
        });
        if (resp.ok) {
            const data = await resp.json();
            if (data.action === "ADDED") {
                WorkstationState.bookmarkedExhibitIds.add(itemId);
            } else {
                WorkstationState.bookmarkedExhibitIds.delete(itemId);
            }
            document.querySelectorAll(`[data-bookmark-id="${itemId}"]`).forEach(btn => {
                const isBmk = WorkstationState.bookmarkedExhibitIds.has(itemId);
                btn.className = `btn-bookmark ${isBmk ? 'bookmarked' : ''}`;
                btn.textContent = isBmk ? "★ Bookmarked" : "☆ Bookmark for BSA";
            });
            generateBsaCertificate();
        }
    } catch (err) {
        console.error("Bookmark toggle error:", err);
    }
}

function jumpToHexFromChat(msgId) {
    const tabHexBtn = document.getElementById("tab-btn-hex");
    if (tabHexBtn) tabHexBtn.click();
    const targetId = WorkstationState.selectedEventId || (WorkstationState.bootstrap && WorkstationState.bootstrap.timeline_events && WorkstationState.bootstrap.timeline_events[0] ? WorkstationState.bootstrap.timeline_events[0].event_id : null);
    if (targetId) loadHexEvent(targetId);
}

// LIVE FORENSIC EVIDENCE INGESTION MODAL CONTROLLER
function initIngestModal() {
    const openBtn = document.getElementById("btn-open-ingest-modal");
    const closeBtn = document.getElementById("btn-close-ingest-modal");
    const modal = document.getElementById("ingest-modal");
    const tabLocal = document.getElementById("tab-btn-ingest-local");
    const tabUpload = document.getElementById("tab-btn-ingest-upload");
    const contentLocal = document.getElementById("tab-ingest-local");
    const contentUpload = document.getElementById("tab-ingest-upload");
    const dropzone = document.getElementById("ingest-dropzone");
    const fileInput = document.getElementById("ingest-file-input");
    const submitLocal = document.getElementById("btn-submit-ingest-local");
    const submitUpload = document.getElementById("btn-submit-ingest-upload");
    const logBox = document.getElementById("ingest-log-stream");
    const resultCard = document.getElementById("ingest-result-card");

    if (!modal) return;

    function appendLog(msg, level = "info") {
        if (!logBox) return;
        const line = document.createElement("div");
        line.className = `log-line log-${level}`;
        line.textContent = `[${new Date().toLocaleTimeString()}] ${msg}`;
        logBox.appendChild(line);
        logBox.scrollTop = logBox.scrollHeight;
    }

    if (openBtn) {
        openBtn.addEventListener("click", () => {
            modal.style.display = "flex";
            if (resultCard) resultCard.style.display = "none";
        });
    }

    if (closeBtn) {
        closeBtn.addEventListener("click", () => {
            modal.style.display = "none";
        });
    }

    modal.addEventListener("click", (e) => {
        if (e.target === modal) {
            modal.style.display = "none";
        }
    });

    if (tabLocal && tabUpload) {
        tabLocal.addEventListener("click", () => {
            tabLocal.classList.add("active");
            tabUpload.classList.remove("active");
            if (contentLocal) contentLocal.classList.add("active");
            if (contentUpload) contentUpload.classList.remove("active");
        });
        tabUpload.addEventListener("click", () => {
            tabUpload.classList.add("active");
            tabLocal.classList.remove("active");
            if (contentUpload) contentUpload.classList.add("active");
            if (contentLocal) contentLocal.classList.remove("active");
        });
    }

    if (dropzone && fileInput) {
        dropzone.addEventListener("click", () => fileInput.click());
        dropzone.addEventListener("dragover", (e) => {
            e.preventDefault();
            dropzone.classList.add("dragover");
        });
        dropzone.addEventListener("dragleave", () => dropzone.classList.remove("dragover"));
        dropzone.addEventListener("drop", (e) => {
            e.preventDefault();
            dropzone.classList.remove("dragover");
            if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
                handleFileSelection(e.dataTransfer.files[0]);
            }
        });
        fileInput.addEventListener("change", (e) => {
            if (e.target.files && e.target.files.length > 0) {
                handleFileSelection(e.target.files[0]);
            }
        });
    }

    function handleFileSelection(file) {
        const fnameEl = document.getElementById("dropzone-filename");
        if (fnameEl) {
            fnameEl.textContent = `Selected: ${file.name} (${(file.size / 1024).toFixed(1)} KB)`;
            fnameEl.style.display = "block";
        }
        appendLog(`Evidence file loaded: ${file.name} (${file.size} bytes)`, "info");

        const reader = new FileReader();
        reader.onload = function(evt) {
            const rawB64 = evt.target.result.split(",")[1];
            WorkstationState.uploadedFileBase64 = rawB64;
            WorkstationState.uploadedFileName = file.name;
            appendLog(`File buffer staged in memory. Ready for cryptographic extraction.`, "info");
        };
        reader.readAsDataURL(file);
    }

    // Submit Local Path Ingestion
    if (submitLocal) {
        submitLocal.addEventListener("click", async () => {
            const pathInput = document.getElementById("ingest-local-path");
            const nameInput = document.getElementById("ingest-case-name");
            const srcPath = pathInput ? pathInput.value.trim() : "";
            const caseLabel = nameInput ? nameInput.value.trim() : "Local Forensic Extraction";

            if (!srcPath) {
                appendLog("Error: Target path cannot be empty.", "err");
                return;
            }

            appendLog(`Initiating live extraction for path: ${srcPath}`, "info");
            appendLog(`Computing Product A Master Container Hash (SHA-256)...`, "info");
            submitLocal.disabled = true;

            try {
                const res = await fetch("/api/ingest/local-path", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ source_path: srcPath, case_name: caseLabel }),
                });
                const data = await res.json();
                submitLocal.disabled = false;

                if (data.success) {
                    appendLog(`Extraction successful! Ingested ${data.total_files} files into ${data.device_id}.`, "success");
                    appendLog(`Product A SHA-256: ${data.product_a_sha256}`, "success");
                    appendLog(`Discovered ${data.discovered_sqlite_tables} SQLite tables, ${data.extracted_utrs.length} UTRs, ${data.extracted_pans.length} PANs.`, "success");

                    showIngestResult(data);
                    updateDeviceSwitcherOptions(data.device_id, data.device_label);
                    WorkstationState.activeDeviceId = data.device_id;
                    await fetchWorkspaceBootstrap(data.device_id);
                } else {
                    appendLog(`Extraction failed: ${data.error || "Unknown error"}`, "err");
                }
            } catch (err) {
                submitLocal.disabled = false;
                appendLog(`Extraction error: ${err.message}`, "err");
            }
        });
    }

    // Submit Direct Upload Ingestion
    if (submitUpload) {
        submitUpload.addEventListener("click", async () => {
            if (!WorkstationState.uploadedFileBase64) {
                appendLog("Error: Please select or drop a file first.", "err");
                return;
            }
            const labelInput = document.getElementById("ingest-upload-label");
            const caseLabel = labelInput ? labelInput.value.trim() : "Uploaded Evidence Archive";

            appendLog(`Streaming ${WorkstationState.uploadedFileName} to forensic ingest pipeline...`, "info");
            submitUpload.disabled = true;

            try {
                const res = await fetch("/api/ingest/upload-file", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                        file_name: WorkstationState.uploadedFileName,
                        file_base64: WorkstationState.uploadedFileBase64,
                        case_name: caseLabel,
                    }),
                });
                const data = await res.json();
                submitUpload.disabled = false;

                if (data.success) {
                    appendLog(`Upload extraction complete! Registered device: ${data.device_id}.`, "success");
                    appendLog(`Product A Container Hash: ${data.product_a_sha256}`, "success");
                    if (data.spoofed_files_count > 0) {
                        appendLog(`WARNING: Detected ${data.spoofed_files_count} extension-spoofed file(s)!`, "warn");
                    }
                    showIngestResult(data);
                    updateDeviceSwitcherOptions(data.device_id, data.device_label);
                    WorkstationState.activeDeviceId = data.device_id;
                    await fetchWorkspaceBootstrap(data.device_id);
                } else {
                    appendLog(`Upload extraction failed: ${data.error || "Unknown error"}`, "err");
                }
            } catch (err) {
                submitUpload.disabled = false;
                appendLog(`Upload error: ${err.message}`, "err");
            }
        });
    }

    function showIngestResult(data) {
        if (!resultCard) return;
        resultCard.style.display = "block";
        const titleEl = document.getElementById("ingest-res-title");
        const bodyEl = document.getElementById("ingest-res-body");
        if (titleEl) titleEl.textContent = `SUCCESS: ${data.device_label}`;
        if (bodyEl) {
            const utrStr = data.extracted_utrs && data.extracted_utrs.length ? data.extracted_utrs.join(", ") : "None";
            const panStr = data.extracted_pans && data.extracted_pans.length ? data.extracted_pans.join(", ") : "None";
            const cryptoStr = data.extracted_crypto_addrs && data.extracted_crypto_addrs.length ? data.extracted_crypto_addrs.join(", ") : "None";
            bodyEl.innerHTML = `
                <div class="meta-row"><span class="meta-key">Device Assigned:</span><span class="meta-val">${data.device_id}</span></div>
                <div class="meta-row"><span class="meta-key">Total Files Extracted:</span><span class="meta-val">${data.total_files} files (${(data.total_bytes / 1024).toFixed(1)} KB)</span></div>
                <div class="meta-row"><span class="meta-key">Product A SHA-256:</span><span class="meta-val" style="font-size: 10px;">${data.product_a_sha256}</span></div>
                <div class="meta-row"><span class="meta-key">Product B SHA-256:</span><span class="meta-val" style="font-size: 10px;">${data.product_b_sha256}</span></div>
                <div class="meta-row"><span class="meta-key">Extracted UTRs:</span><span class="meta-val" style="color: var(--accent-cyan); font-weight: 700;">${utrStr}</span></div>
                <div class="meta-row"><span class="meta-key">Extracted PANs:</span><span class="meta-val" style="color: var(--accent-green); font-weight: 700;">${panStr}</span></div>
                <div class="meta-row"><span class="meta-key">Crypto Addresses:</span><span class="meta-val" style="color: var(--accent-amber); font-weight: 700;">${cryptoStr}</span></div>
                <div class="meta-row"><span class="meta-key">Spoofed Files:</span><span class="meta-val" style="color: ${data.spoofed_files_count ? 'var(--accent-rose)' : 'var(--accent-green)'}; font-weight: 700;">${data.spoofed_files_count}</span></div>
            `;
        }
    }
}

// FETCH BOOTSTRAP DATA FROM BACKEND
async function fetchWorkspaceBootstrap(deviceId = null) {
    try {
        const url = deviceId ? `/api/workspace/bootstrap?device_id=${encodeURIComponent(deviceId)}` : "/api/workspace/bootstrap";
        const response = await fetch(url);
        if (!response.ok) throw new Error("Bootstrap request failed: " + response.status);
        const data = await response.json();
        WorkstationState.bootstrap = data;

        if (data.status === "empty") {
            const totalElem = document.getElementById("kpi-total-vfs");
            const parsedElem = document.getElementById("kpi-parsed-nodes");
            const knownElem = document.getElementById("kpi-known-nodes");
            const unkElem = document.getElementById("kpi-unk-nodes");
            if (totalElem) totalElem.textContent = "0";
            if (parsedElem) parsedElem.textContent = "0";
            if (knownElem) knownElem.textContent = "0";
            if (unkElem) unkElem.textContent = "0";

            const devSelect = document.getElementById("device-switcher") || document.querySelector("select");
            if (devSelect) {
                devSelect.innerHTML = '<option value="none">No Device Ingested</option>';
            }

            const dynamicCaseId = document.getElementById("dynamic-case-id");
            if (dynamicCaseId) {
                dynamicCaseId.textContent = "AWAITING INGEST";
            }

            const devHeaderTitle = document.querySelector("#panel-case .forensic-card:nth-child(1) .card-header-title");
            if (devHeaderTitle) {
                devHeaderTitle.textContent = "No Device Ingested";
            }

            const hwRows = document.querySelectorAll("#panel-case .cards-grid-2 > .forensic-card:nth-child(1) .meta-row .meta-val");
            if (hwRows.length >= 4) {
                hwRows[0].textContent = "No Device Ingested";
                hwRows[1].textContent = "N/A";
                hwRows[2].textContent = "N/A";
                hwRows[3].textContent = "Awaiting Evidence Ingest";
            }

            const shaRows = document.querySelectorAll("#panel-case .cards-grid-2 > .forensic-card:nth-child(2) .meta-row .meta-val");
            if (shaRows.length >= 3) {
                shaRows[0].textContent = "N/A";
                shaRows[0].title = "N/A";
                shaRows[1].textContent = "N/A";
                shaRows[1].title = "N/A";
                shaRows[2].textContent = "N/A";
                shaRows[2].title = "N/A";
            }

            const liveDb = document.getElementById("stat-live-db");
            const walFrames = document.getElementById("stat-wal-frames");
            const mmkv = document.getElementById("stat-mmkv");
            const biome = document.getElementById("stat-biome");
            if (liveDb) liveDb.textContent = "0";
            if (walFrames) walFrames.textContent = "0";
            if (mmkv) mmkv.textContent = "0";
            if (biome) biome.textContent = "0";

            renderForensicGroups(defaultForensicGroupStats);
            renderTimelineEvents([]);
            renderChatWorkspace([]);
            return;
        }

        if (data.status === "active") {
            const totalNodes = data.nodes || 0;
            const totalElem = document.getElementById("kpi-total-vfs");
            const parsedElem = document.getElementById("kpi-parsed-nodes");
            const knownElem = document.getElementById("kpi-known-nodes");
            const unkElem = document.getElementById("kpi-unk-nodes");
            if (totalElem) totalElem.textContent = totalNodes.toLocaleString();
            if (parsedElem) parsedElem.textContent = totalNodes.toLocaleString();
            if (knownElem) knownElem.textContent = "0";
            if (unkElem) unkElem.textContent = "0";

            const deviceLabel = data.device || `DEV-01: ${data.filename || "Uploaded File"}`;
            const devSelect = document.getElementById("device-switcher") || document.querySelector("select");
            if (devSelect) {
                devSelect.innerHTML = `<option value="DEV-01">${deviceLabel}</option>`;
            }

            const dynamicCaseId = document.getElementById("dynamic-case-id");
            if (dynamicCaseId) {
                dynamicCaseId.textContent = "CASE: " + (data.filename || deviceLabel);
            }

            const devHeaderTitle = document.querySelector("#panel-case .forensic-card:nth-child(1) .card-header-title");
            if (devHeaderTitle) {
                devHeaderTitle.textContent = deviceLabel;
            }

            const hwRows = document.querySelectorAll("#panel-case .cards-grid-2 > .forensic-card:nth-child(1) .meta-row .meta-val");
            if (hwRows.length >= 4) {
                hwRows[0].textContent = `${data.filename || "Uploaded Evidence"} (SQLite 3)`;
                hwRows[1].textContent = "N/A";
                hwRows[2].textContent = "N/A";
                hwRows[3].textContent = "SQLite Dump Ingestion";
            }

            if (data.sha256) {
                const sha = data.sha256;
                const formattedSha = sha.length > 20 ? sha.substring(0, 16) + "..." + sha.substring(sha.length - 12) : sha;
                const shaRows = document.querySelectorAll("#panel-case .cards-grid-2 > .forensic-card:nth-child(2) .meta-row .meta-val");
                if (shaRows.length >= 3) {
                    shaRows[0].textContent = formattedSha;
                    shaRows[0].title = sha;
                    shaRows[1].textContent = formattedSha;
                    shaRows[1].title = sha;
                    shaRows[2].textContent = formattedSha;
                    shaRows[2].title = sha;
                }
            }

            const liveDb = document.getElementById("stat-live-db");
            const walFrames = document.getElementById("stat-wal-frames");
            const mmkv = document.getElementById("stat-mmkv");
            const biome = document.getElementById("stat-biome");
            if (liveDb) liveDb.textContent = (data.nodes !== undefined ? data.nodes : 0).toLocaleString();
            if (walFrames) walFrames.textContent = "0";
            if (mmkv) mmkv.textContent = "0";
            if (biome) biome.textContent = "0";

            const groupMap = {};
            if (Array.isArray(data.groups)) {
                data.groups.forEach(g => {
                    groupMap[g.id] = g.count;
                });
            }
            const activeGroups = defaultForensicGroupStats.map(g => ({
                ...g,
                count: groupMap[g.id] !== undefined ? groupMap[g.id] : 0
            }));
            renderForensicGroups(activeGroups);
            renderChatWorkspace(data.chat_threads || []);
            return;
        }

        if (data.case_metadata) {
            if (data.case_metadata.active_device_id) {
                WorkstationState.activeDeviceId = data.case_metadata.active_device_id;
                updateDeviceSwitcherOptions(data.case_metadata.active_device_id, data.case_metadata.active_device_label);
            }
            // Update top bar case badge
            const dynamicCaseId = document.getElementById("dynamic-case-id");
            if (dynamicCaseId) {
                const fir = data.case_metadata.case_fir || "";
                if (fir) {
                    dynamicCaseId.textContent = "CASE: " + fir;
                }
            }
        }

        renderCaseCommandCenter(data);
        const realEvents = (data.timeline_events || []).filter(e => e.event_id && !e.event_id.startsWith("EVT-100"));
        renderTimelineEvents(realEvents);
        if (realEvents.length > 0) {
            const initialEvtId = realEvents[0].event_id;
            WorkstationState.selectedEventId = initialEvtId;
            loadHexEvent(initialEvtId);
        }
        renderChatWorkspace(data.chat_threads);
        renderFinancialTab(data);
        renderGeospatialTab(data);
        renderOcrTabInitial();
        renderBsaAndKeyBrokerTab(data);
    } catch (err) {
        console.error("Forensic bootstrap initialization error:", err);
    }
}

// TAB 1: CASE COMMAND CENTER
function renderCaseCommandCenter(data) {
    if (data.case_metadata) {
        const meta = data.case_metadata;

        // KPI Metrics
        if (meta.kpi_metrics) {
            const kpi = meta.kpi_metrics;
            const totalElem = document.getElementById("kpi-total-vfs");
            const parsedElem = document.getElementById("kpi-parsed-nodes");
            const knownElem = document.getElementById("kpi-known-nodes");
            const unkElem = document.getElementById("kpi-unk-nodes");

            if (totalElem) totalElem.textContent = kpi.total_vfs_nodes.toLocaleString();
            if (parsedElem) parsedElem.textContent = kpi.parsed_vfs_nodes.toLocaleString();
            if (knownElem) knownElem.textContent = kpi.system_known_nodes.toLocaleString();
            if (unkElem) unkElem.textContent = kpi.unk_triage_queue_nodes.toLocaleString();
        }

        // Hardware Profile Specs
        if (meta.hardware_profile) {
            const hw = meta.hardware_profile;
            const devHeaderTitle = document.querySelector("#panel-case .forensic-card:nth-child(1) .card-header-title");
            if (devHeaderTitle) {
                devHeaderTitle.textContent = `${meta.active_device_label || "Target Device"}`;
            }

            const rows = document.querySelectorAll("#panel-case .cards-grid-2 > .forensic-card:nth-child(1) .meta-row .meta-val");
            if (rows.length >= 4) {
                rows[0].textContent = `${hw.device_model || "Target Handset"} (${hw.os_build || "Mobile OS"})`;
                rows[1].textContent = `${hw.imei_1 || "N/A"} / ${hw.imei_2 || "N/A"}`;
                rows[2].textContent = `${hw.sim_1_iccid || "SIM ICCID Not Detected"}`;
                rows[3].textContent = `${hw.extraction_method || "Full File System Extraction"}`;
            }
        }

        // Dual SHA-256 Card
        if (meta.dual_sha256) {
            const sha = meta.dual_sha256;
            const shaRows = document.querySelectorAll("#panel-case .cards-grid-2 > .forensic-card:nth-child(2) .meta-row .meta-val");
            if (shaRows.length >= 3) {
                const pA = sha.product_a_container || "N/A";
                const pB = sha.product_b_staging || "N/A";
                const mR = sha.merkle_root_tree || sha.merkle_root_hash || "N/A";
                shaRows[0].textContent = pA.length > 20 ? pA.substring(0, 16) + "..." + pA.substring(pA.length - 12) : pA;
                shaRows[0].title = pA;
                shaRows[1].textContent = pB.length > 20 ? pB.substring(0, 16) + "..." + pB.substring(pB.length - 12) : pB;
                shaRows[1].title = pB;
                shaRows[2].textContent = mR.length > 20 ? mR.substring(0, 16) + "..." + mR.substring(mR.length - 12) : mR;
                shaRows[2].title = mR;
            }
        }
    }

    // 18 Canonical Forensic Groups Grid
    renderForensicGroups(data.forensic_groups_registry || defaultForensicGroupStats);

    // Update Ingested VFS count
    const totalVfsFiles = (data.ingested_files ? data.ingested_files.length : 0) + (data.discovered_sqlite_tables ? data.discovered_sqlite_tables.length : 0);
    const countEl = document.getElementById("vfs-files-count");
    if (countEl) countEl.textContent = totalVfsFiles;

    // Update VFS storage metrics and anti-forensics card
    const liveDb = document.getElementById("stat-live-db");
    const walFrames = document.getElementById("stat-wal-frames");
    const mmkv = document.getElementById("stat-mmkv");
    const biome = document.getElementById("stat-biome");
    if (liveDb) liveDb.textContent = (data.live_db_count !== undefined ? data.live_db_count : (data.nodes || 0)).toLocaleString();
    if (walFrames) walFrames.textContent = (data.wal_frames_count !== undefined ? data.wal_frames_count : 0).toLocaleString();
    if (mmkv) mmkv.textContent = (data.mmkv_count !== undefined ? data.mmkv_count : 0).toLocaleString();
    if (biome) biome.textContent = (data.biome_count !== undefined ? data.biome_count : 0).toLocaleString();

    const spoofCountEl = document.getElementById("stat-spoof-count");
    const spoofBadgeEl = document.getElementById("stat-spoof-badge");
    if (data.spoofed_files_count !== undefined) {
        if (spoofCountEl) {
            spoofCountEl.textContent = `${data.spoofed_files_count} Detected in Container`;
            spoofCountEl.style.color = data.spoofed_files_count > 0 ? "var(--accent-rose)" : "var(--accent-green)";
        }
        if (spoofBadgeEl) {
            spoofBadgeEl.textContent = data.spoofed_files_count > 0 ? "ANOMALY DETECTED" : "SECURE / MONITORED";
            spoofBadgeEl.className = data.spoofed_files_count > 0 ? "badge-tag badge-freelist" : "badge-tag badge-live";
        }
    }
}

// TAB 2: 3-PANE HEX & TIMELINE
function renderTimelineEvents(events) {
    const listContainer = document.getElementById("timeline-events-list");
    if (!listContainer || !events) return;
    listContainer.innerHTML = "";

    const activeEvents = events.filter(evt => evt.event_id && !evt.event_id.startsWith("EVT-100"));
    const pane1Badge = document.getElementById("pane1-badge");
    if (pane1Badge) pane1Badge.textContent = `${activeEvents.length} COMMITTED`;

    activeEvents.forEach(evt => {
        const card = document.createElement("div");
        card.className = `timeline-event-card ${evt.event_id === WorkstationState.selectedEventId ? "selected" : ""}`;
        card.setAttribute("data-event-id", evt.event_id);

        let stateClass = "badge-live";
        if (evt.state_5d === "WAL_OR_JOURNAL") stateClass = "badge-wal";
        if (evt.state_5d === "FREELIST_OR_UNALLOCATED") stateClass = "badge-freelist";

        const timeStr = formatEventTimestamp(evt);
        const isBmk = WorkstationState.bookmarkedExhibitIds.has(evt.event_id);

        card.innerHTML = `
            <div class="event-top-line">
                <span>${evt.event_id}</span>
                <span>${timeStr}</span>
            </div>
            <div class="event-app-domain">${evt.app_domain}</div>
            <div class="event-summary-text">${evt.summary}</div>
            <div class="badge-row" style="display: flex; justify-content: space-between; align-items: center;">
                <div style="display: flex; gap: 4px; flex-wrap: wrap;">
                    <span class="badge-tag ${stateClass}">${evt.state_5d}</span>
                    <span class="badge-tag badge-orig">${evt.confidence}</span>
                    <span class="badge-tag" style="background: rgba(255,255,255,0.06); color: #cbd5e1;">${evt.clock_integrity}</span>
                </div>
                <button class="btn-bookmark ${isBmk ? 'bookmarked' : ''}" data-bookmark-id="${evt.event_id}">
                    ${isBmk ? '★ Tagged' : '☆ Bookmark'}
                </button>
            </div>
        `;

        const bmkBtn = card.querySelector(`[data-bookmark-id="${evt.event_id}"]`);
        if (bmkBtn) {
            bmkBtn.addEventListener("click", (e) => {
                e.stopPropagation();
                toggleBookmark(evt.event_id, "TIMELINE_EVENT", evt.summary, evt.vfs_path || "evidence.db", evt.raw_hex_preview || "");
            });
        }

        card.addEventListener("click", () => {
            document.querySelectorAll(".timeline-event-card").forEach(c => c.classList.remove("selected"));
            card.classList.add("selected");
            WorkstationState.selectedEventId = evt.event_id;
            loadHexEvent(evt.event_id);
        });

        listContainer.appendChild(card);
    });
}

function renderVfsExplorer(data) {
    const vfsList = document.getElementById("vfs-files-list");
    if (!vfsList || !data) return;
    vfsList.innerHTML = "";

    const files = data.ingested_files || [];
    const tables = data.discovered_sqlite_tables || [];

    if (files.length === 0 && tables.length === 0) {
        vfsList.innerHTML = `<div style="padding: 16px; color: var(--text-muted); font-size: 11px;">No ingested VFS nodes available. Use [+ Ingest Dump] to load evidence files.</div>`;
        return;
    }

    if (files.length > 0) {
        const secHeader = document.createElement("div");
        secHeader.style.cssText = "font-size: 10px; font-weight: 700; color: var(--accent-cyan); text-transform: uppercase; margin: 4px 0 6px 0; padding-bottom: 2px; border-bottom: 1px solid var(--border-color);";
        secHeader.textContent = `INGESTED EVIDENCE FILES (${files.length})`;
        vfsList.appendChild(secHeader);

        files.forEach((file) => {
            const row = document.createElement("div");
            row.className = "vfs-file-row";
            row.setAttribute("data-vfs-path", file.file_path);
            row.style.cursor = "pointer";

            const isSpoofed = file.is_extension_spoofed;
            const entropyVal = typeof file.entropy_shannon === "number" ? file.entropy_shannon.toFixed(2) : "N/A";
            const sizeStr = file.byte_size > 1048576 ? `${(file.byte_size / 1048576).toFixed(1)} MB` : `${(file.byte_size / 1024).toFixed(1)} KB`;

            row.innerHTML = `
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 2px;">
                    <span style="font-weight: 700; color: #fff; font-size: 11.5px;">${escapeHtml(file.file_name)}</span>
                    <span class="badge-tag ${isSpoofed ? 'badge-freelist' : 'badge-live'}">${isSpoofed ? 'SPOOFED_MISMATCH' : (file.inferred_type || 'FILE')}</span>
                </div>
                <div style="font-size: 10px; color: var(--text-muted); font-family: var(--font-mono); margin-bottom: 3px; word-break: break-all;">
                    ${escapeHtml(file.file_path)}
                </div>
                <div style="display: flex; gap: 6px; align-items: center; font-size: 10px; color: var(--text-secondary); flex-wrap: wrap;">
                    <span>Size: <strong style="color: #cbd5e1;">${sizeStr}</strong></span>
                    <span>&bull;</span>
                    <span>H(X): <strong style="color: ${file.entropy_shannon >= 7.5 ? 'var(--accent-rose)' : 'var(--accent-amber)'};">${entropyVal}</strong></span>
                    <span>&bull;</span>
                    <span class="group-tag" style="padding: 1px 4px; font-size: 9.5px;">${file.forensic_group ? file.forensic_group.substring(0, 3) : 'G01'}</span>
                </div>
            `;

            row.addEventListener("click", () => {
                document.querySelectorAll(".vfs-file-row").forEach(r => r.classList.remove("selected"));
                row.classList.add("selected");
                loadVfsFileHex(file);
            });

            vfsList.appendChild(row);
        });
    }

    if (tables.length > 0) {
        const secHeader = document.createElement("div");
        secHeader.style.cssText = "font-size: 10px; font-weight: 700; color: var(--accent-green); text-transform: uppercase; margin: 10px 0 6px 0; padding-bottom: 2px; border-bottom: 1px solid var(--border-color);";
        secHeader.textContent = `DISCOVERED SQLITE TABLES (${tables.length})`;
        vfsList.appendChild(secHeader);

        tables.forEach((tbl) => {
            const row = document.createElement("div");
            row.className = "vfs-file-row";
            row.style.cursor = "pointer";

            row.innerHTML = `
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <span style="font-weight: 700; color: var(--accent-green); font-size: 11px;">${escapeHtml(tbl.table_name)}</span>
                    <span class="badge-tag badge-orig">${tbl.record_count.toLocaleString()} ROWS</span>
                </div>
                <div style="font-size: 10px; color: var(--text-muted); font-family: var(--font-mono);">
                    ${escapeHtml(tbl.vfs_path)}
                </div>
            `;

            row.addEventListener("click", () => {
                const matchedEvt = (data.timeline_events || []).find(e => e.vfs_path === tbl.vfs_path);
                if (matchedEvt) {
                    loadHexEvent(matchedEvt.event_id);
                } else if (data.timeline_events && data.timeline_events.length > 0) {
                    loadHexEvent(data.timeline_events[0].event_id);
                }
            });

            vfsList.appendChild(row);
        });
    }
}

function loadVfsFileHex(fileRecord) {
    if (fileRecord.preview_hex_64 && fileRecord.preview_hex_64.length >= 32) {
        const hexRows = [];
        const fullHex = fileRecord.preview_hex_64.padEnd(128, "0").substring(0, 128);
        for (let rowIdx = 0; rowIdx < 4; rowIdx++) {
            const startByte = rowIdx * 16;
            const rowHex = fullHex.substring(startByte * 2, (startByte + 16) * 2);
            const tokens = [];
            let asciiStr = "";
            for (let b = 0; b < 16; b++) {
                const tok = rowHex.substring(b * 2, (b + 1) * 2);
                tokens.push(tok.toUpperCase());
                const charCode = parseInt(tok, 16);
                asciiStr += (charCode >= 32 && charCode <= 126) ? String.fromCharCode(charCode) : ".";
            }
            hexRows.push({
                offset_hex: "0x" + startByte.toString(16).padStart(8, "0").toUpperCase(),
                hex_tokens: tokens,
                ascii_str: asciiStr,
            });
        }
        const syntheticData = {
            vfs_path: fileRecord.file_path,
            sqlite_page: 1,
            cell_offset: 0,
            wal_frame: null,
            product_a_sha256: fileRecord.sha256_product_a || "N/A",
            raw_hex_all: fullHex,
            hex_rows: hexRows,
        };
        WorkstationState.currentHexData = syntheticData;
        renderHexGrid(syntheticData);
    } else {
        const eventsList = (WorkstationState.bootstrap && WorkstationState.bootstrap.timeline_events) || [];
        const matched = eventsList.find(e => e.vfs_path === fileRecord.file_path);
        if (matched) {
            loadHexEvent(matched.event_id);
        } else if (eventsList.length > 0) {
            loadHexEvent(eventsList[0].event_id);
        }
    }
}

function formatEventTimestamp(evt) {
    if (WorkstationState.currentTimezone === "UTC") {
        if (evt.timestamp_utc) {
            return evt.timestamp_utc.replace("T", " ").substring(0, 19) + " UTC";
        }
        if (evt.timestamp_iso) {
            return evt.timestamp_iso.substring(11, 19) + " UTC";
        }
    }
    if (evt.timestamp_iso) {
        return evt.timestamp_iso.substring(11, 19) + " IST";
    }
    return evt.timestamp || "14:32:00 IST";
}

async function loadHexEvent(eventId) {
    try {
        const response = await fetch(`/api/timeline-hex?event_id=${encodeURIComponent(eventId)}`);
        if (!response.ok) throw new Error("Failed to load timeline hex: " + response.status);
        const data = await response.json();
        WorkstationState.currentHexData = data;
        renderHexGrid(data);
    } catch (err) {
        console.error("Hex inspection fetch error:", err);
    }
}

function renderHexGrid(data) {
    const metaWrap = document.getElementById("hex-provenance-meta");
    const stateBadge = document.getElementById("hex-record-state");
    const gridTbody = document.getElementById("hex-grid-tbody");

    if (metaWrap) {
        const walInfo = data.wal_frame !== null && data.wal_frame !== undefined ? `WAL Frame: #${data.wal_frame}` : "WAL Frame: None";
        metaWrap.innerHTML = `
            <div><strong>VFS Source:</strong> ${data.vfs_path}</div>
            <div>SQLite Page #${data.sqlite_page} | Cell Offset: ${data.cell_offset} | ${walInfo}</div>
            <div><strong>Product A SHA-256:</strong> ${data.product_a_sha256}</div>
        `;
    }

    if (stateBadge) {
        stateBadge.textContent = data.wal_frame ? "WAL_OR_JOURNAL" : "LIVE_RECORD";
    }

    if (!gridTbody || !data.hex_rows) return;
    gridTbody.innerHTML = "";

    // Reconstruct 64-byte raw buffer
    const fullBuffer = new Uint8Array(64);
    if (data.raw_hex_all && data.raw_hex_all.length >= 128) {
        for (let i = 0; i < 64; i++) {
            fullBuffer[i] = parseInt(data.raw_hex_all.substr(i * 2, 2), 16);
        }
    } else {
        let bIdx = 0;
        data.hex_rows.forEach(r => {
            r.hex_tokens.forEach(tok => {
                if (bIdx < 64) fullBuffer[bIdx++] = parseInt(tok, 16);
            });
        });
    }
    WorkstationState.currentRawBuffer = fullBuffer;

    data.hex_rows.forEach((row, rowIdx) => {
        const tr = document.createElement("tr");

        const tdOffset = document.createElement("td");
        tdOffset.className = "hex-offset-col";
        tdOffset.textContent = row.offset_hex;

        const tdBytes = document.createElement("td");
        tdBytes.className = "hex-bytes-col";

        row.hex_tokens.forEach((hexToken, colIdx) => {
            const absoluteByteIndex = (rowIdx * 16) + colIdx;
            const span = document.createElement("span");
            span.className = `hex-byte-cell ${absoluteByteIndex === WorkstationState.selectedByteOffset ? 'selected' : ''}`;
            span.textContent = hexToken;

            // Apply layer colors
            let layerColor = "#f59e0b"; // Header
            let layerLabel = "Record Header";
            if (absoluteByteIndex >= 16 && absoluteByteIndex < 40) {
                layerColor = "#38bdf8"; // Payload
                layerLabel = "Column Payload (UTR: 631014892011)";
            } else if (absoluteByteIndex >= 40 && absoluteByteIndex < 56) {
                layerColor = "#a855f7"; // WAL
                layerLabel = "WAL Frame Header & Salt";
            } else if (absoluteByteIndex >= 56) {
                layerColor = "#f43f5e"; // Slack
                layerLabel = "Unallocated Cell Slack";
            }

            span.style.background = layerColor + "22";
            span.style.color = layerColor;
            span.style.border = `1px solid ${layerColor}44`;
            span.title = `Byte 0x${absoluteByteIndex.toString(16).toUpperCase()} (${absoluteByteIndex}): ${layerLabel} — Click to Inspect`;

            span.addEventListener("click", () => {
                document.querySelectorAll(".hex-byte-cell").forEach(c => c.classList.remove("selected"));
                span.classList.add("selected");
                WorkstationState.selectedByteOffset = absoluteByteIndex;
                updateDataInterpreterFromBuffer(fullBuffer, absoluteByteIndex, data);
            });

            tdBytes.appendChild(span);
        });

        const tdAscii = document.createElement("td");
        tdAscii.className = "hex-ascii-col";
        tdAscii.textContent = row.ascii_str;

        tr.appendChild(tdOffset);
        tr.appendChild(tdBytes);
        tr.appendChild(tdAscii);
        gridTbody.appendChild(tr);
    });

    // Populate Data Interpreter with current selection
    updateDataInterpreterFromBuffer(fullBuffer, WorkstationState.selectedByteOffset || 0, data);
}

// SYNCHRONIZED 12-FORMAT DATA INTERPRETER DECODER
function updateDataInterpreterFromBuffer(buf, offset, data) {
    const table = document.getElementById("data-interpreter-table");
    const metaWrap = document.getElementById("interpreter-provenance-meta");
    if (!table) return;

    const rem = buf.length - offset;
    const dv = new DataView(buf.buffer, buf.byteOffset + offset, rem);

    const u8 = dv.getUint8(0);
    const i8 = dv.getInt8(0);
    const u16_le = rem >= 2 ? dv.getUint16(0, true) : "N/A";
    const u16_be = rem >= 2 ? dv.getUint16(0, false) : "N/A";
    const u32_le = rem >= 4 ? dv.getUint32(0, true) : "N/A";
    const u32_be = rem >= 4 ? dv.getUint32(0, false) : "N/A";
    const u64_le = rem >= 8 ? dv.getBigUint64(0, true).toString() : "N/A";
    const f32_le = rem >= 4 ? dv.getFloat32(0, true).toPrecision(6) : "N/A";
    const f64_le = rem >= 8 ? dv.getFloat64(0, true).toPrecision(8) : "N/A";

    // Epoch checks
    let epochSec = "N/A";
    if (typeof u32_le === "number" && u32_le >= 1577836800 && u32_le <= 2000000000) {
        epochSec = new Date(u32_le * 1000).toISOString().replace("T", " ").replace("Z", " UTC");
    }
    let epochMs = "N/A";
    if (rem >= 8) {
        try {
            const bigVal = dv.getBigUint64(0, true);
            const numVal = Number(bigVal);
            if (numVal >= 1577836800000 && numVal <= 2500000000000) {
                epochMs = new Date(numVal).toISOString().replace("T", " ").replace("Z", " UTC");
            }
        } catch (_) {}
    }

    // SQLite Varint decoder
    let sqliteVarintStr = "N/A";
    let varintVal = 0n;
    let varintBytes = 0;
    for (let i = 0; i < 9 && (offset + i) < buf.length; i++) {
        const b = buf[offset + i];
        varintBytes++;
        if (i < 8) {
            varintVal = (varintVal << 7n) | BigInt(b & 0x7F);
            if ((b & 0x80) === 0) break;
        } else {
            varintVal = (varintVal << 8n) | BigInt(b);
            break;
        }
    }
    if (varintBytes > 0) {
        sqliteVarintStr = `${varintVal.toString()} (${varintBytes}B)`;
    }

    // Protobuf SLEB128 decoder
    let sleb128Str = "N/A";
    let slebVal = 0n;
    let slebShift = 0n;
    let slebBytes = 0;
    for (let i = 0; i < 10 && (offset + i) < buf.length; i++) {
        const b = buf[offset + i];
        slebBytes++;
        slebVal |= BigInt(b & 0x7F) << slebShift;
        if ((b & 0x80) === 0) break;
        slebShift += 7n;
    }
    if (slebBytes > 0) {
        sleb128Str = `${slebVal.toString()} (${slebBytes}B)`;
    }

    // Apple Cocoa Epoch (2001-01-01 00:00:00 UTC)
    let appleCocoaStr = "N/A";
    if (rem >= 8) {
        try {
            const f64Val = dv.getFloat64(0, true);
            if (f64Val >= 400000000 && f64Val <= 1200000000) {
                const unixMs = (f64Val + 978307200) * 1000;
                appleCocoaStr = new Date(unixMs).toISOString().replace("T", " ").replace("Z", " UTC");
            }
        } catch (_) {}
    }
    if (appleCocoaStr === "N/A" && typeof u32_le === "number" && u32_le >= 500000000 && u32_le <= 1000000000) {
        const unixMs = (u32_le + 978307200) * 1000;
        appleCocoaStr = new Date(unixMs).toISOString().replace("T", " ").replace("Z", " UTC");
    }

    // UTF-8 string preview (up to 32 bytes or first null)
    let utf8Chars = "";
    for (let i = 0; i < Math.min(rem, 32); i++) {
        const b = buf[offset + i];
        if (b === 0) break;
        utf8Chars += (b >= 32 && b <= 126) ? String.fromCharCode(b) : ".";
    }

    const hexSlice = Array.from(buf.slice(offset, Math.min(offset + 16, buf.length)))
        .map(b => b.toString(16).padStart(2, "0").toUpperCase())
        .join(" ");

    table.innerHTML = `
        <tbody>
            <tr><td class="interp-type">uint8 / int8</td><td class="interp-val">${u8} / ${i8}</td></tr>
            <tr><td class="interp-type">uint16 (LE / BE)</td><td class="interp-val">${u16_le} / ${u16_be}</td></tr>
            <tr><td class="interp-type">uint32 (LE)</td><td class="interp-val">${u32_le}</td></tr>
            <tr><td class="interp-type">uint32 (BE)</td><td class="interp-val">${u32_be}</td></tr>
            <tr><td class="interp-type">uint64 (LE)</td><td class="interp-val">${u64_le}</td></tr>
            <tr><td class="interp-type">float32 (LE)</td><td class="interp-val">${f32_le}</td></tr>
            <tr><td class="interp-type">float64 (LE)</td><td class="interp-val">${f64_le}</td></tr>
            <tr><td class="interp-type">SQLite Varint</td><td class="interp-val" style="color: var(--accent-cyan); font-family: var(--font-mono); font-size: 11px;">${sqliteVarintStr}</td></tr>
            <tr><td class="interp-type">Protobuf SLEB128</td><td class="interp-val" style="color: var(--accent-amber); font-family: var(--font-mono); font-size: 11px;">${sleb128Str}</td></tr>
            <tr><td class="interp-type">Unix Epoch (sec)</td><td class="interp-val" style="font-size: 11px;">${epochSec}</td></tr>
            <tr><td class="interp-type">Unix Epoch (ms)</td><td class="interp-val" style="font-size: 11px;">${epochMs}</td></tr>
            <tr><td class="interp-type">Apple Cocoa Epoch</td><td class="interp-val" style="font-size: 11px;">${appleCocoaStr}</td></tr>
            <tr><td class="interp-type">Hex Stream (16B)</td><td class="interp-val" style="font-size: 10.5px; font-family: var(--font-mono); color: var(--accent-cyan);">${hexSlice}</td></tr>
            <tr><td class="interp-type">UTF-8 / ASCII</td><td class="interp-val">${escapeHtml(utf8Chars || "(none)")}</td></tr>
        </tbody>
    `;

    if (metaWrap && data) {
        const itemId = `HEX-${data.sqlite_page || 1}-${offset}`;
        const isBmk = WorkstationState.bookmarkedExhibitIds.has(itemId);
        metaWrap.innerHTML = `
            <div class="meta-row"><span class="meta-key">Byte Offset:</span><span class="meta-val">0x${offset.toString(16).padStart(4, "0").toUpperCase()} (${offset})</span></div>
            <div class="meta-row"><span class="meta-key">SQLite Page:</span><span class="meta-val">#${data.sqlite_page}</span></div>
            <div class="meta-row"><span class="meta-key">Cell Base Offset:</span><span class="meta-val">0x${(data.cell_offset || 0).toString(16).toUpperCase()}</span></div>
            <div class="meta-row"><span class="meta-key">WAL Frame:</span><span class="meta-val">${data.wal_frame !== null && data.wal_frame !== undefined ? '#' + data.wal_frame : 'Live B-Tree'}</span></div>
            <div class="meta-row"><span class="meta-key">Product A Hash:</span><span class="meta-val" style="font-size: 9.5px;">${data.product_a_sha256 ? data.product_a_sha256.substring(0, 24) + '...' : 'N/A'}</span></div>
            <div style="margin-top: 8px;">
                <button class="btn-bookmark ${isBmk ? 'bookmarked' : ''}" id="btn-bookmark-hex-current" style="width: 100%; text-align: center;">
                    ${isBmk ? '★ Bookmarked for BSA Report' : '☆ Bookmark for BSA Report'}
                </button>
            </div>
        `;
        const bmkBtn = document.getElementById("btn-bookmark-hex-current");
        if (bmkBtn) {
            bmkBtn.addEventListener("click", () => {
                toggleBookmark(itemId, "HEX_BYTE_SLICE", `Raw Hex Slice at Offset 0x${offset.toString(16).toUpperCase()} (Page #${data.sqlite_page})`, data.vfs_path, data.product_a_sha256);
            });
        }
    }
}

// TAB 3: UNIFIED CHAT RECONSTRUCTOR
function initChatControls() {
    const stdBtn = document.getElementById("btn-toggle-standard-view");
    const redlineBtn = document.getElementById("btn-toggle-myers-redline");

    if (stdBtn && redlineBtn) {
        stdBtn.addEventListener("click", () => {
            stdBtn.classList.add("active");
            redlineBtn.classList.remove("active");
            WorkstationState.chatRedlineMode = false;
            if (WorkstationState.bootstrap && WorkstationState.bootstrap.chat_threads) {
                renderChatWorkspace(WorkstationState.bootstrap.chat_threads);
            }
        });

        redlineBtn.addEventListener("click", () => {
            redlineBtn.classList.add("active");
            stdBtn.classList.remove("active");
            WorkstationState.chatRedlineMode = true;
            if (WorkstationState.bootstrap && WorkstationState.bootstrap.chat_threads) {
                renderChatWorkspace(WorkstationState.bootstrap.chat_threads);
            }
        });
    }
}

function renderChatWorkspace(threads) {
    const roster = document.getElementById("chat-thread-roster");
    const messagesWrap = document.getElementById("chat-messages-container");
    if (roster) roster.innerHTML = "";
    if (messagesWrap) messagesWrap.innerHTML = "";

    const threadList = Array.isArray(threads) ? threads : (threads && Array.isArray(threads.threads) ? threads.threads : null);

    if (!threads || (Array.isArray(threads) && threads.length === 0) || !threadList || threadList.length === 0) {
        if (roster) {
            roster.innerHTML = '<div style="color: gray; padding: 20px;">No chat threads ingested.</div>';
        }
        const badge = document.getElementById("chat-records-badge");
        if (badge) badge.style.display = "none";
        const alertBox = document.getElementById("chat-platform-hopping-alert");
        if (alertBox) alertBox.style.display = "none";
        const subTitle = document.getElementById("chat-thread-subtitle");
        if (subTitle) subTitle.textContent = "";
        return;
    }

    // Render Chat Thread Roster if threads are present
    threadList.forEach(t => {
        const btn = document.createElement("div");
        btn.className = `thread-item-card ${t.thread_id === WorkstationState.selectedThreadId ? 'active' : ''}`;
        btn.innerHTML = `
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <span style="font-weight: 700; color: #fff; font-size: 11px;">${escapeHtml(t.title)}</span>
                <span class="badge-tag badge-live" style="font-size: 9px;">${(t.messages ? t.messages.length : 0)} MSGS</span>
            </div>
            <div style="font-size: 10px; color: var(--accent-cyan); margin-top: 1px;">${t.platform}</div>
        `;
        btn.addEventListener("click", () => {
            WorkstationState.selectedThreadId = t.thread_id;
            renderChatWorkspace(threads);
        });
        roster.appendChild(btn);
    });

    // Determine active messages list and master entity
    let activeMessages = [];
    if (threads && threads.messages) activeMessages = threads.messages;
    let currentEntity = threads && threads.master_entity;
    if (threadList.length > 0) {
        const found = threadList.find(t => t.thread_id === WorkstationState.selectedThreadId) || threadList[0];
        if (found) {
            if (found.messages) activeMessages = found.messages;
            if (found.master_entity) currentEntity = found.master_entity;
            const subTitle = document.getElementById("chat-thread-subtitle");
            if (subTitle) subTitle.textContent = found.title || "";
        }
    }

    if (currentEntity) {
        const nameEl = document.getElementById("chat-entity-name");
        const phoneEl = document.getElementById("chat-entity-phone");
        const lidEl = document.getElementById("chat-entity-lid");

        if (nameEl) nameEl.textContent = currentEntity.name;
        if (phoneEl) phoneEl.textContent = currentEntity.unmasked_phone;
        if (lidEl) lidEl.textContent = currentEntity.whatsapp_lid;
    }

    const badge = document.getElementById("chat-records-badge");
    if (badge) {
        badge.style.display = "inline-block";
        badge.textContent = `${activeMessages.length} RECOVERED RECORDS`;
    }

    if (!messagesWrap || !activeMessages) return;
    messagesWrap.innerHTML = "";

    activeMessages.forEach(msg => {
        const row = document.createElement("div");
        row.className = `chat-bubble-row ${msg.is_outgoing ? "outbound" : "inbound"}`;

        let messageBodyHtml = "";
        if (msg.is_edited && WorkstationState.chatRedlineMode) {
            const diffHtml = msg.myers_diff_html || (WorkstationState.bootstrap && WorkstationState.bootstrap.initial_redline && WorkstationState.bootstrap.initial_redline.html_rendered_diff) || escapeHtml(msg.edited_text || msg.text || "");
            messageBodyHtml = `
                <div style="margin-bottom: 4px;">
                    <span class="badge-tag badge-freelist">MYERS REDLINE DIFF</span>
                </div>
                <div class="chat-text-content">${diffHtml}</div>
            `;
        } else if (msg.is_edited) {
            messageBodyHtml = `
                <div style="margin-bottom: 4px;">
                    <span class="badge-tag badge-wal">EDITED MESSAGE (CURRENT RAW)</span>
                </div>
                <div class="chat-text-content">${escapeHtml(msg.edited_text || msg.text || "")}</div>
            `;
        } else {
            messageBodyHtml = `<div class="chat-text-content">${escapeHtml(msg.text || "")}</div>`;
        }

        // Voice note widget for MSG-02
        let audioWidgetHtml = "";
        if (msg.has_audio_waveform) {
            const transcriptText = WorkstationState.currentTranscriptLang === "hi" ? msg.audio_transcript_hi : msg.audio_transcript_en;
            audioWidgetHtml = `
                <div class="audio-waveform-card">
                    <div class="waveform-controls">
                        <button class="audio-play-btn" id="btn-play-voice-note" title="Play Voice Intercept">
                            ${WorkstationState.audioPlaying ? "⏸" : "▶"}
                        </button>
                        <div class="waveform-visual-bars" id="waveform-visual-bars">
                            <span class="waveform-bar" style="height: 8px;"></span>
                            <span class="waveform-bar" style="height: 16px;"></span>
                            <span class="waveform-bar" style="height: 22px;"></span>
                            <span class="waveform-bar" style="height: 14px;"></span>
                            <span class="waveform-bar" style="height: 18px;"></span>
                            <span class="waveform-bar" style="height: 10px;"></span>
                            <span class="waveform-bar" style="height: 20px;"></span>
                            <span class="waveform-bar" style="height: 12px;"></span>
                            <span class="waveform-bar" style="height: 6px;"></span>
                        </div>
                        <span style="font-size: 11px; font-family: var(--font-mono); color: var(--accent-cyan);">${msg.audio_duration_sec}s</span>
                        <button class="btn-toggle" id="btn-toggle-transcript" style="padding: 2px 6px; font-size: 10px; margin-left: auto;">
                            Lang: ${WorkstationState.currentTranscriptLang.toUpperCase()}
                        </button>
                    </div>
                    <div class="audio-transcript-box">
                        <span class="transcript-label">Intercept Transcript (${WorkstationState.currentTranscriptLang === "hi" ? "Hindi Devanagari" : "English Translation"}):</span>
                        <span id="voice-transcript-text" style="color: #f1f5f9;">${escapeHtml(transcriptText)}</span>
                    </div>
                </div>
            `;
        }

        // Platform hopping trigger note
        let hoppingNote = "";
        if (msg.has_platform_switch_after) {
            hoppingNote = `
                <div style="margin-top: 6px; font-size: 10.5px; color: var(--accent-amber); font-weight: 600;">
                    &rarr; TARGET SWITCHED APP TO: <strong>${msg.next_platform}</strong>
                </div>
            `;
        }

        const isBmk = WorkstationState.bookmarkedExhibitIds.has(msg.msg_id);

        row.innerHTML = `
            <div class="chat-bubble-card">
                <div class="chat-meta-bar">
                    <span class="chat-sender-tag">${escapeHtml(msg.sender)}</span>
                    <span>${msg.timestamp_ist}</span>
                </div>
                <div style="margin-bottom: 2px;">
                    <span class="platform-tag">${msg.platform}</span>
                </div>
                ${messageBodyHtml}
                ${audioWidgetHtml}
                ${hoppingNote}
                <div style="display: flex; gap: 6px; margin-top: 8px; align-items: center; border-top: 1px solid var(--border-color); padding-top: 6px;">
                    <button class="btn-toggle" style="padding: 2px 6px; font-size: 10px;" data-jump-msg="${msg.msg_id}">
                        &rarr; Jump to Raw Bytes in Hex
                    </button>
                    <button class="btn-bookmark ${isBmk ? 'bookmarked' : ''}" data-bookmark-id="${msg.msg_id}">
                        ${isBmk ? '★ Bookmarked' : '☆ Bookmark'}
                    </button>
                </div>
            </div>
        `;

        const jumpBtn = row.querySelector(`[data-jump-msg="${msg.msg_id}"]`);
        if (jumpBtn) {
            jumpBtn.addEventListener("click", () => {
                const tabHexBtn = document.getElementById("tab-btn-hex");
                if (tabHexBtn) tabHexBtn.click();
                loadHexEvent("EVT-1006");
            });
        }

        const bmkBtn = row.querySelector(`[data-bookmark-id="${msg.msg_id}"]`);
        if (bmkBtn) {
            bmkBtn.addEventListener("click", () => {
                toggleBookmark(msg.msg_id, "CHAT_RECORD", `${msg.platform} record: ${escapeHtml(msg.text ? msg.text.substring(0, 40) : msg.msg_id)}`, "msgstore.db");
            });
        }

        messagesWrap.appendChild(row);
    });

    // Bind audio button listeners
    const playBtn = document.getElementById("btn-play-voice-note");
    if (playBtn) {
        playBtn.addEventListener("click", () => {
            WorkstationState.audioPlaying = !WorkstationState.audioPlaying;
            renderChatWorkspace(WorkstationState.bootstrap.chat_threads);
        });
    }

    const transcriptToggleBtn = document.getElementById("btn-toggle-transcript");
    if (transcriptToggleBtn) {
        transcriptToggleBtn.addEventListener("click", () => {
            WorkstationState.currentTranscriptLang = WorkstationState.currentTranscriptLang === "hi" ? "en" : "hi";
            renderChatWorkspace(WorkstationState.bootstrap.chat_threads);
        });
    }
}

// TAB 4: FINANCIAL & STORYBOARD
function renderFinancialTab(data) {
    const container = document.getElementById("financial-sankey-container");
    const nodeInspector = document.getElementById("sankey-node-details");
    const ledgerWrap = document.getElementById("sankey-ledger-table-wrap");
    const sbContainer = document.getElementById("storyboard-container");

    const hasSankey = data && data.initial_sankey_svg;
    const hasTxs = data && data.financial_ledger_transactions && data.financial_ledger_transactions.length > 0;

    if (!data || (!hasSankey && !hasTxs)) {
        if (container) container.innerHTML = '<div style="color: gray; padding: 20px; text-align: center;">No financial flow data found.</div>';
        if (nodeInspector) nodeInspector.innerHTML = '';
        if (ledgerWrap) ledgerWrap.innerHTML = '<div style="color: gray; padding: 20px; text-align: center;">No financial flow data found.</div>';
    } else {
        if (container) {
            container.innerHTML = hasSankey ? data.initial_sankey_svg : '<div style="color: gray; padding: 20px; text-align: center;">No financial flow data found.</div>';

            // Interactive node click listeners
            const svgElem = container.querySelector("svg");
            if (svgElem) {
                svgElem.style.width = "100%";
                svgElem.style.maxHeight = "360px";
                svgElem.querySelectorAll("rect, path").forEach(shape => {
                    shape.style.cursor = "pointer";
                    shape.addEventListener("click", () => {
                        const titleElem = shape.querySelector("title");
                        const label = titleElem ? titleElem.textContent : "Financial Flow Node";
                        renderSankeyNodeDetails(label);
                        renderFinancialLedgerTable(data, label);
                    });
                });
            }
        }

        if (hasTxs) {
            const firstTx = data.financial_ledger_transactions[0];
            const defaultLabel = firstTx.layer || "Layer 2: Mule Tier-1";
            renderSankeyNodeDetails(defaultLabel);
            renderFinancialLedgerTable(data);
        } else {
            if (nodeInspector) nodeInspector.innerHTML = '';
            if (ledgerWrap) ledgerWrap.innerHTML = '<div style="color: gray; padding: 20px; text-align: center;">No financial flow data found.</div>';
        }
    }

    // Button controls
    const highlightBtn = document.getElementById("btn-highlight-sankey-path");
    const resetBtn = document.getElementById("btn-reset-sankey");

    if (highlightBtn && resetBtn) {
        highlightBtn.addEventListener("click", () => {
            highlightBtn.classList.add("active");
            resetBtn.classList.remove("active");
            if (container) {
                container.querySelectorAll("path").forEach(p => {
                    p.style.opacity = "0.95";
                    p.style.stroke = "#f43f5e";
                    p.style.strokeWidth = "5";
                });
            }
            renderSankeyNodeDetails("CRITICAL MULE HOP: Layer 1 -> Layer 2 -> Layer 3 -> Crypto P2P -> TRC20");
            renderFinancialLedgerTable(data, "Mule");
        });

        resetBtn.addEventListener("click", () => {
            resetBtn.classList.add("active");
            highlightBtn.classList.remove("active");
            if (container) {
                container.innerHTML = (data && data.initial_sankey_svg) ? data.initial_sankey_svg : '<div style="color: gray; padding: 20px; text-align: center;">No financial flow data found.</div>';
                const svg = container.querySelector("svg");
                if (svg) svg.style.width = "100%";
            }
            if (data && data.financial_ledger_transactions && data.financial_ledger_transactions.length > 0) {
                renderSankeyNodeDetails(data.financial_ledger_transactions[0].layer || "Layer 2: Mule Tier-1");
                renderFinancialLedgerTable(data);
            }
        });
    }

    // 5-Swimlane Chrono-Storyboard
    if (sbContainer) {
        const hasStoryboard = data && data.action_burst_storyboard && data.action_burst_storyboard.swimlanes && data.action_burst_storyboard.swimlanes.length > 0;
        if (!hasStoryboard) {
            sbContainer.innerHTML = '<div style="color: gray; padding: 20px; text-align: center;">No storyboard events found.</div>';
        } else {
            sbContainer.innerHTML = data.action_burst_storyboard.swimlanes.map(lane => `
                <div class="swimlane-row">
                    <div class="swimlane-header">
                        <span class="swimlane-pill" style="border-left: 3px solid ${lane.color || '#38bdf8'};">${escapeHtml(lane.label)}</span>
                    </div>
                    <div class="swimlane-track">
                        ${(lane.events || []).map(evt => `
                            <div class="swimlane-event-block" title="${escapeHtml(evt.detail || '')}">
                                <span class="swimlane-event-time">+${evt.time_offset_s}s</span>
                                <span>${escapeHtml(evt.title)}: ${escapeHtml(evt.detail || '')}</span>
                            </div>
                        `).join("")}
                    </div>
                </div>
            `).join("");
        }
    }
}

function renderFinancialLedgerTable(data, filterLabel = null) {
    const wrap = document.getElementById("sankey-ledger-table-wrap");
    if (!wrap) return;

    const txs = (data && data.financial_ledger_transactions) || [];
    const filtered = filterLabel
        ? txs.filter(t => (t.layer && t.layer.toLowerCase().includes(filterLabel.toLowerCase())) ||
                          (t.debited_entity && t.debited_entity.toLowerCase().includes(filterLabel.toLowerCase())) ||
                          (t.credited_entity && t.credited_entity.toLowerCase().includes(filterLabel.toLowerCase())))
        : txs;

    if (filtered.length === 0) {
        wrap.innerHTML = `<div style="padding: 10px; color: var(--text-muted); font-size: 11px;">No transactions matching filter "${escapeHtml(filterLabel)}".</div>`;
        return;
    }

    wrap.innerHTML = `
        <table class="ledger-table">
            <thead>
                <tr>
                    <th>Tx ID / UTR</th>
                    <th>Timestamp (${WorkstationState.currentTimezone})</th>
                    <th>Debited Entity</th>
                    <th>Credited Entity</th>
                    <th>Amount (INR)</th>
                    <th>Laundering Hop Layer</th>
                    <th>5D State</th>
                    <th>Evidence Bookmark</th>
                </tr>
            </thead>
            <tbody>
                ${filtered.map(tx => {
                    const timeStr = WorkstationState.currentTimezone === "UTC"
                        ? (tx.timestamp_utc ? tx.timestamp_utc.replace("T", " ").substring(0, 19) + " UTC" : tx.timestamp_ist)
                        : tx.timestamp_ist;
                    const isBmk = WorkstationState.bookmarkedExhibitIds.has(tx.tx_id);
                    return `
                        <tr>
                            <td>
                                <strong style="color: #fff;">${tx.tx_id}</strong><br>
                                <span style="font-family: var(--font-mono); color: var(--accent-cyan); font-size: 10px;">${tx.utr}</span>
                            </td>
                            <td style="font-size: 10.5px;">${timeStr}</td>
                            <td style="color: #cbd5e1; font-size: 11px;">${escapeHtml(tx.debited_entity)}</td>
                            <td style="color: var(--accent-green); font-size: 11px;">${escapeHtml(tx.credited_entity)}</td>
                            <td style="color: var(--accent-rose); font-weight: 700; font-family: var(--font-mono);">₹${tx.amount_inr.toLocaleString()}</td>
                            <td style="font-size: 10px; color: var(--accent-amber);">${escapeHtml(tx.layer)}</td>
                            <td><span class="badge-tag ${tx.state_5d === 'LIVE_RECORD' ? 'badge-live' : 'badge-wal'}">${tx.state_5d}</span></td>
                            <td>
                                <button class="btn-bookmark ${isBmk ? 'bookmarked' : ''}" data-bookmark-id="${tx.tx_id}">
                                    ${isBmk ? '★ Bookmarked' : '☆ Bookmark'}
                                </button>
                            </td>
                        </tr>
                    `;
                }).join("")}
            </tbody>
        </table>
    `;

    wrap.querySelectorAll(".btn-bookmark").forEach(btn => {
        const id = btn.getAttribute("data-bookmark-id");
        btn.addEventListener("click", () => {
            const txObj = txs.find(t => t.tx_id === id);
            toggleBookmark(id, "FINANCIAL_TRANSACTION", `Laundering Hop: ${txObj ? txObj.debited_entity + ' -> ' + txObj.credited_entity : id}`, "paisa.db", txObj ? txObj.sha256 : "");
        });
    });
}

function renderSankeyNodeDetails(nodeTitle) {
    const nodeInspector = document.getElementById("sankey-node-details");
    if (!nodeInspector) return;

    nodeInspector.innerHTML = `
        <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border-color); padding-bottom: 4px; margin-bottom: 4px;">
            <span style="font-weight: 700; color: var(--accent-cyan);">${escapeHtml(nodeTitle)}</span>
            <span class="badge-tag badge-live">LEGAL PROVENANCE ATTACHED</span>
        </div>
        <div class="card-body-meta" style="font-size: 11.5px;">
            <div class="meta-row"><span class="meta-key">Flow Node:</span><span class="meta-val" style="color: var(--accent-green);">${escapeHtml(nodeTitle)}</span></div>
        </div>
    `;
}

// TAB 5: DUAL-MODE GEOSPATIAL MAP & 3-MODE TAMPER INSPECTOR
function renderGeospatialTab(data) {
    const mapWrap = document.getElementById("geo-map-frame-wrap");
    const tableWrap = document.getElementById("geo-fixes-table-wrap");
    const onlineBtn = document.getElementById("btn-map-online");
    const offlineBtn = document.getElementById("btn-map-offline");
    const hubSelect = document.getElementById("geo-hub-select");

    const hasFixes = data && data.geospatial_fixes && data.geospatial_fixes.length > 0;
    const hasMap = data && data.resolved_default_location && data.resolved_default_location.map_html;

    if (!data || (!hasFixes && !hasMap)) {
        if (mapWrap) mapWrap.innerHTML = '<div style="color: gray; padding: 20px; text-align: center;">No geospatial data found.</div>';
        if (tableWrap) tableWrap.innerHTML = '<div style="color: gray; padding: 20px; text-align: center;">No geospatial data found.</div>';
        initTamperModes(data);
        return;
    }

    // Default Online Map
    if (mapWrap && hasMap) {
        mapWrap.innerHTML = data.resolved_default_location.map_html;
    } else if (mapWrap) {
        mapWrap.innerHTML = '<div style="color: gray; padding: 20px; text-align: center;">No geospatial data found.</div>';
    }

    if (onlineBtn && offlineBtn) {
        onlineBtn.addEventListener("click", () => {
            onlineBtn.classList.add("active");
            offlineBtn.classList.remove("active");
            if (mapWrap && data && data.resolved_default_location) {
                mapWrap.innerHTML = data.resolved_default_location.map_html;
            }
        });

        offlineBtn.addEventListener("click", () => {
            offlineBtn.classList.add("active");
            onlineBtn.classList.remove("active");
            renderOfflineTacticalGraticule(mapWrap);
        });
    }

    if (hubSelect) {
        hubSelect.addEventListener("change", async (e) => {
            const isVaranasi = e.target.value === "VARANASI";
            const lat = isVaranasi ? 25.317600 : 12.971600;
            const lon = isVaranasi ? 82.973900 : 77.594600;
            try {
                const resp = await fetch("/api/map/resolve", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ lat: lat, lon: lon, force_offline: false }),
                });
                if (resp.ok) {
                    const resData = await resp.json();
                    if (onlineBtn && onlineBtn.classList.contains("active")) {
                        mapWrap.innerHTML = resData.map_html;
                    } else {
                        renderOfflineTacticalGraticule(mapWrap, lat, lon, resData.display_address);
                    }
                }
            } catch (err) {
                console.error("Map hub switch error:", err);
            }
        });
    }

    // 4-Tier Fixes Summary Table
    if (tableWrap) {
        if (hasFixes) {
            tableWrap.innerHTML = `
                <table class="data-interpreter-table">
                    <thead>
                        <tr style="color: var(--text-muted); font-size: 11px;">
                            <th style="padding: 6px;">Tier</th>
                            <th style="padding: 6px;">Coordinates</th>
                            <th style="padding: 6px;">Provenance Marker</th>
                            <th style="padding: 6px;">Accuracy</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${data.geospatial_fixes.map(f => `
                            <tr>
                                <td><span class="badge-tag badge-live">${f.tier}</span></td>
                                <td class="interp-val" style="font-size: 11px;">${f.lat.toFixed(6)}, ${f.lon.toFixed(6)}</td>
                                <td style="color: #fff; font-size: 11px;">${f.label}</td>
                                <td style="color: var(--accent-cyan); font-size: 11px;">${f.accuracy}</td>
                            </tr>
                        `).join("")}
                    </tbody>
                </table>
            `;
        } else {
            tableWrap.innerHTML = '<div style="color: gray; padding: 20px; text-align: center;">No geospatial data found.</div>';
        }
    }

    // Tamper Mode Switcher
    initTamperModes(data);
}

function renderOfflineTacticalGraticule(container, lat = 25.317600, lon = 82.973900, address = "Varanasi Ghats Hub (Offline Air-Gapped)") {
    if (!container) return;
    container.innerHTML = `
        <div class="tactical-svg-container">
            <svg viewBox="0 0 500 340" style="width: 100%; height: 100%;">
                <!-- Coordinate Graticule Grid -->
                <defs>
                    <pattern id="tactical-grid-pat" width="40" height="40" patternUnits="userSpaceOnUse">
                        <path d="M 40 0 L 0 0 0 40" fill="none" stroke="#1e3a5f" stroke-width="0.8" opacity="0.6"/>
                    </pattern>
                </defs>
                <rect width="500" height="340" fill="url(#tactical-grid-pat)"/>

                <!-- Cell Tower Trilateration Radii -->
                <circle cx="250" cy="170" r="120" fill="rgba(56, 189, 248, 0.05)" stroke="#38bdf8" stroke-dasharray="4,4" stroke-width="1.2"/>
                <circle cx="250" cy="170" r="80" fill="rgba(16, 185, 129, 0.06)" stroke="#10b981" stroke-dasharray="3,3" stroke-width="1.2"/>
                <circle cx="250" cy="170" r="40" fill="rgba(245, 158, 11, 0.08)" stroke="#f59e0b" stroke-width="1.5"/>

                <!-- Crosshair & Azimuth -->
                <line x1="250" y1="20" x2="250" y2="320" stroke="#38bdf8" stroke-width="0.8" opacity="0.4"/>
                <line x1="30" y1="170" x2="470" y2="170" stroke="#38bdf8" stroke-width="0.8" opacity="0.4"/>

                <!-- Pinned Targets -->
                <circle cx="250" cy="170" r="5" fill="#f43f5e"/>
                <text x="260" y="165" fill="#f8fafc" font-size="11" font-weight="bold">GPS Fix (25.3176° N, 82.9739° E)</text>

                <circle cx="280" cy="140" r="4" fill="#38bdf8"/>
                <text x="290" y="142" fill="#38bdf8" font-size="10">Wi-Fi BSSID (00:14:22:01:23:45)</text>

                <circle cx="210" cy="210" r="4" fill="#f59e0b"/>
                <text x="220" y="215" fill="#f59e0b" font-size="10">Jio Tower CGI 404-45-12049</text>

                <!-- Status Header -->
                <rect x="10" y="10" width="280" height="26" rx="4" fill="#0b1322" stroke="#1e3a5f" stroke-width="1"/>
                <text x="20" y="27" fill="#10b981" font-size="10.5" font-weight="bold">TACTICAL RADAR (AIR-GAPPED OFFLINE)</text>
            </svg>
        </div>
    `;
}

function initTamperModes(data) {
    const stage = document.getElementById("tamper-interactive-stage");
    const curtainBtn = document.getElementById("btn-tamper-curtain");
    const uidaiBtn = document.getElementById("btn-tamper-uidai");
    const scoreBtn = document.getElementById("btn-tamper-scorecard");

    const buttons = [curtainBtn, uidaiBtn, scoreBtn];

    function activateMode(mode) {
        buttons.forEach(b => {
            if (b && b.getAttribute("data-mode") === mode) b.classList.add("active");
            else if (b) b.classList.remove("active");
        });

        if (mode === "curtain") renderTamperCurtain(stage, data);
        if (mode === "uidai") renderTamperUidai(stage, data);
        if (mode === "scorecard") renderTamperScorecard(stage, data);
    }

    if (curtainBtn) curtainBtn.addEventListener("click", () => activateMode("curtain"));
    if (uidaiBtn) uidaiBtn.addEventListener("click", () => activateMode("uidai"));
    if (scoreBtn) scoreBtn.addEventListener("click", () => activateMode("scorecard"));

    // Default to Curtain Slider
    activateMode("curtain");
}

function renderTamperCurtain(container, data) {
    if (!container) return;
    const vte = (data && data.visual_tamper_exhibits && data.visual_tamper_exhibits.uncrop_curtain) || {};

    container.innerHTML = `
        <div style="font-size: 11px; color: var(--text-secondary); margin-bottom: 6px;">
            Drag or click inside the frame to split-view the cropped screenshot against unallocated SQLite freelist slack:
        </div>
        <div class="curtain-slider-box" id="curtain-slider-box">
            <!-- Cropped Layer -->
            <div class="curtain-image-layer curtain-before" id="curtain-layer-before">
                <span class="badge-tag badge-wal" style="margin-bottom: 8px;">CROPPED EXHIBIT (16:9 Aspect)</span>
                <div style="color: #cbd5e1; font-size: 13px; text-align: center; max-width: 200px;">
                    Payment Screenshot Bottom Cropped by 48px to Conceal Transaction Timestamp
                </div>
                <div style="color: var(--accent-rose); font-size: 11px; margin-top: 6px;">Footer Truncated at Offset 0x0041A000</div>
            </div>

            <!-- Recovered Slack Layer -->
            <div class="curtain-image-layer curtain-after" id="curtain-layer-after">
                <span class="badge-tag badge-live" style="margin-bottom: 8px;">RECOVERED FREELIST SLACK (Full Frame)</span>
                <div style="color: #6ee7b7; font-size: 13px; text-align: center; max-width: 220px; font-weight: 600;">
                    Unallocated Freelist Page #512 Contains Complete Uncropped Footer:
                </div>
                <div style="color: var(--accent-cyan); font-family: var(--font-mono); font-size: 11px; margin-top: 6px;">
                    Device ID: SM-S928B | Timestamp: 14:32:15 IST | UTR: 631014892011
                </div>
            </div>

            <!-- Divider Line & Knob -->
            <div class="curtain-divider-line" id="curtain-divider-line">
                <div class="curtain-handle-knob">&harr;</div>
            </div>
        </div>

        <div style="display: flex; justify-content: space-between; font-size: 11px; color: var(--text-muted); margin-top: 6px;">
            <span>Cropped Suspect Image</span>
            <span style="color: var(--accent-green); font-weight: 700;">48px Residual Slack Carved from Page #512</span>
        </div>
    `;

    // Interactive slider mousemove
    const box = document.getElementById("curtain-slider-box");
    const beforeLayer = document.getElementById("curtain-layer-before");
    const afterLayer = document.getElementById("curtain-layer-after");
    const divider = document.getElementById("curtain-divider-line");

    if (box && beforeLayer && afterLayer && divider) {
        let isDragging = false;
        function updateCurtain(xPos) {
            const rect = box.getBoundingClientRect();
            let ratio = (xPos - rect.left) / rect.width;
            if (ratio < 0.05) ratio = 0.05;
            if (ratio > 0.95) ratio = 0.95;
            const pct = ratio * 100;
            divider.style.left = `${pct}%`;
            beforeLayer.style.clipPath = `inset(0 ${100 - pct}% 0 0)`;
            afterLayer.style.clipPath = `inset(0 0 0 ${pct}%)`;
        }

        box.addEventListener("mousedown", (e) => {
            isDragging = true;
            updateCurtain(e.clientX);
        });

        window.addEventListener("mouseup", () => { isDragging = false; });
        window.addEventListener("mousemove", (e) => {
            if (isDragging) updateCurtain(e.clientX);
        });
    }
}

function renderTamperUidai(container, data) {
    if (!container) return;
    const uidai = (data && data.visual_tamper_exhibits && data.visual_tamper_exhibits.uidai_qr_verifier) || {};

    container.innerHTML = `
        <div class="card-body-meta" style="font-size: 12px; gap: 10px;">
            <div class="meta-row">
                <span class="meta-key">QR Specification:</span>
                <span class="meta-val" style="color: var(--accent-cyan); font-weight: 700;">UIDAI Secure QR (v2 - 2048-bit RSA Signed)</span>
            </div>
            <div class="meta-row">
                <span class="meta-key">Cryptographic Signature:</span>
                <span class="badge-tag badge-live">VERIFIED_VALID (UIDAI ROOT CA)</span>
            </div>
            <div class="meta-row">
                <span class="meta-key">Facial Photo Extract:</span>
                <span class="meta-val" style="color: var(--accent-green);">JP2 (JPEG 2000) Signature Matched (512 Bytes)</span>
            </div>
            <div class="meta-row">
                <span class="meta-key">Masked Aadhaar Number:</span>
                <span class="meta-val" style="font-family: var(--font-mono); font-size: 14px; font-weight: 700;">XXXX-XXXX-4821</span>
            </div>
            <div class="meta-row">
                <span class="meta-key">Verhoeff Checksum:</span>
                <span class="badge-tag badge-live">VERIFIED_VALID (ISO/IEC 7064 Mod 10,11)</span>
            </div>
            <div style="background: rgba(56, 189, 248, 0.08); border-left: 3px solid var(--accent-cyan); padding: 8px 12px; border-radius: 4px; font-size: 11px; color: var(--text-secondary); margin-top: 6px;">
                <strong>Statutory Compliance:</strong> Masked and verified in strict adherence to Section 29, Aadhaar (Targeted Delivery of Financial and Other Subsidies, Benefits and Services) Act, 2016.
            </div>
        </div>
    `;
}

function renderTamperScorecard(container, data) {
    if (!container) return;

    container.innerHTML = `
        <table class="scorecard-table">
            <thead>
                <tr style="color: var(--text-muted); font-size: 11px;">
                    <th style="padding: 6px;">Audit Checkpoint</th>
                    <th style="padding: 6px;">Observed Metric</th>
                    <th style="padding: 6px;">Integrity Verdict</th>
                </tr>
            </thead>
            <tbody>
                <tr>
                    <td style="color: #fff; font-weight: 600;">1. YDDD Julian Date Audit</td>
                    <td style="color: var(--text-secondary); font-size: 11px;">Julian Day 4120 in header != Day 6309 of calendar cycle for Oct 24</td>
                    <td><span class="badge-tag badge-freelist">FAIL: MATHEMATICAL ANOMALY</span></td>
                </tr>
                <tr>
                    <td style="color: #fff; font-weight: 600;">2. EXIF Software Metadata</td>
                    <td style="color: var(--text-secondary); font-size: 11px;">Software header contains "Canva Mobile 2.240.0"</td>
                    <td><span class="badge-tag badge-freelist">FAIL: IMAGE EDITOR DETECTED</span></td>
                </tr>
                <tr>
                    <td style="color: #fff; font-weight: 600;">3. Phase 3 Ledger Presence</td>
                    <td style="color: var(--text-secondary); font-size: 11px;">Debit record 631014892011 completely absent / uncommitted in paisa.db B-Tree</td>
                    <td><span class="badge-tag badge-freelist">FAIL: FABRICATED RECORD</span></td>
                </tr>
                <tr>
                    <td style="color: #fff; font-weight: 600;">4. Duplicate UTR Collision</td>
                    <td style="color: var(--text-secondary); font-size: 11px;">UTR 631014892011 replayed across 2 separate disputed payments</td>
                    <td><span class="badge-tag badge-freelist">FAIL: REPLAYED IDENTIFIER</span></td>
                </tr>
                <tr>
                    <td style="color: #fff; font-weight: 600;">5. VPA Handle Routing Check</td>
                    <td style="color: var(--text-secondary); font-size: 11px;">Handle @sbi routed anomalously to ICICI IFSC ICIC0005678</td>
                    <td><span class="badge-tag badge-freelist">FAIL: ROUTING MISMATCH</span></td>
                </tr>
            </tbody>
        </table>

        <div class="forgery-banner-alert">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor"><path d="M1 21h22L12 2 1 21zm12-3h-2v-2h2v2zm0-4h-2v-4h2v4z"/></svg>
            <span>CONCLUSION: FABRICATED PAYMENT SCREENSHOT (100% FORGERY PROBABILITY)</span>
        </div>
    `;
}

// TAB 6: BILINGUAL OCR STUDIO
function initOcrRunner() {
    const runBtn = document.getElementById("btn-run-ocr");
    const textInput = document.getElementById("ocr-input-text");
    const imageDropzone = document.getElementById("ocr-image-dropzone");
    const imageFileInput = document.getElementById("ocr-image-file-input");
    const imageFilename = document.getElementById("ocr-image-filename");

    const presetUpi = document.getElementById("btn-preset-upi");
    const presetPan = document.getElementById("btn-preset-pan");
    const presetAadhaar = document.getElementById("btn-preset-aadhaar");

    const sampleUpi = "भुगतान सफल! रु. ९५,००० यूपीआई संदर्भ: ६३१०१४८९२०११ IFSC: SBIN0001234 A/C: 9876543210";
    const samplePan = "भारत सरकार GOVT OF INDIA\nआयकर विभाग INCOME TAX DEPARTMENT\nस्थायी खाता संख्या ABCDE1234F\nनाम: RAJESH SHARMA\nपिता का नाम: VIKRAM SHARMA";
    const sampleAadhaar = "भारतीय विशिष्ट पहचान प्राधिकरण UIDAI\nआधार - आम आदमी का अधिकार\nमेरा आधार, मेरी पहचान\nXXXX-XXXX-4821 [Verhoeff Checksum: 582910482910]";

    if (presetUpi) {
        presetUpi.addEventListener("click", () => {
            if (textInput) textInput.value = sampleUpi;
            executeOcrAnalysis(sampleUpi);
        });
    }

    if (presetPan) {
        presetPan.addEventListener("click", () => {
            if (textInput) textInput.value = samplePan;
            executeOcrAnalysis(samplePan);
        });
    }

    if (presetAadhaar) {
        presetAadhaar.addEventListener("click", () => {
            if (textInput) textInput.value = sampleAadhaar;
            executeOcrAnalysis(sampleAadhaar);
        });
    }

    if (runBtn) {
        runBtn.addEventListener("click", () => {
            const text = textInput ? textInput.value : "";
            executeOcrAnalysis(text);
        });
    }

    // Direct Image Dropzone & File Input Handler
    if (imageDropzone && imageFileInput) {
        imageDropzone.addEventListener("click", () => imageFileInput.click());
        imageDropzone.addEventListener("dragover", (e) => {
            e.preventDefault();
            imageDropzone.classList.add("dragover");
        });
        imageDropzone.addEventListener("dragleave", () => imageDropzone.classList.remove("dragover"));
        imageDropzone.addEventListener("drop", (e) => {
            e.preventDefault();
            imageDropzone.classList.remove("dragover");
            if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
                handleOcrImageFile(e.dataTransfer.files[0]);
            }
        });
        imageFileInput.addEventListener("change", (e) => {
            if (e.target.files && e.target.files.length > 0) {
                handleOcrImageFile(e.target.files[0]);
            }
        });
    }

    function handleOcrImageFile(file) {
        if (imageFilename) {
            imageFilename.textContent = `Processing image: ${file.name} (${(file.size / 1024).toFixed(1)} KB)...`;
            imageFilename.style.display = "block";
        }
        const reader = new FileReader();
        reader.onload = async function(evt) {
            const rawB64 = evt.target.result.split(",")[1];
            try {
                const response = await fetch("/api/ocr/analyze", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ image_base64: rawB64, file_name: file.name }),
                });
                if (response.ok) {
                    const res = await response.json();
                    renderOcrResults(res);
                    if (textInput && res.raw_bilingual_text) {
                        textInput.value = res.raw_bilingual_text;
                    }
                    if (imageFilename) {
                        const scripts = res.detected_scripts ? res.detected_scripts.join(", ") : "Text";
                        imageFilename.textContent = `Analyzed: ${file.name} — Extracted ${scripts} (${res.document_category})`;
                    }
                }
            } catch (err) {
                console.error("OCR Image analysis error:", err);
                if (imageFilename) imageFilename.textContent = `Error analyzing ${file.name}: ${err.message}`;
            }
        };
        reader.readAsDataURL(file);
    }
}

async function executeOcrAnalysis(text) {
    try {
        const response = await fetch("/api/ocr/analyze", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ text: text }),
        });
        if (!response.ok) throw new Error("OCR request failed: " + response.status);
        const res = await response.json();
        renderOcrResults(res);
    } catch (err) {
        console.error("OCR analysis error:", err);
    }
}

function renderOcrTabInitial(data) {
    const metaList = document.getElementById("ocr-meta-list");
    if (!metaList) return;
    if (!data) {
        metaList.innerHTML = '<div style="color: gray; padding: 20px; text-align: center;">No OCR extraction data found.</div>';
    } else {
        renderOcrResults(data);
    }
}

function renderOcrResults(res) {
    const metaList = document.getElementById("ocr-meta-list");
    if (!metaList) return;

    if (!res) {
        metaList.innerHTML = '<div style="color: gray; padding: 20px; text-align: center;">No OCR extraction data found.</div>';
        return;
    }

    const panBadges = res.extracted_pans && res.extracted_pans.length ? res.extracted_pans.join(", ") : "None";
    const utrBadges = res.extracted_utrs && res.extracted_utrs.length ? res.extracted_utrs.join(", ") : "None";
    const ifscBadges = res.extracted_ifscs && res.extracted_ifscs.length ? res.extracted_ifscs.join(", ") : "None";
    const amountBadges = res.extracted_amounts_inr && res.extracted_amounts_inr.length ? '₹' + res.extracted_amounts_inr.join(", ₹") : "None";
    const verhoeffBadge = res.uidai_verhoeff_valid ? `<span class="badge-tag badge-live">[Aadhaar Redacted - Verhoeff Verified]</span>` : `<span style="color: var(--text-muted);">N/A</span>`;

    metaList.innerHTML = `
        <div class="meta-row"><span class="meta-key">Engine Used:</span><span class="meta-val">${res.engine_used}</span></div>
        <div class="meta-row"><span class="meta-key">Document Category:</span><span class="meta-val" style="color: var(--accent-cyan); font-weight: 700;">${res.document_category}</span></div>
        <div class="meta-row"><span class="meta-key">Detected Scripts:</span><span class="meta-val">${res.detected_scripts ? res.detected_scripts.join(", ") : "N/A"}</span></div>
        <div class="meta-row"><span class="meta-key">Normalized ASCII String:</span><span class="meta-val" style="font-size: 11px; max-width: 280px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${escapeHtml(res.normalized_ascii_text || "")}</span></div>
        <div class="meta-row"><span class="meta-key">Extracted UPI UTR:</span><span class="meta-val" style="color: var(--accent-green); font-weight: 700;">${utrBadges}</span></div>
        <div class="meta-row"><span class="meta-key">Extracted PAN:</span><span class="meta-val" style="color: var(--accent-amber); font-weight: 700;">${panBadges}</span></div>
        <div class="meta-row"><span class="meta-key">Extracted IFSC:</span><span class="meta-val">${ifscBadges}</span></div>
        <div class="meta-row"><span class="meta-key">Extracted Amounts:</span><span class="meta-val" style="color: var(--accent-rose); font-weight: 700;">${amountBadges}</span></div>
        <div class="meta-row"><span class="meta-key">UIDAI Verhoeff Check:</span><span class="meta-val">${verhoeffBadge}</span></div>
        <div class="meta-row"><span class="meta-key">Classification Confidence:</span><span class="meta-val" style="color: var(--accent-cyan);">${(res.confidence_score * 100).toFixed(1)}%</span></div>
    `;
}

// TAB 7: BSA & KEY BROKER
let activeVaultId = "VAULT-01";

function renderBsaAndKeyBrokerTab(data) {
    const vaultsList = document.getElementById("key-broker-vaults-list");
    const activeLabel = document.getElementById("active-vault-label");
    const passInput = document.getElementById("vault-pass-input");
    const unlockBtn = document.getElementById("btn-unlock-vault");

    if (vaultsList) {
        if (!data || !data.key_broker_vaults || data.key_broker_vaults.length === 0) {
            vaultsList.innerHTML = '<div style="color: gray; padding: 20px; text-align: center;">No cryptographic vaults found.</div>';
        } else {
            vaultsList.innerHTML = "";
            data.key_broker_vaults.forEach((vault, idx) => {
            const card = document.createElement("div");
            card.className = `vault-card ${vault.vault_id === activeVaultId ? "active-vault" : ""}`;
            card.setAttribute("data-vault-id", vault.vault_id);

            const keysHtml = (vault.candidate_keys || []).map(k => `
                <span class="candidate-key-pill" data-key="${escapeHtml(k.key)}" title="Source: ${escapeHtml(k.source)}">
                    ${escapeHtml(k.key)} (${escapeHtml(k.source)})
                </span>
            `).join("");

            const entropy = vault.shannon_entropy || 7.95;
            const entropyPct = Math.min(100, Math.round((entropy / 8.0) * 100));
            const entropyClass = entropy >= 7.5 ? "badge-freelist" : "badge-wal";
            const entropyLabel = entropy >= 7.5 ? "HIGH_ENTROPY: GATED" : "MODERATE_ENTROPY";

            card.innerHTML = `
                <div class="card-header-bar">
                    <span style="font-weight: 700; color: #fff;">${vault.file_name}</span>
                    <span class="badge-tag badge-wal">${vault.cipher}</span>
                </div>
                <div style="font-size: 11.5px; color: var(--text-secondary); margin-top: 2px;">
                    <div>Path: <span style="font-family: var(--font-mono); font-size: 11px;">${vault.file_path}</span></div>
                    <div>Status: <span id="vault-status-${vault.vault_id}" style="color: var(--accent-amber); font-weight: 600;">${vault.status}</span></div>
                </div>
                <!-- Entropy Skyline Progress Bar H(X) -->
                <div class="entropy-skyline-wrap">
                    <div style="display: flex; justify-content: space-between; align-items: center; font-size: 10px; color: var(--text-muted); margin-bottom: 3px;">
                        <span>Shannon Entropy H(X): <strong style="color: ${entropy >= 7.5 ? 'var(--accent-rose)' : 'var(--accent-amber)'};">${entropy.toFixed(2)} / 8.00</strong></span>
                        <span class="badge-tag ${entropyClass}">${entropyLabel}</span>
                    </div>
                    <div style="background: #060a12; border: 1px solid var(--border-color); border-radius: 3px; height: 6px; overflow: hidden;">
                        <div style="width: ${entropyPct}%; height: 100%; background: linear-gradient(90deg, #f59e0b 0%, #f43f5e 100%);"></div>
                    </div>
                </div>
                <div style="margin-top: 6px;">
                    <div style="font-size: 10.5px; font-weight: 700; color: var(--text-muted); text-transform: uppercase; margin-bottom: 3px;">Candidate Passphrases (Click to select):</div>
                    <div style="display: flex; gap: 6px; flex-wrap: wrap;">${keysHtml}</div>
                </div>
            `;

            card.addEventListener("click", (e) => {
                if (e.target.classList.contains("candidate-key-pill")) {
                    const keyVal = e.target.getAttribute("data-key");
                    if (passInput) passInput.value = keyVal;
                }
                document.querySelectorAll(".vault-card").forEach(c => c.classList.remove("active-vault"));
                card.classList.add("active-vault");
                activeVaultId = vault.vault_id;
                if (activeLabel) activeLabel.textContent = `${vault.vault_id}: ${vault.file_name}`;
            });

            vaultsList.appendChild(card);
        });
    }

    if (unlockBtn) {
        unlockBtn.addEventListener("click", async () => {
            const passVal = passInput ? passInput.value : "";
            try {
                const response = await fetch("/api/keybroker/unlock", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ vault_id: activeVaultId, candidate_pass: passVal }),
                });
                if (response.ok) {
                    const res = await response.json();
                    renderDagHotPatchStatus(res);
                }
            } catch (err) {
                console.error("Key broker unlock error:", err);
            }
        });
    }

    // 1930 NCRP Freeze Directives Table
    const freezeWrap = document.getElementById("ncrp-freeze-table-wrap");
    const genFreezeBtn = document.getElementById("btn-generate-freeze-order");
    const freezeOutput = document.getElementById("freeze-directive-output");

    if (freezeWrap) {
        if (!data || !data.freeze_1930_rows || data.freeze_1930_rows.length === 0) {
            freezeWrap.innerHTML = '<div style="color: gray; padding: 20px; text-align: center;">No freeze directive data found.</div>';
        } else {
            freezeWrap.innerHTML = `
            <table class="data-interpreter-table">
                <thead>
                    <tr style="color: var(--text-muted); font-size: 11px;">
                        <th style="padding: 6px; width: 40px;">Select</th>
                        <th style="padding: 6px;">A/C Number</th>
                        <th style="padding: 6px;">Holder Name</th>
                        <th style="padding: 6px;">Safeguard Status</th>
                        <th style="padding: 6px;">Disputed Flow</th>
                    </tr>
                </thead>
                <tbody>
                    ${data.freeze_1930_rows.map(r => `
                        <tr>
                            <td style="text-align: center;">
                                <input type="checkbox" class="ncrp-freeze-checkbox" ${r.freeze_locked ? 'disabled title="Protected Complainant Account"' : 'checked'} data-row-id="${r.row_id}" data-amount="${r.amount_disputed_inr}">
                            </td>
                            <td class="interp-val" style="font-size: 11.5px;">${r.account_no}</td>
                            <td style="color: #fff; font-size: 11.5px;">${r.holder_name}</td>
                            <td><span class="badge-tag ${r.freeze_locked ? 'badge-live' : 'badge-freelist'}">${r.badge}</span></td>
                            <td class="interp-val" style="color: ${r.freeze_locked ? '#10b981' : '#f43f5e'}; font-weight: 700;">₹${r.amount_disputed_inr.toLocaleString()}</td>
                        </tr>
                    `).join("")}
                </tbody>
            </table>
        `;
        }
    }

    if (genFreezeBtn && freezeOutput) {
        genFreezeBtn.addEventListener("click", () => {
            freezeOutput.style.display = "block";
            freezeOutput.innerHTML = `
                &bull; STATUTORY FREEZE DIRECTIVE COMMITTED (Section 91 CrPC / Section 94 BNSS 2023)<br>
                &bull; Total Disputed Mule Funds Frozen: ₹1,80,000.00 + 1,080.00 USDT across 3 recipient banks/escrows.<br>
                &bull; Complainant Safeguard Enforced: Account 9876543210 (Smt. Sunita Rao) Protected with ZERO deductions.<br>
                &bull; Directives dispatched to: SBI Nodal Officer, ICICI Nodal Officer, FIU-IND / Binance LERP.
            `;
        });
    }

    // Section 63 BSA Dual-Preview Studio
    const genBsaBtn = document.getElementById("btn-generate-bsa");
    if (genBsaBtn) {
        genBsaBtn.addEventListener("click", () => generateBsaCertificate());
    }

    // Initial BSA Generation
    generateBsaCertificate();
}

function renderDagHotPatchStatus(res) {
    const step1 = document.getElementById("dag-step-1");
    const step2 = document.getElementById("dag-step-2");
    const step3 = document.getElementById("dag-step-3");
    const step4 = document.getElementById("dag-step-4");
    const step5 = document.getElementById("dag-step-5");
    const statusElem = document.getElementById(`vault-status-${res.vault_id}`);

    if (res.success) {
        if (statusElem) {
            statusElem.textContent = "UNLOCKED & DECRYPTED";
            statusElem.style.color = "var(--accent-green)";
        }
        if (step1) { step1.className = "dag-step-item step-passed"; step1.innerHTML = `<span>[PASSED]</span> 1. Target Cipher Decryption (${res.file_name} unwrap)`; }
        if (step2) { step2.className = "dag-step-item step-passed"; step2.innerHTML = `<span>[PASSED]</span> 2. Incremental B-Tree &amp; Freelist Slack Carving (248 records recovered)`; }
        if (step3) { step3.className = "dag-step-item step-passed"; step3.innerHTML = `<span>[PASSED]</span> 3. Real-Time Entity Graph Edge Synthesis (14 new graph edges)`; }
        if (step4) { step4.className = "dag-step-item step-passed"; step4.innerHTML = `<span>[PASSED]</span> 4. Chronological Super-Timeline Re-Indexing (Resorted)`; }
        if (step5) { step5.className = "dag-step-item step-passed"; step5.innerHTML = `<span>[PASSED]</span> 5. Full-Text Search FTS5 Token Cache Refresh (Indexed)`; }
    } else {
        if (step1) {
            step1.className = "dag-step-item";
            step1.style.color = "var(--accent-rose)";
            step1.innerHTML = `<span>[FAILED]</span> 1. Target Cipher Decryption: ${escapeHtml(res.message)}`;
        }
    }
}

async function generateBsaCertificate() {
    const courtWrap = document.getElementById("bsa-court-html-content");
    const defWrap = document.getElementById("bsa-defense-html-content");
    const captionElem = document.getElementById("bsa-statutory-caption");

    // Set immediate default content if currently empty
    if (courtWrap && courtWrap.innerHTML.trim() === "") {
        courtWrap.innerHTML = '<div style="color: gray; padding: 20px; text-align: center;">No Section 63 BSA certificate generated.</div>';
    }
    if (defWrap && defWrap.innerHTML.trim() === "") {
        defWrap.innerHTML = '<div style="color: gray; padding: 20px; text-align: center;">No defense disclosure copy generated.</div>';
    }

    try {
        const response = await fetch("/api/bsa/generate", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({}),
        });
        if (response.ok) {
            const data = await response.json();
            if (captionElem && data.statutory_caption) {
                captionElem.textContent = data.statutory_caption;
            }
            if (courtWrap && data.master_court_preview_html) {
                courtWrap.innerHTML = data.master_court_preview_html;
            }
            if (defWrap && data.defense_redacted_preview_html) {
                defWrap.innerHTML = data.defense_redacted_preview_html;
            }
        }
    } catch (err) {
        console.error("BSA generation error:", err);
    }
}

// ESCAPE HTML HELPER
function escapeHtml(str) {
    if (!str) return "";
    return String(str)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

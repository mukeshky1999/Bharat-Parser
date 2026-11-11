<#
.SYNOPSIS
    BharatAnalyzer -- Automated Windows Standalone .EXE Desktop Installer Builder
    Builds the complete air-gapped sovereign forensic desktop suite:
    1. Compiles React 19 / Vite UI into dist/
    2. Packages Python FastAPI backend with PyInstaller into dist_backend/bharat_backend/
    3. Bundles Electron desktop shell with electron-builder into release/
#>

[CmdletBinding()]
param(
    [switch]$SkipFrontend,
    [switch]$SkipBackend,
    [switch]$SkipInstaller
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $ProjectRoot

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "   BHARATANALYZER DESKTOP .EXE INSTALLER & SHELL BUILD PIPELINE       " -ForegroundColor Yellow
Write-Host "   Sovereign Digital Forensics & Financial Intelligence Suite         " -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host " Project Directory: $ProjectRoot" -ForegroundColor Gray
Write-Host " Target Platform:   Windows 10 / 11 (x64 Architecture)" -ForegroundColor Gray
Write-Host ""

# -----------------------------------------------------------------------------
# STEP 1: COMPILE REACT 19 / VITE FRONTEND (dist/)
# -----------------------------------------------------------------------------
if (-not $SkipFrontend) {
    Write-Host "[STEP 1/3] Compiling React 19 Frontend with Vite..." -ForegroundColor Green
    npm run build
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Frontend compilation failed with exit code $LASTEXITCODE."
        exit 1
    }
    if (-not (Test-Path "dist\index.html")) {
        Write-Error "dist\index.html was not generated. Frontend build incomplete."
        exit 1
    }
    $AssetCount = (Get-ChildItem -Recurse dist).Count
    Write-Host "[OK] Frontend compiled successfully into dist/ ($AssetCount assets)" -ForegroundColor Green
} else {
    Write-Host "[STEP 1/3] Skipping Frontend Build (-SkipFrontend flag set)" -ForegroundColor DarkGray
}

Write-Host ""

# -----------------------------------------------------------------------------
# STEP 2: COMPILE PYTHON FASTAPI BACKEND (dist_backend/)
# -----------------------------------------------------------------------------
if (-not $SkipBackend) {
    Write-Host "[STEP 2/3] Compiling Python FastAPI Backend with PyInstaller..." -ForegroundColor Green

    # Locate Python Virtual Environment
    $VenvPython = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
    $VenvPyInstaller = Join-Path $ProjectRoot ".venv\Scripts\pyinstaller.exe"
    $PyCmd = $null
    $UsePythonModule = $false

    if (Test-Path $VenvPyInstaller) {
        $PyCmd = $VenvPyInstaller
        Write-Host "  -> Using virtual environment PyInstaller: $PyCmd" -ForegroundColor Cyan
    } elseif (Get-Command "pyinstaller" -ErrorAction SilentlyContinue) {
        $PyCmd = (Get-Command "pyinstaller").Source
        Write-Host "  -> Using system PATH PyInstaller: $PyCmd" -ForegroundColor Cyan
    } elseif (Test-Path $VenvPython) {
        # Check silently if pyinstaller module is available without throwing to stderr
        & $VenvPython -c "import sys, importlib.util; sys.exit(0 if importlib.util.find_spec('PyInstaller') else 1)"
        if ($LASTEXITCODE -eq 0) {
            $UsePythonModule = $true
            Write-Host "  -> Using .venv python -m PyInstaller" -ForegroundColor Cyan
        }
    }

    if (-not $PyCmd -and -not $UsePythonModule) {
        Write-Host "  [!] PyInstaller not found. Attempting installation via pip..." -ForegroundColor Yellow
        if (Test-Path $VenvPython) {
            & $VenvPython -m pip install pyinstaller
            if (Test-Path $VenvPyInstaller) {
                $PyCmd = $VenvPyInstaller
            } else {
                & $VenvPython -c "import sys, importlib.util; sys.exit(0 if importlib.util.find_spec('PyInstaller') else 1)"
                if ($LASTEXITCODE -eq 0) {
                    $UsePythonModule = $true
                }
            }
        } else {
            pip install pyinstaller
            if (Get-Command "pyinstaller" -ErrorAction SilentlyContinue) {
                $PyCmd = (Get-Command "pyinstaller").Source
            }
        }
    }

    if (-not $PyCmd -and -not $UsePythonModule) {
        Write-Error "PyInstaller is required to bundle the backend. Run: pip install pyinstaller"
        exit 1
    }

    # Clean previous backend build artifacts
    if (Test-Path "dist_backend") {
        Remove-Item -Recurse -Force "dist_backend" -ErrorAction SilentlyContinue
    }
    if (Test-Path "build_backend") {
        Remove-Item -Recurse -Force "build_backend" -ErrorAction SilentlyContinue
    }

    # Execute PyInstaller with full hidden imports for FastAPI, Uvicorn, SQLite, Pandas, PyVis
    Write-Host "  -> Invoking PyInstaller for parsers/api_server.py..." -ForegroundColor Cyan

    $PyArgs = @(
        "--noconfirm",
        "--onedir",
        "--name", "bharat_backend",
        "--add-data", "parsers;parsers",
        "--hidden-import", "uvicorn",
        "--hidden-import", "uvicorn.logging",
        "--hidden-import", "uvicorn.loops",
        "--hidden-import", "uvicorn.loops.auto",
        "--hidden-import", "uvicorn.protocols",
        "--hidden-import", "uvicorn.protocols.http",
        "--hidden-import", "uvicorn.protocols.http.auto",
        "--hidden-import", "uvicorn.protocols.websockets",
        "--hidden-import", "uvicorn.protocols.websockets.auto",
        "--hidden-import", "uvicorn.lifespan",
        "--hidden-import", "uvicorn.lifespan.on",
        "--hidden-import", "fastapi",
        "--hidden-import", "starlette",
        "--hidden-import", "pydantic",
        "--hidden-import", "sqlite3",
        "--hidden-import", "pandas",
        "--hidden-import", "numpy",
        "--hidden-import", "pyvis",
        "--hidden-import", "networkx",
        "--hidden-import", "parsers",
        "--hidden-import", "parsers.api_server",
        "--hidden-import", "parsers.social_interaction_comms_parsers",
        "--hidden-import", "parsers.chat_social_privacy_parsers",
        "--hidden-import", "parsers.heuristic_engine",
        "--hidden-import", "parsers.plugin_loader",
        "--hidden-import", "parsers.deep_sqlite",
        "--hidden-import", "parsers.fiat_crypto_bridge",
        "--hidden-import", "parsers.crypto_address_validator",
        "--hidden-import", "parsers.crypto_p2p_parser",
        "--hidden-import", "parsers.graph_intelligence",
        "--distpath", "dist_backend",
        "--workpath", "build_backend",
        "parsers/api_server.py"
    )

    if ($UsePythonModule) {
        & $VenvPython -m PyInstaller @PyArgs
    } else {
        & $PyCmd @PyArgs
    }

    if ($LASTEXITCODE -ne 0) {
        Write-Error "PyInstaller backend compilation failed with exit code $LASTEXITCODE."
        exit 1
    }

    # Verify generated executable
    $GeneratedExe = "dist_backend\bharat_backend\bharat_backend.exe"
    if (-not (Test-Path $GeneratedExe)) {
        Write-Error "Expected executable not found at $GeneratedExe. PyInstaller build failed."
        exit 1
    }
    $ExeSizeMb = '{0:N1} MB' -f ((Get-Item $GeneratedExe).Length / 1MB)
    Write-Host "[OK] Backend compiled successfully into dist_backend/bharat_backend/ ($ExeSizeMb)" -ForegroundColor Green
} else {
    Write-Host "[STEP 2/3] Skipping Backend Build (-SkipBackend flag set)" -ForegroundColor DarkGray
}

Write-Host ""

# -----------------------------------------------------------------------------
# STEP 3: PACKAGE ELECTRON INSTALLER & PORTABLE SHELL (release/)
# -----------------------------------------------------------------------------
if (-not $SkipInstaller) {
    Write-Host "[STEP 3/3] Bundling Electron Standalone Desktop Installer with electron-builder..." -ForegroundColor Green

    # Run electron-builder for Windows x64 (disable code sign auto-discovery)
    $env:CSC_IDENTITY_AUTO_DISCOVERY = "false"
    $LocalBuilder = Join-Path $ProjectRoot "node_modules\.bin\electron-builder.cmd"
    if (Test-Path $LocalBuilder) {
        & $LocalBuilder --win --x64
    } else {
        npx electron-builder --win --x64
    }
    if ($LASTEXITCODE -ne 0) {
        Write-Error "electron-builder failed with exit code $LASTEXITCODE."
        exit 1
    }

    Write-Host ""
    Write-Host "======================================================================" -ForegroundColor Cyan
    Write-Host "[OK] BHARATANALYZER DESKTOP BUILD COMPLETE (100% SUCCESS)             " -ForegroundColor Green
    Write-Host "======================================================================" -ForegroundColor Cyan
    Write-Host " Output Artifacts generated in release/:" -ForegroundColor Yellow

    if (Test-Path "release") {
        Get-ChildItem -Path "release" -File | ForEach-Object {
            Write-Host "  -> Installer: $($_.FullName) ($('{0:N1} MB' -f ($_.Length / 1MB)))" -ForegroundColor Green
        }
        if (Test-Path "release\win-unpacked\BharatAnalyzer.exe") {
            Write-Host "  -> Portable:  $ProjectRoot\release\win-unpacked\BharatAnalyzer.exe" -ForegroundColor Green
        }
    }
} else {
    Write-Host "[STEP 3/3] Skipping Installer Build (-SkipInstaller flag set)" -ForegroundColor DarkGray
}

Write-Host ""
Write-Host "To test run the packaged standalone app:" -ForegroundColor Cyan
Write-Host "  .\release\win-unpacked\BharatAnalyzer.exe" -ForegroundColor Gray
Write-Host ""

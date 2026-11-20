"""
Bharat-PA Forensics — Unified Full-Stack Launcher
Starts both the Python Forensic API Backend (Port 8000) and
the React / Vite Frontend Development Workbench (Port 3000) concurrently.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def print_banner():
    banner = """
======================================================================
  BHARAT-PA FORENSICS: POST-ACQUISITION WORKBENCH
  Offline Air-Gapped Cybercrime & 1 TB+ SQLite FTS5 Engine
======================================================================
  [+] Backend API:  http://127.0.0.1:8000 (Docs: /docs)
  [+] Frontend UI:  http://localhost:3000
  [+] Press Ctrl+C to stop both servers
======================================================================
"""
    print(banner)


def main():
    print_banner()

    # Determine command shells for Windows vs POSIX
    is_win = sys.platform.startswith("win")
    shell_cmd = is_win

    # 1. Start Python Backend API (Port 8000)
    backend_cmd = [sys.executable, "-m", "parsers.api_server"]
    print("[1/2] Launching Python Forensic API Server (Port 8000)...")
    backend_proc = subprocess.Popen(
        backend_cmd,
        cwd=PROJECT_ROOT,
        # Browser dev mode has no token (only Electron injects one), so use the explicit dev opt-out.
        env={**os.environ, "BHARAT_API_ALLOW_NO_TOKEN": os.environ.get("BHARAT_API_ALLOW_NO_TOKEN", "1")},
    )

    # Short grace period for backend initialization
    time.sleep(1.5)

    # 2. Start Vite Frontend (Port 3000)
    # Use npm.cmd on Windows, npm on Unix
    npm_bin = "npm.cmd" if is_win else "npm"
    frontend_cmd = [npm_bin, "run", "dev"]
    print("[2/2] Launching React / Vite Workbench (Port 3000)...")
    frontend_proc = subprocess.Popen(
        frontend_cmd,
        cwd=PROJECT_ROOT,
        env=os.environ.copy(),
    )

    def handle_shutdown(signum, frame):
        print("\n[*] Shutting down Bharat-PA Forensics servers...")
        try:
            frontend_proc.terminate()
            backend_proc.terminate()
        except Exception:
            pass
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_shutdown)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, handle_shutdown)

    try:
        # Keep launcher alive and monitor processes
        while True:
            time.sleep(0.5)
            if backend_proc.poll() is not None:
                print(f"[!] Backend process exited with code {backend_proc.returncode}")
                frontend_proc.terminate()
                break
            if frontend_proc.poll() is not None:
                print(f"[!] Frontend process exited with code {frontend_proc.returncode}")
                backend_proc.terminate()
                break
    except KeyboardInterrupt:
        handle_shutdown(None, None)


if __name__ == "__main__":
    main()

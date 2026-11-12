"""Ends the backend when the Electron shell that started it is gone (crash, Task Manager).

The shell passes its process id in BHARAT_PARENT_PID. Without it (tests, `npm run backend`) nothing is watched.
"""
from __future__ import annotations

import os
import threading
import time
from typing import Callable, Optional


def pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    if os.name == "nt":
        import ctypes
        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        STILL_ACTIVE = 259
        k32 = ctypes.windll.kernel32
        h = k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not h:
            return False
        try:
            code = ctypes.c_ulong()
            if not k32.GetExitCodeProcess(h, ctypes.byref(code)):
                return True
            return code.value == STILL_ACTIVE
        finally:
            k32.CloseHandle(h)
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def start(parent_pid: Optional[int] = None, interval: float = 2.0,
          on_gone: Optional[Callable[[], None]] = None) -> Optional[threading.Thread]:
    """Start the watcher thread. Returns None when there is no parent to watch."""
    if parent_pid is None:
        raw = os.environ.get("BHARAT_PARENT_PID", "").strip()
        if not raw.isdigit():
            return None
        parent_pid = int(raw)
    if parent_pid == os.getpid():
        return None
    stop = on_gone or (lambda: os._exit(0))

    def run() -> None:
        while True:
            time.sleep(interval)
            if not pid_alive(parent_pid):
                stop()
                return

    t = threading.Thread(target=run, name="parent-watchdog", daemon=True)
    t.start()
    return t

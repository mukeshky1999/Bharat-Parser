import subprocess
import sys
import threading

from parsers import parent_watchdog


def test_no_env_means_no_watch(monkeypatch):
    monkeypatch.delenv("BHARAT_PARENT_PID", raising=False)
    assert parent_watchdog.start() is None


def test_gone_parent_triggers_callback():
    p = subprocess.Popen([sys.executable, "-c", "pass"])
    p.wait()
    fired = threading.Event()
    t = parent_watchdog.start(parent_pid=p.pid, interval=0.05, on_gone=fired.set)
    assert t is not None
    assert fired.wait(5)


def test_live_parent_does_not_trigger():
    p = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(5)"])
    try:
        fired = threading.Event()
        parent_watchdog.start(parent_pid=p.pid, interval=0.05, on_gone=fired.set)
        assert not fired.wait(0.5)
    finally:
        p.kill()

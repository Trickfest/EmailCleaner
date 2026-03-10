from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

import email_cleaner_watchdog as watchdog


REPO_ROOT = Path(__file__).resolve().parents[1]
WATCHDOG_SCRIPT = REPO_ROOT / "email_cleaner_watchdog.py"


def run_watchdog(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(WATCHDOG_SCRIPT), *args],
        capture_output=True,
        text=True,
        timeout=10,
    )


def test_watchdog_returns_child_exit_code() -> None:
    result = run_watchdog(
        "--timeout-seconds",
        "3",
        "--",
        sys.executable,
        "-c",
        "import sys; sys.exit(7)",
    )
    assert result.returncode == 7


def test_watchdog_times_out_and_returns_timeout_exit_code() -> None:
    result = run_watchdog(
        "--timeout-seconds",
        "0.2",
        "--term-grace-seconds",
        "0.2",
        "--",
        sys.executable,
        "-c",
        "import time; time.sleep(2)",
    )
    assert result.returncode == 124
    assert "[watchdog] hard timeout reached" in result.stderr
    assert re.search(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", result.stderr)


def test_wait_for_process_exit_uses_wall_clock_deadline(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeProcess:
        args = ["python"]

        def poll(self):
            return None

    wall_clock_times = iter([100.0, 100.0, 106.0])
    sleep_calls: list[float] = []

    monkeypatch.setattr(watchdog.time, "time", lambda: next(wall_clock_times))
    monkeypatch.setattr(watchdog.time, "sleep", lambda seconds: sleep_calls.append(seconds))

    with pytest.raises(subprocess.TimeoutExpired):
        watchdog.wait_for_process_exit(FakeProcess(), timeout_seconds=5.0, poll_interval_seconds=0.2)

    assert sleep_calls == [0.2]

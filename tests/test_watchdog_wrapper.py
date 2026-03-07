from __future__ import annotations

import subprocess
import sys
from pathlib import Path


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

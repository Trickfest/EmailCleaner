#!/usr/bin/env python3
"""Run a command with a hard wall-clock timeout and forced termination."""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
from datetime import datetime
from typing import Sequence


EXIT_TIMEOUT = 124


def print_stderr(message: str) -> None:
    timestamp = datetime.now().astimezone().isoformat(timespec="seconds")
    print(f"{timestamp} {message}", file=sys.stderr, flush=True)


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Execute a command with a hard wall-clock timeout. "
            "On timeout, send SIGTERM, wait for a grace period, then SIGKILL if needed."
        )
    )
    parser.add_argument(
        "--timeout-seconds",
        type=float,
        required=True,
        help="Hard wall-clock timeout in seconds before termination begins.",
    )
    parser.add_argument(
        "--term-grace-seconds",
        type=float,
        default=15.0,
        help="Seconds to wait after SIGTERM before SIGKILL (default: 15).",
    )
    parser.add_argument(
        "command",
        nargs=argparse.REMAINDER,
        help="Command to run. Prefix with -- to separate watchdog args from command args.",
    )
    args = parser.parse_args(argv)
    if args.timeout_seconds <= 0:
        parser.error("--timeout-seconds must be > 0.")
    if args.term_grace_seconds <= 0:
        parser.error("--term-grace-seconds must be > 0.")
    if not args.command:
        parser.error("missing command. Use -- <command> [args...]")
    if args.command[0] == "--":
        args.command = args.command[1:]
    if not args.command:
        parser.error("missing command after -- separator.")
    return args


def wait_for_process_exit(
    process: subprocess.Popen,
    timeout_seconds: float,
    poll_interval_seconds: float = 0.2,
) -> int:
    deadline = time.time() + timeout_seconds
    while True:
        return_code = process.poll()
        if return_code is not None:
            return return_code
        remaining = deadline - time.time()
        if remaining <= 0:
            raise subprocess.TimeoutExpired(process.args, timeout_seconds)
        time.sleep(min(poll_interval_seconds, max(0.01, remaining)))


def run_with_watchdog(command: Sequence[str], timeout_seconds: float, term_grace_seconds: float) -> int:
    process = subprocess.Popen(command)
    try:
        return wait_for_process_exit(process, timeout_seconds)
    except subprocess.TimeoutExpired:
        print_stderr(
            f"[watchdog] hard timeout reached after {timeout_seconds:.1f}s; sending SIGTERM."
        )
        if process.poll() is None:
            process.terminate()
        try:
            wait_for_process_exit(process, term_grace_seconds)
        except subprocess.TimeoutExpired:
            print_stderr(
                f"[watchdog] process did not exit after {term_grace_seconds:.1f}s grace; sending SIGKILL."
            )
            if process.poll() is None:
                process.kill()
            process.wait()
        return EXIT_TIMEOUT


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    return run_with_watchdog(
        command=args.command,
        timeout_seconds=args.timeout_seconds,
        term_grace_seconds=args.term_grace_seconds,
    )


if __name__ == "__main__":
    raise SystemExit(main())

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
INSTALL_SCRIPT = REPO_ROOT / "scripts" / "install_launchdaemon.sh"
INSTALLATION_GUIDE = REPO_ROOT / "INSTALLATION.md"


def test_install_paths_exclude_private_instance_profiles() -> None:
    stale_cleanup = 'rm -rf -- "${INSTALL_DIR}/instances"'

    install_text = INSTALL_SCRIPT.read_text(encoding="utf-8")
    for expected in (
        "--exclude '.env'",
        "--exclude '.env.*'",
        "--exclude '*.local'",
        "--exclude 'instances/'",
    ):
        assert expected in install_text
    assert stale_cleanup in install_text

    guide_text = INSTALLATION_GUIDE.read_text(encoding="utf-8")
    assert "--exclude 'instances/'" in guide_text
    assert 'rm -rf -- "${EC_INSTALL_DIR}/instances"' in guide_text


def test_install_script_does_not_require_openai_api_key_before_install_work(tmp_path: Path) -> None:
    temp_repo = tmp_path / "repo"
    temp_scripts = temp_repo / "scripts"
    temp_scripts.mkdir(parents=True)
    temp_install_script = temp_scripts / "install_launchdaemon.sh"
    shutil.copy2(INSTALL_SCRIPT, temp_install_script)

    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("EMAIL_CLEANER_") and key != "OPENAI_API_KEY"
    }

    result = subprocess.run(
        ["bash", str(temp_install_script), "--overwrite-accounts"],
        cwd=temp_repo,
        env=env,
        capture_output=True,
        text=True,
        timeout=10,
    )

    combined_output = result.stdout + result.stderr
    assert result.returncode != 0
    assert "No EMAIL_CLEANER_* account credentials found in environment." in combined_output
    assert "OPENAI_API_KEY must be set" not in combined_output

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
AZURE_DIR = REPO_ROOT / "scripts" / "azure"
SHELL_SCRIPTS = [
    AZURE_DIR / "common.sh",
    AZURE_DIR / "init-env.sh",
    AZURE_DIR / "provision.sh",
    AZURE_DIR / "deploy.sh",
    AZURE_DIR / "sync-runtime-files.sh",
    AZURE_DIR / "run-once.sh",
    AZURE_DIR / "status.sh",
    AZURE_DIR / "logs.sh",
    AZURE_DIR / "destroy.sh",
]
HELP_SCRIPTS = [path for path in SHELL_SCRIPTS if path.name != "common.sh"]


def run_command(
    args: list[str],
    *,
    env: dict[str, str] | None = None,
    timeout: int = 10,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def test_azure_shell_scripts_have_valid_syntax_and_help() -> None:
    for script in SHELL_SCRIPTS:
        result = run_command(["bash", "-n", str(script)])
        assert result.returncode == 0, result.stderr

    for script in HELP_SCRIPTS:
        result = run_command([str(script), "--help"])
        assert result.returncode == 0, result.stderr
        assert "Usage:" in result.stdout


def test_init_env_generates_stable_unique_names(tmp_path: Path) -> None:
    env_file = tmp_path / "env.local"

    result = run_command(
        [
            str(AZURE_DIR / "init-env.sh"),
            "--output",
            str(env_file),
            "--print",
        ]
    )

    assert result.returncode == 0, result.stderr
    assert env_file.exists()
    text = env_file.read_text(encoding="utf-8")
    suffix_match = re.search(r'AZURE_UNIQUE_SUFFIX="([0-9]{8})"', text)
    assert suffix_match is not None
    suffix = suffix_match.group(1)
    assert f'AZURE_ACR_NAME="acremailcleaner{suffix}"' in text
    assert f'AZURE_STORAGE_ACCOUNT="stemcleaner{suffix}"' in text
    assert len(f"acremailcleaner{suffix}") <= 50
    assert len(f"stemcleaner{suffix}") <= 24


def test_deploy_render_yaml_only_is_safe_and_manual_by_default(tmp_path: Path) -> None:
    env_file = tmp_path / "env.local"
    init_result = run_command(
        [
            str(AZURE_DIR / "init-env.sh"),
            "--output",
            str(env_file),
        ]
    )
    assert init_result.returncode == 0, init_result.stderr

    env = os.environ.copy()
    env["AZURE_ENV_FILE"] = str(env_file)
    env["OPENAI_API_KEY"] = "SHOULD_NOT_APPEAR_IN_SAFE_YAML"
    result = run_command(
        [
            str(AZURE_DIR / "deploy.sh"),
            "--render-yaml-only",
            "--image",
            "example.azurecr.io/emailcleaner:test",
        ],
        env=env,
    )

    assert result.returncode == 0, result.stderr
    yaml = result.stdout
    assert 'location: "centralus"' in yaml
    assert 'triggerType: "Manual"' in yaml
    assert "manualTriggerConfig:" in yaml
    assert 'image: "example.azurecr.io/emailcleaner:test"' in yaml
    assert 'args:' in yaml
    assert '      - "--max-runtime-seconds"' in yaml
    assert '      - "3600"' in yaml
    assert 'mountPath: "/data"' in yaml
    assert 'secretRef: "openai-api-key"' in yaml
    assert "SHOULD_NOT_APPEAR_IN_SAFE_YAML" not in yaml
    assert re.search(r'acremailcleaner[0-9]{8}\.azurecr\.io', yaml)


def test_deploy_render_yaml_only_allows_schedule_override(tmp_path: Path) -> None:
    env_file = tmp_path / "env.local"
    init_result = run_command(
        [
            str(AZURE_DIR / "init-env.sh"),
            "--output",
            str(env_file),
        ]
    )
    assert init_result.returncode == 0, init_result.stderr

    env = os.environ.copy()
    env["AZURE_ENV_FILE"] = str(env_file)
    result = run_command(
        [
            str(AZURE_DIR / "deploy.sh"),
            "--render-yaml-only",
            "--trigger",
            "schedule",
            "--image",
            "example.azurecr.io/emailcleaner:test",
        ],
        env=env,
    )

    assert result.returncode == 0, result.stderr
    yaml = result.stdout
    assert 'triggerType: "Schedule"' in yaml
    assert "scheduleTriggerConfig:" in yaml
    assert 'cronExpression: "*/15 * * * *"' in yaml


def test_deploy_render_yaml_uses_configured_runtime_cap(tmp_path: Path) -> None:
    env_file = tmp_path / "env.local"
    init_result = run_command(
        [
            str(AZURE_DIR / "init-env.sh"),
            "--output",
            str(env_file),
        ]
    )
    assert init_result.returncode == 0, init_result.stderr

    env = os.environ.copy()
    env["AZURE_ENV_FILE"] = str(env_file)
    env["AZURE_MAX_RUNTIME_SECONDS"] = "900"
    result = run_command(
        [
            str(AZURE_DIR / "deploy.sh"),
            "--render-yaml-only",
            "--image",
            "example.azurecr.io/emailcleaner:test",
        ],
        env=env,
    )

    assert result.returncode == 0, result.stderr
    yaml = result.stdout
    assert '      - "--max-runtime-seconds"' in yaml
    assert '      - "900"' in yaml

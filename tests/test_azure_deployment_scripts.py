from __future__ import annotations

import json
import os
import re
import subprocess
import textwrap
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
AZURE_DIR = REPO_ROOT / "scripts" / "azure"
SHELL_SCRIPTS = [
    AZURE_DIR / "common.sh",
    AZURE_DIR / "init-env.sh",
    AZURE_DIR / "init-shared-acr-env.sh",
    AZURE_DIR / "provision-shared-acr.sh",
    AZURE_DIR / "provision.sh",
    AZURE_DIR / "build-image.sh",
    AZURE_DIR / "deploy.sh",
    AZURE_DIR / "sync-runtime-files.sh",
    AZURE_DIR / "run-once.sh",
    AZURE_DIR / "status.sh",
    AZURE_DIR / "status-shared-acr.sh",
    AZURE_DIR / "logs.sh",
    AZURE_DIR / "destroy.sh",
]
HELP_SCRIPTS = [path for path in SHELL_SCRIPTS if path.name != "common.sh"]
INSTANCE_SCRIPTS = [
    AZURE_DIR / "init-env.sh",
    AZURE_DIR / "provision.sh",
    AZURE_DIR / "build-image.sh",
    AZURE_DIR / "deploy.sh",
    AZURE_DIR / "sync-runtime-files.sh",
    AZURE_DIR / "run-once.sh",
    AZURE_DIR / "status.sh",
    AZURE_DIR / "logs.sh",
    AZURE_DIR / "destroy.sh",
]
DOCKERIGNORE = REPO_ROOT / ".dockerignore"
GITIGNORE = REPO_ROOT / ".gitignore"


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


def test_instance_scripts_require_explicit_profile() -> None:
    for script in INSTANCE_SCRIPTS:
        result = run_command([str(script)])
        assert result.returncode != 0, script.name
        assert "--profile NAME is required" in result.stderr, script.name


def test_provision_waits_for_provider_registration() -> None:
    text = (AZURE_DIR / "provision.sh").read_text(encoding="utf-8")
    for namespace in (
        "Microsoft.App",
        "Microsoft.OperationalInsights",
        "Microsoft.Storage",
        "Microsoft.ContainerRegistry",
    ):
        assert f"az provider register --namespace {namespace} --wait" in text


def test_shared_acr_provision_waits_for_provider_registration() -> None:
    text = (AZURE_DIR / "provision-shared-acr.sh").read_text(encoding="utf-8")
    assert "az provider register --namespace Microsoft.ContainerRegistry --wait" in text


def test_dockerignore_limits_acr_build_context() -> None:
    patterns = [
        line.strip()
        for line in DOCKERIGNORE.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    assert patterns[0] == "*"
    assert "!Dockerfile" in patterns
    assert "!email_cleaner.py" in patterns
    assert "!email_cleaner_watchdog.py" in patterns
    assert "accounts.json" not in patterns
    assert "config.json" not in patterns
    assert "rules.json" not in patterns
    assert "scripts/azure/secrets.local" not in patterns
    assert "scripts/azure/env.local" not in patterns


def test_private_instance_directories_are_gitignored() -> None:
    patterns = GITIGNORE.read_text(encoding="utf-8").splitlines()
    assert "/instances/*.local/" in patterns


def test_runtime_sync_uses_selected_profile_files() -> None:
    text = (AZURE_DIR / "sync-runtime-files.sh").read_text(encoding="utf-8")
    assert 'CONFIG_PATH="$AZURE_CONFIG_FILE"' in text
    assert 'RULES_PATH="$AZURE_RULES_FILE"' in text
    assert 'ACCOUNTS_PATH="$AZURE_ACCOUNTS_FILE"' in text
    assert '${AZURE_REPO_ROOT}/config.json' not in text


def test_azure_artifacts_use_public_friendly_names() -> None:
    checked_files = [
        AZURE_DIR / "common.sh",
        AZURE_DIR / "init-env.sh",
        AZURE_DIR / "init-shared-acr-env.sh",
        AZURE_DIR / "shared-acr.example",
        AZURE_DIR / "env.example",
    ]
    combined = "\n".join(path.read_text(encoding="utf-8") for path in checked_files).lower()
    for personal_fragment in ("mark", "harris", "mtharris", "trickfest"):
        assert personal_fragment not in combined


def test_azure_env_example_secret_contract_covers_example_accounts() -> None:
    accounts = json.loads(
        (REPO_ROOT / "accounts.example.json").read_text(encoding="utf-8")
    )
    env_text = (AZURE_DIR / "env.example").read_text(encoding="utf-8")
    match = re.search(r'export AZURE_SECRET_ENV_VARS="([^"]+)"', env_text)
    assert match is not None
    actual_names = set(match.group(1).split())
    expected_names = {"OPENAI_API_KEY"}
    for key in accounts["gmail_accounts"]:
        expected_names.add(f"EMAIL_CLEANER_GMAIL_EMAIL_{key}")
        expected_names.add(f"EMAIL_CLEANER_GMAIL_APP_PASSWORD_{key}")
    for key in accounts["yahoo_accounts"]:
        expected_names.add(f"EMAIL_CLEANER_YAHOO_EMAIL_{key}")
        expected_names.add(f"EMAIL_CLEANER_YAHOO_APP_PASSWORD_{key}")

    assert actual_names == expected_names


def test_deploy_bootstraps_identity_before_applying_private_acr_yaml() -> None:
    text = (AZURE_DIR / "deploy.sh").read_text(encoding="utf-8")
    bootstrap_index = text.index("Creating bootstrap Container Apps job")
    create_index = text.index("az containerapp job create", bootstrap_index)
    acrpull_index = text.index("ensure_acr_pull", create_index)
    update_index = text.index("az containerapp job update", acrpull_index)
    assert "--mi-system-assigned \\" in text[create_index:acrpull_index]
    assert "--image \"$AZURE_BOOTSTRAP_IMAGE\"" in text[create_index:acrpull_index]
    assert update_index > acrpull_index


def test_deploy_grants_acrpull_against_acr_resource_group() -> None:
    text = (AZURE_DIR / "deploy.sh").read_text(encoding="utf-8")
    assert '--resource-group "$AZURE_ACR_RESOURCE_GROUP"' in text


def test_deploy_uses_existing_image_without_building() -> None:
    text = (AZURE_DIR / "deploy.sh").read_text(encoding="utf-8")
    assert "az acr build" not in text
    assert '[[ -n "$IMAGE_OVERRIDE" ]] || fail "--image IMAGE is required."' in text


def test_instance_destroy_never_deletes_shared_resource_group() -> None:
    text = (AZURE_DIR / "destroy.sh").read_text(encoding="utf-8")
    assert "az group delete" not in text
    assert "az containerapp job delete" in text
    assert "az containerapp env storage remove" in text
    assert "az storage share-rm delete" in text


def test_provision_can_use_existing_shared_acr() -> None:
    text = (AZURE_DIR / "provision.sh").read_text(encoding="utf-8")
    assert 'if [[ "$AZURE_CREATE_ACR" == "true" ]]' in text
    assert "Using existing Azure Container Registry" in text
    assert '--resource-group "$AZURE_ACR_RESOURCE_GROUP"' in text


def test_provision_can_verify_shared_infrastructure_without_recreating_it() -> None:
    text = (AZURE_DIR / "provision.sh").read_text(encoding="utf-8")
    assert 'if [[ "$AZURE_PROVISION_SHARED_INFRASTRUCTURE" == "true" ]]' in text
    assert "Verifying shared Azure infrastructure" in text
    assert 'sync_args=(--profile "$PROFILE")' in text


def test_init_env_generates_stable_unique_names(tmp_path: Path) -> None:
    env_file = tmp_path / "env.local"

    result = run_command(
        [
            str(AZURE_DIR / "init-env.sh"),
            "--profile",
            "test",
            "--output",
            str(env_file),
            "--print",
        ]
    )

    assert result.returncode == 0, result.stderr
    assert env_file.exists()
    text = env_file.read_text(encoding="utf-8")
    assert 'EMAILCLEANER_INSTANCE_NAME="test"' in text
    suffix_match = re.search(r'AZURE_UNIQUE_SUFFIX="([0-9]{8})"', text)
    assert suffix_match is not None
    suffix = suffix_match.group(1)
    assert f'AZURE_ACR_NAME="acremailcleaner{suffix}"' in text
    assert f'AZURE_STORAGE_ACCOUNT="stemcleaner{suffix}"' in text
    assert 'AZURE_ACR_RESOURCE_GROUP="rg-emailcleaner-prod"' in text
    assert 'AZURE_CREATE_ACR="true"' in text
    assert "EMAIL_CLEANER_GMAIL_EMAIL_MAIN" in text
    assert "EMAIL_CLEANER_GMAIL_APP_PASSWORD_MAIN" in text
    assert "EMAIL_CLEANER_YAHOO_EMAIL_MAIN" in text
    assert "EMAIL_CLEANER_YAHOO_APP_PASSWORD_MAIN" in text
    assert len(f"acremailcleaner{suffix}") <= 50
    assert len(f"stemcleaner{suffix}") <= 24


def test_profile_name_must_match_profile_env(tmp_path: Path) -> None:
    env_file = tmp_path / "azure.env"
    init_result = run_command(
        [
            str(AZURE_DIR / "init-env.sh"),
            "--profile",
            "alpha",
            "--output",
            str(env_file),
        ]
    )
    assert init_result.returncode == 0, init_result.stderr

    result = run_command(
        [
            str(AZURE_DIR / "deploy.sh"),
            "--profile",
            "beta",
            "--env-file",
            str(env_file),
            "--image",
            "example.azurecr.io/emailcleaner:test",
            "--render-yaml-only",
        ]
    )

    assert result.returncode != 0
    assert "does not match EMAILCLEANER_INSTANCE_NAME='alpha'" in result.stderr


def test_init_shared_acr_env_generates_generic_names(tmp_path: Path) -> None:
    env_file = tmp_path / "shared-acr.local"

    result = run_command(
        [
            str(AZURE_DIR / "init-shared-acr-env.sh"),
            "--output",
            str(env_file),
            "--print",
        ]
    )

    assert result.returncode == 0, result.stderr
    assert env_file.exists()
    text = env_file.read_text(encoding="utf-8")
    assert 'AZURE_ACR_RESOURCE_GROUP="rg-shared-container-registry-prod"' in text
    assert re.search(r'AZURE_ACR_NAME="acrautomationjobs[0-9]{8}"', text)
    assert "mtharris" not in text.lower()
    assert "mark" not in text.lower()
    assert "harris" not in text.lower()


def test_deploy_render_yaml_only_is_safe_and_manual_by_default(tmp_path: Path) -> None:
    env_file = tmp_path / "env.local"
    init_result = run_command(
        [
            str(AZURE_DIR / "init-env.sh"),
            "--profile",
            "test",
            "--output",
            str(env_file),
        ]
    )
    assert init_result.returncode == 0, init_result.stderr

    env = os.environ.copy()
    env["OPENAI_API_KEY"] = "SHOULD_NOT_APPEAR_IN_SAFE_YAML"
    result = run_command(
        [
            str(AZURE_DIR / "deploy.sh"),
            "--profile",
            "test",
            "--render-yaml-only",
            "--env-file",
            str(env_file),
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
    assert '      - "--dry-run"' not in yaml
    assert "SHOULD_NOT_APPEAR_IN_SAFE_YAML" not in yaml
    assert re.search(r'acremailcleaner[0-9]{8}\.azurecr\.io', yaml)


def test_deploy_render_yaml_only_allows_schedule_override(tmp_path: Path) -> None:
    env_file = tmp_path / "env.local"
    init_result = run_command(
        [
            str(AZURE_DIR / "init-env.sh"),
            "--profile",
            "test",
            "--output",
            str(env_file),
        ]
    )
    assert init_result.returncode == 0, init_result.stderr

    result = run_command(
        [
            str(AZURE_DIR / "deploy.sh"),
            "--profile",
            "test",
            "--render-yaml-only",
            "--env-file",
            str(env_file),
            "--trigger",
            "schedule",
            "--image",
            "example.azurecr.io/emailcleaner:test",
        ],
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
            "--profile",
            "test",
            "--output",
            str(env_file),
        ]
    )
    assert init_result.returncode == 0, init_result.stderr

    text = env_file.read_text(encoding="utf-8")
    env_file.write_text(text.replace('AZURE_MAX_RUNTIME_SECONDS="3600"', 'AZURE_MAX_RUNTIME_SECONDS="900"'), encoding="utf-8")
    result = run_command(
        [
            str(AZURE_DIR / "deploy.sh"),
            "--profile",
            "test",
            "--render-yaml-only",
            "--env-file",
            str(env_file),
            "--image",
            "example.azurecr.io/emailcleaner:test",
        ],
    )

    assert result.returncode == 0, result.stderr
    yaml = result.stdout
    assert '      - "--max-runtime-seconds"' in yaml
    assert '      - "900"' in yaml


def test_deploy_render_yaml_supports_profile_dry_run(tmp_path: Path) -> None:
    env_file = tmp_path / "azure.env"
    init_result = run_command(
        [
            str(AZURE_DIR / "init-env.sh"),
            "--profile",
            "test",
            "--output",
            str(env_file),
        ]
    )
    assert init_result.returncode == 0, init_result.stderr

    text = env_file.read_text(encoding="utf-8")
    env_file.write_text(
        text.replace('AZURE_DRY_RUN="false"', 'AZURE_DRY_RUN="true"'),
        encoding="utf-8",
    )
    result = run_command(
        [
            str(AZURE_DIR / "deploy.sh"),
            "--profile",
            "test",
            "--env-file",
            str(env_file),
            "--image",
            "example.azurecr.io/emailcleaner:test",
            "--render-yaml-only",
        ]
    )

    assert result.returncode == 0, result.stderr
    assert '      - "--dry-run"' in result.stdout


def test_secret_loader_uses_local_secret_file_and_accounts_json(tmp_path: Path) -> None:
    env_file = tmp_path / "env.local"
    secrets_file = tmp_path / "secrets.local"
    accounts_file = tmp_path / "accounts.json"

    init_result = run_command(
        [
            str(AZURE_DIR / "init-env.sh"),
            "--profile",
            "test",
            "--output",
            str(env_file),
        ]
    )
    assert init_result.returncode == 0, init_result.stderr
    with env_file.open("a", encoding="utf-8") as file:
        file.write(f'export AZURE_SECRETS_FILE="{secrets_file}"\n')
        file.write(f'export AZURE_ACCOUNTS_SECRET_FILE="{accounts_file}"\n')
    secrets_file.write_text('export OPENAI_API_KEY="local-openai-key"\n', encoding="utf-8")
    accounts_file.write_text(
        """
{
  "gmail_accounts": {
    "MAIN": {
      "email": "gmail@example.test",
      "app_password": "gmail-app-password"
    }
  },
  "yahoo_accounts": {
    "MAIN": {
      "email": "yahoo@example.test",
      "app_password": "yahoo-app-password"
    }
  }
}
""".strip()
        + "\n",
        encoding="utf-8",
    )

    env = {
        key: value
        for key, value in os.environ.items()
        if key not in {
            "OPENAI_API_KEY",
            "EMAIL_CLEANER_GMAIL_EMAIL_MAIN",
            "EMAIL_CLEANER_GMAIL_APP_PASSWORD_MAIN",
            "EMAIL_CLEANER_YAHOO_EMAIL_MAIN",
            "EMAIL_CLEANER_YAHOO_APP_PASSWORD_MAIN",
        }
    }
    result = run_command(
        [
            "bash",
            "-lc",
            textwrap.dedent(
                """
                set -euo pipefail
                source scripts/azure/common.sh
                load_azure_env "$1"
                load_azure_secret_sources
                validate_secret_env_values
                printf 'loaded\\n'
                """
            ).strip(),
            "test-shell",
            str(env_file),
        ],
        env=env,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout == "loaded\n"
    combined_output = result.stdout + result.stderr
    assert "local-openai-key" not in combined_output
    assert "gmail-app-password" not in combined_output
    assert "yahoo-app-password" not in combined_output


def test_secret_loader_ignores_shell_values(tmp_path: Path) -> None:
    env_file = tmp_path / "env.local"
    secrets_file = tmp_path / "secrets.local"
    accounts_file = tmp_path / "accounts.json"

    init_result = run_command(
        [
            str(AZURE_DIR / "init-env.sh"),
            "--profile",
            "test",
            "--output",
            str(env_file),
        ]
    )
    assert init_result.returncode == 0, init_result.stderr
    with env_file.open("a", encoding="utf-8") as file:
        file.write(f'export AZURE_SECRETS_FILE="{secrets_file}"\n')
        file.write(f'export AZURE_ACCOUNTS_SECRET_FILE="{accounts_file}"\n')
    secrets_file.write_text('export OPENAI_API_KEY="from-secrets-file"\n', encoding="utf-8")
    accounts_file.write_text(
        """
{
  "gmail_accounts": {
    "MAIN": {
      "email": "from-accounts-json@example.test",
      "app_password": "gmail-app-password"
    }
  },
  "yahoo_accounts": {
    "MAIN": {
      "email": "yahoo@example.test",
      "app_password": "yahoo-app-password"
    }
  }
}
""".strip()
        + "\n",
        encoding="utf-8",
    )

    env = os.environ.copy()
    env["OPENAI_API_KEY"] = "from-shell"
    env["EMAIL_CLEANER_GMAIL_EMAIL_MAIN"] = "from-shell@example.test"

    result = run_command(
        [
            "bash",
            "-lc",
            textwrap.dedent(
                """
                set -euo pipefail
                source scripts/azure/common.sh
                load_azure_env "$1"
                load_azure_secret_sources
                validate_secret_env_values
                if [[ "$OPENAI_API_KEY" == "from-secrets-file" && "$EMAIL_CLEANER_GMAIL_EMAIL_MAIN" == "from-accounts-json@example.test" ]]; then
                  printf 'local-files-used\\n'
                else
                  printf 'shell-values-used\\n'
                  exit 1
                fi
                """
            ).strip(),
            "test-shell",
            str(env_file),
        ],
        env=env,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout == "local-files-used\n"

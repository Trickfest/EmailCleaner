#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys


def fail(message: str) -> None:
    print(f"Error: {message}", file=sys.stderr)
    raise SystemExit(1)


def env(name: str, default: str = "") -> str:
    value = os.environ.get(name, default)
    return value.strip() if isinstance(value, str) else default


def yaml_value(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    return json.dumps(str(value))


def env_to_secret_name(env_name: str) -> str:
    return env_name.lower().replace("_", "-")


def required_env(name: str) -> str:
    value = env(name)
    if not value:
        fail(f"Missing required environment variable: {name}")
    if "\n" in value or "\r" in value:
        fail(f"{name} must be a single-line value.")
    return value


def positive_int(name: str, default: str) -> int:
    raw = env(name, default)
    try:
        value = int(raw)
    except ValueError:
        fail(f"{name} must be an integer.")
    if value < 1:
        fail(f"{name} must be >= 1.")
    return value


def nonnegative_int(name: str, default: str) -> int:
    raw = env(name, default)
    try:
        value = int(raw)
    except ValueError:
        fail(f"{name} must be an integer.")
    if value < 0:
        fail(f"{name} must be >= 0.")
    return value


def boolean_env(name: str, default: str = "false") -> bool:
    raw = env(name, default).lower()
    if raw not in {"true", "false"}:
        fail(f"{name} must be true or false.")
    return raw == "true"


def emit_key(lines: list[str], indent: int, key: str, value: object) -> None:
    lines.append(f"{' ' * indent}{key}: {yaml_value(value)}")


def emit_list(lines: list[str], indent: int, key: str, values: list[object]) -> None:
    lines.append(f"{' ' * indent}{key}:")
    for value in values:
        lines.append(f"{' ' * (indent + 2)}- {yaml_value(value)}")


def render_yaml(*, image: str, include_secret_values: bool) -> str:
    resource_group = required_env("AZURE_RESOURCE_GROUP")
    location = required_env("AZURE_LOCATION")
    environment = required_env("AZURE_CONTAINERAPPS_ENV")
    job_name = required_env("AZURE_JOB_NAME")
    acr_name = required_env("AZURE_ACR_NAME")
    container_name = env("AZURE_CONTAINER_NAME", "emailcleaner")
    storage_mount_name = required_env("AZURE_STORAGE_MOUNT_NAME")
    trigger_type = env("AZURE_JOB_TRIGGER_TYPE", "Manual")
    cron = env("AZURE_SCAN_CRON", "*/15 * * * *")
    secret_env_vars = env("AZURE_SECRET_ENV_VARS").split()
    max_runtime_seconds = nonnegative_int("AZURE_MAX_RUNTIME_SECONDS", "3600")
    dry_run = boolean_env("AZURE_DRY_RUN")

    if trigger_type not in {"Manual", "Schedule"}:
        fail("AZURE_JOB_TRIGGER_TYPE must be Manual or Schedule.")

    subscription_id = required_env("AZURE_SUBSCRIPTION_ID")
    environment_id = (
        f"/subscriptions/{subscription_id}/resourceGroups/{resource_group}"
        f"/providers/Microsoft.App/managedEnvironments/{environment}"
    )

    lines: list[str] = []
    emit_key(lines, 0, "name", job_name)
    emit_key(lines, 0, "location", location)
    emit_key(lines, 0, "type", "Microsoft.App/jobs")
    lines.append("identity:")
    emit_key(lines, 2, "type", "SystemAssigned")
    lines.append("properties:")
    emit_key(lines, 2, "environmentId", environment_id)
    lines.append("  configuration:")
    emit_key(lines, 4, "triggerType", trigger_type)
    emit_key(lines, 4, "replicaTimeout", positive_int("AZURE_REPLICA_TIMEOUT", "3600"))
    emit_key(
        lines,
        4,
        "replicaRetryLimit",
        nonnegative_int("AZURE_REPLICA_RETRY_LIMIT", "0"),
    )
    if trigger_type == "Schedule":
        lines.append("    scheduleTriggerConfig:")
        emit_key(lines, 6, "cronExpression", cron)
        emit_key(lines, 6, "parallelism", positive_int("AZURE_PARALLELISM", "1"))
        emit_key(
            lines,
            6,
            "replicaCompletionCount",
            positive_int("AZURE_REPLICA_COMPLETION_COUNT", "1"),
        )
    else:
        lines.append("    manualTriggerConfig:")
        emit_key(lines, 6, "parallelism", positive_int("AZURE_PARALLELISM", "1"))
        emit_key(
            lines,
            6,
            "replicaCompletionCount",
            positive_int("AZURE_REPLICA_COMPLETION_COUNT", "1"),
        )
    lines.append("    registries:")
    emit_key(lines, 6, "- server", f"{acr_name}.azurecr.io")
    emit_key(lines, 8, "identity", "system")
    if include_secret_values:
        lines.append("    secrets:")
        for env_name in secret_env_vars:
            lines.append(f"      - name: {yaml_value(env_to_secret_name(env_name))}")
            emit_key(lines, 8, "value", required_env(env_name))
    lines.append("  template:")
    lines.append("    containers:")
    lines.append(f"      - name: {yaml_value(container_name)}")
    emit_key(lines, 8, "image", image)
    args = [
        "--max-runtime-seconds",
        str(max_runtime_seconds),
        "--rules-file",
        "/data/rules.json",
        "--accounts-file",
        "/data/accounts.json",
        "--config-file",
        "/data/config.json",
        "--state-file",
        "/data/.email_cleaner_state.json",
    ]
    if dry_run:
        args.append("--dry-run")
    emit_list(lines, 8, "args", args)
    lines.append("        resources:")
    emit_key(lines, 10, "cpu", env("AZURE_CPU", "0.25"))
    emit_key(lines, 10, "memory", env("AZURE_MEMORY", "0.5Gi"))
    if secret_env_vars:
        lines.append("        env:")
        for env_name in secret_env_vars:
            lines.append(f"          - name: {yaml_value(env_name)}")
            emit_key(lines, 12, "secretRef", env_to_secret_name(env_name))
    lines.append("        volumeMounts:")
    emit_key(lines, 10, "- volumeName", storage_mount_name)
    emit_key(lines, 12, "mountPath", "/data")
    lines.append("    volumes:")
    emit_key(lines, 6, "- name", storage_mount_name)
    emit_key(lines, 8, "storageType", "AzureFile")
    emit_key(lines, 8, "storageName", storage_mount_name)
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Render EmailCleaner Container Apps job YAML.")
    parser.add_argument("--image", required=True, help="Container image reference to deploy.")
    parser.add_argument(
        "--include-secret-values",
        action="store_true",
        help="Include secret values from the current environment. Use only for temporary deploy files.",
    )
    args = parser.parse_args()
    print(render_yaml(image=args.image, include_secret_values=args.include_secret_values), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

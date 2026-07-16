# Private Instance Profiles

EmailCleaner keeps each operator's runtime configuration in a separate private
profile directory:

```text
instances/
  example.local/
    azure.env
    secrets.env
    config.json
    accounts.json
    rules.json
```

Directories matching `instances/*.local/` are ignored by Git. Never commit
their contents. Keep the standard filenames inside each profile so the selected
files can be mounted in Azure as `/data/config.json`, `/data/rules.json`, and
`/data/.email_cleaner_state.json` without instance-specific application logic.

| File | Purpose |
| --- | --- |
| `azure.env` | Durable nonsecret deployment settings: instance identity, Azure resource names, trigger, schedule, dry-run mode, and required secret variable names. |
| `secrets.env` | Optional integration secrets such as `OPENAI_API_KEY`. |
| `accounts.json` | Email addresses and app passwords used to create job-scoped Container Apps secrets. |
| `config.json` | Folder selection, IMAP timeout, daily summary, and optional OpenAI behavior. |
| `rules.json` | Per-instance deterministic keep/delete rules and quarantine cleanup. |

Treat `azure.env` as the source of truth for future deployments. A command-line
`deploy.sh --trigger ...` override affects that deployment only; it does not
rewrite the profile. Persist production trigger and schedule changes in
`AZURE_JOB_TRIGGER_TYPE` and `AZURE_SCAN_CRON` before deploying.

Every instance-targeting Azure command requires `--profile NAME`. The selected
`instances/NAME.local/azure.env` must also contain:

```bash
export EMAILCLEANER_INSTANCE_NAME="NAME"
```

Use a lowercase profile name that starts with a letter or number and contains
only lowercase letters, numbers, and hyphens.

The duplicated name is intentional. It prevents a command from labeling one
profile while loading another profile's Azure targets.

`accounts.json` remains local in the recommended deployment. `deploy.sh` reads
its values and stores them as secrets on the selected Container Apps job;
`sync-runtime-files.sh` does not upload it unless `--include-accounts` is
explicitly supplied.

Repo-root `config.json`, `rules.json`, and `accounts.json` remain supported for
standalone commands and the single-instance macOS LaunchDaemon installer. They
are not an implicit default profile and are not used by profile-aware Azure
commands. See [`README.md`](../README.md) for an explicit profile-based local
dry run and [`AZURE_DEPLOYMENT.md`](../AZURE_DEPLOYMENT.md) for deployment
steps.

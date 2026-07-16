# EmailCleaner Azure Deployment Guide

EmailCleaner runs in Azure as a scheduled Azure Container Apps job. Each job
starts, scans its configured mailboxes, writes state to Azure Files, sends any
configured summary, and exits.

The repository supports multiple private EmailCleaner instances that share one
application image and, when appropriate, shared Azure infrastructure. Every
instance-targeting command requires an explicit `--profile NAME`; there is no
default profile.

## Deployment Shape

The recommended multi-instance arrangement is:

| Resource | Shared or isolated |
| --- | --- |
| Azure Container Registry and image | Shared |
| Resource group | Shared when one operator owns all instances |
| Container Apps environment | Shared |
| Log Analytics workspace | Shared |
| Storage account | Shared |
| Container Apps job | One per profile |
| Azure Files share and mount registration | One per profile |
| Container Apps job identity and secrets | One per profile |
| Runtime configuration and state | One per profile |

Container Apps jobs have no public endpoint. Account credentials are stored as
job-scoped Container Apps secrets, not in the image or the Azure Files share.

## Private Local Profiles

Private runtime files live under ignored profile directories:

```text
instances/
  primary.local/
    azure.env
    secrets.env
    config.json
    accounts.json
    rules.json

  secondary.local/
    azure.env
    secrets.env
    config.json
    accounts.json
    rules.json
```

Keep standard filenames inside each directory. The profile name selects the
source files and Azure targets; the container continues to read
`/data/config.json`, `/data/rules.json`, and `/data/.email_cleaner_state.json`.

| Profile file | Purpose |
| --- | --- |
| `azure.env` | Durable deployment settings: identity, Azure resources, trigger, cron schedule, dry-run mode, and required secret names. |
| `secrets.env` | Optional integration secrets such as `OPENAI_API_KEY`. |
| `accounts.json` | Email addresses and app passwords used to populate job-scoped secrets. |
| `config.json` | Folder selection, IMAP timeout, summary email, and optional OpenAI behavior. |
| `rules.json` | Per-instance deterministic rules and quarantine cleanup. |

Repo-root runtime JSON files remain supported for standalone commands and the
single-instance macOS installer. Profile-aware Azure scripts never silently
fall back to those files.

Directories matching `instances/*.local/` are ignored by Git. Confirm private
files are not tracked before every push:

```bash
git ls-files -- ':(glob)instances/*.local/**' config.json rules.json accounts.json \
  .email_cleaner_state.json
```

The command should print nothing.

## Profile Safety

Every private `azure.env` contains an instance identity:

```bash
export EMAILCLEANER_INSTANCE_NAME="primary"
```

Profile names must start with a lowercase letter or number and then use only
lowercase letters, numbers, and hyphens. The same name appears in the directory,
the `--profile` argument, and `EMAILCLEANER_INSTANCE_NAME`.

The command-line profile and embedded identity must match. For example:

```bash
scripts/azure/status.sh --profile primary
```

fails before Azure access if `primary.local/azure.env` identifies a different
profile. Do not add an environment-variable or shell-session default for the
profile name.

All instance commands support `--env-file PATH` for controlled testing or
migration, but `--profile NAME` is still required and must match the file.

## Security And Secret Flow

Keep these files private:

- `instances/NAME.local/config.json`
- `instances/NAME.local/rules.json`
- `instances/NAME.local/accounts.json`
- `instances/NAME.local/secrets.env`
- `instances/NAME.local/azure.env`
- `.email_cleaner_state.json`

The deployment flow is:

1. `azure.env` selects nonsecret Azure resource names and required secret
   environment-variable names.
2. `secrets.env` supplies optional integration secrets such as
   `OPENAI_API_KEY`.
3. `accounts.json` supplies email addresses and app passwords.
4. `deploy.sh` clears matching ambient shell values and reads the selected
   profile files.
5. Secret values are included only in a restrictive temporary deployment YAML
   and then stored as secrets on that profile's Container Apps job.
6. The temporary file is removed when deployment exits.

By default, `accounts.json` is not uploaded to Azure Files. Its absence from
the share is expected. Avoid `sync-runtime-files.sh --include-accounts` unless
there is a deliberate reason to store credentials on Azure Files.

## Prerequisites

Install and authenticate the Azure CLI, then verify the intended subscription:

```bash
az login
az account show --output table
```

If the active subscription is not the deployment target, select it explicitly:

```bash
az account set --subscription '<subscription-id-or-name>'
az account show --output table
```

You also need:

- Python 3.10 or newer for local validation and deployment rendering.
- Git for source control and default image tags.
- Gmail/Yahoo app passwords for every configured account.
- An OpenAI API key only for profiles with OpenAI fallback enabled.

Local Docker is not required because image builds run in Azure Container
Registry.

## Optional Shared Registry Bootstrap

If no reusable ACR exists yet, create one independently of any EmailCleaner
profile:

```bash
scripts/azure/init-shared-acr-env.sh
scripts/azure/provision-shared-acr.sh
scripts/azure/status-shared-acr.sh
```

This creates `scripts/azure/shared-acr.local`, a shared registry resource group,
and one ACR. The local file is ignored by Git. Profiles that use this registry
set its `AZURE_ACR_NAME` and `AZURE_ACR_RESOURCE_GROUP`, then set
`AZURE_CREATE_ACR="false"`.

## Create A Profile Template

Generate a first-instance template with stable, globally unique ACR and storage
names:

```bash
scripts/azure/init-env.sh --profile primary
```

This writes `instances/primary.local/azure.env`. Add private runtime files:

```bash
cp config.example.json instances/primary.local/config.json
cp rules.example.json instances/primary.local/rules.json
cp accounts.example.json instances/primary.local/accounts.json
cp scripts/azure/secrets.example instances/primary.local/secrets.env
chmod 600 instances/primary.local/*
```

Edit the files with real local values. Keep documentation and tracked examples
fictional.

`init-env.sh` creates a first-instance infrastructure template with a `Manual`
trigger and `AZURE_DRY_RUN="false"`. For new-account onboarding, change dry-run
to `true` before the first deployment. Do not assume a generated profile is safe
to run until its resource names, accounts, rules, summary recipients, and secret
list have been reviewed.

## Configure `azure.env`

The generated file is the durable source of truth for deployments:

| Setting group | Variables |
| --- | --- |
| Profile identity | `EMAILCLEANER_INSTANCE_NAME` must exactly match `--profile`. |
| Region and image | `AZURE_LOCATION`, `AZURE_IMAGE_NAME`, and `AZURE_BOOTSTRAP_IMAGE`. The bootstrap image is used only while allocating a new job identity. |
| Shared resources | `AZURE_RESOURCE_GROUP`, `AZURE_CONTAINERAPPS_ENV`, `AZURE_LOG_WORKSPACE`, `AZURE_STORAGE_ACCOUNT`, `AZURE_ACR_NAME`, `AZURE_ACR_RESOURCE_GROUP`, and `AZURE_ACR_SKU`. |
| Per-instance resources | `AZURE_JOB_NAME`, `AZURE_FILE_SHARE`, and `AZURE_STORAGE_MOUNT_NAME` must be unique within the shared deployment. |
| Trigger and safety | `AZURE_JOB_TRIGGER_TYPE`, `AZURE_SCAN_CRON`, and `AZURE_DRY_RUN`. |
| Runtime sizing | `AZURE_MAX_RUNTIME_SECONDS`, `AZURE_REPLICA_TIMEOUT`, `AZURE_CPU`, `AZURE_MEMORY`, `AZURE_REPLICA_RETRY_LIMIT`, `AZURE_PARALLELISM`, and `AZURE_REPLICA_COMPLETION_COUNT`. |
| Infrastructure mode | `AZURE_PROVISION_SHARED_INFRASTRUCTURE` and `AZURE_CREATE_ACR` control create-versus-verify behavior. |
| Generated uniqueness | `AZURE_UNIQUE_SUFFIX` seeds generated ACR and storage names. Explicit `AZURE_ACR_NAME` and `AZURE_STORAGE_ACCOUNT` values are authoritative. |
| Secret contract | `AZURE_SECRET_ENV_VARS` lists every value that `deploy.sh` must install as a job secret. |
| Optional local paths | `AZURE_SECRETS_FILE`, `AZURE_CONFIG_FILE`, `AZURE_RULES_FILE`, `AZURE_ACCOUNTS_FILE`, and `AZURE_ACCOUNTS_SECRET_FILE` override profile-local defaults. Leave them unset for the standard layout. |

When OpenAI is disabled, remove `OPENAI_API_KEY` from
`AZURE_SECRET_ENV_VARS`; otherwise deployment still treats it as required. The
Gmail/Yahoo variable suffixes must match account keys in `accounts.json`.

## Add An Instance To Existing Infrastructure

To share an existing resource group, Container Apps environment, Log Analytics
workspace, storage account, and ACR, create another profile and set its shared
resource names to the existing values. Give the new instance unique values for:

- `EMAILCLEANER_INSTANCE_NAME`
- `AZURE_JOB_NAME`
- `AZURE_FILE_SHARE`
- `AZURE_STORAGE_MOUNT_NAME`

Set:

```bash
export AZURE_PROVISION_SHARED_INFRASTRUCTURE="false"
export AZURE_CREATE_ACR="false"
```

`provision.sh` will verify the shared resources rather than recreate them. It
will create only the selected profile's Azure Files share and Container Apps
environment storage registration.

In practice, copy the shared-resource values from one healthy profile, retain
the newly generated `EMAILCLEANER_INSTANCE_NAME`, replace the three
per-instance resource names, and review `AZURE_SECRET_ENV_VARS`. An unused
generated `AZURE_UNIQUE_SUFFIX` may remain in the file; explicit ACR and storage
names take precedence.

Use a five-field UTC cron expression. The trigger ignores the cron while it is
`Manual`:

| Expression | Meaning |
| --- | --- |
| `*/15 * * * *` | Every 15 minutes at `:00`, `:15`, `:30`, and `:45`. |
| `7,22,37,52 * * * *` | Every 15 minutes at `:07`, `:22`, `:37`, and `:52`. |

Keep a new instance manual and dry-run during validation:

```bash
export AZURE_JOB_TRIGGER_TYPE="Manual"
export AZURE_DRY_RUN="true"
```

## Runtime Configuration

`config.json` controls account folder selection, IMAP timeout, summary email,
and optional OpenAI fallback. Account scan keys must match the account keys in
`accounts.json`, for example `gmail:MAIN` and `yahoo:MAIN`.

`daily_summary.summary_time` is interpreted in the process's local timezone.
The current Azure container runs in UTC, so configure the summary time as UTC.

`rules.json` controls deterministic keep/delete behavior and quarantine cleanup.
For a new user, review all inherited sender/domain entries and keep quarantine
cleanup disabled until initial results have been inspected.

`accounts.json` supports `gmail_accounts` and `yahoo_accounts`. Each account key
must be alphanumeric or underscore-compatible so it can map to environment
variables such as:

```text
EMAIL_CLEANER_GMAIL_EMAIL_MAIN
EMAIL_CLEANER_GMAIL_APP_PASSWORD_MAIN
```

List every required secret variable in `AZURE_SECRET_ENV_VARS` in the selected
profile's `azure.env`.

## Provision One Profile

Provisioning mutates Azure. It registers required providers, creates or verifies
shared resources according to the profile, creates the instance file share and
mount registration, uploads runtime files, and initializes state if missing:

```bash
scripts/azure/provision.sh --profile primary
```

Use `--skip-runtime-upload` when only infrastructure should be created.

## Build The Shared Image

Build code once using any profile that points to the shared ACR:

```bash
scripts/azure/build-image.sh \
  --profile primary \
  --tag "$(git rev-parse --short HEAD)"
```

The script prints the full image reference. Keep that exact immutable reference
for every profile deployment. Building an image does not update any job.

Check `git status --short` before choosing a tag. Use a Git SHA only when the
worktree is clean and the build therefore corresponds to that commit. For an
uncommitted validation build, use a unique descriptive or timestamped tag so an
existing immutable-looking SHA tag is not overwritten with different code.

## Deploy One Profile

Deploy an existing image reference:

```bash
scripts/azure/deploy.sh \
  --profile primary \
  --image '<registry>.azurecr.io/emailcleaner:<tag>' \
  --no-run
```

`deploy.sh` creates a bootstrap job if needed, grants its system identity
`AcrPull` on the configured registry, applies job-scoped secrets, and updates
the final job definition. It never builds an image.

Render safe YAML without Azure mutation or secret values:

```bash
scripts/azure/deploy.sh \
  --profile primary \
  --image '<registry>.azurecr.io/emailcleaner:<tag>' \
  --render-yaml-only
```

## Safe Initial Activation

For a new profile:

1. Keep `AZURE_JOB_TRIGGER_TYPE="Manual"`.
2. Keep `AZURE_DRY_RUN="true"`.
3. Provision runtime storage.
4. Deploy the same image used by an existing healthy instance.
5. Start one execution and inspect status and logs.
6. Confirm both account credentials work and dry-run reports no state writes or
   mailbox mutations.
7. Set `AZURE_DRY_RUN="false"`, deploy again, and perform one supervised live
   run.
8. Review the summary and Quarantine folders.
9. Set `AZURE_JOB_TRIGGER_TYPE="Schedule"` and deploy again.

An empty state file causes the first live run to process the current unread
backlog. Later runs process only newly discovered unread messages.

## Operate A Profile

A healthy profile has the intended trigger, UTC cron, immutable image, and
runtime files; recent executions finish `Succeeded`; logs show every configured
account and no persistent authentication, timeout, Quarantine, or OpenAI errors.
A successful run that processes zero new messages is still healthy.

Start one execution:

```bash
scripts/azure/run-once.sh --profile primary
```

Check live configuration, recent executions, and runtime-file presence:

```bash
scripts/azure/status.sh --profile primary --executions 10
```

Read the latest completed logs:

```bash
scripts/azure/logs.sh --profile primary --tail 200
```

Read or follow a specific execution:

```bash
scripts/azure/logs.sh \
  --profile primary \
  --execution '<execution-name>' \
  --tail 300

scripts/azure/logs.sh \
  --profile primary \
  --execution '<execution-name>' \
  --follow
```

## Change A Schedule Or Trigger

Edit the selected profile's durable `azure.env` values:

```bash
export AZURE_SCAN_CRON="7,22,37,52 * * * *"
export AZURE_JOB_TRIGGER_TYPE="Schedule"
```

Then redeploy the image already used by that job and verify the effective Azure
configuration:

```bash
scripts/azure/deploy.sh \
  --profile primary \
  --image '<registry>.azurecr.io/emailcleaner:<tag>' \
  --no-run
scripts/azure/status.sh --profile primary --executions 5
```

`deploy.sh --trigger manual|schedule` is useful for a one-off override, but it
does not rewrite `azure.env`. Persist intended production behavior in the
profile so a future deployment cannot restore an obsolete trigger or schedule.

## Refresh Rules Or Config

Runtime-only changes do not require an image build or job deployment:

```bash
scripts/azure/sync-runtime-files.sh --profile primary
scripts/azure/run-once.sh --profile primary
scripts/azure/logs.sh --profile primary --tail 200
```

The sync preserves an existing `.email_cleaner_state.json` and creates `{}` only
when the state file is missing.

## Refresh Credentials

Edit the selected profile's `accounts.json` or `secrets.env`, then redeploy the
same image so job-scoped secrets are updated:

```bash
scripts/azure/deploy.sh \
  --profile primary \
  --image '<registry>.azurecr.io/emailcleaner:<tag>' \
  --no-run
```

## Deploy A Code Change To Multiple Profiles

Build one image, then explicitly deploy that exact reference to each intended
profile:

```bash
scripts/azure/build-image.sh --profile primary --tag '<git-sha>'
scripts/azure/deploy.sh --profile primary --image '<full-image>' --no-run
scripts/azure/deploy.sh --profile secondary --image '<full-image>' --no-run
scripts/azure/status.sh --profile primary --executions 5
scripts/azure/status.sh --profile secondary --executions 5
```

There is intentionally no implicit deploy-all default.

## Delete One Instance

Instance teardown requires both an explicit profile and exact profile/job
confirmation:

```bash
scripts/azure/destroy.sh \
  --profile secondary \
  --confirm 'secondary:caj-emailcleaner-secondary-prod'
```

This deletes only the selected job, environment storage registration, and Azure
Files share. It never deletes the resource group, shared environment, storage
account, Log Analytics workspace, or ACR.

## Verification Checklist

- `python3 -m py_compile email_cleaner.py` succeeds.
- `python3 -m pytest -q` succeeds in the development environment.
- Every instance command fails when `--profile` is omitted.
- Rendered YAML contains the selected job, storage mount, trigger, and dry-run
  setting without secret values.
- `status.sh` shows the intended immutable image and schedule.
- `config.json`, `rules.json`, and `.email_cleaner_state.json` exist in the
  selected Azure Files share.
- `accounts.json: false` is expected in the recommended deployment.
- Recent executions succeed and logs show the intended account keys.
- `git ls-files -- ':(glob)instances/*.local/**'` prints nothing.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| A command selects the wrong instance | Always pass `--profile NAME`; confirm `EMAILCLEANER_INSTANCE_NAME` in that profile's `azure.env`. |
| A future deploy restores an old trigger or cron | Update `AZURE_JOB_TRIGGER_TYPE` and `AZURE_SCAN_CRON` in `azure.env`; do not rely only on `--trigger`. |
| `status.sh` reports `accounts.json: false` | Expected in the recommended secret-backed deployment. |
| Deployment reports a missing secret | Reconcile `AZURE_SECRET_ENV_VARS` with `accounts.json` and optional values in `secrets.env`. |
| Config or rule edits are absent in Azure | Run `sync-runtime-files.sh --profile NAME`; code deployment does not upload runtime JSON. |
| Gmail or Yahoo authentication fails | Correct the selected profile's `accounts.json`, then redeploy the same image to refresh job secrets. |
| OpenAI fails but deterministic scanning continues | Confirm `OPENAI_API_KEY` and model settings; OpenAI failures keep the message safely. |
| The first live run processes existing unread mail | Expected with empty state; later runs process only newly discovered unread messages. |
| A completed execution has no logs yet | Log Analytics ingestion can lag by a few minutes; retry `logs.sh` while using `status.sh` for execution state. |
| A run remains active longer than Gmail-only runs | Yahoo IMAP can respond more slowly; follow the execution logs and check the configured runtime cap before treating it as stuck. |
| Azure and a Mac both scan the same accounts | Disable or uninstall the macOS LaunchDaemon; use one production scheduler per account set. |

## Cost Notes

Sharing the ACR avoids a second registry charge. A second job can still add
Container Apps execution usage, Azure Files storage and transactions, Log
Analytics ingestion, and optional OpenAI API usage. Treat incremental cost as
small and measurable rather than guaranteed zero.

## Script Reference

| Script | Purpose |
| --- | --- |
| `scripts/azure/init-env.sh` | Creates a private profile `azure.env`. |
| `scripts/azure/init-shared-acr-env.sh` | Creates ignored settings for an optional shared ACR. |
| `scripts/azure/provision-shared-acr.sh` | Creates or verifies the optional shared ACR. |
| `scripts/azure/status-shared-acr.sh` | Shows shared ACR status and repositories. |
| `scripts/azure/provision.sh` | Creates or verifies infrastructure and provisions one profile's share/mount. |
| `scripts/azure/build-image.sh` | Builds one shared image without deploying it. |
| `scripts/azure/deploy.sh` | Deploys an existing image and selected profile secrets. |
| `scripts/azure/sync-runtime-files.sh` | Uploads selected profile config/rules and initializes state if absent. |
| `scripts/azure/run-once.sh` | Starts one selected profile execution. |
| `scripts/azure/status.sh` | Shows selected profile Azure status. |
| `scripts/azure/logs.sh` | Reads selected profile logs. |
| `scripts/azure/destroy.sh` | Deletes one selected instance, never shared infrastructure. |
| `scripts/azure/render-job-yaml.py` | Internal safe job-definition renderer. |

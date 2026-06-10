# EmailCleaner Azure Deployment Guide

This guide explains how to deploy EmailCleaner to Azure using the scripts that
are already included in this repository. It is written as an operator guide:
start here when setting up a new Azure deployment, refreshing the deployed code,
checking status, reading logs, or tearing the deployment down.

EmailCleaner runs in Azure as an Azure Container Apps job. It is not a web app
and it is not an always-on VM. The job starts on a schedule, scans configured
mailboxes, writes state to Azure Files, sends any configured summary email, then
exits.

## Deployed Shape

The app deployment scripts create and manage these Azure resources:

| Resource | Purpose |
| --- | --- |
| App resource group | Holds EmailCleaner runtime resources so they can be managed or deleted together. A shared ACR can live in a separate resource group. |
| Azure Container Apps environment | Runtime environment for the scheduled job. |
| Azure Container Apps job | Runs EmailCleaner manually or on a cron schedule. |
| Azure Container Registry | Private registry for the EmailCleaner container image. This can be app-specific or a shared registry in a separate resource group. |
| Storage account and Azure Files share | Stores runtime files mounted at `/data`. |
| Log Analytics workspace | Stores completed job logs for later review. |

The default deployment settings match the current production-style setup:

| Setting | Default |
| --- | --- |
| Azure region | `centralus` |
| Resource group | `rg-emailcleaner-prod` |
| Container Apps environment | `cae-emailcleaner-prod` |
| Container Apps job | `caj-emailcleaner-prod` |
| Log Analytics workspace | `law-emailcleaner-prod` |
| Azure Files share | `emailcleaner-data` |
| Schedule | `*/15 * * * *` |
| Runtime cap | `3600` seconds |
| CPU / memory | `0.25` CPU / `0.5Gi` |
| ACR resource group | `rg-emailcleaner-prod` by default, or a shared registry resource group |
| ACR SKU | `Basic` |

Azure requires the ACR name and storage account name to be globally unique.
`scripts/azure/init-env.sh` generates stable names with an eight-digit random
suffix and stores them in `scripts/azure/env.local`.

Local Docker is not required. `scripts/azure/deploy.sh` uses `az acr build`, so
the image is built in Azure Container Registry.

## Optional Shared Container Registry

If you operate more than one Azure Container Apps job, it is usually cleaner and
cheaper to use one shared Azure Container Registry. EmailCleaner owns the helper
scripts for this shared registry because they are generic and can be reused by
other automation projects.

The shared registry scripts create only:

| Resource | Purpose |
| --- | --- |
| Shared registry resource group | Holds the reusable Azure Container Registry. |
| Azure Container Registry | Stores container images for EmailCleaner and other automation jobs. |

They do not create EmailCleaner runtime storage, jobs, secrets, or logs.

Create local shared registry settings:

```bash
scripts/azure/init-shared-acr-env.sh
```

Provision the shared registry:

```bash
scripts/azure/provision-shared-acr.sh
```

Check the shared registry:

```bash
scripts/azure/status-shared-acr.sh
```

The default shared registry names are intentionally generic:

| Setting | Default |
| --- | --- |
| Shared ACR resource group | `rg-shared-container-registry-prod` |
| Shared ACR name prefix | `acrautomationjobs` plus an eight-digit suffix |
| Shared ACR SKU | `Basic` |

To make EmailCleaner use that shared registry, set these values in
`scripts/azure/env.local` after creating `scripts/azure/shared-acr.local`:

```bash
export AZURE_ACR_RESOURCE_GROUP="<shared-acr-resource-group>"
export AZURE_ACR_NAME="<shared-acr-name>"
export AZURE_CREATE_ACR="false"
```

With `AZURE_CREATE_ACR=false`, `scripts/azure/provision.sh` verifies the shared
registry exists instead of creating an app-specific registry. `deploy.sh` still
builds the EmailCleaner image into the configured registry and grants the
Container Apps job identity `AcrPull` on that registry.

## Important Security Rules

Do not commit local runtime files or secret files to GitHub:

- `config.json`
- `rules.json`
- `accounts.json`
- `.email_cleaner_state.json`
- `scripts/azure/env.local`
- `scripts/azure/shared-acr.local`
- `scripts/azure/secrets.local`

The repository `.gitignore` already excludes these files. Keep it that way.
Before pushing, this command should print nothing:

```bash
git ls-files config.json rules.json accounts.json .email_cleaner_state.json scripts/azure/env.local scripts/azure/shared-acr.local scripts/azure/secrets.local
```

Use this command if you want to confirm the ignore rule that applies:

```bash
git check-ignore -v config.json rules.json accounts.json scripts/azure/env.local scripts/azure/shared-acr.local scripts/azure/secrets.local
```

### Secret Flow

Secrets are intentionally defined in local files, not in the interactive shell.
This is the deployment flow:

1. Nonsecret Azure settings live in `scripts/azure/env.local`.
2. The OpenAI API key normally lives in `scripts/azure/secrets.local`.
3. Email account addresses and app passwords normally live in the ignored
   repo-root `accounts.json`.
4. `scripts/azure/deploy.sh` loads those files through `scripts/azure/common.sh`.
   The loader clears the named secret variables first, so ambient shell
   environment values are not used as the source of truth.
5. `AZURE_SECRET_ENV_VARS` in `env.local` lists exactly which values must be
   copied into Azure Container Apps secrets.
6. `deploy.sh` validates that every required secret value is present.
7. `render-job-yaml.py` renders a temporary job YAML file with the secret
   values included only for the `az containerapp job update` call.
8. The temporary YAML file is created with restrictive permissions and removed
   when the deployment command exits.
9. Azure stores the values as Container Apps secrets.
10. The job container receives them as environment variables through
    `secretRef`.
11. EmailCleaner loads account credentials from those environment variables at
    runtime.

By default, `accounts.json` is not uploaded to Azure Files. That is intentional.
The deployed job receives account credentials through Container Apps secrets,
not through a credentials file mounted at `/data/accounts.json`.

`scripts/azure/sync-runtime-files.sh --include-accounts` exists, but only use it
if you explicitly choose to store account credentials in Azure Files. The
recommended deployment does not use that option.

### What Is Secure In Azure

The secrets are not public once deployed to Azure:

- They are not committed to GitHub.
- They are not copied into the container image.
- They are not uploaded to Azure Files in the recommended flow.
- They are stored as Azure Container Apps secrets.
- They are exposed only to the EmailCleaner container as environment variables.
- Access is controlled by Azure authentication and RBAC.

This does not mean no one can ever access them. Azure users with sufficiently
high privileges over the resource group or Container Apps job can administer,
replace, or potentially expose runtime configuration. Treat Azure RBAC as the
security boundary and keep access to the resource group limited.

## Prerequisites

Install and authenticate the Azure CLI:

```bash
az login
az account show --output table
```

Confirm you are on the Azure subscription where the resources should be created.
If needed, select the subscription:

```bash
az account set --subscription "<subscription-id-or-name>"
```

You also need:

- Python 3 available as `python3`.
- Git.
- A valid OpenAI API key if OpenAI fallback or summaries are enabled.
- Gmail/Yahoo app passwords for the accounts you will scan.
- Local `config.json`, `rules.json`, and `accounts.json` files configured for
  the deployment.

If EmailCleaner is still installed as a macOS LaunchDaemon, do not run the Mac
daemon and the Azure schedule at the same time unless you intentionally want two
independent scanners. See `INSTALLATION.md` for LaunchDaemon operations.

## First-Time Setup

Run all commands from the repository root.

### 1. Check Out The Code To Deploy

For a reproducible deployment, deploy from a clean checkout:

```bash
git status -sb
git rev-parse --short HEAD
```

`az acr build` sends the current local build context to Azure. If you have
uncommitted changes to tracked files that are included in the Docker build
context, they can be deployed even if the image tag is the current commit SHA.
Use a clean tree when you want the image to match a committed revision.

### 2. Create `scripts/azure/env.local`

Create the local Azure settings file:

```bash
scripts/azure/init-env.sh
```

This creates `scripts/azure/env.local` with:

- Central US as the region.
- The default resource group, job, storage, and logging names.
- An eight-digit suffix for globally unique ACR and storage account names.
- `AZURE_ACR_RESOURCE_GROUP` and `AZURE_CREATE_ACR` for either app-specific or
  shared registry use.
- The 15-minute schedule.
- The list of required secret variables.

Do not rerun this with `--force` for an existing deployment unless you intend to
change the generated ACR and storage account names. Those names identify the
deployed resources.

`env.local` contains deployment settings and generated resource names. It should
not contain passwords or API keys, but it is still local machine configuration
and should stay untracked.

If you are using a shared registry, create it with the shared registry scripts
before provisioning EmailCleaner, then edit `scripts/azure/env.local` so
`AZURE_ACR_RESOURCE_GROUP` and `AZURE_ACR_NAME` point at that registry and
`AZURE_CREATE_ACR` is `false`.

### 3. Create `scripts/azure/secrets.local`

Create the local secret file:

```bash
cp scripts/azure/secrets.example scripts/azure/secrets.local
chmod 600 scripts/azure/secrets.local
```

Edit `scripts/azure/secrets.local` and set:

```bash
export OPENAI_API_KEY="..."
```

Keep this file untracked.

### 4. Prepare Runtime Config Files

Create or update the ignored runtime files in the repository root:

```bash
cp config.example.json config.json
cp rules.example.json rules.json
cp accounts.example.json accounts.json
chmod 600 config.json rules.json accounts.json
```

Then edit them for the real deployment.

`config.json` controls app behavior such as OpenAI fallback, summary email
settings, summary sender, summary recipients, and summary interval.

`rules.json` controls deterministic filtering rules.

`accounts.json` defines the Gmail/Yahoo accounts and app passwords. The Azure
deployment reads this file locally during `deploy.sh` and copies those account
credentials into Container Apps secrets. The file is not uploaded by default.

If you add accounts beyond the default Gmail account key `1` and Yahoo account
key `1`, update `AZURE_SECRET_ENV_VARS` in `scripts/azure/env.local` so the new
account variables are required and deployed. The naming pattern is:

```bash
EMAIL_CLEANER_GMAIL_EMAIL_<KEY>
EMAIL_CLEANER_GMAIL_APP_PASSWORD_<KEY>
EMAIL_CLEANER_YAHOO_EMAIL_<KEY>
EMAIL_CLEANER_YAHOO_APP_PASSWORD_<KEY>
```

For example, account key `2` would need:

```bash
EMAIL_CLEANER_GMAIL_EMAIL_2
EMAIL_CLEANER_GMAIL_APP_PASSWORD_2
```

### 5. Confirm Local Secret Files Are Ignored

Before provisioning, confirm the local files are not tracked:

```bash
git ls-files config.json rules.json accounts.json .email_cleaner_state.json scripts/azure/env.local scripts/azure/shared-acr.local scripts/azure/secrets.local
```

Expected result: no output.

## Provision Azure Resources

Create the resource group and supporting Azure resources:

```bash
scripts/azure/provision.sh
```

This script:

1. Loads `scripts/azure/env.local`.
2. Registers required Azure providers.
3. Creates the resource group.
4. Creates the Log Analytics workspace.
5. Creates the Container Apps environment.
6. Creates an app-specific private Azure Container Registry with admin access
   disabled, or verifies the configured shared registry exists when
   `AZURE_CREATE_ACR=false`.
7. Creates the storage account and Azure Files share.
8. Registers the Azure Files share as a Container Apps environment storage
   mount.
9. Uploads `config.json` and `rules.json`.
10. Creates `/data/.email_cleaner_state.json` if it does not already exist.

The provision script does not apply secrets. Secrets are applied by
`scripts/azure/deploy.sh`.

If you want to create infrastructure without uploading runtime config yet, use:

```bash
scripts/azure/provision.sh --skip-runtime-upload
```

## Deploy And Validate Manually

Deploy the image as a manual job first. This builds the image in ACR, applies
Container Apps secrets, updates the job definition, and starts one validation
execution.

```bash
scripts/azure/deploy.sh --trigger manual --tag "$(git rev-parse --short HEAD)"
```

What this script does:

1. Loads nonsecret settings from `scripts/azure/env.local`.
2. Loads secrets from `scripts/azure/secrets.local` and `accounts.json`.
3. Builds the container image in Azure Container Registry.
4. Creates a bootstrap Container Apps job if the job does not already exist.
5. Enables a system-assigned managed identity for the job.
6. Grants that identity `AcrPull` on the configured ACR, even when that ACR is
   in a separate shared resource group.
7. Renders a temporary job YAML file with secret values.
8. Applies the real EmailCleaner job definition.
9. Starts one manual execution unless `--no-run` is provided.

The image tag is usually the current Git short SHA. The current deployed image
can be seen with `scripts/azure/status.sh`.

## Monitor The Validation Run

Check the job, recent executions, and runtime files:

```bash
scripts/azure/status.sh --executions 5
```

Read logs for the latest execution:

```bash
scripts/azure/logs.sh --tail 100
```

Read logs for a specific execution:

```bash
scripts/azure/logs.sh --execution "<execution-name>" --tail 300
```

Stream a running execution:

```bash
scripts/azure/logs.sh --execution "<execution-name>" --follow
```

Completed execution logs are read from Log Analytics. Azure can take a little
time to ingest logs after a job completes. If the execution status is
`Succeeded` but the log command returns no lines immediately after completion,
wait a few minutes and run the log command again.

Yahoo Mail can also be slow to respond. A long Yahoo phase is not automatically
a failure. Check the execution status and logs before interrupting or
redeploying.

## Enable The 15-Minute Schedule

After the manual validation run succeeds, switch the job to the configured
schedule:

```bash
scripts/azure/deploy.sh --trigger schedule --tag "$(git rev-parse --short HEAD)" --no-run
```

The default schedule is:

```text
*/15 * * * *
```

Verify that Azure shows the live job as scheduled:

```bash
scripts/azure/status.sh --executions 5
```

The `Container Apps Job` section should show:

- `Trigger` = `Schedule`
- `Cron` = `*/15 * * * *`
- the expected image tag
- `ReplicaTimeout` = `3600`
- `ReplicaRetryLimit` = `0`

## Day-To-Day Operations

Use this section after the deployment is live. The normal operating loop is:

1. Confirm recent scheduled executions are succeeding.
2. Review logs when a run fails, takes unusually long, or reports errors.
3. Confirm runtime files still exist in Azure Files.
4. Refresh config, rules, secrets, or code only when something changed.

### What Healthy Looks Like

A healthy deployment should have these properties:

| Area | Healthy signal |
| --- | --- |
| Schedule | `scripts/azure/status.sh` shows `Trigger` as `Schedule` and `Cron` as the expected expression. |
| Executions | Recent executions are mostly or entirely `Succeeded`. |
| Timing | New scheduled executions appear around each cron boundary, such as every 15 minutes for `*/15 * * * *`. |
| Logs | Logs show each configured account scanned and end without unhandled tracebacks. |
| OpenAI | Logs or summary email show OpenAI failures as `0` during normal operation. |
| Quarantine | Logs show `Quarantine failures (will retry next run): 0`. |
| Runtime files | `config.json`, `rules.json`, and `.email_cleaner_state.json` are present in Azure Files. |
| Accounts file | `accounts.json: false` is expected in Azure Files for the recommended secret-backed deployment. |

An individual run can find zero messages and still be healthy. The key is that
the job starts, completes successfully, scans the configured accounts, and does
not report persistent errors.

### Routine Health Check

For a quick health check:

```bash
scripts/azure/status.sh --executions 10
scripts/azure/logs.sh --tail 200
```

Review the status output first. The `Container Apps Job` section should show
the live Azure job configuration, including schedule, image, timeout, and retry
limit. The `Recent Executions` section should show recent scheduled runs and
their final status.

Then review the logs for the latest execution. For normal operation, look for:

- `Beginning scan for ... configured account(s)`
- one account section per configured account
- `OpenAI fallback: enabled` when OpenAI is expected to run
- `Quarantine failures (will retry next run): 0`
- no Python traceback
- no repeated IMAP authentication or timeout errors

The job can still be healthy if it reports `Found 0 new unread message(s)`.
That only means there was nothing new to process for that account in that run.

### Check Status

```bash
scripts/azure/status.sh --executions 10
```

This shows:

- Current Azure account.
- Local resource configuration.
- Resource group existence.
- Live Container Apps job trigger, cron, image, timeout, and retry limit.
- Recent executions.
- Whether expected runtime files exist in Azure Files.

`accounts.json: false` in the Azure Files section is expected for the
recommended deployment because account credentials are deployed as Container
Apps secrets.

If a scheduled run is missing, wait until the next cron boundary and run the
status command again. For the default 15-minute schedule, a new execution should
appear around `:00`, `:15`, `:30`, and `:45` UTC.

### Read Logs

Latest execution:

```bash
scripts/azure/logs.sh --tail 300
```

Specific execution:

```bash
scripts/azure/logs.sh --execution "<execution-name>" --tail 300
```

Follow a live execution:

```bash
scripts/azure/logs.sh --execution "<execution-name>" --follow
```

The same logs are visible in the Azure portal through the Log Analytics
workspace. The script queries the `ContainerAppConsoleLogs_CL` table.

If the latest execution just finished, Log Analytics may not have ingested the
logs yet. In that case, wait a few minutes and rerun `logs.sh`. The execution
status from `status.sh` is still useful while logs are catching up.

### Investigate A Failed Or Suspicious Run

Start with the latest executions:

```bash
scripts/azure/status.sh --executions 10
```

Then inspect the failing execution:

```bash
scripts/azure/logs.sh --execution "<execution-name>" --tail 300
```

Use this checklist:

| Signal | Likely meaning | Next action |
| --- | --- | --- |
| Execution status is `Failed` | The container exited nonzero or hit a platform failure. | Read logs for traceback, auth failure, missing file, or timeout. |
| Execution status is still running | The scanner may be waiting on Gmail/Yahoo/OpenAI. | Use `logs.sh --follow`; be patient with Yahoo. |
| `OPENAI_API_KEY` or OpenAI auth errors | Secret was not deployed or is invalid. | Fix `scripts/azure/secrets.local`, then run `deploy.sh`. |
| Gmail/Yahoo authentication error | Account email or app password is wrong or expired. | Fix `accounts.json`, then run `deploy.sh`. |
| Missing `/data/config.json` or `/data/rules.json` | Runtime files were not uploaded or storage mount failed. | Run `scripts/azure/sync-runtime-files.sh`, then run once. |
| Quarantine failures are nonzero | The app could not move one or more messages. | Review folder permissions and IMAP errors in the same log. |
| OpenAI failures are nonzero | OpenAI calls failed but messages were kept safely. | Check API key, network/API status, and error summary. |

OpenAI and IMAP failures are designed to fail safe. A failed OpenAI call should
not cause EmailCleaner to quarantine a message solely because of that error.

### Start One Manual Run

Use this when you want an immediate scan without waiting for the next 15-minute
schedule boundary:

```bash
scripts/azure/run-once.sh
```

### Refresh Deployed Code

Deploy from the checkout you want Azure to run:

```bash
git status -sb
python3 -m py_compile email_cleaner.py
python3 -m pytest -q
python3 email_cleaner.py --help
scripts/azure/deploy.sh --trigger schedule --tag "$(git rev-parse --short HEAD)" --no-run
scripts/azure/run-once.sh
scripts/azure/status.sh --executions 5
```

Use a clean checkout when you want the deployed image to correspond exactly to a
commit.

### Refresh Config Or Rules

Changing `config.json` or `rules.json` does not require rebuilding the image.
Upload the runtime files:

```bash
scripts/azure/sync-runtime-files.sh
```

Then run once and check logs:

```bash
scripts/azure/run-once.sh
scripts/azure/status.sh --executions 5
scripts/azure/logs.sh --tail 200
```

`sync-runtime-files.sh` preserves the existing state file if it already exists.
It creates an empty state file only when one is missing.

### Refresh Secrets Or Account Credentials

Edit one or both local files:

- `scripts/azure/secrets.local`
- `accounts.json`

Then redeploy the job definition so Container Apps secrets are refreshed:

```bash
scripts/azure/deploy.sh --trigger schedule --tag "$(git rev-parse --short HEAD)" --no-run
scripts/azure/run-once.sh
scripts/azure/logs.sh --tail 200
```

The deploy script will rebuild the image as part of this flow. That is expected.

### Change The Schedule

Edit `AZURE_SCAN_CRON` in `scripts/azure/env.local`, then redeploy the scheduled
job:

```bash
scripts/azure/deploy.sh --trigger schedule --tag "$(git rev-parse --short HEAD)" --no-run
scripts/azure/status.sh --executions 5
```

## Azure Portal Checks

The scripts are the preferred operational interface, but the Azure portal is
useful for confirming the same state:

1. Open the Azure portal.
2. Go to **Resource groups**.
3. Open the EmailCleaner resource group, for example `rg-emailcleaner-prod`.
4. Use the resource group overview as the inventory of app runtime resources.
5. If `AZURE_CREATE_ACR=false`, also open the shared registry resource group to
   inspect the Azure Container Registry.

From there, these are the most useful places to check:

| Portal location | What to check |
| --- | --- |
| Container Apps job, for example `caj-emailcleaner-prod` | Confirm the job exists, check execution history, trigger type, schedule, image, and failures. |
| Container Apps job executions | Open recent executions and compare status, start time, end time, and duration. |
| Log Analytics workspace, for example `law-emailcleaner-prod` | Query historical container logs after completed executions. |
| Storage account, for example `stemcleaner...` | Inspect the `emailcleaner-data` file share and confirm runtime files exist. |
| Azure Container Registry, app-specific or shared | Confirm the deployed image tag exists. If the registry is shared, check it in the shared registry resource group. |
| Access control (IAM) on the resource group | Confirm only intended Azure users can administer the deployment. |

For historical logs in the portal:

1. Open the Log Analytics workspace.
2. Open **Logs**.
3. Query `ContainerAppConsoleLogs_CL`.
4. Filter by the Container Apps job name and, when needed, by execution name.

Example KQL shape:

```kusto
ContainerAppConsoleLogs_CL
| where ContainerJobName_s == "caj-emailcleaner-prod"
| order by time_t desc
| take 100
```

For a specific execution, use the execution name as a prefix for
`ContainerGroupName_s`:

```kusto
ContainerAppConsoleLogs_CL
| where ContainerJobName_s == "caj-emailcleaner-prod"
| where ContainerGroupName_s startswith "<execution-name>-"
| order by time_t asc
| project time_t, Log_s
```

The portal is also a good place to check Azure RBAC. Secrets are not public, but
users with enough Azure privileges over the resource group or Container Apps job
can administer runtime configuration. Keep access narrow.

The deployment has no public web endpoint. EmailCleaner runs as a scheduled
container job and exits.

### Daily And Weekly Care

Daily or whenever you want assurance:

```bash
scripts/azure/status.sh --executions 10
scripts/azure/logs.sh --tail 200
```

Check that scheduled runs are succeeding and that the latest log has no error
summary.

After changing rules, config, account credentials, or the OpenAI key, always run
one manual execution and inspect logs:

```bash
scripts/azure/run-once.sh
scripts/azure/status.sh --executions 5
scripts/azure/logs.sh --tail 300
```

Weekly or after larger changes:

- Confirm the deployed image tag is the tag you expect.
- Confirm `config.json`, `rules.json`, and `.email_cleaner_state.json` exist in
  Azure Files.
- Confirm `accounts.json` is not present in Azure Files unless you intentionally
  uploaded it.
- Review Azure resource group access in IAM if other users have subscription
  access.
- Check Azure cost for the resource group, especially Log Analytics. If using an
  app-specific ACR, also check ACR cost. If using a shared ACR, check the shared
  registry resource group.

## Cost Control And Teardown

The resource group contains billable resources, including Log Analytics,
Storage, Container Apps job executions, and possibly ACR. ACR Basic has an idle
cost even when the scanner is not running. Use the shared ACR pattern when you
operate multiple automation jobs and want only one registry bill.

To delete the EmailCleaner app deployment:

```bash
scripts/azure/destroy.sh --confirm rg-emailcleaner-prod
```

This permanently deletes the app resource group, including logs workspace,
storage account, Azure Files runtime files, scanner state, and any app-specific
ACR in that same resource group. It does not delete a shared ACR in a separate
resource group. Deletion can take a long time.

After deletion, confirm Azure no longer has the resource group:

```bash
az group show --name rg-emailcleaner-prod --output none
```

Expected result after deletion: Azure reports `ResourceGroupNotFound`.

## Troubleshooting

| Symptom | What to check |
| --- | --- |
| `status.sh` shows no executions | The job may not have been deployed yet, or the schedule boundary may not have occurred. Run `scripts/azure/run-once.sh`. |
| Execution succeeded but `logs.sh` is empty | Log Analytics ingestion may be delayed. Wait a few minutes and retry. |
| `accounts.json: false` in status output | Expected in the recommended deployment. Accounts are supplied through Container Apps secrets. |
| Deploy fails with missing secret variables | Check `AZURE_SECRET_ENV_VARS` in `env.local`, `secrets.local`, and `accounts.json`. |
| Gmail or Yahoo login fails | Confirm the account email and app password in `accounts.json`, then rerun `deploy.sh` to refresh Container Apps secrets. |
| OpenAI calls fail | Confirm `OPENAI_API_KEY` in `scripts/azure/secrets.local`, then rerun `deploy.sh`. |
| First run after rebuilding scans many messages | Expected if `.email_cleaner_state.json` was deleted or recreated empty. Later runs should settle. |
| Yahoo appears slow | Be patient. Yahoo Mail can take much longer than Gmail to return IMAP responses. |
| Schedule is wrong | Check the live `Container Apps Job` section from `scripts/azure/status.sh`, not just local files. |
| Local Mac and Azure both process messages | Stop or uninstall the macOS LaunchDaemon if Azure is now the production runtime. |

## Script Reference

| Script | Purpose |
| --- | --- |
| `scripts/azure/init-env.sh` | Creates ignored local Azure settings with generated unique names. |
| `scripts/azure/init-shared-acr-env.sh` | Creates ignored local settings for a reusable shared Azure Container Registry. |
| `scripts/azure/provision-shared-acr.sh` | Creates the shared registry resource group and Azure Container Registry. |
| `scripts/azure/status-shared-acr.sh` | Shows shared registry status and repositories. |
| `scripts/azure/provision.sh` | Creates Azure infrastructure and uploads initial runtime files. |
| `scripts/azure/deploy.sh` | Builds the image, applies secrets, updates the job, and optionally starts a run. |
| `scripts/azure/sync-runtime-files.sh` | Uploads `config.json` and `rules.json`, and creates state if missing. |
| `scripts/azure/run-once.sh` | Starts one manual job execution. |
| `scripts/azure/status.sh` | Shows account, resource, job, execution, and runtime-file status. |
| `scripts/azure/logs.sh` | Reads completed logs from Log Analytics or follows live logs. |
| `scripts/azure/destroy.sh` | Deletes the app deployment resource group. It does not delete a shared ACR in a separate resource group. |
| `scripts/azure/render-job-yaml.py` | Internal helper used by `deploy.sh` to render Container Apps job YAML. |

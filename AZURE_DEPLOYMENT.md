# EmailCleaner Azure Deployment Design

This document describes a practical Azure deployment for EmailCleaner that keeps
cost low, keeps every Azure resource in one resource group, and provides
repeatable scripts for code refresh, status checks, logs, and manual runs.

The recommended target is an Azure Container Apps scheduled job. EmailCleaner is
already a finite command-line scan process, so it maps better to a scheduled job
than to an always-on web app, VM, or App Service instance.

## Goals

- Run EmailCleaner without depending on this Mac being powered on.
- Keep Azure cost as low as practical.
- Put all Azure resources in a single resource group.
- Preserve the current app behavior: scan on a schedule, write state, quarantine
  messages, and send daily summary emails.
- Keep personal account credentials and API keys out of git and out of container
  images.
- Provide scripts to:
  - provision Azure resources
  - refresh deployed code
  - update runtime configuration intentionally
  - start a manual scan
  - check status and recent logs
  - tear down the deployment

## Recommended Architecture

Use these Azure resources in one resource group:

| Resource | Purpose |
| --- | --- |
| Resource group | Owns all EmailCleaner Azure resources. |
| Azure Container Registry, Basic SKU | Stores the EmailCleaner container image. |
| Azure Container Apps environment | Hosts the scheduled Container Apps job. |
| Azure Container Apps scheduled job | Runs EmailCleaner on a cron schedule and exits. |
| Managed identity | Lets the job pull from ACR without storing registry passwords. |
| Storage account | Owns the Azure Files share used for runtime files and state. |
| Azure Files share | Stores `config.json`, `rules.json`, optional `accounts.json`, and `.email_cleaner_state.json`. |
| Log Analytics workspace | Stores Container Apps job stdout/stderr for status and troubleshooting. |

These are the customer-managed resources. Azure Container Apps may also create
platform-managed infrastructure behind the environment; the deployment scripts
should keep all named EmailCleaner resources in the EmailCleaner resource group.

Recommended names, with a short unique suffix where Azure requires global
uniqueness:

```text
RESOURCE_GROUP=rg-emailcleaner-prod
LOCATION=centralus
CONTAINERAPPS_ENV=cae-emailcleaner-prod
JOB_NAME=caj-emailcleaner-prod
ACR_NAME=acremailcleaner<suffix>
STORAGE_ACCOUNT=stemcleaner<suffix>
FILE_SHARE=emailcleaner-data
LOG_WORKSPACE=law-emailcleaner-prod
```

Azure's display name for this region is `Central US`; the Azure CLI and scripts
should use the programmatic location name `centralus`. Microsoft lists region
display names and programmatic names in the
[Azure regions list](https://learn.microsoft.com/azure/availability-zones/az-region).

## Why Container Apps Jobs

Container Apps jobs run finite tasks and can be triggered manually, on a
schedule, or by events. Scheduled jobs use standard five-field cron expressions
evaluated in UTC. They also support execution history, manual starts, retries,
timeouts, and single-replica execution settings. Microsoft documents this as a
first-class Container Apps job scenario:

- [Jobs in Azure Container Apps](https://learn.microsoft.com/en-us/azure/container-apps/jobs)
- [Create a job in Azure Container Apps](https://learn.microsoft.com/en-us/azure/container-apps/jobs-get-started-cli)

Cost is also a good fit. Container Apps jobs are billed only while executions
are running, and no job usage charge applies when no execution is running. The
current pricing page also documents monthly free grants for Container Apps
consumption compute. Pricing changes over time, so use the Azure pricing page
for the final estimate:

- [Azure Container Apps pricing](https://azure.microsoft.com/en-us/pricing/details/container-apps/)

## Cost Notes

This design is intended to be cheaper than an always-on VM or always-on App
Service plan because compute scales to zero between scans. Expected recurring
cost drivers are:

1. Container Apps job execution time.
2. Log Analytics ingestion and retention.
3. Azure Files storage and transactions.
4. Azure Container Registry Basic SKU.

Cost controls:

- Keep the Container Apps job at `0.25` vCPU and `0.5Gi` memory unless runtime
  data proves it needs more.
- Keep `--max-runtime-seconds` bounded, for example `3600`.
- Use `--parallelism 1` and `--replica-completion-count 1`.
- Keep logs compact. EmailCleaner already avoids printing full message bodies.
- Use the Basic ACR SKU unless image retention or production requirements force
  a higher tier.
- Retain only the logs needed for operational review.

Reference pricing pages:

- [Azure Container Apps pricing](https://azure.microsoft.com/en-us/pricing/details/container-apps/)
- [Azure Container Registry pricing](https://azure.microsoft.com/en-us/pricing/details/container-registry/)
- [Azure Files pricing](https://azure.microsoft.com/en-us/pricing/details/storage/files/)
- [Azure Monitor pricing](https://azure.microsoft.com/en-us/pricing/details/monitor/)

## Runtime Files And Secrets

The container image should contain code only. Runtime data should live outside
the image.

Use the Azure Files share mounted at `/data` for:

- `/data/config.json`
- `/data/rules.json`
- `/data/accounts.json`, optional
- `/data/.email_cleaner_state.json`

Use Container Apps secrets for:

- `OPENAI_API_KEY`
- `EMAIL_CLEANER_GMAIL_EMAIL_<KEY>`
- `EMAIL_CLEANER_GMAIL_APP_PASSWORD_<KEY>`
- `EMAIL_CLEANER_YAHOO_EMAIL_<KEY>`
- `EMAIL_CLEANER_YAHOO_APP_PASSWORD_<KEY>`

The app already supports account credentials from environment variables and
also treats `accounts.json` as optional. For Azure, the preferred path is
secret-backed environment variables for credentials, with `config.json`,
`rules.json`, and state stored in Azure Files. If maintaining accounts in JSON
is operationally easier, store `/data/accounts.json` in the file share, but
protect the share because that file contains credentials.

Container Apps supports secrets and secret-backed environment variables:

- [Manage secrets in Azure Container Apps](https://learn.microsoft.com/en-us/azure/container-apps/manage-secrets)
- [Manage environment variables in Azure Container Apps](https://learn.microsoft.com/en-us/azure/container-apps/environment-variables)

Container Apps supports Azure Files volume mounts. Microsoft recommends using a
YAML definition when configuring Azure Files mounts through Azure CLI:

- [Use storage mounts in Azure Container Apps](https://learn.microsoft.com/en-us/azure/container-apps/storage-mounts)

## Schedule

The closest Azure match to the current LaunchDaemon schedule is:

```text
*/15 * * * *
```

Container Apps scheduled job cron expressions are evaluated in UTC. That is fine
for a 15-minute scan interval. The app's `daily_summary.summary_time` remains a
local-time application setting inside `config.json`; EmailCleaner sends the
summary on the first run at or after the configured local time.

## Container Runtime Contract

The container should run one command and exit:

```bash
python -u /app/email_cleaner.py \
  --max-runtime-seconds 3600 \
  --rules-file /data/rules.json \
  --accounts-file /data/accounts.json \
  --config-file /data/config.json \
  --state-file /data/.email_cleaner_state.json
```

If `/data/accounts.json` does not exist, EmailCleaner still loads accounts from
environment variables.

The container image definition should be minimal:

```dockerfile
FROM python:3.13-slim

WORKDIR /app
COPY email_cleaner.py email_cleaner_watchdog.py ./

ENTRYPOINT ["python", "-u", "/app/email_cleaner.py"]
CMD ["--max-runtime-seconds", "3600", "--rules-file", "/data/rules.json", "--accounts-file", "/data/accounts.json", "--config-file", "/data/config.json", "--state-file", "/data/.email_cleaner_state.json"]
```

This repo currently has no runtime third-party dependencies, so no
`requirements.txt` install is required for the container image.

Local Docker is not required for this deployment. The deployment flow should
build the image in Azure with ACR Tasks and then validate the running container
through a manual Azure Container Apps job execution.

## Deployment Scripts

Add Azure scripts under `scripts/azure/`. The scripts should be idempotent where
reasonable and should default to the production names above, while allowing
environment-variable overrides.

### `scripts/azure/env.example`

Holds nonsecret deployment defaults:

```bash
export AZURE_LOCATION="centralus"
export AZURE_RESOURCE_GROUP="rg-emailcleaner-prod"
export AZURE_CONTAINERAPPS_ENV="cae-emailcleaner-prod"
export AZURE_JOB_NAME="caj-emailcleaner-prod"
export AZURE_ACR_NAME="acremailcleaner<suffix>"
export AZURE_STORAGE_ACCOUNT="stemcleaner<suffix>"
export AZURE_FILE_SHARE="emailcleaner-data"
export AZURE_LOG_WORKSPACE="law-emailcleaner-prod"
export AZURE_IMAGE_NAME="emailcleaner"
export AZURE_SCAN_CRON="*/15 * * * *"
```

Do not put secrets in this file.

### `scripts/azure/provision.sh`

Creates or updates the base Azure resources:

1. Verify Azure CLI login and subscription.
2. Register required providers:
   - `Microsoft.App`
   - `Microsoft.OperationalInsights`
   - `Microsoft.Storage`
   - `Microsoft.ContainerRegistry`
3. Create the resource group.
4. Create the Log Analytics workspace.
5. Create the Container Apps environment.
6. Create the Basic SKU ACR.
7. Create the storage account and Azure Files share.
8. Register the Azure Files share with the Container Apps environment.
9. Configure managed identity and grant it `AcrPull` on the ACR.
10. Upload initial `/data/config.json` and `/data/rules.json`.
11. Create an empty `/data/.email_cleaner_state.json` if it does not exist.

Use `az acr build` for cloud image builds so Docker does not need to be running
locally:

- [Build a container image with ACR Tasks](https://learn.microsoft.com/en-us/azure/container-registry/container-registry-quickstart-task-cli)

### `scripts/azure/deploy.sh`

Builds the current repo and updates the job image:

1. Compute an image tag from `git rev-parse --short HEAD`.
2. Run:
   ```bash
   az acr build \
     --registry "$AZURE_ACR_NAME" \
     --image "$AZURE_IMAGE_NAME:$GIT_SHA" \
     --file Dockerfile .
   ```
3. Create or update the Container Apps job using a generated YAML file.
4. Set CPU/memory, timeout, retry, cron, volume mount, and secret-backed env
   vars.
5. Configure ACR pull through managed identity, not registry passwords.
6. Start one manual execution after deployment unless `--no-run` is passed.

The job configuration should use:

```text
trigger type: Schedule
cron expression: */15 * * * *
replica timeout: 3600
replica retry limit: 0 or 1
parallelism: 1
replica completion count: 1
cpu: 0.25
memory: 0.5Gi
```

### `scripts/azure/sync-runtime-files.sh`

Uploads local runtime files intentionally:

```text
config.json -> /data/config.json
rules.json  -> /data/rules.json
accounts.json -> /data/accounts.json, optional and only with an explicit flag
```

This script should not upload local runtime files by default during every code
deployment. Code refresh and runtime config refresh should be separate actions,
matching the current macOS installer behavior.

### `scripts/azure/run-once.sh`

Starts one manual job execution:

```bash
az containerapp job start \
  --name "$AZURE_JOB_NAME" \
  --resource-group "$AZURE_RESOURCE_GROUP"
```

### `scripts/azure/status.sh`

Shows:

1. Current Azure account and subscription.
2. Resource group existence.
3. Job configuration summary.
4. Recent job executions:
   ```bash
   az containerapp job execution list \
     --name "$AZURE_JOB_NAME" \
     --resource-group "$AZURE_RESOURCE_GROUP" \
     --output table
   ```
5. Recent job logs from Log Analytics or `az containerapp job logs show`.
6. Whether `/data/config.json`, `/data/rules.json`, and
   `/data/.email_cleaner_state.json` exist in the file share.

### `scripts/azure/logs.sh`

Queries recent logs. The first implementation can call Azure CLI job logs:

```bash
az containerapp job logs show \
  --name "$AZURE_JOB_NAME" \
  --resource-group "$AZURE_RESOURCE_GROUP"
```

For more reliable historical logs, query Log Analytics. Container Apps job logs
are written to the environment's configured logging provider; by default this is
Log Analytics in the quickstart path.

### `scripts/azure/destroy.sh`

Deletes the resource group after confirmation. It must require an explicit
confirmation argument because it deletes state and runtime files.

## Job YAML Shape

The implementation should generate YAML rather than relying only on long CLI
arguments, because Azure Files mounts are clearer and less brittle in YAML. The
exact schema should be validated against the current Azure CLI extension, but
the job needs these concepts:

```yaml
properties:
  configuration:
    triggerType: Schedule
    replicaTimeout: 3600
    replicaRetryLimit: 0
    scheduleTriggerConfig:
      cronExpression: "*/15 * * * *"
      parallelism: 1
      replicaCompletionCount: 1
  template:
    containers:
      - name: emailcleaner
        image: <acr-name>.azurecr.io/emailcleaner:<git-sha>
        resources:
          cpu: 0.25
          memory: 0.5Gi
        env:
          - name: OPENAI_API_KEY
            secretRef: openai-api-key
          - name: EMAIL_CLEANER_GMAIL_EMAIL_1
            secretRef: gmail-email-1
          - name: EMAIL_CLEANER_GMAIL_APP_PASSWORD_1
            secretRef: gmail-app-password-1
          - name: EMAIL_CLEANER_YAHOO_EMAIL_1
            secretRef: yahoo-email-1
          - name: EMAIL_CLEANER_YAHOO_APP_PASSWORD_1
            secretRef: yahoo-app-password-1
        volumeMounts:
          - volumeName: emailcleaner-data
            mountPath: /data
    volumes:
      - name: emailcleaner-data
        storageType: AzureFile
        storageName: emailcleaner-data
```

The script should create the Container Apps secrets before applying the job
definition.

## Logging And Monitoring

EmailCleaner already writes operational details to stdout/stderr:

- scan start/end
- account scan counts
- deterministic rule counts
- OpenAI evaluated/delete/failure counts
- quarantine counts
- daily summary send status
- errors

In Azure, these logs flow to the Container Apps environment log provider. The
status script should make common questions easy:

- Did the last execution succeed?
- When did it run?
- How many messages were processed?
- Were any messages quarantined?
- Were any OpenAI calls evaluated or failed?
- Is stderr empty?

The first deployment can rely on:

- job execution history
- Log Analytics queries
- the existing daily summary email

Later, add Azure Monitor alerts if needed:

- failed job execution
- no successful execution in more than one schedule interval
- stderr contains `error`
- daily summary reports errors

## State And Concurrency

EmailCleaner state is a single JSON file. The scheduled job must run as one
replica at a time:

```text
parallelism=1
replicaCompletionCount=1
```

The schedule should also keep a runtime cap shorter than the schedule interval
or operationally long enough that overlap is unlikely. If overlap becomes a real
risk, add app-level state locking before raising concurrency or shortening the
interval.

## Implementation Phases

### Phase 1: Define The Container Image

1. Add `Dockerfile`.
2. Run local Python validation:
   ```bash
   python3 -m py_compile email_cleaner.py
   python3 -m pytest -q
   python3 email_cleaner.py --help
   ```
3. Skip local image builds. The image will be built in Azure with ACR Tasks
   during `scripts/azure/deploy.sh`.

### Phase 2: Provision Azure

1. Add `scripts/azure/env.example`.
2. Add `scripts/azure/provision.sh`.
3. Create the resource group and base resources.
4. Upload initial runtime files to Azure Files.
5. Set Container Apps secrets.

### Phase 3: Deploy Scheduled Job

1. Add `scripts/azure/deploy.sh`.
2. Build and push the image in Azure with `az acr build`.
3. Apply the job YAML.
4. Start a manual execution.
5. Verify status and logs.

### Phase 4: Operations Scripts

1. Add `scripts/azure/status.sh`.
2. Add `scripts/azure/logs.sh`.
3. Add `scripts/azure/run-once.sh`.
4. Add `scripts/azure/sync-runtime-files.sh`.
5. Add `scripts/azure/destroy.sh`.

### Phase 5: Documentation And Cutover

1. Document how to set secrets without printing them.
2. Document how to deploy code without replacing runtime config.
3. Document how to update runtime config intentionally.
4. Run Azure and Mac in parallel for one or two cycles using a safe schedule or
   provider/account filters.
5. Disable the Mac LaunchDaemon after Azure is confirmed healthy.

## Cutover Plan

1. Deploy the Azure job as `Manual` trigger first, or otherwise start with a
   low-risk manual-only run.
2. Start one manual execution.
3. Confirm:
   - job execution succeeded
   - state file was written in Azure Files
   - logs show expected account counts
   - stderr has no unexpected errors
   - daily summary behavior is correct
4. Enable the schedule.
5. Watch two scheduled runs.
6. Disable the Mac LaunchDaemon:
   ```bash
   sudo launchctl disable system/com.emailcleaner.daemon
   sudo launchctl bootout system /Library/LaunchDaemons/com.emailcleaner.daemon.plist
   ```

Do not run Mac and Azure against the same mailboxes indefinitely. Both instances
would maintain separate state files and could process the same unread messages.

## Open Decisions

These should be decided before implementation:

1. Azure region.
2. Production resource group name.
3. Whether to use ACR only, or an external registry to shave off the ACR cost.
   ACR keeps the deployment fully inside the Azure resource group.
4. Whether account credentials should be Container Apps secrets only, or stored
   in `/data/accounts.json`.
5. Whether to deploy first as manual-only, then switch to scheduled.
6. Whether Azure should fully replace the Mac LaunchDaemon or run as a standby
   during a short validation window.


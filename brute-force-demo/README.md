# 🔐 Brute Force Demo — Live Audience PIN Cracking

An interactive demo where your audience tries to crack a 4-digit PIN in real time.
Every attempt is logged to a **Microsoft Sentinel** custom table (`BruteForceDemo_CL`)
via the Azure Monitor Logs Ingestion API — giving you live SOC telemetry to query during a presentation.

## Architecture

```
┌─────────────────────┐  POST /api/attempt  ┌────────────────────┐  Logs Ingestion  ┌──────────────────┐
│  Azure Static Web   │ ─────────────────→  │  Azure Function    │ ───────────────→ │  Sentinel        │
│  App (HTML/CSS/JS)  │ ←───────────────── │  App (Python v2)   │                  │  BruteForceDemo_CL│
│                     │  {result: S/F}      │  Flex Consumption  │                  └──────────────────┘
└─────────────────────┘                     └────────────────────┘
         CORS restricted to SWA hostname        Managed Identity
```

**Key design points:**

- The Function App runs on **Flex Consumption** (FC1) with a maximum of 5 instances.
- Authentication to the Logs Ingestion API uses a **system-assigned managed identity** — no secrets stored.
- **CORS** is handled at the Azure Functions platform level (configured in Bicep) — only the SWA hostname and `localhost` origins are allowed.
- The Function App also needs **Storage Blob Data Contributor** and **Storage Account Contributor** roles on its storage account for Flex Consumption deployment.

## Table Schema — `BruteForceDemo_CL`

| Column | Type | Description |
|--------|------|-------------|
| TimeGenerated | datetime | Attempt timestamp (UTC) |
| Nickname | string | Audience member's chosen name |
| Pincode | string | The 4-digit PIN guessed |
| AttemptResult | string | `"Success"` or `"Failure"` |
| SourceIP | string | Submitter's IP address |
| UserAgent | string | Browser user agent |

## Prerequisites

- Azure subscription with a deployed **Log Analytics workspace** + **Microsoft Sentinel**
- The parent `infra/main.bicep` deployed (creates DCE, DCR, and the `BruteForceDemo_CL` table)
- [Azure Functions Core Tools](https://learn.microsoft.com/azure/azure-functions/functions-run-local) v4+
- [SWA CLI](https://azure.github.io/static-web-apps-cli/) (`npm install -g @azure/static-web-apps-cli`) — for local development only
- Python 3.11+
- Node.js 18+ (for SWA CLI)

## Quick Start — Local Development

### 1. Deploy infrastructure

```bash
# From the repo root — deploy DCE + DCR + tables (including BruteForceDemo_CL)
az deployment group create \
  --resource-group <YOUR_RG> \
  --template-file infra/main.bicep \
  --parameters infra/main.bicepparam
```

Note the outputs: `dceEndpoint` and `dcrImmutableId`.

### 2. Configure the Function App locally

```bash
cd brute-force-demo/api

# Copy the example settings
cp local.settings.json.example local.settings.json

# Edit local.settings.json — fill in:
#   DCE_ENDPOINT      → from step 1
#   DCR_IMMUTABLE_ID  → from step 1
#   SECRET_PIN        → the 4-digit PIN the audience should crack (default: 1337)
```

### 3. Install Function dependencies

```bash
cd brute-force-demo/api
python -m venv .venv
source .venv/bin/activate   # or .venv\Scripts\Activate.ps1 on Windows
pip install -r requirements.txt
```

### 4. Run locally with SWA CLI

```bash
# From the brute-force-demo/ folder
cd brute-force-demo
npx swa start frontend --api-location api
```

Open http://localhost:4280 — the SWA CLI proxies `/api/*` to the Function App.

### 5. Authenticate to Azure (for Logs Ingestion)

```bash
az login
```

`DefaultAzureCredential` will pick up your Azure CLI session.

## Deploy to Azure

### 1. Deploy SWA + Function App infrastructure

Edit `brute-force-demo/infra/main.bicepparam` with your values:

| Parameter | Description |
|-----------|-------------|
| `namePrefix` | Prefix for all resource names (e.g. `sentinel-bf`) |
| `dceEndpoint` | DCE endpoint URL from parent infra deployment |
| `dcrImmutableId` | DCR immutable ID from parent infra deployment |
| `streamName` | DCR stream name — default: `Custom-BruteForceDemo_CL` |
| `secretPin` | The 4-digit PIN the audience must crack — default: `1337` |

```bash
cd brute-force-demo/infra

az deployment group create \
  --resource-group <YOUR_RG> \
  --template-file main.bicep \
  --parameters main.bicepparam
```

### 2. Grant the Function App access

The Function App uses a system-assigned managed identity. It needs two sets of roles:

**a) Monitoring Metrics Publisher** on the Data Collection Rule (for log ingestion):

```bash
# Get the principal ID from the deployment output
PRINCIPAL_ID=$(az deployment group show \
  --resource-group <YOUR_RG> \
  --name main \
  --query properties.outputs.functionAppPrincipalId.value -o tsv)

# Get the DCR resource ID (in the parent resource group)
DCR_ID=$(az monitor data-collection rule show \
  --resource-group <PARENT_RG> \
  --name <dcr-name> \
  --query id -o tsv)

# Assign the role
az role assignment create \
  --assignee-object-id $PRINCIPAL_ID \
  --assignee-principal-type ServicePrincipal \
  --role "Monitoring Metrics Publisher" \
  --scope $DCR_ID
```

**b) Storage roles** on the Function App's storage account (required for Flex Consumption):

```bash
STORAGE_ID=$(az storage account show \
  --name <storage-account-name> \
  --resource-group <YOUR_RG> \
  --query id -o tsv)

az role assignment create \
  --assignee-object-id $PRINCIPAL_ID \
  --assignee-principal-type ServicePrincipal \
  --role "Storage Blob Data Contributor" \
  --scope $STORAGE_ID

az role assignment create \
  --assignee-object-id $PRINCIPAL_ID \
  --assignee-principal-type ServicePrincipal \
  --role "Storage Account Contributor" \
  --scope $STORAGE_ID
```

> **Note:** RBAC assignments can take 1–2 minutes to propagate.

### 3. Deploy the Function App code

```bash
cd brute-force-demo/api
func azure functionapp publish <functionapp-name>
```

### 4. Deploy the Static Web App

Before deploying, update the API URL in `frontend/script.js` to point to your Function App:

```javascript
const API_URL = "https://<functionapp-name>.azurewebsites.net/api/attempt";
```

Then deploy:

```bash
cd brute-force-demo
npx swa deploy frontend --env production
```

### 5. Verify

Open the SWA URL and submit a test PIN guess. Check that the event appears in Sentinel:

```kql
BruteForceDemo_CL
| where TimeGenerated > ago(5m)
| project TimeGenerated, Nickname, Pincode, AttemptResult
```

## Changing the Secret PIN

The secret PIN defaults to `1337`. There are three ways to change it:

### Method 1 — App Setting (instant, no redeployment)

```bash
az functionapp config appsettings set \
  --name <functionapp-name> \
  --resource-group <YOUR_RG> \
  --settings SECRET_PIN=4242
```

This takes effect immediately — no restart needed.

### Method 2 — Bicep parameter override (at deploy time)

Pass a different value when deploying:

```bash
az deployment group create \
  --resource-group <YOUR_RG> \
  --template-file brute-force-demo/infra/main.bicep \
  --parameters brute-force-demo/infra/main.bicepparam \
  --parameters secretPin=4242
```

### Method 3 — Edit `main.bicepparam` (permanent change)

Edit `brute-force-demo/infra/main.bicepparam` and change:

```bicep
param secretPin = '4242'
```

Then redeploy with `az deployment group create`.

> **Tip:** For live demos, use **Method 1** right before the session — it's instant and doesn't require redeployment. Pick something other than `1337` so the audience can't just read the source code!

## Pausing / Stopping the Demo

Use the toggle script to enable or disable all public-facing resources in one command:

```powershell
# Before demo — enable public access and start the Function App
.\brute-force-demo\infra\toggle-public-access.ps1 on

# After demo — disable public access and stop the Function App
.\brute-force-demo\infra\toggle-public-access.ps1 off
```

The script toggles:
- **Storage account** `publicNetworkAccess` (Enabled / Disabled)
- **Function App** start / stop

Alternatively, you can manage them individually:

```bash
# Stop the Function App
az functionapp stop \
  --name <functionapp-name> \
  --resource-group <YOUR_RG>

# Start the Function App
az functionapp start \
  --name <functionapp-name> \
  --resource-group <YOUR_RG>
```

## Demo Day — Presenter Workflow

1. **Change the secret PIN** before the session (see [Changing the Secret PIN](#changing-the-secret-pin)).

2. **Share the SWA URL** with the audience (QR code works great).

3. **Show Sentinel live** while people attempt to crack the PIN:

   ```kql
   BruteForceDemo_CL
   | where TimeGenerated > ago(1h)
   | summarize
       Attempts = count(),
       Successes = countif(AttemptResult == "Success"),
       DistinctPins = dcount(Pincode)
     by Nickname
   | order by Attempts desc
   ```

4. **Timeline view** — watch the brute force unfold:

   ```kql
   BruteForceDemo_CL
   | where TimeGenerated > ago(1h)
   | project TimeGenerated, Nickname, Pincode, AttemptResult, SourceIP
   | order by TimeGenerated desc
   ```

5. **Watch for incidents** — the "[Demo] Brute Force PIN Cracked" analytic rule triggers a High-severity incident when someone guesses the correct PIN after failed attempts.

6. **Stop the Function App** after the demo to prevent ongoing usage:

   ```powershell
   .\brute-force-demo\infra\toggle-public-access.ps1 off
   ```

## Detection Rules

The `infra/analytic-rules.json` ARM template includes a dedicated rule for this demo:

| Rule | Severity | Frequency | Description |
|------|----------|-----------|-------------|
| **[Demo] Brute Force PIN Cracked — Successful Guess** | High | 5 min | Fires when a user successfully guesses the PIN after prior failed attempts |

Deploy it to your Sentinel workspace:

```bash
az deployment group create \
  --resource-group <SENTINEL_RG> \
  --template-file infra/analytic-rules.json \
  --parameters workspaceName=<WORKSPACE_NAME>
```

The rule maps to **MITRE ATT&CK T1110** (Brute Force) and creates incidents with IP + account entity mappings.

## Project Structure

```
brute-force-demo/
├── api/
│   ├── function_app.py              # Azure Function (Python v2)
│   ├── host.json                    # Function host configuration
│   ├── requirements.txt             # Python dependencies
│   └── local.settings.json.example  # Template for local dev settings
├── frontend/
│   ├── index.html                   # Demo page with PIN pad UI
│   ├── style.css                    # Dark security-themed styling
│   └── script.js                    # Form handling & API calls
├── infra/
│   ├── main.bicep                   # SWA + Function App IaC
│   ├── main.bicepparam              # Parameter values
│   └── toggle-public-access.ps1     # Toggle public access on/off
├── qr-code.png                      # QR code to frontend URL
└── README.md                        # This file
```

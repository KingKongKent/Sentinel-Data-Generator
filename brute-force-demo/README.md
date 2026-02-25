# 🔐 Brute Force Demo — Live Audience PIN Cracking

An interactive demo where your audience tries to crack a 4-digit PIN in real time.
Every attempt is logged to a **Microsoft Sentinel** custom table (`BruteForceDemo_CL`)
via the Azure Monitor Logs Ingestion API — giving you live SOC telemetry to query during a presentation.

## Architecture

```
┌─────────────────────┐  POST /api/attempt  ┌────────────────────┐  Logs Ingestion  ┌──────────────────┐
│  Azure Static Web   │ ─────────────────→  │  Azure Function    │ ───────────────→ │  Sentinel        │
│  App (HTML/CSS/JS)  │ ←───────────────── │  App (Python v2)   │                  │  BruteForceDemo_CL│
│                     │  {result: S/F}      │                    │                  └──────────────────┘
└─────────────────────┘                     └────────────────────┘
```

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
- [SWA CLI](https://azure.github.io/static-web-apps-cli/) (`npm install -g @azure/static-web-apps-cli`)
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

```bash
cd brute-force-demo/infra

# Edit main.bicepparam with your DCE endpoint and DCR ID
az deployment group create \
  --resource-group <YOUR_RG> \
  --template-file main.bicep \
  --parameters main.bicepparam
```

### 2. Grant the Function App access to the DCR

The Function App uses a system-assigned managed identity. Grant it the
**Monitoring Metrics Publisher** role on the Data Collection Rule:

```bash
# Get the principal ID from the deployment output
PRINCIPAL_ID=$(az deployment group show \
  --resource-group <YOUR_RG> \
  --name main \
  --query properties.outputs.functionAppPrincipalId.value -o tsv)

# Get the DCR resource ID
DCR_ID=$(az monitor data-collection rule show \
  --resource-group <YOUR_RG> \
  --name sentinel-datagen-dcr \
  --query id -o tsv)

# Assign the role
az role assignment create \
  --assignee-object-id $PRINCIPAL_ID \
  --assignee-principal-type ServicePrincipal \
  --role "Monitoring Metrics Publisher" \
  --scope $DCR_ID
```

### 3. Deploy the Function App code

```bash
cd brute-force-demo/api
func azure functionapp publish sentinel-datagen-bf-func
```

### 4. Deploy the Static Web App

```bash
cd brute-force-demo
npx swa deploy frontend --env production
```

## Demo Day — Presenter Workflow

1. **Change the secret PIN** (optional):
   ```bash
   az functionapp config appsettings set \
     --name sentinel-datagen-bf-func \
     --resource-group <YOUR_RG> \
     --settings SECRET_PIN=4242
   ```

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
│   └── main.bicepparam              # Parameter values
└── README.md                        # This file
```

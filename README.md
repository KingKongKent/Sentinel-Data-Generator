# Sentinel Data Generator

A Python CLI tool for generating realistic demo/test log data for [Microsoft Sentinel](https://learn.microsoft.com/azure/sentinel/overview). It simulates security events and sends them to an Azure Log Analytics workspace via the **Azure Monitor Data Collection API** (Logs Ingestion API), or outputs them locally as JSON/CSV for offline analysis.

Use it to populate Sentinel with realistic data for testing analytics rules, workbooks, hunting queries, and automation playbooks — without needing a live data source.

## Features

- **Realistic security event generation** — 4 log types with 11 scenarios:
  - **Windows SecurityEvent** — brute-force attacks, privilege escalation (Event IDs 4624, 4625, 4648, 4672, 4688, 4720, 4726)
  - **CommonSecurityLog** — CEF format with firewall, IDS, malware, threat intel events from Palo Alto, Fortinet, Cisco, Check Point, Zscaler
  - **SigninLogs** — Azure AD/Entra ID sign-in events with brute-force, credential stuffing, impossible travel scenarios
  - **Syslog** — Linux system events with SSH authentication, sudo abuse, service failures
- **Scenario-driven** — configure brute-force attacks, privilege escalation, anomalous sign-ins, and more via YAML
- **Multiple output targets** — send to Azure Log Analytics (`log_analytics`), write to local file (`file` — JSON/CSV), or print to console (`stdout`)
- **Azure-native ingestion** — uses `DefaultAzureCredential` and `LogsIngestionClient` with automatic retry on HTTP 429
- **Pydantic v2 validation** — all generated events are validated against strict schemas before output
- **Configurable** — control event count, time range, random seed, and per-scenario parameters
- **Infrastructure-as-Code** — includes Bicep templates to deploy DCE, DCR, custom tables, workbook, and analytic rules
- **Sentinel content included** — pre-built workbook with 5 visualization tabs and 11 detection rules
- **Extensible** — add new log types by subclassing `BaseGenerator` and registering in the engine

## Prerequisites

- **Python 3.10+**
- **Azure CLI** (`az`) with an active login (for cloud ingestion)
- An Azure subscription with a **Log Analytics workspace** enabled for Microsoft Sentinel
- A **Data Collection Endpoint (DCE)** and **Data Collection Rule (DCR)** — deploy using the included Bicep template
- **Monitoring Metrics Publisher** role assigned to your identity on the DCR

## Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/KingKongKent/Sentinel-Data-Generator.git
cd Sentinel-Data-Generator
```

### 2. Create a virtual environment and install dependencies

```bash
python -m venv .venv

# Windows
.venv\Scripts\activate
# macOS/Linux
source .venv/bin/activate

pip install -r requirements.txt
```

### 3. Deploy Azure Infrastructure (DCE + DCR)

The project includes a Bicep template (`infra/main.bicep`) that creates:
- A **Data Collection Endpoint** (DCE)
- Four **custom Log Analytics tables** (`SecurityEventDemo_CL`, `SigninLogDemo_CL`, `SyslogDemo_CL`, `CommonSecurityLogDemo_CL`)
- A **Data Collection Rule** (DCR) with stream declarations and data flows for all four tables

**Prerequisites:** Azure CLI with Bicep support (`az bicep install`).

1. Edit `infra/main.bicepparam` with your Log Analytics workspace resource ID and preferred region.

2. Deploy:

   ```powershell
   # PowerShell
   .\infra\deploy.ps1 -ResourceGroup rg-sentinel-demo -Location eastus
   ```

   ```bash
   # Bash
   ./infra/deploy.sh -g rg-sentinel-demo -l eastus
   ```

3. Note the **DCE Endpoint** and **DCR Immutable ID** from the deployment outputs.

4. Assign the **Monitoring Metrics Publisher** role to your identity on the DCR:

   ```bash
   az role assignment create \
     --assignee "<your-object-id>" \
     --role "Monitoring Metrics Publisher" \
     --scope "<dcr-resource-id>"
   ```

### 4. Configure

Copy the example configuration and fill in the deployment outputs:

```bash
cp config/config.example.yaml config/config.yaml
```

Edit `config/config.yaml`:

```yaml
azure:
  dce_endpoint: "https://<your-dce>.eastus-1.ingest.monitor.azure.com"
  dcr_id: "dcr-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
  stream_name: "Custom-SecurityEventDemo_CL"

output:
  type: stdout  # Change to 'log_analytics' to send to Sentinel

generation:
  count: 50
  time_range:
    start: "2025-06-15T00:00:00Z"
    end: "2025-06-16T00:00:00Z"

scenarios:
  - name: brute_force_login
    log_type: security_event
    stream_name: "Custom-SecurityEventDemo_CL"
    count: 50
    parameters:
      target_host: "DC01.contoso.com"
      target_account: "admin"
      source_ip: "203.0.113.50"
      event_ids: [4625, 4625, 4625, 4625, 4624]
```

You can also set Azure values via environment variables (they override the YAML):
- `SENTINEL_DCE_ENDPOINT`
- `SENTINEL_DCR_ID`
- `SENTINEL_STREAM_NAME`

### 5. Run

```bash
# Preview events in the console
python -m sentinel_data_generator --output stdout --count 10

# Send events to Azure Log Analytics
python -m sentinel_data_generator --output log_analytics

# Write events to a local JSON file
python -m sentinel_data_generator --output file
```

### CLI Options

| Flag | Description | Default |
|------|-------------|---------|
| `--config PATH` | Path to YAML config file | `config/config.yaml` |
| `--output TYPE` | Override output: `log_analytics`, `file`, `stdout` | From config |
| `--count N` | Override event count per scenario | From config |
| `--log-level LEVEL` | Logging level: `DEBUG`, `INFO`, `WARNING`, `ERROR` | `INFO` |

## Project Structure

```
Sentinel-Data-Generator/
├── .github/
│   ├── copilot-instructions.md     # AI agent coding guidelines
│   └── workflows/
│       └── generate-data.yml       # GitHub Actions workflow
├── .vscode/
│   └── extensions.json             # Recommended VS Code extensions
├── infra/
│   ├── main.bicep                  # DCE + DCR + custom tables (Bicep)
│   ├── main.bicepparam             # Deployment parameters
│   ├── deploy.ps1                  # PowerShell deployment script
│   ├── deploy.sh                   # Bash deployment script
│   ├── workbook.json               # Sentinel workbook (5 tabs)
│   └── analytic-rules.json         # 11 Sentinel detection rules
├── config/
│   └── config.example.yaml         # Example YAML configuration
├── notebooks/
│   └── sentinel_analysis.ipynb     # Sentinel compute analysis notebook
├── sentinel_data_generator/
│   ├── __init__.py                 # Package init, version
│   ├── __main__.py                 # CLI entry point (argparse)
│   ├── core/
│   │   ├── __init__.py
│   │   ├── config.py              # YAML config loader (Pydantic validation)
│   │   └── engine.py              # Orchestrator: generators → outputs
│   ├── generators/
│   │   ├── __init__.py
│   │   ├── base.py                # BaseGenerator ABC
│   │   ├── security_event.py      # Windows SecurityEvent generator
│   │   ├── common_security_log.py # CEF CommonSecurityLog generator
│   │   ├── signin_logs.py         # Azure AD/Entra ID SigninLogs generator
│   │   └── syslog.py              # Linux Syslog generator
│   ├── models/
│   │   ├── __init__.py
│   │   └── schemas.py             # Pydantic v2 models (4 log types)
│   ├── outputs/
│   │   ├── __init__.py
│   │   ├── base.py                # BaseOutput ABC
│   │   ├── log_analytics.py       # Azure Monitor Logs Ingestion adapter
│   │   ├── file.py                # Local file output (JSON/CSV)
│   │   └── stdout.py              # Console output for debugging
│   └── utils/
│       ├── __init__.py
│       └── exceptions.py          # Custom exception hierarchy
├── tests/
│   ├── __init__.py
│   ├── test_base_generator.py     # BaseGenerator unit tests
│   ├── test_cli.py                # CLI argument parsing tests
│   ├── test_exceptions.py         # Exception hierarchy tests
│   └── test_schemas.py            # Pydantic schema validation tests
├── .env.example                   # Environment variable template
├── .gitignore
├── .dockerignore                  # Docker build exclusions
├── CONTRIBUTING.md
├── Dockerfile                     # Container image definition
├── LICENSE                        # MIT License
├── README.md
├── pyproject.toml                 # PEP 621 project metadata
├── requirements.txt               # Production dependencies
└── requirements-dev.txt           # Development dependencies
```

## Architecture

```
                  ┌──────────────┐
                  │  config.yaml │
                  └──────┬───────┘
                         │
                  ┌──────▼───────┐
                  │ Config Loader │  ← Pydantic validation + env var overrides
                  │  (core/       │
                  │   config.py)  │
                  └──────┬───────┘
                         │
                  ┌──────▼───────┐
                  │    Engine     │  ← Iterates scenarios, creates generators & output
                  │  (core/       │
                  │   engine.py)  │
                  └──┬────────┬──┘
                     │        │
          ┌──────────▼──┐  ┌──▼──────────────┐
          │  Generator  │  │  Output Adapter  │
          │ (security_  │  │ (log_analytics/  │
          │  event.py)  │  │  stdout/file.py) │
          └──────┬──────┘  └────────┬─────────┘
                 │                  │
          ┌──────▼──────┐  ┌───────▼─────────┐
          │  Pydantic   │  │  Azure Monitor   │
          │  Schema     │  │  Logs Ingestion  │
          │  Validation │  │  API (DCE/DCR)   │
          └─────────────┘  └─────────────────┘
```

## Configuration

Configuration is YAML-based with Pydantic validation. Values can be overridden via environment variables or CLI flags.

| Section | Key | Description |
|---------|-----|-------------|
| `azure` | `dce_endpoint` | Data Collection Endpoint URL |
| `azure` | `dcr_id` | Data Collection Rule immutable ID |
| `azure` | `stream_name` | Default DCR stream name |
| `output` | `type` | Output target: `log_analytics`, `file`, or `stdout` |
| `output` | `file_path` | File path (when `type: file`) |
| `output` | `file_format` | `json` or `csv` (when `type: file`) |
| `generation` | `count` | Default event count per scenario |
| `generation` | `time_range.start` | ISO 8601 UTC start datetime |
| `generation` | `time_range.end` | ISO 8601 UTC end datetime |
| `generation` | `seed` | Random seed for reproducibility |
| `scenarios[]` | `name` | Scenario identifier |
| `scenarios[]` | `log_type` | Generator type: `security_event`, `common_security_log_native`, `signin_logs`, `syslog` |
| `scenarios[]` | `stream_name` | Override stream for this scenario |
| `scenarios[]` | `count` | Override event count for this scenario |
| `scenarios[]` | `parameters` | Generator-specific parameters |

### Environment Variable Overrides

| Variable | Overrides |
|----------|-----------|
| `SENTINEL_DCE_ENDPOINT` | `azure.dce_endpoint` |
| `SENTINEL_DCR_ID` | `azure.dcr_id` |
| `SENTINEL_STREAM_NAME` | `azure.stream_name` |

## Supported Log Types

| Log Type | Generator | Target Table | Status |
|----------|-----------|--------------|--------|
| SecurityEvent | `security_event` | `SecurityEventDemo_CL` (custom) | ✅ Implemented |
| CommonSecurityLog | `common_security_log_native` | `CommonSecurityLog` (native) | ✅ Implemented |
| SigninLogs | `signin_logs` | `SigninLogDemo_CL` (custom) | ✅ Implemented |
| Syslog | `syslog` | `SyslogDemo_CL` (custom) | ✅ Implemented |

### SecurityEvent Generator

Generates realistic Windows Security events with the following supported Event IDs:

| Event ID | Description |
|----------|-------------|
| 4624 | Successful logon |
| 4625 | Failed logon |
| 4648 | Logon with explicit credentials |
| 4672 | Special privileges assigned |
| 4688 | New process created |
| 4720 | User account created |
| 4726 | User account deleted |

**Scenario parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `target_host` | `string` | Target hostname (optional — randomized if omitted) |
| `target_account` | `string` | Target account name (optional) |
| `source_ip` | `string` | Attacker source IP (optional) |
| `event_ids` | `list[int]` | Event IDs to generate — weighted by frequency in list |

### CommonSecurityLog Generator

Generates CEF-format events that ingest to the **native CommonSecurityLog table** in Sentinel. Supports multiple security vendors:

| Vendor | Product | Event Types |
|--------|---------|-------------|
| Palo Alto Networks | PAN-OS | Firewall allow/deny, IDS, malware |
| Fortinet | FortiGate | Firewall allow/deny, threat intel |
| Cisco | ASA | Firewall allow/deny, VPN |
| Check Point | NGFW | Firewall allow/deny, IDS |
| Zscaler | ZIA | Web access, threat intel |

**Event types:**

| Event Type | DeviceEventClassID | Description |
|------------|-------------------|-------------|
| `firewall_allow` | `traffic:allow` | Permitted network traffic |
| `firewall_deny` | `traffic:deny` | Blocked network traffic |
| `ids_alert` | `intrusion:alert` | Intrusion detection alert |
| `malware_detected` | `malware:detected` | Malware detection event |
| `web_access` | `web:access` | Web proxy/gateway access |
| `vpn_connection` | `vpn:connect` | VPN connection event |
| `threat_intelligence` | `threat:match` | Threat intel IOC match |

**Scenario parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `vendor` | `string` | Specific vendor to use (optional — randomized if omitted) |
| `event_type` | `string` | Specific event type (optional — randomized if omitted) |
| `threat_actor_ip` | `bool` | Use known threat actor IPs for source (default: false) |

### SigninLogs Generator

Generates Azure AD/Entra ID sign-in events for the `SigninLogDemo_CL` custom table. Supports multiple attack scenarios:

| Attack Type | Description |
|-------------|-------------|
| `brute_force` | Multiple failed logins from same IP against one user |
| `credential_stuffing` | Failed logins across multiple users from one IP |
| `impossible_travel` | Sign-ins from distant locations in short time |

**Scenario parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `attack_type` | `string` | Attack scenario: `brute_force`, `credential_stuffing`, `impossible_travel` |
| `target_user` | `string` | Specific target UPN (optional — randomized if omitted) |
| `source_ip` | `string` | Attacker source IP (optional — randomized if omitted) |
| `success_rate` | `float` | Probability of successful sign-in (0.0-1.0, default: 0.1) |

**Generated fields include:** `TimeGenerated`, `UserPrincipalName`, `IPAddress`, `Location`, `ResultType`, `ResultDescription`, `AppDisplayName`, `ClientAppUsed`, `DeviceDetail`, `RiskLevelDuringSignIn`, `RiskState`.

### Syslog Generator

Generates Linux syslog events for the `SyslogDemo_CL` custom table. Supports multiple event categories:

| Event Category | Facility | Description |
|----------------|----------|-------------|
| SSH authentication | `auth` | SSH login success/failure, key auth, password auth |
| Sudo events | `authpriv` | sudo command execution, permission denied |
| Cron jobs | `cron` | Scheduled task execution |
| Kernel events | `kern` | Out-of-memory, hardware errors |
| Service events | `daemon` | Service start/stop/failure |
| Firewall events | `kern` | iptables allow/deny |

**Severity levels:** `emerg`, `alert`, `crit`, `err`, `warning`, `notice`, `info`, `debug`

**Scenario parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `event_category` | `string` | Category: `ssh`, `sudo`, `cron`, `kernel`, `service`, `firewall` |
| `severity` | `string` | Minimum severity level (optional) |
| `hostname` | `string` | Specific hostname (optional — randomized if omitted) |
| `failure_rate` | `float` | Probability of failure events (0.0-1.0, default: 0.3) |

**Generated fields include:** `TimeGenerated`, `Facility`, `SeverityLevel`, `Computer`, `HostIP`, `ProcessName`, `ProcessID`, `SyslogMessage`.

## Sentinel Content

Pre-built Sentinel content is included for immediate use with the generated demo data.

### Analysis Notebook

A Jupyter notebook (`notebooks/sentinel_analysis.ipynb`) for analyzing all 4 tables directly in the **Microsoft Sentinel Data Lake**. Built following the [official documentation](https://learn.microsoft.com/en-us/azure/sentinel/datalake/notebooks) using the `MicrosoftSentinelProvider` class, PySpark DataFrames, and `matplotlib`.

- **Setup** — Initializes `MicrosoftSentinelProvider(spark)` and lists available workspaces
- **Overview** — Event distribution across all tables (pie chart)
- **SecurityEventDemo_CL** — Events by Event ID, failed login analysis, brute force detection
- **CommonSecurityLog** — Vendor breakdown, threat intelligence matches, firewall denies
- **SigninLogDemo_CL** — Sign-in results, risky sign-ins, success/failure by location
- **SyslogDemo_CL** — Facility/severity breakdown, SSH failures, service errors
- **Dashboard** — Combined 2×2 visualization summary
- **Key Findings** — Automated security summary with counts

**To use:**

1. Install the [Microsoft Sentinel VS Code extension](https://marketplace.visualstudio.com/items?itemName=ms-azure-sentinel.azure-sentinel-notebooks)
2. Open the notebook in VS Code
3. Run the first cell — select **Microsoft Sentinel** as the runtime
4. Choose a pool size (Small is sufficient for ~3k events)
5. Wait 3–5 minutes for the Spark session to start, then run remaining cells

> **Note:** Custom pip installs are not supported in the Sentinel runtime. The notebook uses only `matplotlib` (pre-installed in Azure Synapse) and the `sentinel_lake` provider library.

### Workbook

The workbook (`infra/workbook.json`) provides 5 visualization tabs:

| Tab | Visualizations |
|-----|---------------|
| **Overview** | Event distribution pie chart, events over time timeline |
| **Security Events** | Windows events by type, failed logins by host |
| **CommonSecurityLog** | Firewall events by vendor, threat intel matches |
| **Sign-in Logs** | Sign-in results by location, risky sign-ins |
| **Syslog** | Events by facility and severity, SSH failures |

**Deploy the workbook:**

```bash
az deployment group create \
  --resource-group <your-resource-group> \
  --template-file infra/workbook.json \
  --parameters workspaceName=<your-workspace-name>
```

### Analytic Rules

11 detection rules (`infra/analytic-rules.json`) covering all demo scenarios:

| Rule | Log Type | Description |
|------|----------|-------------|
| Windows Brute Force Attack | SecurityEventDemo_CL | 10+ failed logins in 5 minutes |
| Windows Privilege Escalation | SecurityEventDemo_CL | Admin account creation |
| High Volume Firewall Denies | CommonSecurityLog | 50+ denies from same source |
| IDS Intrusion Detected | CommonSecurityLog | Intrusion alert from IDS |
| Threat Intel IOC Match | CommonSecurityLog | Known threat actor IP |
| AAD Brute Force Attack | SigninLogDemo_CL | 10+ failed sign-ins in 5 minutes |
| Credential Stuffing Attack | SigninLogDemo_CL | Failed logins across 5+ accounts |
| Risky Sign-in Detected | SigninLogDemo_CL | High risk sign-in |
| SSH Brute Force Attack | SyslogDemo_CL | 10+ SSH failures in 5 minutes |
| Suspicious Sudo Activity | SyslogDemo_CL | Multiple sudo failures |
| Critical Service Failure | SyslogDemo_CL | Service failure events |

**Deploy the analytic rules:**

```bash
az deployment group create \
  --resource-group <your-resource-group> \
  --template-file infra/analytic-rules.json \
  --parameters workspaceName=<your-workspace-name>
```

## Docker

Build and run the generator in a container:

```bash
# Build the image
docker build -t sentinel-datagen .

# Run with Azure authentication (send to Sentinel)
docker run --rm \
  -e AZURE_CLIENT_ID=<sp-client-id> \
  -e AZURE_CLIENT_SECRET=<sp-secret> \
  -e AZURE_TENANT_ID=<tenant-id> \
  -e SENTINEL_DCE_ENDPOINT=<dce-endpoint> \
  -e SENTINEL_DCR_ID=<dcr-id> \
  sentinel-datagen --output log_analytics --count 100

# Preview events locally
docker run --rm sentinel-datagen --output stdout --count 10
```

## GitHub Actions

The project includes a GitHub Actions workflow (`.github/workflows/generate-data.yml`) that:

1. **Scheduled execution** — runs every 6 hours to continuously populate Sentinel with demo data
2. **Manual trigger** — run on-demand from the GitHub Actions UI with customizable parameters
3. **Docker build** — optionally build and push the container image to GitHub Container Registry

### Required Secrets

Configure these secrets in your GitHub repository (Settings → Secrets → Actions):

| Secret | Description |
|--------|-------------|
| `AZURE_CLIENT_ID` | Service principal application (client) ID |
| `AZURE_CLIENT_SECRET` | Service principal secret |
| `AZURE_TENANT_ID` | Azure AD tenant ID |
| `SENTINEL_DCE_ENDPOINT` | Data Collection Endpoint URL |
| `SENTINEL_DCR_ID` | Data Collection Rule immutable ID |

### Manual Trigger Options

| Input | Description | Default |
|-------|-------------|---------|
| `count` | Events per scenario | 50 |
| `log_level` | DEBUG, INFO, WARNING, ERROR | INFO |
| `build_docker` | Build and push Docker image | false |

## Testing

```bash
# Run all tests
python -m pytest

# Run with coverage
python -m pytest --cov=sentinel_data_generator

# Run with verbose output
python -m pytest -v
```

38 unit tests covering schemas, generators, CLI, and exceptions.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on adding new generators, scenarios, and output adapters.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

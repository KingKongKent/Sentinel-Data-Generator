# Sentinel Data Generator

A Python CLI tool for generating realistic demo/test log data for [Microsoft Sentinel](https://learn.microsoft.com/azure/sentinel/overview). It simulates security events and sends them to an Azure Log Analytics workspace via the **Azure Monitor Data Collection API** (Logs Ingestion API), or outputs them locally as JSON/CSV for offline analysis.

Use it to populate Sentinel with realistic data for testing analytics rules, workbooks, hunting queries, and automation playbooks — without needing a live data source.

## Features

- **Realistic security event generation** — Windows SecurityEvent (4624, 4625, 4648, 4672, 4688, 4720, 4726), with Syslog, SigninLogs, and CommonSecurityLog schemas ready for extension
- **Scenario-driven** — configure brute-force attacks, privilege escalation, anomalous sign-ins, and more via YAML
- **Multiple output targets** — send to Azure Log Analytics (`log_analytics`), write to local file (`file` — JSON/CSV), or print to console (`stdout`)
- **Azure-native ingestion** — uses `DefaultAzureCredential` and `LogsIngestionClient` with automatic retry on HTTP 429
- **Pydantic v2 validation** — all generated events are validated against strict schemas before output
- **Configurable** — control event count, time range, random seed, and per-scenario parameters
- **Infrastructure-as-Code** — includes a Bicep template to deploy the DCE, DCR, and custom Log Analytics tables
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
│   └── copilot-instructions.md     # AI agent coding guidelines
├── .vscode/
│   └── extensions.json             # Recommended VS Code extensions
├── infra/
│   ├── main.bicep                  # DCE + DCR + custom tables (Bicep)
│   ├── main.bicepparam             # Deployment parameters
│   ├── deploy.ps1                  # PowerShell deployment script
│   └── deploy.sh                   # Bash deployment script
├── config/
│   └── config.example.yaml         # Example YAML configuration
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
│   │   └── security_event.py      # Windows SecurityEvent generator
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
├── CONTRIBUTING.md
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
| `scenarios[]` | `log_type` | Generator type: `security_event` |
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

| Log Type | Generator | Custom Table | Status |
|----------|-----------|--------------|--------|
| SecurityEvent | `security_event` | `SecurityEventDemo_CL` | ✅ Implemented |
| SigninLogs | `signin_logs` | `SigninLogDemo_CL` | 📋 Schema ready |
| Syslog | `syslog` | `SyslogDemo_CL` | 📋 Schema ready |
| CommonSecurityLog | `common_security_log` | `CommonSecurityLogDemo_CL` | 📋 Schema ready |

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

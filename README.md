# Sentinel Data Generator

A Python-based tool for simulating and generating demo log data for [Microsoft Sentinel](https://learn.microsoft.com/azure/sentinel/overview). Use this project to create realistic, customizable security event logs for testing analytics rules, workbooks, hunting queries, and automation playbooks — without needing a live data source.

## Features

- Generate realistic security event logs across multiple log types (Syslog, CommonSecurityLog, SigninLogs, SecurityEvent, etc.)
- Configurable scenarios: brute-force attacks, lateral movement, data exfiltration, anomalous sign-ins, and more
- Output to Azure Log Analytics workspace via the Data Collection API, or export to local JSON/CSV files
- Customizable volume, frequency, and time range for generated data
- Extensible architecture: add new log types and attack scenarios via configuration

## Prerequisites

- **Python 3.10+**
- An Azure subscription with a **Log Analytics workspace** (for cloud ingestion)
- A **Data Collection Endpoint (DCE)** and **Data Collection Rule (DCR)** configured in Azure Monitor (for cloud ingestion)
- Azure CLI or a service principal for authentication

## Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/<org>/Sentinel-Data-Generator.git
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

### 3. Configure

Copy the example configuration and fill in your values:

```bash
cp config/config.example.yaml config/config.yaml
```

Edit `config/config.yaml` with your Log Analytics workspace ID, DCE/DCR details, and desired scenarios.

### 4. Run

```bash
python -m sentinel_data_generator --config config/config.yaml
```

## Project Structure

```
Sentinel-Data-Generator/
├── .github/
│   └── copilot-instructions.md   # AI agent coding instructions
├── .vscode/
│   └── settings.json             # VS Code workspace settings
├── config/
│   ├── config.example.yaml       # Example configuration
│   └── scenarios/                # Scenario definitions
├── sentinel_data_generator/
│   ├── __init__.py
│   ├── __main__.py               # CLI entry point
│   ├── core/
│   │   ├── __init__.py
│   │   ├── engine.py             # Log generation engine
│   │   └── scheduler.py          # Timing and scheduling
│   ├── generators/
│   │   ├── __init__.py
│   │   ├── base.py               # Base generator class
│   │   ├── syslog.py             # Syslog event generator
│   │   ├── security_event.py     # Windows SecurityEvent generator
│   │   ├── signin_logs.py        # Azure AD SigninLogs generator
│   │   └── common_security_log.py# CEF/CommonSecurityLog generator
│   ├── models/
│   │   ├── __init__.py
│   │   └── schemas.py            # Pydantic models for log schemas
│   ├── outputs/
│   │   ├── __init__.py
│   │   ├── log_analytics.py      # Azure Log Analytics output
│   │   ├── file_output.py        # Local file output (JSON/CSV)
│   │   └── stdout.py             # Console output for debugging
│   └── utils/
│       ├── __init__.py
│       ├── auth.py               # Azure authentication helpers
│       ├── faker_providers.py    # Custom Faker providers for security data
│       └── helpers.py            # General utility functions
├── tests/
│   ├── __init__.py
│   ├── test_generators.py
│   ├── test_engine.py
│   └── test_outputs.py
├── .gitignore
├── CONTRIBUTING.md
├── LICENSE
├── README.md
├── pyproject.toml
└── requirements.txt
```

## Configuration

Configuration is YAML-based. Key options:

| Key | Description |
|-----|-------------|
| `workspace_id` | Log Analytics workspace ID |
| `dce_endpoint` | Data Collection Endpoint URI |
| `dcr_id` | Data Collection Rule immutable ID |
| `stream_name` | Target stream (e.g., `Custom-MyTable_CL`) |
| `scenarios` | List of attack/event scenarios to simulate |
| `output` | Output target: `log_analytics`, `file`, or `stdout` |
| `volume` | Number of events to generate per scenario |
| `time_range` | Time window for generated events |

## Supported Log Types

| Log Type | Table | Description |
|----------|-------|-------------|
| Syslog | `Syslog` | Linux syslog events |
| SecurityEvent | `SecurityEvent` | Windows Security events (4624, 4625, 4688, etc.) |
| SigninLogs | `SigninLogs` | Azure AD/Entra ID sign-in events |
| CommonSecurityLog | `CommonSecurityLog` | CEF-formatted events from firewalls, IDS/IPS |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

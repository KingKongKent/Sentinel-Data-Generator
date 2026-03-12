# Copilot Instructions for Sentinel Data Generator

## Project Overview

This is a **Python CLI tool** that generates realistic demo/test log data for **Microsoft Sentinel**. It simulates security events (sign-ins, Windows security events, syslog, CEF, AWS CloudTrail, GCP Audit Logs, Purview DLP/IRM, Defender for Office 365) and sends them to an Azure Log Analytics workspace via the **Azure Monitor Logs Ingestion API** (Data Collection Endpoint + Data Collection Rule), or outputs them locally as JSON/CSV.

## Tech Stack

- **Language:** Python 3.10+
- **Package management:** pip with `pyproject.toml` (PEP 621)
- **Data validation:** Pydantic v2
- **Fake data generation:** Faker
- **Azure SDK:** `azure-identity` (DefaultAzureCredential), `azure-monitor-ingestion` (LogsIngestionClient)
- **CLI framework:** `argparse` (stdlib)
- **Configuration:** YAML (`PyYAML`) with Pydantic validation
- **Testing:** pytest, pytest-cov
- **Linting/Formatting:** ruff
- **IaC:** Bicep (DCE + DCR + custom Log Analytics tables)

## Code Style & Conventions

### General
- Follow **PEP 8** naming conventions strictly.
- Use **type hints** on all function signatures and variables where beneficial.
- Use **f-strings** for string formatting.
- Prefer **pathlib.Path** over `os.path` for file system operations.
- Use **`logging`** module (never `print()`) for runtime output. Configure via a root logger.
- Keep functions small and focused — each should do one thing.
- Write **docstrings** (Google style) for all public classes, methods, and functions.

### Project Structure
- All source code lives in `sentinel_data_generator/` package.
- CLI entry point is `sentinel_data_generator/__main__.py` — uses `argparse`, wires up config loader and engine.
- Configuration loading and Pydantic config models are in `sentinel_data_generator/core/config.py`.
- The orchestration engine (iterates scenarios, creates generators, sends output) is in `sentinel_data_generator/core/engine.py`.
- Each log type has its own generator module in `sentinel_data_generator/generators/`.
- All generators inherit from `sentinel_data_generator.generators.base.BaseGenerator`.
- New generators must be registered in `GENERATOR_REGISTRY` in `sentinel_data_generator/core/engine.py`.
- Pydantic models for log schemas are in `sentinel_data_generator/models/schemas.py`.
- Output adapters (Log Analytics, file, stdout) are in `sentinel_data_generator/outputs/` and inherit from `sentinel_data_generator.outputs.base.BaseOutput`.
- Custom exceptions are in `sentinel_data_generator/utils/exceptions.py`.
- Configuration and scenario definitions go in `config/`.
- Tests mirror source structure under `tests/`.

### Error Handling
- Raise specific exceptions; avoid bare `except`.
- Use custom exception classes in `sentinel_data_generator/utils/exceptions.py`:
  - `SentinelDataGeneratorError` — base exception
  - `ConfigurationError` — invalid or missing config
  - `AuthenticationError` — Azure credential failures
  - `IngestionError` — data ingestion failures
  - `SchemaValidationError` — Pydantic validation failures
- Handle Azure SDK exceptions (`HttpResponseError`, `ClientAuthenticationError`) explicitly and log actionable messages.
- On `429 (Request Rate Too Large)` from Azure, implement **retry-after** logic (see `outputs/log_analytics.py`).

### Azure & Sentinel Specifics
- Use `azure.identity.DefaultAzureCredential` for authentication (supports CLI, managed identity, env vars).
- Use `azure.monitor.ingestion.LogsIngestionClient` for sending data via the Logs Ingestion API.
- Never hardcode credentials — always read from environment variables or config.
- Log schemas must match the **Data Collection Rule (DCR)** stream schema exactly.
- Timestamps must be in **ISO 8601 UTC** format (`datetime.datetime.now(datetime.timezone.utc).isoformat()`).
- Reuse the `LogsIngestionClient` instance — do not create a new client per batch (singleton pattern in `LogAnalyticsOutput`).
- The Bicep IaC template (`infra/main.bicep`) defines nine custom tables and their DCR streams.
- When calling the Logs Ingestion API you POST to the **input** stream name — this is what `LOG_TYPE_STREAM_MAP` in `core/config.py` stores. For native Sentinel tables the DCR internally routes to a different output stream; for custom `_CL` tables the input and output stream name are the same.
- **CRITICAL — Do not confuse `common_security_log` (custom demo table) with `common_security_log_native` (native `CommonSecurityLog` table).** Always check the `log_type` value and the table it targets before generating or sending data.
- `BruteForceDemo_CL` is **not** populated by the main data generator. It is populated exclusively by the standalone `brute-force-demo/` web app (Azure Function). There is no `brute_force` log_type in `GENERATOR_REGISTRY` or `LOG_TYPE_STREAM_MAP`.

#### Full `log_type` → Stream → Table mapping

| `log_type` (config) | DCR input stream (API / `LOG_TYPE_STREAM_MAP`) | DCR output stream | Sentinel table | Table type |
|---|---|---|---|---|
| `security_event` | `Custom-SecurityEventDemo_CL` | `Custom-SecurityEventDemo_CL` | `SecurityEventDemo_CL` | Custom |
| `signin_logs` | `Custom-SigninLogDemo_CL` | `Custom-SigninLogDemo_CL` | `SigninLogDemo_CL` | Custom |
| `syslog` | `Custom-SyslogDemo_CL` | `Custom-SyslogDemo_CL` | `SyslogDemo_CL` | Custom |
| `common_security_log` | `Custom-CommonSecurityLogDemo_CL` | `Custom-CommonSecurityLogDemo_CL` | `CommonSecurityLogDemo_CL` | Custom |
| `aws_cloudtrail` | `Custom-AWSCloudTrailDemo_CL` | `Custom-AWSCloudTrailDemo_CL` | `AWSCloudTrailDemo_CL` | Custom |
| `gcp_audit_logs` | `Custom-GCPAuditLogsDemo_CL` | `Custom-GCPAuditLogsDemo_CL` | `GCPAuditLogsDemo_CL` | Custom |
| `purview_dlp` | `Custom-PurviewDLPDemo_CL` | `Custom-PurviewDLPDemo_CL` | `PurviewDLPDemo_CL` | Custom |
| `defender_office` | `Custom-DefenderOfficeDemo_CL` | `Custom-DefenderOfficeDemo_CL` | `DefenderOfficeDemo_CL` | Custom |
| `common_security_log_native` | `Custom-CommonSecurityLogNative` | `Microsoft-CommonSecurityLog` | `CommonSecurityLog` | **Native** |
| `syslog_native` | `Custom-SyslogNative` | `Microsoft-Syslog` | `Syslog` | **Native** |

### Data Generation
- Each generator must produce data conforming to the target Sentinel table schema.
- Use Faker for realistic IPs, hostnames, UPNs, etc.
- Generators must accept parameters: `count`, `time_range`, `scenario` configuration dict.
- Generated events should have **realistic time distribution** (use `BaseGenerator._distribute_timestamps()` for sorted timestamps).
- IP addresses, usernames, and hostnames should be internally consistent within a scenario (e.g., a brute-force attack comes from the same source IP).
- All generated events are validated through Pydantic models before being returned as `list[dict]`.

### Configuration
- Configuration is loaded from YAML files via `core/config.py`.
- Pydantic models (`AppConfig`, `AzureConfig`, `OutputConfig`, `GenerationConfig`, `ScenarioConfig`) validate config on load.
- Environment variables override YAML values: `SENTINEL_DCE_ENDPOINT`, `SENTINEL_DCR_ID`, `SENTINEL_STREAM_NAME`.
- CLI flags (`--output`, `--count`) override config values.
- Sensitive values (DCE endpoint, DCR ID) should come from environment variables in CI/CD and never be committed.
- Stream names are auto-resolved from `log_type` via `LOG_TYPE_STREAM_MAP` in `core/config.py`, or overridden per-scenario.

### Testing
- Write unit tests for every generator and output adapter.
- Use `pytest` fixtures for reusable test data.
- Mock Azure SDK calls in tests — never make real API calls in tests.
- Aim for **80%+ code coverage**.
- Current test files: `test_schemas.py`, `test_base_generator.py`, `test_cli.py`, `test_exceptions.py` (38 tests).

### Dependencies
- Pin major versions in `requirements.txt`.
- Keep dependencies minimal — justify any new dependency.

### Sentinel Data Lake Notebooks
Notebooks in `notebooks/` are designed to run on the **Microsoft Sentinel Data Lake** via the VS Code Microsoft Sentinel extension. They use **Apache Spark** (PySpark) — not `azure-monitor-query` or `msticpy`.

#### Runtime Environment
- Notebooks run in a **Sentinel compute runtime** (Small / Medium / Large pool) selected via the VS Code Sentinel extension.
- The runtime provides a pre-configured `spark` (SparkSession) variable — **never create your own SparkSession**.
- Only **Azure Synapse libraries 3.4** and the **`sentinel_lake` provider library** are available. `pip install` and custom libraries are **not supported**.
- Available visualization library: `matplotlib`. Do **not** use `plotly`, `seaborn`, or other libraries that are not pre-installed.

#### MicrosoftSentinelProvider API
- Import: `from sentinel_lake.providers import MicrosoftSentinelProvider`
- Initialize once per notebook: `data_provider = MicrosoftSentinelProvider(spark)`
- Key methods:
  - `data_provider.list_databases()` → `list[str]` of workspace names
  - `data_provider.list_tables(database_name, database_id=None)` → `list[str]` of table names
  - `data_provider.read_table(table_name, database_name=None, database_id=None)` → Spark `DataFrame`
  - `data_provider.save_as_table(df, table_name, database_name=None, database_id=None, write_options=None)` → run ID
  - `data_provider.delete_table(table_name, database_name=None, database_id=None)` → dict
- When reading tables, always pass the **workspace name** as the second argument: `data_provider.read_table("SecurityEventDemo_CL", WORKSPACE_NAME)`

#### Custom Table Naming
- Data lake tier custom tables must end with `_SPRK` suffix.
- Analytics tier custom tables must end with `_SPRK_CL` suffix.
- `save_as_table` supports `append` (default) and `overwrite` modes. `overwrite` is only supported in the lake tier.
- Partitioning (`partitionBy`) is only supported for custom tables in the `System tables` database in the lake tier.

#### Code Patterns
- Use **PySpark DataFrame API** (`col`, `count`, `when`, `desc`, `from_json`, etc.) for all data transformations — not Pandas.
- Convert to Pandas only for visualization: `pd_df = spark_df.toPandas()`
- Use `matplotlib.pyplot` for charts (bar, pie, line). Import as `import matplotlib.pyplot as plt`.
- Define a `WORKSPACE_NAME` variable at the top of the notebook for the target workspace.
- Structure notebooks in logical sections: Setup → Load Data → Analysis per table → Summary Dashboard.
- Use `.show(truncate=False)` to display Spark DataFrames in output cells.

#### Limitations & Considerations
- Session startup takes **3–5 minutes**; subsequent cell runs are fast.
- Interactive session timeout is **20 minutes** (configurable).
- Interactive query timeout is **2 hours**.
- Max **100,000 rows** displayed in VS Code output.
- VS Code linting (Pylance/Ruff) will flag false errors for `spark`, `sentinel_lake`, and `pyspark` imports — these are expected since the packages only exist in the Sentinel runtime.
- Analytics tier tables **cannot be deleted** from notebooks; use Log Analytics API instead.

#### Reference Documentation
- [Sentinel Data Lake Notebooks](https://learn.microsoft.com/en-us/azure/sentinel/datalake/notebooks)
- [Sample Notebooks](https://learn.microsoft.com/en-us/azure/sentinel/datalake/notebook-examples)
- [MicrosoftSentinelProvider Class Reference](https://learn.microsoft.com/en-us/azure/sentinel/datalake/sentinel-provider-class-reference)

## File Naming
- Python modules: `snake_case.py`
- Config files: `snake_case.yaml`
- Test files: `test_<module>.py`

## Commit Messages
- Use [Conventional Commits](https://www.conventionalcommits.org/): `feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`.
- Keep subject line under 72 characters.

## Security
- Never generate or log real credentials, tokens, or secrets.
- Demo data must use obviously fake values (e.g., `user@contoso.com`, `10.0.0.x` ranges, `203.0.113.x` documentation IPs).
- Sanitize all configuration values before logging.

### Brute Force Demo (`brute-force-demo/`)

A standalone interactive web app for live presentations. Separate from the Python CLI — it has its own `api/`, `frontend/`, and `infra/` folders.

#### Architecture
- **Frontend:** Azure Static Web App (vanilla HTML/CSS/JS, no framework).
- **Backend:** Azure Function App (Python v2, Flex Consumption), authenticates to Logs Ingestion API via system-assigned managed identity.
- **Table:** `BruteForceDemo_CL` with columns: `TimeGenerated`, `Nickname`, `Pincode`, `AttemptResult`, `SourceIP`, `UserAgent`.

#### Frontend Patterns
- The frontend is a single-page app wrapped in an IIFE in `script.js`.
- `API_URL` is auto-detected from the hostname (SWA proxy uses relative `/api/attempt`, otherwise falls back to the configured Function App URL).
- The "Try in Sentinel" panel is a collapsible `<section>` using `max-height` CSS transition. State is toggled via `aria-expanded` on the header `<button>`.
- Prompt cards use a `.prompt-badge` class with `.nl` (cyan) or `.kql` (gold) variant for type labeling.
- KQL queries in prompt cards contain `"<your-nickname>"` placeholder text that is dynamically replaced with the user's entered nickname via `updatePromptNicknames()`.
- Copy-to-clipboard uses `navigator.clipboard.writeText()` with a visual `✓ Copied` feedback state.

#### Workbook (`infra/workbook.json`)
- The workbook is an ARM template with `serializedData` JSON strings inside each item.
- The Brute Force Demo tab (`groupBruteForce`) contains: summary tiles, timeline, per-nickname chart, most-guessed PINs, recent attempts, Leaderboard, Who Cracked the PIN?, and a Try in Sentinel markdown panel.
- **Tiles visualization** requires queries that produce one row per tile. Use the `pack_array` → `mv-expand` → `bag_unpack` pattern to pivot aggregation columns into separate rows.
- To edit workbook items programmatically, parse the outer ARM JSON, then parse the `serializedData` string of the target item, modify it, re-serialize, and write back.

#### Analytic Rules
- `infra/analytic-rules.json` contains 33 detection rules (ARM template).
- The brute-force demo rule (`[Demo] Brute Force PIN Cracked`) queries `BruteForceDemo_CL`, joins successes with prior failures, maps to MITRE T1110, and runs every 5 minutes.

#### Toggle Script
- `brute-force-demo/infra/toggle-public-access.ps1` enables or disables public access on the storage account and starts/stops the Function App in one command (`on` / `off`).

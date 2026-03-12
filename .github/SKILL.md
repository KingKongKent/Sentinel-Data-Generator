---
name: sentinel-data-generator
description: >-
  Expert guidance for the Sentinel Data Generator project — a Python CLI tool that generates
  realistic demo/test log data for Microsoft Sentinel. Use when adding a new log type or
  generator, adding a scenario, debugging ingestion, editing config, extending schemas,
  writing tests, deploying infrastructure, understanding table/stream mappings, modifying
  the brute-force demo, or editing Sentinel workbooks and analytic rules.
  Do not use for general KQL authoring, Sentinel workspace administration, Log Analytics
  pricing, general Azure infrastructure questions unrelated to this repo, or Jupyter
  notebook runtime issues in the Sentinel Data Lake.
license: MIT
metadata:
  author: KingKongKent
  version: "1.0.0"
---

# Sentinel Data Generator — Project Skill

Expert knowledge for working with the **Sentinel Data Generator** codebase: a Python CLI tool that generates realistic security event data and sends it to a Microsoft Sentinel Log Analytics workspace via the Azure Monitor Logs Ingestion API.

## Skill Activation Triggers

**Use this skill when the user asks to:**

- Add a new log type, generator, or scenario
- Debug data ingestion or authentication failures
- Edit the YAML configuration or add new scenario parameters
- Extend or fix a Pydantic schema in `models/schemas.py`
- Understand how log types map to DCR streams and Sentinel tables
- Write or fix tests for generators or output adapters
- Deploy or update the Bicep infrastructure (DCE, DCR, custom tables)
- Modify the workbook (`infra/workbook.json`) or analytic rules (`infra/analytic-rules.json`)
- Work on the brute-force demo (`brute-force-demo/`) API, frontend, or infra
- Understand the GitHub Actions workflow (`generate-data.yml`)
- Add MCP tools for Copilot/agent integration

## When NOT to Use This Skill

- General KQL authoring or Sentinel workspace administration not tied to this codebase
- Azure infrastructure questions unrelated to this repo's DCE/DCR/tables
- Sentinel Data Lake notebook runtime issues (PySpark, `sentinel_lake` provider)
- Log Analytics pricing, capacity, or retention configuration
- General Python, Pydantic, or Azure SDK questions with no connection to this project

## Project Layout

```
sentinel_data_generator/
  __main__.py          ← CLI entry point (argparse)
  core/
    config.py          ← YAML loader, Pydantic models, LOG_TYPE_STREAM_MAP
    engine.py          ← Orchestrator; GENERATOR_REGISTRY; create_output()
  generators/
    base.py            ← BaseGenerator ABC
    security_event.py, signin_logs.py, syslog.py, common_security_log.py
    aws_cloudtrail.py, gcp_audit_logs.py, purview_dlp.py, defender_office.py
  models/
    schemas.py         ← Pydantic v2 models for all 8 log types
  outputs/
    base.py            ← BaseOutput ABC
    log_analytics.py   ← Azure Monitor Logs Ingestion adapter (singleton client)
    file.py            ← JSON/CSV file output
    stdout.py          ← Console pretty-print output
  utils/
    exceptions.py      ← Custom exception hierarchy
config/
  config.yaml          ← Active config (never commit secrets)
  config.example.yaml  ← Template for new deployments
infra/
  main.bicep           ← DCE + DCR + 9 custom tables
  workbook.json        ← 11-tab Sentinel workbook (ARM template)
  analytic-rules.json  ← 33 detection rules (ARM template)
brute-force-demo/
  api/function_app.py  ← Azure Function (Python v2, Flex Consumption)
  frontend/            ← Vanilla HTML/CSS/JS SWA
  infra/main.bicep     ← SWA + Function App + BruteForceDemo_CL table
tests/
  test_schemas.py, test_base_generator.py, test_cli.py, test_exceptions.py
```

## log_type → Stream → Table Mapping

| `log_type` (config) | DCR input stream | Sentinel table | Table type |
|---|---|---|---|
| `security_event` | `Custom-SecurityEventDemo_CL` | `SecurityEventDemo_CL` | Custom |
| `signin_logs` | `Custom-SigninLogDemo_CL` | `SigninLogDemo_CL` | Custom |
| `syslog` | `Custom-SyslogDemo_CL` | `SyslogDemo_CL` | Custom |
| `common_security_log` | `Custom-CommonSecurityLogDemo_CL` | `CommonSecurityLogDemo_CL` | Custom |
| `aws_cloudtrail` | `Custom-AWSCloudTrailDemo_CL` | `AWSCloudTrailDemo_CL` | Custom |
| `gcp_audit_logs` | `Custom-GCPAuditLogsDemo_CL` | `GCPAuditLogsDemo_CL` | Custom |
| `purview_dlp` | `Custom-PurviewDLPDemo_CL` | `PurviewDLPDemo_CL` | Custom |
| `defender_office` | `Custom-DefenderOfficeDemo_CL` | `DefenderOfficeDemo_CL` | Custom |
| `common_security_log_native` | `Custom-CommonSecurityLogNative` | `CommonSecurityLog` | **Native** |
| `syslog_native` | `Custom-SyslogNative` | `Syslog` | **Native** |

> **Critical:** `BruteForceDemo_CL` is populated exclusively by the Azure Function in `brute-force-demo/`. There is **no** `brute_force` log_type in `GENERATOR_REGISTRY` or `LOG_TYPE_STREAM_MAP`.

## Active Scenarios (35 total)

| Table | Scenario names |
|---|---|
| `SecurityEventDemo_CL` | `brute_force_login`, `privilege_escalation` |
| `CommonSecurityLog` (native) | `firewall_traffic`, `ids_intrusion_detection`, `threat_intel_matches`, `ubiquiti_firewall_traffic`, `firewall_deny_scan`, `ubiquiti_port_scan`, `ubiquiti_ids_vpn` |
| `SigninLogDemo_CL` | `suspicious_signins`, `brute_force_aad`, `credential_stuffing` |
| `SyslogDemo_CL` | `ssh_brute_force`, `linux_sudo_abuse`, `service_anomalies` |
| `AWSCloudTrailDemo_CL` | `aws_iam_credential_abuse`, `aws_s3_exfiltration`, `aws_security_tampering`, `aws_compute_abuse`, `aws_brute_force_console` |
| `GCPAuditLogsDemo_CL` | `gcp_iam_abuse`, `gcp_data_exfiltration`, `gcp_security_tampering`, `gcp_compute_abuse`, `gcp_brute_force_auth` |
| `PurviewDLPDemo_CL` | `purview_dlp_policy_violation`, `purview_sensitivity_label_downgrade`, `purview_external_sharing`, `purview_bulk_download`, `purview_irm_protection_removed` |
| `DefenderOfficeDemo_CL` | `defender_phishing_detected`, `defender_malicious_url_click`, `defender_user_reported_phish`, `defender_bulk_phishing_campaign`, `defender_safe_attachment_block` |

## How to Add a New Generator

Follow these steps in order:

### 1. Create the generator module

Create `sentinel_data_generator/generators/<log_type>.py` subclassing `BaseGenerator`. Implement a `generate()` method that returns a validated `list[dict]`:

```python
from sentinel_data_generator.generators.base import BaseGenerator

class MyNewGenerator(BaseGenerator):
    """Generates demo events for <table>."""

    def generate(self) -> list[dict]:
        events = []
        for ts in self._distribute_timestamps(self.count):
            event = MyNewSchema(
                TimeGenerated=ts.isoformat(),
                # ... other fields
            )
            events.append(event.model_dump())
        return events
```

### 2. Add the Pydantic schema

Add a model to `sentinel_data_generator/models/schemas.py`:

```python
class MyNewSchema(BaseModel):
    TimeGenerated: str
    # ... all fields matching the DCR stream schema exactly
```

### 3. Register the log_type in the engine

In `sentinel_data_generator/core/engine.py`, add to `GENERATOR_REGISTRY`:

```python
from sentinel_data_generator.generators.my_new import MyNewGenerator

GENERATOR_REGISTRY: dict[str, type[BaseGenerator]] = {
    ...
    "my_new_log_type": MyNewGenerator,
}
```

### 4. Add the stream mapping

In `sentinel_data_generator/core/config.py`, add to `LOG_TYPE_STREAM_MAP`:

```python
LOG_TYPE_STREAM_MAP: dict[str, str] = {
    ...
    "my_new_log_type": "Custom-MyNewDemo_CL",
}
```

### 5. Add the Bicep table + DCR stream

In `infra/main.bicep`, add:
- A custom table resource for `MyNewDemo_CL` with the column schema
- A `streamDeclarations` entry: `Custom-MyNewDemo_CL`
- A `dataFlows` entry routing the stream to the table

### 6. Add scenarios to config.yaml

```yaml
- name: my_new_scenario
  log_type: my_new_log_type
  stream_name: "Custom-MyNewDemo_CL"
  description: "..."
  count: 30
  parameters:
    event_type: "some_type"
```

### 7. Write tests

Add `tests/test_my_new_generator.py`. Mock all Azure SDK calls — never make real API calls in tests.

---

## Key Code Conventions

- **Language:** Python 3.10+, PEP 8, f-strings, `pathlib.Path`
- **Logging:** Use `logging` module only — never `print()`
- **Timestamps:** ISO 8601 UTC — `datetime.now(timezone.utc).isoformat()`
- **Docstrings:** Google style on all public functions/classes
- **Pydantic:** v2 — call `model_dump()` not `.dict()`
- **Faker:** Use for realistic IPs, hostnames, UPNs
- **Demo data safety:** Use `@contoso.com`, `10.0.x.x`, `203.0.113.x` (documentation range), `.example.com` — never real domains or credentials
- **BaseGenerator:** Call `self._distribute_timestamps(self.count)` for sorted, realistic event timing
- **Client reuse:** `LogAnalyticsOutput` is a singleton — do not create a new `LogsIngestionClient` per batch

## Exception Hierarchy

```
SentinelDataGeneratorError
  ├── ConfigurationError    ← invalid/missing config
  ├── AuthenticationError   ← Azure credential failures
  ├── IngestionError        ← data ingestion failures (429 → retry-after)
  └── SchemaValidationError ← Pydantic validation failures
```

Raise specific exceptions. Handle `HttpResponseError` and `ClientAuthenticationError` from the Azure SDK explicitly.

## Authentication

Use `DefaultAzureCredential` — supports Azure CLI (`az login`), managed identity, and environment variables. For the GitHub Actions workflow, authenticate via a Service Principal using:
- `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `AZURE_TENANT_ID` (secrets)
- `SENTINEL_DCE_ENDPOINT`, `SENTINEL_DCR_ID` (secrets)

## Configuration Priority

1. CLI flags (`--output`, `--count`) — highest priority
2. Environment variables (`SENTINEL_DCE_ENDPOINT`, `SENTINEL_DCR_ID`, `SENTINEL_STREAM_NAME`)
3. `config/config.yaml` (active config)
4. `config/config.example.yaml` (template only — the GitHub Actions workflow `cp`s it to `config.yaml`)

## Infrastructure

`infra/main.bicep` deploys:
- 1 Data Collection Endpoint (DCE)
- 1 Data Collection Rule (DCR) covering all 9 custom tables + 2 native table routes
- 9 custom Log Analytics tables (`*Demo_CL` + `BruteForceDemo_CL`)

Deploy with:
```powershell
.\infra\deploy.ps1 -ResourceGroup rg-sentinel-demo -Location eastus
```

Assign the **Monitoring Metrics Publisher** role on the DCR to the identity running the generator.

## Brute Force Demo

Standalone interactive web app — completely separate from the Python CLI:

- `brute-force-demo/api/function_app.py` — Python Azure Function v2 (Flex Consumption), logs via managed identity
- `brute-force-demo/frontend/` — IIFE-based single-page app, `API_URL` auto-detected from hostname
- `brute-force-demo/infra/main.bicep` — deploys SWA + Function App
- PIN is set via `SECRET_PIN` app setting or `secretPin` Bicep parameter
- Toggle public access: `brute-force-demo/infra/toggle-public-access.ps1 on|off`

Table schema: `TimeGenerated`, `Nickname`, `Pincode`, `AttemptResult`, `SourceIP`, `UserAgent`

## Workbook Editing Pattern

`infra/workbook.json` is an ARM template where each panel's content is a JSON string inside `serializedData`. To edit programmatically:
1. Parse the outer ARM JSON
2. Parse the `serializedData` string of the target item
3. Modify the inner object
4. Re-serialize and write back

The Brute Force Demo tab uses the `pack_array` → `mv-expand` → `bag_unpack` KQL pattern to pivot tile metrics.

## Testing

```bash
pytest tests/ -v --cov=sentinel_data_generator
```

- Mock all Azure SDK calls — never make real API calls in tests
- Use pytest fixtures for reusable test data
- Target 80%+ code coverage
- Test files: `test_schemas.py`, `test_base_generator.py`, `test_cli.py`, `test_exceptions.py`

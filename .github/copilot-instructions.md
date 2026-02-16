# Copilot Instructions for Sentinel Data Generator

## Project Overview

This is a **Python CLI tool** that generates realistic demo/test log data for **Microsoft Sentinel**. It simulates security events (sign-ins, Windows security events, syslog, CEF) and sends them to an Azure Log Analytics workspace via the **Azure Monitor Logs Ingestion API** (Data Collection Endpoint + Data Collection Rule), or outputs them locally as JSON/CSV.

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
- The Bicep IaC template (`infra/main.bicep`) defines four custom tables and their DCR streams:
  - `Custom-SecurityEventDemo_CL`
  - `Custom-SigninLogDemo_CL`
  - `Custom-SyslogDemo_CL`
  - `Custom-CommonSecurityLogDemo_CL`

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

# Contributing to Sentinel Data Generator

Thank you for your interest in contributing! This document provides guidelines to help you get started.

## Getting Started

### 1. Fork and Clone

```bash
git clone https://github.com/<your-fork>/Sentinel-Data-Generator.git
cd Sentinel-Data-Generator
```

### 2. Set Up Your Development Environment

```bash
python -m venv .venv

# Windows
.venv\Scripts\activate
# macOS/Linux
source .venv/bin/activate

pip install -r requirements.txt
pip install -r requirements-dev.txt
```

### 3. Verify Your Setup

```bash
python -m pytest -v
ruff check .
```

## Development Workflow

1. **Create a feature branch** from `main`:
   ```bash
   git checkout -b feat/my-new-feature
   ```
2. **Make your changes** following the coding standards below.
3. **Write or update tests** for any new functionality.
4. **Run the full test suite** and linter before committing:
   ```bash
   python -m pytest --cov=sentinel_data_generator
   ruff check .
   ruff format .
   ```
5. **Commit** using [Conventional Commits](https://www.conventionalcommits.org/):
   ```
   feat: add DNS log generator
   fix: correct timestamp format in syslog output
   docs: update README with new scenario examples
   test: add tests for file output adapter
   refactor: simplify base generator interface
   chore: update dependencies
   ```
6. **Push** and open a Pull Request against `main`.

## Coding Standards

### Python Style
- Follow **PEP 8** conventions.
- Use **type hints** on all public function signatures.
- Use **f-strings** for string formatting.
- Use **`pathlib.Path`** instead of `os.path`.
- Use the **`logging`** module — never `print()`.
- Write **Google-style docstrings** for all public classes and functions.

### Project Conventions
- Generators go in `sentinel_data_generator/generators/` and must inherit from `BaseGenerator`.
- New generators must be registered in `GENERATOR_REGISTRY` in `sentinel_data_generator/core/engine.py`.
- Pydantic models for log schemas go in `sentinel_data_generator/models/schemas.py`.
- Output adapters go in `sentinel_data_generator/outputs/` and must inherit from `BaseOutput`.
- Config loading and Pydantic config models are in `sentinel_data_generator/core/config.py`.
- Custom exceptions go in `sentinel_data_generator/utils/exceptions.py`.
- Config/scenario YAML files go in `config/`.
- Tests mirror the source structure under `tests/` and are named `test_<module>.py`.

### Security
- **Never** commit real credentials, tokens, or secrets.
- Use obviously fake demo values (e.g., `user@contoso.com`, `203.0.113.x` documentation IPs).
- Sensitive configuration must come from environment variables.

## Adding a New Log Type Generator

1. **Add a Pydantic schema** in `sentinel_data_generator/models/schemas.py` with fields matching the DCR stream schema.
2. **Create a generator module** in `sentinel_data_generator/generators/` (e.g., `syslog.py`).
3. **Subclass `BaseGenerator`** and implement the `generate()` method:
   - Accept `count` and `time_range` parameters.
   - Use `self._distribute_timestamps()` for realistic time distribution.
   - Use `self.scenario` dict for scenario-specific parameters.
   - Validate events through the Pydantic model and return `list[dict]` via `model.model_dump(mode="json")`.
4. **Register the generator** in `GENERATOR_REGISTRY` in `sentinel_data_generator/core/engine.py`:
   ```python
   from sentinel_data_generator.generators.syslog import SyslogGenerator
   
   GENERATOR_REGISTRY: dict[str, type[BaseGenerator]] = {
       "security_event": SecurityEventGenerator,
       "syslog": SyslogGenerator,  # ← add here
   }
   ```
5. **Add the stream mapping** in `LOG_TYPE_STREAM_MAP` in `sentinel_data_generator/core/config.py` (already pre-populated for the four base types).
6. **Write tests** in `tests/test_<generator>.py`.
7. **Update `README.md`** to list the new supported log type.

### Example: Minimal Generator

```python
"""Syslog event generator."""

from sentinel_data_generator.generators.base import BaseGenerator
from sentinel_data_generator.models.schemas import SyslogEvent

class SyslogGenerator(BaseGenerator):
    def generate(self, count, time_range):
        timestamps = self._distribute_timestamps(count, *time_range)
        events = []
        for ts in timestamps:
            event = SyslogEvent(
                TimeGenerated=ts,
                Computer=self.scenario.get("host", self.faker.hostname()),
                HostIP=self.faker.ipv4_private(),
                Facility="auth",
                SeverityLevel="warning",
                ProcessName="sshd",
                SyslogMessage=f"Failed password for root from {self.faker.ipv4_public()}",
            )
            events.append(event.model_dump(mode="json"))
        return events
```

## Adding a New Output Adapter

1. Create a module in `sentinel_data_generator/outputs/` (e.g., `webhook.py`).
2. Subclass `BaseOutput` and implement the `send(events, stream_name)` method.
3. Register the adapter in `create_output()` in `sentinel_data_generator/core/engine.py`.
4. Add any new config fields to `OutputConfig` in `sentinel_data_generator/core/config.py`.
5. Write tests with mocked external calls.

## Adding a New Scenario

1. Add a new entry to the `scenarios` list in your `config/config.yaml`.
2. Set the `log_type` to match a registered generator.
3. Provide generator-specific `parameters`.
4. Optionally override `stream_name` and `count`.

```yaml
scenarios:
  - name: ssh_brute_force
    log_type: syslog
    stream_name: "Custom-SyslogDemo_CL"
    description: "Simulate SSH brute-force attempts"
    count: 100
    parameters:
      host: "web-svr01.contoso.com"
      facility: "auth"
      severity: "warning"
```

## Testing

- All tests use **pytest**.
- Use **fixtures** for reusable test data.
- **Mock all Azure SDK calls** — never make real API calls in tests.
- Aim for **80%+ code coverage**.
- Current test suite: 38 tests across 4 files.
- Run tests: `python -m pytest --cov=sentinel_data_generator -v`

## Pull Request Checklist

- [ ] Code follows project style conventions
- [ ] Type hints added to public functions
- [ ] Docstrings written for public classes/functions
- [ ] Tests added/updated with adequate coverage
- [ ] `ruff check .` passes with no errors
- [ ] `ruff format .` applied
- [ ] All tests pass (`python -m pytest`)
- [ ] New generator is registered in `GENERATOR_REGISTRY`
- [ ] Commit messages follow Conventional Commits
- [ ] No credentials or secrets in code or config

## Reporting Issues

- Use GitHub Issues to report bugs or request features.
- Include steps to reproduce, expected vs. actual behavior, and your environment details.

## Code of Conduct

Be respectful, inclusive, and constructive. We follow the [Contributor Covenant](https://www.contributor-covenant.org/) code of conduct.

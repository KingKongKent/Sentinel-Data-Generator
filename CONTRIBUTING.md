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
python -m pytest
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
- Pydantic models for log schemas go in `sentinel_data_generator/models/schemas.py`.
- Output adapters go in `sentinel_data_generator/outputs/`.
- Config/scenario YAML files go in `config/`.
- Tests mirror the source structure under `tests/` and are named `test_<module>.py`.

### Security
- **Never** commit real credentials, tokens, or secrets.
- Use obviously fake demo values (e.g., `user@contoso.com`, `10.0.0.x`).
- Sensitive configuration must come from environment variables.

## Adding a New Log Type Generator

1. Create a new module in `sentinel_data_generator/generators/` (e.g., `dns_logs.py`).
2. Create a class that inherits from `BaseGenerator`.
3. Implement the required `generate()` method.
4. Add Pydantic schema models in `sentinel_data_generator/models/schemas.py`.
5. Register the generator in the engine/config loader.
6. Add corresponding tests in `tests/`.
7. Update `README.md` with the new supported log type.

## Adding a New Scenario

1. Create a YAML file in `config/scenarios/`.
2. Define scenario parameters (attacker IPs, target users, event distribution, etc.).
3. Ensure the scenario is validated by the config Pydantic model.
4. Add tests for the scenario.

## Testing

- All tests use **pytest**.
- Use **fixtures** for reusable test data.
- **Mock all Azure SDK calls** — never make real API calls in tests.
- Aim for **80%+ code coverage**.
- Run tests: `python -m pytest --cov=sentinel_data_generator`

## Pull Request Checklist

- [ ] Code follows project style conventions
- [ ] Type hints added to public functions
- [ ] Docstrings written for public classes/functions
- [ ] Tests added/updated with adequate coverage
- [ ] `ruff check .` passes with no errors
- [ ] `ruff format .` applied
- [ ] All tests pass (`python -m pytest`)
- [ ] Commit messages follow Conventional Commits
- [ ] No credentials or secrets in code or config

## Reporting Issues

- Use GitHub Issues to report bugs or request features.
- Include steps to reproduce, expected vs. actual behavior, and your environment details.

## Code of Conduct

Be respectful, inclusive, and constructive. We follow the [Contributor Covenant](https://www.contributor-covenant.org/) code of conduct.

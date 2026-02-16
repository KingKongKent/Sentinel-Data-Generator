"""Configuration loader with Pydantic validation and env-var overrides."""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, field_validator

from sentinel_data_generator.utils.exceptions import ConfigurationError

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Pydantic config models
# ---------------------------------------------------------------------------


class AzureConfig(BaseModel):
    """Azure Data Collection settings."""

    dce_endpoint: str = Field(..., description="Data Collection Endpoint URL")
    dcr_id: str = Field(..., description="Data Collection Rule immutable ID")
    stream_name: str = Field(
        "Custom-SecurityEventDemo_CL",
        description="Default DCR stream name (can be overridden per scenario)",
    )


class OutputConfig(BaseModel):
    """Output target settings."""

    type: str = Field("stdout", description="Output type: log_analytics | file | stdout")
    file_path: str | None = Field(None, description="File path for file output")
    file_format: str = Field("json", description="File format: json | csv")

    @field_validator("type")
    @classmethod
    def validate_type(cls, v: str) -> str:
        """Validate the output type."""
        allowed = {"log_analytics", "file", "stdout"}
        if v not in allowed:
            raise ValueError(f"output.type must be one of {allowed}, got '{v}'")
        return v


class TimeRangeConfig(BaseModel):
    """Time range settings."""

    start: str = Field(..., description="ISO 8601 start datetime (UTC)")
    end: str = Field(..., description="ISO 8601 end datetime (UTC)")


class GenerationConfig(BaseModel):
    """Global generation settings."""

    count: int = Field(100, description="Default event count per scenario")
    time_range: TimeRangeConfig
    seed: int | None = Field(None, description="Random seed for reproducibility")


class ScenarioConfig(BaseModel):
    """A single scenario definition."""

    name: str = Field(..., description="Scenario name")
    log_type: str = Field(..., description="Log type: security_event | signin_logs | syslog | common_security_log")
    description: str = Field("", description="Human-readable description")
    stream_name: str | None = Field(None, description="Override stream name for this scenario")
    parameters: dict[str, Any] = Field(default_factory=dict, description="Generator-specific parameters")
    count: int | None = Field(None, description="Override event count for this scenario")


class AppConfig(BaseModel):
    """Top-level application configuration."""

    azure: AzureConfig
    output: OutputConfig = Field(default_factory=lambda: OutputConfig(type="stdout"))
    generation: GenerationConfig
    scenarios: list[ScenarioConfig] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Mapping of log_type string → DCR stream name (defaults)
# ---------------------------------------------------------------------------

LOG_TYPE_STREAM_MAP: dict[str, str] = {
    "security_event": "Custom-SecurityEventDemo_CL",
    "signin_logs": "Custom-SigninLogDemo_CL",
    "syslog": "Custom-SyslogDemo_CL",
    "common_security_log": "Custom-CommonSecurityLogDemo_CL",
    "common_security_log_native": "Custom-CommonSecurityLogNative",
}


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------


def load_config(config_path: Path, overrides: dict[str, Any] | None = None) -> AppConfig:
    """Load and validate configuration from a YAML file.

    Environment variables override YAML values:
        SENTINEL_DCE_ENDPOINT → azure.dce_endpoint
        SENTINEL_DCR_ID       → azure.dcr_id
        SENTINEL_STREAM_NAME  → azure.stream_name

    Args:
        config_path: Path to the YAML configuration file.
        overrides: Optional dict of CLI overrides (output, count).

    Returns:
        Validated AppConfig instance.

    Raises:
        ConfigurationError: If the file is missing, malformed, or validation fails.
    """
    overrides = overrides or {}

    if not config_path.exists():
        raise ConfigurationError(f"Configuration file not found: {config_path}")

    try:
        raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ConfigurationError(f"Failed to parse YAML config: {exc}") from exc

    if not isinstance(raw, dict):
        raise ConfigurationError("Config file must contain a YAML mapping at the top level.")

    # Apply environment variable overrides
    azure_section = raw.setdefault("azure", {})
    _env_override(azure_section, "dce_endpoint", "SENTINEL_DCE_ENDPOINT")
    _env_override(azure_section, "dcr_id", "SENTINEL_DCR_ID")
    _env_override(azure_section, "stream_name", "SENTINEL_STREAM_NAME")

    # Apply CLI overrides
    if overrides.get("output"):
        raw.setdefault("output", {})["type"] = overrides["output"]
    if overrides.get("count") is not None:
        raw.setdefault("generation", {})["count"] = overrides["count"]

    try:
        config = AppConfig.model_validate(raw)
    except Exception as exc:
        raise ConfigurationError(f"Configuration validation failed: {exc}") from exc

    logger.info("Configuration loaded from %s", config_path)
    logger.debug("Output type: %s", config.output.type)
    logger.debug("Scenarios: %d", len(config.scenarios))
    return config


def resolve_stream_name(scenario: ScenarioConfig, default_stream: str) -> str:
    """Resolve the DCR stream name for a scenario.

    Priority: scenario.stream_name > LOG_TYPE_STREAM_MAP > azure.stream_name default.

    Args:
        scenario: The scenario configuration.
        default_stream: The default stream from azure config.

    Returns:
        Resolved stream name.
    """
    if scenario.stream_name:
        return scenario.stream_name
    return LOG_TYPE_STREAM_MAP.get(scenario.log_type, default_stream)


def _env_override(section: dict[str, Any], key: str, env_var: str) -> None:
    """Override a config value from an environment variable if set.

    Args:
        section: The config section dictionary.
        key: The key to override.
        env_var: The environment variable name.
    """
    value = os.environ.get(env_var)
    if value:
        logger.debug("Overriding config '%s' from env var '%s'", key, env_var)
        section[key] = value

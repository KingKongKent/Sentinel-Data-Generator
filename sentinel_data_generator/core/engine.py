"""Core engine that orchestrates generation and output."""

from __future__ import annotations

import datetime
import logging
from typing import Any

from sentinel_data_generator.core.config import (
    AppConfig,
    ScenarioConfig,
    resolve_stream_name,
)
from sentinel_data_generator.generators.base import BaseGenerator
from sentinel_data_generator.generators.security_event import SecurityEventGenerator
from sentinel_data_generator.outputs.base import BaseOutput
from sentinel_data_generator.outputs.file import FileOutput
from sentinel_data_generator.outputs.log_analytics import LogAnalyticsOutput
from sentinel_data_generator.outputs.stdout import StdoutOutput
from sentinel_data_generator.utils.exceptions import ConfigurationError

logger = logging.getLogger(__name__)

# Registry: log_type string → generator class
GENERATOR_REGISTRY: dict[str, type[BaseGenerator]] = {
    "security_event": SecurityEventGenerator,
    # TODO: Add more generators as they are implemented
    # "signin_logs": SigninLogGenerator,
    # "syslog": SyslogGenerator,
    # "common_security_log": CommonSecurityLogGenerator,
}


def create_output(config: AppConfig) -> BaseOutput:
    """Create the appropriate output adapter from config.

    Args:
        config: Validated application configuration.

    Returns:
        An output adapter instance.

    Raises:
        ConfigurationError: If the output type is unsupported or misconfigured.
    """
    output_type = config.output.type

    if output_type == "stdout":
        return StdoutOutput(pretty=True)

    if output_type == "file":
        if not config.output.file_path:
            raise ConfigurationError("output.file_path is required when output.type is 'file'")
        return FileOutput(
            file_path=config.output.file_path,
            file_format=config.output.file_format,
        )

    if output_type == "log_analytics":
        return LogAnalyticsOutput(
            dce_endpoint=config.azure.dce_endpoint,
            dcr_id=config.azure.dcr_id,
        )

    raise ConfigurationError(f"Unknown output type: '{output_type}'")


def create_generator(scenario: ScenarioConfig, seed: int | None = None) -> BaseGenerator:
    """Create a generator instance for the given scenario.

    Args:
        scenario: The scenario configuration.
        seed: Optional random seed.

    Returns:
        A generator instance.

    Raises:
        ConfigurationError: If the log_type is not registered.
    """
    generator_cls = GENERATOR_REGISTRY.get(scenario.log_type)
    if generator_cls is None:
        supported = ", ".join(sorted(GENERATOR_REGISTRY.keys()))
        raise ConfigurationError(
            f"Unknown log_type '{scenario.log_type}'. "
            f"Supported types: {supported}"
        )
    return generator_cls(scenario=scenario.parameters, seed=seed)


def run(config: AppConfig) -> dict[str, Any]:
    """Run all scenarios defined in the configuration.

    For each scenario:
      1. Creates a generator.
      2. Generates events.
      3. Sends events to the output adapter.

    Args:
        config: Validated application configuration.

    Returns:
        Summary dict with per-scenario counts.
    """
    output = create_output(config)
    summary: dict[str, Any] = {"scenarios": {}, "total_events": 0}

    # Parse time range
    gen_config = config.generation
    try:
        start = datetime.datetime.fromisoformat(gen_config.time_range.start)
        end = datetime.datetime.fromisoformat(gen_config.time_range.end)
    except ValueError as exc:
        raise ConfigurationError(f"Invalid time_range format: {exc}") from exc

    time_range = (start, end)

    for scenario in config.scenarios:
        logger.info("--- Running scenario: %s (%s) ---", scenario.name, scenario.log_type)

        # Determine event count (scenario override → global default)
        count = scenario.count or scenario.parameters.get("count") or gen_config.count

        # Resolve stream name
        stream_name = resolve_stream_name(scenario, config.azure.stream_name)

        try:
            generator = create_generator(scenario, seed=gen_config.seed)
            events = generator.generate(count=count, time_range=time_range)
            output.send(events, stream_name=stream_name)

            summary["scenarios"][scenario.name] = {
                "log_type": scenario.log_type,
                "stream_name": stream_name,
                "events_generated": len(events),
                "status": "success",
            }
            summary["total_events"] += len(events)

        except Exception as exc:
            logger.error("Scenario '%s' failed: %s", scenario.name, exc)
            summary["scenarios"][scenario.name] = {
                "log_type": scenario.log_type,
                "events_generated": 0,
                "status": f"error: {exc}",
            }

    # Clean up
    if hasattr(output, "close"):
        output.close()

    logger.info("=== Generation complete. Total events: %d ===", summary["total_events"])
    return summary

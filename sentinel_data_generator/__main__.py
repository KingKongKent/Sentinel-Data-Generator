"""CLI entry point for Sentinel Data Generator."""

import argparse
import logging
import sys
from pathlib import Path

from sentinel_data_generator.core.config import load_config
from sentinel_data_generator.core.engine import run
from sentinel_data_generator.utils.exceptions import (
    ConfigurationError,
    SentinelDataGeneratorError,
)

logger = logging.getLogger(__name__)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments.

    Args:
        argv: Optional list of arguments (defaults to sys.argv).

    Returns:
        Parsed arguments namespace.
    """
    parser = argparse.ArgumentParser(
        prog="sentinel-data-generator",
        description="Generate realistic demo log data for Microsoft Sentinel.",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("config/config.yaml"),
        help="Path to YAML configuration file (default: config/config.yaml)",
    )
    parser.add_argument(
        "--output",
        choices=["log_analytics", "file", "stdout"],
        default=None,
        help="Override output target from config",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=None,
        help="Override number of events to generate per scenario",
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="Set logging level (default: INFO)",
    )
    return parser.parse_args(argv)


def configure_logging(level: str) -> None:
    """Configure the root logger.

    Args:
        level: Logging level string (DEBUG, INFO, WARNING, ERROR).
    """
    logging.basicConfig(
        level=getattr(logging, level),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )


def main(argv: list[str] | None = None) -> int:
    """Main entry point for the CLI.

    Args:
        argv: Optional list of arguments.

    Returns:
        Exit code (0 for success, non-zero for failure).
    """
    args = parse_args(argv)
    configure_logging(args.log_level)

    logger.info("Sentinel Data Generator v%s starting", "0.1.0")
    logger.info("Config file: %s", args.config)

    try:
        # Build CLI overrides dict
        overrides = {}
        if args.output:
            overrides["output"] = args.output
        if args.count is not None:
            overrides["count"] = args.count

        # Load and validate configuration
        config = load_config(args.config, overrides=overrides)

        if not config.scenarios:
            logger.warning("No scenarios defined in config — nothing to do.")
            return 0

        # Run all scenarios
        summary = run(config)

        # Report results
        for name, info in summary["scenarios"].items():
            status = info["status"]
            count = info["events_generated"]
            if status == "success":
                logger.info("  ✓ %s: %d events sent", name, count)
            else:
                logger.error("  ✗ %s: %s", name, status)

        # Return non-zero if any scenario failed
        failed = [n for n, i in summary["scenarios"].items() if i["status"] != "success"]
        if failed:
            logger.error("%d scenario(s) failed: %s", len(failed), ", ".join(failed))
            return 1

        return 0

    except ConfigurationError as exc:
        logger.error("Configuration error: %s", exc)
        return 2
    except SentinelDataGeneratorError as exc:
        logger.error("Error: %s", exc)
        return 1
    except KeyboardInterrupt:
        logger.info("Interrupted by user.")
        return 130


if __name__ == "__main__":
    sys.exit(main())

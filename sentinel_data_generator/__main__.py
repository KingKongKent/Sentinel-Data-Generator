"""CLI entry point for Sentinel Data Generator."""

import argparse
import logging
import sys
from pathlib import Path


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

    # TODO: Load config, initialize engine, run generation
    logger.warning("Not yet implemented — scaffolding only.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

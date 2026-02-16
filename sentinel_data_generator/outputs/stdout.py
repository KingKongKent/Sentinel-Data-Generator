"""Stdout output adapter for local debugging and preview."""

from __future__ import annotations

import json
import logging
from typing import Any

from sentinel_data_generator.outputs.base import BaseOutput

logger = logging.getLogger(__name__)


class StdoutOutput(BaseOutput):
    """Output adapter that prints events to stdout as JSON.

    Useful for debugging, previewing generated data, and piping to files.
    """

    def __init__(self, pretty: bool = True) -> None:
        """Initialize the stdout output adapter.

        Args:
            pretty: Whether to pretty-print JSON (default: True).
        """
        self.pretty = pretty

    def send(self, events: list[dict[str, Any]], stream_name: str) -> None:
        """Print events to stdout as JSON.

        Args:
            events: List of event dictionaries to print.
            stream_name: The target stream name (logged but not used).
        """
        indent = 2 if self.pretty else None
        logger.info("Writing %d events for stream '%s' to stdout", len(events), stream_name)
        print(json.dumps(events, indent=indent, default=str))

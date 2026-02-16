"""File output adapter for writing events to JSON or CSV files."""

from __future__ import annotations

import csv
import json
import logging
from pathlib import Path
from typing import Any

from sentinel_data_generator.outputs.base import BaseOutput

logger = logging.getLogger(__name__)


class FileOutput(BaseOutput):
    """Output adapter that writes events to a local file.

    Supports JSON and CSV formats.
    """

    def __init__(self, file_path: str | Path, file_format: str = "json") -> None:
        """Initialize the file output adapter.

        Args:
            file_path: Path to the output file.
            file_format: Output format — 'json' or 'csv'.
        """
        self.file_path = Path(file_path)
        self.file_format = file_format.lower()
        if self.file_format not in ("json", "csv"):
            raise ValueError(f"Unsupported file format: '{file_format}'. Use 'json' or 'csv'.")

    def send(self, events: list[dict[str, Any]], stream_name: str) -> None:
        """Write events to a file.

        Args:
            events: List of event dictionaries to write.
            stream_name: The target stream name (used in logging).
        """
        if not events:
            logger.warning("No events to write — skipping.")
            return

        # Ensure parent directory exists
        self.file_path.parent.mkdir(parents=True, exist_ok=True)

        if self.file_format == "json":
            self._write_json(events)
        else:
            self._write_csv(events)

        logger.info(
            "Wrote %d events for stream '%s' to %s",
            len(events),
            stream_name,
            self.file_path,
        )

    def _write_json(self, events: list[dict[str, Any]]) -> None:
        """Write events as a JSON array."""
        with self.file_path.open("w", encoding="utf-8") as fh:
            json.dump(events, fh, indent=2, default=str)

    def _write_csv(self, events: list[dict[str, Any]]) -> None:
        """Write events as CSV with headers from the first event's keys."""
        if not events:
            return
        fieldnames = list(events[0].keys())
        with self.file_path.open("w", encoding="utf-8", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(events)

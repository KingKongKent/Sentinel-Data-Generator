"""Base output adapter interface."""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import Any

logger = logging.getLogger(__name__)


class BaseOutput(ABC):
    """Abstract base class for output adapters.

    All output adapters must inherit from this class and implement
    the `send` method.
    """

    @abstractmethod
    def send(self, events: list[dict[str, Any]], stream_name: str) -> None:
        """Send a batch of events to the output target.

        Args:
            events: List of event dictionaries to send.
            stream_name: The target stream/table name.
        """
        ...

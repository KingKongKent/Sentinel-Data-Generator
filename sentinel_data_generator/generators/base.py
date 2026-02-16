"""Base generator class for all log type generators."""

from __future__ import annotations

import datetime
import logging
import random
from abc import ABC, abstractmethod
from typing import Any

from faker import Faker


logger = logging.getLogger(__name__)


class BaseGenerator(ABC):
    """Abstract base class for log event generators.

    All log type generators must inherit from this class and implement
    the `generate` method.

    Attributes:
        faker: Faker instance for generating realistic fake data.
        scenario: Scenario configuration dictionary.
    """

    def __init__(self, scenario: dict[str, Any] | None = None, seed: int | None = None) -> None:
        """Initialize the base generator.

        Args:
            scenario: Optional scenario configuration dictionary.
            seed: Optional random seed for reproducible output.
        """
        self.faker = Faker()
        if seed is not None:
            Faker.seed(seed)
            random.seed(seed)
        self.scenario = scenario or {}

    @abstractmethod
    def generate(self, count: int, time_range: tuple[datetime.datetime, datetime.datetime]) -> list[dict[str, Any]]:
        """Generate a list of log events.

        Args:
            count: Number of events to generate.
            time_range: Tuple of (start, end) datetimes in UTC for the event window.

        Returns:
            List of dictionaries, each representing a single log event.
        """
        ...

    def _random_timestamp(
        self,
        start: datetime.datetime,
        end: datetime.datetime,
    ) -> str:
        """Generate a random ISO 8601 UTC timestamp within the given range.

        Args:
            start: Start of the time range (UTC).
            end: End of the time range (UTC).

        Returns:
            ISO 8601 formatted timestamp string.
        """
        delta = end - start
        random_seconds = random.uniform(0, delta.total_seconds())
        ts = start + datetime.timedelta(seconds=random_seconds)
        return ts.isoformat()

    def _distribute_timestamps(
        self,
        count: int,
        start: datetime.datetime,
        end: datetime.datetime,
    ) -> list[str]:
        """Generate a sorted list of random timestamps within the range.

        Args:
            count: Number of timestamps to generate.
            start: Start of the time range (UTC).
            end: End of the time range (UTC).

        Returns:
            Sorted list of ISO 8601 timestamp strings.
        """
        timestamps = [self._random_timestamp(start, end) for _ in range(count)]
        timestamps.sort()
        return timestamps

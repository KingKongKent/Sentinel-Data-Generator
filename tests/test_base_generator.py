"""Tests for the BaseGenerator abstract class."""

import datetime
from typing import Any

import pytest

from sentinel_data_generator.generators.base import BaseGenerator


# Concrete implementation for testing
class _StubGenerator(BaseGenerator):
    """Minimal concrete generator for testing BaseGenerator functionality."""

    def generate(
        self,
        count: int,
        time_range: tuple[datetime.datetime, datetime.datetime],
    ) -> list[dict[str, Any]]:
        timestamps = self._distribute_timestamps(count, time_range[0], time_range[1])
        return [{"TimeGenerated": ts, "index": i} for i, ts in enumerate(timestamps)]


START = datetime.datetime(2026, 2, 15, 0, 0, 0, tzinfo=datetime.timezone.utc)
END = datetime.datetime(2026, 2, 16, 0, 0, 0, tzinfo=datetime.timezone.utc)


class TestBaseGeneratorInit:
    """Tests for BaseGenerator initialization."""

    def test_default_init(self) -> None:
        gen = _StubGenerator()
        assert gen.scenario == {}
        assert gen.faker is not None

    def test_init_with_scenario(self) -> None:
        scenario = {"target_host": "DC01", "source_ip": "10.0.0.1"}
        gen = _StubGenerator(scenario=scenario)
        assert gen.scenario == scenario

    def test_init_with_seed_is_reproducible(self) -> None:
        gen = _StubGenerator(seed=42)
        events = gen.generate(5, (START, END))
        assert len(events) == 5
        # Verify timestamps are sorted (deterministic ordering from seed)
        timestamps = [e["TimeGenerated"] for e in events]
        assert timestamps == sorted(timestamps)


class TestRandomTimestamp:
    """Tests for _random_timestamp method."""

    def test_timestamp_within_range(self) -> None:
        gen = _StubGenerator(seed=99)
        for _ in range(50):
            ts_str = gen._random_timestamp(START, END)
            ts = datetime.datetime.fromisoformat(ts_str)
            assert START <= ts <= END

    def test_returns_iso_format(self) -> None:
        gen = _StubGenerator(seed=1)
        ts_str = gen._random_timestamp(START, END)
        # Should not raise
        datetime.datetime.fromisoformat(ts_str)


class TestDistributeTimestamps:
    """Tests for _distribute_timestamps method."""

    def test_returns_correct_count(self) -> None:
        gen = _StubGenerator(seed=10)
        timestamps = gen._distribute_timestamps(20, START, END)
        assert len(timestamps) == 20

    def test_timestamps_are_sorted(self) -> None:
        gen = _StubGenerator(seed=10)
        timestamps = gen._distribute_timestamps(100, START, END)
        assert timestamps == sorted(timestamps)

    def test_zero_count(self) -> None:
        gen = _StubGenerator(seed=10)
        timestamps = gen._distribute_timestamps(0, START, END)
        assert timestamps == []


class TestGenerate:
    """Tests for the generate method via _StubGenerator."""

    def test_generate_returns_list(self) -> None:
        gen = _StubGenerator(seed=1)
        events = gen.generate(10, (START, END))
        assert isinstance(events, list)
        assert len(events) == 10

    def test_generate_events_have_expected_keys(self) -> None:
        gen = _StubGenerator(seed=1)
        events = gen.generate(5, (START, END))
        for event in events:
            assert "TimeGenerated" in event
            assert "index" in event

    def test_cannot_instantiate_abstract_base(self) -> None:
        with pytest.raises(TypeError):
            BaseGenerator()  # type: ignore[abstract]

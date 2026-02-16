"""Tests for custom exception classes."""

import pytest

from sentinel_data_generator.utils.exceptions import (
    AuthenticationError,
    ConfigurationError,
    IngestionError,
    SchemaValidationError,
    SentinelDataGeneratorError,
)


class TestExceptionHierarchy:
    """Tests that all custom exceptions inherit from the base."""

    @pytest.mark.parametrize(
        "exc_class",
        [
            ConfigurationError,
            AuthenticationError,
            IngestionError,
            SchemaValidationError,
        ],
    )
    def test_inherits_from_base(self, exc_class: type) -> None:
        assert issubclass(exc_class, SentinelDataGeneratorError)

    def test_base_inherits_from_exception(self) -> None:
        assert issubclass(SentinelDataGeneratorError, Exception)

    @pytest.mark.parametrize(
        "exc_class",
        [
            ConfigurationError,
            AuthenticationError,
            IngestionError,
            SchemaValidationError,
        ],
    )
    def test_can_raise_and_catch(self, exc_class: type) -> None:
        with pytest.raises(SentinelDataGeneratorError):
            raise exc_class("test message")

    def test_exception_message_preserved(self) -> None:
        msg = "Config file not found"
        exc = ConfigurationError(msg)
        assert str(exc) == msg

"""Custom exception classes for Sentinel Data Generator."""


class SentinelDataGeneratorError(Exception):
    """Base exception for all Sentinel Data Generator errors."""


class ConfigurationError(SentinelDataGeneratorError):
    """Raised when configuration is invalid or missing."""


class AuthenticationError(SentinelDataGeneratorError):
    """Raised when Azure authentication fails."""


class IngestionError(SentinelDataGeneratorError):
    """Raised when data ingestion to Log Analytics fails."""


class SchemaValidationError(SentinelDataGeneratorError):
    """Raised when generated data does not conform to the expected schema."""

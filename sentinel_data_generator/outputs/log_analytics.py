"""Log Analytics output adapter using Azure Monitor Ingestion SDK."""

from __future__ import annotations

import logging
import time
from typing import Any

from azure.core.exceptions import HttpResponseError
from azure.identity import DefaultAzureCredential
from azure.monitor.ingestion import LogsIngestionClient

from sentinel_data_generator.outputs.base import BaseOutput
from sentinel_data_generator.utils.exceptions import AuthenticationError, IngestionError

logger = logging.getLogger(__name__)

# Maximum batch size recommended by the Logs Ingestion API
MAX_BATCH_SIZE = 500
MAX_RETRIES = 3


class LogAnalyticsOutput(BaseOutput):
    """Output adapter that sends events to Azure Log Analytics via the Data Collection API.

    Uses DefaultAzureCredential for authentication and the LogsIngestionClient
    for sending data through a Data Collection Endpoint (DCE) / Data Collection
    Rule (DCR).

    Attributes:
        dce_endpoint: The Data Collection Endpoint URL.
        dcr_id: The immutable ID of the Data Collection Rule.
    """

    def __init__(self, dce_endpoint: str, dcr_id: str) -> None:
        """Initialize the Log Analytics output adapter.

        Args:
            dce_endpoint: The DCE endpoint URL.
            dcr_id: The DCR immutable ID (e.g., dcr-...).
        """
        self.dce_endpoint = dce_endpoint
        self.dcr_id = dcr_id
        self._client: LogsIngestionClient | None = None
        self._credential: DefaultAzureCredential | None = None

    def _get_client(self) -> LogsIngestionClient:
        """Get or create a singleton LogsIngestionClient.

        Returns:
            A LogsIngestionClient instance.

        Raises:
            AuthenticationError: If Azure credential acquisition fails.
        """
        if self._client is None:
            try:
                self._credential = DefaultAzureCredential()
                self._client = LogsIngestionClient(
                    endpoint=self.dce_endpoint,
                    credential=self._credential,
                    logging_enable=False,
                )
                logger.debug("Created LogsIngestionClient for endpoint: %s", self.dce_endpoint)
            except Exception as exc:
                raise AuthenticationError(
                    f"Failed to create Azure credential or ingestion client: {exc}"
                ) from exc
        return self._client

    def send(self, events: list[dict[str, Any]], stream_name: str) -> None:
        """Send events to Log Analytics via the Logs Ingestion API.

        Events are batched into chunks of MAX_BATCH_SIZE. Retries are
        performed on HTTP 429 (Too Many Requests) with backoff.

        Args:
            events: List of event dictionaries to send.
            stream_name: The DCR stream name (e.g., Custom-SecurityEventDemo_CL).

        Raises:
            IngestionError: If sending fails after retries.
        """
        if not events:
            logger.warning("No events to send — skipping.")
            return

        client = self._get_client()
        total_sent = 0

        # Send in batches
        for batch_start in range(0, len(events), MAX_BATCH_SIZE):
            batch = events[batch_start : batch_start + MAX_BATCH_SIZE]
            batch_num = (batch_start // MAX_BATCH_SIZE) + 1
            self._send_batch_with_retry(client, batch, stream_name, batch_num)
            total_sent += len(batch)

        logger.info(
            "Successfully sent %d events to stream '%s' via DCR '%s'",
            total_sent,
            stream_name,
            self.dcr_id,
        )

    def _send_batch_with_retry(
        self,
        client: LogsIngestionClient,
        batch: list[dict[str, Any]],
        stream_name: str,
        batch_num: int,
    ) -> None:
        """Send a single batch with retry logic for 429 responses.

        Args:
            client: The LogsIngestionClient instance.
            batch: List of event dictionaries.
            stream_name: The DCR stream name.
            batch_num: Batch number for logging.

        Raises:
            IngestionError: If all retries are exhausted or a non-retryable error occurs.
        """
        for attempt in range(1, MAX_RETRIES + 1):
            try:
                logger.debug(
                    "Sending batch %d (%d events) to stream '%s' (attempt %d/%d)",
                    batch_num,
                    len(batch),
                    stream_name,
                    attempt,
                    MAX_RETRIES,
                )
                client.upload(
                    rule_id=self.dcr_id,
                    stream_name=stream_name,
                    logs=batch,
                )
                logger.debug("Batch %d sent successfully", batch_num)
                return
            except HttpResponseError as exc:
                if exc.status_code == 429:
                    retry_after = _parse_retry_after(exc)
                    logger.warning(
                        "Rate limited (429) on batch %d. Retrying after %ds (attempt %d/%d)",
                        batch_num,
                        retry_after,
                        attempt,
                        MAX_RETRIES,
                    )
                    time.sleep(retry_after)
                else:
                    raise IngestionError(
                        f"Failed to send batch {batch_num} to '{stream_name}': "
                        f"HTTP {exc.status_code} — {exc.message}"
                    ) from exc
            except Exception as exc:
                raise IngestionError(
                    f"Unexpected error sending batch {batch_num}: {exc}"
                ) from exc

        raise IngestionError(
            f"Exhausted {MAX_RETRIES} retries for batch {batch_num} to stream '{stream_name}'"
        )

    def close(self) -> None:
        """Close the underlying client and credential."""
        if self._client is not None:
            self._client.close()
            self._client = None
        if self._credential is not None:
            self._credential.close()
            self._credential = None
        logger.debug("LogAnalyticsOutput client closed")


def _parse_retry_after(exc: HttpResponseError) -> int:
    """Extract retry-after seconds from an HTTP 429 response.

    Args:
        exc: The HttpResponseError to extract retry-after from.

    Returns:
        Number of seconds to wait before retrying (default 5).
    """
    try:
        if exc.response and exc.response.headers:
            retry_val = exc.response.headers.get("Retry-After", "5")
            return int(retry_val)
    except (ValueError, AttributeError):
        pass
    return 5

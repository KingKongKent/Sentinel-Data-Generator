"""SecurityEvent generator for Windows Security log events."""

from __future__ import annotations

import datetime
import logging
import random
from typing import Any

from sentinel_data_generator.generators.base import BaseGenerator
from sentinel_data_generator.models.schemas import SecurityEvent

logger = logging.getLogger(__name__)

# Realistic Windows Security Event definitions
EVENT_DEFINITIONS: dict[int, dict[str, Any]] = {
    4624: {
        "activity": "4624 - An account was successfully logged on.",
        "logon_types": [2, 3, 7, 10, 11],
        "status": "0x0",
        "sub_status": "0x0",
    },
    4625: {
        "activity": "4625 - An account failed to log on.",
        "logon_types": [2, 3, 7, 10, 11],
        "status": "0xC000006D",
        "sub_status": "0xC000006A",
    },
    4648: {
        "activity": "4648 - A logon was attempted using explicit credentials.",
        "logon_types": [None],
        "status": "0x0",
        "sub_status": "0x0",
    },
    4672: {
        "activity": "4672 - Special privileges assigned to new logon.",
        "logon_types": [None],
        "status": None,
        "sub_status": None,
    },
    4688: {
        "activity": "4688 - A new process has been created.",
        "logon_types": [None],
        "status": None,
        "sub_status": None,
    },
    4720: {
        "activity": "4720 - A user account was created.",
        "logon_types": [None],
        "status": None,
        "sub_status": None,
    },
    4726: {
        "activity": "4726 - A user account was deleted.",
        "logon_types": [None],
        "status": None,
        "sub_status": None,
    },
}

# Default event IDs if none specified in scenario
DEFAULT_EVENT_IDS = [4624, 4625, 4672, 4688]

# Fake target hosts
DEFAULT_HOSTS = [
    "DC01.contoso.com",
    "DC02.contoso.com",
    "WEB-SVR01.contoso.com",
    "FILE-SVR01.contoso.com",
    "SQL-SVR01.contoso.com",
]

# Fake accounts
DEFAULT_ACCOUNTS = [
    "admin",
    "svc_backup",
    "svc_sql",
    "john.doe",
    "jane.smith",
    "helpdesk",
    "SYSTEM",
]

# Fake workstation names
DEFAULT_WORKSTATIONS = [
    "WORKSTATION01",
    "WORKSTATION02",
    "LAPTOP-JDOE",
    "LAPTOP-JSMITH",
    "KIOSK-LOBBY",
]


class SecurityEventGenerator(BaseGenerator):
    """Generator for Windows SecurityEvent log data.

    Generates realistic Windows Security events conforming to the
    SecurityEvent schema, suitable for ingestion into a custom
    Sentinel table.

    Scenario parameters:
        target_host: Specific host to target (optional).
        target_account: Specific account to target (optional).
        source_ip: Specific source IP for attacks (optional).
        event_ids: List of event IDs to generate (optional).
    """

    def generate(
        self,
        count: int,
        time_range: tuple[datetime.datetime, datetime.datetime],
    ) -> list[dict[str, Any]]:
        """Generate SecurityEvent log entries.

        Args:
            count: Number of events to generate.
            time_range: Tuple of (start, end) UTC datetimes.

        Returns:
            List of event dictionaries matching the SecurityEvent schema.
        """
        start, end = time_range
        timestamps = self._distribute_timestamps(count, start, end)

        # Extract scenario parameters with defaults
        target_host = self.scenario.get("target_host")
        target_account = self.scenario.get("target_account")
        source_ip = self.scenario.get("source_ip")
        event_ids = self.scenario.get("event_ids", DEFAULT_EVENT_IDS)

        events: list[dict[str, Any]] = []
        for ts in timestamps:
            event_id = random.choice(event_ids)
            event_def = EVENT_DEFINITIONS.get(event_id, EVENT_DEFINITIONS[4624])

            computer = target_host or random.choice(DEFAULT_HOSTS)
            account = target_account or random.choice(DEFAULT_ACCOUNTS)
            ip = source_ip or self.faker.ipv4_public()
            workstation = random.choice(DEFAULT_WORKSTATIONS)

            logon_type_options = event_def["logon_types"]
            logon_type = random.choice(logon_type_options)

            event = SecurityEvent(
                TimeGenerated=ts,
                Computer=computer,
                EventID=event_id,
                Activity=event_def["activity"],
                Account=account,
                AccountType="User",
                LogonType=logon_type,
                IpAddress=ip,
                WorkstationName=workstation,
                Status=event_def["status"],
                SubStatus=event_def["sub_status"],
            )
            events.append(event.model_dump(mode="json"))

        logger.info("Generated %d SecurityEvent entries", len(events))
        return events

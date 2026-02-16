"""SigninLogs generator for Azure AD / Entra ID sign-in events."""

from __future__ import annotations

import datetime
import logging
import random
import uuid
from typing import Any

from sentinel_data_generator.generators.base import BaseGenerator
from sentinel_data_generator.models.schemas import SigninLog

logger = logging.getLogger(__name__)


# Sample users and their display names
SAMPLE_USERS: list[dict[str, str]] = [
    {"upn": "john.doe@contoso.com", "display": "John Doe"},
    {"upn": "jane.smith@contoso.com", "display": "Jane Smith"},
    {"upn": "admin@contoso.com", "display": "Admin Account"},
    {"upn": "svc-backup@contoso.com", "display": "Backup Service"},
    {"upn": "ceo@contoso.com", "display": "Chief Executive Officer"},
    {"upn": "helpdesk@contoso.com", "display": "Help Desk"},
    {"upn": "developer@contoso.com", "display": "Developer Account"},
    {"upn": "guest_user@external.com", "display": "Guest User"},
    {"upn": "contractor@partner.com", "display": "External Contractor"},
    {"upn": "test.user@contoso.com", "display": "Test User"},
]

# Sample applications
SAMPLE_APPS: list[str] = [
    "Azure Portal",
    "Microsoft 365",
    "Microsoft Teams",
    "SharePoint Online",
    "Outlook Web App",
    "Power BI",
    "Azure CLI",
    "Visual Studio Code",
    "GitHub Enterprise",
    "Salesforce",
    "ServiceNow",
    "Workday",
]

# Client applications
CLIENT_APPS: list[str] = [
    "Browser",
    "Mobile Apps and Desktop clients",
    "Exchange ActiveSync",
    "Other clients",
    "IMAP4",
    "POP3",
    "MAPI Over HTTP",
]

# Locations with risk profiles
LOCATIONS: list[dict[str, Any]] = [
    {"country": "US", "city": "Seattle", "risk": "low"},
    {"country": "US", "city": "New York", "risk": "low"},
    {"country": "US", "city": "San Francisco", "risk": "low"},
    {"country": "GB", "city": "London", "risk": "low"},
    {"country": "DE", "city": "Berlin", "risk": "low"},
    {"country": "CA", "city": "Toronto", "risk": "low"},
    {"country": "AU", "city": "Sydney", "risk": "low"},
    {"country": "JP", "city": "Tokyo", "risk": "low"},
    {"country": "IN", "city": "Bangalore", "risk": "medium"},
    {"country": "BR", "city": "São Paulo", "risk": "medium"},
    {"country": "RU", "city": "Moscow", "risk": "high"},
    {"country": "CN", "city": "Beijing", "risk": "high"},
    {"country": "IR", "city": "Tehran", "risk": "high"},
    {"country": "KP", "city": "Pyongyang", "risk": "high"},
]

# Sign-in result codes
RESULT_CODES: dict[str, dict[str, Any]] = {
    "success": {
        "code": "0",
        "description": "Success",
        "weight": 70,
    },
    "invalid_password": {
        "code": "50126",
        "description": "Invalid username or password",
        "weight": 15,
    },
    "account_locked": {
        "code": "50053",
        "description": "Account is locked",
        "weight": 3,
    },
    "mfa_required": {
        "code": "50074",
        "description": "Strong authentication is required",
        "weight": 5,
    },
    "expired_password": {
        "code": "50055",
        "description": "Password is expired",
        "weight": 2,
    },
    "blocked_by_ca": {
        "code": "53003",
        "description": "Access blocked by Conditional Access",
        "weight": 3,
    },
    "user_not_found": {
        "code": "50034",
        "description": "User account not found",
        "weight": 2,
    },
}

# Conditional Access status options
CA_STATUS: list[str] = [
    "success",
    "failure",
    "notApplied",
]

# Risk levels
RISK_LEVELS: list[str] = [
    "none",
    "low",
    "medium",
    "high",
    "hidden",
]


class SigninLogsGenerator(BaseGenerator):
    """Generator for Azure AD / Entra ID SigninLogs events."""

    def generate(
        self,
        count: int,
        time_range: tuple[datetime.datetime, datetime.datetime],
    ) -> list[dict[str, Any]]:
        """Generate SigninLogs events.

        Args:
            count: Number of events to generate.
            time_range: Tuple of (start, end) datetime for event distribution.

        Returns:
            List of SigninLogs events as dicts.
        """
        events: list[dict[str, Any]] = []
        timestamps = self._distribute_timestamps(count, time_range[0], time_range[1])
        params = self.scenario

        # Extract scenario parameters
        target_user = params.get("target_user")
        target_app = params.get("target_app")
        attack_type = params.get("attack_type")  # brute_force, credential_stuffing, impossible_travel
        risky_locations = params.get("risky_locations", False)
        failure_rate = params.get("failure_rate", 0.2)

        for ts in timestamps:
            event = self._generate_single_event(
                ts,
                target_user=target_user,
                target_app=target_app,
                attack_type=attack_type,
                risky_locations=risky_locations,
                failure_rate=failure_rate,
            )
            events.append(event)

        logger.info("Generated %d SigninLogs events", len(events))
        return events

    def _generate_single_event(
        self,
        timestamp: str,
        target_user: str | None = None,
        target_app: str | None = None,
        attack_type: str | None = None,
        risky_locations: bool = False,
        failure_rate: float = 0.2,
    ) -> dict[str, Any]:
        """Generate a single SigninLogs event."""
        # Select user
        if target_user:
            user_info = {"upn": target_user, "display": target_user.split("@")[0].replace(".", " ").title()}
        else:
            user_info = random.choice(SAMPLE_USERS)

        # Select application
        app = target_app if target_app else random.choice(SAMPLE_APPS)

        # Select location based on scenario
        if risky_locations:
            location = random.choice([loc for loc in LOCATIONS if loc["risk"] in ("high", "medium")])
        else:
            location = random.choice(LOCATIONS)

        # Determine result based on attack type or random
        if attack_type == "brute_force":
            # Brute force: mostly failures with occasional success at end
            result_key = random.choices(
                ["invalid_password", "account_locked", "success"],
                weights=[85, 10, 5],
            )[0]
        elif attack_type == "credential_stuffing":
            result_key = random.choices(
                ["invalid_password", "user_not_found", "success"],
                weights=[70, 25, 5],
            )[0]
        elif attack_type == "impossible_travel":
            result_key = "success"  # Impossible travel is about location, not failure
        else:
            # Normal distribution
            result_key = random.choices(
                list(RESULT_CODES.keys()),
                weights=[RESULT_CODES[k]["weight"] for k in RESULT_CODES.keys()],
            )[0]

        result = RESULT_CODES[result_key]

        # Generate IP based on location risk
        if location["risk"] == "high":
            ip = self._generate_threat_ip()
        else:
            ip = self.faker.ipv4_public()

        # Risk level based on various factors
        if location["risk"] == "high" or attack_type in ("brute_force", "credential_stuffing"):
            risk_during = random.choice(["medium", "high"])
            risk_aggregated = random.choice(["medium", "high"])
        elif result_key != "success":
            risk_during = random.choice(["none", "low", "medium"])
            risk_aggregated = random.choice(["none", "low"])
        else:
            risk_during = "none"
            risk_aggregated = "none"

        # CA status
        if result_key == "blocked_by_ca":
            ca_status = "failure"
        elif result_key == "success":
            ca_status = random.choice(["success", "notApplied"])
        else:
            ca_status = "notApplied"

        location_str = f"{location['city']}, {location['country']}"

        # Build the event - using schema fields
        event_data = SigninLog(
            TimeGenerated=timestamp,
            UserPrincipalName=user_info["upn"],
            UserDisplayName=user_info["display"],
            AppDisplayName=app,
            IPAddress=ip,
            Location=location_str,
            ResultType=result["code"],
            ResultDescription=result["description"],
            ClientAppUsed=random.choice(CLIENT_APPS),
            ConditionalAccessStatus=ca_status,
            RiskLevelDuringSignIn=risk_during,
            RiskLevelAggregated=risk_aggregated,
        )

        return event_data.model_dump(mode="json")

    def _generate_threat_ip(self) -> str:
        """Generate an IP from known threat ranges."""
        threat_ranges = [
            "203.0.113.",  # TEST-NET-3
            "198.51.100.",  # TEST-NET-2
            "192.0.2.",  # TEST-NET-1
        ]
        prefix = random.choice(threat_ranges)
        return f"{prefix}{random.randint(1, 254)}"

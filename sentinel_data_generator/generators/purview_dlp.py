"""Purview DLP / IRM generator for data-protection demo events."""

from __future__ import annotations

import datetime
import logging
import random
from typing import Any

from sentinel_data_generator.generators.base import BaseGenerator
from sentinel_data_generator.models.schemas import PurviewDLPEvent

logger = logging.getLogger(__name__)


# ── Demo users ──────────────────────────────────────────────────────────
DEMO_USERS = [
    "alex.johnson@contoso.com",
    "maria.garcia@contoso.com",
    "james.wilson@contoso.com",
    "sara.chen@contoso.com",
    "david.kumar@contoso.com",
    "emily.taylor@contoso.com",
]

EXTERNAL_RECIPIENTS = [
    "partner@fabrikam.example.com",
    "vendor@northwind.example.com",
    "consultant@litware.example.com",
]

# Documentation-safe IPs
CORPORATE_IPS = ["10.1.0.50", "10.1.0.51", "10.2.0.10", "172.16.1.20"]
REMOTE_IPS = ["203.0.113.10", "203.0.113.11", "198.51.100.40"]

# ── DLP policies & rules ───────────────────────────────────────────────
DLP_POLICIES: dict[str, list[dict[str, Any]]] = {
    "Financial Data Protection": [
        {
            "rule": "Block external sharing of financial data",
            "info_type": "Credit Card Number",
            "severity": "High",
            "actions": "BlockAccess",
        },
        {
            "rule": "Notify on financial report sharing",
            "info_type": "International Banking Account Number (IBAN)",
            "severity": "Medium",
            "actions": "NotifyUser",
        },
    ],
    "PII Protection Policy": [
        {
            "rule": "Block PII in email",
            "info_type": "Social Security Number (SSN)",
            "severity": "High",
            "actions": "BlockAccess",
        },
        {
            "rule": "Audit PII in SharePoint",
            "info_type": "National Identification Number",
            "severity": "Medium",
            "actions": "Audit",
        },
        {
            "rule": "Warn on passport number sharing",
            "info_type": "Passport Number",
            "severity": "Medium",
            "actions": "NotifyUser",
        },
    ],
    "Healthcare Compliance": [
        {
            "rule": "Block health records external sharing",
            "info_type": "Health Insurance Claim Number",
            "severity": "High",
            "actions": "BlockAccess",
        },
        {
            "rule": "Audit medical ID in OneDrive",
            "info_type": "Medical Record Number",
            "severity": "Medium",
            "actions": "Audit",
        },
    ],
    "Intellectual Property": [
        {
            "rule": "Block source code sharing",
            "info_type": "Source Code",
            "severity": "High",
            "actions": "BlockAccess",
        },
        {
            "rule": "Notify on confidential document download",
            "info_type": "Confidential Document Marker",
            "severity": "Medium",
            "actions": "NotifyUser",
        },
    ],
}

# ── Sensitivity labels ─────────────────────────────────────────────────
LABELS = ["Public", "Internal", "Confidential", "Highly Confidential"]
LABEL_DOWNGRADES = [
    ("Highly Confidential", "Internal"),
    ("Highly Confidential", "Public"),
    ("Confidential", "Internal"),
    ("Confidential", "Public"),
]

# ── Workloads & demo file/path combos ─────────────────────────────────
WORKLOAD_FILES: dict[str, list[dict[str, str]]] = {
    "SharePoint": [
        {"name": "Q4-Financial-Report.xlsx", "path": "https://contoso.sharepoint.example.com/sites/Finance/Shared Documents/"},
        {"name": "Customer-PII-Export.csv", "path": "https://contoso.sharepoint.example.com/sites/HR/Shared Documents/"},
        {"name": "Patent-Application-Draft.docx", "path": "https://contoso.sharepoint.example.com/sites/Legal/Shared Documents/"},
        {"name": "Employee-Health-Records.xlsx", "path": "https://contoso.sharepoint.example.com/sites/HR/Restricted/"},
    ],
    "OneDrive": [
        {"name": "Budget-2026.xlsx", "path": "https://contoso-my.sharepoint.example.com/personal/alex_johnson/Documents/"},
        {"name": "Client-Contracts.pdf", "path": "https://contoso-my.sharepoint.example.com/personal/maria_garcia/Documents/"},
        {"name": "Source-Code-Archive.zip", "path": "https://contoso-my.sharepoint.example.com/personal/james_wilson/Documents/"},
    ],
    "Exchange": [
        {"name": "RE: Quarterly financials attached", "path": "alex.johnson@contoso.com/Sent Items/"},
        {"name": "FW: Customer data export", "path": "maria.garcia@contoso.com/Sent Items/"},
        {"name": "Contract details for review", "path": "sara.chen@contoso.com/Sent Items/"},
    ],
    "Teams": [
        {"name": "financial-data.xlsx", "path": "Teams/Finance Channel/Files/"},
        {"name": "project-credentials.txt", "path": "Teams/Engineering Channel/Files/"},
    ],
    "Endpoint": [
        {"name": "customer-database-backup.sql", "path": "C:\\Users\\alex.johnson\\Downloads\\"},
        {"name": "HR-salary-data.csv", "path": "C:\\Users\\david.kumar\\Desktop\\"},
        {"name": "source-repo-clone.zip", "path": "D:\\Projects\\confidential\\"},
    ],
}

# ── Event catalog per scenario ─────────────────────────────────────────
OPERATIONS: dict[str, list[str]] = {
    "dlp_policy_violation": ["DLPRuleMatch"],
    "sensitivity_label_downgrade": ["SensitivityLabelDowngraded", "SensitivityLabelRemoved"],
    "external_sharing": ["DLPRuleMatch", "SharingSet"],
    "bulk_download": ["FileDownloaded", "DLPRuleMatch"],
    "irm_protection_removed": ["IRMProtectionRemoved", "SensitivityLabelRemoved"],
}


class PurviewDLPGenerator(BaseGenerator):
    """Generator for Microsoft Purview DLP / IRM demo events.

    Produces realistic DLP policy match, sensitivity-label change,
    and IRM protection events covering Exchange, SharePoint, OneDrive,
    Teams, and Endpoint workloads.

    Scenario parameters:
        event_type: Attack scenario (optional, randomised if omitted).
            Options: dlp_policy_violation, sensitivity_label_downgrade,
                     external_sharing, bulk_download, irm_protection_removed
        source_ip: Override client IP (optional).
        target_user: Specific user UPN (optional).
    """

    def generate(
        self,
        count: int,
        time_range: tuple[datetime.datetime, datetime.datetime],
    ) -> list[dict[str, Any]]:
        """Generate Purview DLP / IRM entries.

        Args:
            count: Number of events to generate.
            time_range: Tuple of (start, end) UTC datetimes.

        Returns:
            List of event dicts matching the PurviewDLPEvent schema.
        """
        start, end = time_range
        timestamps = self._distribute_timestamps(count, start, end)

        event_type = self.scenario.get("event_type")
        source_ip_override = self.scenario.get("source_ip")
        target_user = self.scenario.get("target_user")

        event_types = [event_type] if event_type else list(OPERATIONS.keys())

        events: list[dict[str, Any]] = []
        for ts in timestamps:
            et = random.choice(event_types)
            operation = random.choice(OPERATIONS[et])
            workload = self._pick_workload(et)
            file_info = random.choice(WORKLOAD_FILES[workload])
            user = target_user or random.choice(DEMO_USERS)
            ip = source_ip_override or random.choice(
                REMOTE_IPS if et in ("external_sharing", "bulk_download") else CORPORATE_IPS
            )

            # Pick a policy / rule
            policy_name = random.choice(list(DLP_POLICIES.keys()))
            rule_info = random.choice(DLP_POLICIES[policy_name])

            # Sensitivity-label specifics
            sensitivity_label: str | None = None
            if et == "sensitivity_label_downgrade":
                old_label, new_label = random.choice(LABEL_DOWNGRADES)
                sensitivity_label = f"{old_label} → {new_label}"
            elif et == "irm_protection_removed":
                sensitivity_label = random.choice(["Highly Confidential", "Confidential"])
            else:
                sensitivity_label = random.choice(LABELS)

            item_type = self._item_type(workload)

            event = PurviewDLPEvent(
                TimeGenerated=ts,
                Operation=operation,
                Workload=workload,
                UserId=user,
                PolicyName=policy_name,
                RuleName=rule_info["rule"],
                Severity=rule_info["severity"],
                Actions=rule_info["actions"],
                SensitiveInfoType=rule_info["info_type"],
                SensitiveInfoCount=random.randint(1, 25),
                FileName=file_info["name"],
                FilePath=file_info["path"] + file_info["name"],
                SensitivityLabel=sensitivity_label,
                ClientIP=ip,
                ItemType=item_type,
            )
            events.append(event.model_dump(mode="json"))

        logger.info("Generated %d Purview DLP events", len(events))
        return events

    # ── helpers ──────────────────────────────────────────────────────────

    @staticmethod
    def _pick_workload(event_type: str) -> str:
        """Choose a realistic workload for the scenario type."""
        weights: dict[str, dict[str, int]] = {
            "dlp_policy_violation": {"Exchange": 3, "SharePoint": 3, "OneDrive": 2, "Teams": 1, "Endpoint": 1},
            "sensitivity_label_downgrade": {"SharePoint": 3, "OneDrive": 3, "Endpoint": 2, "Exchange": 1, "Teams": 1},
            "external_sharing": {"SharePoint": 4, "OneDrive": 3, "Exchange": 2, "Teams": 1, "Endpoint": 0},
            "bulk_download": {"SharePoint": 4, "OneDrive": 3, "Endpoint": 2, "Exchange": 0, "Teams": 1},
            "irm_protection_removed": {"SharePoint": 3, "OneDrive": 3, "Endpoint": 2, "Exchange": 1, "Teams": 1},
        }
        w = weights.get(event_type, {"SharePoint": 1, "Exchange": 1, "OneDrive": 1, "Teams": 1, "Endpoint": 1})
        workloads = [k for k, v in w.items() if v > 0]
        wts = [w[k] for k in workloads]
        return random.choices(workloads, weights=wts, k=1)[0]

    @staticmethod
    def _item_type(workload: str) -> str:
        """Map workload to item type."""
        return {
            "Exchange": "Email",
            "SharePoint": "File",
            "OneDrive": "File",
            "Teams": "Message",
            "Endpoint": "EndpointItem",
        }.get(workload, "File")

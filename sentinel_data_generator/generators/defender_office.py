"""Defender for Office 365 generator for email-threat demo events."""

from __future__ import annotations

import datetime
import json
import logging
import random
import uuid
from typing import Any

from sentinel_data_generator.generators.base import BaseGenerator
from sentinel_data_generator.models.schemas import DefenderOfficeEvent

logger = logging.getLogger(__name__)


# ── Demo users (recipients) ────────────────────────────────────────────
RECIPIENTS = [
    "alex.johnson@contoso.com",
    "maria.garcia@contoso.com",
    "james.wilson@contoso.com",
    "sara.chen@contoso.com",
    "david.kumar@contoso.com",
    "emily.taylor@contoso.com",
    "chris.lee@contoso.com",
    "nina.patel@contoso.com",
]

# ── Sender addresses (demo-safe) ──────────────────────────────────────
LEGITIMATE_SENDERS = [
    "noreply@contoso.com",
    "it-support@contoso.com",
    "hr@contoso.com",
    "finance@contoso.com",
]

PHISH_SENDERS = [
    "security-alert@c0nt0so.example.com",
    "it-helpdesk@cont0so-support.example.com",
    "noreply@contoso-verify.example.com",
    "admin@contoso-reset.example.com",
    "payment@contoso-billing.example.com",
    "hr-team@contoso-onboard.example.com",
    "ceo@contoso-urgent.example.com",
]

SPAM_SENDERS = [
    "deals@promo-offers.example.com",
    "newsletter@marketing-blast.example.com",
    "winner@prize-claim.example.com",
]

# ── Demo-safe URLs (all .example.com) ─────────────────────────────────
PHISH_URLS = [
    "https://contoso-verify.example.com/login",
    "https://contoso-reset.example.com/password-reset",
    "https://secure-contoso.example.com/account/verify",
    "https://contoso-billing.example.com/invoice/pay",
    "https://contoso-support.example.com/ticket/urgent",
    "https://contoso-onboard.example.com/new-employee",
    "https://contoso-sharepoint.example.com/shared/document",
]

SAFE_URLS = [
    "https://www.contoso.com",
    "https://portal.contoso.com/dashboard",
    "https://intranet.contoso.com/news",
]

# ── Sender IPs (documentation ranges) ─────────────────────────────────
LEGITIMATE_IPS = ["10.0.5.10", "10.0.5.11", "172.16.5.20"]
THREAT_IPS = ["198.51.100.60", "198.51.100.61", "203.0.113.70", "203.0.113.71"]
SPAM_IPS = ["198.51.100.80", "198.51.100.81"]

# ── Phishing subject lines (demo/non-harmful) ─────────────────────────
PHISH_SUBJECTS = [
    "[Action Required] Verify your Contoso account",
    "Urgent: Password expiring in 24 hours",
    "Contoso IT: Suspicious sign-in detected — verify now",
    "Your Contoso invoice #INV-{num} is ready",
    "HR Update: Complete your annual benefits enrollment",
    "Important: Update your payment details",
    "Contoso Security: Unusual activity on your account",
    "CEO Request: Urgent wire transfer needed",
    "SharePoint: Document shared with you — review now",
    "Microsoft 365: License renewal required",
]

SAFE_SUBJECTS = [
    "Weekly Team Standup Notes",
    "Q4 Project Status Update",
    "Lunch & Learn: Cloud Security Best Practices",
    "Welcome to the team!",
    "Monthly Newsletter — March 2026",
]

# ── Attachment names (demo-safe) for Safe Attachments scenarios ────────
MALICIOUS_ATTACHMENTS = [
    "Invoice_March2026.xlsm",
    "PaymentDetails.docm",
    "Urgent-Review.pdf.exe",
    "Benefits-Enrollment.xlsm",
    "ContractAmendment.docm",
]

# ── Authentication result combos ───────────────────────────────────────
AUTH_PASS = "SPF=pass;DKIM=pass;DMARC=pass"
AUTH_FAIL_SPF = "SPF=fail;DKIM=pass;DMARC=fail"
AUTH_FAIL_ALL = "SPF=fail;DKIM=fail;DMARC=fail"
AUTH_SOFT_FAIL = "SPF=softfail;DKIM=none;DMARC=bestguesspass"


class DefenderOfficeGenerator(BaseGenerator):
    """Generator for Microsoft Defender for Office 365 email-threat events.

    Produces realistic email security events covering phishing detection,
    malicious URL detonation, user-reported phish, bulk phishing campaigns,
    and Safe Attachments blocking.

    All URLs use demo-safe `.example.com` domains.

    Scenario parameters:
        event_type: Scenario to simulate (optional, randomised if omitted).
            Options: phishing_detected, malicious_url_click,
                     user_reported_phish, bulk_phishing_campaign,
                     safe_attachment_block
        target_recipient: Specific recipient UPN (optional).
        sender_ip: Override sender IP (optional).
    """

    def generate(
        self,
        count: int,
        time_range: tuple[datetime.datetime, datetime.datetime],
    ) -> list[dict[str, Any]]:
        """Generate Defender for Office 365 email events.

        Args:
            count: Number of events to generate.
            time_range: Tuple of (start, end) UTC datetimes.

        Returns:
            List of event dicts matching the DefenderOfficeEvent schema.
        """
        start, end = time_range
        timestamps = self._distribute_timestamps(count, start, end)

        event_type = self.scenario.get("event_type")
        target_recipient = self.scenario.get("target_recipient")
        sender_ip_override = self.scenario.get("sender_ip")

        event_types = [event_type] if event_type else [
            "phishing_detected",
            "malicious_url_click",
            "user_reported_phish",
            "bulk_phishing_campaign",
            "safe_attachment_block",
        ]

        events: list[dict[str, Any]] = []
        for ts in timestamps:
            et = random.choice(event_types)
            builder = getattr(self, f"_build_{et}", self._build_phishing_detected)
            event_dict = builder(ts, target_recipient, sender_ip_override)
            events.append(event_dict)

        logger.info("Generated %d Defender for Office events", len(events))
        return events

    # ── scenario builders ───────────────────────────────────────────────

    def _build_phishing_detected(
        self,
        ts: str,
        target: str | None,
        sender_ip: str | None,
    ) -> dict[str, Any]:
        """Phishing email detected and blocked by Defender."""
        recipient = target or random.choice(RECIPIENTS)
        urls = random.sample(PHISH_URLS, k=random.randint(1, 3))
        subject = random.choice(PHISH_SUBJECTS).replace("{num}", str(random.randint(1000, 9999)))
        event = DefenderOfficeEvent(
            TimeGenerated=ts,
            NetworkMessageId=str(uuid.uuid4()),
            SenderFromAddress=random.choice(PHISH_SENDERS),
            RecipientEmailAddress=recipient,
            Subject=subject,
            DeliveryAction="Blocked",
            DeliveryLocation="Quarantine",
            ThreatType="Phish",
            DetectionMethod=random.choice(["URLDetonation", "Impersonation", "Reputation"]),
            UrlCount=len(urls),
            Urls=json.dumps(urls),
            PhishConfidenceLevel=random.choice(["High", "VeryHigh"]),
            SenderIPAddress=sender_ip or random.choice(THREAT_IPS),
            AuthenticationDetails=random.choice([AUTH_FAIL_SPF, AUTH_FAIL_ALL, AUTH_SOFT_FAIL]),
            UserAction=None,
        )
        return event.model_dump(mode="json")

    def _build_malicious_url_click(
        self,
        ts: str,
        target: str | None,
        sender_ip: str | None,
    ) -> dict[str, Any]:
        """User clicked a link retroactively identified as malicious."""
        recipient = target or random.choice(RECIPIENTS)
        urls = [random.choice(PHISH_URLS)]
        subject = random.choice(PHISH_SUBJECTS).replace("{num}", str(random.randint(1000, 9999)))
        event = DefenderOfficeEvent(
            TimeGenerated=ts,
            NetworkMessageId=str(uuid.uuid4()),
            SenderFromAddress=random.choice(PHISH_SENDERS),
            RecipientEmailAddress=recipient,
            Subject=subject,
            DeliveryAction="Delivered",
            DeliveryLocation="Inbox",
            ThreatType="Phish",
            DetectionMethod="URLDetonation",
            UrlCount=len(urls),
            Urls=json.dumps(urls),
            PhishConfidenceLevel=random.choice(["High", "VeryHigh"]),
            SenderIPAddress=sender_ip or random.choice(THREAT_IPS),
            AuthenticationDetails=AUTH_SOFT_FAIL,
            UserAction="Clicked",
        )
        return event.model_dump(mode="json")

    def _build_user_reported_phish(
        self,
        ts: str,
        target: str | None,
        sender_ip: str | None,
    ) -> dict[str, Any]:
        """User reported an email as phishing via the Report button."""
        recipient = target or random.choice(RECIPIENTS)
        # Mix of real phish and false positives
        is_real_phish = random.random() < 0.7
        if is_real_phish:
            sender = random.choice(PHISH_SENDERS)
            subject = random.choice(PHISH_SUBJECTS).replace("{num}", str(random.randint(1000, 9999)))
            urls = random.sample(PHISH_URLS, k=random.randint(1, 2))
            threat = "Phish"
            confidence = random.choice(["High", "VeryHigh"])
            auth_details = random.choice([AUTH_FAIL_SPF, AUTH_FAIL_ALL])
            ip = sender_ip or random.choice(THREAT_IPS)
        else:
            sender = random.choice(LEGITIMATE_SENDERS)
            subject = random.choice(SAFE_SUBJECTS)
            urls = random.sample(SAFE_URLS, k=random.randint(0, 2))
            threat = "Clean"
            confidence = "Normal"
            auth_details = AUTH_PASS
            ip = sender_ip or random.choice(LEGITIMATE_IPS)

        event = DefenderOfficeEvent(
            TimeGenerated=ts,
            NetworkMessageId=str(uuid.uuid4()),
            SenderFromAddress=sender,
            RecipientEmailAddress=recipient,
            Subject=subject,
            DeliveryAction="Delivered",
            DeliveryLocation="Inbox" if not is_real_phish else random.choice(["Inbox", "JunkFolder"]),
            ThreatType=threat,
            DetectionMethod="UserReported",
            UrlCount=len(urls),
            Urls=json.dumps(urls) if urls else None,
            PhishConfidenceLevel=confidence,
            SenderIPAddress=ip,
            AuthenticationDetails=auth_details,
            UserAction="ReportedAsPhish",
        )
        return event.model_dump(mode="json")

    def _build_bulk_phishing_campaign(
        self,
        ts: str,
        target: str | None,
        sender_ip: str | None,
    ) -> dict[str, Any]:
        """Mass phishing campaign targeting multiple users."""
        recipient = target or random.choice(RECIPIENTS)
        sender = random.choice(PHISH_SENDERS[:3])  # Consistent sender for campaigns
        subject = random.choice(PHISH_SUBJECTS[:3]).replace("{num}", str(random.randint(1000, 9999)))
        urls = [random.choice(PHISH_URLS[:3])]  # Consistent URL for campaign
        blocked = random.random() < 0.8  # 80% blocked
        event = DefenderOfficeEvent(
            TimeGenerated=ts,
            NetworkMessageId=str(uuid.uuid4()),
            SenderFromAddress=sender,
            RecipientEmailAddress=recipient,
            Subject=subject,
            DeliveryAction="Blocked" if blocked else "Delivered",
            DeliveryLocation="Quarantine" if blocked else random.choice(["Inbox", "JunkFolder"]),
            ThreatType="Phish",
            DetectionMethod=random.choice(["Reputation", "Impersonation"]),
            UrlCount=len(urls),
            Urls=json.dumps(urls),
            PhishConfidenceLevel="VeryHigh" if blocked else "High",
            SenderIPAddress=sender_ip or random.choice(THREAT_IPS[:2]),
            AuthenticationDetails=AUTH_FAIL_ALL,
            UserAction=None if blocked else random.choice(["Clicked", None]),
        )
        return event.model_dump(mode="json")

    def _build_safe_attachment_block(
        self,
        ts: str,
        target: str | None,
        sender_ip: str | None,
    ) -> dict[str, Any]:
        """Safe Attachments detected a malicious attachment."""
        recipient = target or random.choice(RECIPIENTS)
        attachment = random.choice(MALICIOUS_ATTACHMENTS)
        subject = f"RE: {attachment.rsplit('.', 1)[0].replace('_', ' ')}"
        event = DefenderOfficeEvent(
            TimeGenerated=ts,
            NetworkMessageId=str(uuid.uuid4()),
            SenderFromAddress=random.choice(PHISH_SENDERS),
            RecipientEmailAddress=recipient,
            Subject=subject,
            DeliveryAction="Replaced",
            DeliveryLocation="Quarantine",
            ThreatType="Malware",
            DetectionMethod="SafeAttachments",
            UrlCount=0,
            Urls=None,
            PhishConfidenceLevel="VeryHigh",
            SenderIPAddress=sender_ip or random.choice(THREAT_IPS),
            AuthenticationDetails=random.choice([AUTH_FAIL_SPF, AUTH_FAIL_ALL]),
            UserAction=None,
        )
        return event.model_dump(mode="json")

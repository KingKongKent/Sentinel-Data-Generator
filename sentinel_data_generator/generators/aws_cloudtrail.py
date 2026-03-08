"""AWS CloudTrail generator for cloud security audit events."""

from __future__ import annotations

import datetime
import json
import logging
import random
from typing import Any

from sentinel_data_generator.generators.base import BaseGenerator
from sentinel_data_generator.models.schemas import AWSCloudTrailEvent

logger = logging.getLogger(__name__)


# AWS account IDs (documentation-safe fake values)
AWS_ACCOUNTS = [
    "123456789012",
    "987654321098",
    "111222333444",
]

# AWS regions — normal ops vs. suspicious crypto-mining regions
NORMAL_REGIONS = ["us-east-1", "us-west-2", "eu-west-1"]
SUSPICIOUS_REGIONS = ["ap-southeast-1", "sa-east-1", "af-south-1", "me-south-1"]

# Sample IAM users with ARNs
IAM_USERS = [
    {"arn": "arn:aws:iam::123456789012:user/admin", "type": "IAMUser"},
    {"arn": "arn:aws:iam::123456789012:user/devops-deploy", "type": "IAMUser"},
    {"arn": "arn:aws:iam::123456789012:user/svc-cicd", "type": "IAMUser"},
    {"arn": "arn:aws:iam::123456789012:user/jane.doe", "type": "IAMUser"},
    {"arn": "arn:aws:iam::123456789012:user/john.smith", "type": "IAMUser"},
    {"arn": "arn:aws:iam::123456789012:root", "type": "Root"},
    {"arn": "arn:aws:sts::123456789012:assumed-role/LambdaExecRole/function-x", "type": "AssumedRole"},
]

# Threat actor principals (compromised or unauthorized)
THREAT_ACTORS = [
    {"arn": "arn:aws:iam::123456789012:user/temp-contractor", "type": "IAMUser"},
    {"arn": "arn:aws:iam::123456789012:root", "type": "Root"},
]

# Threat actor IPs (documentation ranges)
THREAT_IPS = ["198.51.100.20", "198.51.100.21", "203.0.113.80", "203.0.113.81"]
NORMAL_IPS = ["10.0.1.50", "10.0.2.100", "172.16.0.10", "192.168.1.50"]

# S3 bucket names for exfiltration scenarios
S3_BUCKETS = [
    "contoso-prod-data",
    "contoso-customer-pii",
    "contoso-financial-reports",
    "contoso-backups",
]

# User agents
BROWSER_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
]
CLI_UAS = [
    "aws-cli/2.15.0 Python/3.11.6 Linux/5.15.0",
    "aws-cli/2.13.0 Python/3.11.4 Windows/10",
    "Boto3/1.28.0 Python/3.11.0",
]
SUSPICIOUS_UAS = [
    "python-requests/2.31.0",
    "curl/7.88.1",
]

# Event definitions per attack scenario
EVENT_CATALOG: dict[str, list[dict[str, Any]]] = {
    "iam_abuse": [
        {
            "name": "ConsoleLogin",
            "source": "signin.amazonaws.com",
            "error": None,
            "params": '{"MFAUsed": "No"}',
        },
        {
            "name": "CreateUser",
            "source": "iam.amazonaws.com",
            "error": None,
            "params": '{"userName": "backdoor-user"}',
        },
        {
            "name": "AttachUserPolicy",
            "source": "iam.amazonaws.com",
            "error": None,
            "params": '{"policyArn": "arn:aws:iam::aws:policy/AdministratorAccess", "userName": "backdoor-user"}',
        },
        {
            "name": "CreateAccessKey",
            "source": "iam.amazonaws.com",
            "error": None,
            "params": '{"userName": "backdoor-user"}',
        },
        {
            "name": "PutUserPolicy",
            "source": "iam.amazonaws.com",
            "error": None,
            "params": '{"userName": "backdoor-user", "policyName": "inline-admin"}',
        },
    ],
    "s3_exfiltration": [
        {
            "name": "ListBuckets",
            "source": "s3.amazonaws.com",
            "error": None,
            "params": "{}",
        },
        {
            "name": "GetBucketPolicy",
            "source": "s3.amazonaws.com",
            "error": None,
            "params": None,  # filled dynamically with bucket name
        },
        {
            "name": "GetObject",
            "source": "s3.amazonaws.com",
            "error": None,
            "params": None,
        },
        {
            "name": "PutBucketPolicy",
            "source": "s3.amazonaws.com",
            "error": None,
            "params": None,
        },
    ],
    "security_tampering": [
        {
            "name": "StopLogging",
            "source": "cloudtrail.amazonaws.com",
            "error": None,
            "params": '{"name": "management-trail"}',
        },
        {
            "name": "DeleteTrail",
            "source": "cloudtrail.amazonaws.com",
            "error": None,
            "params": '{"name": "management-trail"}',
        },
        {
            "name": "AuthorizeSecurityGroupIngress",
            "source": "ec2.amazonaws.com",
            "error": None,
            "params": '{"groupId": "sg-0123456789abcdef0", "ipPermissions": [{"ipProtocol": "-1", "ipRanges": [{"cidrIp": "0.0.0.0/0"}]}]}',
        },
        {
            "name": "DeleteFlowLogs",
            "source": "ec2.amazonaws.com",
            "error": None,
            "params": '{"flowLogIds": ["fl-0123456789abcdef0"]}',
        },
        {
            "name": "DisableEbsEncryptionByDefault",
            "source": "ec2.amazonaws.com",
            "error": None,
            "params": "{}",
        },
    ],
    "compute_abuse": [
        {
            "name": "RunInstances",
            "source": "ec2.amazonaws.com",
            "error": None,
            "params": '{"instanceType": "p3.8xlarge", "imageId": "ami-0abcdef1234567890", "minCount": 10, "maxCount": 10}',
        },
        {
            "name": "RunInstances",
            "source": "ec2.amazonaws.com",
            "error": None,
            "params": '{"instanceType": "g5.12xlarge", "imageId": "ami-0abcdef1234567890", "minCount": 5, "maxCount": 5}',
        },
        {
            "name": "DescribeInstances",
            "source": "ec2.amazonaws.com",
            "error": None,
            "params": "{}",
        },
    ],
    "credential_brute_force": [
        {
            "name": "ConsoleLogin",
            "source": "signin.amazonaws.com",
            "error": "Failed authentication",
            "error_code": "AccessDenied",
            "params": '{"MFAUsed": "No"}',
        },
    ],
}


class AWSCloudTrailGenerator(BaseGenerator):
    """Generator for AWS CloudTrail audit log events.

    Produces realistic CloudTrail events covering IAM abuse,
    S3 exfiltration, security config tampering, compute abuse,
    and credential brute-force scenarios.

    Scenario parameters:
        event_type: Attack scenario to simulate (optional).
            Options: iam_abuse, s3_exfiltration, security_tampering,
                     compute_abuse, credential_brute_force
        source_ip: Override source IP for all events (optional).
        target_account: AWS account ID to target (optional).
        target_user_arn: ARN of the targeted/compromised user (optional).
    """

    def generate(
        self,
        count: int,
        time_range: tuple[datetime.datetime, datetime.datetime],
    ) -> list[dict[str, Any]]:
        """Generate AWS CloudTrail entries.

        Args:
            count: Number of events to generate.
            time_range: Tuple of (start, end) UTC datetimes.

        Returns:
            List of event dictionaries matching the AWSCloudTrailEvent schema.
        """
        start, end = time_range
        timestamps = self._distribute_timestamps(count, start, end)

        event_type = self.scenario.get("event_type")
        source_ip_override = self.scenario.get("source_ip")
        target_account = self.scenario.get("target_account", random.choice(AWS_ACCOUNTS))
        target_user_arn = self.scenario.get("target_user_arn")

        event_types = [event_type] if event_type else list(EVENT_CATALOG.keys())

        events: list[dict[str, Any]] = []
        for ts in timestamps:
            evt_type = random.choice(event_types)
            evt_templates = EVENT_CATALOG[evt_type]
            evt_def = random.choice(evt_templates)

            # Determine caller identity
            if target_user_arn:
                arn = target_user_arn
                identity_type = "IAMUser"
            elif evt_type in ("iam_abuse", "s3_exfiltration", "security_tampering", "compute_abuse"):
                actor = random.choice(THREAT_ACTORS)
                arn = actor["arn"]
                identity_type = actor["type"]
            elif evt_type == "credential_brute_force":
                user = random.choice(IAM_USERS[:5])  # Only IAMUsers
                arn = user["arn"]
                identity_type = user["type"]
            else:
                user = random.choice(IAM_USERS)
                arn = user["arn"]
                identity_type = user["type"]

            # Determine source IP
            if source_ip_override:
                src_ip = source_ip_override
            elif evt_type in ("iam_abuse", "s3_exfiltration", "security_tampering",
                              "compute_abuse", "credential_brute_force"):
                src_ip = random.choice(THREAT_IPS)
            else:
                src_ip = random.choice(NORMAL_IPS)

            # Determine region
            if evt_type == "compute_abuse":
                region = random.choice(SUSPICIOUS_REGIONS)
            else:
                region = random.choice(NORMAL_REGIONS)

            # Determine user agent
            if evt_type == "credential_brute_force":
                ua = random.choice(SUSPICIOUS_UAS)
            elif evt_def["source"] == "signin.amazonaws.com":
                ua = random.choice(BROWSER_UAS)
            else:
                ua = random.choice(CLI_UAS)

            # Build request parameters
            params = evt_def["params"]
            if evt_def["name"] in ("GetObject", "GetBucketPolicy", "PutBucketPolicy"):
                bucket = random.choice(S3_BUCKETS)
                if evt_def["name"] == "GetObject":
                    params = json.dumps({
                        "bucketName": bucket,
                        "key": f"exports/{self.faker.file_name(extension='csv')}",
                    })
                else:
                    params = json.dumps({"bucketName": bucket})

            # Error handling
            error_code = evt_def.get("error_code")
            error_message = evt_def.get("error")

            event = AWSCloudTrailEvent(
                TimeGenerated=ts,
                EventName=evt_def["name"],
                EventSource=evt_def["source"],
                SourceIPAddress=src_ip,
                UserIdentityArn=arn,
                UserIdentityType=identity_type,
                UserAgent=ua,
                AWSRegion=region,
                RecipientAccountId=target_account,
                ErrorCode=error_code,
                ErrorMessage=error_message,
                RequestParameters=params,
                ResponseElements=None,
            )
            events.append(event.model_dump(mode="json"))

        logger.info("Generated %d AWS CloudTrail entries", len(events))
        return events

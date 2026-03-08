"""GCP Audit Logs generator for cloud security audit events."""

from __future__ import annotations

import datetime
import json
import logging
import random
from typing import Any

from sentinel_data_generator.generators.base import BaseGenerator
from sentinel_data_generator.models.schemas import GCPAuditLogEvent

logger = logging.getLogger(__name__)


# GCP project IDs (documentation-safe fake values)
GCP_PROJECTS = [
    "contoso-prod-123456",
    "contoso-staging-789012",
    "contoso-shared-345678",
]

# GCP regions — normal vs. suspicious
NORMAL_REGIONS = ["us-central1", "us-east1", "europe-west1"]
SUSPICIOUS_REGIONS = ["asia-east1", "southamerica-east1", "africa-south1"]

# Sample principals (emails)
NORMAL_PRINCIPALS = [
    "admin@contoso-gcp.iam.gserviceaccount.com",
    "devops@contoso.altostrat.com",
    "jane.doe@contoso.altostrat.com",
    "john.smith@contoso.altostrat.com",
    "ci-pipeline@contoso-prod-123456.iam.gserviceaccount.com",
]

THREAT_PRINCIPALS = [
    "temp-contractor@contoso.altostrat.com",
    "compromised-sa@contoso-prod-123456.iam.gserviceaccount.com",
    "exfil-bot@contoso-prod-123456.iam.gserviceaccount.com",
]

# Threat actor IPs (documentation ranges)
THREAT_IPS = ["198.51.100.30", "198.51.100.31", "203.0.113.90", "203.0.113.91"]
NORMAL_IPS = ["10.128.0.10", "10.128.0.20", "10.138.0.10", "35.192.0.50"]

# GCS bucket names for exfiltration scenarios
GCS_BUCKETS = [
    "contoso-customer-data",
    "contoso-financial-exports",
    "contoso-pii-backup",
    "contoso-ml-datasets",
]

# BigQuery datasets
BQ_DATASETS = [
    "analytics.user_sessions",
    "billing.invoices",
    "security.audit_events",
    "hr.employee_records",
]

# Firewall rule names
FIREWALL_RULES = [
    "allow-internal",
    "deny-all-ingress",
    "allow-ssh-restricted",
    "allow-https-lb",
]

# Event definitions per attack scenario
EVENT_CATALOG: dict[str, list[dict[str, Any]]] = {
    "iam_abuse": [
        {
            "service": "iam.googleapis.com",
            "method": "google.iam.admin.v1.CreateServiceAccountKey",
            "resource_type": "service_account",
            "resource_template": "projects/{project}/serviceAccounts/compromised-sa@{project}.iam.gserviceaccount.com",
            "severity": "NOTICE",
            "status_code": 0,
            "status_msg": "OK",
        },
        {
            "service": "iam.googleapis.com",
            "method": "SetIamPolicy",
            "resource_type": "project",
            "resource_template": "projects/{project}",
            "severity": "NOTICE",
            "status_code": 0,
            "status_msg": "OK",
            "auth_info": '{"permission": "resourcemanager.projects.setIamPolicy", "granted": true}',
        },
        {
            "service": "iam.googleapis.com",
            "method": "google.iam.admin.v1.CreateServiceAccount",
            "resource_type": "project",
            "resource_template": "projects/{project}",
            "severity": "NOTICE",
            "status_code": 0,
            "status_msg": "OK",
        },
        {
            "service": "cloudresourcemanager.googleapis.com",
            "method": "SetIamPolicy",
            "resource_type": "project",
            "resource_template": "projects/{project}",
            "severity": "WARNING",
            "status_code": 0,
            "status_msg": "OK",
            "auth_info": '{"permission": "resourcemanager.projects.setIamPolicy", "granted": true, "role": "roles/owner"}',
        },
    ],
    "data_exfiltration": [
        {
            "service": "storage.googleapis.com",
            "method": "storage.objects.get",
            "resource_type": "gcs_bucket",
            "resource_template": None,  # filled dynamically
            "severity": "NOTICE",
            "status_code": 0,
            "status_msg": "OK",
        },
        {
            "service": "storage.googleapis.com",
            "method": "storage.objects.list",
            "resource_type": "gcs_bucket",
            "resource_template": None,
            "severity": "NOTICE",
            "status_code": 0,
            "status_msg": "OK",
        },
        {
            "service": "bigquery.googleapis.com",
            "method": "jobservice.insert",
            "resource_type": "bigquery_dataset",
            "resource_template": None,
            "severity": "NOTICE",
            "status_code": 0,
            "status_msg": "OK",
        },
        {
            "service": "storage.googleapis.com",
            "method": "storage.buckets.getIamPolicy",
            "resource_type": "gcs_bucket",
            "resource_template": None,
            "severity": "NOTICE",
            "status_code": 0,
            "status_msg": "OK",
        },
    ],
    "security_tampering": [
        {
            "service": "compute.googleapis.com",
            "method": "v1.compute.firewalls.delete",
            "resource_type": "gce_firewall_rule",
            "resource_template": None,
            "severity": "WARNING",
            "status_code": 0,
            "status_msg": "OK",
        },
        {
            "service": "compute.googleapis.com",
            "method": "v1.compute.firewalls.insert",
            "resource_type": "gce_firewall_rule",
            "resource_template": None,
            "severity": "NOTICE",
            "status_code": 0,
            "status_msg": "OK",
            "auth_info": '{"permission": "compute.firewalls.create", "granted": true, "direction": "INGRESS", "allowed": [{"IPProtocol": "all"}], "sourceRanges": ["0.0.0.0/0"]}',
        },
        {
            "service": "logging.googleapis.com",
            "method": "google.logging.v2.ConfigServiceV2.DeleteSink",
            "resource_type": "logging_sink",
            "resource_template": "projects/{project}/sinks/audit-export",
            "severity": "WARNING",
            "status_code": 0,
            "status_msg": "OK",
        },
        {
            "service": "logging.googleapis.com",
            "method": "google.logging.v2.ConfigServiceV2.UpdateSink",
            "resource_type": "logging_sink",
            "resource_template": "projects/{project}/sinks/audit-export",
            "severity": "WARNING",
            "status_code": 0,
            "status_msg": "OK",
        },
    ],
    "compute_abuse": [
        {
            "service": "compute.googleapis.com",
            "method": "v1.compute.instances.insert",
            "resource_type": "gce_instance",
            "resource_template": "projects/{project}/zones/{region}-a/instances/crypto-miner-{idx}",
            "severity": "NOTICE",
            "status_code": 0,
            "status_msg": "OK",
            "auth_info": '{"machineType": "n1-highcpu-96", "count": 5}',
        },
        {
            "service": "compute.googleapis.com",
            "method": "v1.compute.instances.insert",
            "resource_type": "gce_instance",
            "resource_template": "projects/{project}/zones/{region}-b/instances/gpu-worker-{idx}",
            "severity": "NOTICE",
            "status_code": 0,
            "status_msg": "OK",
            "auth_info": '{"machineType": "a2-highgpu-8g", "acceleratorType": "nvidia-tesla-a100"}',
        },
        {
            "service": "compute.googleapis.com",
            "method": "v1.compute.instances.list",
            "resource_type": "gce_instance",
            "resource_template": "projects/{project}/zones/{region}-a",
            "severity": "NOTICE",
            "status_code": 0,
            "status_msg": "OK",
        },
    ],
    "credential_brute_force": [
        {
            "service": "login.googleapis.com",
            "method": "google.login.LoginService.loginFailure",
            "resource_type": "project",
            "resource_template": "projects/{project}",
            "severity": "WARNING",
            "status_code": 7,
            "status_msg": "PERMISSION_DENIED",
        },
    ],
}


class GCPAuditLogsGenerator(BaseGenerator):
    """Generator for GCP Audit Log events.

    Produces realistic GCP Cloud Audit Logs covering IAM abuse,
    data exfiltration, security config tampering, compute abuse,
    and credential brute-force scenarios.

    Scenario parameters:
        event_type: Attack scenario to simulate (optional).
            Options: iam_abuse, data_exfiltration, security_tampering,
                     compute_abuse, credential_brute_force
        source_ip: Override caller IP for all events (optional).
        target_project: GCP project ID to target (optional).
        target_principal: Email of the threat actor principal (optional).
    """

    def _build_resource_name(
        self,
        template: str | None,
        project: str,
        evt_def: dict[str, Any],
        evt_type: str,
        idx: int,
    ) -> str:
        """Build a realistic GCP resource name from the template.

        Args:
            template: Resource name template with {project}/{region}/{idx} placeholders.
            project: GCP project ID.
            evt_def: Event definition dict.
            evt_type: Attack scenario type.
            idx: Event index for unique naming.

        Returns:
            Fully-resolved resource name string.
        """
        if template is None:
            # Dynamic resource names per event type
            service = evt_def["service"]
            if "storage" in service:
                bucket = random.choice(GCS_BUCKETS)
                method = evt_def["method"]
                if method == "storage.objects.get":
                    return f"projects/_/buckets/{bucket}/objects/export-{idx}.csv"
                return f"projects/_/buckets/{bucket}"
            if "bigquery" in service:
                dataset = random.choice(BQ_DATASETS)
                return f"projects/{project}/datasets/{dataset}"
            if "compute" in service and "firewall" in evt_def["method"]:
                rule = random.choice(FIREWALL_RULES)
                return f"projects/{project}/global/firewalls/{rule}"
            return f"projects/{project}"

        region = random.choice(SUSPICIOUS_REGIONS if evt_type == "compute_abuse" else NORMAL_REGIONS)
        return template.format(project=project, region=region, idx=idx)

    def generate(
        self,
        count: int,
        time_range: tuple[datetime.datetime, datetime.datetime],
    ) -> list[dict[str, Any]]:
        """Generate GCP Audit Log entries.

        Args:
            count: Number of events to generate.
            time_range: Tuple of (start, end) UTC datetimes.

        Returns:
            List of event dictionaries matching the GCPAuditLogEvent schema.
        """
        start, end = time_range
        timestamps = self._distribute_timestamps(count, start, end)

        event_type = self.scenario.get("event_type")
        source_ip_override = self.scenario.get("source_ip")
        target_project = self.scenario.get("target_project", random.choice(GCP_PROJECTS))
        target_principal = self.scenario.get("target_principal")

        event_types = [event_type] if event_type else list(EVENT_CATALOG.keys())

        events: list[dict[str, Any]] = []
        for i, ts in enumerate(timestamps):
            evt_type = random.choice(event_types)
            evt_templates = EVENT_CATALOG[evt_type]
            evt_def = random.choice(evt_templates)

            # Determine caller principal
            if target_principal:
                principal = target_principal
            elif evt_type in ("iam_abuse", "data_exfiltration", "security_tampering",
                              "compute_abuse"):
                principal = random.choice(THREAT_PRINCIPALS)
            elif evt_type == "credential_brute_force":
                principal = random.choice(NORMAL_PRINCIPALS[:4])  # Only human users
            else:
                principal = random.choice(NORMAL_PRINCIPALS)

            # Determine caller IP
            if source_ip_override:
                caller_ip = source_ip_override
            elif evt_type in ("iam_abuse", "data_exfiltration", "security_tampering",
                              "compute_abuse", "credential_brute_force"):
                caller_ip = random.choice(THREAT_IPS)
            else:
                caller_ip = random.choice(NORMAL_IPS)

            # Build resource name
            resource_name = self._build_resource_name(
                evt_def.get("resource_template"),
                target_project,
                evt_def,
                evt_type,
                i,
            )

            event = GCPAuditLogEvent(
                TimeGenerated=ts,
                ServiceName=evt_def["service"],
                MethodName=evt_def["method"],
                CallerIP=caller_ip,
                PrincipalEmail=principal,
                ResourceName=resource_name,
                ResourceType=evt_def["resource_type"],
                Severity=evt_def["severity"],
                ProjectId=target_project,
                StatusCode=evt_def["status_code"],
                StatusMessage=evt_def["status_msg"],
                AuthorizationInfo=evt_def.get("auth_info"),
            )
            events.append(event.model_dump(mode="json"))

        logger.info("Generated %d GCP Audit Log entries", len(events))
        return events

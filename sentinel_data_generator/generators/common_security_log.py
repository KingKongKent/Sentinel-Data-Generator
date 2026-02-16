"""CommonSecurityLog (CEF) generator for network security events."""

from __future__ import annotations

import datetime
import logging
import random
from typing import Any

from sentinel_data_generator.generators.base import BaseGenerator
from sentinel_data_generator.models.schemas import CommonSecurityLogEvent

logger = logging.getLogger(__name__)


# CEF Device/Product definitions
DEVICE_VENDORS: dict[str, dict[str, Any]] = {
    "Palo Alto Networks": {
        "products": ["PAN-OS", "Prisma Access"],
        "version": "10.2.0",
    },
    "Fortinet": {
        "products": ["FortiGate"],
        "version": "7.4.1",
    },
    "Cisco": {
        "products": ["ASA", "Firepower"],
        "version": "9.18",
    },
    "Check Point": {
        "products": ["NGFW"],
        "version": "R81.20",
    },
    "Zscaler": {
        "products": ["ZIA"],
        "version": "6.0",
    },
}

# CEF event class definitions
EVENT_CLASSES: dict[str, dict[str, Any]] = {
    "firewall_allow": {
        "class_id": "traffic:allow",
        "activity": "Firewall session allowed",
        "severity": "1",
        "protocols": ["TCP", "UDP"],
        "dest_ports": [80, 443, 8080, 22, 3389, 25, 53, 636],
    },
    "firewall_deny": {
        "class_id": "traffic:deny",
        "activity": "Firewall session denied",
        "severity": "5",
        "protocols": ["TCP", "UDP"],
        "dest_ports": [22, 3389, 445, 135, 139, 1433, 3306, 5432],
    },
    "ids_alert": {
        "class_id": "intrusion:detected",
        "activity": "Intrusion attempt detected",
        "severity": "8",
        "protocols": ["TCP", "UDP"],
        "dest_ports": [80, 443, 8080, 22, 445],
    },
    "malware_detected": {
        "class_id": "malware:detected",
        "activity": "Malware communication blocked",
        "severity": "9",
        "protocols": ["TCP"],
        "dest_ports": [443, 80, 8443],
    },
    "web_access": {
        "class_id": "web:access",
        "activity": "Web access logged",
        "severity": "1",
        "protocols": ["TCP"],
        "dest_ports": [80, 443, 8080],
    },
    "vpn_connection": {
        "class_id": "vpn:connection",
        "activity": "VPN session established",
        "severity": "1",
        "protocols": ["UDP", "TCP"],
        "dest_ports": [443, 500, 4500, 1194],
    },
    "threat_intelligence": {
        "class_id": "threat:match",
        "activity": "Threat intelligence IOC match",
        "severity": "10",
        "protocols": ["TCP", "UDP"],
        "dest_ports": [443, 80, 53],
    },
}

# Sample URLs for web access events
SAMPLE_URLS = [
    "https://login.microsoftonline.com/auth",
    "https://www.contoso.com/api/v1/users",
    "http://malicious-site.example/payload.exe",
    "https://github.com/downloads/release.zip",
    "http://suspicious-domain.net/beacon",
    "https://office365.com/owa",
    "https://drive.google.com/file/download",
]

# Known bad IPs for threat scenarios (documentation ranges)
THREAT_ACTOR_IPS = [
    "198.51.100.10",
    "198.51.100.11",
    "198.51.100.12",
    "203.0.113.50",
    "203.0.113.51",
    "203.0.113.52",
]

# Internal network ranges
INTERNAL_SUBNETS = ["10.0.0.", "10.1.0.", "192.168.1.", "172.16.0."]


class CommonSecurityLogGenerator(BaseGenerator):
    """Generator for CommonSecurityLog (CEF) events.

    Generates realistic CEF-format events from various network security
    devices such as firewalls, IDS/IPS, and web proxies.

    Scenario parameters:
        vendor: Specific device vendor (optional).
        event_type: Type of event to generate (optional).
            Options: firewall_allow, firewall_deny, ids_alert,
                     malware_detected, web_access, vpn_connection,
                     threat_intelligence
        source_ip: Specific source IP (optional).
        dest_ip: Specific destination IP (optional).
        threat_actor_ip: Use known threat actor IP as source (optional).
    """

    def _random_internal_ip(self) -> str:
        """Generate a random internal IP address."""
        subnet = random.choice(INTERNAL_SUBNETS)
        return f"{subnet}{random.randint(1, 254)}"

    def _random_external_ip(self) -> str:
        """Generate a random external IP address."""
        return self.faker.ipv4_public()

    def generate(
        self,
        count: int,
        time_range: tuple[datetime.datetime, datetime.datetime],
    ) -> list[dict[str, Any]]:
        """Generate CommonSecurityLog entries.

        Args:
            count: Number of events to generate.
            time_range: Tuple of (start, end) UTC datetimes.

        Returns:
            List of event dictionaries matching the CommonSecurityLogEvent schema.
        """
        start, end = time_range
        timestamps = self._distribute_timestamps(count, start, end)

        # Extract scenario parameters
        vendor_name = self.scenario.get("vendor")
        event_type = self.scenario.get("event_type")
        source_ip_override = self.scenario.get("source_ip")
        dest_ip_override = self.scenario.get("dest_ip")
        use_threat_actor = self.scenario.get("threat_actor_ip", False)

        # Determine event types to use
        event_types = [event_type] if event_type else list(EVENT_CLASSES.keys())

        events: list[dict[str, Any]] = []
        for ts in timestamps:
            # Select vendor and product
            if vendor_name and vendor_name in DEVICE_VENDORS:
                vendor = vendor_name
                vendor_info = DEVICE_VENDORS[vendor]
            else:
                vendor = random.choice(list(DEVICE_VENDORS.keys()))
                vendor_info = DEVICE_VENDORS[vendor]

            product = random.choice(vendor_info["products"])
            version = vendor_info["version"]

            # Select event type
            evt_type = random.choice(event_types)
            evt_def = EVENT_CLASSES[evt_type]

            # Determine source IP
            if source_ip_override:
                src_ip = source_ip_override
            elif use_threat_actor or evt_type in ["ids_alert", "malware_detected", "threat_intelligence"]:
                # High-severity events likely from external threat actors
                src_ip = random.choice(THREAT_ACTOR_IPS) if random.random() > 0.3 else self._random_external_ip()
            elif evt_type in ["firewall_deny"]:
                # Denied traffic often from external
                src_ip = self._random_external_ip() if random.random() > 0.5 else self._random_internal_ip()
            else:
                # Normal traffic from internal
                src_ip = self._random_internal_ip()

            # Determine destination IP
            if dest_ip_override:
                dst_ip = dest_ip_override
            elif evt_type in ["ids_alert", "malware_detected", "threat_intelligence"]:
                # Target is internal server
                dst_ip = self._random_internal_ip()
            else:
                # External destination for outbound, internal for inbound
                dst_ip = self._random_external_ip() if random.random() > 0.4 else self._random_internal_ip()

            # Select ports
            protocol = random.choice(evt_def["protocols"])
            dst_port = random.choice(evt_def["dest_ports"])
            src_port = random.randint(49152, 65535)  # Ephemeral port

            # URL for web-related events
            request_url = None
            if evt_type in ["web_access", "malware_detected"]:
                request_url = random.choice(SAMPLE_URLS)

            event = CommonSecurityLogEvent(
                TimeGenerated=ts,
                DeviceVendor=vendor,
                DeviceProduct=product,
                DeviceVersion=version,
                DeviceEventClassID=evt_def["class_id"],
                Activity=evt_def["activity"],
                LogSeverity=evt_def["severity"],
                SourceIP=src_ip,
                DestinationIP=dst_ip,
                SourcePort=src_port,
                DestinationPort=dst_port,
                Protocol=protocol,
                RequestURL=request_url,
            )

            events.append(event.model_dump(mode="json"))

        logger.info("Generated %d CommonSecurityLog entries", len(events))
        return events

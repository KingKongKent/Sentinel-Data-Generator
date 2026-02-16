"""Syslog generator for Linux/Unix system log events."""

from __future__ import annotations

import datetime
import logging
import random
from typing import Any

from sentinel_data_generator.generators.base import BaseGenerator
from sentinel_data_generator.models.schemas import SyslogEvent

logger = logging.getLogger(__name__)


# Syslog facilities (RFC 5424)
FACILITIES: list[str] = [
    "auth",
    "authpriv",
    "cron",
    "daemon",
    "kern",
    "local0",
    "local1",
    "local2",
    "local3",
    "local4",
    "local5",
    "local6",
    "local7",
    "mail",
    "syslog",
    "user",
]

# Syslog severity levels (RFC 5424)
SEVERITY_LEVELS: list[str] = [
    "emerg",
    "alert",
    "crit",
    "err",
    "warning",
    "notice",
    "info",
    "debug",
]

# Sample hostnames for different server types
SAMPLE_HOSTS: list[dict[str, str]] = [
    {"hostname": "web-server-01.contoso.local", "ip": "10.1.1.10", "type": "web"},
    {"hostname": "web-server-02.contoso.local", "ip": "10.1.1.11", "type": "web"},
    {"hostname": "db-primary.contoso.local", "ip": "10.1.2.10", "type": "database"},
    {"hostname": "db-replica.contoso.local", "ip": "10.1.2.11", "type": "database"},
    {"hostname": "app-server-01.contoso.local", "ip": "10.1.3.10", "type": "app"},
    {"hostname": "app-server-02.contoso.local", "ip": "10.1.3.11", "type": "app"},
    {"hostname": "mail-server.contoso.local", "ip": "10.1.4.10", "type": "mail"},
    {"hostname": "dns-server.contoso.local", "ip": "10.1.5.10", "type": "dns"},
    {"hostname": "proxy-server.contoso.local", "ip": "10.1.6.10", "type": "proxy"},
    {"hostname": "jump-server.contoso.local", "ip": "10.1.7.10", "type": "jump"},
    {"hostname": "k8s-master.contoso.local", "ip": "10.1.8.10", "type": "kubernetes"},
    {"hostname": "k8s-worker-01.contoso.local", "ip": "10.1.8.11", "type": "kubernetes"},
]

# Process/daemon names by type
PROCESSES: dict[str, list[str]] = {
    "auth": ["sshd", "sudo", "su", "login", "pam", "passwd", "useradd", "groupadd"],
    "web": ["nginx", "apache2", "httpd", "php-fpm", "gunicorn", "uwsgi"],
    "database": ["mysqld", "postgres", "mongod", "redis-server", "mariadbd"],
    "system": ["systemd", "cron", "anacron", "kernel", "rsyslogd", "logrotate"],
    "network": ["NetworkManager", "dhclient", "named", "dnsmasq", "firewalld", "iptables"],
    "security": ["fail2ban", "auditd", "apparmor", "selinux", "aide", "ossec"],
    "container": ["dockerd", "containerd", "kubelet", "kube-proxy", "etcd"],
    "mail": ["postfix", "dovecot", "sendmail", "spamassassin", "amavisd"],
}

# Message templates organized by event type
MESSAGE_TEMPLATES: dict[str, list[dict[str, Any]]] = {
    "ssh_success": [
        {
            "facility": "auth",
            "severity": "info",
            "process": "sshd",
            "message": "Accepted publickey for {user} from {ip} port {port} ssh2: RSA SHA256:{hash}",
        },
        {
            "facility": "auth",
            "severity": "info",
            "process": "sshd",
            "message": "Accepted password for {user} from {ip} port {port} ssh2",
        },
    ],
    "ssh_failure": [
        {
            "facility": "auth",
            "severity": "warning",
            "process": "sshd",
            "message": "Failed password for {user} from {ip} port {port} ssh2",
        },
        {
            "facility": "auth",
            "severity": "warning",
            "process": "sshd",
            "message": "Failed publickey for {user} from {ip} port {port} ssh2",
        },
        {
            "facility": "auth",
            "severity": "err",
            "process": "sshd",
            "message": "Invalid user {user} from {ip} port {port}",
        },
        {
            "facility": "auth",
            "severity": "warning",
            "process": "sshd",
            "message": "Connection closed by authenticating user {user} {ip} port {port} [preauth]",
        },
    ],
    "ssh_brute_force": [
        {
            "facility": "auth",
            "severity": "crit",
            "process": "sshd",
            "message": "message repeated {count} times: [ Failed password for {user} from {ip} port {port} ssh2]",
        },
        {
            "facility": "auth",
            "severity": "err",
            "process": "sshd",
            "message": "Disconnecting invalid user {user} {ip} port {port}: Too many authentication failures",
        },
    ],
    "sudo_success": [
        {
            "facility": "authpriv",
            "severity": "info",
            "process": "sudo",
            "message": "{user} : TTY=pts/{tty} ; PWD={pwd} ; USER=root ; COMMAND={cmd}",
        },
    ],
    "sudo_failure": [
        {
            "facility": "authpriv",
            "severity": "alert",
            "process": "sudo",
            "message": "{user} : user NOT in sudoers ; TTY=pts/{tty} ; PWD={pwd} ; USER=root ; COMMAND={cmd}",
        },
        {
            "facility": "authpriv",
            "severity": "err",
            "process": "sudo",
            "message": "{user} : 3 incorrect password attempts ; TTY=pts/{tty} ; PWD={pwd} ; USER=root ; COMMAND={cmd}",
        },
    ],
    "cron_job": [
        {
            "facility": "cron",
            "severity": "info",
            "process": "CRON",
            "message": "({user}) CMD ({cmd})",
        },
    ],
    "kernel_security": [
        {
            "facility": "kern",
            "severity": "warning",
            "process": "kernel",
            "message": "SELinux: denied {{ {action} }} for pid={pid} comm=\"{comm}\" path=\"{path}\"",
        },
        {
            "facility": "kern",
            "severity": "err",
            "process": "kernel",
            "message": "Out of memory: Killed process {pid} ({comm})",
        },
    ],
    "service_start": [
        {
            "facility": "daemon",
            "severity": "info",
            "process": "systemd",
            "message": "Started {service}.",
        },
        {
            "facility": "daemon",
            "severity": "info",
            "process": "systemd",
            "message": "Starting {service}...",
        },
    ],
    "service_stop": [
        {
            "facility": "daemon",
            "severity": "info",
            "process": "systemd",
            "message": "Stopped {service}.",
        },
        {
            "facility": "daemon",
            "severity": "info",
            "process": "systemd",
            "message": "Stopping {service}...",
        },
    ],
    "service_failure": [
        {
            "facility": "daemon",
            "severity": "err",
            "process": "systemd",
            "message": "{service} failed to start.",
        },
        {
            "facility": "daemon",
            "severity": "crit",
            "process": "systemd",
            "message": "{service}.service: Main process exited, code=exited, status={status}",
        },
    ],
    "firewall_block": [
        {
            "facility": "kern",
            "severity": "warning",
            "process": "kernel",
            "message": "iptables denied: IN={iface} OUT= SRC={src_ip} DST={dst_ip} PROTO={proto} DPT={port}",
        },
    ],
    "disk_error": [
        {
            "facility": "kern",
            "severity": "err",
            "process": "kernel",
            "message": "EXT4-fs error (device {device}): {error_msg}",
        },
        {
            "facility": "kern",
            "severity": "crit",
            "process": "kernel",
            "message": "Buffer I/O error on device {device}, logical block {block}",
        },
    ],
    "web_access": [
        {
            "facility": "local0",
            "severity": "info",
            "process": "nginx",
            "message": '{ip} - {user} [{timestamp}] "{method} {path} HTTP/1.1" {status} {bytes}',
        },
    ],
    "db_connection": [
        {
            "facility": "local1",
            "severity": "info",
            "process": "postgres",
            "message": "connection received: host={ip} port={port}",
        },
        {
            "facility": "local1",
            "severity": "warning",
            "process": "postgres",
            "message": "connection attempt from {ip} failed: authentication failed for user \"{user}\"",
        },
    ],
}

# Common Linux users
LINUX_USERS: list[str] = [
    "root",
    "admin",
    "ubuntu",
    "centos",
    "ec2-user",
    "deploy",
    "www-data",
    "nginx",
    "postgres",
    "mysql",
    "redis",
    "ansible",
    "jenkins",
]

# Common commands for sudo
SUDO_COMMANDS: list[str] = [
    "/usr/bin/systemctl restart nginx",
    "/usr/bin/apt-get update",
    "/usr/bin/yum install -y httpd",
    "/bin/cat /etc/shadow",
    "/bin/chmod 777 /var/www/html",
    "/usr/sbin/useradd newuser",
    "/usr/bin/docker exec -it container bash",
    "/bin/rm -rf /tmp/*",
    "/usr/bin/vi /etc/passwd",
]

# Service names
SERVICES: list[str] = [
    "nginx.service",
    "apache2.service",
    "mysql.service",
    "postgresql.service",
    "docker.service",
    "redis.service",
    "sshd.service",
    "crond.service",
    "firewalld.service",
    "kubelet.service",
]


class SyslogGenerator(BaseGenerator):
    """Generator for Linux/Unix Syslog events."""

    def generate(
        self,
        count: int,
        time_range: tuple[datetime.datetime, datetime.datetime],
    ) -> list[dict[str, Any]]:
        """Generate Syslog events.

        Args:
            count: Number of events to generate.
            time_range: Tuple of (start, end) datetime for event distribution.

        Returns:
            List of Syslog events as dicts.
        """
        events: list[dict[str, Any]] = []
        timestamps = self._distribute_timestamps(count, time_range[0], time_range[1])
        params = self.scenario

        # Extract scenario parameters
        event_type = params.get("event_type")  # ssh_failure, brute_force, etc.
        target_host = params.get("target_host")
        attacker_ip = params.get("attacker_ip", "203.0.113.50")

        for ts in timestamps:
            event = self._generate_single_event(
                ts,
                event_type=event_type,
                target_host=target_host,
                attacker_ip=attacker_ip,
            )
            events.append(event)

        logger.info("Generated %d Syslog events", len(events))
        return events

    def _generate_single_event(
        self,
        timestamp: str,
        event_type: str | None = None,
        target_host: str | None = None,
        attacker_ip: str | None = None,
    ) -> dict[str, Any]:
        """Generate a single Syslog event."""
        # Select host
        if target_host:
            host = {"hostname": target_host, "ip": self.faker.ipv4_private(), "type": "server"}
        else:
            host = random.choice(SAMPLE_HOSTS)

        # Select event type if not specified
        if not event_type:
            event_type = random.choice(list(MESSAGE_TEMPLATES.keys()))

        # Get message template
        templates = MESSAGE_TEMPLATES.get(event_type, MESSAGE_TEMPLATES["service_start"])
        template = random.choice(templates)

        # Generate message content based on event type
        message = self._format_message(template["message"], event_type, attacker_ip)

        # Build the event
        event_data = SyslogEvent(
            TimeGenerated=timestamp,
            Computer=host["hostname"],
            HostIP=host["ip"],
            Facility=template["facility"],
            SeverityLevel=template["severity"],
            ProcessName=template["process"],
            SyslogMessage=message,
        )

        return event_data.model_dump(mode="json")

    def _format_message(
        self,
        template: str,
        event_type: str,
        attacker_ip: str | None = None,
    ) -> str:
        """Format a message template with realistic values."""
        replacements = {
            "user": random.choice(LINUX_USERS),
            "ip": attacker_ip if attacker_ip else self.faker.ipv4_public(),
            "port": str(random.randint(1024, 65535)),
            "hash": self.faker.sha256()[:43],
            "tty": str(random.randint(0, 9)),
            "pwd": random.choice(["/home/admin", "/root", "/var/www", "/tmp"]),
            "cmd": random.choice(SUDO_COMMANDS),
            "service": random.choice(SERVICES),
            "status": str(random.choice([1, 2, 127, 137, 143])),
            "pid": str(random.randint(1000, 65535)),
            "comm": random.choice(["nginx", "python", "java", "node", "httpd"]),
            "path": random.choice(["/etc/passwd", "/var/log/syslog", "/tmp/malware"]),
            "action": random.choice(["read", "write", "execute", "open"]),
            "count": str(random.randint(5, 100)),
            "iface": random.choice(["eth0", "ens192", "ens33"]),
            "src_ip": attacker_ip if attacker_ip else self.faker.ipv4_public(),
            "dst_ip": self.faker.ipv4_private(),
            "proto": random.choice(["TCP", "UDP"]),
            "device": random.choice(["sda1", "sdb1", "nvme0n1p1"]),
            "error_msg": random.choice(["ext4_read_block_bitmap", "unable to read inode", "checksum error"]),
            "block": str(random.randint(100000, 999999)),
            "method": random.choice(["GET", "POST", "PUT", "DELETE"]),
            "timestamp": datetime.datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0000"),
            "bytes": str(random.randint(100, 50000)),
        }

        # Replace all placeholders
        message = template
        for key, value in replacements.items():
            message = message.replace("{" + key + "}", value)

        return message

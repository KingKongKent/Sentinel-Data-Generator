"""Tests for Pydantic schema models."""

import datetime

import pytest
from pydantic import ValidationError

from sentinel_data_generator.models.schemas import (
    CommonSecurityLogEvent,
    SecurityEvent,
    SigninLog,
    SyslogEvent,
)


NOW = datetime.datetime.now(datetime.timezone.utc)


class TestSyslogEvent:
    """Tests for SyslogEvent schema."""

    def test_valid_syslog_event(self) -> None:
        event = SyslogEvent(
            TimeGenerated=NOW,
            Computer="linux-web-01",
            HostIP="10.0.0.5",
            Facility="auth",
            SeverityLevel="warning",
            ProcessName="sshd",
            SyslogMessage="Failed password for root from 203.0.113.50 port 22 ssh2",
        )
        assert event.Computer == "linux-web-01"
        assert event.Facility == "auth"

    def test_missing_required_field_raises(self) -> None:
        with pytest.raises(ValidationError):
            SyslogEvent(
                TimeGenerated=NOW,
                Computer="linux-web-01",
                # Missing HostIP, Facility, SeverityLevel, ProcessName, SyslogMessage
            )

    def test_serialization_roundtrip(self) -> None:
        event = SyslogEvent(
            TimeGenerated=NOW,
            Computer="linux-web-01",
            HostIP="10.0.0.5",
            Facility="daemon",
            SeverityLevel="info",
            ProcessName="cron",
            SyslogMessage="Job completed",
        )
        data = event.model_dump()
        restored = SyslogEvent.model_validate(data)
        assert restored == event


class TestSecurityEvent:
    """Tests for SecurityEvent schema."""

    def test_valid_security_event(self) -> None:
        event = SecurityEvent(
            TimeGenerated=NOW,
            Computer="DC01.contoso.com",
            EventID=4625,
            Activity="4625 - An account failed to log on.",
            Account="admin",
            AccountType="User",
            LogonType=10,
            IpAddress="203.0.113.50",
        )
        assert event.EventID == 4625
        assert event.AccountType == "User"

    def test_optional_fields_default_none(self) -> None:
        event = SecurityEvent(
            TimeGenerated=NOW,
            Computer="DC01.contoso.com",
            EventID=4624,
            Activity="4624 - An account was successfully logged on.",
            Account="admin",
            AccountType="User",
        )
        assert event.LogonType is None
        assert event.IpAddress is None
        assert event.WorkstationName is None
        assert event.Status is None
        assert event.SubStatus is None

    def test_invalid_event_id_type_raises(self) -> None:
        with pytest.raises(ValidationError):
            SecurityEvent(
                TimeGenerated=NOW,
                Computer="DC01.contoso.com",
                EventID="not-a-number",  # type: ignore[arg-type]
                Activity="test",
                Account="admin",
                AccountType="User",
            )


class TestSigninLog:
    """Tests for SigninLog schema."""

    def test_valid_signin_log(self) -> None:
        event = SigninLog(
            TimeGenerated=NOW,
            UserPrincipalName="john.doe@contoso.com",
            UserDisplayName="John Doe",
            AppDisplayName="Azure Portal",
            IPAddress="198.51.100.1",
            Location="US",
            ResultType="0",
            ResultDescription="Success",
            ClientAppUsed="Browser",
        )
        assert event.UserPrincipalName == "john.doe@contoso.com"
        assert event.ResultType == "0"

    def test_defaults_applied(self) -> None:
        event = SigninLog(
            TimeGenerated=NOW,
            UserPrincipalName="jane@contoso.com",
            UserDisplayName="Jane",
            AppDisplayName="Teams",
            IPAddress="10.0.0.1",
            Location="NO",
            ResultType="0",
            ResultDescription="Success",
            ClientAppUsed="Mobile",
        )
        assert event.ConditionalAccessStatus == "notApplied"
        assert event.RiskLevelDuringSignIn == "none"
        assert event.RiskLevelAggregated == "none"

    def test_json_roundtrip(self) -> None:
        event = SigninLog(
            TimeGenerated=NOW,
            UserPrincipalName="user@contoso.com",
            UserDisplayName="User",
            AppDisplayName="Outlook",
            IPAddress="10.0.0.2",
            Location="SE",
            ResultType="50126",
            ResultDescription="Invalid username or password",
            ClientAppUsed="Browser",
            RiskLevelDuringSignIn="high",
        )
        json_str = event.model_dump_json()
        restored = SigninLog.model_validate_json(json_str)
        assert restored.RiskLevelDuringSignIn == "high"


class TestCommonSecurityLogEvent:
    """Tests for CommonSecurityLogEvent schema."""

    def test_valid_cef_event(self) -> None:
        event = CommonSecurityLogEvent(
            TimeGenerated=NOW,
            DeviceVendor="Palo Alto Networks",
            DeviceProduct="PAN-OS",
            DeviceVersion="10.1",
            DeviceEventClassID="TRAFFIC",
            Activity="deny",
            LogSeverity="High",
            SourceIP="198.51.100.10",
            DestinationIP="10.0.0.5",
            DestinationPort=443,
            Protocol="TCP",
        )
        assert event.DeviceVendor == "Palo Alto Networks"
        assert event.DestinationPort == 443

    def test_optional_ports_default_none(self) -> None:
        event = CommonSecurityLogEvent(
            TimeGenerated=NOW,
            DeviceVendor="Fortinet",
            DeviceProduct="FortiGate",
            DeviceVersion="7.0",
            DeviceEventClassID="0",
            Activity="allow",
            LogSeverity="Low",
            SourceIP="10.0.0.1",
            DestinationIP="10.0.0.2",
        )
        assert event.SourcePort is None
        assert event.DestinationPort is None
        assert event.Protocol is None
        assert event.RequestURL is None

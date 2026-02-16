"""Pydantic v2 schema models for Sentinel log types."""

from __future__ import annotations

import datetime

from pydantic import BaseModel, Field


class SyslogEvent(BaseModel):
    """Schema for Syslog table events."""

    TimeGenerated: datetime.datetime = Field(..., description="Event timestamp in UTC")
    Computer: str = Field(..., description="Hostname of the source machine")
    HostIP: str = Field(..., description="IP address of the source machine")
    Facility: str = Field(..., description="Syslog facility (e.g., auth, daemon)")
    SeverityLevel: str = Field(..., description="Syslog severity (e.g., info, warning, err)")
    ProcessName: str = Field(..., description="Name of the process that generated the event")
    SyslogMessage: str = Field(..., description="Syslog message body")


class SecurityEvent(BaseModel):
    """Schema for Windows SecurityEvent table events."""

    TimeGenerated: datetime.datetime = Field(..., description="Event timestamp in UTC")
    Computer: str = Field(..., description="Hostname of the Windows machine")
    EventID: int = Field(..., description="Windows Security event ID (e.g., 4624, 4625)")
    Activity: str = Field(..., description="Human-readable event description")
    Account: str = Field(..., description="Account name involved in the event")
    AccountType: str = Field(..., description="Account type (User or Machine)")
    LogonType: int | None = Field(None, description="Logon type number (for logon events)")
    IpAddress: str | None = Field(None, description="Source IP address")
    WorkstationName: str | None = Field(None, description="Source workstation name")
    Status: str | None = Field(None, description="Event status code")
    SubStatus: str | None = Field(None, description="Event sub-status code")


class SigninLog(BaseModel):
    """Schema for Azure AD / Entra ID SigninLogs table events."""

    TimeGenerated: datetime.datetime = Field(..., description="Event timestamp in UTC")
    UserPrincipalName: str = Field(..., description="UPN of the signing-in user")
    UserDisplayName: str = Field(..., description="Display name of the user")
    AppDisplayName: str = Field(..., description="Application display name")
    IPAddress: str = Field(..., description="Source IP address of the sign-in")
    Location: str = Field(..., description="Geographic location (country/region)")
    ResultType: str = Field(..., description="Sign-in result code (0 = success)")
    ResultDescription: str = Field(..., description="Human-readable result description")
    ClientAppUsed: str = Field(..., description="Client application used (e.g., Browser, Mobile)")
    ConditionalAccessStatus: str = Field("notApplied", description="CA policy evaluation result")
    RiskLevelDuringSignIn: str = Field("none", description="Risk level during sign-in")
    RiskLevelAggregated: str = Field("none", description="Aggregated risk level")


class CommonSecurityLogEvent(BaseModel):
    """Schema for CommonSecurityLog (CEF) table events."""

    TimeGenerated: datetime.datetime = Field(..., description="Event timestamp in UTC")
    DeviceVendor: str = Field(..., description="Vendor of the reporting device")
    DeviceProduct: str = Field(..., description="Product name of the reporting device")
    DeviceVersion: str = Field(..., description="Version of the reporting device")
    DeviceEventClassID: str = Field(..., description="Event class identifier")
    Activity: str = Field(..., description="Human-readable event name")
    LogSeverity: str = Field(..., description="Log severity (1-10)")
    SourceIP: str = Field(..., description="Source IP address")
    DestinationIP: str = Field(..., description="Destination IP address")
    SourcePort: int | None = Field(None, description="Source port number")
    DestinationPort: int | None = Field(None, description="Destination port number")
    Protocol: str | None = Field(None, description="Network protocol (TCP, UDP, etc.)")
    RequestURL: str | None = Field(None, description="Requested URL if applicable")

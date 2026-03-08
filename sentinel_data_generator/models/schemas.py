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
    """Schema for Microsoft Entra ID SigninLogs table events."""

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


class AWSCloudTrailEvent(BaseModel):
    """Schema for AWS CloudTrail audit log events.

    Mirrors the Sentinel AWSCloudTrail table schema used by the
    Amazon Web Services S3 connector.
    """

    TimeGenerated: datetime.datetime = Field(..., description="Event timestamp in UTC")
    EventName: str = Field(..., description="AWS API action name (e.g., ConsoleLogin, RunInstances)")
    EventSource: str = Field(..., description="AWS service (e.g., iam.amazonaws.com)")
    SourceIPAddress: str = Field(..., description="Caller IP address")
    UserIdentityArn: str = Field(..., description="ARN of the calling principal")
    UserIdentityType: str = Field(..., description="Identity type: Root, IAMUser, AssumedRole")
    UserAgent: str = Field(..., description="Caller user agent string")
    AWSRegion: str = Field(..., description="AWS region (e.g., us-east-1)")
    RecipientAccountId: str = Field(..., description="AWS account ID receiving the API call")
    ErrorCode: str | None = Field(None, description="Error code if the call failed")
    ErrorMessage: str | None = Field(None, description="Error message if the call failed")
    RequestParameters: str | None = Field(None, description="JSON-encoded request parameters")
    ResponseElements: str | None = Field(None, description="JSON-encoded response elements")


class GCPAuditLogEvent(BaseModel):
    """Schema for Google Cloud Platform audit log events.

    Mirrors the Sentinel GCPAuditLogs table schema used by the
    Google Cloud Platform connector.
    """

    TimeGenerated: datetime.datetime = Field(..., description="Event timestamp in UTC")
    ServiceName: str = Field(..., description="GCP service (e.g., iam.googleapis.com)")
    MethodName: str = Field(..., description="API method (e.g., SetIamPolicy)")
    CallerIP: str = Field(..., description="Caller IP address")
    PrincipalEmail: str = Field(..., description="Email of the calling principal")
    ResourceName: str = Field(..., description="Full resource path")
    ResourceType: str = Field(..., description="Resource type (e.g., gce_instance)")
    Severity: str = Field(..., description="Log severity: NOTICE, WARNING, ERROR, CRITICAL")
    ProjectId: str = Field(..., description="GCP project ID")
    StatusCode: int = Field(0, description="Status code (0 = success)")
    StatusMessage: str = Field("OK", description="Status message")
    AuthorizationInfo: str | None = Field(None, description="JSON-encoded authorization details")

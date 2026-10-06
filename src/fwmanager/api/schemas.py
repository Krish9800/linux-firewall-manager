"""Pydantic schemas for the REST API endpoints."""

from typing import List, Literal, Optional

from pydantic import BaseModel, Field

from fwmanager.models.rules import FirewallRule


class HealthResponse(BaseModel):
    """Health check response."""

    status: str = "ok"
    version: str
    backend: str


class AddRuleRequest(BaseModel):
    """Payload to add a single firewall rule."""

    chain: Literal["INPUT", "OUTPUT", "FORWARD"] = Field(..., description="Traffic chain target")
    protocol: Optional[Literal["tcp", "udp", "icmp", "all"]] = Field(
        None, description="Transport protocol"
    )
    port: Optional[str] = Field(None, description="Port or port range (e.g. 80, 8080-8090)")
    source_ip: Optional[str] = Field(None, description="Source IP address or CIDR")
    dest_ip: Optional[str] = Field(None, description="Destination IP address or CIDR")
    in_interface: Optional[str] = Field(None, description="Inbound network interface")
    out_interface: Optional[str] = Field(None, description="Outbound network interface")
    action: Literal["ACCEPT", "DROP", "REJECT", "LOG"] = Field(
        "ACCEPT", description="Firewall action"
    )
    comment: Optional[str] = Field(None, description="Operator comment or note")


class RulesListResponse(BaseModel):
    """List of active rules and policy name."""

    policy_name: str
    rules: List[FirewallRule]


class ApplyProfileRequest(BaseModel):
    """Payload to apply a predefined hardening profile."""

    profile_name: str = Field(..., description="Name of profile to apply")
    timeout_seconds: int = Field(30, ge=5, le=300, description="Safety switch confirmation window")


class ConfirmRollbackResponse(BaseModel):
    """Response returned upon confirmation or rollback of policy."""

    message: str
    status: str


class SafetyStatusResponse(BaseModel):
    """Status of the Deadman's switch."""

    armed: bool
    target_policy: str = ""
    remaining_seconds: float = 0.0
    reverted: bool = False


class ExportResponse(BaseModel):
    """Response containing exported ruleset in requested syntax."""

    format: str
    output: str

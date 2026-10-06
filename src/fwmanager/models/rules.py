"""Declarative models for firewall rules, chains, and overall policies."""

import uuid
from typing import List, Literal, Optional

from pydantic import BaseModel, Field, field_validator

from fwmanager.core.sanitizer import (
    sanitize_action,
    sanitize_identifier,
    sanitize_interface,
    sanitize_ip_or_cidr,
    sanitize_port_or_range,
    sanitize_protocol,
)

ProtocolType = Literal["tcp", "udp", "icmp", "all"]
ActionType = Literal["ACCEPT", "DROP", "REJECT", "LOG"]
ChainNameType = Literal["INPUT", "OUTPUT", "FORWARD"]


class FirewallRule(BaseModel):
    """Declarative specification for a single packet filtering rule."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    chain: str = Field(default="INPUT")
    protocol: ProtocolType = Field(default="tcp")
    port: Optional[str] = Field(
        default=None, description="Port or port range (e.g. '80', '80:443')"
    )
    source_ip: Optional[str] = Field(default=None, description="Source IP or CIDR network")
    destination_ip: Optional[str] = Field(default=None, description="Destination IP or CIDR")
    interface_in: Optional[str] = Field(default=None, description="Inbound network interface")
    interface_out: Optional[str] = Field(default=None, description="Outbound network interface")
    state: Optional[List[str]] = Field(
        default=None, description="Connection states: NEW, ESTABLISHED, RELATED, INVALID"
    )
    action: ActionType = Field(default="ACCEPT")
    comment: Optional[str] = Field(default=None, max_length=128)

    @field_validator("chain")
    @classmethod
    def validate_chain(cls, v: str) -> str:
        """Validate chain identifier."""
        return sanitize_identifier(v, "Chain")

    @field_validator("protocol")
    @classmethod
    def validate_protocol(cls, v: str) -> ProtocolType:
        """Validate protocol."""
        return sanitize_protocol(v)

    @field_validator("action")
    @classmethod
    def validate_action(cls, v: str) -> ActionType:
        """Validate action target."""
        return sanitize_action(v)

    @field_validator("port")
    @classmethod
    def validate_port(cls, v: Optional[str]) -> Optional[str]:
        """Validate port format if present."""
        return sanitize_port_or_range(v) if v is not None else None

    @field_validator("source_ip", "destination_ip")
    @classmethod
    def validate_ips(cls, v: Optional[str]) -> Optional[str]:
        """Validate IP/CIDR formats if present."""
        return sanitize_ip_or_cidr(v) if v is not None else None

    @field_validator("interface_in", "interface_out")
    @classmethod
    def validate_interfaces(cls, v: Optional[str]) -> Optional[str]:
        """Validate interface strings if present."""
        return sanitize_interface(v) if v is not None else None


class ChainDefaultPolicy(BaseModel):
    """Default policy for a standard chain."""

    chain: str
    default_action: ActionType = "DROP"

    @field_validator("chain")
    @classmethod
    def validate_chain(cls, v: str) -> str:
        return sanitize_identifier(v, "Chain")

    @field_validator("default_action")
    @classmethod
    def validate_action(cls, v: str) -> ActionType:
        return sanitize_action(v)


class FirewallPolicy(BaseModel):
    """Consolidated declarative firewall policy containing rules and default chain actions."""

    name: str = Field(default="default_policy")
    description: str = Field(default="Declarative Linux firewall policy")
    chain_defaults: List[ChainDefaultPolicy] = Field(
        default_factory=lambda: [
            ChainDefaultPolicy(chain="INPUT", default_action="DROP"),
            ChainDefaultPolicy(chain="FORWARD", default_action="DROP"),
            ChainDefaultPolicy(chain="OUTPUT", default_action="ACCEPT"),
        ]
    )
    rules: List[FirewallRule] = Field(default_factory=list)

    def get_rule_by_id(self, rule_id: str) -> Optional[FirewallRule]:
        """Find a rule by its ID."""
        for r in self.rules:
            if r.id == rule_id:
                return r
        return None

    def add_rule(self, rule: FirewallRule) -> None:
        """Append a new rule to policy."""
        self.rules.append(rule)

    def delete_rule(self, rule_id: str) -> bool:
        """Remove a rule by ID; returns True if deleted."""
        initial_len = len(self.rules)
        self.rules = [r for r in self.rules if r.id != rule_id]
        return len(self.rules) < initial_len

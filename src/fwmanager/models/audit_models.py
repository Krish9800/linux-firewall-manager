"""Audit and telemetry domain models for Linux Firewall Manager."""

import hashlib
import json
from typing import Dict, List

from pydantic import BaseModel, Field

from fwmanager.models.rules import FirewallPolicy, FirewallRule


class PolicyAuditReport(BaseModel):
    """Consolidated audit report for an active or staged firewall policy."""

    policy_name: str
    description: str
    timestamp: str
    rules_count: int
    default_chain_policies: Dict[str, str] = Field(default_factory=dict)
    policy_sha256: str = ""
    rules: List[FirewallRule] = Field(default_factory=list)

    @classmethod
    def from_policy(cls, policy: FirewallPolicy, timestamp: str) -> "PolicyAuditReport":
        """Construct audit report from FirewallPolicy with deterministic SHA-256 digest."""
        defaults = {cd.chain: str(cd.default_action) for cd in policy.chain_defaults}
        raw_dict = policy.model_dump()
        canonical_json = json.dumps(raw_dict, sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()

        return cls(
            policy_name=policy.name,
            description=policy.description,
            timestamp=timestamp,
            rules_count=len(policy.rules),
            default_chain_policies=defaults,
            policy_sha256=digest,
            rules=policy.rules,
        )

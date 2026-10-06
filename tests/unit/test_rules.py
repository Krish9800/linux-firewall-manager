"""Unit tests for declarative firewall rule models and policies."""

import pytest
from pydantic import ValidationError

from fwmanager.models.rules import ChainDefaultPolicy, FirewallPolicy, FirewallRule


def test_firewall_rule_valid_creation() -> None:
    """Test valid rule instantiation."""
    rule = FirewallRule(
        id="ssh-in",
        chain="INPUT",
        protocol="tcp",
        port="22",
        source_ip="192.168.1.0/24",
        action="ACCEPT",
        comment="Allow SSH from local network",
    )
    assert rule.id == "ssh-in"
    assert rule.port == "22"
    assert rule.source_ip == "192.168.1.0/24"
    assert rule.action == "ACCEPT"


def test_firewall_rule_validation_failures() -> None:
    """Test rejection of invalid fields in FirewallRule."""
    with pytest.raises(ValidationError):
        FirewallRule(chain="INVALID_CHAIN_NAME_WITH_SPACES!!!")

    with pytest.raises(ValidationError):
        FirewallRule(protocol="unsupported_protocol")  # type: ignore[arg-type]

    with pytest.raises(ValidationError):
        FirewallRule(port="999999")

    with pytest.raises(ValidationError):
        FirewallRule(source_ip="invalid.ip.address")

    with pytest.raises(ValidationError):
        FirewallRule(interface_in="invalid/interface/name")


def test_firewall_policy_operations() -> None:
    """Test policy manipulation (add, find, delete)."""
    policy = FirewallPolicy(name="production_web")
    assert len(policy.rules) == 0

    r1 = FirewallRule(id="rule-http", chain="INPUT", protocol="tcp", port="80", action="ACCEPT")
    r2 = FirewallRule(id="rule-https", chain="INPUT", protocol="tcp", port="443", action="ACCEPT")

    policy.add_rule(r1)
    policy.add_rule(r2)
    assert len(policy.rules) == 2

    found = policy.get_rule_by_id("rule-http")
    assert found is not None
    assert found.port == "80"

    assert policy.get_rule_by_id("nonexistent") is None

    # Delete rule
    assert policy.delete_rule("rule-http") is True
    assert len(policy.rules) == 1
    assert policy.delete_rule("rule-http") is False


def test_chain_default_policy() -> None:
    """Test default chain policy validation."""
    cd = ChainDefaultPolicy(chain="INPUT", default_action="DROP")
    assert cd.chain == "INPUT"
    assert cd.default_action == "DROP"

    with pytest.raises(ValidationError):
        ChainDefaultPolicy(chain="INPUT", default_action="FORWARD")  # type: ignore[arg-type]

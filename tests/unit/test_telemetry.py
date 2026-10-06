"""Unit tests for firewall audit reports and ArcSight CEF telemetry."""

import json

from fwmanager.models.audit_models import PolicyAuditReport
from fwmanager.models.rules import FirewallPolicy, FirewallRule
from fwmanager.telemetry.cef_exporter import (
    export_cef_policy_applied,
    export_cef_rule_event,
    export_json_audit,
)


def test_policy_audit_report_generation() -> None:
    """Test generating audit report with deterministic hash."""
    policy = FirewallPolicy(name="audit_test")
    policy.add_rule(
        FirewallRule(id="rule-http", chain="INPUT", protocol="tcp", port="80", action="ACCEPT")
    )

    report = PolicyAuditReport.from_policy(policy, timestamp="2026-10-06T12:00:00Z")
    assert report.policy_name == "audit_test"
    assert report.rules_count == 1
    assert len(report.policy_sha256) == 64
    assert report.default_chain_policies["INPUT"] == "DROP"


def test_export_cef_policy_applied() -> None:
    """Test CEF event string for policy application."""
    policy = FirewallPolicy(name="prod_fw")
    report = PolicyAuditReport.from_policy(policy, timestamp="2026-10-06T12:00:00Z")

    cef = export_cef_policy_applied(report)
    assert cef.startswith(
        "CEF:0|LinuxFirewallManager|FirewallManager|0.1.0|FW-100|PolicyApplied|5|"
    )
    assert "cs1=prod_fw" in cef
    assert "cn1=0" in cef
    assert "cs2Label=PolicyHashDigest" in cef


def test_export_cef_rule_event() -> None:
    """Test CEF event for an individual rule modification."""
    rule = FirewallRule(
        id="ssh-rule",
        chain="INPUT",
        protocol="tcp",
        port="22",
        source_ip="10.0.0.0/24",
        action="ACCEPT",
        comment="Admin SSH",
    )
    cef = export_cef_rule_event("RuleAdded", rule)
    assert "FW-200|RuleAdded|3|" in cef
    assert "act=ACCEPT" in cef
    assert "proto=tcp" in cef
    assert "dpt=22" in cef
    assert "src=10.0.0.0/24" in cef
    assert "msg=Admin SSH" in cef


def test_export_json_audit() -> None:
    """Test JSON audit export."""
    policy = FirewallPolicy(name="json_test")
    report = PolicyAuditReport.from_policy(policy, timestamp="2026-10-06T12:00:00Z")

    json_str = export_json_audit(report)
    parsed = json.loads(json_str)
    assert parsed["policy_name"] == "json_test"
    assert len(parsed["policy_sha256"]) == 64

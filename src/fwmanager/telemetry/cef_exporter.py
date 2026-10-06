"""ArcSight Common Event Format (CEF) and JSON audit exporters."""

import json

from fwmanager.models.audit_models import PolicyAuditReport
from fwmanager.models.rules import FirewallRule


def _escape_cef(value: str) -> str:
    """Escape backslashes, pipes, and equals signs for CEF values."""
    return str(value).replace("\\", "\\\\").replace("|", "\\|").replace("=", "\\=")


def export_cef_policy_applied(report: PolicyAuditReport) -> str:
    """Format PolicyAuditReport into an ArcSight CEF event."""
    extensions = [
        f"cs1={_escape_cef(report.policy_name)}",
        "cs1Label=PolicyName",
        f"cn1={report.rules_count}",
        "cn1Label=RuleCount",
        f"cs2={_escape_cef(report.policy_sha256[:16])}",
        "cs2Label=PolicyHashDigest",
        f"msg={_escape_cef(f'Applied policy {report.policy_name} ({report.rules_count} rules)')}",
    ]
    ext_str = " ".join(extensions)
    return f"CEF:0|LinuxFirewallManager|FirewallManager|0.1.0|FW-100|PolicyApplied|5|{ext_str}"


def export_cef_rule_event(event_type: str, rule: FirewallRule) -> str:
    """Format rule modification event into an ArcSight CEF line."""
    action_severity = 3 if rule.action in ("ACCEPT", "LOG") else 6

    extensions = [
        f"act={_escape_cef(rule.action)}",
        f"proto={_escape_cef(rule.protocol)}",
        f"cs1={_escape_cef(rule.chain)}",
        "cs1Label=Chain",
        f"cs2={_escape_cef(rule.id)}",
        "cs2Label=RuleId",
    ]
    if rule.port:
        extensions.append(f"dpt={rule.port}")
    if rule.source_ip:
        extensions.append(f"src={rule.source_ip}")
    if rule.comment:
        extensions.append(f"msg={_escape_cef(rule.comment)}")

    ext_str = " ".join(extensions)
    return (
        f"CEF:0|LinuxFirewallManager|FirewallManager|0.1.0|"
        f"FW-200|{event_type}|{action_severity}|{ext_str}"
    )


def export_json_audit(report: PolicyAuditReport, indent: int = 2) -> str:
    """Export PolicyAuditReport as indented JSON."""
    return json.dumps(report.model_dump(), indent=indent, sort_keys=True)

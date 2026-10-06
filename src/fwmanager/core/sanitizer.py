"""Strict validation and sanitization for firewall identifiers, interfaces, and rules."""

import ipaddress
import re
from typing import Literal

IDENTIFIER_REGEX = re.compile(r"^[A-Za-z0-9_-]{1,32}$")
INTERFACE_REGEX = re.compile(r"^[A-Za-z0-9_.+-]{1,16}$")


class RuleValidationError(ValueError):
    """Raised when firewall parameters fail validation."""


def sanitize_identifier(name: str, field_name: str = "Identifier") -> str:
    """Validate and normalize chain, table, or profile identifier."""
    cleaned = name.strip()
    if not IDENTIFIER_REGEX.match(cleaned):
        raise RuleValidationError(
            f"Invalid {field_name} '{name}': must be 1-32 alphanumeric, dash, or underscore chars."
        )
    return cleaned


def sanitize_interface(interface: str) -> str:
    """Validate network interface identifier (e.g., eth0, wlan0, wg0)."""
    cleaned = interface.strip()
    if not INTERFACE_REGEX.match(cleaned):
        raise RuleValidationError(
            f"Invalid network interface '{interface}': must be 1-16 valid interface characters."
        )
    return cleaned


def sanitize_ip_or_cidr(target: str) -> str:
    """Validate IP address or CIDR notation."""
    cleaned = target.strip()
    try:
        network = ipaddress.ip_network(cleaned, strict=False)
        return str(network)
    except ValueError as exc:
        raise RuleValidationError(f"Invalid IP address or CIDR '{target}': {exc}") from exc


def sanitize_port_or_range(port_spec: str | int) -> str:
    """Validate port number or range (e.g., 80, '80', '80:443', '1000-2000')."""
    raw = str(port_spec).strip()
    # Normalize range separator
    norm = raw.replace("-", ":")
    if ":" in norm:
        parts = norm.split(":")
        if len(parts) != 2:
            raise RuleValidationError(f"Invalid port range '{raw}'")
        try:
            start, end = int(parts[0]), int(parts[1])
            if not (1 <= start <= 65535 and 1 <= end <= 65535 and start <= end):
                raise RuleValidationError(f"Port range '{raw}' out of bounds (1-65535).")
            return f"{start}:{end}"
        except ValueError as exc:
            raise RuleValidationError(f"Invalid non-integer port range '{raw}': {exc}") from exc

    try:
        port_num = int(norm)
        if not (1 <= port_num <= 65535):
            raise RuleValidationError(f"Port {port_num} out of valid range (1-65535).")
        return str(port_num)
    except ValueError as exc:
        raise RuleValidationError(f"Invalid non-integer port '{raw}': {exc}") from exc


def sanitize_protocol(proto: str) -> Literal["tcp", "udp", "icmp", "all"]:
    """Normalize and validate protocol."""
    p = proto.strip().lower()
    if p not in ("tcp", "udp", "icmp", "all"):
        raise RuleValidationError(
            f"Unsupported protocol '{proto}': must be tcp, udp, icmp, or all."
        )
    return p  # type: ignore[return-value]


def sanitize_action(action: str) -> Literal["ACCEPT", "DROP", "REJECT", "LOG"]:
    """Normalize and validate rule target action."""
    act = action.strip().upper()
    if act not in ("ACCEPT", "DROP", "REJECT", "LOG"):
        raise RuleValidationError(
            f"Invalid firewall action '{action}': must be ACCEPT, DROP, REJECT, or LOG."
        )
    return act  # type: ignore[return-value]

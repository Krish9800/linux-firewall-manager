"""Unit tests for Phase 1 foundations, settings, and sanitizers."""

import pytest

from fwmanager.config.settings import Settings
from fwmanager.core.sanitizer import (
    RuleValidationError,
    sanitize_action,
    sanitize_identifier,
    sanitize_interface,
    sanitize_ip_or_cidr,
    sanitize_port_or_range,
    sanitize_protocol,
)


def test_settings_defaults() -> None:
    """Verify settings defaults and types."""
    s = Settings()
    assert s.app_name == "Linux Firewall Manager"
    assert s.backend == "simulation"
    assert s.auto_rollback_timeout == 30


def test_sanitize_identifier() -> None:
    """Test valid and invalid identifier sanitization."""
    assert sanitize_identifier("INPUT") == "INPUT"
    assert sanitize_identifier("custom_chain_1") == "custom_chain_1"
    assert sanitize_identifier("my-filter") == "my-filter"

    with pytest.raises(RuleValidationError):
        sanitize_identifier("chain; rm -rf /")

    with pytest.raises(RuleValidationError):
        sanitize_identifier("has spaces")

    with pytest.raises(RuleValidationError):
        sanitize_identifier("")


def test_sanitize_interface() -> None:
    """Test network interface sanitization."""
    assert sanitize_interface("eth0") == "eth0"
    assert sanitize_interface("wlan0") == "wlan0"
    assert sanitize_interface("wg0") == "wg0"
    assert sanitize_interface("lo") == "lo"

    with pytest.raises(RuleValidationError):
        sanitize_interface("eth0; reboot")


def test_sanitize_ip_or_cidr() -> None:
    """Test IP and CIDR notation validation."""
    assert sanitize_ip_or_cidr("192.168.1.0/24") == "192.168.1.0/24"
    assert sanitize_ip_or_cidr("10.0.0.1") == "10.0.0.1/32"
    assert sanitize_ip_or_cidr("::1") == "::1/128"

    with pytest.raises(RuleValidationError):
        sanitize_ip_or_cidr("999.999.999.999")


def test_sanitize_port_or_range() -> None:
    """Test port and port range sanitization."""
    assert sanitize_port_or_range(80) == "80"
    assert sanitize_port_or_range("443") == "443"
    assert sanitize_port_or_range("8000:8080") == "8000:8080"
    assert sanitize_port_or_range("8000-8080") == "8000:8080"

    with pytest.raises(RuleValidationError):
        sanitize_port_or_range(70000)

    with pytest.raises(RuleValidationError):
        sanitize_port_or_range(0)

    with pytest.raises(RuleValidationError):
        sanitize_port_or_range("8080:8000")  # inverted

    with pytest.raises(RuleValidationError):
        sanitize_port_or_range("invalid")


def test_sanitize_protocol() -> None:
    """Test protocol validation."""
    assert sanitize_protocol("TCP") == "tcp"
    assert sanitize_protocol("udp") == "udp"
    assert sanitize_protocol("ICMP") == "icmp"
    assert sanitize_protocol("all") == "all"

    with pytest.raises(RuleValidationError):
        sanitize_protocol("sctp")


def test_sanitize_action() -> None:
    """Test action validation."""
    assert sanitize_action("accept") == "ACCEPT"
    assert sanitize_action("DROP") == "DROP"
    assert sanitize_action("reject") == "REJECT"
    assert sanitize_action("log") == "LOG"

    with pytest.raises(RuleValidationError):
        sanitize_action("FORWARD")

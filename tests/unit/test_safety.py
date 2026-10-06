"""Unit tests for DeadmanSwitch safety rollback engine."""

import time

import pytest

from fwmanager.models.rules import FirewallPolicy, FirewallRule
from fwmanager.safety.deadman_switch import DeadmanSwitch, SafetyStatus


def test_deadman_switch_confirm() -> None:
    """Test standard arm and confirm flow without rollback."""
    switch = DeadmanSwitch(default_timeout=5)
    p_orig = FirewallPolicy(name="original")
    p_new = FirewallPolicy(name="new_policy")

    reverted_policy = None

    def _callback(snapshot: FirewallPolicy) -> None:
        nonlocal reverted_policy
        reverted_policy = snapshot

    switch.arm(p_orig, p_new, _callback, timeout=2)
    assert switch.is_armed is True

    status = switch.get_status()
    assert isinstance(status, SafetyStatus)
    assert status.is_armed is True
    assert status.target_policy_name == "new_policy"
    assert status.remaining_seconds > 0

    # Confirm before timeout
    assert switch.confirm() is True
    assert switch.is_armed is False
    assert reverted_policy is None


def test_deadman_switch_auto_revert_on_timeout() -> None:
    """Test auto-revert triggered when confirmation timer expires."""
    switch = DeadmanSwitch(default_timeout=1)
    p_orig = FirewallPolicy(name="original_safe")
    p_orig.add_rule(
        FirewallRule(id="ssh", chain="INPUT", protocol="tcp", port="22", action="ACCEPT")
    )
    p_bad = FirewallPolicy(name="bad_lockout")

    reverted_policy: FirewallPolicy | None = None

    def _callback(snapshot: FirewallPolicy) -> None:
        nonlocal reverted_policy
        reverted_policy = snapshot

    # Arm with tiny timeout 0.1s
    switch.arm(p_orig, p_bad, _callback, timeout=0.1)
    time.sleep(0.25)

    assert switch.is_armed is False
    assert reverted_policy is not None
    assert reverted_policy.name == "original_safe"
    assert len(reverted_policy.rules) == 1
    assert reverted_policy.rules[0].id == "ssh"


def test_deadman_switch_manual_rollback() -> None:
    """Test manual rollback prior to timer expiration."""
    switch = DeadmanSwitch(default_timeout=10)
    p_orig = FirewallPolicy(name="base_safe")
    p_new = FirewallPolicy(name="test")

    reverted_policy = None

    def _callback(snapshot: FirewallPolicy) -> None:
        nonlocal reverted_policy
        reverted_policy = snapshot

    switch.arm(p_orig, p_new, _callback, timeout=10)
    assert switch.manual_rollback() is True
    assert switch.is_armed is False
    assert reverted_policy is not None
    assert reverted_policy.name == "base_safe"


def test_deadman_switch_double_arm_raises() -> None:
    """Test that arming twice without confirmation raises RuntimeError."""
    switch = DeadmanSwitch(default_timeout=5)
    p = FirewallPolicy(name="p")
    switch.arm(p, p, lambda x: None, timeout=5)

    with pytest.raises(RuntimeError):
        switch.arm(p, p, lambda x: None, timeout=5)

    switch.confirm()

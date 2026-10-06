"""Unit tests for firewall execution drivers."""

import pytest

from fwmanager.core.executor import (
    ExecutionResult,
    KernelDriver,
    SimulationDriver,
    get_driver,
)
from fwmanager.models.rules import FirewallPolicy, FirewallRule


def test_simulation_driver_apply_and_flush() -> None:
    """Test SimulationDriver applying policies in memory without kernel changes."""
    driver = SimulationDriver()
    assert driver.get_active_policy() is None

    policy = FirewallPolicy(name="sim_test")
    policy.add_rule(
        FirewallRule(id="rule-1", chain="INPUT", protocol="tcp", port="80", action="ACCEPT")
    )

    result = driver.apply_policy(policy)
    assert isinstance(result, ExecutionResult)
    assert result.success is True
    assert result.backend == "simulation"
    assert len(result.executed_commands) > 0

    active = driver.get_active_policy()
    assert active is not None
    assert active.name == "sim_test"
    assert len(active.rules) == 1

    # Flush
    flush_res = driver.flush()
    assert flush_res.success is True
    assert driver.get_active_policy() is None


def test_kernel_driver_unprivileged_check() -> None:
    """Test KernelDriver raises PermissionError when run as unprivileged user."""
    driver = KernelDriver(backend_type="nftables")
    policy = FirewallPolicy(name="kernel_test")

    with pytest.raises(PermissionError):
        driver.apply_policy(policy)

    with pytest.raises(PermissionError):
        driver.flush()


def test_get_driver_factory() -> None:
    """Test driver factory instantiation."""
    drv_sim = get_driver("simulation")
    assert isinstance(drv_sim, SimulationDriver)

    drv_nft = get_driver("nftables")
    assert isinstance(drv_nft, KernelDriver)

    drv_default = get_driver()
    assert isinstance(drv_default, SimulationDriver)


def test_kernel_driver_nftables_mocked(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test KernelDriver nftables apply and flush with mocked root permissions."""
    import subprocess
    from unittest.mock import MagicMock

    monkeypatch.setattr("os.geteuid", lambda: 0)

    # Success case
    mock_run = MagicMock(
        return_value=subprocess.CompletedProcess(args=["nft"], returncode=0, stdout="", stderr="")
    )
    monkeypatch.setattr("subprocess.run", mock_run)

    driver = KernelDriver(backend_type="nftables")
    policy = FirewallPolicy(name="kernel_nft_test")
    policy.add_rule(
        FirewallRule(id="rule-k1", chain="INPUT", protocol="tcp", port="443", action="ACCEPT")
    )

    res = driver.apply_policy(policy)
    assert res.success is True
    assert driver.get_active_policy() is not None

    # Flush
    flush_res = driver.flush()
    assert flush_res.success is True
    assert driver.get_active_policy() is None

    # Failure case
    mock_fail = MagicMock(
        return_value=subprocess.CompletedProcess(
            args=["nft"], returncode=1, stdout="", stderr="Syntax error"
        )
    )
    monkeypatch.setattr("subprocess.run", mock_fail)
    res_fail = driver.apply_policy(policy)
    assert res_fail.success is False
    assert "Syntax error" in res_fail.message


def test_kernel_driver_iptables_mocked(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test KernelDriver iptables apply and flush with mocked root permissions."""
    import subprocess
    from unittest.mock import MagicMock

    monkeypatch.setattr("os.geteuid", lambda: 0)

    # Success case
    mock_run = MagicMock(
        return_value=subprocess.CompletedProcess(
            args=["iptables"], returncode=0, stdout="", stderr=""
        )
    )
    monkeypatch.setattr("subprocess.run", mock_run)

    driver = KernelDriver(backend_type="iptables")
    policy = FirewallPolicy(name="kernel_ipt_test")
    policy.add_rule(
        FirewallRule(id="rule-k2", chain="INPUT", protocol="tcp", port="22", action="ACCEPT")
    )

    res = driver.apply_policy(policy)
    assert res.success is True

    # Flush
    flush_res = driver.flush()
    assert flush_res.success is True

    # Failure case
    mock_fail = MagicMock(
        return_value=subprocess.CompletedProcess(
            args=["iptables"], returncode=2, stdout="", stderr="Bad rule"
        )
    )
    monkeypatch.setattr("subprocess.run", mock_fail)
    res_fail = driver.apply_policy(policy)
    assert res_fail.success is False
    assert "Bad rule" in res_fail.message

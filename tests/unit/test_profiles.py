"""Unit tests for hardened firewall security profiles."""

import pytest

from fwmanager.profiles.library import (
    dmz_proxy_profile,
    get_profile,
    hardened_server_profile,
    list_profiles,
    stealth_drop_profile,
    workstation_profile,
)


def test_hardened_server_profile() -> None:
    """Test hardened server profile defaults and custom SSH CIDR."""
    p = hardened_server_profile(trusted_ssh_cidr="10.0.0.0/24")
    assert p.name == "hardened_server"
    assert any(cd.chain == "INPUT" and cd.default_action == "DROP" for cd in p.chain_defaults)

    ssh_rule = next((r for r in p.rules if r.port == "22"), None)
    assert ssh_rule is not None
    assert ssh_rule.source_ip == "10.0.0.0/24"
    assert ssh_rule.action == "ACCEPT"

    # Verify loopback and state tracking are present
    assert any(r.interface_in == "lo" for r in p.rules)
    assert any(r.state == ["ESTABLISHED", "RELATED"] for r in p.rules)


def test_workstation_profile() -> None:
    """Test workstation profile."""
    p = workstation_profile()
    assert p.name == "workstation"
    assert len(p.rules) == 3
    assert any(r.interface_in == "lo" for r in p.rules)


def test_dmz_proxy_profile() -> None:
    """Test DMZ proxy profile."""
    p = dmz_proxy_profile(admin_cidr="192.168.10.0/24")
    assert p.name == "dmz_proxy"
    assert any(r.port == "80" for r in p.rules)
    assert any(r.port == "443" for r in p.rules)
    assert any(r.port == "22" and r.source_ip == "192.168.10.0/24" for r in p.rules)


def test_stealth_drop_profile() -> None:
    """Test air-gapped stealth drop profile."""
    p = stealth_drop_profile()
    assert p.name == "stealth_drop"
    # All 3 chains default to DROP
    assert all(cd.default_action == "DROP" for cd in p.chain_defaults)


def test_get_profile_factory_and_list() -> None:
    """Test factory resolution and list helper."""
    p_server = get_profile("server")
    assert p_server.name == "hardened_server"

    p_dmz = get_profile("dmz")
    assert p_dmz.name == "dmz_proxy"

    p_ws = get_profile("workstation")
    assert p_ws.name == "workstation"

    p_stealth = get_profile("stealth")
    assert p_stealth.name == "stealth_drop"

    with pytest.raises(ValueError):
        get_profile("nonexistent_profile_xyz")

    profiles_list = list_profiles()
    assert len(profiles_list) == 4
    assert any(item["name"] == "hardened_server" for item in profiles_list)

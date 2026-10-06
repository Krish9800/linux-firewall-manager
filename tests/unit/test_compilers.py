"""Unit tests for nftables and iptables rule compilers."""

from fwmanager.compilers.iptables_compiler import IptablesCompiler
from fwmanager.compilers.nft_compiler import NftablesCompiler
from fwmanager.models.rules import FirewallPolicy, FirewallRule


def test_nftables_compile_rule() -> None:
    """Test individual rule compilation to nftables syntax."""
    rule = FirewallRule(
        id="allow-ssh",
        chain="INPUT",
        protocol="tcp",
        port="22",
        source_ip="10.0.0.0/24",
        state=["NEW", "ESTABLISHED"],
        action="ACCEPT",
        comment="SSH Admin Access",
    )
    compiled = NftablesCompiler.compile_rule(rule)
    assert "ip saddr 10.0.0.0/24" in compiled
    assert "ct state { new,established }" in compiled
    assert "tcp dport 22" in compiled
    assert "accept" in compiled
    assert 'comment "SSH Admin Access"' in compiled


def test_nftables_compile_policy() -> None:
    """Test policy compilation into complete nftables table structure."""
    policy = FirewallPolicy(name="hardened_base")
    policy.add_rule(
        FirewallRule(
            id="est-rel",
            chain="INPUT",
            protocol="all",
            state=["ESTABLISHED", "RELATED"],
            action="ACCEPT",
        )
    )
    compiler = NftablesCompiler()
    conf = compiler.compile_policy(policy)

    assert "table inet filter {" in conf
    assert "chain INPUT {" in conf
    assert "type filter hook input priority 0; policy drop;" in conf
    assert "ct state { established,related } accept" in conf


def test_iptables_compile_rule() -> None:
    """Test individual rule compilation to iptables arguments."""
    rule = FirewallRule(
        id="http-in",
        chain="INPUT",
        protocol="tcp",
        port="80",
        action="ACCEPT",
        interface_in="eth0",
    )
    compiled = IptablesCompiler.compile_rule(rule)
    assert compiled.startswith("iptables -A INPUT")
    assert "-i eth0" in compiled
    assert "-p tcp" in compiled
    assert "--dport 80" in compiled
    assert "-j ACCEPT" in compiled


def test_iptables_compile_policy() -> None:
    """Test policy compilation to sequential iptables commands."""
    policy = FirewallPolicy(name="dmz")
    policy.add_rule(
        FirewallRule(id="drop-bad", chain="INPUT", protocol="tcp", port="23", action="DROP")
    )
    compiler = IptablesCompiler()
    cmds = compiler.compile_policy(policy)

    assert any("iptables -F" in c for c in cmds)
    assert any("iptables -P INPUT DROP" in c for c in cmds)
    assert any("iptables -A INPUT -p tcp --dport 23 -j DROP" in c for c in cmds)

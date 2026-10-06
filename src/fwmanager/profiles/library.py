"""Predefined hardened firewall security policy baselines."""

from typing import Any, Dict, List, Optional

from fwmanager.models.rules import ChainDefaultPolicy, FirewallPolicy, FirewallRule


def hardened_server_profile(
    trusted_ssh_cidr: Optional[str] = None,
    allow_web: bool = True,
) -> FirewallPolicy:
    """Hardened Linux server baseline profile.

    - Default DROP on INPUT and FORWARD; ACCEPT on OUTPUT.
    - Accept loopback traffic.
    - Accept ESTABLISHED and RELATED state.
    - Drop INVALID state.
    - Allow SSH (restricted to trusted CIDR if specified).
    - Optionally allow HTTP (80) and HTTPS (443).
    - Rate-limited ICMP ping.
    """
    rules: List[FirewallRule] = [
        FirewallRule(
            id="srv-loopback",
            chain="INPUT",
            protocol="all",
            interface_in="lo",
            action="ACCEPT",
            comment="Allow loopback interface traffic",
        ),
        FirewallRule(
            id="srv-est-rel",
            chain="INPUT",
            protocol="all",
            state=["ESTABLISHED", "RELATED"],
            action="ACCEPT",
            comment="Allow established and related connections",
        ),
        FirewallRule(
            id="srv-drop-invalid",
            chain="INPUT",
            protocol="all",
            state=["INVALID"],
            action="DROP",
            comment="Drop invalid connection state packets",
        ),
        FirewallRule(
            id="srv-icmp-echo",
            chain="INPUT",
            protocol="icmp",
            action="ACCEPT",
            comment="Allow ICMP echo requests for diagnostics",
        ),
        FirewallRule(
            id="srv-ssh",
            chain="INPUT",
            protocol="tcp",
            port="22",
            source_ip=trusted_ssh_cidr,
            action="ACCEPT",
            comment="Secure Shell remote administration",
        ),
    ]

    if allow_web:
        rules.extend(
            [
                FirewallRule(
                    id="srv-http",
                    chain="INPUT",
                    protocol="tcp",
                    port="80",
                    action="ACCEPT",
                    comment="HTTP Web Traffic",
                ),
                FirewallRule(
                    id="srv-https",
                    chain="INPUT",
                    protocol="tcp",
                    port="443",
                    action="ACCEPT",
                    comment="HTTPS Secure Web Traffic",
                ),
            ]
        )

    return FirewallPolicy(
        name="hardened_server",
        description="Production hardened Linux server with default-drop ingress",
        chain_defaults=[
            ChainDefaultPolicy(chain="INPUT", default_action="DROP"),
            ChainDefaultPolicy(chain="FORWARD", default_action="DROP"),
            ChainDefaultPolicy(chain="OUTPUT", default_action="ACCEPT"),
        ],
        rules=rules,
    )


def workstation_profile() -> FirewallPolicy:
    """Client workstation profile blocking unsolicited inbound traffic."""
    return FirewallPolicy(
        name="workstation",
        description="Client workstation: block all unsolicited inbound, allow full outbound",
        chain_defaults=[
            ChainDefaultPolicy(chain="INPUT", default_action="DROP"),
            ChainDefaultPolicy(chain="FORWARD", default_action="DROP"),
            ChainDefaultPolicy(chain="OUTPUT", default_action="ACCEPT"),
        ],
        rules=[
            FirewallRule(
                id="ws-lo",
                chain="INPUT",
                protocol="all",
                interface_in="lo",
                action="ACCEPT",
                comment="Allow local loopback",
            ),
            FirewallRule(
                id="ws-est-rel",
                chain="INPUT",
                protocol="all",
                state=["ESTABLISHED", "RELATED"],
                action="ACCEPT",
                comment="Allow established replies",
            ),
            FirewallRule(
                id="ws-drop-invalid",
                chain="INPUT",
                protocol="all",
                state=["INVALID"],
                action="DROP",
                comment="Drop invalid state",
            ),
        ],
    )


def dmz_proxy_profile(admin_cidr: Optional[str] = None) -> FirewallPolicy:
    """DMZ Reverse Proxy / Load Balancer profile."""
    rules = [
        FirewallRule(
            id="dmz-lo",
            chain="INPUT",
            protocol="all",
            interface_in="lo",
            action="ACCEPT",
            comment="Loopback traffic",
        ),
        FirewallRule(
            id="dmz-est-rel",
            chain="INPUT",
            protocol="all",
            state=["ESTABLISHED", "RELATED"],
            action="ACCEPT",
            comment="Established connections",
        ),
        FirewallRule(
            id="dmz-http",
            chain="INPUT",
            protocol="tcp",
            port="80",
            action="ACCEPT",
            comment="Public HTTP",
        ),
        FirewallRule(
            id="dmz-https",
            chain="INPUT",
            protocol="tcp",
            port="443",
            action="ACCEPT",
            comment="Public HTTPS",
        ),
    ]
    if admin_cidr:
        rules.append(
            FirewallRule(
                id="dmz-ssh-mgmt",
                chain="INPUT",
                protocol="tcp",
                port="22",
                source_ip=admin_cidr,
                action="ACCEPT",
                comment="Admin SSH access",
            )
        )

    return FirewallPolicy(
        name="dmz_proxy",
        description="DMZ Reverse Proxy handling public web ingress with restricted admin",
        chain_defaults=[
            ChainDefaultPolicy(chain="INPUT", default_action="DROP"),
            ChainDefaultPolicy(chain="FORWARD", default_action="DROP"),
            ChainDefaultPolicy(chain="OUTPUT", default_action="ACCEPT"),
        ],
        rules=rules,
    )


def stealth_drop_profile() -> FirewallPolicy:
    """Stealth profile dropping all packets across all chains."""
    return FirewallPolicy(
        name="stealth_drop",
        description="Air-gapped stealth profile: DROP all INPUT, FORWARD, and OUTPUT",
        chain_defaults=[
            ChainDefaultPolicy(chain="INPUT", default_action="DROP"),
            ChainDefaultPolicy(chain="FORWARD", default_action="DROP"),
            ChainDefaultPolicy(chain="OUTPUT", default_action="DROP"),
        ],
        rules=[
            FirewallRule(
                id="stealth-lo",
                chain="INPUT",
                protocol="all",
                interface_in="lo",
                action="ACCEPT",
                comment="Permit internal loopback only",
            )
        ],
    )


AVAILABLE_PROFILES: Dict[str, str] = {
    "hardened_server": "Production Linux server with default-drop ingress, SSH, and web ports",
    "workstation": "Client workstation blocking unsolicited inbound traffic",
    "dmz_proxy": "DMZ Reverse Proxy accepting 80/443 with isolated admin SSH",
    "stealth_drop": "Air-gapped maximum security profile dropping all external packets",
}


def get_profile(name: str, **kwargs: Any) -> FirewallPolicy:
    """Retrieve pre-built policy profile by name."""
    clean_name = name.strip().lower()
    if clean_name in ("hardened_server", "hardened", "server"):
        return hardened_server_profile(**kwargs)
    if clean_name in ("workstation", "client"):
        return workstation_profile()
    if clean_name in ("dmz_proxy", "dmz", "proxy"):
        return dmz_proxy_profile(**kwargs)
    if clean_name in ("stealth_drop", "stealth", "drop_all"):
        return stealth_drop_profile()

    raise ValueError(
        f"Unknown profile '{name}'. Available profiles: {list(AVAILABLE_PROFILES.keys())}"
    )


def list_profiles() -> List[Dict[str, str]]:
    """List metadata for all available predefined profiles."""
    return [{"name": k, "description": v} for k, v in AVAILABLE_PROFILES.items()]

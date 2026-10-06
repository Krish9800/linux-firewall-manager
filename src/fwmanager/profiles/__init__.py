"""Profiles package for Linux Firewall Manager."""

from fwmanager.profiles.library import (
    AVAILABLE_PROFILES,
    dmz_proxy_profile,
    get_profile,
    hardened_server_profile,
    list_profiles,
    stealth_drop_profile,
    workstation_profile,
)

__all__ = [
    "AVAILABLE_PROFILES",
    "dmz_proxy_profile",
    "get_profile",
    "hardened_server_profile",
    "list_profiles",
    "stealth_drop_profile",
    "workstation_profile",
]

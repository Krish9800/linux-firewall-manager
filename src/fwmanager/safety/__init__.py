"""Safety package for Linux Firewall Manager."""

from fwmanager.safety.deadman_switch import DeadmanSwitch, SafetyStatus

__all__ = ["DeadmanSwitch", "SafetyStatus"]

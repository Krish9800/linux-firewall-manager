"""Execution engine and kernel/simulation drivers for firewall orchestration."""

import datetime
import os
import subprocess  # nosec B404
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Optional

from fwmanager.config.settings import settings
from fwmanager.models.rules import FirewallPolicy


@dataclass
class ExecutionResult:
    """Result of a firewall policy execution or command."""

    success: bool
    backend: str
    message: str
    executed_commands: List[str] = field(default_factory=list)
    timestamp: str = field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat()
    )


class FirewallDriver(ABC):
    """Abstract interface for packet filtering drivers."""

    @abstractmethod
    def apply_policy(self, policy: FirewallPolicy) -> ExecutionResult:
        """Apply the given declarative firewall policy."""

    @abstractmethod
    def flush(self) -> ExecutionResult:
        """Flush active firewall rules."""

    @abstractmethod
    def get_active_policy(self) -> Optional[FirewallPolicy]:
        """Retrieve current in-memory or active policy."""


class SimulationDriver(FirewallDriver):
    """Safe, in-memory simulation driver for non-root testing and CI/CD validation."""

    def __init__(self) -> None:
        self.active_policy: Optional[FirewallPolicy] = None
        self.command_history: List[str] = []

    def apply_policy(self, policy: FirewallPolicy) -> ExecutionResult:
        """Simulate atomic application of firewall policy."""
        from fwmanager.compilers.nft_compiler import NftablesCompiler

        nft_compiler = NftablesCompiler()
        compiled_nft = nft_compiler.compile_policy(policy)
        commands = [f"nft -f /etc/nftables.conf << EOF\n{compiled_nft}\nEOF"]

        self.active_policy = policy.model_copy(deep=True)
        self.command_history.extend(commands)

        return ExecutionResult(
            success=True,
            backend="simulation",
            message=f"Policy '{policy.name}' successfully applied in simulation mode.",
            executed_commands=commands,
        )

    def flush(self) -> ExecutionResult:
        """Simulate flushing rules."""
        self.active_policy = None
        cmd = "nft flush ruleset"
        self.command_history.append(cmd)
        return ExecutionResult(
            success=True,
            backend="simulation",
            message="Firewall rules flushed in simulation mode.",
            executed_commands=[cmd],
        )

    def get_active_policy(self) -> Optional[FirewallPolicy]:
        return self.active_policy


class KernelDriver(FirewallDriver):
    """Kernel driver executing real nftables/iptables commands with safety checks."""

    def __init__(self, backend_type: str = "nftables") -> None:
        self.backend_type = backend_type
        self.active_policy: Optional[FirewallPolicy] = None

    def _check_privileges(self) -> None:
        """Ensure current process has root/CAP_NET_ADMIN privileges."""
        if os.geteuid() != 0:
            raise PermissionError(
                "Live kernel firewall modification requires root or sudo privileges."
            )

    def apply_policy(self, policy: FirewallPolicy) -> ExecutionResult:
        """Apply rules directly to Linux kernel."""
        self._check_privileges()

        if self.backend_type == "nftables":
            from fwmanager.compilers.nft_compiler import NftablesCompiler

            compiler = NftablesCompiler()
            ruleset = compiler.compile_policy(policy)
            proc = subprocess.run(  # nosec B603, B607
                ["nft", "-f", "-"],
                input=ruleset,
                text=True,
                capture_output=True,
                check=False,
            )
            if proc.returncode != 0:
                return ExecutionResult(
                    success=False,
                    backend="nftables",
                    message=f"nftables error: {proc.stderr.strip()}",
                )
        else:
            from fwmanager.compilers.iptables_compiler import IptablesCompiler

            ipt_compiler = IptablesCompiler()
            cmds = ipt_compiler.compile_policy(policy)
            for cmd in cmds:
                if cmd.startswith("#"):
                    continue
                parts = cmd.split()
                proc = subprocess.run(parts, capture_output=True, text=True, check=False)  # nosec B603, B607
                if proc.returncode != 0:
                    return ExecutionResult(
                        success=False,
                        backend="iptables",
                        message=f"iptables error on '{cmd}': {proc.stderr.strip()}",
                    )

        self.active_policy = policy.model_copy(deep=True)
        return ExecutionResult(
            success=True,
            backend=self.backend_type,
            message=f"Policy '{policy.name}' applied to Linux kernel.",
        )

    def flush(self) -> ExecutionResult:
        self._check_privileges()
        cmd = ["nft", "flush", "ruleset"] if self.backend_type == "nftables" else ["iptables", "-F"]
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)  # nosec B603, B607
        self.active_policy = None
        return ExecutionResult(
            success=proc.returncode == 0,
            backend=self.backend_type,
            message="Live rules flushed." if proc.returncode == 0 else proc.stderr,
        )

    def get_active_policy(self) -> Optional[FirewallPolicy]:
        return self.active_policy


# Driver factory singleton
def get_driver(backend_name: Optional[str] = None) -> FirewallDriver:
    """Factory creating appropriate driver based on settings or parameter."""
    selected = backend_name if backend_name is not None else settings.backend
    if selected == "simulation":
        return SimulationDriver()
    if selected in ("nftables", "iptables"):
        return KernelDriver(backend_type=selected)
    return SimulationDriver()

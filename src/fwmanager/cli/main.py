"""Command-line interface for Linux Firewall Manager."""

import datetime
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from fwmanager.compilers.iptables_compiler import IptablesCompiler
from fwmanager.compilers.nft_compiler import NftablesCompiler
from fwmanager.config.settings import settings
from fwmanager.core.executor import SimulationDriver, get_driver
from fwmanager.core.sanitizer import RuleValidationError
from fwmanager.models.audit_models import PolicyAuditReport
from fwmanager.models.rules import FirewallPolicy, FirewallRule
from fwmanager.profiles.library import get_profile, list_profiles
from fwmanager.safety.deadman_switch import DeadmanSwitch
from fwmanager.telemetry.cef_exporter import export_cef_policy_applied, export_json_audit

app = typer.Typer(
    name="fw-manager",
    help="Declarative Packet Filtering, Hardened Profiles & Safe Rule Orchestration Engine",
    add_completion=False,
)
rules_app = typer.Typer(help="Manage individual packet filtering rules")
profiles_app = typer.Typer(help="Inspect and apply pre-built hardened security profiles")
app.add_typer(rules_app, name="rules")
app.add_typer(profiles_app, name="profiles")

console = Console()

# Global state instances for CLI operation
_driver = SimulationDriver()
_safety_switch = DeadmanSwitch()


def _format_action_tag(action: str) -> str:
    """Format firewall action with Rich colors."""
    if action == "ACCEPT":
        return "[bold green]ACCEPT[/bold green]"
    if action == "DROP":
        return "[bold red]DROP[/bold red]"
    if action == "REJECT":
        return "[red]REJECT[/red]"
    return "[yellow]LOG[/yellow]"


@rules_app.command("list")
def list_rules_cmd(
    json_output: bool = typer.Option(False, "--json", help="Output active policy as JSON"),
) -> None:
    """List active firewall rules and chain defaults."""
    policy = _driver.get_active_policy()
    if not policy:
        policy = FirewallPolicy(name="initial_empty")

    if json_output:
        console.print(policy.model_dump_json(indent=2))
        return

    table = Table(title=f"Firewall Policy: {policy.name}")
    table.add_column("Rule ID", style="cyan")
    table.add_column("Chain", style="white")
    table.add_column("Protocol", style="magenta")
    table.add_column("Port", style="green")
    table.add_column("Source IP / CIDR", style="dim")
    table.add_column("Action", justify="center")
    table.add_column("Comment")

    for r in policy.rules:
        table.add_row(
            r.id,
            r.chain,
            r.protocol,
            r.port or "[dim]all[/dim]",
            r.source_ip or "[dim]any[/dim]",
            _format_action_tag(r.action),
            r.comment or "",
        )

    console.print(table)
    defaults_str = ", ".join(f"{cd.chain}={cd.default_action}" for cd in policy.chain_defaults)
    console.print(f"[dim]Default chain actions: {defaults_str}[/dim]")


@rules_app.command("add")
def add_rule_cmd(
    chain: str = typer.Option(
        "INPUT", "--chain", "-c", help="Firewall chain: INPUT, FORWARD, OUTPUT"
    ),
    protocol: str = typer.Option("tcp", "--protocol", "-p", help="Protocol: tcp, udp, icmp, all"),
    port: Optional[str] = typer.Option(None, "--port", help="Port or range (e.g. 80, 80:443)"),
    source_ip: Optional[str] = typer.Option(None, "--source-ip", "-s", help="Source IP or CIDR"),
    action: str = typer.Option(
        "ACCEPT", "--action", "-a", help="Action: ACCEPT, DROP, REJECT, LOG"
    ),
    comment: Optional[str] = typer.Option(None, "--comment", "-m", help="Rule comment"),
) -> None:
    """Add a new packet filtering rule to active policy."""
    try:
        new_rule = FirewallRule(
            chain=chain,
            protocol=protocol,  # type: ignore[arg-type]
            port=port,
            source_ip=source_ip,
            action=action,  # type: ignore[arg-type]
            comment=comment,
        )
    except (RuleValidationError, ValueError) as exc:
        console.print(f"[bold red]Validation error: {exc}[/bold red]")
        raise typer.Exit(code=1) from None

    policy = _driver.get_active_policy() or FirewallPolicy(name="custom_policy")
    policy.add_rule(new_rule)
    _driver.apply_policy(policy)
    port_desc = new_rule.port or "all"
    console.print(
        f"[bold green]Added rule {new_rule.id}:[/bold green] "
        f"{new_rule.action} {new_rule.protocol} {port_desc}"
    )


@rules_app.command("delete")
def delete_rule_cmd(rule_id: str = typer.Argument(..., help="ID of rule to delete")) -> None:
    """Delete a rule from the active policy by ID."""
    policy = _driver.get_active_policy()
    if not policy or not policy.delete_rule(rule_id):
        console.print(f"[bold red]Rule '{rule_id}' not found in active policy.[/bold red]")
        raise typer.Exit(code=1)

    _driver.apply_policy(policy)
    console.print(f"[bold green]Deleted rule {rule_id}.[/bold green]")


@profiles_app.command("list")
def list_profiles_cmd() -> None:
    """List all pre-built hardened security profiles."""
    table = Table(title="Available Hardened Security Profiles")
    table.add_column("Profile Name", style="cyan")
    table.add_column("Description", style="white")

    for p in list_profiles():
        table.add_row(p["name"], p["description"])
    console.print(table)


@profiles_app.command("apply")
def apply_profile_cmd(
    name: str = typer.Argument(
        ..., help="Profile name: hardened_server, workstation, dmz_proxy, stealth_drop"
    ),
    timeout: int = typer.Option(
        30, "--timeout", "-t", help="Deadman's switch auto-rollback timeout in seconds"
    ),
    live: bool = typer.Option(False, "--live", help="Apply to live Linux kernel (requires root)"),
) -> None:
    """Apply a hardened security profile with auto-rollback protection."""
    try:
        new_policy = get_profile(name)
    except ValueError as exc:
        console.print(f"[bold red]{exc}[/bold red]")
        raise typer.Exit(code=1) from None

    current_policy = _driver.get_active_policy() or FirewallPolicy(name="clean_baseline")
    driver = _driver if not live else get_driver("nftables")

    def _revert(snapshot: FirewallPolicy) -> None:
        driver.apply_policy(snapshot)
        console.print(
            f"[bold yellow]Safety Timeout: Reverted to policy '{snapshot.name}'.[/bold yellow]"
        )

    _safety_switch.arm(current_policy, new_policy, _revert, timeout=timeout)
    exec_res = driver.apply_policy(new_policy)

    if not exec_res.success:
        console.print(f"[bold red]Failed to apply profile: {exec_res.message}[/bold red]")
        _safety_switch.confirm()
        raise typer.Exit(code=1)

    console.print(
        Panel(
            f"[bold green]Applied Profile '{new_policy.name}'[/bold green]\n"
            f"Rules configured: {len(new_policy.rules)} | Backend: {exec_res.backend}\n"
            f"[bold yellow]Safety Timer Armed: {timeout}s[/bold yellow] (Run 'fw-manager confirm')",
            title="Firewall State Transition",
            expand=False,
        )
    )


@app.command()
def confirm() -> None:
    """Confirm pending firewall changes and cancel the auto-rollback timer."""
    if _safety_switch.confirm():
        console.print(
            "[bold green]Firewall configuration confirmed. Rollback timer cancelled.[/bold green]"
        )
    else:
        console.print("[yellow]No pending unconfirmed policy transition found.[/yellow]")


@app.command()
def rollback() -> None:
    """Manually trigger immediate rollback to previous policy snapshot."""
    if _safety_switch.manual_rollback():
        console.print("[bold green]Rollback completed successfully.[/bold green]")
    else:
        console.print("[yellow]No active rollback snapshot available.[/yellow]")


@app.command()
def status() -> None:
    """Display live firewall status and safety timer telemetry."""
    safety_stat = _safety_switch.get_status()
    policy = _driver.get_active_policy()
    armed_tag = "[red]YES[/red]" if safety_stat.is_armed else "[green]NO[/green]"

    status_str = (
        f"[bold]Active Policy:[/bold] {policy.name if policy else 'None'} "
        f"({len(policy.rules) if policy else 0} rules)\n"
        f"[bold]Backend:[/bold] {_driver.__class__.__name__}\n"
        f"[bold]Safety Switch Armed:[/bold] {armed_tag}\n"
    )
    if safety_stat.is_armed:
        status_str += f"[bold yellow]Time Remaining:[/bold yellow] {safety_stat.remaining_seconds}s"

    console.print(Panel(status_str, title="Firewall Subsystem Status", expand=False))


@app.command()
def export(
    fmt: str = typer.Option("json", "--format", "-f", help="Export format: json, cef, nft, ipt"),
) -> None:
    """Export active firewall policy to requested format."""
    policy = _driver.get_active_policy() or FirewallPolicy(name="empty_policy")
    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
    report = PolicyAuditReport.from_policy(policy, timestamp)

    fmt_clean = fmt.lower()
    if fmt_clean == "cef":
        console.print(export_cef_policy_applied(report))
    elif fmt_clean == "nft":
        compiler = NftablesCompiler()
        console.print(compiler.compile_policy(policy))
    elif fmt_clean == "ipt":
        ipt_compiler = IptablesCompiler()
        console.print("\n".join(ipt_compiler.compile_policy(policy)))
    else:
        console.print(export_json_audit(report))


@app.command()
def version() -> None:
    """Display software version and defense charter."""
    console.print(
        Panel(
            f"[bold cyan]{settings.app_name}[/bold cyan] v{settings.app_version}\n"
            "[white]Declarative Linux Packet Filtering & Safe Rule Orchestration[/white]\n"
            "[dim]Strictly authorized defensive kernel management utility[/dim]",
            title="System Info",
            expand=False,
        )
    )


if __name__ == "__main__":
    app()

"""REST API routes for firewall management and safety operations."""

import datetime
import uuid
from typing import Dict, List

from fastapi import APIRouter, HTTPException, Query, status

from fwmanager.api.schemas import (
    AddRuleRequest,
    ApplyProfileRequest,
    ConfirmRollbackResponse,
    ExportResponse,
    HealthResponse,
    RulesListResponse,
    SafetyStatusResponse,
)
from fwmanager.compilers.iptables_compiler import IptablesCompiler
from fwmanager.compilers.nft_compiler import NftablesCompiler
from fwmanager.config.settings import settings
from fwmanager.core.executor import SimulationDriver
from fwmanager.models.audit_models import PolicyAuditReport
from fwmanager.models.rules import FirewallPolicy, FirewallRule
from fwmanager.profiles.library import AVAILABLE_PROFILES, get_profile
from fwmanager.safety.deadman_switch import DeadmanSwitch
from fwmanager.telemetry.cef_exporter import export_cef_policy_applied

router = APIRouter()

# Service state
driver = SimulationDriver()
safety_switch = DeadmanSwitch()


@router.get("/health", response_model=HealthResponse)
def get_health() -> HealthResponse:
    """Return service health status and backend engine."""
    return HealthResponse(
        status="ok",
        version=settings.app_version,
        backend=driver.backend_type,
    )


@router.get("/api/v1/rules", response_model=RulesListResponse)
def get_rules() -> RulesListResponse:
    """Retrieve active firewall policy and rules."""
    policy = driver.get_active_policy()
    if policy is None:
        policy = FirewallPolicy(name="active_policy")
    return RulesListResponse(
        policy_name=policy.name,
        rules=policy.rules,
    )


@router.post("/api/v1/rules", response_model=FirewallRule, status_code=status.HTTP_201_CREATED)
def add_rule(req: AddRuleRequest) -> FirewallRule:
    """Add a new validated rule to the active policy."""
    try:
        new_rule = FirewallRule(
            id=f"rule-{uuid.uuid4().hex[:8]}",
            chain=req.chain,
            protocol=req.protocol or "all",
            port=req.port,
            source_ip=req.source_ip,
            destination_ip=req.dest_ip,
            interface_in=req.in_interface,
            interface_out=req.out_interface,
            action=req.action,
            comment=req.comment,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc

    policy = driver.get_active_policy()
    if policy is None:
        policy = FirewallPolicy(name="custom_policy")
    else:
        policy = policy.model_copy(deep=True)

    policy.add_rule(new_rule)
    driver.apply_policy(policy)
    return new_rule


@router.delete("/api/v1/rules/{rule_id}", status_code=status.HTTP_200_OK)
def delete_rule(rule_id: str) -> Dict[str, str]:
    """Delete a rule by ID from the active policy."""
    policy = driver.get_active_policy()
    if policy is None or not any(r.id == rule_id for r in policy.rules):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Rule '{rule_id}' not found.",
        )

    updated_policy = policy.model_copy(deep=True)
    updated_policy.rules = [r for r in updated_policy.rules if r.id != rule_id]
    driver.apply_policy(updated_policy)
    return {"message": f"Rule '{rule_id}' deleted successfully."}


@router.get("/api/v1/profiles", response_model=List[str])
def list_profiles_endpoint() -> List[str]:
    """List available pre-hardened firewall profile templates."""
    return list(AVAILABLE_PROFILES.keys())


@router.post("/api/v1/profiles/apply", response_model=SafetyStatusResponse)
def apply_profile(req: ApplyProfileRequest) -> SafetyStatusResponse:
    """Stage and apply a profile guarded by the Deadman's switch."""
    if req.profile_name not in AVAILABLE_PROFILES:
        avail = list(AVAILABLE_PROFILES.keys())
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Profile '{req.profile_name}' not found. Available: {avail}",
        )

    target_policy = get_profile(req.profile_name)
    current = driver.get_active_policy() or FirewallPolicy(name="initial_empty")

    def _revert(snapshot: FirewallPolicy) -> None:
        driver.apply_policy(snapshot)

    try:
        safety_switch.arm(
            current_policy=current,
            pending_policy=target_policy,
            revert_callback=_revert,
            timeout=req.timeout_seconds,
        )
    except RuntimeError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc

    driver.apply_policy(target_policy)
    stat = safety_switch.get_status()
    return SafetyStatusResponse(
        armed=stat.is_armed,
        target_policy=stat.target_policy_name,
        remaining_seconds=stat.remaining_seconds,
        reverted=stat.reverted,
    )


@router.post("/api/v1/safety/confirm", response_model=ConfirmRollbackResponse)
def confirm_policy() -> ConfirmRollbackResponse:
    """Confirm staged policy, disarming the Deadman's switch."""
    if safety_switch.confirm():
        return ConfirmRollbackResponse(
            message="Active policy confirmed successfully.",
            status="confirmed",
        )
    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="No pending unconfirmed policy transition found.",
    )


@router.post("/api/v1/safety/rollback", response_model=ConfirmRollbackResponse)
def rollback_policy() -> ConfirmRollbackResponse:
    """Manually trigger rollback to previous policy."""
    if safety_switch.manual_rollback():
        return ConfirmRollbackResponse(
            message="Rollback completed successfully.",
            status="rolled_back",
        )
    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="No active rollback snapshot available.",
    )


@router.get("/api/v1/safety/status", response_model=SafetyStatusResponse)
def get_safety_status() -> SafetyStatusResponse:
    """Inspect current Deadman's switch arm state and remaining countdown."""
    stat = safety_switch.get_status()
    return SafetyStatusResponse(
        armed=stat.is_armed,
        target_policy=stat.target_policy_name,
        remaining_seconds=stat.remaining_seconds,
        reverted=stat.reverted,
    )


@router.get("/api/v1/export", response_model=ExportResponse)
def export_policy(
    format_type: str = Query(
        "json", alias="format", pattern="^(json|cef|nft|ipt)$", description="Export target format"
    ),
) -> ExportResponse:
    """Export active ruleset in JSON, CEF, nftables, or iptables syntax."""
    policy = driver.get_active_policy()
    if policy is None:
        policy = FirewallPolicy(name="active_policy")

    output_str: str
    if format_type == "json":
        output_str = policy.model_dump_json(indent=2)
    elif format_type == "cef":
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        audit_rep = PolicyAuditReport.from_policy(policy, timestamp=now_iso)
        output_str = export_cef_policy_applied(audit_rep)
    elif format_type == "nft":
        compiler_nft = NftablesCompiler()
        output_str = compiler_nft.compile_policy(policy)
    else:  # ipt
        compiler_ipt = IptablesCompiler()
        cmds = compiler_ipt.compile_policy(policy)
        output_str = "\n".join(cmds)

    return ExportResponse(
        format=format_type,
        output=output_str,
    )

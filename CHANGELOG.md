# Changelog

All notable changes to **Linux Firewall Manager** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-10-06

### Added
- **Phase 1: Architecture & Foundation**:
  - `pyproject.toml` with strict DevSecOps gates (pytest, ruff, mypy, bandit).
  - Sanitization primitives for identifiers, interfaces, ports, IPs, and CIDRs.
  - Pydantic Settings configuration engine.
- **Phase 2: Declarative Rule Engine**:
  - `FirewallRule`, `ChainDefaultPolicy`, and `FirewallPolicy` domain models with input validation.
  - Support for multi-chain policies (`INPUT`, `OUTPUT`, `FORWARD`) and connection tracking state (`ESTABLISHED`, `RELATED`, `INVALID`).
- **Phase 3: Multi-Backend Compilers**:
  - `NftablesCompiler` emitting atomic `inet filter` rule sets.
  - `IptablesCompiler` generating deterministic command vectors.
- **Phase 4: Deadman's Switch Safety Engine**:
  - Automatic rollback timer preventing remote administrator SSH lockout.
  - Asynchronous countdown loop with deep-clone state snapshots and manual rollback controls.
- **Phase 5: Pre-Hardened Security Profiles**:
  - `hardened_server`: Default-drop ingress with loopback, state tracking, and rate-limited ICMP.
  - `workstation`: Client workstation profile allowing full outbound with drop on unsolicited inbound.
  - `dmz_proxy`: DMZ reverse proxy template with ports 80/443 and isolated SSH management.
  - `stealth_drop`: High-security air-gapped drop baseline.
- **Phase 6: Execution Engine & Simulation Driver**:
  - `SimulationDriver` enabling safe, rootless testing and CI/CD validation.
  - `KernelDriver` supporting live Linux kernel manipulation with privilege verification.
- **Phase 7: ArcSight CEF & JSON Audit Exporters**:
  - `export_cef_policy_applied` and `export_cef_rule_event` generating SIEM-compatible CEF events.
  - Deterministic SHA-256 fingerprinting for configuration audit tracking.
- **Phase 8: Typer & Rich CLI**:
  - Subcommands for rule management (`rules list`, `rules add`, `rules delete`).
  - Pre-built profile lifecycle (`profiles list`, `profiles apply`).
  - Safety operations (`confirm`, `rollback`, `status`).
  - Syntax export (`export --format [json|cef|nft|ipt]`).
- **Phase 9: FastAPI Microservice & Adversarial Suite**:
  - REST API with OWASP defensive security headers middleware (`CSP`, `HSTS`, `X-Frame-Options: DENY`, `nosniff`).
  - Adversarial test suite validating shell injection rejection, directory traversal resistance, and timeout auto-revert.
- **Phase 10: DevSecOps CI/CD & Documentation**:
  - GitHub Actions CI workflow with matrix testing (Python 3.11, 3.12).
  - Multi-stage rootless Dockerfile (`netsecuser:10001`).
  - Threat modeling documentation with STRIDE matrix.

# Linux Firewall Manager

[![CI Pipeline](https://github.com/Krish9800/linux-firewall-manager/actions/workflows/ci.yml/badge.svg)](https://github.com/Krish9800/linux-firewall-manager/actions)
[![Python Version](https://img.shields.io/badge/python-3.11%20%7C%203.12-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Coverage](https://img.shields.io/badge/coverage-96%25-brightgreen.svg)](tests/)
[![Code Style: Ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![Security: Bandit](https://img.shields.io/badge/security-bandit-yellow.svg)](https://github.com/PyCQA/bandit)

**Linux Firewall Manager** is an enterprise-grade, defense-in-depth Linux host packet filtering engine designed to manage and enforce declarative security policies across modern `nftables` and legacy `iptables` subsystems.

Featuring a lock-safe **Deadman's Switch**, it protects system administrators and DevSecOps engineers from catastrophic remote SSH lockouts during firewall transitions by staging rules under a countdown timer that automatically reverts upon timeout unless explicitly confirmed.

---

## Key Features

- **Declarative Rule Modeling**: Specify policies as strongly typed objects with automatic validation of ports, protocols, chains, IPs, CIDRs, and interfaces.
- **Dual-Backend Compilers**:
  - `nftables`: Emits atomic `table inet filter { ... }` configuration files with native connection tracking.
  - `iptables`: Compiles rules into deterministic, sequential rule commands.
- **Deadman's Switch Lockout Prevention**:
  - Automatically captures deep-clone snapshots before rule application.
  - Arms a countdown timer (default 30s) during unverified transitions.
  - Reverts atomically if operator confirmation is not received within the window.
- **Pre-Hardened Security Baseline Profiles**:
  - `hardened_server`: Default DROP on ingress, stateful inspection, loopback isolation, rate-limited ICMP, and SSH access.
  - `workstation`: Blocks unsolicited inbound while permitting stateful outbound.
  - `dmz_proxy`: DMZ reverse proxy accepting 80/443 with isolated admin SSH.
  - `stealth_drop`: High-security air-gapped drop baseline across all chains.
- **Simulation Execution Driver**: Emulates firewall compilation and state transitions in memory for non-root environments and CI/CD validation without requiring kernel capabilities.
- **SIEM Telemetry Exporter**: Formats audit logs into **ArcSight Common Event Format (CEF:0)** and structured JSON with deterministic SHA-256 configuration fingerprinting.
- **REST API Microservice**: FastAPI service equipped with OWASP defensive HTTP headers (`CSP`, `nosniff`, `DENY`, `HSTS`).
- **Interactive CLI**: Rich terminal user interface built with Typer and Rich.

---

## Architecture Overview

```mermaid
graph TD
    CLI[Typer / Rich CLI] --> Engine[Core Firewall Engine]
    API[FastAPI REST Daemon] --> Engine

    subgraph Core Engine
        Sanitizer[Input Sanitizer & Validation]
        Models[Declarative Rule & Policy Models]
        Switch[Deadman's Switch Safety Controller]
        CompilerNFT[nftables Atomic Compiler]
        CompilerIPT[iptables Vector Compiler]
        CEF[ArcSight CEF Telemetry Exporter]
    end

    Engine --> Sanitizer
    Sanitizer --> Models
    Models --> Switch
    Switch --> CompilerNFT
    Switch --> CompilerIPT
    Switch --> CEF

    subgraph Drivers
        SimDriver[Simulation Driver (Memory)]
        KernelDriver[Linux Kernel Driver (Root/CAP_NET_ADMIN)]
    end

    CompilerNFT --> SimDriver
    CompilerNFT --> KernelDriver
    CompilerIPT --> SimDriver
    CompilerIPT --> KernelDriver
```

Detailed architectural diagrams and state models can be found in [docs/architecture.md](docs/architecture.md).

---

## Installation

### Prerequisites
- Python 3.11+
- Linux kernel with `nftables` or `iptables` (for live enforcement; simulation mode requires no privileges)

### Local Setup
```bash
# Clone the repository
git clone https://github.com/Krish9800/linux-firewall-manager.git
cd linux-firewall-manager

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install in editable mode with development dependencies
pip install -e ".[dev]"
```

---

## CLI Usage

The CLI command is installed as `fw-manager`.

### Inspecting Profiles & Applying with Deadman's Switch
```bash
# List available security profiles
fw-manager profiles list

# Apply hardened server profile with a 30-second safety window
fw-manager profiles apply hardened_server --timeout 30

# Inspect switch status and remaining countdown time
fw-manager status

# Confirm policy before countdown expires to commit changes
fw-manager confirm

# Or trigger an immediate manual rollback
fw-manager rollback
```

### Managing Rules
```bash
# List active rules
fw-manager rules list

# Add an ingress rule allowing HTTPS from a specific subnet
fw-manager rules add --chain INPUT --protocol tcp --port 443 --source 192.168.1.0/24 --action ACCEPT

# Delete a rule by ID
fw-manager rules delete <rule-id>
```

### Exporting Rule Sets
```bash
# Export active configuration as nftables syntax
fw-manager export --format nft

# Export as ArcSight CEF event for SIEM ingestion
fw-manager export --format cef

# Export as JSON audit document
fw-manager export --format json
```

---

## REST API Microservice

Start the API daemon:
```bash
uvicorn fwmanager.api.app:app --host 0.0.0.0 --port 8000
```

Interactive OpenAPI documentation is available at `http://localhost:8000/docs`.

### API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/health` | Healthcheck and backend status |
| `GET` | `/api/v1/rules` | List active rules and policies |
| `POST` | `/api/v1/rules` | Add a new packet filtering rule |
| `DELETE` | `/api/v1/rules/{id}` | Delete a rule by identifier |
| `GET` | `/api/v1/profiles` | List pre-hardened baseline profiles |
| `POST` | `/api/v1/profiles/apply` | Stage profile guarded by Deadman's switch |
| `POST` | `/api/v1/safety/confirm` | Confirm staged policy |
| `POST` | `/api/v1/safety/rollback` | Manually revert to previous snapshot |
| `GET` | `/api/v1/safety/status` | Read switch armed status and remaining time |
| `GET` | `/api/v1/export` | Export ruleset in `json`, `cef`, `nft`, or `ipt` |

---

## Docker Deployment

Build and run using rootless Docker:
```bash
# Build image
docker build -t linux-firewall-manager:latest .

# Run container
docker run -d -p 8000:8000 --name fw-manager linux-firewall-manager:latest

# Or use docker-compose
docker compose up -d
```

---

## Security & Threat Model

- **No Shell Execution**: Subprocess commands are executed strictly with `shell=False` and tokenized argument arrays.
- **Defense Against Command Injection**: All port, interface, IP, CIDR, and identifier strings are subjected to whitelist regex sanitizers.
- **Rootless Operation**: Docker containers run as non-root user `netsec (UID 10001)`.
- **Privilege Separation**: Live kernel modification verifies `CAP_NET_ADMIN` / `root` and fails closed on unprivileged processes.

Refer to [docs/threat_model.md](docs/threat_model.md) for full STRIDE matrix analysis.

---

## Verification & DevSecOps

Run the automated test suite and linters locally:
```bash
# Unit & integration tests with coverage check
pytest tests/ --cov=src/fwmanager --cov-report=term-missing --cov-fail-under=90

# Code formatting and linting
ruff format --check .
ruff check .

# Static type checking
mypy src tests

# Static application security testing (SAST)
bandit -r src/ -c pyproject.toml
```

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

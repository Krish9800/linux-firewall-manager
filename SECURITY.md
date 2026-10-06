# Security Policy

## Responsible Use & Kernel Safety
The Linux Firewall Manager is designed for system administrators, devops teams, and security engineers to safely define, test, and orchestrate Linux packet filtering rules.

### Defensive Safety Guarantees
1. **Simulation Default**: The tool defaults to simulation/dry-run mode unless explicitly commanded to execute against live kernel subsystems (`--live`).
2. **Deadman's Switch**: Remote rule application requires confirmation or automatically triggers an atomic rollback timer to prevent administrative lockouts.
3. **No Unsanitized Shell Execution**: Commands are constructed using explicit tokenized argument vectors, never through raw shell string concatenation (`shell=True` is prohibited).

## Reporting Vulnerabilities
Submit vulnerability reports privately to `security@portfolio.local`.

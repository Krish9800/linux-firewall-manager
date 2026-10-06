# Linux Firewall Manager Threat Model

This document outlines the threat modeling, trust boundaries, STRIDE classification, and defensive controls implemented across **Linux Firewall Manager**.

## 1. Trust Boundaries & Privileges

```
[ External Untrusted Inputs ]
       │  (CLI parameters / REST JSON payloads)
       ▼
┌──────────────────────────────────────────────────────────┐
│ Trust Boundary: Application Layer (Non-Root NetSec User) │
│ - Input Sanitizer (Regex, IPv4/v6 parser, Range checks)  │
│ - Pydantic Validations                                   │
│ - Security Headers Middleware                            │
└──────────────────────────┬───────────────────────────────┘
                           │  Tokenized Argument Vectors
                           ▼
┌──────────────────────────────────────────────────────────┐
│ Trust Boundary: Execution Engine                         │
│ - Simulation Mode (Air-gapped memory space)              │
│ - Kernel Mode: Requires CAP_NET_ADMIN or Root UID (0)    │
│ - Subprocess executed with shell=False                   │
└──────────────────────────────────────────────────────────┘
```

---

## 2. STRIDE Assessment

| Threat Category | Potential Attack Vector | Defensive Countermeasure Implemented |
|---|---|---|
| **Spoofing** | Attacker injects malformed CIDRs or spoofed IPs | `sanitize_ip_or_cidr` parses via standard Python `ipaddress` module; invalid CIDRs (e.g. `/33`) or octets (`999.999.999.999`) rejected at boundary. |
| **Tampering** | Parameter tampering via shell metacharacters (`;&|$\`><`) in interface or port fields | Strict regex matching: Ports must be integers or numeric ranges (1-65535); Interfaces must match `^[A-Za-z0-9_.+-]{1,16}$`. Subprocess runs with `shell=False` to eliminate shell expansion. |
| **Repudiation** | Operator applies disruptive rules without audit trail | ArcSight CEF (`CEF:0|LinuxFirewallManager|...`) and JSON audit logs compute a deterministic SHA-256 fingerprint for every applied policy. |
| **Information Disclosure** | Leakage of system state via unhandled error stack traces | Standardized error messages; Pydantic validation errors return structured 422 responses; security headers strip diagnostic framing (`X-Content-Type-Options: nosniff`). |
| **Denial of Service (Lockout)** | Faulty policy drops SSH port 22 or breaks upstream routing | **Deadman's Switch**: Rules are staged under an active timer. Failure to confirm within $N$ seconds automatically triggers atomic rollback to the pre-change snapshot. |
| **Elevation of Privilege** | Container escape or unauthorized live kernel rule manipulation | Rootless Docker image running as UID `10001:10001`; `KernelDriver` validates `os.geteuid() == 0` and fails closed with `PermissionError` if unprivileged. |

---

## 3. Subprocess Execution & SAST Considerations

- To ensure resistance against command injection (CWE-78), all subprocess invocations:
  1. Tokenize command arguments into discrete argument arrays (e.g. `["nft", "-f", "-"]`).
  2. Enforce `shell=False`.
  3. Pre-validate every token through whitelist regex sanitizers.
- SAST scanners (`Bandit`) are configured with appropriate exclusions (`B404`, `B603`, `B607`) where token arrays are statically guaranteed.

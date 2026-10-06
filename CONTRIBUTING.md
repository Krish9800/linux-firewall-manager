# Contributing Guidelines

Thank you for contributing to Linux Firewall Manager!

## Setup
```bash
git clone https://github.com/Krish9800/linux-firewall-manager.git
cd linux-firewall-manager
python3 -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
```

## Quality Gates
- 100% type hints checked with Mypy (`strict = true`).
- PEP 8 and formatting enforced with Ruff (`line-length = 100`).
- SAST security scanning with Bandit.
- Minimum 90% test coverage with Pytest.

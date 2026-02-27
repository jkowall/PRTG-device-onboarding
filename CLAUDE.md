# CLAUDE.md

PRTG Device Onboarding Automation — a Python CLI tool (`prtg_manager.py`) that automates onboarding and managing network devices in PRTG monitoring via local SNMP scans and the PRTG API.

## Quick Commands

```bash
pip install -r requirements.txt   # Install dependencies
./run_checks.sh                   # Lint (pylint) + tests (pytest)
pylint --fail-under=8.0 prtg_manager.py
python3 -m pytest tests/
```

## Agent Rules

All agent instructions, constraints, and project conventions are in **[AGENTS.md](AGENTS.md)**.

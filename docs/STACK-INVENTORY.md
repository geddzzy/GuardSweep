# Stack Inventory

This document keeps the repo stack organized so it is easier to remember what technology is in use, what config files matter, and what should be reviewed before changes.

## Repository Identity

- Repo: `guard-sweep`
- Working title: `GuardSweep - Cross-Platform Endpoint Detection and Response (EDR)`
- Current repository type: product or tooling repository

## Detected Stack Signals

- Python via pyproject
- Python via requirements.txt
- GitHub Actions CI

## Key Files Present

- README: `present`
- Tests directory: `present`
- GitHub Actions: `present`
- `pyproject.toml`: `present`
- `requirements.txt`: `present`
- `package.json`: `missing`
- `pubspec.yaml`: `missing`

## Maintenance Notes

- Update this file when the stack changes materially.
- Keep service ownership, major manifests, and runtime assumptions easy to review.
- If the repo grows beyond one main stack, split this inventory by subsystem.

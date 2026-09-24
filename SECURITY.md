# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| main / latest release | :white_check_mark: |
| older releases | :x: |

Only the latest release and the `main` branch receive security fixes.

## Reporting a Vulnerability

If you find a security issue in `Advisory-RSS`, please **do not open a public GitHub issue**.

Report privately using one of the following:

- **GitHub Private Vulnerability Reporting** (preferred): open a report via the repo's [Security tab - "Report a vulnerability"](../../security/advisories/new)
- **Email**: security@lunixizm.website

Please include:
- A clear description of the vulnerability and its impact
- Steps to reproduce, or a minimal PoC if possible
- Affected version/commit
- Any suggested remediation, if you have one

## Disclosure Policy

This project follows **coordinated disclosure**:
- Please give me reasonable time to investigate and patch before any public disclosure
- I aim to resolve confirmed critical/high severity issues within 10 days of report
- If a fix isn't possible within that window, i'll communicate an updated timeline directly with you
- Once a fix is released, im happy to coordinate a mutually agreed disclosure date and credit you in the advisory

## Scope

In scope:
- `Advisory-RSS` source code, packaging (pypi), and dependencies as pinned in `pyproject.toml`
- CI/CD workflows in `.github/`

Out of scope:
- Issues in third-party dependencies not pinned/bundled by this project (report upstream instead)

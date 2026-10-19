# Secure Multi-Department Campus Network with Security Automation

## Overview
A Cisco Packet Tracer campus network combined with a Python tool that audits sanitized Cisco IOS configuration extracts and generates JSON reports.

## Network Design

| VLAN | Department | Subnet | Gateway |
|---|---|---|---|
| 10 | Admin | 192.168.10.0/24 | 192.168.10.1 |
| 20 | IT | 192.168.20.0/24 | 192.168.20.1 |
| 30 | Staff | 192.168.30.0/24 | 192.168.30.1 |
| 40 | Guest | 192.168.40.0/24 | 192.168.40.1 |
| 99 | Management | 192.168.99.0/24 | 192.168.99.1 |
| 999 | Parking | No user subnet | N/A |

## Devices
- SW-Core: multilayer switch and inter-VLAN routing.
- SW-Admin: Admin and IT access switch.
- SW-Staff: Staff and Guest access switch.
- Four PCs represent the client networks.

## Security Controls
- VLAN segmentation and trunk links.
- SSH version 2 and SSH-only remote management in the supplied extracts.
- Local VTY authentication configuration.
- Access-port security using sticky MAC learning and restrict mode.
- Unused ports assigned to VLAN 999 and shut down.
- GUEST-IN ACL intended to restrict Guest access to internal subnets.

## Python Configuration Auditor
Script: `scripts/audit_config.py`

The auditor checks selected SSH, HTTP management, VTY, port-security, and ACL configuration settings. It generates JSON reports.

### Run the audits
```bash
python3 scripts/audit_config.py configs/SW-Core.cfg --device SW-Core --output reports/SW-Core-audit.json
python3 scripts/audit_config.py configs/SW-Admin.cfg --device SW-Admin --output reports/SW-Admin-audit.json
python3 scripts/audit_config.py configs/SW-Staff.cfg --device SW-Staff --output reports/SW-Staff-audit.json
```

### Run the tests
```bash
python3 -m unittest discover -s tests -v
```

The current test suite has seven tests, all of which passed during the latest validation.

## Current Audit Results
- SW-Admin: 0 findings from the current checks.
- SW-Core: 1 informational finding — GUEST-IN is defined but not shown attached in the supplied core configuration extract.
- SW-Staff: 0 findings from the current checks.

Zero findings do not prove that a device is completely secure. The auditor checks only selected rules against the supplied text.

## Repository Contents
- `configs/`: sanitized switch configuration extracts.
- `evidence/`: topology, switch, and connectivity screenshots.
- `reports/`: JSON audit reports.
- `scripts/`: Python audit script.
- `tests/`: unit tests.
- Packet Tracer project files (`.pkt`) are kept locally and excluded from Git, including the backup.

## Limitations
This is an educational simulation, not a production deployment. Packet Tracer may differ from physical hardware. The auditor checks configuration text, not live device state, and is not a complete security or compliance assessment.

## Technologies
Cisco Packet Tracer, Cisco IOS-style configuration, Python 3, regular expressions, JSON, unittest, Ubuntu Linux.

## Responsible Use
Use this project only in authorized labs. Never publish real credentials, password hashes, or private configurations.

## Author
Software Engineering student focused on networking, network security, and automation.

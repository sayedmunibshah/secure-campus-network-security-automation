#!/usr/bin/env python3
"""Audit selected security controls in a sanitized Cisco IOS configuration."""

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path


def audit_config(config_text: str, device_name: str) -> dict:
    config = config_text.lower()
    findings = []

    def add(severity, rule_id, title, evidence, recommendation):
        findings.append({
            "severity": severity,
            "rule_id": rule_id,
            "title": title,
            "evidence": evidence,
            "recommendation": recommendation,
        })

    # SSH configuration
    if not re.search(r"(?m)^ip ssh version 2\s*$", config):
        add(
            "MEDIUM", "SSH-001", "SSH version 2 not explicitly configured",
            "The extract does not contain 'ip ssh version 2'.",
            "Verify SSH status on the device and explicitly configure SSHv2 if supported."
        )

    # HTTP management
    if re.search(r"(?m)^ip http server\s*$", config):
        add(
            "HIGH", "MGMT-001", "HTTP management service enabled",
            "The extract contains 'ip http server'.",
            "Disable HTTP if it is not required and verify management access."
        )

    # VTY remote-access controls
    vty_blocks = re.findall(
        r"(?ms)^line vty\b.*?(?=^line \S|\Z)", config
    )

    if not vty_blocks:
        add(
            "MEDIUM", "VTY-001", "VTY configuration not found",
            "No VTY line configuration was detected in the extract.",
            "Inspect remote-access line configuration on the device."
        )
    else:
        for block in vty_blocks:
            if re.search(r"(?m)^\s*transport input none\s*$", block):
                add(
                    "INFO", "VTY-002", "VTY remote transport disabled",
                    "A VTY block contains 'transport input none'.",
                    "Keep remote access disabled unless remote management is needed."
                )

            transport = re.search(
                r"(?m)^\s*transport input\s+(.+?)\s*$", block
            )
            if transport:
                permitted = transport.group(1).split()
                if "telnet" in permitted and "ssh" not in permitted:
                    add(
                        "HIGH", "VTY-003", "Telnet-only transport configured",
                        "A VTY block permits Telnet without SSH.",
                        "Use SSH rather than Telnet for remote administration."
                    )
                elif "ssh" not in permitted and "none" not in permitted:
                    add(
                        "HIGH", "VTY-006", "SSH not permitted by VTY transport",
                        f"Configured VTY transport is: {transport.group(1)}.",
                        "Verify intended remote access and permit SSH where required."
                    )
            else:
                add(
                    "HIGH", "VTY-006", "VTY transport not explicitly configured",
                    "No 'transport input' command was found in a VTY block.",
                    "Explicitly configure the intended remote-access transport."
                )

            if re.search(r"(?m)^\s*login\s*$", block):
                add(
                    "MEDIUM", "VTY-004", "VTY uses line-based login",
                    "A VTY block contains 'login' rather than 'login local'.",
                    "Review authentication and use an appropriate local or AAA account."
                )
            elif not re.search(r"(?m)^\s*login local\s*$", block):
                add(
                    "MEDIUM", "VTY-005", "Local VTY authentication not shown",
                    "The VTY block does not contain 'login local'.",
                    "Verify the intended AAA or local authentication configuration."
                )

    # Interface checks
    interface_blocks = re.findall(
        r"(?ms)^interface\s+(\S+)\s*\n(.*?)(?=^[^\s]|\Z)",
        config,
    )

    defined_acls = set(re.findall(
        r"(?m)^ip access-list extended\s+(\S+)", config
    ))
    attached_acls = set()

    for interface, block in interface_blocks:
        is_shutdown = bool(re.search(r"(?m)^\s*shutdown\s*$", block))
        is_access_port = bool(re.search(
            r"(?m)^\s*switchport mode access\s*$", block
        ))

        if is_access_port and not is_shutdown:
            if not re.search(r"(?m)^\s*switchport port-security\s*$", block):
                add(
                    "HIGH", "PORTSEC-001",
                    f"Port security not shown on {interface}",
                    f"{interface} is an enabled access port without the port-security command.",
                    "Enable and verify port security on intended user-facing access ports."
                )

        if is_access_port and re.search(
            r"(?m)^\s*switchport port-security\s*$", block
        ):
            if not re.search(
                r"(?m)^\s*switchport port-security violation\s+\S+", block
            ):
                add(
                    "MEDIUM", "PORTSEC-002",
                    f"Port-security violation action not shown on {interface}",
                    f"{interface} enables port security but no violation action appears in the extract.",
                    "Verify and explicitly configure the intended violation action."
                )

        if re.search(r"(?m)^\s*no shutdown\s*$", block):
            if not re.search(r"(?m)^\s*ip address\s+\S+\s+\S+", block):
                add(
                    "INFO", "IFACE-001",
                    f"{interface} enabled without IPv4 address",
                    f"{interface} has 'no shutdown' but no explicit IPv4 address.",
                    "Check whether this interface is intended for Layer 2 or Layer 3."
                )

        acl_matches = re.findall(
            r"(?m)^\s*ip access-group\s+(\S+)\s+(in|out)\s*$", block
        )
        attached_acls.update(name for name, _direction in acl_matches)

        is_guest_access_port = (
            is_access_port
            and re.search(r"(?m)^\s*switchport access vlan 40\s*$", block)
        )
        if is_guest_access_port and not any(
            name == "guest-in" and direction == "in"
            for name, direction in acl_matches
        ):
            add(
                "HIGH", "ACL-002", f"Guest access ACL not shown inbound on {interface}",
                f"{interface} is assigned to VLAN 40, but the extract does not show 'ip access-group GUEST-IN in'.",
                "Verify guest filtering and apply the intended inbound ACL to the guest-facing interface if appropriate."
            )

    for acl_name in sorted(defined_acls - attached_acls):
        add(
            "INFO", "ACL-001", f"ACL {acl_name} defined but not shown attached",
            f"The extract defines {acl_name}, but no interface attachment for that ACL was found.",
            "Verify whether this ACL is intentionally unused or whether its attachment is missing from the extract."
        )

    return {
        "device": device_name,
        "audit_time_utc": datetime.now(timezone.utc).isoformat(),
        "finding_count": len(findings),
        "findings": findings,
        "scope_note": (
            "Results apply only to the supplied sanitized configuration extract. "
            "They do not prove live device state or complete network security."
        ),
    }


def main():
    parser = argparse.ArgumentParser(
        description="Audit a sanitized Cisco IOS configuration extract."
    )
    parser.add_argument("config_file", help="Path to a sanitized config text file")
    parser.add_argument("--device", default="Unknown", help="Device label")
    parser.add_argument(
        "--output", default="reports/audit_report.json",
        help="JSON report output path"
    )
    args = parser.parse_args()

    source = Path(args.config_file)
    destination = Path(args.output)

    if not source.is_file():
        parser.error(f"Configuration file not found: {source}")

    result = audit_config(source.read_text(encoding="utf-8"), args.device)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(result, indent=2) + "\n", encoding="utf-8"
    )

    print(f"Device: {result['device']}")
    print(f"Findings: {result['finding_count']}")
    for item in result["findings"]:
        print(f"[{item['severity']}] {item['rule_id']}: {item['title']}")
    print(f"Report saved to: {destination}")


if __name__ == "__main__":
    main()

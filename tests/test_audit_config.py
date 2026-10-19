import unittest

from scripts.audit_config import audit_config


class TestAuditConfig(unittest.TestCase):

    def test_detects_http_server(self):
        result = audit_config("hostname Switch\nip http server\n", "Switch")
        rule_ids = [item["rule_id"] for item in result["findings"]]
        self.assertIn("MGMT-001", rule_ids)

    def test_detects_disabled_vty_transport(self):
        config = (
            "hostname Router\n"
            "line vty 0 4\n"
            " login\n"
            " transport input none\n"
        )
        result = audit_config(config, "Router")
        rule_ids = [item["rule_id"] for item in result["findings"]]
        self.assertIn("VTY-002", rule_ids)

    def test_reports_device_name(self):
        result = audit_config("hostname Router\n", "Test-Router")
        self.assertEqual(result["device"], "Test-Router")

    def test_clean_config_has_no_findings(self):
        config = (
            "hostname Router\n"
            "ip ssh version 2\n"
            "line vty 0 4\n"
            " login local\n"
            " transport input ssh\n"
        )
        result = audit_config(config, "Router")
        self.assertEqual(result["finding_count"], 0)

    def test_detects_access_port_without_port_security(self):
        config = (
            "hostname Switch\n"
            "ip ssh version 2\n"
            "interface FastEthernet0/1\n"
            " switchport mode access\n"
            " no shutdown\n"
            "line vty 0 4\n"
            " login local\n"
            " transport input ssh\n"
        )
        result = audit_config(config, "Switch")
        rule_ids = [item["rule_id"] for item in result["findings"]]
        self.assertIn("PORTSEC-001", rule_ids)

    def test_detects_guest_port_without_inbound_acl(self):
        config = (
            "hostname SW-Staff\n"
            "ip ssh version 2\n"
            "interface FastEthernet0/2\n"
            " switchport access vlan 40\n"
            " switchport mode access\n"
            " switchport port-security\n"
            " switchport port-security violation restrict\n"
            "ip access-list extended GUEST-IN\n"
            " deny ip 192.168.40.0 0.0.0.255 192.168.10.0 0.0.0.255\n"
            "line vty 0 4\n"
            " login local\n"
            " transport input ssh\n"
        )
        result = audit_config(config, "SW-Staff")
        rule_ids = [item["rule_id"] for item in result["findings"]]
        self.assertIn("ACL-002", rule_ids)

    def test_accepts_guest_port_with_inbound_acl(self):
        config = (
            "hostname SW-Staff\n"
            "ip ssh version 2\n"
            "interface FastEthernet0/2\n"
            " switchport access vlan 40\n"
            " switchport mode access\n"
            " switchport port-security\n"
            " switchport port-security violation restrict\n"
            " ip access-group GUEST-IN in\n"
            "ip access-list extended GUEST-IN\n"
            " deny ip 192.168.40.0 0.0.0.255 192.168.10.0 0.0.0.255\n"
            "line vty 0 4\n"
            " login local\n"
            " transport input ssh\n"
        )
        result = audit_config(config, "SW-Staff")
        rule_ids = [item["rule_id"] for item in result["findings"]]
        self.assertNotIn("ACL-002", rule_ids)


if __name__ == "__main__":
    unittest.main()

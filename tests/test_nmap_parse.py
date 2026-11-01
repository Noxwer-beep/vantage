"""nmap XML parsing tests, using captured real-shaped output."""

import unittest

from vantage import nmap
from vantage.models import Host, Port

SAMPLE_XML = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sV -oX - 10.0.0.5" start="1700000000">
<host starttime="1700000000" endtime="1700000005">
  <status state="up" reason="syn-ack"/>
  <address addr="10.0.0.5" addrtype="ipv4"/>
  <address addr="00:11:22:33:44:55" addrtype="mac"/>
  <hostnames>
    <hostname name="web01.lab" type="user"/>
    <hostname name="web01" type="PTR"/>
  </hostnames>
  <ports>
    <port protocol="tcp" portid="22">
      <state state="open" reason="syn-ack"/>
      <service name="ssh" product="OpenSSH" version="7.2p2" extrainfo="Ubuntu Linux; protocol 2.0" method="probed" conf="10"/>
      <script id="ssh-hostkey" output="2048 aa:bb (RSA)"/>
    </port>
    <port protocol="tcp" portid="80">
      <state state="open" reason="syn-ack"/>
      <service name="http" product="Apache httpd" version="2.2.15" method="probed" conf="10"/>
      <script id="http-title" output="Lab intranet"/>
    </port>
    <port protocol="tcp" portid="3306">
      <state state="closed" reason="reset"/>
      <service name="mysql" method="table" conf="3"/>
    </port>
  </ports>
  <hostscript>
    <script id="smb-vuln-ms17-010" output="State: VULNERABLE"/>
  </hostscript>
  <os>
    <osmatch name="Linux 3.2 - 4.9" accuracy="94"/>
  </os>
</host>
<host>
  <status state="down" reason="no-response"/>
  <address addr="10.0.0.6" addrtype="ipv4"/>
</host>
<runstats><finished time="1700000005" timestr="x" elapsed="5.00" exit="success"/>
<hosts up="1" down="1" total="2"/></runstats>
</nmaprun>
"""


class TestParse(unittest.TestCase):
    def setUp(self):
        self.hosts, self.warnings = nmap.parse_nmap_xml(SAMPLE_XML)

    def test_only_up_hosts_returned(self):
        self.assertEqual(len(self.hosts), 1)
        self.assertEqual(self.hosts[0].address, "10.0.0.5")

    def test_hostname_prefers_user_supplied(self):
        self.assertEqual(self.hosts[0].hostname, "web01.lab")

    def test_ports_parsed_with_state(self):
        host = self.hosts[0]
        self.assertEqual(len(host.ports), 3)
        self.assertEqual(len(host.open_ports), 2)
        self.assertEqual(host.port(3306).state, "closed")

    def test_service_banner(self):
        ssh = self.hosts[0].port(22)
        self.assertEqual(ssh.service, "ssh")
        self.assertEqual(ssh.product, "OpenSSH")
        self.assertEqual(ssh.version, "7.2p2")
        self.assertIn("Ubuntu", ssh.banner)

    def test_port_scripts_attached(self):
        self.assertIn("http-title", self.hosts[0].port(80).scripts)

    def test_host_scripts_attached(self):
        self.assertIn("smb-vuln-ms17-010", self.hosts[0].scripts)

    def test_os_match(self):
        self.assertEqual(self.hosts[0].os_matches[0]["accuracy"], "94")

    def test_empty_input_is_not_an_error(self):
        hosts, _ = nmap.parse_nmap_xml("")
        self.assertEqual(hosts, [])

    def test_malformed_xml_raises(self):
        with self.assertRaises(nmap.NmapError):
            nmap.parse_nmap_xml("<nmaprun><host>")


class TestParseEdgeCases(unittest.TestCase):
    def test_host_without_ports_is_kept_when_up(self):
        xml = """<nmaprun><host><status state="up"/>
        <address addr="10.0.0.9" addrtype="ipv4"/></host></nmaprun>"""
        hosts, _ = nmap.parse_nmap_xml(xml)
        self.assertEqual(len(hosts), 1)
        self.assertEqual(hosts[0].open_ports, [])

    def test_ipv6_address_parsed(self):
        xml = """<nmaprun><host><status state="up"/>
        <address addr="fd00::1" addrtype="ipv6"/></host></nmaprun>"""
        hosts, _ = nmap.parse_nmap_xml(xml)
        self.assertEqual(hosts[0].address, "fd00::1")


class TestBinaryDetection(unittest.TestCase):
    def test_have_binary_finds_nmap(self):
        self.assertTrue(nmap.have_binary("nmap"))

    def test_have_binary_rejects_nonsense(self):
        self.assertFalse(nmap.have_binary("definitely-not-a-real-binary-xyz"))

    def test_unprivileged_uses_connect_scan(self):
        class Guard:
            networks = ["10.0.0.0/30"]
            addresses = ["10.0.0.1"]

        runner = nmap.NmapRunner(Guard(), "quick")
        args = runner.base_args("ports")
        self.assertIn("-sT" if not nmap.is_privileged() else "-sS", args)
        self.assertNotIn("--script-args", args)

    def test_discovery_uses_no_port_scan(self):
        class Guard:
            networks = ["10.0.0.0/30"]
            addresses = ["10.0.0.1"]

        runner = nmap.NmapRunner(Guard(), "quick")
        args = runner.base_args("discovery")
        self.assertIn("-sn", args)
        self.assertNotIn("-sT", args)


if __name__ == "__main__":
    unittest.main()

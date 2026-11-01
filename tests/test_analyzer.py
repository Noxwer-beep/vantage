"""Analyzer tests: the claims this tool is allowed to make."""

import unittest

from vantage import analyzer
from vantage.models import Finding, Host, Port, summarise, risk_score


def host_with(address="10.0.0.5", ports=None, scripts=None):
    h = Host(address=address)
    for p in ports or []:
        h.ports.append(p)
    if scripts:
        h.scripts.update(scripts)
    return h


class TestNseGrading(unittest.TestCase):
    def test_confirmed_vulnerable(self):
        h = host_with(scripts={
            "smb-vuln-ms17-010": "State: VULNERABLE\nCVE: CVE-2017-0143\nRisk factor: CRITICAL"
        })
        findings = analyzer.nse_findings([h])
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.severity, "critical")
        self.assertEqual(f.confidence, "confirmed")
        self.assertIn("CVE-2017-0143", f.cves)

    def test_likely_is_not_confirmed(self):
        h = host_with(scripts={"http-csrf": "State: LIKELY VULNERABLE\nPotential CSRF"})
        findings = analyzer.nse_findings([h])
        self.assertEqual(findings[0].confidence, "likely")

    def test_negative_result_produces_nothing(self):
        h = host_with(scripts={"ssl-heartbleed": "State: NOT VULNERABLE"})
        self.assertEqual(analyzer.nse_findings([h]), [])

    def test_error_output_produces_nothing(self):
        h = host_with(scripts={"smb-vuln-ms17-010": "ERROR: Script execution failed"})
        self.assertEqual(analyzer.nse_findings([h]), [])

    def test_unknown_script_with_vulnerable_text_is_reported(self):
        h = host_with(scripts={"custom-check": "The server appears vulnerable to widget overflow"})
        findings = analyzer.nse_findings([h])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "high")

    def test_tls_scripts_skipped_when_tls_phase_ran(self):
        h = host_with(scripts={"ssl-cert": "Subject: commonName=x"})
        self.assertEqual(analyzer.nse_findings([h], tls_covered=True), [])
        self.assertEqual(len(analyzer.nse_findings([h], tls_covered=False)), 1)

    def test_cvss_extracted(self):
        h = host_with(scripts={"ssl-heartbleed": "State: VULNERABLE\nCVSS: 7.5"})
        self.assertEqual(analyzer.nse_findings([h])[0].cvss, 7.5)


class TestExposure(unittest.TestCase):
    def test_redis_is_high(self):
        h = host_with(ports=[Port(number=6379, service="redis", state="open")])
        findings = analyzer.exposure_findings([h])
        self.assertEqual(findings[0].severity, "high")
        self.assertIn("requirepass", findings[0].remediation.lower())

    def test_falls_back_to_port_number(self):
        h = host_with(ports=[Port(number=23, service="", state="open")])
        findings = analyzer.exposure_findings([h])
        self.assertEqual(findings[0].title, "Telnet reachable")

    def test_closed_ports_ignored(self):
        h = host_with(ports=[Port(number=6379, service="redis", state="closed")])
        self.assertEqual(analyzer.exposure_findings([h]), [])

    def test_https_not_flagged_as_plaintext(self):
        h = host_with(ports=[Port(number=443, service="http", state="open")])
        self.assertEqual(analyzer.exposure_findings([h]), [])

    def test_exposure_is_confirmed_but_only_about_reachability(self):
        h = host_with(ports=[Port(number=445, service="microsoft-ds", state="open")])
        f = analyzer.exposure_findings([h])[0]
        self.assertEqual(f.confidence, "confirmed")
        self.assertIn("reachability only", f.detail)


class TestVersions(unittest.TestCase):
    def test_old_apache_flagged_as_possible(self):
        h = host_with(ports=[Port(number=80, service="http", product="Apache httpd",
                                  version="2.2.15", state="open")])
        findings = analyzer.version_findings([h])
        self.assertTrue(findings)
        self.assertEqual(findings[0].confidence, "possible")
        self.assertIn("backport", findings[0].detail)

    def test_current_apache_not_flagged(self):
        h = host_with(ports=[Port(number=80, service="http", product="Apache httpd",
                                  version="2.4.62", state="open")])
        self.assertEqual(analyzer.version_findings([h]), [])

    def test_no_version_no_claim(self):
        h = host_with(ports=[Port(number=80, service="http", product="Apache httpd",
                                  state="open")])
        self.assertEqual(analyzer.version_findings([h]), [])

    def test_old_openssh_flagged(self):
        h = host_with(ports=[Port(number=22, service="ssh", product="OpenSSH",
                                  version="7.2p2", state="open")])
        self.assertTrue(analyzer.version_findings([h]))


class TestWeb(unittest.TestCase):
    def test_missing_header_aggregated_with_fixes(self):
        class T:
            url = "http://10.0.0.5:80/"
            host = "10.0.0.5"
            port = 80
            scheme = "http"

        class Item:
            target = T()
            message = "The anti-clickjacking X-Frame-Options header is not present."
            cves = []

        findings = analyzer.web_findings([], [Item()])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].title, "1 security header(s) missing")
        self.assertIn("X-Frame-Options: DENY", findings[0].remediation)
        self.assertEqual(findings[0].confidence, "possible")

    def test_two_headers_on_one_endpoint_collapse_to_one_finding(self):
        class T:
            url = "http://10.0.0.5:80/"
            host = "10.0.0.5"
            port = 80
            scheme = "http"

        class A:
            target = T()
            message = "The anti-clickjacking X-Frame-Options header is not present."
            cves = []

        class B:
            target = T()
            message = "The X-Content-Type-Options header is not set."
            cves = []

        findings = analyzer.web_findings([], [A(), B()])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].title, "2 security header(s) missing")
        self.assertIn("nosniff", findings[0].remediation)

    def test_hsts_not_reported_on_plain_http(self):
        class T:
            url = "http://10.0.0.5:80/"
            host = "10.0.0.5"
            port = 80
            scheme = "http"

        class Item:
            target = T()
            message = "Strict-Transport-Security header is not present."
            cves = []

        self.assertEqual(analyzer.web_findings([], [Item()]), [])

    def test_directory_listing_is_low(self):
        class T:
            url = "http://10.0.0.5/"
            host = "10.0.0.5"
            port = 80
            scheme = "http"

        class Item:
            target = T()
            message = "/admin/: Directory indexing found."
            cves = []

        f = analyzer.web_findings([], [Item()])[0]
        self.assertEqual(f.severity, "low")
        self.assertEqual(f.category, "misconfig")


class TestDedupeAndScoring(unittest.TestCase):
    def test_dedupe_keeps_most_severe(self):
        a = Finding(title="Same", severity="low", host="h", port=80, category="x")
        b = Finding(title="Same", severity="high", host="h", port=80, category="x")
        out = analyzer.dedupe([a, b])
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].severity, "high")

    def test_dedupe_keeps_distinct_hosts(self):
        a = Finding(title="Same", severity="low", host="h1", port=80)
        b = Finding(title="Same", severity="low", host="h2", port=80)
        self.assertEqual(len(analyzer.dedupe([a, b])), 2)

    def test_empty_risk_is_zero(self):
        self.assertEqual(risk_score([]), 0)

    def test_confirmed_critical_outranks_many_lows(self):
        critical = Finding(title="crit", severity="critical", confidence="confirmed", host="h")
        lows = [Finding(title=f"low{i}", severity="low", confidence="confirmed", host="h")
                for i in range(20)]
        self.assertGreater(risk_score([critical]), risk_score(lows))

    def test_score_is_bounded(self):
        many = [Finding(title=f"f{i}", severity="critical", confidence="confirmed", host="h")
                for i in range(200)]
        self.assertLessEqual(risk_score(many), 100)

    def test_summary_counts(self):
        findings = [
            Finding(title="a", severity="high", host="h"),
            Finding(title="b", severity="high", host="h2", confidence="confirmed"),
            Finding(title="c", severity="info", host="h"),
        ]
        s = summarise(findings)
        self.assertEqual(s["total"], 3)
        self.assertEqual(s["counts"]["high"], 2)
        self.assertEqual(s["confirmed"], 1)


class TestCoverage(unittest.TestCase):
    def test_notes_mention_missing_phases(self):
        class P:
            vuln_scripts = False
            udp = False

        notes = analyzer.coverage_notes(P(), [Host(address="1.1.1.1")], False, False)
        blob = " ".join(notes)
        self.assertIn("TCP scanning only", blob)
        self.assertIn("TLS endpoints were not inspected", blob)
        self.assertIn("No exploit was executed", blob)


if __name__ == "__main__":
    unittest.main()

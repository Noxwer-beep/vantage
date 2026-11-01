"""Report and storage tests — everything must render from stored data alone."""

import json
import os
import tempfile
import unittest

os.environ.setdefault("VANTAGE_DATA_DIR", tempfile.mkdtemp(prefix="vantage-store-"))

from vantage import report as reporting, store  # noqa: E402

FIXTURE = {
    "scan_id": "20260101-120000-abcd",
    "target": "10.0.0.0/24",
    "profile": "standard",
    "started": "2026-01-01T12:00:00",
    "finished": "2026-01-01T12:03:00",
    "duration_s": 180.0,
    "status": "complete",
    "guard": {
        "target": "10.0.0.0/24",
        "addresses": ["10.0.0.0"],
        "networks": ["10.0.0.0/24"],
        "host_estimate": 254,
        "operator": "nox",
        "statement": "I HAVE PERMISSION",
        "scope": {"name": "lab", "networks": ["10.0.0.0/24"],
                  "fingerprint": "deadbeefdeadbeef", "notes": "", "client": "",
                  "created": "2026-01-01T11:00:00"},
        "warnings": [],
        "created": "2026-01-01T12:00:00",
    },
    "summary": {"total": 2, "counts": {"critical": 1, "high": 0, "medium": 1,
                                      "low": 0, "info": 0},
                "confirmed": 1, "score": 61, "grade": "high"},
    "hosts": [
        {"address": "10.0.0.5", "hostname": "web01.lab", "state": "up",
         "os_matches": [], "scripts": {},
         "ports": [{"number": 445, "protocol": "tcp", "state": "open",
                    "service": "microsoft-ds", "product": "Windows",
                    "version": "7", "extrainfo": "", "reason": "syn-ack",
                    "scripts": {}}]},
    ],
    "findings": [
        {"key": "k1", "title": "SMBv1 EternalBlue (MS17-010) reported vulnerable",
         "severity": "critical", "category": "cve", "host": "10.0.0.5", "port": 445,
         "protocol": "tcp", "service": "smb", "evidence": "State: VULNERABLE",
         "detail": "nmap NSE script reported this.", "remediation": "Patch MS17-010.",
         "references": ["https://nvd.nist.gov/vuln/detail/CVE-2017-0143"],
         "confidence": "confirmed", "cvss": 9.3, "source": "nmap:smb-vuln-ms17-010",
         "cves": ["CVE-2017-0143"], "location": "10.0.0.5:445/tcp", "weighted": 40.0},
        {"key": "k2", "title": "Security header missing: X-Frame-Options",
         "severity": "medium", "category": "headers", "host": "10.0.0.6", "port": 80,
         "protocol": "tcp", "service": "http", "evidence": "http://10.0.0.6/",
         "detail": "Reported by nikto.", "remediation": "Add X-Frame-Options: DENY.",
         "references": [], "confidence": "possible", "cvss": None, "source": "nikto",
         "cves": [], "location": "10.0.0.6:80/tcp", "weighted": 3.15},
    ],
    "warnings": ["large range"],
    "errors": [],
    "coverage": ["TCP scanning only — UDP services were not enumerated."],
    "logs": ["12:00:00  start"],
    "phases": [],
    "fingerprints": [],
    "tls": [],
    "tool_versions": {"nmap": "7.98", "nikto": "present", "whatweb": "present",
                      "openssl": "present", "vantage": "1.0.0", "python": "3.13.5"},
    "vantage_version": "1.0.0",
}


class TestRender(unittest.TestCase):
    def test_markdown_contains_key_facts(self):
        md = reporting.render_markdown(FIXTURE)
        self.assertIn("10.0.0.0/24", md)
        self.assertIn("EternalBlue", md)
        self.assertIn("CVE-2017-0143", md)
        self.assertIn("I HAVE PERMISSION", md)
        self.assertIn("deadbeef", md)

    def test_markdown_groups_by_severity(self):
        md = reporting.render_markdown(FIXTURE)
        self.assertLess(md.index("### Critical"), md.index("### Medium"))

    def test_html_is_self_contained(self):
        html = reporting.render_html(FIXTURE)
        self.assertIn("<!DOCTYPE html>", html)
        self.assertIn("EternalBlue", html)
        self.assertNotIn("<link rel=\"stylesheet\"", html)
        self.assertNotIn("http://cdn", html)

    def test_html_escapes_untrusted_evidence(self):
        evil = json.loads(json.dumps(FIXTURE))
        evil["findings"][0]["evidence"] = "<script>alert(1)</script>"
        html = reporting.render_html(evil)
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;", html)

    def test_json_roundtrips(self):
        data = json.loads(reporting.render_json(FIXTURE))
        self.assertEqual(data["scan_id"], FIXTURE["scan_id"])

    def test_empty_findings_renders_clean_note(self):
        empty = json.loads(json.dumps(FIXTURE))
        empty["findings"] = []
        empty["summary"] = {"total": 0, "counts": {}, "confirmed": 0,
                            "score": 0, "grade": "clean"}
        html = reporting.render_html(empty)
        self.assertIn("nothing was detected", html.replace("\n", " ").lower())

    def test_write_reports_creates_three_files(self):
        out = tempfile.mkdtemp(prefix="vantage-reports-")
        paths = reporting.write_reports(FIXTURE, out)
        for fmt in ("html", "md", "json"):
            self.assertTrue(os.path.exists(paths[fmt]), fmt)
            self.assertGreater(os.path.getsize(paths[fmt]), 100)


class TestStore(unittest.TestCase):
    def setUp(self):
        os.environ["VANTAGE_DATA_DIR"] = tempfile.mkdtemp(prefix="vantage-db-")
        store.init_db()

    def test_save_and_load(self):
        result = _FakeResult(FIXTURE)
        store.save_scan(result)
        loaded = store.get_scan(FIXTURE["scan_id"])
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded["target"], "10.0.0.0/24")
        self.assertEqual(len(loaded["findings"]), 2)

    def test_list_scans(self):
        store.save_scan(_FakeResult(FIXTURE))
        rows = store.list_scans()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["n_findings"], 2)
        self.assertEqual(rows[0]["counts"]["critical"], 1)

    def test_findings_query_by_severity(self):
        store.save_scan(_FakeResult(FIXTURE))
        rows = store.query_findings(severity="critical")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["host"], "10.0.0.5")

    def test_resave_replaces_findings(self):
        store.save_scan(_FakeResult(FIXTURE))
        store.save_scan(_FakeResult(FIXTURE))
        self.assertEqual(len(store.query_findings()), 2)

    def test_delete_scan(self):
        store.save_scan(_FakeResult(FIXTURE))
        self.assertTrue(store.delete_scan(FIXTURE["scan_id"]))
        self.assertIsNone(store.get_scan(FIXTURE["scan_id"]))

    def test_stats(self):
        store.save_scan(_FakeResult(FIXTURE))
        s = store.stats()
        self.assertEqual(s["scans"], 1)
        self.assertEqual(s["findings"], 2)


class _FakeResult:
    """Minimal stand-in for engine.ScanResult (store only needs to_dict)."""

    def __init__(self, data):
        self._data = data

    def to_dict(self):
        return self._data


if __name__ == "__main__":
    unittest.main()

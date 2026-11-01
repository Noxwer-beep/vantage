"""Diff tests: what changed between two scans."""

import unittest

from vantage import diff as diffmod


def finding(key, title="Finding", severity="high", confidence="confirmed", host="10.0.0.5", port=443):
    return {
        "key": key,
        "title": title,
        "severity": severity,
        "confidence": confidence,
        "host": host,
        "port": port,
        "location": f"{host}:{port}/tcp",
        "protocol": "tcp",
    }


def scan(scan_id, findings, ports=((("10.0.0.5"), 443),), score=40, target="10.0.0.0/24"):
    hosts: dict[str, dict] = {}
    for host, port in ports:
        hosts.setdefault(host, {"address": host, "hostname": "", "state": "up", "ports": []})
        hosts[host]["ports"].append({"number": port, "protocol": "tcp", "state": "open"})
    return {
        "scan_id": scan_id,
        "target": target,
        "started": "2026-01-01T10:00:00",
        "summary": {"score": score, "counts": {}, "total": len(findings), "grade": "high"},
        "hosts": list(hosts.values()),
        "findings": findings,
    }


class TestDiff(unittest.TestCase):
    def test_new_finding(self):
        a = scan("a", [finding("k1")])
        b = scan("b", [finding("k1"), finding("k2", title="Fresh")])
        d = diffmod.diff_scans(a, b)
        self.assertEqual([f["key"] for f in d.new], ["k2"])
        self.assertEqual(d.resolved, [])
        self.assertEqual(len(d.persisting), 1)

    def test_resolved_finding(self):
        a = scan("a", [finding("k1"), finding("k2")])
        b = scan("b", [finding("k1")])
        d = diffmod.diff_scans(a, b)
        self.assertEqual([f["key"] for f in d.resolved], ["k2"])
        self.assertEqual(d.new, [])

    def test_nothing_changed(self):
        a = scan("a", [finding("k1")])
        b = scan("b", [finding("k1")])
        d = diffmod.diff_scans(a, b)
        self.assertFalse(d.noisy)
        self.assertEqual(len(d.persisting), 1)

    def test_severity_change_detected(self):
        a = scan("a", [finding("k1", severity="medium")])
        b = scan("b", [finding("k1", severity="critical")])
        d = diffmod.diff_scans(a, b)
        self.assertEqual(len(d.changed), 1)
        self.assertEqual(d.changed[0]["severity_before"], "medium")
        self.assertEqual(d.changed[0]["severity_after"], "critical")
        self.assertEqual(d.new, [])
        self.assertEqual(d.resolved, [])

    def test_confidence_change_detected(self):
        a = scan("a", [finding("k1", confidence="possible")])
        b = scan("b", [finding("k1", confidence="confirmed")])
        self.assertEqual(len(diffmod.diff_scans(a, b).changed), 1)

    def test_port_change(self):
        a = scan("a", [], ports=[("10.0.0.5", 443)])
        b = scan("b", [], ports=[("10.0.0.5", 443), ("10.0.0.5", 8080)])
        d = diffmod.diff_scans(a, b)
        self.assertEqual(d.new_ports, [{"host": "10.0.0.5", "port": 8080}])
        self.assertEqual(d.closed_ports, [])
        self.assertTrue(d.noisy)

    def test_port_closed(self):
        a = scan("a", [], ports=[("10.0.0.5", 443), ("10.0.0.5", 22)])
        b = scan("b", [], ports=[("10.0.0.5", 443)])
        d = diffmod.diff_scans(a, b)
        self.assertEqual(d.closed_ports, [{"host": "10.0.0.5", "port": 22}])

    def test_closed_ports_are_not_counted(self):
        a = {
            "scan_id": "a", "target": "x", "findings": [], "summary": {"score": 0},
            "hosts": [{"address": "h", "ports": [{"number": 22, "state": "closed"}]}],
        }
        b = {
            "scan_id": "b", "target": "x", "findings": [], "summary": {"score": 0},
            "hosts": [{"address": "h", "ports": []}],
        }
        self.assertEqual(diffmod.diff_scans(a, b).closed_ports, [])

    def test_score_delta(self):
        a = scan("a", [], score=30)
        b = scan("b", [], score=55)
        self.assertEqual(diffmod.diff_scans(a, b).score_delta, 25)

    def test_target_mismatch_flagged(self):
        a = scan("a", [], target="10.0.0.0/24")
        b = scan("b", [], target="192.168.1.0/24")
        self.assertFalse(diffmod.diff_scans(a, b).same_target)

    def test_new_findings_sorted_by_severity(self):
        a = scan("a", [])
        b = scan("b", [
            finding("k1", severity="low"),
            finding("k2", severity="critical"),
            finding("k3", severity="medium"),
        ])
        sev = [f["severity"] for f in diffmod.diff_scans(a, b).new]
        self.assertEqual(sev, ["critical", "medium", "low"])

    def test_missing_keys_do_not_crash(self):
        a = {"scan_id": "a", "findings": [{"title": "no key"}], "hosts": []}
        b = {"scan_id": "b", "findings": [{"title": "no key"}], "hosts": []}
        d = diffmod.diff_scans(a, b)
        self.assertEqual(d.new, [])
        self.assertEqual(d.resolved, [])


class TestDiffRender(unittest.TestCase):
    def test_markdown_mentions_both_scans(self):
        a = scan("20260101-100000-aaaa", [finding("k1")])
        b = scan("20260102-100000-bbbb", [finding("k2", title="New thing")])
        md = diffmod.render_markdown(diffmod.diff_scans(a, b))
        self.assertIn("20260101-100000-aaaa", md)
        self.assertIn("20260102-100000-bbbb", md)
        self.assertIn("New thing", md)

    def test_markdown_reports_no_changes(self):
        a = scan("a", [finding("k1")])
        b = scan("b", [finding("k1")])
        md = diffmod.render_markdown(diffmod.diff_scans(a, b))
        self.assertIn("No changes", md)

    def test_markdown_warns_on_target_mismatch(self):
        a = scan("a", [], target="10.0.0.0/24")
        b = scan("b", [], target="192.168.0.0/24")
        md = diffmod.render_markdown(diffmod.diff_scans(a, b))
        self.assertIn("different targets", md)

    def test_to_dict_counts(self):
        a = scan("a", [finding("k1")])
        b = scan("b", [finding("k2")])
        data = diffmod.to_dict(diffmod.diff_scans(a, b))
        self.assertEqual(data["counts"]["new"], 1)
        self.assertEqual(data["counts"]["resolved"], 1)
        self.assertEqual(data["counts"]["persisting"], 0)


if __name__ == "__main__":
    unittest.main()

"""Scope and authorisation tests — the legal boundary."""

import json
import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("VANTAGE_DATA_DIR", tempfile.mkdtemp(prefix="vantage-test-"))

from vantage import scope as scoping  # noqa: E402


class TestTargetParsing(unittest.TestCase):
    def test_accepts_ip_and_cidr(self):
        for token in ("10.0.0.1", "10.0.0.0/24", "fd00::/64", "::1"):
            self.assertEqual(scoping.parse_target_spec(token), token)

    def test_accepts_hostname(self):
        self.assertEqual(scoping.parse_target_spec("host.lan"), "host.lan")

    def test_rejects_shell_metacharacters(self):
        for token in ("10.0.0.1;rm -rf /", "10.0.0.1|cat", "`id`", "$(id)"):
            with self.assertRaises(scoping.ScopeError):
                scoping.parse_target_spec(token)

    def test_rejects_malformed_cidr(self):
        with self.assertRaises(scoping.ScopeError):
            scoping.parse_target_spec("10.0.0.0/99")

    def test_rejects_empty(self):
        with self.assertRaises(scoping.ScopeError):
            scoping.parse_target_spec("   ")


class TestScope(unittest.TestCase):
    def test_from_targets_normalises(self):
        scope = scoping.Scope.from_targets(["192.168.1.0/24", "10.0.0.7"])
        self.assertIn("192.168.1.0/24", scope.networks)
        self.assertIn("10.0.0.7/32", scope.networks)

    def test_allows_membership(self):
        scope = scoping.Scope(networks=["10.0.0.0/24"])
        self.assertTrue(scope.allows("10.0.0.5"))
        self.assertFalse(scope.allows("10.0.1.5"))

    def test_host_count(self):
        scope = scoping.Scope(networks=["10.0.0.0/24"])
        self.assertEqual(scope.host_count(), 254)

    def test_fingerprint_is_stable_and_order_independent(self):
        a = scoping.Scope(networks=["10.0.0.0/24", "192.168.0.0/24"])
        b = scoping.Scope(networks=["192.168.0.0/24", "10.0.0.0/24"])
        self.assertEqual(a.fingerprint(), b.fingerprint())

    def test_load_plain_text_with_comments(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
            fh.write("# homelab\nname: home\n10.0.0.0/24\n192.168.1.10\n")
            path = fh.name
        scope = scoping.Scope.load(path)
        self.assertEqual(scope.name, "home")
        self.assertIn("10.0.0.0/24", scope.networks)
        self.assertIn("192.168.1.10/32", scope.networks)

    def test_load_json(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            json.dump({"name": "client", "networks": ["10.1.0.0/16"], "client": "ACME"}, fh)
            path = fh.name
        scope = scoping.Scope.load(path)
        self.assertEqual(scope.name, "client")
        self.assertEqual(scope.networks, ["10.1.0.0/16"])

    def test_validate_rejects_garbage(self):
        with self.assertRaises(scoping.ScopeError):
            scoping.Scope(networks=["not-a-network"]).validate()

    def test_validate_rejects_empty(self):
        with self.assertRaises(scoping.ScopeError):
            scoping.Scope(networks=[]).validate()


class TestAuthorize(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="vantage-audit-")
        os.environ["VANTAGE_DATA_DIR"] = self.dir

    def test_refuses_without_statement(self):
        with self.assertRaises(scoping.AuthorizationRequired):
            scoping.authorize("127.0.0.1", statement=None)

    def test_refuses_blank_statement(self):
        with self.assertRaises(scoping.AuthorizationRequired):
            scoping.authorize("127.0.0.1", statement="   ")

    def test_allows_loopback_with_statement(self):
        guard = scoping.authorize("127.0.0.1", statement="I HAVE PERMISSION")
        self.assertEqual(guard.addresses, ["127.0.0.1"])
        self.assertEqual(guard.host_estimate, 1)

    def test_refuses_public_without_flag(self):
        with self.assertRaises(scoping.ScopeError) as ctx:
            scoping.authorize("8.8.8.8", statement="I HAVE PERMISSION")
        self.assertIn("public address", str(ctx.exception))

    def test_allows_public_with_flag(self):
        guard = scoping.authorize(
            "8.8.8.8", statement="I HAVE PERMISSION", allow_public=True
        )
        self.assertTrue(any("public" in w for w in guard.warnings))

    def test_refuses_out_of_scope(self):
        scope = scoping.Scope(name="lab", networks=["10.0.0.0/24"])
        with self.assertRaises(scoping.ScopeError) as ctx:
            scoping.authorize("10.0.1.5", scope=scope, statement="I HAVE PERMISSION")
        self.assertIn("outside scope", str(ctx.exception))

    def test_accepts_in_scope(self):
        scope = scoping.Scope(name="lab", networks=["10.0.0.0/24"])
        guard = scoping.authorize("10.0.0.0/24", scope=scope, statement="I HAVE PERMISSION")
        self.assertEqual(guard.scope.name, "lab")

    def test_refuses_oversized_range(self):
        with self.assertRaises(scoping.ScopeError) as ctx:
            scoping.authorize("10.0.0.0/8", statement="I HAVE PERMISSION", max_hosts=4096)
        self.assertIn("ceiling", str(ctx.exception))

    def test_allows_oversized_range_when_permitted(self):
        guard = scoping.authorize(
            "10.0.0.0/16", statement="I HAVE PERMISSION", allow_large=True
        )
        self.assertEqual(guard.host_estimate, 65534)

    def test_refuses_multicast(self):
        with self.assertRaises(scoping.ScopeError):
            scoping.authorize("224.0.0.1", statement="I HAVE PERMISSION")

    def test_audit_log_records_both_outcomes(self):
        scoping.authorize("127.0.0.1", statement="I HAVE PERMISSION")
        try:
            scoping.authorize("8.8.8.8", statement="I HAVE PERMISSION")
        except scoping.ScopeError:
            pass
        log = Path(self.dir) / "logs" / "audit.jsonl"
        self.assertTrue(log.exists())
        events = [json.loads(line)["event"] for line in log.read_text().splitlines()]
        self.assertIn("authorized", events)
        self.assertIn("refused", events)

    def test_guard_serialises(self):
        guard = scoping.authorize("127.0.0.1", statement="I HAVE PERMISSION")
        data = guard.to_dict()
        self.assertIn("scope", data)
        self.assertIn("fingerprint", data["scope"])
        self.assertTrue(data["scope"]["fingerprint"])


class TestParseBlob(unittest.TestCase):
    def test_splits_on_commas_and_spaces(self):
        tokens = scoping.parse_targets_blob("10.0.0.0/24, 192.168.1.5\n10.0.0.9")
        self.assertEqual(len(tokens), 3)

    def test_rejects_bad_token_in_blob(self):
        with self.assertRaises(scoping.ScopeError):
            scoping.parse_targets_blob("10.0.0.1, ; rm -rf /")


if __name__ == "__main__":
    unittest.main()

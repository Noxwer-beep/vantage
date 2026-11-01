"""Strategy and planning tests.

A strategy is a promise about which phases will run. These tests hold it to
that: the phase list is the source of truth, and the planner must never emit a
phase the strategy did not ask for (or silently drop one it did).
"""

import os
import tempfile
import unittest

os.environ.setdefault("VANTAGE_DATA_DIR", tempfile.mkdtemp(prefix="vantage-strat-"))

from vantage import config, scope as scoping  # noqa: E402
from vantage.engine import Engine  # noqa: E402


class TestStrategyDefinitions(unittest.TestCase):
    def test_all_phases_are_known(self):
        for s in config.list_strategies():
            for phase in s.phases:
                self.assertIn(phase, config.PHASE_ORDER, f"{s.name}: {phase}")

    def test_dependent_phases_need_ports(self):
        dependent = {"services", "vuln", "web", "tls"}
        for s in config.list_strategies():
            if dependent & set(s.phases):
                self.assertIn("ports", s.phases, f"{s.name} needs ports")
                self.assertTrue(s.scans_ports, s.name)

    def test_discovery_only_strategy_scans_no_ports(self):
        s = config.get_profile("discover")
        self.assertEqual(s.phases, ("discover",))
        self.assertFalse(s.scans_ports)
        self.assertEqual(s.port_label, "no port scan")

    def test_known_strategies_exist(self):
        for name in (
            "discover", "quick", "gentle", "inventory",
            "hardening", "web", "vuln", "standard", "deep",
        ):
            self.assertIn(name, config.STRATEGIES)

    def test_flags_derive_from_phases(self):
        s = config.get_profile("standard")
        self.assertTrue(s.vuln_scripts)
        self.assertTrue(s.web_checks)
        self.assertTrue(s.tls_checks)
        quick = config.get_profile("quick")
        self.assertFalse(quick.vuln_scripts)
        self.assertFalse(quick.web_checks)

    def test_legacy_profile_names_still_work(self):
        for legacy in ("quick", "standard", "deep"):
            self.assertIsNotNone(config.get_profile(legacy))

    def test_unknown_strategy_raises(self):
        with self.assertRaises(ValueError):
            config.get_profile("nope")

    def test_to_dict_is_serialisable(self):
        import json

        for s in config.list_strategies():
            json.dumps(s.to_dict())


class TestOverrides(unittest.TestCase):
    def test_without_phases(self):
        s = config.without_phases(config.get_profile("standard"), "vuln", "web")
        self.assertNotIn("vuln", s.phases)
        self.assertNotIn("web", s.phases)
        self.assertIn("tls", s.phases)

    def test_with_phases_keeps_canonical_order(self):
        s = config.without_phases(config.get_profile("standard"), "vuln", "web", "tls")
        back = config.with_phases(s, "tls", "web")
        self.assertEqual(back.phases, ("ports", "services", "web", "tls"))

    def test_with_ports_normalises(self):
        s = config.with_ports(config.get_profile("quick"), "22,80")
        self.assertEqual(s.ports, "-p 22,80")

    def test_with_timing(self):
        s = config.with_timing(config.get_profile("standard"), 2)
        self.assertEqual(s.timing, 2)


class TestPlanner(unittest.TestCase):
    def _guard(self, target):
        return scoping.authorize(target, statement="I HAVE PERMISSION")

    def test_discover_strategy_plans_discovery_only(self):
        engine = Engine(self._guard("10.0.0.0/30"), "discover")
        self.assertEqual(engine.plan(), ["discover", "analyse"])

    def test_single_target_skips_discovery(self):
        engine = Engine(self._guard("10.0.0.5"), "standard")
        plan = engine.plan()
        self.assertNotIn("discover", plan)
        self.assertIn("ports", plan)

    def test_range_runs_discovery(self):
        engine = Engine(self._guard("10.0.0.0/29"), "standard")
        self.assertIn("discover", engine.plan())

    def test_plan_ends_with_analyse(self):
        for name in ("discover", "quick", "web", "deep"):
            engine = Engine(self._guard("10.0.0.0/29"), name)
            self.assertEqual(engine.plan()[-1], "analyse", name)

    def test_plan_matches_strategy_phases(self):
        engine = Engine(self._guard("10.0.0.5"), "web")   # single host: no discovery
        plan = engine.plan()
        self.assertEqual(plan[:-1], list(config.get_profile("web").phases))

    def test_no_ports_means_no_dependent_phases(self):
        # A strategy edited to drop ports must not leave services behind.
        s = config.without_phases(config.get_profile("standard"), "ports")
        engine = Engine(self._guard("10.0.0.0/29"), s)
        plan = engine.plan()
        for dependent in ("services", "vuln", "web", "tls"):
            self.assertNotIn(dependent, plan)

    def test_plan_is_idempotent(self):
        engine = Engine(self._guard("10.0.0.0/29"), "quick")
        self.assertEqual(engine.plan(), engine.plan())


if __name__ == "__main__":
    unittest.main()

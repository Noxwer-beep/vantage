"""Profile and port-spec tests.

The `--ports` regression: a bare list used to be passed through untouched, so
nmap received a stray positional argument, ignored it, and scanned its default
port set instead. The scan still looked successful — it just wasn't the scan
that was asked for. Silent wrongness is the worst kind, hence these tests.
"""

import unittest

from vantage import config


class TestPortSpec(unittest.TestCase):
    def test_bare_list_gets_p_flag(self):
        self.assertEqual(config.normalise_port_spec("22,80,443"), "-p 22,80,443")

    def test_bare_range_gets_p_flag(self):
        self.assertEqual(config.normalise_port_spec("1-1024"), "-p 1-1024")

    def test_existing_p_flag_untouched(self):
        self.assertEqual(config.normalise_port_spec("-p 22,80"), "-p 22,80")

    def test_all_ports_untouched(self):
        self.assertEqual(config.normalise_port_spec("-p-"), "-p-")

    def test_top_ports_untouched(self):
        self.assertEqual(
            config.normalise_port_spec("--top-ports 100"), "--top-ports 100"
        )

    def test_whitespace_trimmed(self):
        self.assertEqual(config.normalise_port_spec("  8080  "), "-p 8080")

    def test_empty_stays_empty(self):
        self.assertEqual(config.normalise_port_spec(""), "")
        self.assertEqual(config.normalise_port_spec(None), "")

    def test_result_splits_into_valid_argv(self):
        for given in ("22,80", "-p-", "--top-ports 100", "-p 1-1024"):
            argv = config.normalise_port_spec(given).split()
            self.assertIn(argv[0], ("-p", "-p-", "--top-ports"), given)
            self.assertNotIn(",", argv[0], f"{given} leaked a bare list into argv")


class TestProfiles(unittest.TestCase):
    def test_profiles_are_complete(self):
        for name in ("quick", "standard", "deep"):
            profile = config.get_profile(name)
            self.assertTrue(profile.ports)
            self.assertGreaterEqual(profile.timing, 0)
            self.assertLessEqual(profile.timing, 5)

    def test_unknown_profile_raises(self):
        with self.assertRaises(ValueError):
            config.get_profile("turbo")

    def test_vuln_scripts_only_in_deeper_profiles(self):
        self.assertFalse(config.get_profile("quick").vuln_scripts)
        self.assertTrue(config.get_profile("standard").vuln_scripts)
        self.assertTrue(config.get_profile("deep").vuln_scripts)

    def test_deep_covers_all_ports(self):
        self.assertIn("-p-", config.get_profile("deep").ports.split())


if __name__ == "__main__":
    unittest.main()

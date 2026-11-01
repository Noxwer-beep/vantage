"""Runtime configuration: paths, scan strategies, severity model.

A *strategy* is a named answer to the question "what am I here to find out?".
It fixes which phases run, how many ports are covered, and how hard it leans on
the target. The old "profiles" (quick, standard, deep) are just strategies kept
under their original names so existing commands keep working.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field, replace
from pathlib import Path

APP_NAME = "vantage"

# ---------------------------------------------------------------- paths

def data_dir() -> Path:
    """Writable state directory (respects XDG)."""
    env = os.environ.get("VANTAGE_DATA_DIR")
    if env:
        return Path(env).expanduser()
    base = os.environ.get("XDG_DATA_HOME") or (Path.home() / ".local" / "share")
    return Path(base) / APP_NAME


def ensure_dirs() -> dict[str, Path]:
    root = data_dir()
    dirs = {
        "root": root,
        "scans": root / "scans",
        "reports": root / "reports",
        "logs": root / "logs",
    }
    for path in dirs.values():
        path.mkdir(parents=True, exist_ok=True)
    return dirs


DB_PATH = lambda: data_dir() / "vantage.db"          # noqa: E731
AUDIT_PATH = lambda: data_dir() / "logs" / "audit.jsonl"  # noqa: E731

# ---------------------------------------------------------------- severity

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
SEVERITY_RANK = {name: i for i, name in enumerate(SEVERITY_ORDER)}

# Weight used for the 0-100 risk score. Confidence scales these down.
SEVERITY_WEIGHT = {
    "critical": 40,
    "high": 18,
    "medium": 6,
    "low": 1,
    "info": 0,
}

#: A single finding of this severity (confirmed) puts the score at least here.
#: Without a floor, twenty low findings would outweigh one critical, which is
#: exactly the judgement call a reader should not have to make.
SEVERITY_FLOOR = {
    "critical": 82,
    "high": 55,
    "medium": 28,
    "low": 8,
    "info": 0,
}

CONFIDENCE_SCALE = {
    "confirmed": 1.0,
    "likely": 0.7,
    "possible": 0.45,
    "informational": 0.2,
}

# ---------------------------------------------------------------- phases

#: Canonical phase order. A strategy selects a subset of these.
PHASE_ORDER = ("discover", "ports", "services", "vuln", "web", "tls")

PHASE_LABELS = {
    "discover": "Host discovery",
    "ports": "Port scan",
    "services": "Service & version detection",
    "vuln": "Vulnerability scripts (NSE)",
    "web": "Web surface review",
    "tls": "TLS inspection",
    "analyse": "Analysis",
}

_PHASE_WORDS = {
    "discover": "discovery",
    "ports": "port scan",
    "services": "versions",
    "vuln": "NSE vuln",
    "web": "web",
    "tls": "TLS",
}


# ---------------------------------------------------------------- strategies

@dataclass(frozen=True)
class Profile:
    """A named scan strategy.

    `phases` is the source of truth. The boolean properties below exist because
    callers read them like flags (`if profile.vuln_scripts`); deriving them from
    one list means a strategy cannot describe a phase it will not actually run.
    """

    name: str
    title: str
    use_case: str
    ports: str
    phases: tuple[str, ...]
    timing: int = 3
    discovery: str = "auto"          # auto | always | never
    hostgroup: int = 8
    version_intensity: int = 5
    udp: bool = False

    # -- phase flags ------------------------------------------------------

    @property
    def version_detection(self) -> bool:
        return "services" in self.phases

    @property
    def vuln_scripts(self) -> bool:
        return "vuln" in self.phases

    @property
    def web_checks(self) -> bool:
        return "web" in self.phases

    @property
    def tls_checks(self) -> bool:
        return "tls" in self.phases

    @property
    def scans_ports(self) -> bool:
        return "ports" in self.phases

    # -- human text -------------------------------------------------------

    @property
    def port_label(self) -> str:
        p = self.ports.strip()
        return {
            "--top-ports 100": "top 100 TCP",
            "--top-ports 1000": "top 1000 TCP",
            "-p-": "all 65535 TCP",
            "": "no port scan",
        }.get(p, p)

    @property
    def description(self) -> str:
        words: list[str] = []
        if self.scans_ports:
            words.append(self.port_label)
        words += [_PHASE_WORDS[p] for p in self.phases if p != "ports"]
        return " · ".join(words)

    def estimate(self) -> str:
        if not self.scans_ports:
            return "seconds per range"
        if self.name == "gentle":
            return "slow by design: about 1 min per host"
        if self.name == "deep":
            return "10-60+ min per host, depending on open services"
        if self.name == "quick":
            return "seconds per host"
        return "1-4 min per host; longer on busy web servers"

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "title": self.title,
            "use_case": self.use_case,
            "description": self.description,
            "ports": self.ports,
            "port_label": self.port_label,
            "phases": list(self.phases),
            "timing": self.timing,
            "estimate": self.estimate(),
        }


_STRATEGIES = [
    Profile(
        name="discover",
        title="Host discovery",
        use_case="Which addresses answer at all? No port scanning, no probing.",
        ports="",
        phases=("discover",),
        discovery="always",
    ),
    Profile(
        name="quick",
        title="Fast sweep",
        use_case="A first look at a range: top 100 ports and their banners.",
        ports="--top-ports 100",
        phases=("ports", "services"),
    ),
    Profile(
        name="gentle",
        title="Gentle sweep",
        use_case="Fragile or production gear: few ports, low timing, one host at a time.",
        ports="--top-ports 100",
        phases=("ports", "services"),
        timing=2,
        hostgroup=1,
    ),
    Profile(
        name="inventory",
        title="Asset inventory",
        use_case="What runs where: top 1000 ports with service and version, nothing intrusive.",
        ports="--top-ports 1000",
        phases=("ports", "services"),
    ),
    Profile(
        name="hardening",
        title="Hardening review",
        use_case="Crypto and patch posture only: certificates, TLS versions, end-of-life banners.",
        ports="--top-ports 1000",
        phases=("ports", "services", "tls"),
    ),
    Profile(
        name="web",
        title="Web surface",
        use_case="HTTP endpoints: what the server is, what it leaks, missing headers, TLS.",
        ports="--top-ports 1000",
        phases=("ports", "services", "web", "tls"),
    ),
    Profile(
        name="vuln",
        title="Known issues",
        use_case="NSE vulnerability checks on hosts you already understand, without web crawling.",
        ports="--top-ports 1000",
        phases=("ports", "services", "vuln"),
    ),
    Profile(
        name="standard",
        title="Standard assessment",
        use_case="The default: ports, versions, NSE vuln, web review and TLS.",
        ports="--top-ports 1000",
        phases=("ports", "services", "vuln", "web", "tls"),
    ),
    Profile(
        name="deep",
        title="Deep assessment",
        use_case="Full 65535-port coverage with deeper version probing. Slow.",
        ports="-p-",
        phases=("ports", "services", "vuln", "web", "tls"),
        timing=4,
        version_intensity=7,
    ),
]

STRATEGIES: dict[str, Profile] = {s.name: s for s in _STRATEGIES}

#: Backwards-compatible alias: a profile is a strategy.
PROFILES = STRATEGIES


def get_profile(name: str) -> Profile:
    try:
        return STRATEGIES[name]
    except KeyError:
        raise ValueError(
            f"unknown strategy {name!r}; choose from {', '.join(STRATEGIES)}"
        ) from None


get_strategy = get_profile


def list_strategies() -> list[Profile]:
    return list(_STRATEGIES)


# ---------------------------------------------------------------- overrides

def without_phases(profile: Profile, *names: str) -> Profile:
    keep = tuple(p for p in profile.phases if p not in names)
    return replace(profile, phases=keep)


def with_phases(profile: Profile, *names: str) -> Profile:
    keep = set(profile.phases) | set(names)
    ordered = tuple(p for p in PHASE_ORDER if p in keep)
    return replace(profile, phases=ordered)


def with_ports(profile: Profile, spec: str) -> Profile:
    return replace(profile, ports=normalise_port_spec(spec))


def with_timing(profile: Profile, timing: int) -> Profile:
    return replace(profile, timing=timing)


def normalise_port_spec(value: str) -> str:
    """Turn a user-supplied port list into a complete nmap argument.

    `--ports 22,80` must become `-p 22,80`; a spec that already carries its own
    flag (`-p-`, `--top-ports 100`, `-p 22,80`) must be left alone. Without this
    a bare list silently degrades to nmap's default scan, which looks like it
    worked and quietly scans the wrong thing.
    """
    spec = (value or "").strip()
    if not spec:
        return spec
    return spec if spec.startswith("-") else f"-p {spec}"


# ---------------------------------------------------------------- limits

#: A scan profile never expands beyond this many addresses without an explicit
#: opt-in. Keeps a typo ("10.0.0.0/8") from becoming an incident.
MAX_HOSTS_DEFAULT = 4096

#: Hosts contacted in parallel within one nmap run.
MAX_PARALLEL_HOSTGROUP = 8

#: Hard ceiling on any single nmap invocation, in seconds.
SCAN_TIMEOUTS = {"discovery": 300, "ports": 3600, "services": 2400, "vuln": 5400, "web": 1800, "tls": 120}

WEB_PORTS = {80, 81, 88, 311, 443, 591, 593, 832, 981, 1010, 1311, 2082, 2087,
             2095, 2096, 2480, 3000, 4000, 5000, 5104, 5800, 5985, 5986, 7070,
             8000, 8008, 8042, 8080, 8081, 8088, 8090, 8161, 8180, 8443, 8834,
             8888, 9000, 9090, 9443, 10000, 10443}
TLS_PORTS = {443, 465, 636, 993, 995, 8443, 9443, 10443, 5061, 8883}


@dataclass
class Limits:
    """Ceilings applied at runtime; overridable from the CLI."""

    max_hosts: int = MAX_HOSTS_DEFAULT
    hostgroup: int = MAX_PARALLEL_HOSTGROUP
    timeout: dict[str, int] = field(default_factory=lambda: dict(SCAN_TIMEOUTS))

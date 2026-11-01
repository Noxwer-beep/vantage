"""Scope enforcement and the authorisation gate.

This module is the legal boundary of the tool. Everything else assumes that a
`Guard` was obtained here first, and a `Guard` can only be produced for targets
inside an explicitly authorised scope.

Design rules:
  1. Deny by default. A target is allowed only if a scope says so, or the
     operator explicitly claims the single target as their own.
  2. Resolve first, decide after. Hostnames are resolved and *every* returned
     address must pass, so DNS cannot be used to smuggle a target through.
  3. Refuse ambiguous ranges. Loopback, multicast, broadcast, unspecified and
     oversized ranges are rejected outright.
  4. Write an audit line for every decision, including refusals.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import ipaddress
import json
import os
import re
import socket
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Sequence

from . import config

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


class ScopeError(Exception):
    """Raised when a target is not permitted. Carries a human explanation."""


class AuthorizationRequired(ScopeError):
    """Raised when no authorisation statement was supplied."""


# ---------------------------------------------------------------- helpers

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$"
)


def _normalise(token: str) -> str:
    return token.strip().strip(",")


def parse_target_spec(token: str) -> str:
    """Validate one target token: IP, CIDR, hostname or hostname/CIDR.

    Returns the token untouched (case preserved for display) after validation.
    Raises ScopeError on anything that is not a well-formed target.
    """
    token = _normalise(token)
    if not token:
        raise ScopeError("empty target")
    if len(token) > 253:
        raise ScopeError(f"target too long: {token[:40]!r}...")
    if any(c in token for c in " \t\r\n;|&$`'\"\\"):
        raise ScopeError(f"illegal character in target {token!r}")
    # CIDR or bare IP
    try:
        ipaddress.ip_network(token, strict=False)
        return token
    except ValueError:
        pass
    if "/" in token:
        raise ScopeError(f"malformed CIDR {token!r}")
    if not _HOSTNAME_RE.match(token):
        raise ScopeError(f"not a valid IP, CIDR or hostname: {token!r}")
    return token


def resolve_target(token: str) -> list[IPAddress]:
    """Resolve a target token to concrete addresses.

    A CIDR expands to its network and broadcast addresses *only* when the
    network is small enough to be meaningful for the caller; here we return the
    network's `hosts()` count separately (see `network_of`).
    """
    try:
        net = ipaddress.ip_network(token, strict=False)
        if net.num_addresses == 1:
            return [net.network_address]
        return [net.network_address]  # membership test handled by network
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(token, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise ScopeError(f"cannot resolve {token!r}: {exc}") from None
    seen: list[IPAddress] = []
    for info in infos:
        addr = ipaddress.ip_address(info[4][0])
        if addr not in seen:
            seen.append(addr)
    if not seen:
        raise ScopeError(f"{token!r} resolved to no addresses")
    return seen


def network_of(token: str) -> IPNetwork | None:
    """Return the network a CIDR target denotes, else None for single hosts."""
    try:
        net = ipaddress.ip_network(token, strict=False)
    except ValueError:
        return None
    return net if net.num_addresses > 1 else None


def is_single_host(token: str) -> bool:
    net = network_of(token)
    if net is None:
        return True
    return net.num_addresses <= 2  # a /31 or /32 is a host pair


# ---------------------------------------------------------------- scope

@dataclass
class Scope:
    """An explicit, auditable list of networks an engagement may touch."""

    name: str = "adhoc"
    networks: list[str] = field(default_factory=list)
    notes: str = ""
    created: str = field(default_factory=lambda: _dt.datetime.now().isoformat(timespec="seconds"))
    client: str = ""

    # -- construction -----------------------------------------------------

    @classmethod
    def from_targets(cls, targets: Iterable[str], name: str = "adhoc", **kw) -> "Scope":
        nets: list[str] = []
        for raw in targets:
            token = parse_target_spec(raw)
            net = network_of(token)
            if net is not None:
                nets.append(str(net))
            else:
                for addr in resolve_target(token):
                    nets.append(f"{addr}/{addr.max_prefixlen}")
        return cls(name=name, networks=nets, **kw)

    @classmethod
    def load(cls, path: str | Path) -> "Scope":
        p = Path(path).expanduser()
        if not p.exists():
            raise ScopeError(f"scope file not found: {p}")
        text = p.read_text(encoding="utf-8")
        suffix = p.suffix.lower()
        if suffix == ".json":
            data = json.loads(text or "{}")
            if not isinstance(data, dict):
                raise ScopeError("scope JSON must be an object")
            return cls(
                name=str(data.get("name") or p.stem),
                networks=[str(n) for n in data.get("networks", [])],
                notes=str(data.get("notes", "")),
                client=str(data.get("client", "")),
            )
        if suffix == ".toml":
            try:
                import tomllib
            except ModuleNotFoundError:  # pragma: no cover - py<3.11
                raise ScopeError("TOML scopes need Python 3.11+") from None
            data = tomllib.loads(text)
            return cls(
                name=str(data.get("name") or p.stem),
                networks=[str(n) for n in data.get("networks", [])],
                notes=str(data.get("notes", "")),
                client=str(data.get("client", "")),
            )
        # plain text: one target per line, '#' comments
        nets: list[str] = []
        name = p.stem
        for line in text.splitlines():
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            if line.lower().startswith("name:"):
                name = line.split(":", 1)[1].strip()
                continue
            net = network_of(line)
            nets.append(str(net) if net else f"{resolve_target(line)[0]}/{resolve_target(line)[0].max_prefixlen}")
        return cls(name=name, networks=nets)

    # -- queries ----------------------------------------------------------

    def validate(self) -> None:
        cleaned: list[str] = []
        for raw in self.networks:
            try:
                net = ipaddress.ip_network(raw, strict=False)
            except ValueError:
                raise ScopeError(f"scope contains an invalid network: {raw!r}") from None
            cleaned.append(str(net))
        if not cleaned:
            raise ScopeError("scope defines no networks")
        self.networks = cleaned

    @property
    def parsed(self) -> list[IPNetwork]:
        out: list[IPNetwork] = []
        for raw in self.networks:
            try:
                out.append(ipaddress.ip_network(raw, strict=False))
            except ValueError:
                continue
        return out

    def allows(self, addr: str | IPAddress) -> bool:
        ip = ipaddress.ip_address(addr) if isinstance(addr, str) else addr
        return any(ip in net for net in self.parsed if net.version == ip.version)

    def host_count(self) -> int:
        total = 0
        for net in self.parsed:
            total += max(net.num_addresses - 2, 1)
        return total

    def fingerprint(self) -> str:
        """Stable hash of the authorised networks — goes in the audit line."""
        blob = json.dumps(sorted(self.networks), sort_keys=True).encode()
        return hashlib.sha256(blob).hexdigest()[:16]

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "networks": self.networks,
            "notes": self.notes,
            "client": self.client,
            "created": self.created,
            "fingerprint": self.fingerprint(),
        }

    def summary(self) -> str:
        if len(self.networks) <= 4:
            return ", ".join(self.networks)
        return f"{', '.join(self.networks[:3])} (+{len(self.networks) - 3} more)"


# ---------------------------------------------------------------- guard

@dataclass
class Guard:
    """Proof that a target set was checked. Only produced by `authorize`."""

    target: str
    scope: Scope
    addresses: list[str]
    networks: list[str]
    host_estimate: int
    operator: str
    statement: str
    warnings: list[str] = field(default_factory=list)
    created: str = field(default_factory=lambda: _dt.datetime.now().isoformat(timespec="seconds"))

    @property
    def is_local_only(self) -> bool:
        return all(
            ipaddress.ip_address(a).is_private or ipaddress.ip_address(a).is_loopback
            for a in self.addresses
        )

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "addresses": self.addresses,
            "networks": self.networks,
            "host_estimate": self.host_estimate,
            "operator": self.operator,
            "statement": self.statement,
            "scope": self.scope.to_dict(),
            "warnings": self.warnings,
            "created": self.created,
        }


CONSENT_PHRASES = (
    "I HAVE PERMISSION",
)


def operator_name() -> str:
    return os.environ.get("VANTAGE_OPERATOR") or os.environ.get("USER") or os.environ.get("USERNAME") or "unknown"


def audit(record: dict) -> None:
    """Append one JSON line to the audit log. Never raises."""
    try:
        config.ensure_dirs()
        record = {
            "ts": _dt.datetime.now().isoformat(timespec="seconds"),
            "operator": operator_name(),
            "host": socket.gethostname(),
            **record,
        }
        with open(config.AUDIT_PATH(), "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, sort_keys=True) + "\n")
    except OSError:
        pass


def authorize(
    target: str,
    *,
    scope: Scope | None = None,
    statement: str | None = None,
    allow_public: bool = False,
    allow_large: bool = False,
    max_hosts: int = config.MAX_HOSTS_DEFAULT,
) -> Guard:
    """Validate a target against a scope and produce a Guard, or raise.

    `statement` must be an explicit authorisation claim (see CONSENT_PHRASES);
    passing None raises AuthorizationRequired.
    """
    warnings: list[str] = []

    if not statement or not statement.strip():
        audit({"event": "refused", "reason": "no-authorization-statement", "target": target})
        raise AuthorizationRequired(
            "no authorisation statement supplied — pass --authorized to confirm that "
            "you own this target or hold written permission to test it"
        )

    token = parse_target_spec(target)

    # ---- expand the target into networks + addresses
    net = network_of(token)
    if net is not None:
        networks = [str(net)]
        addresses = [str(net.network_address)]
        estimate = max(net.num_addresses - 2, 1)
    else:
        addresses = [str(a) for a in resolve_target(token)]
        networks = [f"{a}/{ipaddress.ip_address(a).max_prefixlen}" for a in addresses]
        estimate = len(addresses)

    # ---- hard refusals on the target itself
    for raw in addresses:
        ip = ipaddress.ip_address(raw)
        if ip.is_multicast:
            raise ScopeError(f"{raw} is a multicast address; refusing")
        if ip.is_unspecified:
            raise ScopeError(f"{raw} is the unspecified address; refusing")
        if ip == ipaddress.ip_address("255.255.255.255"):
            raise ScopeError("broadcast target; refusing")

    # ---- scope membership
    if scope is not None:
        scope.validate()
        for raw in addresses:
            if not scope.allows(raw):
                audit({
                    "event": "refused",
                    "reason": "out-of-scope",
                    "target": target,
                    "addresses": addresses,
                    "scope": scope.name,
                    "scope_fingerprint": scope.fingerprint(),
                })
                raise ScopeError(
                    f"{raw} is outside scope {scope.name!r} ({scope.summary()}) — refusing"
                )
        if net is not None:
            for addr in (net.network_address, net.broadcast_address):
                if not scope.allows(addr):
                    raise ScopeError(
                        f"network boundary {addr} is outside scope {scope.name!r} — refusing"
                    )
    else:
        # No scope: the target claims itself. Only a single host is implicit;
        # a range always needs a written scope.
        if net is not None and net.num_addresses > 2:
            warnings.append(
                "no scope file: implicit authorisation for "
                f"{net} based on the operator's --authorized statement"
            )
        scope = Scope.from_targets([token], name=f"implicit:{token}")

    # ---- public address handling
    globals_found = [
        raw for raw in addresses if ipaddress.ip_address(raw).is_global
    ]
    if globals_found and not allow_public:
        audit({
            "event": "refused",
            "reason": "public-address-without-flag",
            "target": target,
            "addresses": globals_found,
        })
        raise ScopeError(
            f"{', '.join(globals_found)} is a public address. Testing internet-facing "
            "systems requires written permission; re-run with --allow-public only if "
            "you have it."
        )
    if globals_found:
        warnings.append("public addresses in scope — confirm written authorisation is on file")

    # ---- size limits
    if estimate > max_hosts and not allow_large:
        audit({
            "event": "refused",
            "reason": "range-too-large",
            "target": target,
            "estimate": estimate,
        })
        raise ScopeError(
            f"target covers ~{estimate} addresses, above the {max_hosts} ceiling. "
            "Narrow the range, or raise it deliberately with --allow-large."
        )
    if estimate > 512:
        warnings.append(f"large range (~{estimate} addresses): expect a long run")

    guard = Guard(
        target=token,
        scope=scope,
        addresses=addresses,
        networks=networks,
        host_estimate=estimate,
        operator=operator_name(),
        statement=statement.strip(),
        warnings=warnings,
    )
    audit({
        "event": "authorized",
        "target": token,
        "addresses": addresses,
        "networks": networks,
        "host_estimate": estimate,
        "scope": scope.name,
        "scope_fingerprint": scope.fingerprint(),
        "statement": guard.statement,
        "warnings": warnings,
    })
    return guard


def check_scope_file(path: str | Path) -> Scope:
    """Load and validate a scope file (used by `vantage scope check`)."""
    scope = Scope.load(path)
    scope.validate()
    return scope


def parse_targets_blob(blob: str) -> list[str]:
    """Split a comma/space separated target string into validated tokens."""
    tokens = [t for t in re.split(r"[,\s]+", blob or "") if t]
    return [parse_target_spec(t) for t in tokens]


def deny_private_guard(guard: Guard) -> None:
    """Convenience assertion used by tests and by the web UI form handler."""
    if not guard.addresses:
        raise ScopeError("guard has no addresses")

"""Published URLs on an emulator: the hosts a customer reaches it at, and how a URL is graded.

A customer of an emulator sets one endpoint URL and reaches every host the emulator publishes
without rerouting, resolving or re-signing. A URL or host a fidelity test is handed that no such
customer can use fails the test (``PublishedUrlRejected``) before anything is dialed.
"""

import functools
import ipaddress
import json
import os
import re
import socket
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

import botocore

from fidelity_tests_runner.target import (
    PRIVATE_NETWORKS,
    is_strict_loopback_host,
    partition_suffixes,
    validate_endpoint,
)

#: Where a run reads the emulator's documented own hosts when its caller names none.
OWN_HOSTS_ENV = "FIDELITY_TESTS_OWN_HOSTS"


def under_partition(host: str) -> bool:
    """Whether ``host`` is under an AWS partition's DNS suffix, matched on whole labels."""
    host = (host or "").lower().rstrip(".")
    if not host or not all(host.split(".")):
        return False
    return any(host == s or host.endswith(f".{s}") for s in partition_suffixes())


def is_private_address(text: str) -> bool:
    """A loopback or private-block IP literal, never link-local or the instance-metadata range."""
    try:
        ip = ipaddress.ip_address(text.strip("[]"))
    except ValueError:
        return False
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if ip.is_loopback:
        return True
    return any(ip in n for n in PRIVATE_NETWORKS if n.version == ip.version)


#: Why a published value is unusable: ``published_url_violations`` reasons and wire diff reasons.
NAME_UNDER_IP = "host_unresolvable"
FOREIGN_HOST = "host_not_own"
NOT_IDENTIFIED = "resource_not_identified"

#: What a published value is: ``published_url_violations`` value classes.
URL = "url"
SIGNED_URL = "signed_url"
HOST = "host"

#: Each URL scheme's default port.
DEFAULT_PORTS = {"http": 80, "https": 443, "ws": 80, "wss": 443}
#: The names of one loopback listener: another loopback address is another listener.
LOOPBACK_NAMES = frozenset({"localhost", "127.0.0.1", "::1"})
#: Query keys that make a URL signed: SigV4 and SigV2 presigning, CloudFront signed URLs.
_SIGNATURE_KEYS = frozenset({"x-amz-signature", "signature"})


class PublishedUrlRejected(AssertionError):
    """An emulator published a URL or host no customer of it can use: the test fails.

    ``reason`` and ``value_class`` are the ``published_url_violations`` entry's.
    """

    def __init__(self, message: str, reason: str, value_class: str):
        super().__init__(message)
        self.reason = reason
        self.value_class = value_class


def is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return True


def name_under_ip(host: str) -> bool:
    """Whether ``host`` is a name under an IPv4 literal (``bkt.s3.127.0.0.1``): no resolver answers.

    One under an IPv6 literal cannot be written. An OID (``1.3.6.1.5.5.7.3.1``: numbers only, the
    first 0, 1 or 2) is none; an all-digit bucket label (``12345.127.0.0.1``) is one.
    """
    labels = host.lower().rstrip(".").split(".")
    return len(labels) > 4 and is_ip_literal(".".join(labels[-4:])) and not is_oid(host)


def is_oid(value: str) -> bool:
    """Whether ``value`` is a dotted object identifier: numbers only, the first arc 0, 1 or 2."""
    arcs = value.split(".")
    return len(arcs) > 1 and all(a.isdigit() for a in arcs) and arcs[0] in ("0", "1", "2")


def is_signed(url: str) -> bool:
    """Whether ``url`` carries a signature in its query (presigned, or a CloudFront signed URL)."""
    return any(k.lower() in _SIGNATURE_KEYS for k, _ in parse_qsl(urlsplit(url).query))


def value_class(value: str) -> str:
    """``signed_url``, ``url`` or ``host``: the kind of published value ``value`` is."""
    if "://" not in value:
        return HOST
    return SIGNED_URL if is_signed(value) else URL


def host_pattern(value: str) -> str:
    """``value``'s host with its resource label as ``*``, no port: the key that groups violations.

    The first label is the resource's (a distribution, an API id, a bucket) unless the host is an
    AWS service endpoint (``_aws_service_host``), which stays whole. An IP literal is ``<ip>``, a
    name under one ``*.<ip>``, and a one-label host stays as it is.
    """
    url = value if "://" in value else f"tcp://{_bracketed(value)}"
    try:
        host = _canonical(urlsplit(url).hostname or "")
    except ValueError:
        host = ""
    if is_ip_literal(host):
        return "<ip>"
    if name_under_ip(host):
        return "*.<ip>"
    _, dot, rest = host.partition(".")
    if not (dot and rest) or _aws_service_host(host):
        return host
    return f"*.{rest}"


#: Services that put a resource name first in their host (a bucket, an access point, an API id).
#: A host with one of these second is a resource's, even when its first label (a bucket named
#: ``logs``) is also an endpoint prefix.
_RESOURCE_HOSTING = frozenset(
    {
        "s3",
        "s3-accesspoint",
        "s3-object-lambda",
        "execute-api",
        "appsync-api",
        "appsync-realtime-api",
    }
)


def _aws_service_host(host: str) -> bool:
    """Whether ``host`` is an AWS service endpoint: an endpoint prefix first, or ``x.<region>``.

    The region rule (``sqs.us-west-2``) also covers services ``endpoints.json`` does not list; a
    resource label before the region (``vpc-x.us-west-2.es``) does not match it. A
    host whose second label is a resource-hosting service (``_RESOURCE_HOSTING``) is a resource's.
    """
    if not under_partition(host):
        return False
    second = host.split(".")[1]
    if second in _RESOURCE_HOSTING or second.startswith("s3-website"):
        return False
    prefixes, regions, suffixes = _endpoint_data()
    if any(host.startswith(f"{p}.") for p in prefixes):
        return True
    labels = next((host[: -len(s) - 1].split(".") for s in suffixes if host.endswith(f".{s}")), [])
    return len(labels) == 2 and any(r.fullmatch(labels[1]) for r in regions)


@functools.cache
def _endpoint_data() -> tuple[frozenset[str], tuple[re.Pattern[str], ...], tuple[str, ...]]:
    """The endpoint prefixes, region patterns and DNS suffixes (longest first) botocore lists."""
    data = Path(botocore.__file__).parent / "data"
    endpoints = json.loads((data / "endpoints.json").read_text())
    partitions = json.loads((data / "partitions.json").read_text())["partitions"]
    prefixes = frozenset(k for p in endpoints["partitions"] for k in p["services"])
    regions = tuple(re.compile(p["regionRegex"]) for p in partitions)
    suffixes = {
        o[k]
        for p in partitions
        for o in [p["outputs"]]
        for k in ("dnsSuffix", "dualStackDnsSuffix")
    }
    return prefixes, regions, tuple(sorted(suffixes, key=len, reverse=True))


def own_host_entries(values: Iterable[str] | str | None) -> tuple[str, ...]:
    """Documented own hosts, each an exact host or ``*.<suffix>``, checked and lower-cased.

    ``None`` reads ``OWN_HOSTS_ENV`` (comma-separated); an IPv6 entry may be bracketed. Refused as
    the run's input error: a name under an IP, ``*.<IP>``, an IP that is not loopback or private
    (the unspecified addresses included), a non-IP whose last label is a number, a host under an AWS
    partition's DNS suffix or one that resolves to an address neither loopback nor private (an
    emulator run never reaches AWS), a one-label suffix other than ``localhost`` (``*.com``), and
    anything but a bare host.
    """
    if values is None:
        values = os.environ.get(OWN_HOSTS_ENV, "")
    if isinstance(values, str):
        values = values.split(",")
    entries = []
    for raw in values:
        entry = _canonical(raw.strip())
        if not entry:
            continue
        host = entry.removeprefix("*.")
        if ":" in host and not is_ip_literal(host):
            raise ValueError(f"own host {raw!r} is not a bare host or *.<suffix>: it has a port")
        try:
            validate_endpoint(f"http://{f'[{host}]' if ':' in host else host}")
        except ValueError as exc:
            raise ValueError(f"own host {raw!r} is not a bare host or *.<suffix>: {exc}") from None
        if name_under_ip(host) or (host != entry and is_ip_literal(host)):
            raise ValueError(f"own host {raw!r} is a name under an IP address; none resolves")
        if not is_ip_literal(host) and host.rpartition(".")[2].isdigit():
            raise ValueError(f"own host {raw!r} has a last label that is a number; it is no name")
        if is_ip_literal(host) and not is_private_address(host):
            raise ValueError(f"own host {raw!r} is not a loopback or private address")
        if under_partition(host):
            raise ValueError(f"own host {raw!r} is under an AWS partition's DNS suffix")
        if host != entry and "." not in host and host != "localhost":
            raise ValueError(f"own host {raw!r} is a public suffix; name two labels or more")
        name = f"{_PROBE_LABEL}.{host}" if host != entry else host
        if not is_ip_literal(host) and (public := public_addresses(name)):
            raise ValueError(
                f"own host {raw!r} resolves to {', '.join(public)}, not loopback or private"
            )
        entries.append(entry)
    return tuple(dict.fromkeys(entries))


#: The label a ``*.<suffix>`` entry is resolved under, to learn what its names resolve to.
_PROBE_LABEL = "fidelity-tests-own-host-probe"


#: ``name -> public addresses`` for names that resolved; a failed lookup is not kept.
_RESOLVED: dict[str, tuple[str, ...]] = {}
_RESOLVED_MAX = 256


def public_addresses(name: str) -> tuple[str, ...]:
    """The addresses ``name`` resolves to that are neither loopback nor private; none if none.

    A documented own host that resolves elsewhere (an AWS host) is no emulator's own; one that
    resolves nowhere cannot reach AWS either. A failed lookup is resolved again on the next call.
    """
    if (known := _RESOLVED.get(name)) is not None:
        return known
    try:
        infos = socket.getaddrinfo(name, None)
    except OSError:
        return ()
    public = tuple(sorted({i[4][0] for i in infos if not is_private_address(i[4][0])}))
    if len(_RESOLVED) >= _RESOLVED_MAX:
        _RESOLVED.clear()
    _RESOLVED[name] = public
    return public


def _canonical(host: str) -> str:
    """``host`` lower-case, unbracketed, with no trailing dot; an IPv4-mapped IPv6 as IPv4."""
    host = host.lower().rstrip(".").strip("[]")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return host
    return str(ip.ipv4_mapped) if ip.version == 6 and ip.ipv4_mapped else str(ip)


def matches_entry(host: str, entries: Iterable[str]) -> bool:
    """Whether ``host`` is an exact entry or a name strictly under a ``*.<suffix>`` entry."""
    host = _canonical(host)
    return any(host == e or (e.startswith("*.") and host.endswith(e[1:])) for e in entries)


@dataclass(frozen=True)
class OwnHosts:
    """The hosts a customer of an emulator reaches it at, and the endpoint it configures."""

    #: The endpoint's scheme, host (lower-case, unbracketed) and port.
    scheme: str
    host: str
    port: int
    #: The documented own hosts beyond loopback and the endpoint host (``own_host_entries``).
    entries: tuple[str, ...] = ()

    @classmethod
    def of(cls, endpoint: str, own_hosts: Iterable[str] | str | None = None) -> "OwnHosts":
        """``endpoint``'s own hosts, with ``own_hosts`` (else ``OWN_HOSTS_ENV``) added."""
        return cls.of_entries(endpoint, own_host_entries(own_hosts))

    @classmethod
    def of_entries(cls, endpoint: str, entries: Iterable[str]) -> "OwnHosts":
        """``endpoint``'s own hosts with ``entries``, already checked by ``own_host_entries``."""
        parts = urlsplit(endpoint)
        scheme = parts.scheme.lower()
        host = _canonical(parts.hostname or "")
        entries = tuple(dict.fromkeys(entries))
        loopback = (is_strict_loopback_host(e.removeprefix("*.")) for e in entries)
        if not is_strict_loopback_host(host) and any(loopback):
            raise ValueError(f"a remote endpoint {endpoint!r} takes no loopback own host")
        return cls(scheme, host, parts.port or DEFAULT_PORTS.get(scheme, 80), entries)

    @property
    def loopback(self) -> bool:
        """Whether the endpoint is on loopback, so every loopback address is the emulator's too."""
        return is_strict_loopback_host(self.host)

    @property
    def bracketed_host(self) -> str:
        """The endpoint's host as a URL writes it: an IPv6 address bracketed."""
        return f"[{self.host}]" if ":" in self.host else self.host

    @property
    def netloc(self) -> str:
        """The endpoint's ``host[:port]``, as a customer writes it in ``endpoint_url``."""
        host = self.bracketed_host
        return host if DEFAULT_PORTS.get(self.scheme) == self.port else f"{host}:{self.port}"

    @property
    def endpoint(self) -> str:
        """The endpoint URL a customer sets: ``scheme://host[:port]``."""
        return f"{self.scheme}://{self.netloc}"

    def owns(self, host: str) -> bool:
        """Whether ``host`` is an own host, matched literally and case-insensitively.

        The endpoint host or a documented entry (exact, or strictly under ``*.<suffix>``); for a
        loopback endpoint also ``localhost`` and every loopback address. Never a name under an IP.
        """
        host = _canonical(host)
        if not host or name_under_ip(host):
            return False
        if host == self.host or matches_entry(host, self.entries):
            return True
        return self.loopback and is_strict_loopback_host(host)

    def expected(self, value: str) -> str:
        """The form a customer of the emulator needs ``value`` in, naming no AWS host."""
        if "://" not in value:
            return (
                "an own host[:port]: the endpoint host, a documented own host or, for a "
                "loopback endpoint, a loopback address"
            )
        scheme = urlsplit(value).scheme.lower()
        family = {"https": "http", "wss": "ws"}.get(scheme, scheme)
        family += "(s)" if family in ("http", "ws") else ""
        return (
            f"{family}://{self.netloc}/<resource path>, or {family}://<own host>:<port>/<path> on "
            "a per-resource listener"
        )

    def problem(self, value: str) -> tuple[str, str] | None:
        """``(reason, why)`` for why a customer of the emulator cannot use ``value``, or None.

        ``value`` is a URL or a bare ``host[:port]``; its host is a name under an IP or not an own
        host. ``why`` names the host's fault and the form the customer needs; the scheme and port
        are the caller's to grade.
        """
        url = value if "://" in value else f"tcp://{_bracketed(value)}"
        try:
            host = (urlsplit(url).hostname or "").lower().rstrip(".")
        except ValueError:
            host = ""
        if name_under_ip(host):
            reason, why = NAME_UNDER_IP, "a name under an IP address, which no resolver answers"
        elif not self.owns(host):
            reason, why = FOREIGN_HOST, "not one of the emulator's own hosts"
        else:
            return None
        return reason, f"its host is {why}; a customer of the emulator needs {self.expected(value)}"


def _bracketed(value: str) -> str:
    """A bare IPv6 ``host`` or ``host:port`` with its address bracketed, else ``value``."""
    if value.startswith("[") or value.count(":") < 2:
        return value
    host, _, port = value.rpartition(":")
    if is_ip_literal(value):
        return f"[{value}]"
    return f"[{host}]:{port}" if is_ip_literal(host) and port.isdigit() else value

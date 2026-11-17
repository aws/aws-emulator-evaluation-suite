"""Properties of the emulator endpoint: is it up, is it this machine, may TLS go unverified.

"Nothing was listening" is a bootstrap failure, not a fidelity measurement, and TLS verification
may only be disabled for a loopback host.
"""

import functools
import ipaddress
import json
import os
import re
from collections.abc import Iterable
from pathlib import Path
from urllib.parse import urlparse, urlsplit

import botocore
import botocore.session
from botocore.config import Config
from urllib3.exceptions import LocationParseError
from urllib3.util import parse_url

#: The error codes an emulator answers for a request it cannot route to an operation: an
#: unimplemented, unknown or ambiguous service, operation or query action. Matched
#: case-insensitively by both engines.
UNROUTABLE_ERROR_CODES = (
    "NotImplemented",
    "NotImplementedException",
    "UnknownService",
    "AmbiguousService",
    "UnknownOperation",
    "UnknownOperationException",
    "InvalidAction",
)


LOOPBACK_HOST_NAMES = frozenset({"localhost"})


@functools.cache
def partition_suffixes() -> tuple[str, ...]:
    """Every partition's DNS suffixes in botocore's ``partitions.json``."""
    data = json.loads((Path(botocore.__file__).parent / "data" / "partitions.json").read_text())
    outputs = [p["outputs"] for p in data["partitions"]]
    return tuple(dict.fromkeys(o[k] for o in outputs for k in ("dnsSuffix", "dualStackDnsSuffix")))


#: Apexes of the hosts AWS serves, matched on whole labels: every partition's service endpoints
#: (``api.aws`` is the only host some services have), then the data planes AWS publishes:
#: CloudFront distributions, Lambda function URLs, ECR Public, App Runner, SageMaker Studio, Chime
#: and CodePipeline webhooks, Elastic Beanstalk environments, Amplify Hosting, Cognito hosted
#: domains and IAM Identity Center portals.
_AWS_APEXES = (
    *partition_suffixes(),
    "cloudfront.net",
    "on.aws",
    "ecr.aws",
    "sagemaker.aws",
    "chime.aws",
    "webhooks.aws",
    "awsapprunner.com",
    "elasticbeanstalk.com",
    "amplifyapp.com",
    "amazoncognito.com",
    "awsapps.com",
)


def names_aws_host(url: str) -> bool:
    """True when the URL's host is one AWS serves, matched on whole DNS labels.

    A real AWS name in any partition or a published data plane; ``amazonaws.com.attacker.example``
    and ``notamazonaws.com`` do not match.
    """
    host = (urlparse(url).hostname or "").lower().rstrip(".")
    if not host or not all(host.split(".")):
        return False
    return any(host == apex or host.endswith(f".{apex}") for apex in _AWS_APEXES)


class EndpointRefused(ValueError):
    """An endpoint that is malformed, or that an emulator run may not reach."""


class RealAwsRefused(EndpointRefused):
    """The endpoint is an AWS host; this runner targets emulators only."""


def refuse_real_aws(endpoint: str) -> None:
    """Raise ``RealAwsRefused`` for an endpoint whose host is one AWS serves."""
    if names_aws_host(endpoint):
        raise RealAwsRefused(
            f"{endpoint!r} is an AWS endpoint; this runner runs fidelity tests against an "
            "emulator only"
        )


#: The private blocks: RFC 1918.
PRIVATE_NETWORKS = tuple(
    ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)

#: An endpoint's whole authority: a host name or IP literal and an optional port, nothing else.
_AUTHORITY_RE = re.compile(
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?|\[[0-9A-Fa-f:.]+\])(?::[0-9]{1,5})?"
)


#: A path escape that decodes to a space, a printable or a non-ASCII byte, never a control.
_PATH_ESCAPE_RE = re.compile(r"%(?:[2-6][0-9A-Fa-f]|7[0-9A-Ea-e]|[89A-Fa-f][0-9A-Fa-f])")

#: The schemes a published data-plane address is dialed with, and those of them without TLS.
DIALED_SCHEMES = ("http", "https", "ws", "wss", "rtmp", "rtmps")
_PLAIN_SCHEMES = ("http", "ws", "rtmp")


def validate_endpoint(
    endpoint: str, *, schemes: tuple[str, ...] = ("http", "https"), path: bool = False
) -> str:
    """``endpoint`` unchanged when every URL parser reads the same host from it, else raise.

    A scheme in ``schemes``; an authority with no userinfo, percent-encoding, backslash or
    whitespace and a port in 1..65535; no query or fragment, and no path unless ``path``. A path
    may hold ``@`` and ``%XX`` escapes of a space, printable or non-ASCII bytes (an npm scope).
    """
    if not isinstance(endpoint, str) or any(c.isspace() or c == "\\" for c in endpoint):
        raise EndpointRefused(f"endpoint {endpoint!r} has whitespace or a backslash")
    scheme, sep, rest = endpoint.partition("://")
    head = scheme + sep + re.split(r"[/?#]", rest, maxsplit=1)[0]
    if "@" in head or "%" in head:
        raise EndpointRefused(f"endpoint {endpoint!r} has userinfo or '%' before its path")
    if "%" in _PATH_ESCAPE_RE.sub("", endpoint[len(head) :]):
        raise EndpointRefused(f"endpoint {endpoint!r} has a '%' that is not a path escape")
    try:
        parts = urlsplit(endpoint)
    except ValueError as exc:
        raise EndpointRefused(f"endpoint {endpoint!r} is malformed: {exc}") from None
    if parts.scheme.lower() not in schemes or not _AUTHORITY_RE.fullmatch(parts.netloc):
        raise EndpointRefused(f"endpoint {endpoint!r} is not a {'/'.join(schemes)} URL with a host")
    if "?" in endpoint or "#" in endpoint or (not path and parts.path not in ("", "/")):
        raise EndpointRefused(f"endpoint {endpoint!r} has a path, query or fragment")
    try:
        port = parts.port
        other = (parse_url(endpoint).host or "").strip("[]").lower()
    except (ValueError, LocationParseError) as exc:
        raise EndpointRefused(f"endpoint {endpoint!r} is malformed: {exc}") from None
    if port is not None and not 0 < port < 65536:
        raise EndpointRefused(f"endpoint {endpoint!r} has a port outside 1..65535")
    if other != (parts.hostname or "").lower():
        raise EndpointRefused(f"endpoint {endpoint!r} names two different hosts to two parsers")
    return endpoint


def is_strict_loopback_host(host: str) -> bool:
    """``localhost`` exactly, or a loopback IP literal: names that never leave this machine."""
    host = host.lower().strip("[]")
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def require_loopback(endpoint: str) -> None:
    """Raise ``EndpointRefused`` unless ``endpoint`` is a well-formed URL on this machine.

    Its host is ``localhost`` or a loopback literal (:func:`validate_endpoint` first): an IP
    literal, a private address or an alias can reach AWS as well as a name under its domain can.
    An AWS host raises ``RealAwsRefused``.
    """
    refuse_real_aws(endpoint)
    validate_endpoint(endpoint)
    if not is_strict_loopback_host(urlsplit(endpoint).hostname or ""):
        raise EndpointRefused(
            f"{endpoint!r} is not on this machine; this runner runs fidelity tests against a "
            "loopback emulator only (127.0.0.0/8, ::1 or localhost)"
        )


def is_loopback_host(host: str) -> bool:
    """True when ``host`` names this machine.

    ``localhost``, a ``*.localhost`` name (RFC 6761), a parsed loopback address, or a name under
    one (``bkt.s3.us-west-2.127.0.0.1``). Parsed, never prefix-matched: ``127.example.com`` is a
    legal hostname anywhere on the internet.
    """
    host = host.lower()
    if host in LOOPBACK_HOST_NAMES or host.endswith(".localhost"):
        return True
    return _loopback_address(host) is not None or loopback_suffix(host) is not None


def loopback_suffix(host: str) -> str | None:
    """The loopback IPv4 address ``host`` is a name under, or ``None``."""
    labels = host.split(".")
    return _loopback_address(".".join(labels[-4:])) if len(labels) > 4 else None


def private_suffix(host: str) -> str | None:
    """The private IPv4 address ``host`` is a name under (``lb.elb.10.250.3.2``), or ``None``.

    An emulator that advertises its private container address publishes data-plane names under
    it, as it publishes them under a loopback address; DNS never resolves such a name, and it is
    served at that address. Private means RFC 1918 (``PRIVATE_NETWORKS``).
    """
    labels = host.lower().rstrip(".").split(".")
    if len(labels) <= 4:
        return None
    try:
        ip = ipaddress.ip_address(".".join(labels[-4:]))
    except ValueError:
        return None
    return str(ip) if any(ip in n for n in PRIVATE_NETWORKS) else None


def _loopback_address(text: str) -> str | None:
    try:
        return text if ipaddress.ip_address(text).is_loopback else None
    except ValueError:
        return None


def is_loopback_endpoint(endpoint: str) -> bool:
    """True when ``endpoint``'s host is this machine (:func:`is_loopback_host`)."""
    try:
        host = urlparse(endpoint).hostname or ""
    except ValueError:
        return False
    return is_loopback_host(host)


class NonLocalHostRefused(BaseException):
    """A test was about to reach a host that is neither this machine, a private address, nor the
    emulator endpoint's host.

    A ``BaseException``, so a test's ``except Exception`` cannot turn the refusal into a retry, a
    timeout or a pass: the runner grades it as the ``non_local_host`` runner fault.
    """


def _is_private_address(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return ip.version == 4 and any(ip in n for n in PRIVATE_NETWORKS)


def is_local_host(host: str, endpoint: str, own_hosts: Iterable[str] = ()) -> bool:
    """Whether a test may reach ``host`` on a run against ``endpoint``.

    This machine (:func:`is_loopback_host`), a private IPv4 address or a name under one
    (:func:`private_suffix`), the endpoint's own host, or a documented own host (``own_hosts``,
    each exact or ``*.<suffix>``).
    """
    host = (host or "").lower().rstrip(".").strip("[]")
    own = (urlsplit(endpoint).hostname or "").lower()
    return bool(host) and (
        host == own
        or is_loopback_host(host)
        or _is_private_address(host)
        or private_suffix(host) is not None
        or any(host == e or (e.startswith("*.") and host.endswith(e[1:])) for e in own_hosts)
    )


def require_local_host(host: str, endpoint: str, own_hosts: Iterable[str] = ()) -> None:
    """Raise :class:`NonLocalHostRefused` unless :func:`is_local_host`."""
    if not is_local_host(host, endpoint, own_hosts):
        raise NonLocalHostRefused(
            f"refusing to reach {host!r}: a run against {endpoint!r} reaches only this machine, "
            "private addresses and the emulator's own host"
        )


def require_local_url(url: str, endpoint: str, own_hosts: Iterable[str] = ()) -> None:
    """:func:`require_local_host` for ``url``'s host."""
    try:
        host = urlsplit(url).hostname or ""
    except ValueError:
        host = ""
    require_local_host(host, endpoint, own_hosts)


def assert_tls_verification_permitted(endpoint: str, verify_ssl: bool | str) -> None:
    """Refuse disabled TLS verification for a TLS endpoint that is not loopback.

    ``verify_ssl`` is requests' ``verify``: a non-empty str is a CA bundle, allowed anywhere. With
    it disabled, the URL first passes :func:`validate_endpoint`; ``http``, ``ws`` and ``rtmp``
    carry no certificate to verify.
    """
    if verify_ssl:
        return
    url = endpoint.split("?", 1)[0].split("#", 1)[0] if isinstance(endpoint, str) else endpoint
    validate_endpoint(url, schemes=DIALED_SCHEMES, path=True)
    if urlsplit(endpoint).scheme.lower() in _PLAIN_SCHEMES:
        return
    if not is_loopback_endpoint(endpoint):
        raise EndpointRefused(
            f"verify_ssl={verify_ssl!r} disables certificate verification, which is only permitted "
            f"for a loopback emulator host (127.0.0.0/8, ::1, localhost, *.localhost or a name "
            f"under a loopback address); refusing for endpoint {endpoint!r}"
        )


@functools.cache
def _signing_name(service: str) -> str:
    return botocore.session.get_session().get_service_model(service).signing_name


def bearer_free_config(service: str) -> Config | None:
    """SigV4 for a service whose ``AWS_BEARER_TOKEN_<SIGNING NAME>`` is set, else ``None``.

    botocore signs such a service with that bearer token whenever it is set; an emulator gets
    SigV4 with its keys instead, so no token in the environment ever reaches it.
    """
    env = "AWS_BEARER_TOKEN_" + _signing_name(service).upper().replace("-", "_")
    return Config(auth_scheme_preference="sigv4") if os.environ.get(env) else None

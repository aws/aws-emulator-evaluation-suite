"""``Context``: what a check's ``run(ctx)`` receives, wired to one emulator.

A check gets clients wired to the emulator (``ctx.client``), teardown registration
(``ctx.on_cleanup``), ``ctx.region``, ``ctx.unique_name``, ``ctx.subprocess_env`` for CLI and
IaC tools, ``ctx.network`` for a default-VPC-shaped network, ``ctx.ingress_cidrs`` for the
source ranges a port opened to the runner admits, the address helpers for every URL
or host a test dials, and ``ctx.http_verify`` for a test's own HTTP calls. Everything
service-specific stays in the test.

A URL or host the emulator published is used as published, as a customer of the emulator uses it;
one no such customer can use (``published.OwnHosts.problem``) fails the test with
``PublishedUrlRejected`` before anything is dialed. Every URL and host the context hands a test,
or builds a client for, is also on this machine, a private address, or the emulator's own host
(``target.require_local_host``); anything else raises ``NonLocalHostRefused``. Tools and
containers a test starts are not limited this way.
"""

import hashlib
import os
import re
import shutil
import string
import tempfile
import threading
import time
import uuid
from collections.abc import Callable, Iterable
from typing import Any
from urllib.parse import quote, urlsplit

import boto3
from botocore.config import Config

from fidelity_tests_runner import isolate
from fidelity_tests_runner.harness import DEFAULT_REGION
from fidelity_tests_runner.network import Network, Networks
from fidelity_tests_runner.published import (
    NOT_IDENTIFIED,
    OwnHosts,
    PublishedUrlRejected,
    host_pattern,
    own_host_entries,
    under_partition,
    value_class,
)
from fidelity_tests_runner.target import (
    EndpointRefused,
    NonLocalHostRefused,
    assert_tls_verification_permitted,
    bearer_free_config,
    fit_to_emulator,
    is_loopback_endpoint,
    refuse_real_aws,
    require_local_host,
    require_local_url,
    require_loopback,
    validate_endpoint,
)
from fidelity_tests_runner.trust import emulator_verify, union_bundle

#: botocore's own switch: a client with no explicit ``inject_host_prefix`` reads it at creation.
NO_HOST_PREFIX_ENV = "AWS_DISABLE_HOST_PREFIX_INJECTION"

#: A URL scheme at the start of a value (RFC 3986 section 3.1), as opposed to `://` anywhere in it.
_SCHEME_RE = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://")
_WEBSOCKET_SCHEME = {"http": "ws", "https": "wss"}
_PLAIN = {"ws": "http", "wss": "https"}
#: The schemes a published data-plane URL is dialed with.
_DIALED = ("http", "https", "ws", "wss")
#: The family a published URL's scheme is graded by: ``https`` is ``http``, ``wss`` is ``ws``.
_SCHEME_FAMILY = {"https": "http", "wss": "ws", "rediss": "redis", "postgres": "postgresql"}
#: What a bare host never holds: a scheme or port (`:`), a path, a query, a fragment, userinfo,
#: or whitespace.
_NOT_A_BARE_HOST = frozenset(":/?#@ \t\r\n")

#: Wide enough that a concurrency check's threads race on the target, not on the client's pool.
MAX_POOL_CONNECTIONS = 128

#: The keys a check signs with when the emulator runs without ``--auth on``.
FIXED_CREDS = {"aws_access_key_id": "test", "aws_secret_access_key": "test"}

#: What every run gets from ``ctx.ingress_cidrs()``: the emulator sees the runner on loopback.
EMULATOR_INGRESS = ("127.0.0.1/32",)

#: Where a run reads the emulator's API Gateway invoke-URL template.
EXECUTE_API_URL_ENV = "FIDELITY_TESTS_EXECUTE_API_URL_TEMPLATE"
#: The placeholders an invoke-URL template may name.
_EXECUTE_API_FIELDS = frozenset({"api_id", "stage", "region", "endpoint", "port"})
_STAGE_SEGMENT_RE = re.compile(r"/\{stage\}(?=[/?#]|$)")
#: An API id or stage name as API Gateway mints and accepts them (``$default`` included): a bare
#: token that cannot add a host, path, query or fragment to the URL it is placed in.
_API_TOKEN_RE = re.compile(r"[A-Za-z0-9_$-]{1,128}")
#: An S3 bucket name and an AWS region: the only values an S3 website URL template is filled with.
_BUCKET_RE = re.compile(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]")
_REGION_RE = re.compile(r"[a-z]{2}(?:-[a-z]+)+-\d{1,2}")


def _config_key(config: Config | None) -> str:
    """A cache key from a ``Config``'s explicit settings, so equal configs share a client."""
    if config is None:
        return ""
    opts = getattr(config, "_user_provided_options", None)
    if opts is None:
        return repr(id(config))
    return repr(sorted((k, repr(v)) for k, v in opts.items()))


def _merge_config(base: Config, override: Config) -> Config:
    """``base.merge(override)``, keeping the base retry ``mode`` when only attempts are overridden.

    ``Config.merge`` replaces the whole ``retries`` dict, which would silently fall back to
    ``legacy`` mode and start retrying the 4xx errors checks assert on.
    """
    opts = getattr(override, "_user_provided_options", None)
    if opts is None:
        return override
    provided = dict(opts)
    base_retries = getattr(base, "retries", None)
    if isinstance(provided.get("retries"), dict) and isinstance(base_retries, dict):
        merged = {"mode": base_retries["mode"]} if base_retries.get("mode") else {}
        provided["retries"] = {**merged, **provided["retries"]}
    return base.merge(Config(**provided))


#: Where a run reads the emulator's S3 website endpoint template.
S3_WEBSITE_URL_ENV = "FIDELITY_TESTS_S3_WEBSITE_URL"
#: The placeholders a website endpoint template may name: ``host`` and ``port`` are the endpoint's.
_S3_WEBSITE_FIELDS = frozenset({"bucket", "region", "host", "port"})


class CapabilityNotOffered(AssertionError):
    """The emulator offers no equivalent of an AWS data plane a test needs: the test fails."""


def s3_website_template(template: str | None) -> str | None:
    """``template``, else ``S3_WEBSITE_URL_ENV``, checked as a website endpoint template, or None.

    It is an absolute ``http(s)`` URL naming ``{bucket}`` and only the ``_S3_WEBSITE_FIELDS``.
    """
    return _url_template(
        template, S3_WEBSITE_URL_ENV, "website endpoint", _S3_WEBSITE_FIELDS, ("bucket",)
    )


def run_own_hosts(
    endpoint: str, own_hosts: Iterable[str] | str | None, *templates: str | None
) -> OwnHosts:
    """The own hosts of a run on ``endpoint``: the documented ones and its URL templates' hosts.

    A template's host is filled with the endpoint's ``{host}`` and ``{port}``; leading labels that
    hold another placeholder make the rest a ``*.<suffix>``
    (``{bucket}.s3-website-{region}.localhost`` names ``*.localhost``), and a template on
    ``{endpoint}`` names only the endpoint. A host that can be no own host (``own_host_entries``)
    is the run's input error, naming its template.
    """
    entries = list(own_host_entries(own_hosts))
    for template in filter(None, templates):
        if "{endpoint}" in template:
            continue
        host = _template_host(endpoint, template)
        try:
            entries += own_host_entries([host])
        except ValueError as exc:
            raise ValueError(f"URL template {template!r} names host {host!r}: {exc}") from None
    return OwnHosts.of_entries(endpoint, entries)  # checked above: no second set of lookups


def _template_host(endpoint: str, template: str) -> str:
    """The own host entry ``template``'s host is on ``endpoint`` (``run_own_hosts``)."""
    filled = template.replace("{host}", OwnHosts.of(endpoint, ()).bracketed_host)
    labels = (urlsplit(filled.replace("{port}", "1")).hostname or "").split(".")
    fixed = len(labels)
    while fixed and "{" not in labels[fixed - 1]:
        fixed -= 1
    rest = ".".join(labels[fixed:])
    if fixed and not rest:
        raise ValueError(f"URL template {template!r} names no fixed host label")
    return f"*.{rest}" if fixed else rest


def execute_api_template(template: str | None) -> str | None:
    """``template``, else ``EXECUTE_API_URL_ENV``, checked as an invoke-URL template, or ``None``.

    It is an absolute ``http(s)`` URL naming ``{api_id}``, only the ``_EXECUTE_API_FIELDS``
    placeholders, and ``{stage}`` only as a whole path segment, which a ``$default`` stage drops.
    """
    template = _url_template(
        template, EXECUTE_API_URL_ENV, "invoke-URL", _EXECUTE_API_FIELDS, ("api_id",)
    )
    if template and template.count("{stage}") != len(_STAGE_SEGMENT_RE.findall(template)):
        raise ValueError(f"invoke-URL template {template!r} names {{stage}} outside a path segment")
    return template


def _url_template(
    template: str | None, env: str, kind: str, allowed: frozenset[str], named: tuple[str, ...]
) -> str | None:
    """``template``, else ``env``'s value: an ``http(s)`` URL template naming one of ``named``."""
    if template is None:
        template = os.environ.get(env)
    if not template or not template.strip():
        return None
    template = template.strip()
    try:
        fields = {f for _, f, _, _ in string.Formatter().parse(template) if f is not None}
    except ValueError as exc:
        raise ValueError(f"{kind} template {template!r} is malformed: {exc}") from None
    unknown = fields - allowed
    if unknown or not fields & set(named):
        raise ValueError(
            f"{kind} template {template!r} must name {' or '.join(f'{{{n}}}' for n in named)} "
            f"and only {sorted(allowed)}; it names {sorted(fields)}"
        )
    values = {**dict.fromkeys(allowed, "a"), "endpoint": "http://127.0.0.1:1", "port": 1}
    sample = template.format(**values)
    if urlsplit(sample).scheme.lower() not in _WEBSOCKET_SCHEME:
        raise ValueError(f"{kind} template {template!r} is not an http(s) URL")
    try:
        validate_endpoint(sample.split("?", 1)[0], path=True)
    except ValueError as exc:
        raise ValueError(f"{kind} template {template!r} is not a usable URL: {exc}") from None
    return template


#: The longest base a tool's temporary directory may sit under. A unix socket path holds at most
#: 103 bytes and its terminator on macOS (107 on Linux), and a tool opens its socket below the
#: test's own temporary directory: Terraform's provider plugins at
#: ``<base>/fidelity-tests-check-<8>/plugin<10>``, 47 bytes past the base. A longer base makes the
#: socket path too long, and the plugin exits before its handshake; 51 leaves 5 bytes of margin.
SOCKET_SAFE_BASE_MAX = 51


def socket_safe_tmp_base() -> str | None:
    """The base for a test's temporary directory: ``$TMPDIR``, or ``/tmp`` when it is too long."""
    base = tempfile.gettempdir()
    if len(base) <= SOCKET_SAFE_BASE_MAX or not os.access("/tmp", os.W_OK | os.X_OK):
        return None
    return "/tmp"


#: A Node preload pointing each AWS SDK for JavaScript v2 copy a tool ``require``s by package name
#: (that SDK reads no endpoint from the environment) at ``AWS_ENDPOINT_URL``, host prefix off, S3
#: path-style for an IP. It never fails a process: a value it cannot use leaves the SDK as it is.
_JS_SDK_PRELOAD = """\
const Module = require("module");
const endpoint = process.env.AWS_ENDPOINT_URL;
const configured = new WeakSet();
const load = Module._load;
function settings() {
  const host = new URL(endpoint).hostname.replace(/^\\[|\\]$/g, "");
  const s = { endpoint, hostPrefixEnabled: false };
  if (require("net").isIP(host)) s.s3ForcePathStyle = true;
  return s;
}
Module._load = function (request, parent, isMain) {
  const exported = load.apply(this, arguments);
  if (endpoint && /^aws-sdk(\\/|$)/.test(request)) {
    try {
      const sdk = load.call(this, "aws-sdk/global", parent, false);
      if (!configured.has(sdk)) {
        configured.add(sdk);
        sdk.config.update(settings());
      }
    } catch (e) {}
  }
  return exported;
};
"""
#: Its file name in the context's private ``TMPDIR``.
JS_SDK_PRELOAD_NAME = "aws-sdk-endpoint.js"


def _node_quoted(text: str) -> str:
    r"""``text`` escaped for a double-quoted ``NODE_OPTIONS`` value (``\`` and ``"``)."""
    return text.replace("\\", "\\\\").replace('"', '\\"')


def _secret_key(creds: dict[str, str]) -> str:
    """A cache key for a key pair and token that never holds them."""
    joined = "\0".join(
        creds.get(k) or ""
        for k in ("aws_access_key_id", "aws_secret_access_key", "aws_session_token")
    )
    return hashlib.sha256(joined.encode()).hexdigest() if creds else ""


class Context:
    """The per-check runtime: clients, teardown and identity for one emulator.

    ``creds`` (``aws_access_key_id``, ``aws_secret_access_key``) signs every client; ``verify_ssl``
    may be a CA bundle path.
    """

    def __init__(
        self,
        endpoint: str,
        region: str = DEFAULT_REGION,
        *,
        verify_ssl: bool | str = True,
        creds: dict[str, str],
        execute_api_url: str | None = None,
        s3_website_url: str | None = None,
        own_hosts: Iterable[str] | str | None = None,
    ) -> None:
        isolate.refuse_optimized()
        require_loopback(endpoint)
        assert_tls_verification_permitted(endpoint, verify_ssl)
        self._endpoint = endpoint
        self._region = region
        # An https loopback emulator is verified against the CA it published.
        self._verify_ssl = emulator_verify(endpoint, verify_ssl)
        self._caller_verify = verify_ssl
        self._http_verify: bool | str = self._verify_ssl
        self._trust_lock = threading.Lock()
        self._creds = dict(creds)
        self._account: str | None = None
        # Standard mode retries throttling and transient faults, never the 4xx a check asserts on;
        # few attempts, so a dead endpoint errors as NOT-UP inside the check budget.
        self._config = Config(
            retries={"max_attempts": 3, "mode": "standard"},
            inject_host_prefix=False,
            connect_timeout=10,
            max_pool_connections=MAX_POOL_CONNECTIONS,
            # A client never takes a proxy from the environment.
            proxies={},
        )
        self._clients: dict[str, Any] = {}
        self._clients_lock = threading.Lock()
        self._cleanups: list[Callable[[], None]] = []
        self._execute_api_url = execute_api_template(execute_api_url)
        self._s3_website_url = s3_website_template(s3_website_url)
        #: The hosts a customer of the emulator reaches it at.
        self._own = run_own_hosts(endpoint, own_hosts, self._execute_api_url, self._s3_website_url)
        self._published_url_violations: list[dict[str, str]] = []
        if self._execute_api_url:
            # A template's host is fixed when it is not {endpoint}: check it once, up front. A
            # refusal here is the run's input error, never a test's runner fault.
            try:
                require_local_url(self._format_api_url("a", "s"), endpoint, self._own.entries)
            except NonLocalHostRefused as exc:
                raise EndpointRefused(str(exc)) from None
        self._networks: Networks | None = None
        self._network_lock = threading.Lock()
        self._deadline: float | None = None
        self._thread_deadline = threading.local()  # a teardown thread's own budget
        self._tmpdir: str | None = None

    @property
    def region(self) -> str:
        return self._region

    @property
    def endpoint(self) -> str:
        """The URL a customer of the emulator sets as ``endpoint_url``."""
        return self._own.endpoint

    def service_url(self, aws_url: str) -> str:
        """A service endpoint URL the test names: the emulator's ``endpoint`` for ``aws_url``.

        The customer's endpoint override: ``aws_url`` is ``https://`` or ``wss://``, a real AWS
        host and an optional port with nothing after it; ``wss`` takes the endpoint's family
        (``ws`` for ``http``).
        """
        parts = urlsplit(aws_url)
        if (
            parts.scheme not in ("https", "wss")
            or not under_partition(parts.hostname or "")
            or parts.path not in ("", "/")
            or parts.query
            or parts.fragment
            or "@" in parts.netloc
        ):
            raise ValueError(f"not an AWS service endpoint URL: {aws_url!r}")
        if parts.scheme == "wss":
            return f"{_WEBSOCKET_SCHEME[self._own.scheme]}://{self._own.netloc}"
        return self._own.endpoint

    def service_host(self, aws_host: str, port: int) -> tuple[str, int]:
        """A protocol's contact point the test names itself, as ``endpoint_host`` returns one.

        For ``(aws_host, port)`` on AWS (``cassandra.us-west-2.amazonaws.com``, 9142), the
        emulator endpoint's host at the same port, where it serves that protocol.
        """
        if (
            not isinstance(aws_host, str)
            or any(c in aws_host for c in _NOT_A_BARE_HOST)
            or not under_partition(aws_host)
        ):
            raise ValueError(f"not an AWS service host: {aws_host!r}")
        if isinstance(port, bool) or not isinstance(port, int) or not 0 < port < 65536:
            raise ValueError(f"a port is not an integer in 1..65535: {port!r}")
        return self._own.host, port

    def s3_object_url(self, aws_url: str, bucket: str, key: str) -> str:
        """An unsigned S3 object URL for the test's ``aws_url``: path-style at the endpoint.

        ``<endpoint>/<bucket>/<key>``, the key percent-encoded (``/`` and ``~`` kept), as a
        customer addresses S3 at the endpoint.
        """
        parts = urlsplit(aws_url)
        if parts.scheme != "https" or not under_partition(parts.hostname or ""):
            raise ValueError(f"not an AWS https URL: {aws_url!r}")
        return f"{self._own.endpoint}/{bucket}/{quote(key, safe='/~')}"

    @property
    def published_url_violations(self) -> list[dict[str, str]]:
        """``{field, reason, value_class, host}`` per published value the test could not use."""
        return list(self._published_url_violations)

    def _violation(self, field: str, value: str, reason: str) -> None:
        entry = {
            "field": field,
            "reason": reason,
            "value_class": value_class(value),
            "host": host_pattern(value),
        }
        if entry not in self._published_url_violations:
            self._published_url_violations.append(entry)

    def time_left(self) -> float | None:
        """Seconds until the runner stops this check, or None outside a runner's budget.

        A check whose own wait could outlast it bounds the wait by this, so it fails with its own
        message instead of the runner's timeout.
        """
        deadline = getattr(self._thread_deadline, "at", None)
        if deadline is None:
            deadline = self._deadline
        if deadline is None:
            return None
        return max(0.0, deadline - time.monotonic())

    def start_deadline(self, budget_s: float, *, this_thread: bool = False) -> None:
        """Start the budget ``time_left`` counts down: the test's, as it starts.

        With ``this_thread`` only the calling thread sees it: the runner's teardown thread.
        """
        at = time.monotonic() + budget_s
        if this_thread:
            self._thread_deadline.at = at
        else:
            self._deadline = at

    @property
    def http_verify(self) -> bool | str:
        """``verify`` for a check's own HTTP call to the target: a bool or a CA bundle path."""
        return self._http_verify

    @property
    def account(self) -> str:
        """The emulator's account, as its STS answers."""
        if self._account is None:
            self._account = self.client("sts").get_caller_identity()["Account"]
        return self._account

    def api_url(self, api_id: str, stage: str, *, websocket: bool = False) -> str:
        """The base URL of an API Gateway stage: REST, HTTP or WebSocket API (``websocket=True``).

        Also the ``endpoint_url`` of the stage's ``apigatewaymanagementapi`` client: the
        emulator's invoke-URL template, and with no template ``CapabilityNotOffered``, the
        emulator's failure. A ``$default`` stage has no path in a template. ``api_id`` and
        ``stage`` are bare tokens, and the URL is checked like any data-plane URL.
        """
        for what, value in (("api_id", api_id), ("stage", stage)):
            if not isinstance(value, str) or not _API_TOKEN_RE.fullmatch(value):
                raise ValueError(f"{what} is not an API Gateway id or stage name: {value!r}")
        if not self._execute_api_url:
            raise CapabilityNotOffered(
                "the emulator offers no API Gateway invoke URL (the run names no invoke-URL "
                f"template: --execute-api-url, {EXECUTE_API_URL_ENV})"
            )
        url = self._format_api_url(api_id, stage)
        assert_tls_verification_permitted(url, self._verify_ssl)
        self._require_local_url(url, ("http", "https"))
        if not websocket:
            return url
        scheme, sep, rest = url.partition("://")
        return f"{_WEBSOCKET_SCHEME.get(scheme.lower(), scheme)}{sep}{rest}"

    def _format_api_url(self, api_id: str, stage: str) -> str:
        """The stage URL from the run's invoke-URL template."""
        template = self._execute_api_url or ""
        if stage == "$default":
            template = _STAGE_SEGMENT_RE.sub("", template)
        return template.format(
            api_id=api_id,
            stage=stage,
            region=self._region,
            endpoint=self._endpoint.rstrip("/"),
            port=self._own.port,
        ).rstrip("/")

    def s3_website_urls(
        self, aws_urls: list[str], bucket: str, *, region: str | None = None
    ) -> list[str]:
        """The URLs of a bucket's S3 website endpoint, for the test's ``aws_urls`` on AWS.

        The URL the emulator's website endpoint template gives for ``bucket`` and ``region`` (the
        run's); with no template the emulator offers no website endpoint:
        ``CapabilityNotOffered``, the emulator's failure. ``bucket`` and ``region`` are a bucket
        name and a region, and the URL is checked like any data-plane URL.
        """
        del aws_urls  # AWS's form, which the emulator's template replaces
        if not self._s3_website_url:
            raise CapabilityNotOffered(
                "the emulator offers no S3 website endpoint (the run names no website endpoint "
                f"template: --s3-website-url, {S3_WEBSITE_URL_ENV})"
            )
        region = region or self._region
        if not isinstance(bucket, str) or not _BUCKET_RE.fullmatch(bucket):
            raise ValueError(f"bucket is not an S3 bucket name: {bucket!r}")
        if not isinstance(region, str) or not _REGION_RE.fullmatch(region):
            raise ValueError(f"region is not an AWS region: {region!r}")
        url = self._s3_website_url.format(
            bucket=bucket,
            region=region,
            host=self._own.bracketed_host,
            port=self._own.port,
        ).rstrip("/")
        assert_tls_verification_permitted(url, self._verify_ssl)
        self._require_local_url(url, ("http", "https"))
        return [url]

    def endpoint_url(
        self, published: str, *, websocket: bool = False, aws_port: int | None = None
    ) -> str:
        """The URL of a data-plane endpoint the emulator published in a control-plane response.

        A bare host takes the emulator endpoint's scheme; a value with a scheme keeps it,
        ``websocket`` mapping http(s) to ws(s).
        """
        return self.endpoint_route(published, websocket=websocket, aws_port=aws_port)[0]

    def endpoint_route(
        self, published: str, *, websocket: bool = False, aws_port: int | None = None
    ) -> tuple[str, dict[str, str]]:
        """``endpoint_url(published)`` and the headers a test sends with it, always none.

        The URL is used as published, and one no customer of the emulator can use
        (``OwnHosts.problem``) raises ``PublishedUrlRejected``. ``aws_port`` is the port AWS serves
        a bare host on (IoT's 8443); an emulator's bare host keeps its own.
        """
        del aws_port  # AWS's port; an emulator's bare host is served on its own
        if not published or published != published.strip():
            raise ValueError(f"a published data-plane endpoint is empty or padded: {published!r}")
        if _SCHEME_RE.match(published):
            url = published
        else:
            secure = self._own.scheme == "https"
            url = f"{'https' if secure else 'http'}://{published}"
        scheme, sep, rest = url.partition("://")
        if websocket and scheme.lower() in _WEBSOCKET_SCHEME:
            url = f"{_WEBSOCKET_SCHEME[scheme.lower()]}{sep}{rest}"
        assert_tls_verification_permitted(url, self._verify_ssl)
        target = self._published_target(url, "endpoint_url")
        self._trust_listener(target)
        return target, {}

    def _published_target(self, value: str, field: str) -> str:
        """``value``, unless no customer of the emulator can use it (``OwnHosts.problem``).

        A rejected value is never dialed; a usable one must also be local
        (``target.require_local_host``).
        """
        if "://" in value:  # one host for every parser before any is graded
            validate_endpoint(value.split("?", 1)[0].split("#", 1)[0], schemes=_DIALED, path=True)
        if problem := self._own.problem(value):
            self._violation(field, value, problem[0])
            message = f"{field} was given {value} (published by the emulator or built by the test)"
            raise PublishedUrlRejected(f"{message}: {problem[1]}", problem[0], value_class(value))
        host = urlsplit(value if "://" in value else f"tcp://{value}").hostname or ""
        require_local_host(host, self._endpoint, self._own.entries)
        return value

    def _require_local_url(self, url: str, schemes: tuple[str, ...]) -> None:
        """Refuse a URL whose host parsers disagree on, or whose host is not local."""
        validate_endpoint(url.split("?", 1)[0].split("#", 1)[0], schemes=schemes, path=True)
        require_local_url(url, self._endpoint, self._own.entries)

    def _trust_listener(self, target: str) -> None:
        """Trust in ``http_verify`` what verifies another https loopback listener of the emulator.

        An emulator may serve a data plane on its own listener; that listener is verified against
        the CA the emulator published for its endpoint's port.
        """
        if isinstance(self._caller_verify, str) and self._caller_verify:
            return
        parts = urlsplit(target)
        own = urlsplit(self._endpoint)
        if parts.scheme not in ("https", "wss") or not is_loopback_endpoint(target):
            return
        if (parts.hostname, parts.port) == (own.hostname, own.port):
            return
        verify = emulator_verify(
            parts._replace(scheme="https").geturl(), self._caller_verify, ca_port=own.port or 443
        )
        if isinstance(verify, str) and verify:
            with self._trust_lock:
                self._http_verify = union_bundle(self._http_verify, verify)

    def endpoint_host(self, published_host: str, port: int) -> tuple[str, int]:
        """Where a test's own driver connects to a database protocol the emulator serves.

        The published host and port unchanged; a published ``localhost:PORT`` or
        ``127.0.0.1:PORT`` names that host and port, and one no customer of the emulator can use
        raises ``PublishedUrlRejected``, as ``endpoint_url`` does.
        """
        if isinstance(published_host, str) and published_host.count(":") == 1:
            host, _, published_port = published_host.partition(":")
            if host in ("localhost", "127.0.0.1") and published_port.isdigit():
                published_host, port = host, int(published_port)
        if (
            not isinstance(published_host, str)
            or not published_host
            or published_host != published_host.strip()
            or any(c in published_host for c in _NOT_A_BARE_HOST)
        ):
            raise ValueError(f"a published database host is not a bare host: {published_host!r}")
        if isinstance(port, bool) or not isinstance(port, int) or not 0 < port < 65536:
            raise ValueError(f"a database port is not an integer in 1..65535: {port!r}")
        self._published_target(f"{published_host}:{port}", "endpoint_host")
        return published_host, port

    def published_url_mismatch(
        self,
        url: str,
        *,
        labels: tuple[str, ...] = (),
        path: str | None = None,
        websocket: bool = False,
    ) -> str | None:
        """Why a data-plane URL the emulator published is wrong, or ``None`` when it is right.

        A customer of the emulator can use it (``OwnHosts.problem``), its scheme is of the
        ``websocket`` family, and ``path`` matches a run of its whole path segments anywhere in the
        path. ``labels`` (AWS's host form) are not graded.
        """
        del labels  # AWS's host form; an emulator's own host need not carry it
        parts = urlsplit(url) if isinstance(url, str) else None
        if not parts or not parts.scheme or not parts.hostname:
            return f"the published data-plane endpoint is not a URL with a host: {url!r}"
        want = "ws" if websocket else "http"
        scheme = parts.scheme.lower()
        if _SCHEME_FAMILY.get(scheme, scheme) != want:
            return f"the published endpoint {url!r} is not {want}(s)"
        if problem := self._own.problem(url):
            self._violation("published_url_mismatch", url, problem[0])
            return f"the emulator published {url}: {problem[1]}"
        segments = parts.path.split("/")[1:]
        runs = {
            "/" + "/".join(segments[a:b])
            for a in range(len(segments) + 1)
            for b in range(a, len(segments) + 1)
        }
        if path is not None and not any(re.fullmatch(path, run) for run in runs):
            self._violation("published_url_mismatch", url, NOT_IDENTIFIED)
            return (
                f"the published endpoint's path {parts.path!r} has no run of whole segments "
                f"matching {path!r}"
            )
        return None

    def stage_url(self, api_endpoint: str, stage: str, *, management: bool = False) -> str:
        """An API Gateway v2 stage's URL from the API's published ``ApiEndpoint``.

        ``endpoint_url(api_endpoint)`` plus ``/{stage}``, none for ``$default``; with
        ``management``, a WebSocket API's ``@connections`` endpoint (``wss`` as ``https``, ``ws``
        as ``http``) for its ``apigatewaymanagementapi`` client.
        """
        url = self.endpoint_url(api_endpoint).rstrip("/")
        if management:
            scheme, sep, rest = url.partition("://")
            url = f"{_PLAIN.get(scheme.lower(), scheme)}{sep}{rest}"
        return url if stage == "$default" else f"{url}/{stage}"

    def rest_api_url(self, api_id: str, stage: str) -> str:
        """The invoke URL of an API Gateway REST API stage: ``api_url(api_id, stage)``."""
        return self.api_url(api_id, stage)

    def network(self, region: str | None = None) -> Network:
        """This check's network in ``region`` (its own), shaped like a default VPC.

        A check may add its own tagged, uniquely named resources inside it and deletes them in its
        teardown; it never changes a resource of the network. It is deleted with
        the check's teardowns.
        """
        region = region or self._region
        with self._network_lock:
            if self._networks is None:
                self._networks = Networks()
                self.on_cleanup(lambda networks=self._networks: _raise_any(networks.teardown()))
            networks = self._networks
        return networks.get(region, lambda: self.client("ec2", region=region))

    def ingress_cidrs(self, region: str | None = None) -> list[str]:
        """The IPv4 CIDRs a port this check opens to the runner admits: the loopback ``/32``."""
        return list(EMULATOR_INGRESS)

    def account_email(self) -> str:
        """A root email address for an account this test creates (``CreateAccount``'s ``Email``).

        Each call returns a fresh ``@example.com`` address, so a test that creates two accounts
        calls it twice.
        """
        return f"{self.unique_name('sim2real-account-')}@example.com"

    def unique_name(self, prefix: str = "sim2real-") -> str:
        return f"{prefix}{uuid.uuid4().hex[:12]}"

    def client(
        self,
        service: str,
        *,
        endpoint_url: str | None = None,
        region: str | None = None,
        config: Config | None = None,
        creds: dict[str, str] | None = None,
    ) -> Any:
        """A cached boto3 client for ``service`` wired to the emulator.

        ``endpoint_url`` names a runtime-discovered endpoint or emulator sub-endpoint; ``region``
        pins another region; ``config`` is merged over the runner's; ``creds`` signs as another
        identity against the same emulator. Clients are cached per distinct combination.
        """
        if creds is not None and not creds.get("aws_access_key_id"):
            raise ValueError("a creds override must carry a non-empty aws_access_key_id")
        key = "|".join(
            (
                service,
                endpoint_url or "",
                region or "",
                _config_key(config),
                _secret_key(creds or {}),
            )
        )
        with self._clients_lock:
            if key not in self._clients:
                self._clients[key] = self._build_client(
                    service, endpoint_url, region, config, creds
                )
            return self._clients[key]

    def _build_client(self, service, endpoint_url, region, config, creds) -> Any:
        kw: dict[str, Any] = dict(creds) if creds else dict(self._creds)
        if endpoint_url:
            assert_tls_verification_permitted(endpoint_url, self._verify_ssl)
        target = self._published_target(endpoint_url, "client") if endpoint_url else None
        target = target or self._endpoint
        refuse_real_aws(target)
        # Re-gated: a discovered endpoint is a host __init__ never saw.
        assert_tls_verification_permitted(target, self._verify_ssl)
        if endpoint_url:
            self._require_local_url(target, ("http", "https"))
        kw["endpoint_url"] = target
        base = self._config
        no_bearer = bearer_free_config(service)
        if no_bearer is not None:
            base = base.merge(no_bearer)
        client = boto3.client(
            service,
            region_name=region or self._region,
            config=_merge_config(base, config) if config is not None else base,
            verify=self._verify_ssl,
            **kw,
        )
        fit_to_emulator(client, target)
        return client

    def subprocess_env(self) -> dict[str, str]:
        """Environment for a CLI or IaC subprocess, pointed at the same emulator and identity.

        It is built from an allowlist (``isolate.SUBPROCESS_ENV``), signs with the keys
        ``client`` signs with, gets a private ``HOME`` and ``TMPDIR``, the CDK template endpoint
        and the JS SDK v2 preload, and a pinned emulator certificate is every tool's trust bundle
        (``fidelity_tests_runner.trust.BUNDLE_ENV``).
        """
        env = isolate.subprocess_env(os.environ, self._http_verify)
        env["TMPDIR"] = self._private_tmpdir()
        env["HOME"] = os.path.join(env["TMPDIR"], "home")
        env["DOCKER_CONFIG"] = os.path.join(env["TMPDIR"], "docker")
        env["AWS_REGION"] = env["AWS_DEFAULT_REGION"] = self._region
        env["AWS_ENDPOINT_URL"] = self._endpoint
        # `cdk deploy` resolves the s3:// TemplateURL it hands CloudFormation through this
        # override alone.
        env["AWS_ENDPOINT_URL_S3_FOR_CLOUDFORMATION"] = self._endpoint
        env["NODE_OPTIONS"] = f'--require "{_node_quoted(self._js_sdk_preload())}"'
        env[NO_HOST_PREFIX_ENV] = "true"  # the endpoint host as given, as ctx.client sends
        # S3 Control's endpoint rules prepend "{AccountId}." to a custom endpoint, and an IP
        # literal cannot take a label; *.localhost resolves to loopback for every IaC tool.
        parts = urlsplit(self._endpoint)
        if parts.hostname in ("127.0.0.1", "::1"):
            netloc = f"localhost:{parts.port}" if parts.port else "localhost"
            env["AWS_ENDPOINT_URL_S3_CONTROL"] = parts._replace(netloc=netloc).geturl()
        env["AWS_ACCESS_KEY_ID"] = self._creds["aws_access_key_id"]
        env["AWS_SECRET_ACCESS_KEY"] = self._creds["aws_secret_access_key"]
        if self._creds.get("aws_session_token"):
            env["AWS_SESSION_TOKEN"] = self._creds["aws_session_token"]
        return env

    def _private_tmpdir(self) -> str:
        """A temporary directory of this context's own, removed after its teardowns."""
        with self._clients_lock:
            return self._make_tmpdir()

    def _js_sdk_preload(self) -> str:
        """The path of ``_JS_SDK_PRELOAD`` in this context's own temporary directory."""
        with self._clients_lock:  # one writer, and no reader before the write completes
            path = os.path.join(self._make_tmpdir(), JS_SDK_PRELOAD_NAME)
            if not os.path.exists(path):
                partial = f"{path}.partial"
                with open(partial, "w", encoding="utf-8") as fh:
                    fh.write(_JS_SDK_PRELOAD)
                os.replace(partial, path)  # never a truncated preload in place
            return path

    def _make_tmpdir(self) -> str:
        if self._tmpdir is None:
            base = socket_safe_tmp_base()
            self._tmpdir = tempfile.mkdtemp(prefix="fidelity-tests-check-", dir=base)
            os.mkdir(os.path.join(self._tmpdir, "docker"), 0o700)
            os.mkdir(os.path.join(self._tmpdir, "home"), 0o700)
        return self._tmpdir

    def on_cleanup(self, fn: Callable[[], None]) -> None:
        """Register a zero-arg teardown; the runner runs them LIFO after the check, always."""
        self._cleanups.append(fn)

    def run_cleanups(self) -> None:
        """Run every teardown, LIFO; then raise naming every failure, so each one is reported."""
        failures: list[BaseException] = []
        while self._cleanups:
            fn = self._cleanups.pop()
            try:
                fn()
            except (Exception, NonLocalHostRefused) as exc:  # run every teardown
                failures.append(exc)
        if self._tmpdir is not None:
            shutil.rmtree(self._tmpdir, ignore_errors=True)
            self._tmpdir = None
        if failures:
            named = "; ".join(repr(f) for f in failures)
            raise RuntimeError(f"{len(failures)} teardown(s) failed: {named}") from failures[0]

    def verify_account_safety(self) -> None:
        """A no-op: an emulator holds no account to protect. Kept because checks call it."""


def _raise_any(failures: list[str]) -> None:
    if failures:
        raise RuntimeError(f"shared network teardown failed: {'; '.join(failures)}")

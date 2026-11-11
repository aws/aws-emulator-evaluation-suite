"""http-api-integration-response-passthrough-and-payload-format-multi-value-headers."""
from __future__ import annotations

import hashlib
import io
import json
import socket
import ssl
import time
import zipfile
from urllib.parse import urlsplit

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = 'http-api-integration-response-passthrough-and-payload-format-multi-value-headers'
GROUP = 'invoke'
SERVICES = ['apigatewayv2', 'iam', 'lambda']

TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
TAGS_KV = [{"Key": k, "Value": v} for k, v in TAGS.items()]

# ONE backend behind TWO integrations on ONE API, differing only in PayloadFormatVersion, so the
# two formats are compared against byte-identical returns in the same run on the same stage.
# There is deliberately no '$default' route, so an unrouted target produces a GATEWAY response
# that can be contrasted byte-for-byte against an integration-produced one.
_ROUTE_2_0 = "GET /resp/{mode}"
_ROUTE_1_0 = "GET /resp10/{mode}"

_UA = "sim2real-behav-target/1.0"

# Body markers. Each is used BOTH to build the backend and to state the expected bytes, so the
# two cannot drift apart.
_NOT_FOUND_PREFIX = "INTEG-404-BODY-"
_COOKIES_PREFIX = "COOKIES-"
_MVH_PREFIX = "MVH-"
_JOINED_PREFIX = "JOINED-"
_SIZED_PREFIX = "SIZED-"
_SIZED_TAIL = "-END"

_COOKIE_LINES = ["c1=v1; Path=/", "c2=v2; Path=/"]
_MVH_X_M = ["mv-a", "mv-b"]
_MVH_SET_COOKIE = ["m1=1", "m2=2"]
_JOINED_X_M = "a,b"

# Comfortably inside and comfortably outside the serialized response payload limit. The exact
# boundary is not pinned: a numeric edge that moves would report a gap that is not one, so only
# the SHAPE either side of it is asserted.
_UNDER_BYTES = 6_000_000
_OVER_BYTES = 7_340_032

# The backend returns the same dict for a given mode under both payload formats; it reads only
# pathParameters and queryStringParameters, which both formats deliver.
_RESP_CODE = """
STAMP = "%s"
NOT_FOUND_BODY = "%s" + STAMP
COOKIES_BODY = "%s" + STAMP
MVH_BODY = "%s" + STAMP
JOINED_BODY = "%s" + STAMP
SIZED_HEAD = "%s" + STAMP + "-"
SIZED_TAIL = "%s"
COOKIE_LINES = %s
MVH_X_M = %s
MVH_SET_COOKIE = %s
JOINED_X_M = "%s"


def _size(event):
    params = event.get("queryStringParameters") or {}
    try:
        return int(params.get("n") or 0)
    except (TypeError, ValueError):
        return 0


def lambda_handler(event, context):
    mode = (event.get("pathParameters") or {}).get("mode")
    if mode == "notfound":
        return {
            "statusCode": 404,
            "headers": {"content-type": "text/plain", "x-probe": STAMP},
            "body": NOT_FOUND_BODY,
        }
    if mode == "cookies":
        return {
            "statusCode": 200,
            "headers": {"content-type": "text/plain", "x-probe": STAMP},
            "cookies": COOKIE_LINES,
            "body": COOKIES_BODY,
        }
    if mode == "mvh":
        return {
            "statusCode": 200,
            "headers": {"content-type": "text/plain", "x-probe": STAMP, "x-single": "s"},
            "multiValueHeaders": {"x-m": MVH_X_M, "set-cookie": MVH_SET_COOKIE},
            "body": MVH_BODY,
        }
    if mode == "joined":
        return {
            "statusCode": 200,
            "headers": {"content-type": "text/plain", "x-probe": STAMP, "x-m": JOINED_X_M},
            "body": JOINED_BODY,
        }
    if mode == "sized":
        want = _size(event)
        pad = max(0, want - len(SIZED_HEAD) - len(SIZED_TAIL))
        body = (SIZED_HEAD + ("x" * pad) + SIZED_TAIL)[:want]
        return {
            "statusCode": 200,
            "headers": {"content-type": "text/plain", "x-probe": STAMP},
            "body": body,
        }
    return {
        "statusCode": 418,
        "headers": {"content-type": "text/plain", "x-probe": STAMP},
        "body": "UNKNOWN-MODE",
    }
"""

_GW_404_BODY = b'{"message":"Not Found"}'
_GW_500_BODY = b'{"message":"Internal Server Error"}'
_GONE = ("NotFoundException", "ResourceNotFoundException", "NoSuchEntity")

# Every invoked route sits behind this Lambda REQUEST authorizer, which admits only requests
# carrying the run's own token, so the API serves nobody but this check.
_TOKEN_HEADER = "x-check-token"
_AUTHORIZER_CODE = """
import hmac
TOKEN = "%s"
def lambda_handler(event, context):
    got = (event.get("headers") or {}).get("x-check-token") or ""
    return {"isAuthorized": hmac.compare_digest(got, TOKEN)}
"""

_ROLE_NOT_ASSUMABLE = (
    "InvalidParameterValueException",
    "The role defined for the function cannot be assumed by Lambda.",
)


def _ssl_context(ctx):
    """The TLS context for this check's own call to the target, from ``ctx.http_verify``."""
    verify = ctx.http_verify
    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


def _dest(ctx, api_id, token):
    """Host, port, TLS flag, stage path prefix and authorizer token for the invoke endpoint."""
    parts = urlsplit(ctx.api_url(api_id, "$default"))
    tls = parts.scheme != "http"
    port = parts.port or (443 if tls else 80)
    return parts.hostname, port, tls, parts.path.rstrip("/"), token


def _dechunk(data):
    """The decoded body of a COMPLETE chunked stream, or None while the stream is unfinished."""
    out, i = [], 0
    while True:
        j = data.find(b"\r\n", i)
        if j < 0:
            return None
        token = data[i:j].split(b";", 1)[0].strip()
        if not token or token.strip(b"0123456789abcdefABCDEF"):
            raise ValueError(f"malformed chunk size {token[:32]!r}")
        size = int(token, 16)
        if size == 0:
            return b"".join(out) if data.find(b"\r\n\r\n", j) >= 0 else None
        stop = j + 2 + size
        if len(data) < stop + 2:
            return None
        if data[stop:stop + 2] != b"\r\n":
            raise ValueError(f"chunk of {size} bytes not terminated by CRLF")
        out.append(data[j + 2:stop])
        i = stop + 2


def _read_response(conn, method):
    """Read ONE COMPLETE response; returns (status, header lines, body bytes).

    A short read raises instead of passing for a short body. Under HEAD the peer's close ends the
    response and any body bytes are returned as observed, since those bytes are under test.
    """
    buf = b""
    while b"\r\n\r\n" not in buf:
        block = conn.recv(65536)
        if not block:
            raise ConnectionError(f"peer closed after {len(buf)} bytes without a complete head")
        buf += block
    head, rest = buf.split(b"\r\n\r\n", 1)
    text = head.decode("latin-1").split("\r\n")
    pairs = (line.split(":", 1) for line in text[1:] if ":" in line)
    headers = [(k.strip().lower(), v.strip()) for k, v in pairs]
    framing = dict(headers)
    codings = [c.strip() for c in framing.get("transfer-encoding", "").lower().split(",")]
    chunked = codings[-1] == "chunked"
    length = int(framing["content-length"]) if "content-length" in framing else None
    while True:
        if method != "HEAD":
            if chunked and (body := _dechunk(rest)) is not None:
                return int(text[0].split(" ")[1]), headers, body
            if not chunked and length is not None and len(rest) >= length:
                return int(text[0].split(" ")[1]), headers, rest[:length]
        block = conn.recv(262144)
        if not block:
            if method == "HEAD" or (not chunked and length is None):
                return int(text[0].split(" ")[1]), headers, rest
            raise ConnectionError(f"peer closed with the body incomplete after {len(rest)} bytes")
        rest += block


def _raw(ctx, dest, method, target, extra=None, body=None, ua=_UA, timeout_s=30):
    """Send ``METHOD <target> HTTP/1.1`` with the target byte-for-byte as given.

    Hand-written so route selection gets exactly these bytes, repeated response header LINES stay
    separate (name, value) pairs, and a HEAD response's body bytes stay observable. Never raises:
    a failure is reported in ``error`` for the caller to retry.
    """
    out = {"status": None, "headers": [], "body": b"", "error": None}
    host, port, tls, prefix, token = dest
    lines = [("host", host), ("user-agent", ua), ("accept", "*/*"), (_TOKEN_HEADER, token)]
    lines.extend(extra or ())
    if body is not None:
        lines.append(("content-length", str(len(body))))
    lines.append(("connection", "close"))
    wire = (
        f"{method} {prefix}{target} HTTP/1.1\r\n"
        + "".join(f"{k}: {v}\r\n" for k, v in lines)
        + "\r\n"
    ).encode("latin-1") + (body or b"")
    try:
        conn = socket.create_connection((host, port), timeout=timeout_s)
        try:
            if tls:
                conn = _ssl_context(ctx).wrap_socket(conn, server_hostname=host)
            conn.sendall(wire)
            out["status"], out["headers"], out["body"] = _read_response(conn, method)
        finally:
            conn.close()
    except (OSError, ValueError, IndexError) as exc:
        out["error"] = f"{type(exc).__name__}: {exc}"
    return out


def _hdrs(resp, name):
    """Every value delivered under ``name``, in wire order, repeated lines kept SEPARATE."""
    return [v for k, v in resp["headers"] if k == name]


def _hdr(resp, name):
    """The last value delivered under ``name``, or None when the header never arrived."""
    values = _hdrs(resp, name)
    return values[-1] if values else None


def _cleanup(fn):
    """A cleanup callback running ``fn``; only an already-deleted resource is tolerated."""

    def run_cleanup():
        try:
            fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in _GONE:
                raise

    return run_cleanup


def _create_lambda_role(ctx):
    """A Lambda execution role with no permissions, so no backend can create a log group."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-lambda-")
    statement = {
        "Effect": "Allow",
        "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }
    trust = json.dumps({"Version": "2012-10-17", "Statement": [statement]})
    arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=trust, Path="/sim2real/", Tags=TAGS_KV
    )["Role"]["Arn"]
    ctx.on_cleanup(_cleanup(lambda: iam.delete_role(RoleName=role_name)))
    return arn


def _create_backend(ctx, api_id, role_arn, marker, code, memory_mb=128, timeout_s=10):
    """A python Lambda running ``code``, invokable by this API; returns its ARN."""
    lam = ctx.client("lambda")
    name = ctx.unique_name(f"sim2real-behav-fn-{marker}-")
    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", code)
    kwargs = dict(
        FunctionName=name, Runtime="python3.12", Role=role_arn, Tags=TAGS,
        Handler="lambda_function.lambda_handler", Code={"ZipFile": zip_buf.getvalue()},
        Timeout=timeout_s, MemorySize=memory_mb,
    )
    deadline = time.monotonic() + 90
    while True:
        try:
            arn = lam.create_function(**kwargs)["FunctionArn"]
            break
        except ClientError as exc:
            # IAM propagation: a freshly created role is not yet assumable by Lambda.
            err = exc.response["Error"]
            if (err["Code"], err["Message"]) == _ROLE_NOT_ASSUMABLE and time.monotonic() < deadline:
                time.sleep(3)
                continue
            raise
    ctx.on_cleanup(_cleanup(lambda: lam.delete_function(FunctionName=name)))
    deadline = time.monotonic() + 60
    while True:
        state = lam.get_function_configuration(FunctionName=name).get("State")
        if state == "Active":
            break
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"lambda {marker} did not become Active within 60s (last {state!r})"
            )
        time.sleep(2.0)
    lam.add_permission(
        FunctionName=name,
        StatementId="apigw-invoke",
        Action="lambda:InvokeFunction",
        Principal="apigateway.amazonaws.com",
        SourceArn=f"arn:aws:execute-api:{ctx.region}:{ctx.account}:{api_id}/*/*",
    )
    return arn


def _create_authorizer(ctx, api_id, role_arn, token):
    """A Lambda REQUEST authorizer on ``api_id`` admitting only ``token``; returns its id."""
    fn_arn = _create_backend(ctx, api_id, role_arn, "authz", _AUTHORIZER_CODE % token)
    return ctx.client("apigatewayv2").create_authorizer(
        ApiId=api_id,
        Name=ctx.unique_name("sim2real-behav-authz-"),
        AuthorizerType="REQUEST",
        AuthorizerUri=(
            f"arn:aws:apigateway:{ctx.region}:lambda:path/2015-03-31/functions/{fn_arn}"
            "/invocations"
        ),
        AuthorizerPayloadFormatVersion="2.0",
        EnableSimpleResponses=True,
        IdentitySource=[f"$request.header.{_TOKEN_HEADER}"],
        AuthorizerResultTtlInSeconds=0,
    )["AuthorizerId"]


def _create_api(ctx, agw):
    """Create the HTTP API and register its deletion; returns its id."""
    api_id = agw.create_api(
        Name=ctx.unique_name("sim2real-behav-httpapi-"), ProtocolType="HTTP", Tags=TAGS
    )["ApiId"]
    ctx.on_cleanup(_cleanup(lambda: agw.delete_api(ApiId=api_id)))
    return api_id


def _route_keys(agw, api_id):
    return sorted(r["RouteKey"] for r in agw.get_routes(ApiId=api_id)["Items"])


def _poll(
    ctx,
    dest,
    method,
    target,
    want,
    *,
    stamp=None,
    streak=1,
    timeout_s=180,
    read_timeout_s=30,
):
    """Poll one request until ``streak`` consecutive responses carry status ``want``.

    Absorbs execute-api DNS warm-up and auto-deploy propagation without a fixed sleep. A streak
    above one is required only when the wanted status is 404, which is also what an execute-api
    node that has not yet picked up the deployment answers on every route; for any other wanted
    status a cold node simply does not match and the poll keeps waiting. When ``stamp`` is given
    the response must also carry the backend's stamped header, so a response from the gateway
    itself does not satisfy the wait. Raises AssertionError naming the last observation on
    timeout, so a wrong answer grades as a mismatch rather than surfacing as a harness error.
    """
    last = "no response"
    seen = 0
    deadline = time.monotonic() + timeout_s
    while True:
        resp = _raw(ctx, dest, method, target, timeout_s=read_timeout_s)
        if resp["error"] is not None:
            last, seen = f"transport error {resp['error']}", 0
        elif resp["status"] == want and (stamp is None or _hdrs(resp, "x-probe") == [stamp]):
            seen += 1
            if seen >= streak:
                return resp
        else:
            seen = 0
            last = f"status {resp['status']} body {resp['body'][:200]!r}"
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{method} {target}: never answered {want} {streak}x in a row within {timeout_s}s"
                f"; last observation: {last}"
            )
        time.sleep(3)


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """A Lambda proxy integration's status, headers and body bytes reach the client unchanged and
    byte-distinct from the gateway's own envelopes, and the two payload format versions honour
    disjoint multi-value response keys, each silently dropping the other's.
    """
    agw = ctx.client("apigatewayv2")
    stamp = ctx.unique_name("probe-")
    api_id = _create_api(ctx, agw)
    role_arn = _create_lambda_role(ctx)
    token = ctx.unique_name("token-")
    authorizer_id = _create_authorizer(ctx, api_id, role_arn, token)
    code = _RESP_CODE % (
        stamp,
        _NOT_FOUND_PREFIX,
        _COOKIES_PREFIX,
        _MVH_PREFIX,
        _JOINED_PREFIX,
        _SIZED_PREFIX,
        _SIZED_TAIL,
        json.dumps(_COOKIE_LINES),
        json.dumps(_MVH_X_M),
        json.dumps(_MVH_SET_COOKIE),
        _JOINED_X_M,
    )
    # The oversize leg makes the backend build a multi-megabyte body, which needs headroom the
    # default memory size does not give.
    fn_arn = _create_backend(
        ctx, api_id, role_arn, "resp", code, memory_mb=1024, timeout_s=30
    )

    for route_key, version in ((_ROUTE_2_0, "2.0"), (_ROUTE_1_0, "1.0")):
        integ_id = agw.create_integration(
            ApiId=api_id,
            IntegrationType="AWS_PROXY",
            IntegrationUri=fn_arn,
            IntegrationMethod="POST",
            PayloadFormatVersion=version,
        )["IntegrationId"]
        agw.create_route(
            ApiId=api_id,
            RouteKey=route_key,
            Target=f"integrations/{integ_id}",
            AuthorizationType="CUSTOM",
            AuthorizerId=authorizer_id,
        )
    agw.create_stage(ApiId=api_id, StageName="$default", AutoDeploy=True, Tags=TAGS)

    # Precondition: both formats exist on ONE API, and there is no '$default' route, so the
    # gateway-produced envelopes the passthrough legs are contrasted against are reachable.
    listed = _route_keys(agw, api_id)
    assert listed == sorted([_ROUTE_2_0, _ROUTE_1_0]), (
        f"both payload format routes must coexist on one API with no '$default' sibling; "
        f"GetRoutes reports {listed}"
    )

    dest = _dest(ctx, api_id, token)
    # Warm-up: hold until the auto-deploy stage serves a known-good target twice in a row before
    # any refusal below is believed.
    _poll(ctx, dest, "GET", "/resp/joined", 200, stamp=stamp, streak=2)

    _leg_integration_non_200_passes_through(ctx, dest, stamp)
    _leg_gateway_404_is_byte_distinct(ctx, dest)
    _leg_2_0_honours_cookies_and_drops_multi_value(ctx, dest, stamp)
    _leg_1_0_honours_multi_value_and_drops_cookies(ctx, dest, stamp)
    _leg_a_joined_header_value_stays_one_line(ctx, dest, stamp)
    _leg_oversize_response_shape(ctx, dest, stamp)


def _leg_integration_non_200_passes_through(ctx, dest, stamp):
    """An integration's own status, content-type and body bytes reach the client unaltered."""
    want_body = (_NOT_FOUND_PREFIX + stamp).encode()
    for target, version in (("/resp/notfound", "2.0"), ("/resp10/notfound", "1.0")):
        resp = _poll(ctx, dest, "GET", target, 404, stamp=stamp)
        assert resp["body"] == want_body, (
            f"GET {target} ({version}): the integration's own body bytes must reach the client "
            f"with no gateway envelope substituted, expected {want_body!r}, got "
            f"{resp['body'][:200]!r}"
        )
        assert _hdr(resp, "content-type") == "text/plain", (
            f"GET {target} ({version}): the integration's own content-type must survive, got "
            f"{_hdr(resp, 'content-type')!r}"
        )
        assert _hdr(resp, "content-length") == str(len(want_body)), (
            f"GET {target} ({version}): content-length must be the integration body's own length "
            f"({len(want_body)}), got {_hdr(resp, 'content-length')!r}"
        )
        assert _hdrs(resp, "x-probe") == [stamp], (
            f"GET {target} ({version}): the integration's custom response header must reach the "
            f"client, got {_hdrs(resp, 'x-probe')}"
        )


def _leg_gateway_404_is_byte_distinct(ctx, dest):
    """The gateway's own 404 on the same API, so the passthrough leg above is not vacuous."""
    resp = _poll(ctx, dest, "GET", "/nosuchroute", 404, streak=2)
    where = (
        "GET /nosuchroute: a route miss must produce the GATEWAY's own 404 envelope, byte-distinct "
        "from the integration-produced 404 on this same API in this same run -- that contrast is "
        "what makes the passthrough leg non-vacuous, because a target that 404s by never wiring "
        "the route could otherwise satisfy both"
    )
    assert resp["body"] == _GW_404_BODY, (
        f"{where}; expected body {_GW_404_BODY!r}, got {resp['body'][:200]!r}"
    )
    assert _hdr(resp, "content-length") == str(len(_GW_404_BODY)), (
        f"{where}; expected content-length {len(_GW_404_BODY)}, got "
        f"{_hdr(resp, 'content-length')!r}"
    )
    assert _hdr(resp, "content-type") == "application/json", (
        f"{where}; expected content-type application/json, got {_hdr(resp, 'content-type')!r}"
    )
    assert _hdrs(resp, "x-probe") == [], (
        f"{where}; the integration's stamped header must be absent, got "
        f"{_hdrs(resp, 'x-probe')}"
    )


def _leg_2_0_honours_cookies_and_drops_multi_value(ctx, dest, stamp):
    """Payload format 2.0: ``cookies`` becomes set-cookie lines, ``multiValueHeaders`` is lost."""
    resp = _poll(ctx, dest, "GET", "/resp/cookies", 200, stamp=stamp)
    assert _hdrs(resp, "set-cookie") == _COOKIE_LINES, (
        f"2.0 must emit one verbatim set-cookie LINE per cookies entry, in order "
        f"({_COOKIE_LINES}), got {_hdrs(resp, 'set-cookie')}"
    )
    assert resp["body"] == (_COOKIES_PREFIX + stamp).encode(), (
        f"the body must arrive intact alongside the cookies, got {resp['body'][:200]!r}"
    )

    resp = _poll(ctx, dest, "GET", "/resp/mvh", 200, stamp=stamp)
    # Same response, same return value: 'headers' IS honoured here, so the two absences below are
    # 'multiValueHeaders' being discarded and not a response whose headers were lost wholesale.
    assert _hdr(resp, "x-single") == "s", (
        f"2.0 must honour the plain headers returned beside multiValueHeaders, got x-single "
        f"{_hdr(resp, 'x-single')!r}"
    )
    assert _hdrs(resp, "x-m") == [], (
        f"2.0 must discard multiValueHeaders ENTIRELY -- it does not comma-join the list either "
        f"-- so no x-m line may reach the client, got {_hdrs(resp, 'x-m')}"
    )
    assert _hdrs(resp, "set-cookie") == [], (
        f"2.0 must discard a set-cookie carried in multiValueHeaders, got "
        f"{_hdrs(resp, 'set-cookie')}"
    )
    assert resp["status"] == 200 and resp["body"] == (_MVH_PREFIX + stamp).encode(), (
        f"the discard must be SILENT: still 200 with the body intact, so nothing on the wire "
        f"signals the loss; got status {resp['status']} body {resp['body'][:200]!r}"
    )


def _leg_1_0_honours_multi_value_and_drops_cookies(ctx, dest, stamp):
    """Payload format 1.0: the exact inverse, measured against a byte-identical return value."""
    resp = _poll(ctx, dest, "GET", "/resp10/cookies", 200, stamp=stamp)
    assert _hdrs(resp, "set-cookie") == [], (
        f"1.0 must discard the 2.0-only cookies key entirely, so no set-cookie line may reach "
        f"the client, got {_hdrs(resp, 'set-cookie')}"
    )
    # Control inside the same response: the integration's own header DID arrive, so the absence
    # above is the cookies key being dropped and not a response that lost its headers.
    assert _hdrs(resp, "x-probe") == [stamp], (
        f"1.0 must still honour the plain headers returned beside cookies, got x-probe "
        f"{_hdrs(resp, 'x-probe')}"
    )
    assert resp["status"] == 200 and resp["body"] == (_COOKIES_PREFIX + stamp).encode(), (
        f"the discard must be SILENT: still 200 with the body intact; got status "
        f"{resp['status']} body {resp['body'][:200]!r}"
    )

    resp = _poll(ctx, dest, "GET", "/resp10/mvh", 200, stamp=stamp)
    assert _hdrs(resp, "x-m") == _MVH_X_M, (
        f"1.0 must emit each multiValueHeaders entry as a SEPARATE line in the order given "
        f"({_MVH_X_M}), got {_hdrs(resp, 'x-m')}"
    )
    assert _hdrs(resp, "set-cookie") == _MVH_SET_COOKIE, (
        f"1.0 must emit a repeated set-cookie from multiValueHeaders as separate lines in order "
        f"({_MVH_SET_COOKIE}), got {_hdrs(resp, 'set-cookie')}"
    )
    assert _hdr(resp, "x-single") == "s", (
        f"1.0 must honour plain headers alongside multiValueHeaders, got x-single "
        f"{_hdr(resp, 'x-single')!r}"
    )
    assert resp["status"] == 200 and resp["body"] == (_MVH_PREFIX + stamp).encode(), (
        f"the 1.0 response must be 200 with its body intact; got status {resp['status']} body "
        f"{resp['body'][:200]!r}"
    )


def _leg_a_joined_header_value_stays_one_line(ctx, dest, stamp):
    """A comma inside a single header value is never split, under either payload format."""
    for target, version in (("/resp/joined", "2.0"), ("/resp10/joined", "1.0")):
        resp = _poll(ctx, dest, "GET", target, 200, stamp=stamp)
        assert _hdrs(resp, "x-m") == [_JOINED_X_M], (
            f"GET {target} ({version}): a header returned as the single value {_JOINED_X_M!r} "
            f"must reach the client as exactly ONE line with that value and never be split on "
            f"the comma, got {_hdrs(resp, 'x-m')}"
        )
        assert resp["body"] == (_JOINED_PREFIX + stamp).encode(), (
            f"GET {target} ({version}): the body must arrive intact, got {resp['body'][:200]!r}"
        )


def _leg_oversize_response_shape(ctx, dest, stamp):
    """Either side of the response payload limit: intact passthrough, or the gateway's own 500.

    The limit's exact byte boundary is NOT pinned. Both probes sit far enough from it that a
    boundary that shifts cannot turn this leg into a reported gap, and each ships a multi-megabyte
    response, so there are only two of them.
    """
    resp = _poll(
        ctx, dest, "GET", f"/resp/sized?n={_UNDER_BYTES}", 200, stamp=stamp, read_timeout_s=120
    )
    assert _hdr(resp, "content-length") == str(_UNDER_BYTES), (
        f"a response comfortably under the limit must advertise its own full length "
        f"({_UNDER_BYTES}), got {_hdr(resp, 'content-length')!r}"
    )
    assert len(resp["body"]) == _UNDER_BYTES, (
        f"a response comfortably under the limit must arrive complete: expected "
        f"{_UNDER_BYTES} body bytes, got {len(resp['body'])}"
    )
    head = _SIZED_PREFIX + stamp + "-"
    pad = max(0, _UNDER_BYTES - len(head) - len(_SIZED_TAIL))
    expected = (head + ("x" * pad) + _SIZED_TAIL)[:_UNDER_BYTES].encode()
    got_digest = hashlib.sha256(resp["body"]).hexdigest()
    assert got_digest == hashlib.sha256(expected).hexdigest(), (
        f"the multi-megabyte body must arrive byte-for-byte as the integration built it, not "
        f"truncated, padded or re-encoded; sha256 {got_digest} differs from the expected body's; "
        f"it starts {resp['body'][:40]!r} and ends {resp['body'][-8:]!r}"
    )

    over = _poll(ctx, dest, "GET", f"/resp/sized?n={_OVER_BYTES}", 500, read_timeout_s=120)
    assert over["body"] == _GW_500_BODY, (
        f"a response comfortably over the limit must be replaced by the GATEWAY's own 500 "
        f"envelope, byte-distinct from the passthrough case above: expected {_GW_500_BODY!r}, got "
        f"{over['body'][:200]!r}"
    )
    assert _hdr(over, "content-length") == str(len(_GW_500_BODY)), (
        f"the gateway 500 envelope must advertise content-length {len(_GW_500_BODY)}, got "
        f"{_hdr(over, 'content-length')!r}"
    )
    assert _hdr(over, "content-type") == "application/json", (
        f"the gateway 500 envelope must be served as JSON and not the integration's text/plain, "
        f"got {_hdr(over, 'content-type')!r}"
    )
    assert _hdrs(over, "x-probe") == [], (
        f"the gateway 500 envelope replaces the integration's response entirely, so its custom "
        f"header must not survive, got {_hdrs(over, 'x-probe')}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

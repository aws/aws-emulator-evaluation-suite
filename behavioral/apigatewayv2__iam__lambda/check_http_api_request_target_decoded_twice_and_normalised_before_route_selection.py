"""http-api-request-target-decoded-twice-and-normalised-before-route-selection."""
from __future__ import annotations

import io
import json
import socket
import ssl
import time
import zipfile
from urllib.parse import urlsplit

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = 'http-api-request-target-decoded-twice-and-normalised-before-route-selection'
GROUP = 'invoke'
SERVICES = ['apigatewayv2', 'iam', 'lambda']

TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
TAGS_KV = [{"Key": k, "Value": v} for k, v in TAGS.items()]

# Six overlapping literal/variable/greedy keys and deliberately NO '$default' and no root
# '{proxy+}': an unrouted target therefore produces API Gateway's own 404 instead of falling
# through to a catch-all, which is what makes the "%2F separates" and "trailing slash is
# significant" legs below decidable.
_ROUTE_KEYS = [
    "GET /items", "GET /items/{id}", "GET /pets/{proxy+}", "GET /a/b", "GET /b", "GET /q",
]

_UA = "sim2real-behav-target/1.0"

# The backend reports what route selection decided and what it was handed, plus a stamp the
# gateway cannot forge: a response carrying the stamp provably came from the integration.
_ECHO_CODE = """
import json
STAMP = "%s"
def lambda_handler(event, context):
    rc = event.get("requestContext") or {}
    doc = {
        "stamp": STAMP,
        "keys": sorted(event.keys()),
        "routeKey": event.get("routeKey"),
        "rawPath": event.get("rawPath"),
        "ctxPath": (rc.get("http") or {}).get("path"),
        "rawQueryString": event.get("rawQueryString"),
        "pathParameters": event.get("pathParameters"),
        "queryStringParameters": event.get("queryStringParameters"),
    }
    return {
        "statusCode": 200,
        "headers": {"content-type": "application/json", "x-probe": STAMP},
        "body": json.dumps(doc),
    }
"""

_GW_404_BODY = b'{"message":"Not Found"}'
_GW_400_BODY = b'{"message":"Bad Request"}'
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
    """Every value delivered under ``name``, in wire order, repeated lines kept separate."""
    return [v for k, v in resp["headers"] if k == name]


def _hdr(resp, name):
    """The last value delivered under ``name``, or None when the header never arrived."""
    values = _hdrs(resp, name)
    return values[-1] if values else None


def _doc(resp, stamp):
    """The backend's stamped echo document, or None when this response did not come from it."""
    try:
        parsed = json.loads(resp["body"].decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None
    if isinstance(parsed, dict) and parsed.get("stamp") == stamp:
        return parsed
    return None


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


def _poll(ctx, dest, method, target, want, *, stamp=None, streak=1, extra=None, timeout_s=180):
    """Poll one request until ``streak`` consecutive responses carry status ``want``.

    Absorbs execute-api DNS warm-up and auto-deploy propagation without a fixed sleep. A streak
    above one is required for the refusal legs: an execute-api node that has not yet picked up the
    deployment answers 404 on every route, so a single 404 does not distinguish "this target is
    not routed" from "this node is cold". When ``stamp`` is given the response must also carry the
    backend's stamped document, so a 200 from anything else does not satisfy the wait. Raises
    AssertionError naming the last observation on timeout, so a wrong answer grades as a mismatch
    rather than surfacing as a harness error.
    """
    last = "no response"
    seen = 0
    deadline = time.monotonic() + timeout_s
    while True:
        resp = _raw(ctx, dest, method, target, extra=extra)
        if resp["error"] is not None:
            last, seen = f"transport error {resp['error']}", 0
        elif resp["status"] == want and (stamp is None or _doc(resp, stamp) is not None):
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


def _served(ctx, dest, target, stamp, *, extra=None):
    """One served request on a routed target; returns the backend's echo document."""
    resp = _poll(ctx, dest, "GET", target, 200, stamp=stamp, extra=extra)
    doc = _doc(resp, stamp)
    assert doc is not None, (
        f"GET {target}: a 200 on a routed target must carry the backend's own stamped document, "
        f"got body {resp['body'][:200]!r}"
    )
    assert _hdrs(resp, "x-probe") == [stamp], (
        f"GET {target}: the integration's stamped response header must reach the client once, got "
        f"{_hdrs(resp, 'x-probe')}"
    )
    assert doc.get("ctxPath") == doc.get("rawPath"), (
        f"GET {target}: requestContext.http.path must report the same path as rawPath, got "
        f"{doc.get('ctxPath')!r} and {doc.get('rawPath')!r}"
    )
    return doc


def _assert_gateway_404(resp, where, *, body_on_wire=True):
    """API Gateway's own Not Found envelope, byte-exact, with no trace of any integration.

    The caller established the 404 itself by polling for it, so what is asserted here is only what
    that envelope is MADE OF.
    """
    assert _hdr(resp, "content-length") == str(len(_GW_404_BODY)), (
        f"{where}: the gateway 404 envelope must advertise content-length "
        f"{len(_GW_404_BODY)}, got {_hdr(resp, 'content-length')!r}"
    )
    assert _hdr(resp, "content-type") == "application/json", (
        f"{where}: the gateway 404 envelope must be served as JSON, got content-type "
        f"{_hdr(resp, 'content-type')!r}"
    )
    if body_on_wire:
        assert resp["body"] == _GW_404_BODY, (
            f"{where}: the gateway 404 body must be exactly {_GW_404_BODY!r}, got "
            f"{resp['body'][:200]!r}"
        )
    # The stamp is the integration's own, so its absence is what shows nothing was invoked -- and
    # every leg that asserts it absent is paired with a request on this same API that carries it.
    assert _hdrs(resp, "x-probe") == [], (
        f"{where}: a gateway-produced 404 must carry no integration response header, got x-probe "
        f"{_hdrs(resp, 'x-probe')}"
    )
    assert _hdr(resp, "apigw-requestid"), (
        f"{where}: a gateway-produced response must carry the gateway's own request id header, "
        f"got headers {resp['headers']}"
    )


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """An HTTP API percent-decodes the request target exactly twice and applies dot-segment and
    empty-segment removal BEFORE route selection, then reports the decoded normalised path in
    rawPath, requestContext.http.path and pathParameters while rawQueryString stays encoded.
    """
    agw = ctx.client("apigatewayv2")
    stamp = ctx.unique_name("probe-")
    api_id = _create_api(ctx, agw)
    role_arn = _create_lambda_role(ctx)
    token = ctx.unique_name("token-")
    authorizer_id = _create_authorizer(ctx, api_id, role_arn, token)
    fn_arn = _create_backend(ctx, api_id, role_arn, "echo", _ECHO_CODE % stamp)
    integ_id = agw.create_integration(
        ApiId=api_id,
        IntegrationType="AWS_PROXY",
        IntegrationUri=fn_arn,
        IntegrationMethod="POST",
        PayloadFormatVersion="2.0",
    )["IntegrationId"]
    for key in _ROUTE_KEYS:
        agw.create_route(
            ApiId=api_id,
            RouteKey=key,
            Target=f"integrations/{integ_id}",
            AuthorizationType="CUSTOM",
            AuthorizerId=authorizer_id,
        )
    agw.create_stage(ApiId=api_id, StageName="$default", AutoDeploy=True, Tags=TAGS)

    # Precondition for every leg: exactly these six keys and no catch-all, so an unrouted target
    # really has nowhere to land and a 404 names route selection rather than a missing route table.
    listed = _route_keys(agw, api_id)
    assert listed == sorted(_ROUTE_KEYS), (
        f"the check's six route keys must be the only ones on the API, and in particular no "
        f"'$default' and no root greedy route; GetRoutes reports {listed}"
    )

    dest = _dest(ctx, api_id, token)
    # Warm-up and the leg-4 literal observation in one: hold until the auto-deploy stage serves a
    # known-good target twice in a row before any refusal is believed.
    warm = _poll(ctx, dest, "GET", "/items", 200, stamp=stamp, streak=2)
    base = _doc(warm, stamp)
    assert base is not None, (
        f"GET /items: the routed literal must be answered by the integration, got body "
        f"{warm['body'][:200]!r}"
    )

    _leg_decode_depth(ctx, dest, stamp)
    _leg_malformed_second_pass(ctx, dest, stamp)
    _leg_encoded_slash_separates(ctx, dest, stamp)
    _leg_trailing_slash(ctx, dest, stamp, base)
    _leg_normalisation(ctx, dest, stamp)
    _leg_query_mirror(ctx, dest, stamp)


def _leg_decode_depth(ctx, dest, stamp):
    """Two decode passes and no more: one more %25 layer survives into the captured value."""
    for target, want_path, want_id, why in (
        ("/items/a%41b", "/items/aAb", "aAb", "one encoded layer is decoded"),
        ("/items/a%2541b", "/items/aAb", "aAb", "a second pass decodes the surviving %41"),
        (
            "/items/a%252541b",
            "/items/a%41b",
            "a%41b",
            "a THIRD layer is not decoded, so the depth is exactly two",
        ),
    ):
        doc = _served(ctx, dest, target, stamp)
        assert doc.get("routeKey") == "GET /items/{id}", (
            f"GET {target}: the decoded single segment must select the variable route, got "
            f"{doc.get('routeKey')!r}"
        )
        assert doc.get("rawPath") == want_path, (
            f"GET {target}: {why}, so rawPath must be {want_path!r}, got {doc.get('rawPath')!r}"
        )
        assert doc.get("pathParameters") == {"id": want_id}, (
            f"GET {target}: {why}, so the captured id must be {want_id!r}, got "
            f"{doc.get('pathParameters')}"
        )


def _leg_malformed_second_pass(ctx, dest, stamp):
    """The second decode pass is real: it is the pass that rejects a%25b, and a%2525b is served."""
    resp = _poll(ctx, dest, "GET", "/items/a%25b", 400, streak=2)
    assert resp["body"] == _GW_400_BODY, (
        f"GET /items/a%25b decodes once to 'a%b', whose second pass meets a malformed escape, so "
        f"the gateway must refuse it with exactly {_GW_400_BODY!r}, got {resp['body'][:200]!r}"
    )
    assert _hdr(resp, "content-length") == str(len(_GW_400_BODY)), (
        f"the gateway Bad Request envelope must advertise content-length {len(_GW_400_BODY)}, got "
        f"{_hdr(resp, 'content-length')!r}"
    )
    assert _hdr(resp, "content-type") == "application/json", (
        f"the gateway Bad Request envelope must be served as JSON, got content-type "
        f"{_hdr(resp, 'content-type')!r}"
    )
    assert _hdr(resp, "apigw-requestid"), (
        "the 400 for a malformed escape must come from the gateway itself and so must carry its "
        f"request id header, got headers {resp['headers']}"
    )
    assert _hdrs(resp, "x-probe") == [], (
        f"a target refused for a malformed escape must never reach the integration, but its "
        f"stamped header arrived: {_hdrs(resp, 'x-probe')}"
    )

    # Control, same route, one more encoded layer: the refusal above is the SECOND decode pass
    # meeting a bad escape and not the gateway rejecting the literal bytes '%25'.
    doc = _served(ctx, dest, "/items/a%2525b", stamp)
    assert doc.get("rawPath") == "/items/a%b" and doc.get("pathParameters") == {"id": "a%b"}, (
        f"GET /items/a%2525b must decode twice to 'a%b' and be served, got rawPath "
        f"{doc.get('rawPath')!r} and {doc.get('pathParameters')}"
    )


def _leg_encoded_slash_separates(ctx, dest, stamp):
    """%2F is decoded into a real path separator before matching, so it changes segment count."""
    resp = _poll(ctx, dest, "GET", "/items/a%2Fb", 404, streak=2)
    _assert_gateway_404(
        resp,
        "GET /items/a%2Fb: the decoded %2F is a real separator, so the target is two segments "
        "below /items and the one-segment variable route cannot match it",
    )

    # Positive control for the same decoding, on a greedy route that CAN absorb the extra
    # separator: this is what makes the 404 above a routing consequence and not a dead API.
    doc = _served(ctx, dest, "/pets/a%2Fb/c", stamp)
    assert doc.get("routeKey") == "GET /pets/{proxy+}", (
        f"GET /pets/a%2Fb/c must land on the greedy route, got {doc.get('routeKey')!r}"
    )
    assert doc.get("pathParameters") == {"proxy": "a/b/c"}, (
        f"GET /pets/a%2Fb/c: the decoded %2F must appear in the captured greedy tail as a plain "
        f"separator (proxy == 'a/b/c'), got {doc.get('pathParameters')}"
    )
    assert doc.get("rawPath") == "/pets/a/b/c", (
        f"GET /pets/a%2Fb/c: rawPath must report the decoded path '/pets/a/b/c', got "
        f"{doc.get('rawPath')!r}"
    )


def _leg_trailing_slash(ctx, dest, stamp, base):
    """A trailing slash is significant, never stripped, and can itself be the captured value."""
    assert base.get("routeKey") == "GET /items", (
        f"GET /items must select the literal route, got {base.get('routeKey')!r}"
    )
    assert base.get("rawPath") == "/items", (
        f"GET /items must report rawPath '/items', got {base.get('rawPath')!r}"
    )
    assert "pathParameters" not in base.get("keys", []), (
        f"GET /items captures nothing, so pathParameters must be absent from the event entirely "
        f"rather than an empty object; the event carries {base.get('keys')}"
    )

    doc = _served(ctx, dest, "/items/", stamp)
    assert doc.get("routeKey") == "GET /items/{id}", (
        f"GET /items/ must NOT match the literal route 'GET /items': the trailing slash is a real "
        f"empty segment, so it falls through to the variable route, got {doc.get('routeKey')!r}"
    )
    assert doc.get("rawPath") == "/items/", (
        f"GET /items/ must report the trailing slash in rawPath, got {doc.get('rawPath')!r}"
    )
    assert doc.get("pathParameters") == {"id": ""}, (
        f"GET /items/ must capture the EMPTY STRING as id -- present with an empty value, not "
        f"absent and not '/', got {doc.get('pathParameters')}"
    )

    resp = _poll(ctx, dest, "GET", "/pets", 404, streak=2)
    _assert_gateway_404(
        resp,
        "GET /pets: a greedy route 'GET /pets/{proxy+}' requires the separating slash, so the "
        "bare prefix matches nothing",
    )

    doc = _served(ctx, dest, "/pets/", stamp)
    assert doc.get("routeKey") == "GET /pets/{proxy+}", (
        f"GET /pets/ must match the greedy route the bare prefix could not, got "
        f"{doc.get('routeKey')!r}"
    )
    assert doc.get("pathParameters") == {"proxy": ""}, (
        f"GET /pets/ must capture an EMPTY greedy tail -- present with an empty value, not absent "
        f"and not '/', got {doc.get('pathParameters')}"
    )


def _leg_normalisation(ctx, dest, stamp):
    """Dot segments and empty segments are removed before matching AND reported in rawPath."""
    for target, want_key, want_path in (
        ("/a/./b", "GET /a/b", "/a/b"),
        ("/a/../b", "GET /b", "/b"),
        ("/a//b", "GET /a/b", "/a/b"),
        ("/a/%2e%2e/b", "GET /b", "/b"),
    ):
        doc = _served(ctx, dest, target, stamp)
        assert doc.get("routeKey") == want_key, (
            f"GET {target}: normalisation must happen BEFORE route selection, so the request must "
            f"select {want_key!r}; got {doc.get('routeKey')!r}"
        )
        assert doc.get("rawPath") == want_path, (
            f"GET {target}: rawPath must report the NORMALISED path {want_path!r} and not the "
            f"bytes on the wire, got {doc.get('rawPath')!r}"
        )


def _leg_query_mirror(ctx, dest, stamp):
    """The raw query string stays encoded while queryStringParameters is decoded."""
    doc = _served(ctx, dest, "/q?a%20b=c%2Fd", stamp)
    assert doc.get("rawQueryString") == "a%20b=c%2Fd", (
        f"rawQueryString must be the VERBATIM still-encoded query 'a%20b=c%2Fd' -- the mirror "
        f"image of rawPath, which is reported decoded -- got {doc.get('rawQueryString')!r}"
    )
    assert doc.get("queryStringParameters") == {"a b": "c/d"}, (
        f"queryStringParameters must be percent-decoded in BOTH key and value ({{'a b': 'c/d'}}), "
        f"got {doc.get('queryStringParameters')}"
    )

    for target, why in (
        ("/q", "no query string at all"),
        ("/q?", "a bare '?' with nothing after it"),
    ):
        doc = _served(ctx, dest, target, stamp)
        assert doc.get("rawQueryString") == "", (
            f"GET {target}: with {why} rawQueryString must be the empty string, got "
            f"{doc.get('rawQueryString')!r}"
        )
        assert "queryStringParameters" not in doc.get("keys", []), (
            f"GET {target}: with {why} queryStringParameters must be absent from the event "
            f"entirely rather than an empty object, making a bare '?' indistinguishable from no "
            f"query; the event carries {doc.get('keys')}"
        )

    # Control on the same route: queryStringParameters IS delivered when there is a key to report,
    # so its absence above is the empty query and not a route that never reports the key.
    doc = _served(ctx, dest, "/q?a", stamp)
    assert doc.get("rawQueryString") == "a", (
        f"GET /q?a must report rawQueryString 'a', got {doc.get('rawQueryString')!r}"
    )
    assert doc.get("queryStringParameters") == {"a": ""}, (
        f"GET /q?a must deliver the valueless key with an empty-string value, got "
        f"{doc.get('queryStringParameters')}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

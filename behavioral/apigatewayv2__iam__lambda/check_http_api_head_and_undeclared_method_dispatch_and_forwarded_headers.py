"""http-api-head-and-undeclared-method-dispatch-and-forwarded-headers."""
from __future__ import annotations

import io
import json
import re
import socket
import ssl
import time
import zipfile
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = 'http-api-head-and-undeclared-method-dispatch-and-forwarded-headers'
GROUP = 'invoke'
SERVICES = ['apigatewayv2', 'iam', 'lambda']

TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
TAGS_KV = [{"Key": k, "Value": v} for k, v in TAGS.items()]

# 'GET /items' is deliberately method-scoped and has no HEAD, ANY or '$default' sibling, so HEAD,
# OPTIONS and PATCH on it have nowhere else to land. 'GET /hd' + 'HEAD /hd' and 'ANY /anyhd' are
# the two keys a HEAD CAN match, and they are served by a second backend whose body is a constant,
# so the content-length a HEAD advertises is comparable against a GET on the same route.
_ECHO_ROUTES = ["GET /items", "GET /ctx", "ANY /any/{proxy+}"]
_FIXED_ROUTES = ["GET /hd", "HEAD /hd", "ANY /anyhd"]

_UA = "sim2real-behav-target/1.0"
_UA_ALT = "sim2real-behav-target-alt/9.9"

# The backend reports the delivered request plus a stamp the gateway cannot forge, so a response
# carrying the stamp provably came from the integration. requestContext is PROJECTED to the fields
# this check reasons about: a field AWS adds later cannot make the check report a gap.
_ECHO_CODE = """
import json
STAMP = "%s"
def lambda_handler(event, context):
    rc = event.get("requestContext") or {}
    http = rc.get("http") or {}
    doc = {
        "stamp": STAMP,
        "keys": sorted(event.keys()),
        "routeKey": event.get("routeKey"),
        "rawPath": event.get("rawPath"),
        "headers": event.get("headers"),
        "pathParameters": event.get("pathParameters"),
        "queryStringParameters": event.get("queryStringParameters"),
        "cookies": event.get("cookies"),
        "body": event.get("body"),
        "ctx": {
            "apiId": rc.get("apiId"),
            "domainName": rc.get("domainName"),
            "domainPrefix": rc.get("domainPrefix"),
            "stage": rc.get("stage"),
            "routeKey": rc.get("routeKey"),
            "requestId": rc.get("requestId"),
            "time": rc.get("time"),
            "timeEpoch": rc.get("timeEpoch"),
            "method": http.get("method"),
            "path": http.get("path"),
            "protocol": http.get("protocol"),
            "sourceIp": http.get("sourceIp"),
            "userAgent": http.get("userAgent"),
        },
    }
    return {
        "statusCode": 200,
        "headers": {"content-type": "application/json", "x-probe": STAMP},
        "body": json.dumps(doc),
    }
"""

_FIXED_BODY_PREFIX = "FIXED-BODY-"
_FIXED_BODY_PAD = 256

# A body that does not depend on the event at all, and that the check can therefore construct for
# itself. The echo backend's body necessarily differs between GET and HEAD because the event
# differs, so only a constant body lets a HEAD's advertised content-length be compared against a
# body whose exact bytes are KNOWN rather than merely observed.
_FIXED_CODE = """
STAMP = "%s"
BODY = "%s" + STAMP + ("." * %d)
def lambda_handler(event, context):
    return {
        "statusCode": 200,
        "headers": {"content-type": "text/plain", "x-probe": STAMP},
        "body": BODY,
    }
"""


def _fixed_body(stamp):
    """The exact bytes the fixed backend returns, derived the same way the backend derives them."""
    return (_FIXED_BODY_PREFIX + stamp + ("." * _FIXED_BODY_PAD)).encode()

_GW_404_BODY = b'{"message":"Not Found"}'
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

_MONTHS = {
    m: i
    for i, m in enumerate(
        ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), 1
    )
}
# Common Log Format, parsed without strptime so a non-English locale cannot turn a fidelity
# verdict into a parse error.
_CLF = re.compile(r"^(\d{2})/([A-Z][a-z]{2})/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-])(\d{2})(\d{2})$")
_DOTTED_QUAD = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")


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


def _poll(
    ctx, dest, method, target, want, *, stamp=None, streak=1, extra=None, body=None, ua=_UA,
    timeout_s=180, read_timeout_s=30,
):
    """Poll one request until ``streak`` consecutive responses carry status ``want``.

    Absorbs execute-api DNS warm-up and auto-deploy propagation without a fixed sleep. A streak
    above one is required for the refusal legs: an execute-api node that has not yet picked up the
    deployment answers 404 on every route, so a single 404 does not distinguish "this method is
    not routed" from "this node is cold". When ``stamp`` is given the response must also carry the
    backend's stamped document, so a 200 from anything else does not satisfy the wait. Raises
    AssertionError naming the last observation on timeout, so a wrong answer grades as a mismatch
    rather than surfacing as a harness error.
    """
    last = "no response"
    seen = 0
    deadline = time.monotonic() + timeout_s
    while True:
        resp = _raw(ctx, dest, method, target, extra, body, ua, timeout_s=read_timeout_s)
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


def _echoed(ctx, dest, method, target, stamp, *, extra=None, body=None, ua=_UA):
    """One served request on a routed target; returns (response, the backend's echo document)."""
    resp = _poll(ctx, dest, method, target, 200, stamp=stamp, extra=extra, body=body, ua=ua)
    doc = _doc(resp, stamp)
    assert doc is not None, (
        f"{method} {target}: a 200 on a routed target must carry the backend's own stamped "
        f"document, got body {resp['body'][:200]!r}"
    )
    assert _hdrs(resp, "x-probe") == [stamp], (
        f"{method} {target}: the integration's stamped response header must reach the client "
        f"once, got {_hdrs(resp, 'x-probe')}"
    )
    return resp, doc


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
    else:
        assert resp["body"] == b"", (
            f"{where}: the gateway 404 body must be suppressed to zero bytes on the wire even "
            f"though content-length is still advertised, got {resp['body'][:200]!r}"
        )
    # The stamp is the integration's own and the gateway cannot forge it, so its absence shows that
    # no integration response reached the client -- and every leg asserting it absent is paired
    # with a request on this same API, in the same run, whose response does carry it.
    assert _hdrs(resp, "x-probe") == [], (
        f"{where}: a gateway-produced 404 must carry no integration response header, got x-probe "
        f"{_hdrs(resp, 'x-probe')}"
    )
    assert _hdr(resp, "apigw-requestid"), (
        f"{where}: a gateway-produced response must carry the gateway's own request id header, "
        f"got headers {resp['headers']}"
    )


def _clf_epoch(value):
    """The epoch SECONDS a Common Log Format timestamp names, or None when it is not CLF."""
    match = _CLF.match(value or "")
    if match is None:
        return None
    day, mon, year, hour, minute, sec, sign, off_h, off_m = match.groups()
    if mon not in _MONTHS:
        return None
    delta = timedelta(hours=int(off_h), minutes=int(off_m))
    try:
        moment = datetime(
            int(year), _MONTHS[mon], int(day), int(hour), int(minute), int(sec),
            tzinfo=timezone(-delta if sign == "-" else delta),
        )
    except ValueError:
        return None
    return int(moment.timestamp())


def _is_dotted_quad(value):
    """True when ``value`` is four decimal octets in range."""
    match = _DOTTED_QUAD.match(value or "")
    return match is not None and all(0 <= int(g) <= 255 for g in match.groups())


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """HEAD on an HTTP API matches only a HEAD or ANY route key, where it is invoked and answered
    with the integration's own content-length and a zero-byte body, while HEAD or an undeclared
    method on a method-scoped route gets the gateway's 404; x-forwarded-for is appended to.
    """
    agw = ctx.client("apigatewayv2")
    stamp = ctx.unique_name("probe-")
    api_id = _create_api(ctx, agw)
    role_arn = _create_lambda_role(ctx)
    token = ctx.unique_name("token-")
    authorizer_id = _create_authorizer(ctx, api_id, role_arn, token)
    for marker, code, keys in (
        ("echo", _ECHO_CODE % stamp, _ECHO_ROUTES),
        ("fixed", _FIXED_CODE % (stamp, _FIXED_BODY_PREFIX, _FIXED_BODY_PAD), _FIXED_ROUTES),
    ):
        fn_arn = _create_backend(ctx, api_id, role_arn, marker, code)
        integ_id = agw.create_integration(
            ApiId=api_id,
            IntegrationType="AWS_PROXY",
            IntegrationUri=fn_arn,
            IntegrationMethod="POST",
            PayloadFormatVersion="2.0",
        )["IntegrationId"]
        for key in keys:
            agw.create_route(
                ApiId=api_id,
                RouteKey=key,
                Target=f"integrations/{integ_id}",
                AuthorizationType="CUSTOM",
                AuthorizerId=authorizer_id,
            )
    agw.create_stage(ApiId=api_id, StageName="$default", AutoDeploy=True, Tags=TAGS)

    # Precondition for every leg: 'GET /items' is method-scoped and there is no '$default' and no
    # root greedy route, so a method with no declared route really has nowhere to land.
    expected = sorted(_ECHO_ROUTES + _FIXED_ROUTES)
    listed = _route_keys(agw, api_id)
    assert listed == expected, (
        f"the check's route keys must be the only ones on the API, and in particular 'GET /items' "
        f"must have no HEAD, ANY or '$default' sibling; GetRoutes reports {listed}"
    )

    dest = _dest(ctx, api_id, token)
    # Warm-up: hold until the auto-deploy stage serves a known-good target twice in a row before
    # any refusal below is believed.
    _poll(ctx, dest, "GET", "/items", 200, stamp=stamp, streak=2)

    _leg_head_not_matched_by_a_get_route(ctx, dest, stamp)
    _leg_head_carries_the_integrations_length(ctx, dest, stamp)
    _leg_undeclared_methods(ctx, dest, stamp)
    _leg_forwarded_headers(ctx, dest, stamp)
    _leg_absent_not_empty(ctx, dest, stamp)
    _leg_request_context(ctx, dest, stamp, api_id)


def _leg_head_not_matched_by_a_get_route(ctx, dest, stamp):
    """HEAD never falls back to a GET route, and the 404 it gets is the gateway's own."""
    resp = _poll(ctx, dest, "HEAD", "/items", 404, streak=2)
    _assert_gateway_404(
        resp,
        "HEAD /items: 'GET /items' is method-scoped, so HEAD must not be served by it",
        body_on_wire=False,
    )

    # Two positive controls on the same API in the same run. The first shows this route does serve
    # and does stamp; the second shows a HEAD response can carry the stamp at all, so its absence
    # above means no integration response reached the client, not that HEAD cannot carry one.
    _echoed(ctx, dest, "GET", "/items", stamp)
    head_resp = _poll(ctx, dest, "HEAD", "/hd", 200, streak=1)
    assert _hdrs(head_resp, "x-probe") == [stamp], (
        f"HEAD /hd: a HEAD that DOES match a route must carry the integration's stamped header, "
        f"got {_hdrs(head_resp, 'x-probe')}; without this control the absent stamp on HEAD "
        f"/items would prove nothing"
    )


def _leg_head_carries_the_integrations_length(ctx, dest, stamp):
    """A matched HEAD is invoked and advertises the integration's real length with no body."""
    expected = _fixed_body(stamp)
    for target, route_key in (("/hd", "HEAD /hd"), ("/anyhd", "ANY /anyhd")):
        served = _poll(ctx, dest, "GET", target, 200, streak=1)
        assert _hdrs(served, "x-probe") == [stamp], (
            f"GET {target}: the backend must answer and stamp the response, got "
            f"{_hdrs(served, 'x-probe')}"
        )
        # The length the HEAD is measured against is the integration's KNOWN constant body, and it
        # is asserted here byte-for-byte FIRST: a target that truncated or substituted the body and
        # then reported a content-length agreeing with whatever it did send would otherwise satisfy
        # the HEAD assertion below without ever passing the integration's bytes through.
        assert served["body"] == expected, (
            f"GET {target}: the integration's constant body must reach the client intact, all "
            f"{len(expected)} bytes of it; got {len(served['body'])} bytes starting "
            f"{served['body'][:48]!r}"
        )
        assert _hdr(served, "content-length") == str(len(expected)), (
            f"GET {target}: content-length must equal the integration's own body length "
            f"({len(expected)}), got {_hdr(served, 'content-length')!r}"
        )

        resp = _poll(ctx, dest, "HEAD", target, 200, streak=1)
        assert _hdrs(resp, "x-probe") == [stamp], (
            f"HEAD {target}: a HEAD matching {route_key!r} must be DELIVERED to the integration, "
            f"shown by its stamped response header, got {_hdrs(resp, 'x-probe')}"
        )
        assert _hdr(resp, "content-length") == str(len(expected)), (
            f"HEAD {target}: the response head must carry the integration's REAL body length "
            f"({len(expected)}, the constant body asserted intact under GET {target} just above) "
            f"and not 0 or a recomputed value, got {_hdr(resp, 'content-length')!r}"
        )
        assert resp["body"] == b"", (
            f"HEAD {target}: the body must be suppressed to zero bytes on the wire while "
            f"content-length still advertises {len(expected)}, got {len(resp['body'])} bytes"
        )


def _leg_undeclared_methods(ctx, dest, stamp):
    """A method no route declares gets the gateway 404 with its 23 bytes actually on the wire."""
    for method in ("PATCH", "OPTIONS"):
        resp = _poll(ctx, dest, method, "/items", 404, streak=2)
        _assert_gateway_404(
            resp,
            f"{method} /items: no route declares this method and there is no ANY or '$default' "
            f"sibling, so the gateway answers it itself",
        )

    # Positive control on the same route in the same run: the declared method still serves and
    # still stamps, so the refusals above are method dispatch and not an API that stopped working.
    _echoed(ctx, dest, "GET", "/items", stamp)


def _leg_forwarded_headers(ctx, dest, stamp):
    """x-forwarded-for is appended to, -proto and -port are overwritten, forwarded is passed on."""
    _, doc = _echoed(ctx, dest, "GET", "/items", stamp)
    headers = doc.get("headers") or {}
    source_ip = (doc.get("ctx") or {}).get("sourceIp")
    assert _is_dotted_quad(source_ip), (
        f"requestContext.http.sourceIp must be the real TCP peer as a dotted quad, got "
        f"{source_ip!r}"
    )
    assert headers.get("x-forwarded-for") == source_ip, (
        f"with no client x-forwarded-for the gateway must inject exactly its own view of the "
        f"peer ({source_ip!r}), got {headers.get('x-forwarded-for')!r}"
    )
    assert headers.get("x-forwarded-proto") == "https", (
        f"the gateway must report its own listener protocol as 'https', got "
        f"{headers.get('x-forwarded-proto')!r}"
    )
    assert headers.get("x-forwarded-port") == "443", (
        f"the gateway must report its own listener port as '443', got "
        f"{headers.get('x-forwarded-port')!r}"
    )

    # TEST-NET-1, TEST-NET-3 and TEST-NET-2 addresses, which cannot be a real TCP peer, so the
    # append assertion below can never collide with this client's own address.
    for sent_xff, sent_proto, sent_port in (
        ("192.0.2.1", "http", "8080"),
        ("203.0.113.7, 198.51.100.9", "ftp", "1"),
    ):
        _, doc = _echoed(
            ctx,
            dest,
            "GET",
            "/items",
            stamp,
            extra=[
                ("x-forwarded-for", sent_xff),
                ("x-forwarded-proto", sent_proto),
                ("x-forwarded-port", sent_port),
            ],
        )
        headers = doc.get("headers") or {}
        peer = (doc.get("ctx") or {}).get("sourceIp")
        assert _is_dotted_quad(peer), (
            f"requestContext.http.sourceIp must stay a dotted quad when the client sends "
            f"x-forwarded-for {sent_xff!r}, got {peer!r}"
        )
        assert headers.get("x-forwarded-for") == f"{sent_xff}, {peer}", (
            f"the gateway must APPEND its own view of the peer to the client's x-forwarded-for, "
            f"client value(s) first and the real peer LAST ({sent_xff!r} then {peer!r}), got "
            f"{headers.get('x-forwarded-for')!r}"
        )
        assert headers.get("x-forwarded-proto") == "https", (
            f"x-forwarded-proto must be OVERWRITTEN to 'https' whatever the client sent "
            f"({sent_proto!r}), got {headers.get('x-forwarded-proto')!r}"
        )
        assert headers.get("x-forwarded-port") == "443", (
            f"x-forwarded-port must be OVERWRITTEN to '443' whatever the client sent "
            f"({sent_port!r}), got {headers.get('x-forwarded-port')!r}"
        )

    # RFC 7239's own header gets none of that treatment: it is neither consumed nor rewritten.
    forwarded = "for=192.0.2.9;proto=http"
    _, doc = _echoed(ctx, dest, "GET", "/items", stamp, extra=[("forwarded", forwarded)])
    headers = doc.get("headers") or {}
    peer = (doc.get("ctx") or {}).get("sourceIp")
    assert _is_dotted_quad(peer), (
        f"requestContext.http.sourceIp must stay a dotted quad when the client sends a "
        f"'forwarded' header, got {peer!r}"
    )
    assert headers.get("forwarded") == forwarded, (
        f"an RFC-7239 'forwarded' header must be delivered VERBATIM and not consumed, got "
        f"{headers.get('forwarded')!r}"
    )
    assert headers.get("x-forwarded-for") == peer, (
        f"a client 'forwarded' header must not feed x-forwarded-for, which must still be just the "
        f"real peer ({peer!r}), got {headers.get('x-forwarded-for')!r}"
    )
    assert headers.get("x-forwarded-proto") == "https", (
        f"x-forwarded-proto must stay 'https' when the client claims http via 'forwarded', got "
        f"{headers.get('x-forwarded-proto')!r}"
    )


def _leg_absent_not_empty(ctx, dest, stamp):
    """The optional event keys are absent entirely when inapplicable, never empty placeholders."""
    _, plain = _echoed(ctx, dest, "GET", "/items", stamp)
    keys = plain.get("keys") or []
    for key in ("pathParameters", "queryStringParameters", "cookies", "body"):
        assert key not in keys, (
            f"GET /items reports no {key}, so the key must be absent from the event ENTIRELY and "
            f"never an empty object, list or string; the event carries {keys}"
        )

    # Each absence above is paired with a request on this same API whose event DOES carry the key.
    # The pathParameters control is the sharpest: a greedy route with an empty tail reports the key
    # PRESENT with an empty value, which is exactly what "absent is not empty" has to mean.
    _, doc = _echoed(ctx, dest, "GET", "/any/", stamp)
    assert doc.get("pathParameters") == {"proxy": ""}, (
        f"GET /any/ must report pathParameters PRESENT with an empty captured tail, got "
        f"{doc.get('pathParameters')}"
    )

    _, doc = _echoed(ctx, dest, "GET", "/items?a=1&", stamp)
    assert doc.get("queryStringParameters") == {"a": "1"}, (
        f"GET /items?a=1& must report queryStringParameters present with the one key it has, got "
        f"{doc.get('queryStringParameters')}"
    )

    # These two controls assert PRESENCE of the key and nothing about its shape. Presence is all
    # that is needed -- it is what shows the absences above are the inapplicable case and not a
    # key this event never carries -- and the delivered form of either key is not pinned here.
    _, doc = _echoed(ctx, dest, "GET", "/items", stamp, extra=[("cookie", "k=v")])
    assert "cookies" in (doc.get("keys") or []), (
        f"a request carrying a cookie header must make the event's cookies key APPEAR, got keys "
        f"{doc.get('keys')}"
    )

    _, doc = _echoed(ctx, dest, "POST", "/any/x", stamp, body=b"probe-body")
    assert "body" in (doc.get("keys") or []), (
        f"a request carrying a body must make the event's body key APPEAR, got keys "
        f"{doc.get('keys')}"
    )


def _leg_request_context(ctx, dest, stamp, api_id):
    """The requestContext fields this check reasons about: pinned where stable, shaped where not.

    Only named fields are asserted and no key is asserted ABSENT, so a field AWS adds later cannot
    turn into a reported gap.
    """
    resp, doc = _echoed(ctx, dest, "GET", "/ctx", stamp)
    got = doc.get("ctx") or {}
    invoked_host = dest[0]
    first_label = invoked_host.split(".", 1)[0]
    assert first_label == api_id, (
        f"the invoke host {invoked_host!r} must be this API's own hostname, whose first label is "
        f"the API id {api_id!r}"
    )
    for field, want in (
        ("apiId", api_id),
        ("domainName", invoked_host),
        ("domainPrefix", first_label),
        ("stage", "$default"),
        ("routeKey", "GET /ctx"),
        ("method", "GET"),
        ("path", "/ctx"),
        ("protocol", "HTTP/1.1"),
        ("userAgent", _UA),
    ):
        assert got.get(field) == want, (
            f"GET /ctx: requestContext must report {field} as {want!r}, got {got.get(field)!r}"
        )

    request_id = got.get("requestId")
    assert isinstance(request_id, str) and request_id.strip() == request_id and request_id, (
        f"requestContext.requestId must be a non-empty unpadded string, got {request_id!r}"
    )
    assert _hdr(resp, "apigw-requestid") == request_id, (
        f"the request id the integration saw must be the one the gateway reported to the client, "
        f"got header {_hdr(resp, 'apigw-requestid')!r} against {request_id!r}"
    )

    clf_seconds = _clf_epoch(got.get("time"))
    assert clf_seconds is not None, (
        f"requestContext.time must be Common Log Format (%d/%b/%Y:%H:%M:%S %z), got "
        f"{got.get('time')!r}"
    )
    epoch_ms = got.get("timeEpoch")
    assert isinstance(epoch_ms, int) and not isinstance(epoch_ms, bool), (
        f"requestContext.timeEpoch must be an integer, got {epoch_ms!r}"
    )
    assert 10**12 <= epoch_ms < 10**13, (
        f"requestContext.timeEpoch must be a MILLISECOND epoch and not seconds, got {epoch_ms}"
    )
    assert epoch_ms // 1000 == clf_seconds, (
        f"requestContext.timeEpoch must agree with requestContext.time to the second: "
        f"{got.get('time')!r} is {clf_seconds} but timeEpoch is {epoch_ms} ({epoch_ms // 1000})"
    )
    assert _is_dotted_quad(got.get("sourceIp")), (
        f"requestContext.http.sourceIp must be a dotted quad, got {got.get('sourceIp')!r}"
    )

    # The user agent is the CLIENT's own, read per request: a second request on the same route
    # under a different agent must report that one, which a hard-coded or cached value cannot do.
    _, doc = _echoed(ctx, dest, "GET", "/ctx", stamp, ua=_UA_ALT)
    assert (doc.get("ctx") or {}).get("userAgent") == _UA_ALT, (
        f"requestContext.http.userAgent must echo THIS request's user-agent ({_UA_ALT!r}), got "
        f"{(doc.get('ctx') or {}).get('userAgent')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

"""http-api-route-selection-ladder-method-and-greedy-depth."""
from __future__ import annotations

import http.client
import io
import json
import ssl
import time
import urllib.error
import urllib.request
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = 'http-api-route-selection-ladder-method-and-greedy-depth'
GROUP = 'invoke'
SERVICES = ['apigatewayv2', 'iam', 'lambda']

TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
TAGS_KV = [{"Key": k, "Value": v} for k, v in TAGS.items()]

# Created most-specific first, so a route table that simply prefers the last (or the first)
# declaration cannot pass the selection legs below. Two pairs isolate one ranking input each:
# 'GET /pets/{proxy+}' vs 'GET /{proxy+}' differ only in DEPTH, and 'GET /{proxy+}' vs
# 'ANY /{proxy+}' differ only in METHOD.
_ROUTE_KEYS = [
    "GET /pets/dog/1",
    "GET /pets/dog/{id}",
    "GET /pets/{proxy+}",
    "GET /{proxy+}",
    "ANY /{proxy+}",
    "$default",
]

# 'ANY /{proxy+}' is served by a second function, so the legs that land on it are graded by which
# backend actually answered and not only by the routeKey the service chose to report.
_ANY_ROUTE = "ANY /{proxy+}"

# The backend lives on the target: a Lambda proxy integration echoing which route API Gateway
# selected, what it captured from the path, the method it delivered and which backend ran.
_ROUTE_ECHO_CODE = """
import json
def lambda_handler(event, context):
    doc = {
        "backend": "%s",
        "routeKey": event.get("routeKey"),
        "rawPath": event.get("rawPath"),
        "method": event.get("requestContext", {}).get("http", {}).get("method"),
    }
    if "pathParameters" in event:
        doc["pathParameters"] = event["pathParameters"]
    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(doc),
    }
"""

_NOT_FOUND_BODY = {"message": "Not Found"}
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


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect is part of the response under test: hand it back as-is, never follow it."""

    def redirect_request(self, *args, **kwargs):
        return None


def _ssl_context(ctx):
    """The TLS context for this check's own call to the target, from ``ctx.http_verify``."""
    verify = ctx.http_verify
    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


def _http(ctx, token, method, url):
    """One authorized request, redirects not followed. Returns (status, headers, body_str)."""
    opener = urllib.request.build_opener(
        _NoRedirect, urllib.request.HTTPSHandler(context=_ssl_context(ctx))
    )
    req = urllib.request.Request(url, method=method, headers={_TOKEN_HEADER: token})
    try:
        with opener.open(req, timeout=15) as resp:
            headers = {k.lower(): v for k, v in resp.headers.items()}
            return resp.status, headers, resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in e.headers.items()}, e.read().decode()


def _echo(body):
    """The backend's echo document, or None when the body did not come from a backend."""
    try:
        doc = json.loads(body)
    except ValueError:
        return None
    if not isinstance(doc, dict) or "routeKey" not in doc:
        return None
    return doc


def _json_or_raw(body):
    """The parsed body, or the raw string when it is not JSON, so a non-JSON body still grades."""
    try:
        return json.loads(body)
    except ValueError:
        return body


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
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Path="/sim2real/",
        Tags=TAGS_KV,
    )["Role"]["Arn"]
    ctx.on_cleanup(_cleanup(lambda: iam.delete_role(RoleName=role_name)))
    return arn


def _create_backend(ctx, api_id, role_arn, marker, code):
    """A python Lambda running ``code``, invokable by this API; returns its ARN."""
    lam = ctx.client("lambda")
    name = ctx.unique_name(f"sim2real-behav-fn-{marker}-")
    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", code)
    kwargs = {
        "FunctionName": name,
        "Runtime": "python3.12",
        "Role": role_arn,
        "Handler": "lambda_function.lambda_handler",
        "Code": {"ZipFile": zip_buf.getvalue()},
        "Timeout": 10,
        "MemorySize": 128,
        "Tags": dict(TAGS),
    }
    deadline = time.monotonic() + 90
    while True:
        try:
            arn = lam.create_function(**kwargs)["FunctionArn"]
            break
        except ClientError as e:
            # IAM propagation: a freshly created role is not yet assumable by Lambda.
            err = e.response["Error"]
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


def _create_route(agw, api_id, route_key, target, authorizer_id):
    """A route on ``api_id`` behind the check's authorizer; returns its id."""
    return agw.create_route(
        ApiId=api_id,
        RouteKey=route_key,
        Target=target,
        AuthorizationType="CUSTOM",
        AuthorizerId=authorizer_id,
    )["RouteId"]


def _route_keys(ctx, api_id):
    agw = ctx.client("apigatewayv2")
    return sorted(r["RouteKey"] for r in agw.get_routes(ApiId=api_id)["Items"])


def _poll_selected(ctx, token, method, url, want, backend=None, timeout_s=180):
    """Poll one request until the backend echoes ``want`` as the selected routeKey.

    Absorbs execute-api DNS warm-up and auto-deploy propagation without a fixed sleep. Raises
    AssertionError naming the last observation when ``want`` is never selected, so a wrong winner
    is graded as a mismatch rather than surfacing as a harness error.
    """
    last = "no response"
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            status, _, raw = _http(ctx, token, method, url)
        except (OSError, http.client.HTTPException) as exc:  # DNS/connect warm-up, retried
            last = f"transport error {exc!r}"
        else:
            doc = _echo(raw)
            if status == 200 and doc is not None and doc.get("routeKey") == want:
                if backend is not None:
                    assert doc.get("backend") == backend, (
                        f"{method} {url}: route {want!r} must be served by the backend it targets "
                        f"({backend!r}), but {doc.get('backend')!r} answered"
                    )
                return doc
            last = f"status {status} body {raw[:200]!r}"
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{method} {url}: API Gateway never selected {want!r} within {timeout_s}s; "
                f"last observation: {last}"
            )
        time.sleep(3)


def _poll_status(ctx, token, method, url, want, streak=2, timeout_s=180):
    """Poll until ``streak`` consecutive responses carry status ``want``; return the last one.

    A single observation is not enough: an execute-api node that has not yet picked up a
    deployment answers 404 on every route, so one 404 does not distinguish "the route is gone"
    from "this node is cold". Raises AssertionError naming the last observation on timeout.
    """
    last = "no response"
    seen = 0
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            status, headers, raw = _http(ctx, token, method, url)
        except (OSError, http.client.HTTPException) as exc:  # DNS/connect warm-up, retried
            last, seen = f"transport error {exc!r}", 0
        else:
            if status == want:
                seen += 1
                if seen >= streak:
                    return status, headers, raw
            else:
                seen = 0
            last = f"status {status} body {raw[:200]!r}"
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{method} {url}: never answered {want} {streak}x in a row within {timeout_s}s; "
                f"last observation: {last}"
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
    """HTTP API route selection prefers a full method-and-path match; among greedy routes the
    deeper path prefix when the method is equal, and the method-specific route over ``ANY`` when
    the depth is equal; ``$default`` ranks last, re-derived per request on an auto-deploy stage.
    """
    agw = ctx.client("apigatewayv2")
    api_id = agw.create_api(
        Name=ctx.unique_name("sim2real-behav-httpapi-"), ProtocolType="HTTP", Tags=TAGS
    )["ApiId"]
    ctx.on_cleanup(_cleanup(lambda: agw.delete_api(ApiId=api_id)))
    role_arn = _create_lambda_role(ctx)
    token = ctx.unique_name("token-")
    authorizer_id = _create_authorizer(ctx, api_id, role_arn, token)

    targets = {}
    for marker, keys in (
        ("a", [k for k in _ROUTE_KEYS if k != _ANY_ROUTE]),
        ("b", [_ANY_ROUTE]),
    ):
        fn_arn = _create_backend(ctx, api_id, role_arn, marker, _ROUTE_ECHO_CODE % marker)
        integ_id = agw.create_integration(
            ApiId=api_id,
            IntegrationType="AWS_PROXY",
            IntegrationUri=fn_arn,
            IntegrationMethod="POST",
            PayloadFormatVersion="2.0",
        )["IntegrationId"]
        for key in keys:
            targets[key] = f"integrations/{integ_id}"

    route_ids = {
        rk: _create_route(agw, api_id, rk, targets[rk], authorizer_id) for rk in _ROUTE_KEYS
    }
    agw.create_stage(ApiId=api_id, StageName="$default", AutoDeploy=True, Tags=TAGS)
    ctx.on_cleanup(_cleanup(lambda: agw.delete_stage(ApiId=api_id, StageName="$default")))
    base = ctx.api_url(api_id, "$default")

    # Precondition for every leg below: all six overlapping keys coexist on one API, so each
    # request really is choosing between them rather than finding only one candidate.
    listed = _route_keys(ctx, api_id)
    assert listed == sorted(_ROUTE_KEYS), (
        f"the six overlapping route keys must all be accepted on one API; GetRoutes reports "
        f"{listed}"
    )

    # A literal method-and-path match wins over the four later-created routes that also match it.
    doc = _poll_selected(
        ctx, token, "GET", f"{base}/pets/dog/1", "GET /pets/dog/1", backend="a"
    )
    assert "pathParameters" not in doc, (
        f"a literal route captures nothing, so pathParameters must be absent from the event "
        f"entirely rather than an empty or null value, got {doc.get('pathParameters')!r}"
    )

    # A single-segment variable wins over all three greedy routes.
    doc = _poll_selected(
        ctx, token, "GET", f"{base}/pets/dog/2", "GET /pets/dog/{id}", backend="a"
    )
    assert doc.get("pathParameters") == {"id": "2"}, (
        f"the winning variable route must capture id=2, got {doc.get('pathParameters')}"
    )

    # DEPTH, isolated: both candidates are GET-scoped greedy routes, so only the deeper path
    # prefix distinguishes them.
    doc = _poll_selected(
        ctx, token, "GET", f"{base}/pets/cat/1", "GET /pets/{proxy+}", backend="a"
    )
    assert doc.get("pathParameters") == {"proxy": "cat/1"}, (
        f"the deeper greedy route must capture the tail below /pets (proxy=cat/1), got "
        f"{doc.get('pathParameters')}"
    )

    # METHOD, isolated: both candidates are root greedy routes, so only the method distinguishes
    # them -- and the same path under a method no route declares lands on the ANY route instead,
    # on the other backend.
    doc = _poll_selected(ctx, token, "GET", f"{base}/test/5", "GET /{proxy+}", backend="a")
    assert doc.get("pathParameters") == {"proxy": "test/5"}, (
        f"the root greedy route must capture the whole path (proxy=test/5), got "
        f"{doc.get('pathParameters')}"
    )
    doc = _poll_selected(ctx, token, "POST", f"{base}/test/5", _ANY_ROUTE, backend="b")
    assert doc.get("pathParameters") == {"proxy": "test/5"}, (
        f"the ANY greedy route must capture the whole path (proxy=test/5), got "
        f"{doc.get('pathParameters')}"
    )

    # Method before path: this path is an exact match for 'GET /pets/dog/1', but the method is
    # not, so selection must fall past every GET-scoped route to the ANY greedy route.
    doc = _poll_selected(ctx, token, "POST", f"{base}/pets/dog/1", _ANY_ROUTE, backend="b")
    assert doc.get("pathParameters") == {"proxy": "pets/dog/1"}, (
        f"the ANY greedy route must capture the whole path (proxy=pets/dog/1), got "
        f"{doc.get('pathParameters')}"
    )
    assert doc.get("method") == "POST", (
        f"the delivered request must keep the client's method and not the route key's, got "
        f"{doc.get('method')}"
    )

    # One request, held fixed, while the rung under it is removed: selection is re-derived from
    # the live route table on an auto-deploy stage, not snapshotted.
    probe = f"{base}/pets/cat/1"
    ladder = ["GET /pets/{proxy+}", "GET /{proxy+}", _ANY_ROUTE, "$default"]
    backends = {_ANY_ROUTE: "b"}
    for position, removed in enumerate(ladder):
        agw.delete_route(ApiId=api_id, RouteId=route_ids[removed])
        remaining = sorted(set(_ROUTE_KEYS) - set(ladder[: position + 1]))
        listed = _route_keys(ctx, api_id)
        assert listed == remaining, (
            f"DeleteRoute({removed!r}) must remove exactly that key; GetRoutes reports "
            f"{listed}, expected {remaining}"
        )
        if position + 1 < len(ladder):
            successor = ladder[position + 1]
            doc = _poll_selected(
                ctx, token, "GET", probe, successor, backend=backends.get(successor, "a")
            )
            if successor == "$default":
                assert doc.get("rawPath") == "/pets/cat/1", (
                    f"a request reaching $default must still report the real rawPath and not the "
                    f"matched pattern, got {doc.get('rawPath')}"
                )

    # Bottom of the ladder: with every matching rung gone the request gets API Gateway's own 404.
    _, headers, raw = _poll_status(ctx, token, "GET", probe, 404)
    assert _json_or_raw(raw) == _NOT_FOUND_BODY, (
        f"an unmatched request must get API Gateway's own Not Found envelope "
        f"{_NOT_FOUND_BODY}, and must not reach a backend, got {raw[:200]!r}"
    )
    assert headers.get("content-type") == "application/json", (
        f"the Not Found envelope must be served as JSON, got content-type "
        f"{headers.get('content-type')!r}"
    )

    # Positive control: the untouched literal route still serves, so the 404 above is route
    # selection finding no candidate and not an API that stopped answering.
    _poll_selected(ctx, token, "GET", f"{base}/pets/dog/1", "GET /pets/dog/1", backend="a")

    # Restored least-specific-first, so each rung must take the win back from routes created
    # BEFORE it: the last-created route wins the final probe, which is what a greedy ranking that
    # breaks ties on first-declared order cannot do.
    for restored in reversed(ladder):
        route_ids[restored] = _create_route(
            agw, api_id, restored, targets[restored], authorizer_id
        )
        _poll_selected(ctx, token, "GET", probe, restored, backend=backends.get(restored, "a"))
    listed = _route_keys(ctx, api_id)
    assert listed == sorted(_ROUTE_KEYS), (
        f"recreating the deleted keys must restore the original route table; GetRoutes reports "
        f"{listed}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
